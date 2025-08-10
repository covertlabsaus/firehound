## Firebase endpoints queried by the scanner

This document explains, in practical terms, which Firebase/Google endpoints the pipeline calls and why. It maps directly to the behavior in `audit.py` (discovery/fuzzing) and `summarize.py` (lightweight counting and optional IPA extraction).

### Realtime Database (RTDB)

- Base URL comes from the app’s `GoogleService-Info.plist` key `DATABASE_URL`, e.g. `https://<project-id>-default-rtdb.firebaseio.com` or `https://<db>.firebasedatabase.app`.

- Unauthenticated probes (audit):
  - `GET {db}/{root}/.json?shallow=true&limitToFirst=1`
    - Purpose: Early-exit check for public read access by trying a few common roots (`users`, `public`, `profiles`, `data`, `messages`).
    - Why shallow: returns only keys, minimal payload.
  - `PATCH {db}/probes/.json` with a small JSON blob
    - Purpose: Detect public write access; if it succeeds, the write is immediately deleted.
  - `DELETE {db}/probes/.json`
    - Clean-up of the write test when applicable.

- Authenticated probes (audit):
  - Obtain a Firebase ID token (see Auth section), then:
  - `GET {db}/{root}/.json?shallow=true&limitToFirst=1&auth={ID_TOKEN}`
  - `PATCH {db}/.json?auth={ID_TOKEN}` and `DELETE {db}/_probes_auth/...` (cleanup)
  - Purpose: Detect rules that allow access for any authenticated user (`auth != null`).

- Counting (summarize):
  - `GET {db}/.json?shallow=true`
  - Purpose: Count top-level keys quickly without pulling data.

### Cloud Firestore (REST API)

- Project ID and API key come from `GoogleService-Info.plist` keys `PROJECT_ID` and `API_KEY`.

- Unauthenticated probes (audit):
  - `POST https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents:runQuery?key={API_KEY}`
    - Body: `{"structuredQuery":{"limit":1}}` (pre-flight to detect Datastore mode 400s)
  - `POST ...:runQuery?key={API_KEY}` with body:
    - `{"structuredQuery":{"from":[{"collectionId":"<candidate>"}],"limit":1}}`
    - Purpose: Check if specific collections are publicly readable when only an API key is provided.

- Authenticated probe (audit):
  - Obtain an ID token, then:
  - `POST https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents:runQuery`
    - Headers: `Authorization: Bearer {ID_TOKEN}`
    - Body: same `structuredQuery` as above for a single candidate collection.

- Counting (summarize):
  - `GET https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents/{COLL}?pageSize=1000&pageToken=...&key={API_KEY}`
  - Purpose: Paginate and count documents in discovered collections. In a future “fast mode”, this can be swapped for `runAggregationQuery COUNT(*)` or early-exit when `> 1`.

### Cloud Storage for Firebase

- Bucket name comes from `GoogleService-Info.plist` key `STORAGE_BUCKET`.

- Unauthenticated probes (audit):
  - `GET https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?maxResults=10&delimiter=/`
  - `GET https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?maxResults=10&delimiter=/&prefix=users%2F`
    - Purpose: Detect public listing at root and in `users/`.
  - `POST https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?uploadType=media&name=probes/test-<ts>.txt`
    - Body: small text; if it succeeds, delete via:
    - `DELETE https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o/{OBJECT_NAME}`

- Authenticated probes (audit):
  - Same endpoints as above with header `Authorization: Bearer {ID_TOKEN}`.

- Counting (summarize):
  - `GET https://firebasestorage.googleapis.com/v0/b/{BUCKET}/o?maxResults=1000&pageToken=...`
  - Purpose: Paginate and count object listings.

### Firebase Authentication (Identity Toolkit)

- API key from `GoogleService-Info.plist` `API_KEY`.
- Endpoints used to attempt to obtain an ID token for authenticated probes:
  - Anonymous: `POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}` with body `{ "returnSecureToken": true }`.
  - Email/password: `POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}` with body `{ "returnSecureToken": true, "email": "probe+<ts>@example.com", "password": "..." }`.
  - Purpose: Determine whether anonymous or email/password sign-up is enabled to obtain a token for “auth != null” checks.

### Cloud Functions

- Project ID from `GoogleService-Info.plist` `PROJECT_ID`.
- Probes a small wordlist of function names across a couple of common regions:
  - `GET https://{REGION}-{PROJECT_ID}.cloudfunctions.net/{FUNCTION}`
  - If HTTP 405 (method not allowed), also try `POST` with `{}`.
  - Purpose: Identify publicly exposed callable HTTP endpoints.

### Firebase Hosting

- Project ID from `GoogleService-Info.plist` `PROJECT_ID`.
- Probes:
  - `GET https://{PROJECT_ID}.web.app/` and `GET https://{PROJECT_ID}.firebaseapp.com/`
  - If accessible, also `GET __/firebase/init.json` to confirm hosting config exposure.

### How the scanner decides vulnerability and risk

- `audit.py` labels endpoints based on HTTP status:
  - RTDB: 200/201 on read = Open read; successful write = Critical (public write)
  - Firestore: 200/201 on `runQuery` with only `?key=` = Open read
  - Storage: 200/201 on list = Open; successful unauth upload = Critical
  - Functions/Hosting: 200 = Open
  - Auth: Successful signUp indicates anonymous or email/password enabled

- Auth phase: If an ID token is obtained, it re-tries Firestore/RTDB/Storage with `Authorization: Bearer <token>` or `auth=<token>` to detect rules like `auth != null` (accessible to any signed-in user).

- `summarize.py` reads the JSON audit output and:
  - Computes light counts for RTDB (top-level keys), Firestore (documents per discovered collections), Storage (objects), using REST pagination.
  - Keeps a folder only if there are vulnerabilities AND at least one count > 1.
  - Optionally downloads an IPA (via `ipatool`) for qualifying apps and extracts all `.plist` files into `all_plists/`.

### Performance and safety notes

- Small page sizes and shallow queries are used to reduce bandwidth.
- Retries are minimal with exponential backoff.
- Any write tests are immediately cleaned up when possible.
- No authenticated user credentials are stored; only tokens obtained via Identity Toolkit for probing.

### Future improvements (already outlined in README)

- Use Firestore `runAggregationQuery` COUNT(*) endpoints.
- Early exit once counts exceed thresholds (`> 1`).
- Parallel prefix sharding for Storage listing when exhaustive counts are required.
- Reuse a single HTTP session for connection pooling if switching to `requests`.


