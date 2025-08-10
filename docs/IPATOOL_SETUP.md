## ipatool setup and sign-in

This project uses `ipatool` to search, purchase (if needed), and download iOS apps from the App Store so their plists can be analyzed.

### Install

Choose one method and then verify with `ipatool --version`.

- macOS (Homebrew):
  - `brew install ipatool`
- Linux/WSL:
  - `./scripts/install_ipatool.sh` (tries prebuilt binaries and Go fallback), or
  - download a release from the project page and place the `ipatool` binary in your PATH (e.g., `/usr/local/bin`), `chmod +x` it
- Go (any OS):
  - `GOBIN=/usr/local/bin go install github.com/majd/ipatool/cmd/ipatool@latest`

### One‑time interactive sign‑in

Run this once to create a local, encrypted session so later downloads can be non‑interactive:

```bash
ipatool auth login
```

What you’ll be prompted for:
- Apple ID email and password
- Two‑factor code (if your Apple ID has 2FA enabled; recommended)
- Passphrase for the local keychain used by ipatool (you choose this)

Notes:
- The passphrase is NOT your Apple ID password. It encrypts ipatool’s local credential store on your machine.
- Remember the passphrase. The pipeline supplies it later via `IPATOOL_PASSPHRASE` so ipatool can unlock its store non‑interactively.
- If your Apple ID belongs to multiple providers/teams, ipatool may ask you to choose one. You can also pass it explicitly:
  - `ipatool auth login --provider SHORT_NAME`
  - To see current status/providers: `ipatool auth status` or `ipatool auth info`

### Non‑interactive usage (pipeline)

After the interactive login, you can run downloads without prompts by providing the same passphrase:

```bash
export IPATOOL_PASSPHRASE="<the passphrase you chose at login>"
# Example single download
ipatool download --bundle-identifier com.example.app --purchase
```

The pipeline uses this environment variable and feeds it to ipatool under the hood when running `--purchase` and `download` commands.

### Common issues

- Wrong passphrase
  - Symptom: ipatool asks for passphrase or errors with “invalid passphrase”.
  - Fix: export the correct `IPATOOL_PASSPHRASE`. If forgotten, `ipatool auth logout` (or remove the local store) and re‑run `ipatool auth login` to set a new passphrase.
- 2FA prompts in non‑interactive runs
  - You must complete `ipatool auth login` interactively at least once so a session is stored. After that, the pipeline should run without further 2FA prompts until the session expires.
- Multiple providers/teams
  - Provide `--provider SHORT_NAME` during `auth login` to bind the session to the right team.
- Purchases required
  - Use `--purchase` during download. Without it, some apps will fail to download if not already “owned”.

### Security

- The passphrase only protects the local ipatool credential store. Do not reuse sensitive passwords.
- Never commit your passphrase or Apple ID to git. Use environment variables and local `.env` files (which are ignored by `.gitignore`).

### Legal

- You must comply with Apple’s App Store Terms and all applicable laws. Only use `ipatool` for apps you are authorized to access.
- Do not misuse the tool to exfiltrate data or circumvent protections. This repository is for research and defensive analysis.
- If you find a potential vulnerability, practice responsible disclosure: report privately to the vendor and avoid public exploitation details until fixed.

### Verify your setup

```bash
ipatool --version
ipatool auth status   # should show you’re logged in and which provider is selected
```

If you need to sign out or reset:
```bash
ipatool auth logout
```

---

For end‑to‑end usage of this repository and pipeline, see `USAGE.md`.
