from __future__ import annotations

from typing import List, Optional

from .providers_itunes import search_apps, lookup_by_track_id, lookup_by_bundle_id
from .schemas import AppMetadata, BundleIdResult, Candidate, Diagnostics
from .utils_scoring import score_app


async def resolve_by_name(term: str, country: str = "us", limit: int = 5, developer_hint: str | None = None) -> BundleIdResult:
    raw = await search_apps(term=term, country=country, limit=limit)
    results = raw.get("results", [])
    candidates: List[Candidate] = []
    for item in results:
        meta = AppMetadata.model_validate(item)
        s = score_app(term, meta.name, meta.developer_name, developer_hint)
        candidates.append(Candidate(bundle_id=item.get("bundleId"), score=s, app=meta))

    candidates.sort(key=lambda c: c.score, reverse=True)
    top = candidates[0] if candidates else None
    confidence = top.score if top else 0.0
    return BundleIdResult(
        bundle_id=top.bundle_id if top else None,
        confidence=confidence,
        source="search",
        storefront=country,
        app=top.app if top else None,
        alternatives=candidates[1:5],
        diagnostics=Diagnostics(api_used="itunes-search", cache_hit=False),
    )


async def resolve_by_url(url: str, country: str = "us") -> BundleIdResult:
    # Extract trackId from canonical URL if present
    import re

    m = re.search(r"id(\d+)", url)
    if m:
        track_id = int(m.group(1))
        raw = await lookup_by_track_id(track_id, country)
        results = raw.get("results", [])
        if results:
            item = results[0]
            meta = AppMetadata.model_validate(item)
            return BundleIdResult(
                bundle_id=item.get("bundleId"),
                confidence=0.95,
                source="lookup",
                storefront=country,
                app=meta,
                alternatives=[],
                diagnostics=Diagnostics(api_used="itunes-lookup", cache_hit=False),
            )
    # Fallback: use last path token as term
    term = url.strip().split("/")[-1].replace("-", " ")
    return await resolve_by_name(term, country)


async def verify_bundle_id(bundle_id: str, country: str = "us") -> BundleIdResult:
    raw = await lookup_by_bundle_id(bundle_id, country)
    results = raw.get("results", [])
    if results:
        item = results[0]
        meta = AppMetadata.model_validate(item)
        return BundleIdResult(
            bundle_id=bundle_id,
            confidence=0.98,
            source="lookup",
            storefront=country,
            app=meta,
            alternatives=[],
            diagnostics=Diagnostics(api_used="itunes-lookup", cache_hit=False),
        )
    return BundleIdResult(bundle_id=None, confidence=0.0, source="lookup", storefront=country, alternatives=[])


