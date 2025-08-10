from __future__ import annotations

import httpx
from typing import Any, Dict, List, Optional


ITUNES_SEARCH_URL = "https://itunes.apple.com/search"
ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup"


async def search_apps(term: str, country: str = "us", limit: int = 5) -> Dict[str, Any]:
    params = {
        "term": term,
        "entity": "software",
        "country": country,
        "limit": limit,
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
        r = await client.get(ITUNES_SEARCH_URL, params=params)
        r.raise_for_status()
        return r.json()


async def lookup_by_track_id(track_id: int, country: str = "us") -> Dict[str, Any]:
    params = {"id": track_id, "country": country}
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
        r = await client.get(ITUNES_LOOKUP_URL, params=params)
        r.raise_for_status()
        return r.json()


async def lookup_by_bundle_id(bundle_id: str, country: str = "us") -> Dict[str, Any]:
    params = {"bundleId": bundle_id, "country": country}
    async with httpx.AsyncClient(timeout=httpx.Timeout(8.0)) as client:
        r = await client.get(ITUNES_LOOKUP_URL, params=params)
        r.raise_for_status()
        return r.json()


