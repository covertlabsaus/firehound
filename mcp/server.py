from __future__ import annotations

import asyncio
from fastmcp import FastMCP
from pydantic import BaseModel

from .service_bundleid import resolve_by_name, resolve_by_url, verify_bundle_id
from .utils_ipa import extract_bundle_id_from_ipa


mcp = FastMCP("firehound-bundleid")


class NameInput(BaseModel):
    term: str
    country: str = "us"
    limit: int = 5
    developer_hint: str | None = None


class UrlInput(BaseModel):
    url: str
    country: str = "us"


class VerifyInput(BaseModel):
    bundle_id: str
    country: str = "us"


class IpaInput(BaseModel):
    path: str
    max_size_mb: int = 50


@mcp.tool()
async def get_bundle_id_by_name(input: NameInput):
    """Resolve bundle ID from an app name search. Returns top match and alternatives."""
    return (await resolve_by_name(input.term, input.country, input.limit, input.developer_hint)).model_dump()


@mcp.tool()
async def get_bundle_id_by_url(input: UrlInput):
    """Resolve bundle ID from an App Store URL."""
    return (await resolve_by_url(input.url, input.country)).model_dump()


@mcp.tool()
async def get_bundle_id_from_ipa(input: IpaInput):
    """Extract bundle ID directly from an IPA file on disk."""
    bid = extract_bundle_id_from_ipa(input.path, input.max_size_mb)
    return {"bundle_id": bid, "confidence": 0.99 if bid else 0.0, "source": "ipa", "storefront": "n/a"}


@mcp.tool()
async def verify(input: VerifyInput):
    """Verify that a given bundle ID exists in the App Store and return its metadata."""
    return (await verify_bundle_id(input.bundle_id, input.country)).model_dump()


def main():
    mcp.run()


if __name__ == "__main__":
    main()


