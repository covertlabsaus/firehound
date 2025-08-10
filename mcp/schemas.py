from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, HttpUrl, Field


class AppMetadata(BaseModel):
    name: str = Field(..., alias="trackName")
    developer_name: Optional[str] = Field(None, alias="sellerName")
    track_id: Optional[int] = Field(None, alias="trackId")
    track_view_url: Optional[HttpUrl] = Field(None, alias="trackViewUrl")
    icon_url: Optional[HttpUrl] = Field(None, alias="artworkUrl100")
    bundle_id: Optional[str] = Field(None, alias="bundleId")
    average_user_rating: Optional[float] = Field(None, alias="averageUserRating")
    user_rating_count: Optional[int] = Field(None, alias="userRatingCount")


class Candidate(BaseModel):
    bundle_id: Optional[str]
    score: float
    app: Optional[AppMetadata]


class Diagnostics(BaseModel):
    api_used: Optional[str] = None
    cache_hit: bool = False
    query_time_ms: Optional[int] = None
    notes: Optional[str] = None


class BundleIdResult(BaseModel):
    bundle_id: Optional[str]
    confidence: float
    source: str
    storefront: str = "us"
    app: Optional[AppMetadata] = None
    alternatives: List[Candidate] = []
    diagnostics: Optional[Diagnostics] = None


