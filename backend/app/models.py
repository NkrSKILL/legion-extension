from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = ""
    hostname: str
    title: str = ""
    snippets: list[str] = Field(default_factory=list)
    has_sensitive_form: bool = True
    local_risk: int | None = None
    local_reasons: list[str] = Field(default_factory=list)
    brand_hits: list[str] = Field(default_factory=list)
    asset_hosts: list[str] = Field(default_factory=list)
    strictness: str = "normal"
    allow_llm: bool = False


class AnalyzeResponse(BaseModel):
    risk: int
    reasons: list[str]
    source: str
    used_llm: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class ThreatCheckRequest(BaseModel):
    url: str
    hostname: str = ""


class ThreatCheckResponse(BaseModel):
    hit: bool
    threats: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    source: str
    configured: bool = False
    cached: bool = False
    error: str | None = None


class StatsEventRequest(BaseModel):
    """Лёгкий отчёт о вердикте от расширения (без URL/snippets — приватность)."""

    status: str
    hostname: str = ""
    source: str = ""
    stage: str = ""
    risk: int | None = None


class StatsResponse(BaseModel):
    total: int = 0
    safe: int = 0
    caution: int = 0
    danger: int = 0
    continued: int = 0
    other: int = 0
    unique_hosts: int = 0
    by_source: dict[str, int] = Field(default_factory=dict)
    skipped_dupes: int = 0
    started_at: float | None = None
    updated_at: float | None = None
    last_events: list[dict[str, Any]] = Field(default_factory=list)
    accepted: bool | None = None
    reason: str | None = None
