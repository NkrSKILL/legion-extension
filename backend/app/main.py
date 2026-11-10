from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from .brands import detect_asset_spoof, detect_brand_spoof, detect_homograph
from .domain_intel import check_domain_age
from .feeds import check_feed, feeds_status, refresh_feeds
from .heuristics import evaluate_ml_url, merge_risk, score_text
from .llm import analyze_with_llm, llm_configured
from .models import (
    AnalyzeRequest,
    AnalyzeResponse,
    StatsEventRequest,
    StatsResponse,
    ThreatCheckRequest,
    ThreatCheckResponse,
)
from .safebrowsing import check_url, safe_browsing_configured
from .stats import record_event, reset_stats, snapshot

APP_VERSION = "0.7.0"

app = FastAPI(title="Legion Backend", version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^chrome-extension://[a-z]{32}$",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

_CACHE: dict[str, tuple[float, AnalyzeResponse]] = {}
_TTL = 30 * 60


def _cache_get(key: str) -> AnalyzeResponse | None:
    hit = _CACHE.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > _TTL:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: AnalyzeResponse) -> None:
    if len(_CACHE) > 500:
        for k, _ in sorted(_CACHE.items(), key=lambda kv: kv[1][0])[:100]:
            _CACHE.pop(k, None)
    _CACHE[key] = (time.time(), value)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "legion-backend",
        "version": APP_VERSION,
        "llm_configured": llm_configured(),
        "safe_browsing_configured": safe_browsing_configured(),
        "feeds": feeds_status(),
        "stats": snapshot(),
    }


@app.get("/v1/stats", response_model=StatsResponse)
def get_stats() -> StatsResponse:
    return StatsResponse(**snapshot())


@app.post("/v1/stats/event", response_model=StatsResponse)
def post_stats_event(req: StatsEventRequest) -> StatsResponse:
    """Принять вердикт от расширения. Не влияет на анализ — только учёт."""
    result = record_event(
        status=req.status,
        hostname=req.hostname,
        source=req.source,
        stage=req.stage,
        risk=req.risk,
    )
    return StatsResponse(**result)


@app.post("/v1/stats/reset", response_model=StatsResponse)
def post_stats_reset() -> StatsResponse:
    return StatsResponse(**reset_stats())


@app.get("/v1/feeds/status")
def get_feeds_status() -> dict[str, Any]:
    return feeds_status()


@app.post("/v1/feeds/refresh")
def post_feeds_refresh() -> dict[str, Any]:
    return refresh_feeds()


def _strip_query(url: str) -> str:
    """Наружу уходит только origin + path: в query бывают токены и идентификаторы."""
    try:
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return url
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except ValueError:
        return url


@app.post("/v1/threat-check", response_model=ThreatCheckResponse)
def threat_check(req: ThreatCheckRequest) -> ThreatCheckResponse:
    """Этап 2: Фиды активного фишинга (OpenPhish / URLhaus) + Google Safe Browsing."""
    clean_url = _strip_query(req.url)

    feed_hit = check_feed(clean_url, req.hostname)
    if feed_hit.get("hit"):
        return ThreatCheckResponse(
            hit=True,
            threats=["PHISHING_FEED"],
            reasons=list(feed_hit.get("reasons") or []),
            source="threat_feeds",
            configured=True,
            cached=False,
        )

    result = check_url(clean_url)
    return ThreatCheckResponse(
        hit=bool(result.get("hit")),
        threats=list(result.get("threats") or []),
        reasons=list(result.get("reasons") or []),
        source=str(result.get("source") or "safe_browsing"),
        configured=bool(result.get("configured")),
        cached=bool(result.get("cached")),
        error=result.get("error"),
    )


def _content_fingerprint(req: AnalyzeRequest) -> str:
    raw = "||".join(
        [
            req.title,
            "|".join(req.snippets),
            str(req.local_risk),
            ",".join(req.brand_hits),
            ",".join(req.asset_hosts),
        ]
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


@app.post("/v1/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    cache_key = (
        f"{req.hostname}|{req.url}|{req.strictness}|{int(req.allow_llm)}|{_content_fingerprint(req)}"
    )
    cached = _cache_get(cache_key)
    if cached:
        return cached

    text = f"{req.title}\n" + "\n".join(req.snippets)
    h_risk, h_reasons = score_text(text)

    brand_hits = detect_brand_spoof(req.hostname, text)
    if brand_hits:
        if not req.brand_hits and req.has_sensitive_form:
            h_risk = min(100, h_risk + 42)
        for b in brand_hits:
            h_reasons.append(b["reason"])

    homograph_hits = detect_homograph(req.hostname)
    if homograph_hits and req.has_sensitive_form:
        if req.local_risk is None:
            h_risk = min(100, h_risk + 55)
        for h in homograph_hits:
            h_reasons.append(h["reason"])

    asset_hits = detect_asset_spoof(req.hostname, req.asset_hosts)
    if asset_hits and req.has_sensitive_form:
        if req.local_risk is None:
            h_risk = min(100, h_risk + 45)
        for a in asset_hits:
            h_reasons.append(a["reason"])

    ml_info = evaluate_ml_url(req.hostname, req.url, req.has_sensitive_form)
    if ml_info["score_boost"] > 0:
        if req.local_risk is None:
            h_risk = min(100, h_risk + int(ml_info["score_boost"]))
        if ml_info["reason"]:
            h_reasons.append(str(ml_info["reason"]))

    rdap_info = check_domain_age(req.hostname)
    if rdap_info.get("is_young") and req.has_sensitive_form:
        h_risk = min(100, h_risk + int(rdap_info.get("score_boost") or 35))
        if rdap_info.get("reason"):
            h_reasons.append(str(rdap_info["reason"]))

    if req.url.startswith("http://") and req.has_sensitive_form:
        host = (urlsplit(req.url).hostname or "").lower()
        is_local = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local")
        if not is_local:
            h_risk = min(100, h_risk + 15)
            h_reasons.append("Чувствительная форма на незащищённом HTTP")

    if req.local_risk is not None:
        h_risk = merge_risk(h_risk, req.local_risk)
    for r in req.local_reasons:
        if r not in h_reasons:
            h_reasons.append(r)

    used_llm = False
    source = "backend_heuristics"

    if req.allow_llm and llm_configured():
        llm = analyze_with_llm(req.hostname, req.title, req.snippets, h_risk)
        if llm:
            used_llm = True
            source = "backend_llm"
            h_risk = merge_risk(h_risk, int(llm["risk"]))
            for r in llm.get("reasons") or []:
                if r not in h_reasons:
                    h_reasons.append(r)

    if not h_reasons:
        h_reasons = ["Чувствительная форма найдена, манипулятивных маркеров не обнаружено"]

    resp = AnalyzeResponse(
        risk=min(100, int(h_risk)),
        reasons=list(dict.fromkeys(h_reasons))[:10],
        source=source,
        used_llm=used_llm,
        details={
            "brand_hits": [b.get("brand") for b in brand_hits],
            "homograph_hits": [h.get("brand") for h in homograph_hits],
            "asset_hits": [a.get("brand") for a in asset_hits],
            "ml_probability": ml_info["probability"],
            "domain_age_days": rdap_info.get("age_days"),
            "snippet_count": len(req.snippets),
        },
    )
    _cache_set(cache_key, resp)
    return resp
