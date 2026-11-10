from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_SB_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_SB_TTL = 15 * 60


def safe_browsing_configured() -> bool:
    return bool(os.getenv("SAFE_BROWSING_API_KEY"))


def _cache_get(url: str) -> dict[str, Any] | None:
    hit = _SB_CACHE.get(url)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > _SB_TTL:
        _SB_CACHE.pop(url, None)
        return None
    return value


def _cache_set(url: str, value: dict[str, Any]) -> None:
    if len(_SB_CACHE) > 1000:
        for k, _ in sorted(_SB_CACHE.items(), key=lambda kv: kv[1][0])[:200]:
            _SB_CACHE.pop(k, None)
    _SB_CACHE[url] = (time.time(), value)


def check_url(url: str) -> dict[str, Any]:
    """Google Safe Browsing Lookup API v4."""
    cached = _cache_get(url)
    if cached is not None:
        return {**cached, "cached": True}

    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        return {
            "hit": False,
            "threats": [],
            "reasons": [],
            "source": "safe_browsing_unconfigured",
            "configured": False,
        }

    body = {
        "client": {"clientId": "legion-extension", "clientVersion": "0.5.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    req = urllib.request.Request(
        f"{SAFE_BROWSING_URL}?key={api_key}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        return {
            "hit": False,
            "threats": [],
            "reasons": [],
            "source": "safe_browsing_error",
            "configured": True,
            "error": f"HTTP {e.code}",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return {
            "hit": False,
            "threats": [],
            "reasons": [],
            "source": "safe_browsing_error",
            "configured": True,
            "error": str(e),
        }

    matches = data.get("matches") or []
    threats = sorted({m.get("threatType") for m in matches if m.get("threatType")})
    hit = len(matches) > 0
    reasons = [f"Google Safe Browsing: {t}" for t in threats] if hit else []

    result = {
        "hit": hit,
        "threats": threats,
        "reasons": reasons,
        "source": "safe_browsing",
        "configured": True,
        "cached": False,
    }
    _cache_set(url, result)
    return result
