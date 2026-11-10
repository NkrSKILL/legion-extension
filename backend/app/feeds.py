from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "threat_feeds.json"

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"

# Стартовый офлайн-индекс типовых доменов фишинговых китов (работает сразу даже без сети)
SEED_PHISH_DOMAINS = {
    "phishing-demo.test",
    "gosuslugi-vyplata.ru",
    "gosuslugi-vyplata.xyz",
    "gosuslugi-kompensaciya.top",
    "gosuslugi-posobie-2026.ru",
    "sber-online-verify.xyz",
    "sberbank-bonus-pay.ru",
    "tbank-security-check.top",
    "tinkoff-cashback-prize.ru",
    "vtb-invest-claim.xyz",
    "alfabank-verify-card.top",
    "vk-security-unlock.xyz",
    "steam-free-skins-drop.xyz",
    "steamcommunity-gift-claim.top",
    "telegram-web-verify.top",
    "ozon-prize-bonus.click",
    "wildberries-vozvrat-lk.xyz",
    "yandex-id-security-alert.top",
}

_FEED_DOMAINS: set[str] = set(SEED_PHISH_DOMAINS)
_UPDATED_AT: float | None = None
_SOURCES: list[str] = ["builtin_seed"]
_LOADED = False


def _ensure_loaded() -> None:
    global _LOADED, _UPDATED_AT, _SOURCES
    if _LOADED:
        return
    _LOADED = True
    if DATA_FILE.exists():
        try:
            raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            domains = raw.get("domains") or []
            _FEED_DOMAINS.update(str(d).lower() for d in domains if d)
            _UPDATED_AT = raw.get("updated_at")
            _SOURCES = list(raw.get("sources") or ["builtin_seed"])
        except (OSError, json.JSONDecodeError):
            pass


def _save_to_disk() -> None:
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": _UPDATED_AT,
            "sources": _SOURCES,
            "count": len(_FEED_DOMAINS),
            "domains": sorted(_FEED_DOMAINS)[:25000],
        }
        DATA_FILE.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _extract_host(line: str) -> str:
    s = line.strip()
    if not s or s.startswith("#"):
        return ""
    try:
        if "://" in s:
            host = (urlsplit(s).hostname or "").lower()
        else:
            host = s.split("/")[0].split(":")[0].lower()
    except ValueError:
        return ""
    host = host.removeprefix("www.")
    if not host or "." not in host:
        return ""
    return host


def _fetch_text(url: str, timeout: float = 5.0) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Legion-AntiPhish-FeedSync/0.7"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def refresh_feeds(timeout: float = 5.0) -> dict[str, Any]:
    """Подтянуть свежие фишинговые домены из OpenPhish и URLhaus."""
    global _UPDATED_AT, _SOURCES
    _ensure_loaded()

    added = 0
    active_sources = ["builtin_seed"]

    for name, url in (("openphish", OPENPHISH_FEED_URL), ("urlhaus", URLHAUS_FEED_URL)):
        try:
            text = _fetch_text(url, timeout=timeout)
            before = len(_FEED_DOMAINS)
            for line in text.splitlines():
                h = _extract_host(line)
                if h:
                    _FEED_DOMAINS.add(h)
            added += len(_FEED_DOMAINS) - before
            active_sources.append(name)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue

    _UPDATED_AT = time.time()
    _SOURCES = active_sources
    _save_to_disk()

    return {
        "ok": True,
        "total_domains": len(_FEED_DOMAINS),
        "added": added,
        "sources": _SOURCES,
        "updated_at": _UPDATED_AT,
    }


def feeds_status() -> dict[str, Any]:
    _ensure_loaded()
    return {
        "ok": True,
        "total_domains": len(_FEED_DOMAINS),
        "sources": _SOURCES,
        "updated_at": _UPDATED_AT,
    }


def check_feed(url: str, hostname: str = "") -> dict[str, Any]:
    """Быстрая O(1) проверка домена и его родительских суффиксов по фидам угроз."""
    _ensure_loaded()
    host = (hostname or _extract_host(url)).lower().removeprefix("www.")
    if not host:
        return {"hit": False}

    # Проверяем сам хост и его родительские домены
    parts = host.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if "." in candidate and candidate in _FEED_DOMAINS:
            return {
                "hit": True,
                "matched_domain": candidate,
                "source": "threat_feeds",
                "reasons": [f"Домен {candidate} найден в базе фишинговых фидов (OpenPhish / URLhaus / Legion)"],
            }
    return {"hit": False}
