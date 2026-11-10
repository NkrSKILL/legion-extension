from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

_RDAP_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_RDAP_TTL = 6 * 3600

_SKIP_SUFFIXES = (".example", ".test", ".local", ".invalid", ".localhost", ".internal")
_SKIP_HOSTS = {"localhost", "127.0.0.1", "::1", "unknown-host"}


def _registrable_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().removeprefix("www.")
    if not host or host in _SKIP_HOSTS or host.startswith("local-file"):
        return ""
    if any(host.endswith(s) for s in _SKIP_SUFFIXES):
        return ""
    if re_is_ip(host):
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return ""
    # Двухуровневые зоны вида co.uk / com.ru / org.ru
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def re_is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _parse_iso_date(raw: str) -> datetime | None:
    if not raw:
        return None
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def check_domain_age(hostname: str, timeout: float = 1.5) -> dict[str, Any]:
    """Проверка возраста регистрации домена через публичный RDAP.

    Свежезарегистрированные домены (< 30 дней) — классический признак однодневки.
    """
    domain = _registrable_domain(hostname)
    if not domain:
        return {"checked": False, "domain": "", "age_days": None, "is_young": False}

    if os.getenv("LEGION_RDAP_ENABLED", "1") == "0":
        return {"checked": False, "domain": domain, "age_days": None, "is_young": False}

    cached = _RDAP_CACHE.get(domain)
    if cached and (time.time() - cached[0] < _RDAP_TTL):
        return {**cached[1], "cached": True}

    req = urllib.request.Request(
        f"https://rdap.org/domain/{domain}",
        headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Legion-AntiPhish/0.7"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        result = {"checked": False, "domain": domain, "age_days": None, "is_young": False}
        _RDAP_CACHE[domain] = (time.time(), result)
        return result

    reg_dt: datetime | None = None
    for ev in data.get("events") or []:
        action = str(ev.get("eventAction") or "").lower()
        if action in {"registration", "registered"}:
            reg_dt = _parse_iso_date(str(ev.get("eventDate") or ""))
            if reg_dt:
                break

    if not reg_dt:
        result = {"checked": True, "domain": domain, "age_days": None, "is_young": False}
        _RDAP_CACHE[domain] = (time.time(), result)
        return result

    now = datetime.now(timezone.utc)
    age_days = max(0, (now - reg_dt).days)
    is_young = age_days <= 30

    result = {
        "checked": True,
        "domain": domain,
        "age_days": age_days,
        "is_young": is_young,
        "score_boost": 35 if is_young else 0,
        "reason": (
            f"Домен-однодневка (RDAP): {domain} зарегистрирован всего {age_days} дн. назад"
            if is_young
            else None
        ),
    }
    _RDAP_CACHE[domain] = (time.time(), result)
    return result
