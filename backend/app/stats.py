"""Статистика вердиктов Legion.

Считает, сколько проверок было безопасных / осторожных / опасных и т.д.
Основное хранилище — память процесса. Запись на диск best-effort и
вне критической секции (в Downloads/антивирусе sync-write иногда подвисает).
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

# backend/data/stats.json — можно переопределить через LEGION_STATS_PATH
_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "stats.json"
_STATS_PATH = Path(os.getenv("LEGION_STATS_PATH") or _DEFAULT_PATH)
_PERSIST = os.getenv("LEGION_STATS_PERSIST", "1") not in ("0", "false", "False")

_LOCK = threading.Lock()
_SAVE_LOCK = threading.Lock()
_DEDUP_TTL_SEC = 90
_STATUS_KEYS = ("safe", "caution", "danger", "continued", "other")


def _empty() -> dict[str, Any]:
    return {
        "started_at": time.time(),
        "updated_at": time.time(),
        "total": 0,
        "by_status": {k: 0 for k in _STATUS_KEYS},
        "by_source": {},
        "unique_hosts": 0,
        "hosts": {},
        "skipped_dupes": 0,
        "last_events": [],
    }


_STATE: dict[str, Any] = _empty()
_RECENT: dict[str, float] = {}


def _normalize_status(status: str) -> str:
    s = (status or "").lower().strip()
    if s in ("safe", "caution", "danger", "continued"):
        return s
    return "other"


def _load() -> None:
    global _STATE
    if not _PERSIST or not _STATS_PATH.exists():
        return
    try:
        data = json.loads(_STATS_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "by_status" not in data:
            return
        base = _empty()
        for k in ("started_at", "updated_at", "total", "skipped_dupes", "by_source", "last_events"):
            if k in data:
                base[k] = data[k]
        for k in _STATUS_KEYS:
            base["by_status"][k] = int((data.get("by_status") or {}).get(k) or 0)
        base["unique_hosts"] = int(data.get("unique_hosts") or 0)
        _STATE = base
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass


def _payload_for_disk() -> dict[str, Any]:
    return {
        "started_at": _STATE["started_at"],
        "updated_at": _STATE["updated_at"],
        "total": _STATE["total"],
        "by_status": dict(_STATE["by_status"]),
        "by_source": dict(_STATE["by_source"]),
        "unique_hosts": len(_STATE.get("hosts") or {}) or int(_STATE.get("unique_hosts") or 0),
        "skipped_dupes": _STATE["skipped_dupes"],
        "last_events": list(_STATE.get("last_events") or [])[-20:],
    }


def _save_async() -> None:
    """Не блокируем API: пишем в фоне, ошибки глотаем."""
    if not _PERSIST:
        return

    def worker() -> None:
        if not _SAVE_LOCK.acquire(blocking=False):
            return
        try:
            with _LOCK:
                payload = _payload_for_disk()
            _STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = _STATS_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(_STATS_PATH)
        except OSError:
            pass
        finally:
            _SAVE_LOCK.release()

    threading.Thread(target=worker, daemon=True).start()


_load()


def record_event(
    *,
    status: str,
    hostname: str = "",
    source: str = "",
    stage: str = "",
    risk: int | None = None,
) -> dict[str, Any]:
    """Записать один вердикт. Дубликаты hostname+status за 90 с игнорируются."""
    status_n = _normalize_status(status)
    host = (hostname or "").lower().strip()[:200]
    src = (source or "unknown").strip()[:80] or "unknown"
    now = time.time()
    dedupe_key = f"{host}|{status_n}"

    with _LOCK:
        stale = [k for k, ts in _RECENT.items() if now - ts > _DEDUP_TTL_SEC]
        for k in stale:
            _RECENT.pop(k, None)

        if host and dedupe_key in _RECENT:
            _STATE["skipped_dupes"] = int(_STATE.get("skipped_dupes") or 0) + 1
            _STATE["updated_at"] = now
            snap = _snapshot_unlocked()
            accepted = False
            reason = "duplicate"
        else:
            if host:
                _RECENT[dedupe_key] = now

            _STATE["total"] = int(_STATE.get("total") or 0) + 1
            _STATE["by_status"][status_n] = int(_STATE["by_status"].get(status_n) or 0) + 1
            _STATE["by_source"][src] = int(_STATE["by_source"].get(src) or 0) + 1
            if host:
                hosts = _STATE.setdefault("hosts", {})
                hosts[host] = int(hosts.get(host) or 0) + 1
            _STATE["unique_hosts"] = len(_STATE.get("hosts") or {})
            _STATE["updated_at"] = now

            event = {
                "ts": now,
                "status": status_n,
                "hostname": host or None,
                "source": src,
                "stage": (stage or "")[:40] or None,
                "risk": risk,
            }
            events = _STATE.setdefault("last_events", [])
            events.append(event)
            if len(events) > 30:
                del events[:-30]

            snap = _snapshot_unlocked()
            accepted = True
            reason = None

    if accepted:
        _save_async()

    out = {"accepted": accepted, **snap}
    if reason:
        out["reason"] = reason
    return out


def _snapshot_unlocked() -> dict[str, Any]:
    by = dict(_STATE.get("by_status") or {})
    for k in _STATUS_KEYS:
        by.setdefault(k, 0)
    return {
        "total": int(_STATE.get("total") or 0),
        "safe": by.get("safe", 0),
        "caution": by.get("caution", 0),
        "danger": by.get("danger", 0),
        "continued": by.get("continued", 0),
        "other": by.get("other", 0),
        "unique_hosts": int(_STATE.get("unique_hosts") or len(_STATE.get("hosts") or {})),
        "by_source": dict(_STATE.get("by_source") or {}),
        "skipped_dupes": int(_STATE.get("skipped_dupes") or 0),
        "started_at": _STATE.get("started_at"),
        "updated_at": _STATE.get("updated_at"),
        "last_events": list(_STATE.get("last_events") or [])[-10:],
    }


def snapshot() -> dict[str, Any]:
    with _LOCK:
        return _snapshot_unlocked()


def reset_stats() -> dict[str, Any]:
    global _STATE, _RECENT
    with _LOCK:
        _STATE = _empty()
        _RECENT = {}
        snap = _snapshot_unlocked()
    _save_async()
    return snap
