from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .brands import has_zero_width_obfuscation, strip_zero_width


@dataclass
class HeuristicHit:
    score: int
    reason: str


PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"осталось\s+\d+\s*(мин|минут|секунд|sec|min)", re.I), 35, "Искусственная срочность (таймер)"),
    (re.compile(r"компенсац|выплат[аыуе]|начислен(ие|о)|возврат\s+средств", re.I), 28, "Обещание выплат / компенсации"),
    (
        re.compile(r"пароль\s+от\s+(telegram|телеграм|steam|стим|discord|дискорд|вк|vk|госуслуг)", re.I),
        48,
        "Просьба пароля от стороннего сервиса",
    ),
    (re.compile(r"аккаунт\s+будет\s+заблокир|срочно\s+подтверд|иначе\s+блокир", re.I), 35, "Давление и угроза блокировки"),
    (re.compile(r"введите\s+пароль\s+от\s+госуслуг", re.I), 50, "Фишинговая имитация Госуслуг"),
    (re.compile(r"лёгк(ие|ая)\s+деньг|халяв|бесплатн(о|ые)\s+деньг|лёгкий\s+заработок", re.I), 30, "Обещание лёгкой наживы"),
    (
        re.compile(r"подтвердите\s+(данные|личность|вход).{0,40}(карт|парол|смс|код)", re.I),
        22,
        "Подозрительное подтверждение через секреты",
    ),
    (
        re.compile(r"розыгрыш|бесплатн(ый|ая)\s+skin|скин[ыа].{0,20}(парол|steam|логин)", re.I),
        32,
        "Скам вокруг игровых аккаунтов/скинов",
    ),
    (
        re.compile(r"security\s+alert|unusual\s+sign-?in|verify\s+your\s+account\s+now", re.I),
        24,
        "Типовой англоязычный phishing-шаблон",
    ),
    (re.compile(r"подарочн(ая|ый)\s+карт|gift\s*card.{0,30}(login|парол|steam)", re.I), 26, "Подозрительный gift-card скам"),
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
    "sbs", "cfd", "icu", "buzz", "rest", "cam", "monster", "quest", "zip", "mov",
}

PHISH_URL_TOKENS = (
    "verify", "verification", "secure", "security", "update", "confirm",
    "unlock", "suspend", "bonus", "vyplata", "kompens", "gosuslugi",
    "sber", "tbank", "tinkoff", "vtb", "priz", "gift", "claim", "recover",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def evaluate_ml_url(hostname: str, url: str, has_sensitive_form: bool = True) -> dict[str, Any]:
    host = (hostname or "").lower().removeprefix("www.")
    if not host or host in {"localhost", "127.0.0.1", "::1"} or host.startswith("local-file"):
        return {"probability": 0.05, "score_boost": 0, "reason": None}

    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    main_label = parts[0] if parts else ""
    host_body = ".".join(parts[:-1])

    is_ip = len(parts) == 4 and all(p.isdigit() for p in parts)
    hyphens = host_body.count("-")
    digits = sum(ch.isdigit() for ch in host_body)
    digit_ratio = digits / len(host_body) if host_body else 0.0
    sub_depth = max(0, len(parts) - 2)
    entropy = shannon_entropy(main_label)
    suspicious_tld = tld in SUSPICIOUS_TLDS
    is_idn = "xn--" in host

    try:
        sp = urlsplit(url or "")
        path_and_host = f"{sp.hostname or host}{sp.path or ''}".lower()
    except ValueError:
        path_and_host = host

    tokens = [t for t in PHISH_URL_TOKENS if t in path_and_host]

    z = -2.35
    factors: list[str] = []
    if is_ip:
        z += 2.2
        factors.append("IP-хост")
    if suspicious_tld:
        z += 1.25
        factors.append(f"зона .{tld}")
    if is_idn:
        z += 1.4
        factors.append("IDN/Punycode")
    if hyphens >= 2:
        z += 0.95 + min(0.6, (hyphens - 2) * 0.3)
        factors.append(f"дефисов: {hyphens}")
    if digit_ratio >= 0.2 and digits >= 2:
        z += 0.75
        factors.append("много цифр в домене")
    if sub_depth >= 2:
        z += 0.65
        factors.append("глубокие поддомены")
    if entropy >= 3.65 and len(main_label) >= 12:
        z += 0.8
        factors.append(f"энтропия {entropy}")
    if len(tokens) >= 2:
        z += 1.1
        factors.append(f"маркеры URL ({', '.join(tokens[:2])})")
    elif len(tokens) == 1 and (suspicious_tld or hyphens >= 1):
        z += 0.65
        factors.append(f"маркер «{tokens[0]}»")

    prob = round(1.0 / (1.0 + math.exp(-z)), 3)
    pct = round(prob * 100)
    score_boost = 0
    reason = None
    if prob >= 0.75 and has_sensitive_form:
        score_boost = 32
        reason = f"ML-модель структуры URL: {pct}% вероятности однодневки ({', '.join(factors[:3])})"
    elif prob >= 0.55 and has_sensitive_form:
        score_boost = 18
        reason = f"ML-модель структуры URL: повышенный риск {pct}% ({', '.join(factors[:2])})"

    return {"probability": prob, "pct": pct, "score_boost": score_boost, "reason": reason}


def score_text(text: str) -> tuple[int, list[str]]:
    raw = text or ""
    cleaned = strip_zero_width(raw)
    risk = 8
    reasons: list[str] = []

    if has_zero_width_obfuscation(raw):
        risk += 32
        reasons.append("Маскировка текста невидимыми символами (Zero-Width Obfuscation)")

    for pattern, score, reason in PATTERNS:
        if pattern.search(cleaned):
            risk += score
            reasons.append(reason)
    return min(risk, 100), list(dict.fromkeys(reasons))


def merge_risk(*parts: int) -> int:
    vals = [max(0, min(100, int(p))) for p in parts if p is not None]
    if not vals:
        return 0
    primary = max(vals)
    boost = sum(v for v in vals if v != primary) // 4
    return min(100, primary + boost)
