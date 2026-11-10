from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

# brands.json лежит в ../data относительно backend — используем extension data
BRANDS_PATH = Path(__file__).resolve().parents[2] / "data" / "brands.json"

BRAND_ASSET_DOMAINS: dict[str, list[str]] = {
    "Госуслуги": ["gosuslugi.ru", "gu-st.ru", "esia.gosuslugi.ru"],
    "Сбер": ["sberbank.ru", "sber.ru", "sberbank.com"],
    "Т-Банк": ["tbank.ru", "tinkoff.ru", "cdn-tinkoff.ru"],
    "ВТБ": ["vtb.ru"],
    "Альфа-Банк": ["alfabank.ru"],
    "Яндекс": ["yandex.ru", "ya.ru", "yastatic.net", "yandex.net"],
    "VK": ["vk.com", "vk.ru", "userapi.com", "vkuserphoto.ru"],
    "Telegram": ["telegram.org", "t.me", "telesco.pe"],
    "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "Wildberries": ["wildberries.ru", "wb.ru", "wbbasket.ru"],
    "Ozon": ["ozon.ru", "ozone.ru"],
}

CONFUSABLE_MAP: dict[str, str] = {
    "а": "a", "ɑ": "a", "α": "a", "ạ": "a", "ä": "a",
    "б": "b", "в": "b", "ß": "b", "β": "b",
    "с": "c", "ϲ": "c", "ç": "c",
    "е": "e", "є": "e", "ε": "e", "ё": "e",
    "і": "i", "ї": "i", "ɪ": "i", "ι": "i", "1": "i", "l": "i",
    "ј": "j",
    "к": "k", "κ": "k",
    "м": "m",
    "н": "h", "η": "h",
    "о": "o", "ο": "o", "0": "o", "ö": "o",
    "р": "p", "ρ": "p",
    "ѕ": "s", "5": "s",
    "т": "t", "τ": "t",
    "у": "y", "ү": "y",
    "х": "x", "χ": "x",
    "г": "r",
    "п": "n",
    "и": "u", "υ": "u",
}

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]")


def strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text or "")


def has_zero_width_obfuscation(text: str) -> bool:
    return len(_ZERO_WIDTH_RE.findall(text or "")) >= 2


def decode_idn_host(hostname: str) -> str:
    host = (hostname or "").strip().lower()
    if not host:
        return ""
    out: list[str] = []
    for part in host.split("."):
        if part.startswith("xn--"):
            try:
                out.append(part.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        out.append(part)
    return ".".join(out)


def to_latin_skeleton(text: str) -> str:
    cleaned = strip_zero_width(text).lower()
    return "".join(CONFUSABLE_MAP.get(ch, ch) for ch in cleaned)


@lru_cache(maxsize=1)
def load_brands() -> dict:
    if not BRANDS_PATH.exists():
        return {"brands": []}
    return json.loads(BRANDS_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _alias_patterns() -> tuple[tuple[str, tuple[str, ...], tuple[re.Pattern[str], ...]], ...]:
    compiled = []
    for brand in load_brands().get("brands", []):
        aliases = tuple(str(a).lower() for a in brand.get("aliases", []))
        patterns = tuple(
            re.compile(rf"(?<!\w){re.escape(alias)}(?!\w)", re.UNICODE) for alias in aliases
        )
        domains = tuple(str(d).lower() for d in brand.get("domains", []))
        compiled.append((str(brand.get("name")), domains, patterns))
    return tuple(compiled)


def _host_allowed(host: str, domains: tuple[str, ...] | list[str]) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in domains)


def detect_brand_spoof(hostname: str, text: str) -> list[dict]:
    host = (hostname or "").lower()
    text_l = strip_zero_width(text or "").lower()
    if not text_l.strip():
        return []

    hits: list[dict] = []
    for name, domains, patterns in _alias_patterns():
        if not any(p.search(text_l) for p in patterns):
            continue
        if _host_allowed(host, domains):
            continue
        hits.append(
            {
                "brand": name,
                "reason": f"Упоминается «{name}», но домен {hostname} ему не принадлежит",
            }
        )
    return hits


def detect_homograph(hostname: str) -> list[dict]:
    raw_host = (hostname or "").lower().removeprefix("www.")
    if not raw_host or raw_host.startswith("local-file") or raw_host == "unknown-host":
        return []

    decoded = decode_idn_host(raw_host)
    is_punycode = "xn--" in raw_host or decoded != raw_host
    host_label = decoded.split(".")[0]
    skeleton = to_latin_skeleton(host_label)
    has_cyr = bool(re.search(r"[а-яё]", host_label))

    hits: list[dict] = []
    for brand in load_brands().get("brands", []):
        name = str(brand.get("name"))
        domains = [str(d).lower() for d in brand.get("domains", [])]
        aliases = [str(a).lower() for a in brand.get("aliases", [])]
        if _host_allowed(raw_host, domains):
            continue

        matched = False
        for d in domains:
            base_name = d.removeprefix("www.").split(".")[0]
            if len(base_name) < 4:
                continue
            base_skel = to_latin_skeleton(base_name)
            if skeleton == base_skel or (is_punycode and base_skel in skeleton):
                hits.append(
                    {
                        "brand": name,
                        "kind": "homograph",
                        "decoded_host": decoded,
                        "reason": (
                            f"IDN-омограф ({decoded}): криптографическая подмена букв под «{name}»"
                            if is_punycode
                            else f"Подмена символов в домене под «{name}» ({raw_host})"
                        ),
                    }
                )
                matched = True
                break

        if matched:
            continue

        if is_punycode or has_cyr:
            for alias in aliases:
                if len(alias) < 3:
                    continue
                alias_skel = to_latin_skeleton(alias)
                if (
                    host_label == alias
                    or (len(alias) >= 4 and alias in host_label)
                    or (len(alias_skel) >= 4 and skeleton == alias_skel)
                ):
                    hits.append(
                        {
                            "brand": name,
                            "kind": "homograph",
                            "decoded_host": decoded,
                            "reason": f"IDN-омограф ({decoded}): домен маскируется под бренд «{name}»",
                        }
                    )
                    break

    return hits


def detect_asset_spoof(hostname: str, asset_hosts: list[str] | None = None) -> list[dict]:
    host = (hostname or "").lower().removeprefix("www.")
    if not host or not asset_hosts:
        return []

    hits: list[dict] = []
    for name, domains, _ in _alias_patterns():
        official = list(domains) + [d.lower() for d in BRAND_ASSET_DOMAINS.get(name, [])]
        if _host_allowed(host, official):
            continue
        stolen = next(
            (
                ah
                for ah in asset_hosts
                if any(ah.lower() == od or ah.lower().endswith("." + od) for od in official)
            ),
            None,
        )
        if stolen:
            hits.append(
                {
                    "brand": name,
                    "asset_host": stolen,
                    "reason": f"Визуальная мимикрия: страница подгружает логотипы/ресурсы «{name}» ({stolen}) на чужом домене",
                }
            )
    return hits
