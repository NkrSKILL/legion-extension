"""Автотесты Legion backend / эвристик.
Запуск из папки backend:
  python -m pip install -r requirements.txt
  python -m pytest tests -q
или:
  python tests/run_checks.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.heuristics import score_text
from app.brands import detect_brand_spoof
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["service"] == "legion-backend"


def test_phishing_text_high_risk():
    text = "Получите компенсацию от государства. Осталось 3 минуты. Введите пароль от Госуслуг"
    risk, reasons = score_text(text)
    assert risk >= 70
    assert any("срочн" in x.lower() or "таймер" in x.lower() for x in reasons)


def test_normal_login_low_risk():
    text = "Вход в аккаунт. Email. Пароль. Войти."
    risk, reasons = score_text(text)
    assert risk < 40


def test_brand_spoof_gosuslugi():
    hits = detect_brand_spoof("evil-pay.example", "Вход в Госуслуги")
    assert hits
    assert hits[0]["brand"] == "Госуслуги"


def test_brand_ok_on_real_domain():
    hits = detect_brand_spoof("gosuslugi.ru", "Вход в Госуслуги")
    assert hits == []


def test_analyze_phishing_endpoint():
    r = client.post(
        "/v1/analyze",
        json={
            "hostname": "pay-bonus.example",
            "url": "https://pay-bonus.example/login",
            "title": "Компенсация",
            "snippets": [
                "Осталось 3 минуты",
                "Введите пароль от Госуслуг",
                "Получите выплату",
            ],
            "has_sensitive_form": True,
            "allow_llm": False,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["risk"] >= 70
    assert data["used_llm"] is False


def test_analyze_normal_login_endpoint():
    r = client.post(
        "/v1/analyze",
        json={
            "hostname": "shop.example",
            "url": "https://shop.example/login",
            "title": "Вход",
            "snippets": ["Войдите в аккаунт", "Email", "Пароль", "Войти"],
            "has_sensitive_form": True,
            "allow_llm": False,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["risk"] < 55


def test_localhost_http_no_penalty_flood():
    """На 127.0.0.1 не должен один только HTTP давать огромный риск."""
    r = client.post(
        "/v1/analyze",
        json={
            "hostname": "127.0.0.1",
            "url": "http://127.0.0.1:8765/normal-login.html",
            "title": "Вход",
            "snippets": ["Войдите в аккаунт", "Email", "Пароль", "Войти"],
            "has_sensitive_form": True,
            "allow_llm": False,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["risk"] < 55
    assert not any("HTTP" in x for x in data["reasons"])


def test_brand_alias_not_matched_as_substring():
    """alias «вк» не должен ловиться в «доставка» / «заявка» / «ставка»."""
    text = "Оформите заявку. Выгодная ставка. Доставка завтра. Явка обязательна"
    assert detect_brand_spoof("shop.example", text) == []


def test_brand_alias_matched_as_word():
    hits = detect_brand_spoof("evil.example", "Войдите через ВК, чтобы продолжить")
    assert any(h["brand"] == "VK" for h in hits)


def test_brand_spoof_not_double_counted():
    """Если клиент уже начислил вес за spoof, backend не добавляет его второй раз."""
    common = {
        "hostname": "pay-bonus.example",
        "url": "https://pay-bonus.example/login",
        "has_sensitive_form": True,
        "local_risk": 60,
        "brand_hits": ["Сбер"],
        "allow_llm": False,
    }
    with_brand_text = client.post(
        "/v1/analyze",
        json={**common, "title": "Сбербанк Онлайн", "snippets": ["Вход в Сбербанк Онлайн"]},
    ).json()
    without_brand_text = client.post(
        "/v1/analyze", json={**common, "title": "Вход", "snippets": ["Вход в аккаунт"]}
    ).json()
    assert with_brand_text["risk"] == without_brand_text["risk"]
    # но причина про подмену бренда всё равно должна быть показана
    assert any("Сбер" in r for r in with_brand_text["reasons"])


def test_analyze_cache_reacts_to_content_change():
    """Тот же URL, но появился текст-давление — вердикт обязан пересчитаться."""
    base = {
        "hostname": "modal.example",
        "url": "https://modal.example/shop",
        "has_sensitive_form": True,
        "allow_llm": False,
    }
    quiet = client.post(
        "/v1/analyze", json={**base, "title": "Витрина", "snippets": ["Каталог товаров"]}
    ).json()
    loud = client.post(
        "/v1/analyze",
        json={
            **base,
            "title": "Компенсация",
            "snippets": ["Осталось 3 минуты", "Введите пароль от Госуслуг"],
        },
    ).json()
    assert loud["risk"] > quiet["risk"]


def test_threat_check_strips_query():
    """В Safe Browsing не должны уезжать токены из query."""
    captured: dict[str, str] = {}

    def fake_check(url: str) -> dict:
        captured["url"] = url
        return {
            "hit": False,
            "threats": [],
            "reasons": [],
            "source": "safe_browsing",
            "configured": True,
        }

    with mock.patch("app.main.check_url", fake_check):
        r = client.post(
            "/v1/threat-check",
            json={"url": "https://shop.example/pay?token=secret123#frag", "hostname": "shop.example"},
        )
    assert r.status_code == 200
    assert captured["url"] == "https://shop.example/pay"


def test_threat_check_without_key():
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SAFE_BROWSING_API_KEY", None)
        r = client.post(
            "/v1/threat-check",
            json={"url": "https://no-key-check.example/page", "hostname": "no-key-check.example"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["configured"] is False
    assert data["hit"] is False
    assert data["source"] == "safe_browsing_unconfigured"


def test_stats_event_and_get():
    from app import stats as stats_mod

    # память only — не трогаем диск
    stats_mod._PERSIST = False
    stats_mod.reset_stats()

    r = client.post(
        "/v1/stats/event",
        json={"status": "safe", "hostname": "yandex.ru", "source": "whitelist", "stage": "whitelist"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["accepted"] is True
    assert data["total"] == 1
    assert data["safe"] == 1

    r2 = client.post(
        "/v1/stats/event",
        json={"status": "safe", "hostname": "yandex.ru", "source": "whitelist"},
    )
    assert r2.json()["accepted"] is False
    assert r2.json()["total"] == 1

    r3 = client.post(
        "/v1/stats/event",
        json={"status": "danger", "hostname": "evil.example", "source": "brand_spoof", "risk": 92},
    )
    assert r3.json()["danger"] == 1
    assert r3.json()["total"] == 2

    got = client.get("/v1/stats").json()
    assert got["safe"] == 1
    assert got["danger"] == 1
    assert got["unique_hosts"] == 2


def test_stats_reset():
    from app import stats as stats_mod

    stats_mod._PERSIST = False
    stats_mod.reset_stats()
    client.post("/v1/stats/event", json={"status": "caution", "hostname": "shop.example"})
    r = client.post("/v1/stats/reset")
    assert r.status_code == 200
    assert r.json()["total"] == 0
    assert r.json()["caution"] == 0


def test_health_includes_stats():
    r = client.get("/health")
    assert r.status_code == 200
    assert "stats" in r.json()
    assert "total" in r.json()["stats"]


def test_idn_punycode_homograph():
    from app.brands import detect_homograph

    # xn--sberbnk-60a.ru декодируется в "sberbаnk.ru" (с кириллической 'а') -> бренд Сбер
    hits = detect_homograph("xn--sberbnk-60a.ru")
    assert hits
    assert hits[0]["brand"] == "Сбер"
    assert hits[0]["kind"] == "homograph"

    # xn--90a7a0b.ru ("сбер.ru" в Punycode) декодируется в "сбер.ru" -> бренд Сбер
    puny_sber = "сбер.ru".encode("idna").decode("ascii")
    hits_cyr = detect_homograph(puny_sber)
    assert hits_cyr
    assert hits_cyr[0]["brand"] == "Сбер"


def test_mixed_script_homograph():
    from app.brands import detect_homograph

    # sberbаnk.ru с кириллической 'а'
    hits = detect_homograph("sberb\u0430nk.ru")
    assert hits
    assert hits[0]["brand"] == "Сбер"


def test_zero_width_obfuscation_stripped_and_detected():
    from app.brands import detect_brand_spoof, has_zero_width_obfuscation

    spoofed_text = "Вход в Г\u200bос\u200cуслуги"
    assert has_zero_width_obfuscation(spoofed_text) is True
    hits = detect_brand_spoof("evil-login.example", spoofed_text)
    assert any(h["brand"] == "Госуслуги" for h in hits)


def test_asset_spoof_detection():
    from app.brands import detect_asset_spoof

    # Неизвестный домен подгружает логотип с официального CDN Госуслуг (gu-st.ru)
    hits = detect_asset_spoof("my-compensation-2026.org", ["gu-st.ru", "fonts.googleapis.com"])
    assert hits
    assert hits[0]["brand"] == "Госуслуги"
    assert hits[0]["asset_host"] == "gu-st.ru"

    # На самом gosuslugi.ru это легитимно
    assert detect_asset_spoof("lk.gosuslugi.ru", ["gu-st.ru"]) == []


def test_ml_url_classifier():
    from app.heuristics import evaluate_ml_url

    bad = evaluate_ml_url(
        "x9k2-secure-verify-account-8812.xyz",
        "https://x9k2-secure-verify-account-8812.xyz/login/update",
        has_sensitive_form=True,
    )
    assert bad["pct"] >= 60
    assert bad["score_boost"] >= 18

    good = evaluate_ml_url(
        "school-portal.ru",
        "https://school-portal.ru/schedule",
        has_sensitive_form=False,
    )
    assert good["pct"] < 40


def test_threat_feeds_stage2_hit():
    r = client.post(
        "/v1/threat-check",
        json={"url": "https://gosuslugi-vyplata.ru/claim", "hostname": "gosuslugi-vyplata.ru"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["hit"] is True
    assert data["source"] == "threat_feeds"
    assert "PHISHING_FEED" in data["threats"]


def test_feeds_status_endpoint():
    r = client.get("/v1/feeds/status")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["total_domains"] >= 15


def test_rdap_young_domain_detection():
    import json
    from datetime import datetime, timedelta, timezone
    from app.domain_intel import check_domain_age, _RDAP_CACHE

    _RDAP_CACHE.clear()
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fake_rdap = json.dumps(
        {"events": [{"eventAction": "registration", "eventDate": two_days_ago}]}
    ).encode("utf-8")

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return fake_rdap

    with mock.patch("urllib.request.urlopen", return_value=FakeResp()):
        res = check_domain_age("fresh-scam-2026.xyz")
    assert res["checked"] is True
    assert res["is_young"] is True
    assert res["age_days"] <= 3
    assert res["score_boost"] == 35


