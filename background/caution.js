/**
 * Жёлтый режим Legion (осторожность, без оверлея).
 *
 * A: неизвестный сайт + критичные поля (пароль/карта/ПДн)
 * B: мягкие ПДн (email/телефон/ФИО) + доп.сигнал
 */

function isLocalHost(hostname = "", url = "") {
  const host = (hostname || "").toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".local")) {
    return true;
  }
  if (host.startsWith("local-file")) return true;
  try {
    if (url) {
      const u = new URL(url);
      if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return true;
    }
  } catch (_) {}
  return false;
}

/**
 * @param {object} payload
 * @param {{ lookalikes?: object[], httpInsecure?: boolean, brandHits?: object[] }} extra
 */
export function evaluateCaution(payload, extra = {}) {
  const fields = payload.fields || {};
  const textHints = payload.textHints || {};
  const hasCritical = !!(fields.password || fields.card || fields.govId || fields.otp);
  const hasSoftPii = !!(fields.email || fields.phone || fields.name);
  // догадка по тексту модалки — только мягкий сигнал, не критичное поле
  const hintsLogin = !!(textHints.password || textHints.email);
  const reasons = [];
  const lookalikes = extra.lookalikes || [];
  const brandHits = extra.brandHits || [];
  const crossOrigin = !!payload.formCrossOrigin;
  const httpInsecure = !!extra.httpInsecure;

  // A — критичные данные на неизвестном сайте
  if (hasCritical) {
    reasons.push("Неизвестный сайт запрашивает конфиденциальные данные");
    if (fields.password) reasons.push("Обнаружено поле пароля");
    if (fields.card) reasons.push("Обнаружены поля платёжных данных");
    if (fields.govId) reasons.push("Обнаружены поля документов / идентификаторов");
    if (fields.otp) reasons.push("Обнаружено поле кода подтверждения");
    if (crossOrigin) reasons.push("Форма может отправлять данные на другой домен");
    if (lookalikes.length) {
      reasons.push(...lookalikes.map((l) => l.reason));
    }
    if (brandHits.length) {
      reasons.push(...brandHits.map((b) => b.reason));
    }
    if (httpInsecure) reasons.push("Страница открыта по HTTP");

    return {
      caution: true,
      tier: "A",
      title: "Осторожно: неизвестный сайт просит конфиденциальные данные",
      reasons: [...new Set(reasons)],
      risk: Math.min(
        70,
        40 +
          (crossOrigin ? 12 : 0) +
          (lookalikes.length ? 10 : 0) +
          (brandHits.length ? 8 : 0) +
          (httpInsecure ? 5 : 0)
      )
    };
  }

  // B — мягкие ПДн (или признаки формы входа в тексте) + хотя бы один доп.сигнал
  if (hasSoftPii || hintsLogin) {
    const extras = [];
    if (lookalikes.length) {
      extras.push(...lookalikes.map((l) => l.reason));
    }
    if (brandHits.length) {
      extras.push(...brandHits.map((b) => b.reason));
    }
    if (crossOrigin) extras.push("Форма может отправлять данные на другой домен");
    if (httpInsecure) extras.push("Страница открыта по HTTP");

    if (extras.length === 0) {
      return { caution: false, tier: null, title: null, reasons: [], risk: 0 };
    }

    reasons.push(
      hasSoftPii
        ? "Сайт просит личные данные (email / телефон / имя)"
        : "На странице есть форма входа"
    );
    reasons.push(...extras);

    return {
      caution: true,
      tier: "B",
      title: "Осторожно: проверьте адрес сайта",
      reasons: [...new Set(reasons)],
      risk: Math.min(55, 28 + extras.length * 8)
    };
  }

  return { caution: false, tier: null, title: null, reasons: [], risk: 0 };
}

export function detectHttpInsecure(url = "") {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:") return false;
    return !isLocalHost(u.hostname, url);
  } catch {
    return false;
  }
}

export { isLocalHost };
