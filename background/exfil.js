/**
 * Модуль exfil-hook: события от перехватчика отправки данных (content/exfil-hook.js).
 *
 * Контракт модуля (единый для всех модулей Legion):
 *   { moduleId, riskDelta, confidence, hardBlock, reasons[] }
 */

export const EXFIL_MODULE_ID = "exfil-hook";

/** Сколько времени держим красное предупреждение после остановленной отправки */
export const EXFIL_STICKY_MS = 10 * 60 * 1000;

const FIELD_LABEL = {
  password: "пароль",
  otp: "код из СМС или 2FA",
  card: "данные карты"
};

/** Оценка события. Остановленная отправка — однозначный сигнал, поэтому confidence высокий. */
export function evaluateExfilModule(payload) {
  const field = FIELD_LABEL[payload.field] ? payload.field : "sensitive";
  const label = FIELD_LABEL[field] || "личные данные";
  const dest = payload.dest || "неизвестный сервер";
  const blocked = payload.kind === "blocked";
  return {
    moduleId: EXFIL_MODULE_ID,
    riskDelta: blocked ? 100 : 60,
    confidence: blocked ? 0.95 : 0.6,
    hardBlock: blocked,
    reasons: [
      blocked
        ? `Страница пыталась отправить ваш ${label} на другой сайт (${dest}). Отправка остановлена`
        : `Страница отправляет ${label} на другой сайт (${dest})`
    ]
  };
}

/** Состояние вкладки для предупреждения, которое построено поверх прежнего состояния фрейма. */
export function buildExfilState(payload, prev) {
  const mod = evaluateExfilModule(payload);
  return {
    ...(prev || {}),
    url: payload.url || prev?.url || "",
    hostname: payload.hostname || prev?.hostname || "",
    frame: prev?.frame || "top",
    stage: "exfil",
    status: "danger",
    risk: mod.riskDelta,
    shouldWarn: true,
    analyzed: true,
    userContinued: false,
    title: "Попытка кражи ваших данных",
    reasons: mod.reasons,
    source: EXFIL_MODULE_ID,
    exfilAt: Date.now(),
    moduleVerdict: mod
  };
}

/** Активно ли ещё предупреждение о перехваченной отправке для этого адреса. */
export function isActiveExfil(prev, url) {
  return !!(
    prev &&
    prev.stage === "exfil" &&
    prev.status === "danger" &&
    prev.url === url &&
    Date.now() - (prev.exfilAt || 0) < EXFIL_STICKY_MS
  );
}
