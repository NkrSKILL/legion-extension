/**
 * Автозапуск локального бэкенда Legion через Chrome Native Messaging.
 *
 * Хост ставится установщиком Legion-Setup.exe (installer/). Если его нет —
 * расширение работает как раньше, только локально (без бэкенда).
 */
import { backendHealth } from "./api.js";

export const NATIVE_HOST_NAME = "com.legion.host";

/** Не дёргать хост чаще, чем раз в 30 с (если его нет, каждый вызов был бы ошибкой) */
const MIN_INTERVAL_MS = 30_000;

let lastAttemptAt = 0;
let inFlight = null;

function isLocalBackend(baseUrl) {
  try {
    const host = new URL(baseUrl).hostname;
    return host === "127.0.0.1" || host === "localhost";
  } catch {
    return false;
  }
}

/**
 * Попросить хост поднять сервер, если он не отвечает.
 * Возвращает { ok, status?, error? }. Никогда не бросает исключений.
 */
export function requestBackendStart({ force = false } = {}) {
  if (inFlight) return inFlight;
  if (!force && Date.now() - lastAttemptAt < MIN_INTERVAL_MS) {
    return Promise.resolve({ ok: false, status: "throttled" });
  }
  lastAttemptAt = Date.now();

  inFlight = new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { action: "start" }, (response) => {
        const err = chrome.runtime.lastError;
        if (err) {
          resolve({ ok: false, status: "no_host", error: err.message });
          return;
        }
        resolve(response && typeof response === "object" ? response : { ok: false, status: "empty" });
      });
    } catch (e) {
      resolve({ ok: false, status: "exception", error: String(e && e.message ? e.message : e) });
    }
  }).finally(() => {
    inFlight = null;
  });

  return inFlight;
}

/**
 * Проверить бэкенд и при необходимости запустить его.
 * Нужен при старте Chrome, установке, по таймеру и когда бэкенд молчит.
 */
export async function ensureBackendRunning(baseUrl, { force = false } = {}) {
  if (!baseUrl || !isLocalBackend(baseUrl)) return { ok: true, status: "remote" };
  const health = await backendHealth(baseUrl, 1500);
  if (health && health.ok) return { ok: true, status: "running" };
  return requestBackendStart({ force });
}
