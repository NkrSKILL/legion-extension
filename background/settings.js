/** @typedef {"normal"|"strict"} Strictness */

export const DEFAULT_SETTINGS = {
  enabled: true,
  strictness: /** @type {Strictness} */ ("normal"),
  cautionEnabled: true,
  checkBrandSpoof: true,
  mlEnabled: true,
  pwdGuardEnabled: true,
  customWhitelist: [],
  demoForceWarn: false,
  backendUrl: "http://127.0.0.1:8787",
  useBackend: true,
  useLlmWhenUncertain: true
};

export function riskThreshold(strictness) {
  return strictness === "strict" ? 55 : 70;
}

/** Серый коридор — кандидат на LLM */
export function isUncertainRisk(risk, strictness) {
  const hi = riskThreshold(strictness);
  const lo = Math.max(25, hi - 30);
  return risk >= lo && risk < hi;
}

/** Нормализация домена для пользовательского белого списка */
export function normalizeDomain(raw) {
  if (!raw) return "";
  let s = String(raw).trim().toLowerCase();
  if (!s) return "";
  try {
    if (s.includes("://")) {
      s = new URL(s).hostname.toLowerCase();
    } else {
      s = s.split("/")[0].split(":")[0];
    }
  } catch (_) {
    s = s.split("/")[0].split(":")[0];
  }
  s = s.replace(/^\.+|\.+$/g, "");
  if (s.startsWith("www.") && s.slice(4).includes(".")) {
    s = s.slice(4);
  }
  if (!s || !s.includes(".") || s.startsWith("local-file") || s === "unknown-host") {
    return "";
  }
  return s;
}
