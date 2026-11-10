/**
 * Клиент к локальному FastAPI backend (Legion).
 */

export async function backendHealth(baseUrl, timeoutMs = 1200) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/health`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return { ok: false };
    return { ok: true, data: await res.json() };
  } catch {
    clearTimeout(t);
    return { ok: false };
  }
}

export async function backendAnalyze(baseUrl, body, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(t);
    return null;
  }
}

/**
 * Query и fragment наружу не отправляем: там бывают токены и идентификаторы,
 * а для Safe Browsing достаточно origin + path.
 */
export function sanitizeUrlForLookup(url) {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return "";
  }
}

/**
 * Этап 2: Google Safe Browsing через backend.
 * @returns {Promise<null|{hit:boolean,reasons:string[],source:string,configured?:boolean}>}
 */
export async function backendThreatCheck(baseUrl, { url, hostname }, timeoutMs = 6000) {
  const lookupUrl = sanitizeUrlForLookup(url);
  if (!lookupUrl) return null;

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/v1/threat-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: lookupUrl, hostname }),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(t);
    return null;
  }
}

/** Fire-and-forget: учёт вердикта. Ошибки игнорируем — на защиту не влияет. */
export function backendReportVerdict(baseUrl, event) {
  if (!baseUrl || !event?.status) return;
  const body = {
    status: event.status,
    hostname: event.hostname || "",
    source: event.source || "",
    stage: event.stage || "",
    risk: typeof event.risk === "number" ? event.risk : null
  };
  fetch(`${baseUrl.replace(/\/$/, "")}/v1/stats/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  }).catch(() => {});
}

export async function backendGetStats(baseUrl, timeoutMs = 1500) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/v1/stats`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(t);
    return null;
  }
}

export async function backendResetStats(baseUrl, timeoutMs = 1500) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/v1/stats/reset`, {
      method: "POST",
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(t);
    return null;
  }
}

export async function backendRefreshFeeds(baseUrl, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/v1/feeds/refresh`, {
      method: "POST",
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    clearTimeout(t);
    return null;
  }
}

