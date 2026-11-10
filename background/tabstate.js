/**
 * Состояние вкладок Legion.
 *
 * Два исправления против прежних Map в памяти:
 * 1) вердикты хранятся по фреймам — раньше любой iframe (например рекламный
 *    с полем email) перетирал вердикт основной страницы;
 * 2) всё зеркалится в chrome.storage.session — MV3 выгружает воркер через ~30 с,
 *    и вместе с ним терялась отметка «пользователь продолжил».
 */

const STORAGE_KEY = "pg_tabstate";
const MAX_FRAMES = 300;
const WRITE_DEBOUNCE_MS = 300;

let cache = null;
let writeTimer = null;

function emptyCache() {
  return { frames: {}, continued: {} };
}

async function ensureLoaded() {
  if (cache) return cache;
  try {
    const data = await chrome.storage.session.get(STORAGE_KEY);
    const saved = data?.[STORAGE_KEY];
    cache = saved && typeof saved === "object" ? { ...emptyCache(), ...saved } : emptyCache();
  } catch (_) {
    cache = emptyCache();
  }
  return cache;
}

function scheduleWrite() {
  if (writeTimer) return;
  writeTimer = setTimeout(async () => {
    writeTimer = null;
    try {
      await chrome.storage.session.set({ [STORAGE_KEY]: cache });
    } catch (_) {}
  }, WRITE_DEBOUNCE_MS);
}

function frameKey(tabId, frameId) {
  return `${tabId}:${frameId}`;
}

function prune() {
  const keys = Object.keys(cache.frames);
  if (keys.length <= MAX_FRAMES) return;
  keys
    .sort((a, b) => (cache.frames[a]?.ts || 0) - (cache.frames[b]?.ts || 0))
    .slice(0, keys.length - MAX_FRAMES)
    .forEach((k) => delete cache.frames[k]);
}

/**
 * Итоговый статус вкладки: основной фрейм главный.
 * Подчинённый фрейм может только повысить тревогу до danger,
 * но не понизить вердикт страницы до safe.
 */
function derive(tabId) {
  const top = cache.frames[frameKey(tabId, 0)]?.state || null;
  let danger = null;

  const prefix = `${tabId}:`;
  for (const [key, entry] of Object.entries(cache.frames)) {
    if (!key.startsWith(prefix) || key === frameKey(tabId, 0)) continue;
    const st = entry?.state;
    if (st?.status === "danger" && (!danger || (st.risk || 0) > (danger.risk || 0))) {
      danger = st;
    }
  }

  if (danger && top?.status !== "danger") {
    return { ...danger, url: top?.url || danger.url, fromSubframe: true };
  }
  return top || null;
}

export async function setFrameState(tabId, frameId, state) {
  await ensureLoaded();
  cache.frames[frameKey(tabId, frameId)] = { ts: Date.now(), state };
  prune();
  scheduleWrite();
  return derive(tabId);
}

export async function getTabState(tabId) {
  await ensureLoaded();
  return derive(tabId);
}

export async function getFrameState(tabId, frameId) {
  await ensureLoaded();
  return cache.frames[frameKey(tabId, frameId)]?.state || null;
}

/** Навигация / пересканирование — вердикты всех фреймов вкладки больше не актуальны */
export async function clearTabFrames(tabId) {
  await ensureLoaded();
  const prefix = `${tabId}:`;
  for (const key of Object.keys(cache.frames)) {
    if (key.startsWith(prefix)) delete cache.frames[key];
  }
  scheduleWrite();
}

export async function forgetTab(tabId) {
  await ensureLoaded();
  await clearTabFrames(tabId);
  delete cache.continued[tabId];
  scheduleWrite();
}

export async function setContinued(tabId, hostname) {
  await ensureLoaded();
  if (hostname) cache.continued[tabId] = hostname;
  scheduleWrite();
}

export async function getContinued(tabId) {
  await ensureLoaded();
  return cache.continued[tabId] || null;
}

export async function clearContinued(tabId) {
  await ensureLoaded();
  delete cache.continued[tabId];
  scheduleWrite();
}
