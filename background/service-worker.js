/**
 * Legion service worker — оркестратор
 */
import { DEFAULT_SETTINGS, normalizeDomain } from "./settings.js";
import { runProtocol, invalidateListCaches, getWhitelistInfo } from "./protocol.js";
import {
  backendHealth,
  backendReportVerdict,
  backendGetStats,
  backendResetStats,
  backendRefreshFeeds
} from "./api.js";
import { clearVerdictCache } from "./cache.js";
import {
  recordTrustedPasswordHash,
  checkPasswordReuse,
  getPwdGuardStats,
  clearPwdGuardHashes
} from "./pwdguard.js";
import {
  setFrameState,
  getTabState,
  getFrameState,
  clearTabFrames,
  forgetTab,
  setContinued,
  getContinued,
  clearContinued
} from "./tabstate.js";

/** Если content script не ответил за это время — показываем «не проверено», а не вечное «…» */
const PENDING_TIMEOUT_MS = 4000;
const pendingTimers = new Map();

chrome.runtime.onInstalled.addListener(async (details) => {
  const existing = await chrome.storage.sync.get(null);
  if (existing.enabled === undefined) {
    await chrome.storage.sync.set(DEFAULT_SETTINGS);
  } else {
    await chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...existing });
  }
  invalidateListCaches();
  console.log("[Legion] installed", chrome.runtime.getManifest().version, details.reason);
  // После Reload / обновления Chrome НЕ перевнедряет content scripts в уже открытые
  // вкладки — делаем это сами, чтобы не требовать F5 «как раньше».
  await reinjectOpenTabs();
});

chrome.runtime.onStartup.addListener(() => {
  reinjectOpenTabs().catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  clearPendingTimer(tabId);
  forgetTab(tabId);
});

/** Внедрить content script и запросить скан (нужно для file:// и после Reload расширения) */
async function injectAndScan(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "RESCAN" });
    return { ok: true, injected: false };
  } catch (_) {
    /* content script ещё нет или умер после Reload — внедряем заново */
  }

  try {
    // Сбрасываем флаг сборки: иначе после Reload IIFE сразу выходит
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => {
        try {
          delete window.__legionBuild;
          delete window.__legionLoaded;
        } catch (_) {}
      }
    });
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["content/content.js"]
    });
    // даём IIFE зарегистрировать listener
    await new Promise((r) => setTimeout(r, 50));
    await chrome.tabs.sendMessage(tabId, { type: "RESCAN" });
    return { ok: true, injected: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

/** Пройтись по всем обычным вкладкам и поднять сканер без F5 */
async function reinjectOpenTabs() {
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({});
  } catch (_) {
    return;
  }
  await Promise.all(
    tabs.map(async (tab) => {
      if (!isValidTabId(tab.id) || !tab.url) return;
      if (!/^https?:|^file:/i.test(tab.url)) return;
      await markPending(tab.id, tab.url);
      await injectAndScan(tab.id).catch(() => {});
    })
  );
}

/** Сбрасываем устаревший статус при смене URL; для file:// сами внедряем скрипт */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (!isValidTabId(tabId)) return;

  // Только при реальной смене URL — иначе каждый loading-событие
  // сбрасывает свежий вердикт и оставляет вечный pending
  if (changeInfo.url) {
    await clearTabFrames(tabId);
    await clearContinued(tabId);
    await markPending(tabId, changeInfo.url);
  }

  if (changeInfo.status === "complete" && tab?.url) {
    const url = tab.url;
    const restricted = restrictedPageInfo(url);
    if (restricted) {
      clearPendingTimer(tabId);
      const derived = await setFrameState(tabId, 0, restricted);
      await updateBadge(tabId, derived);
      return;
    }
    if (/^file:/i.test(url)) {
      const result = await injectAndScan(tabId);
      if (!result.ok) {
        console.warn("[Legion] file:// inject failed — включи Allow access to file URLs", result.error);
      }
    } else if (/^https?:/i.test(url)) {
      chrome.tabs.sendMessage(tabId, { type: "RESCAN" }).catch(() => {
        // скрипта ещё нет (страница открыта до Reload) — внедрим
        injectAndScan(tabId).catch(() => {});
      });
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((err) => {
      console.error("[Legion]", err);
      sendResponse({ ok: false, error: String(err) });
    });
  return true;
});

function urlsLooselyEqual(a, b) {
  if (!a || !b) return false;
  try {
    const ua = new URL(a);
    const ub = new URL(b);
    return ua.href === ub.href || (ua.origin === ub.origin && ua.pathname === ub.pathname);
  } catch {
    return a === b;
  }
}

/**
 * Страницы, куда Chrome запрещает внедрять content scripts.
 * Это не баг Legion — так устроена безопасность браузера.
 */
function restrictedPageInfo(url) {
  if (!url) return null;
  let host = "";
  let protocol = "";
  try {
    const u = new URL(url);
    host = (u.hostname || "").toLowerCase();
    protocol = u.protocol;
  } catch {
    return null;
  }

  if (protocol === "chrome:" || protocol === "edge:" || protocol === "about:" || protocol === "devtools:") {
    return {
      status: "restricted",
      stage: "restricted",
      title: "Служебная страница браузера",
      reasons: ["Chrome не даёт расширениям читать chrome://, edge:// и подобные адреса"],
      url
    };
  }

  const blockedHosts = [
    "chrome.google.com",
    "chromewebstore.google.com",
    "chrome.microsoft.com",
    "addons.mozilla.org",
    "microsoftedge.microsoft.com"
  ];
  if (blockedHosts.some((h) => host === h || host.endsWith("." + h))) {
    return {
      status: "restricted",
      stage: "restricted",
      title: "Магазин расширений недоступен для скана",
      reasons: [
        "Браузер специально блокирует внедрение скриптов в Chrome Web Store и похожие страницы",
        "На обычных сайтах (новости, банки, соцсети) Legion работает как обычно"
      ],
      url,
      hostname: host
    };
  }

  return null;
}

async function handleMessage(message, sender) {
  switch (message?.type) {
    case "GET_TAB_STATE": {
      const tabId = message.tabId ?? sender.tab?.id;
      let state = await getTabState(tabId);
      // статус от другого URL не показываем (типичный баг file:// после google)
      if (state && message.tabUrl && state.url && !urlsLooselyEqual(state.url, message.tabUrl)) {
        state = null;
      }
      return { ok: true, state };
    }
    case "RESCAN_ACTIVE_TAB": {
      // попап передаёт tabId/tabUrl — не гадаем заново, какая вкладка активна
      let tab = null;
      if (Number.isInteger(message.tabId)) {
        try {
          tab = await chrome.tabs.get(message.tabId);
        } catch (_) {}
      }
      if (!tab) {
        [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      }
      if (!tab?.id) return { ok: false, error: "no tab", hint: "Нет активной вкладки" };

      const tabUrl = message.tabUrl || tab.url || "";
      const restricted = restrictedPageInfo(tabUrl);
      if (restricted) {
        clearPendingTimer(tab.id);
        const derived = await setFrameState(tab.id, 0, restricted);
        await updateBadge(tab.id, derived);
        return { ok: true, scanned: false, state: restricted, tabUrl, restricted: true };
      }
      if (!isScannableUrl(tabUrl)) {
        return {
          ok: false,
          error: "unsupported_url",
          tabUrl,
          hint:
            "Сейчас открыто: " +
            (tabUrl || "(нет адреса)") +
            ". Legion сканирует только обычные сайты (http/https). Открой, например, https://yandex.ru или любой другой сайт — не chrome:// и не страницу расширений."
        };
      }

      await clearTabFrames(tab.id);
      await clearContinued(tab.id);
      await markPending(tab.id, tabUrl);

      try {
        const host = new URL(tabUrl).hostname || "local-file";
        await clearVerdictCache(host);
        if (tabUrl.startsWith("file:")) await clearVerdictCache("local-file");
      } catch (_) {
        await clearVerdictCache();
      }

      const inject = await injectAndScan(tab.id);
      if (!inject.ok) {
        const isFile = /^file:/i.test(tabUrl);
        // Часто это Web Store / другая защищённая страница — не пугаем «ошибкой»
        const maybeRestricted = restrictedPageInfo(tabUrl);
        if (maybeRestricted || /Cannot access|The extensions gallery|Cannot access contents/i.test(inject.error || "")) {
          const state = maybeRestricted || {
            status: "restricted",
            stage: "restricted",
            title: "Страница защищена браузером",
            reasons: ["Chrome запретил внедрение сканера на этот адрес"],
            url: tabUrl
          };
          clearPendingTimer(tab.id);
          const derived = await setFrameState(tab.id, 0, state);
          await updateBadge(tab.id, derived);
          return { ok: true, scanned: false, state, tabUrl, restricted: true };
        }
        return {
          ok: false,
          error: inject.error,
          tabUrl,
          hint: isFile
            ? "Это file://. Включи: chrome://extensions → Legion → «Allow access to file URLs», обнови страницу. Надёжнее: http://127.0.0.1:8765/fake-phish.html"
            : "Не удалось внедрить сканер на эту страницу. Попробуй Пересканировать ещё раз."
        };
      }

      // ждём ответ PAGE_SCAN_RESULT (до ~2.5 с)
      let state = null;
      for (let i = 0; i < 10 && !state; i++) {
        await new Promise((r) => setTimeout(r, 250));
        const candidate = await getTabState(tab.id);
        if (candidate && candidate.status !== "pending") state = candidate;
      }
      return { ok: true, scanned: true, state, tabUrl };
    }
    case "PAGE_SCAN_RESULT": {
      const tabId = sender.tab?.id;
      if (!isValidTabId(tabId)) return { ok: false, error: "no tab" };
      const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;

      const host = message.payload?.hostname;
      const continuedHost = await getContinued(tabId);
      if (continuedHost && continuedHost === host) {
        const skipped = {
          ...((await getFrameState(tabId, frameId)) || {}),
          ...message.payload,
          shouldWarn: false,
          userContinued: true,
          title: "Вы продолжили на свой риск",
          status: "continued",
          stage: "continued"
        };
        clearPendingTimer(tabId);
        const derived = await setFrameState(tabId, frameId, skipped);
        await updateBadge(tabId, derived);
        maybeReportStats(skipped, { frameId });
        return { ok: true, state: skipped };
      }

      const state = await runProtocol(message.payload);
      clearPendingTimer(tabId);
      const derived = await setFrameState(tabId, frameId, state);
      await updateBadge(tabId, derived);
      maybeReportStats(state, { frameId, fromCache: !!state.fromCache });

      if (state.shouldWarn) {
        const opts = Number.isInteger(sender.frameId) ? { frameId: sender.frameId } : {};
        await chrome.tabs
          .sendMessage(tabId, { type: "SHOW_WARNING", payload: state }, opts)
          .catch(() => {});
      }
      return { ok: true, state };
    }
    case "USER_CONTINUE": {
      const tabId = sender.tab?.id;
      if (!isValidTabId(tabId)) return { ok: true };
      const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;
      const current = (await getFrameState(tabId, frameId)) || (await getTabState(tabId));
      if (!current) return { ok: true };

      const s = { ...current, userContinued: true, shouldWarn: false, status: "continued" };
      await setContinued(tabId, s.hostname);
      const derived = await setFrameState(tabId, frameId, s);
      await updateBadge(tabId, derived);
      maybeReportStats(s, { frameId });
      return { ok: true };
    }
    case "GET_SETTINGS": {
      const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);
      return { ok: true, settings: { ...DEFAULT_SETTINGS, ...settings } };
    }
    case "SAVE_SETTINGS": {
      await chrome.storage.sync.set(message.settings || {});
      invalidateListCaches();
      await clearVerdictCache();
      return { ok: true };
    }
    case "GET_WHITELIST_STATUS": {
      const rawHost = message.hostname || "";
      const normalizedHost = normalizeDomain(rawHost);
      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      if (!normalizedHost) {
        return {
          ok: true,
          canWhitelist: false,
          whitelisted: false,
          inCustom: false,
          inBuiltin: false,
          normalizedHost: "",
          customWhitelist: settings.customWhitelist || []
        };
      }
      const info = await getWhitelistInfo(rawHost);
      return {
        ok: true,
        canWhitelist: true,
        ...info,
        normalizedHost,
        customWhitelist: settings.customWhitelist || []
      };
    }
    case "ADD_TO_WHITELIST": {
      const tabId = message.tabId ?? sender.tab?.id;
      let rawHost = message.hostname || "";
      let tabUrl = message.tabUrl || sender.tab?.url || "";
      if (!rawHost && tabUrl) {
        try {
          rawHost = new URL(tabUrl).hostname;
        } catch (_) {}
      }
      const domain = normalizeDomain(rawHost);
      if (!domain) {
        return { ok: false, error: "invalid_domain", hint: "Этот адрес нельзя добавить в белый список" };
      }

      const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
      const currentList = Array.isArray(stored.customWhitelist) ? stored.customWhitelist : [];
      const nextList = [...new Set([...currentList.map((d) => normalizeDomain(d)).filter(Boolean), domain])];

      await chrome.storage.sync.set({ customWhitelist: nextList });
      invalidateListCaches();
      await clearVerdictCache(rawHost);
      await clearVerdictCache(domain);

      if (isValidTabId(tabId)) {
        clearPendingTimer(tabId);
        await clearContinued(tabId);
        await chrome.tabs.sendMessage(tabId, { type: "HIDE_WARNING" }).catch(() => {});

        const prev = (await getTabState(tabId)) || {};
        const safeState = {
          ...prev,
          url: tabUrl || prev.url || `https://${domain}/`,
          hostname: rawHost || domain,
          stage: "whitelist",
          status: "safe",
          risk: 0,
          shouldWarn: false,
          analyzed: false,
          title: "Доверенный сайт",
          reasons: ["Домен добавлен вами в белый список"],
          source: "custom_whitelist",
          customWhitelisted: true
        };
        const derived = await setFrameState(tabId, 0, safeState);
        await updateBadge(tabId, derived);
        return { ok: true, domain, customWhitelist: nextList, state: derived };
      }

      return { ok: true, domain, customWhitelist: nextList };
    }
    case "REMOVE_FROM_WHITELIST": {
      const tabId = message.tabId ?? sender.tab?.id;
      const rawHost = (message.hostname || "").trim().toLowerCase();
      const domain = normalizeDomain(rawHost) || rawHost;
      if (!domain) return { ok: false, error: "invalid_domain" };

      const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
      const currentList = Array.isArray(stored.customWhitelist) ? stored.customWhitelist : [];
      const nextList = currentList
        .map((d) => normalizeDomain(d) || String(d).trim().toLowerCase())
        .filter((d) => {
          if (!d) return false;
          if (d === domain || d === rawHost) return false;
          // если удаляют поддомен, а в списке лежит родительский домен — тоже убираем совпадение
          if (rawHost && (rawHost === d || rawHost.endsWith("." + d))) return false;
          return true;
        });

      await chrome.storage.sync.set({ customWhitelist: nextList });
      invalidateListCaches();
      await clearVerdictCache();

      if (isValidTabId(tabId)) {
        await clearTabFrames(tabId);
        await clearContinued(tabId);
        await injectAndScan(tabId).catch(() => {});
      }
      return { ok: true, domain, customWhitelist: nextList };
    }
    case "BACKEND_STATUS": {
      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      const health = await backendHealth(settings.backendUrl || DEFAULT_SETTINGS.backendUrl);
      return { ok: true, backend: health };
    }
    case "GET_STATS": {
      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      if (!settings.useBackend) return { ok: true, stats: null, offline: true };
      const stats = await backendGetStats(settings.backendUrl || DEFAULT_SETTINGS.backendUrl);
      return { ok: true, stats, offline: !stats };
    }
    case "RESET_STATS": {
      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      if (!settings.useBackend) return { ok: false, error: "backend_off" };
      const stats = await backendResetStats(settings.backendUrl || DEFAULT_SETTINGS.backendUrl);
      return { ok: !!stats, stats };
    }
    case "REFRESH_FEEDS": {
      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      if (!settings.useBackend) return { ok: false, error: "backend_off" };
      const feeds = await backendRefreshFeeds(settings.backendUrl || DEFAULT_SETTINGS.backendUrl);
      await clearVerdictCache();
      return { ok: !!feeds, feeds };
    }
    case "GET_PWD_GUARD_STATS": {
      const stats = await getPwdGuardStats();
      return { ok: true, stats };
    }
    case "CLEAR_PWD_GUARD": {
      const stats = await clearPwdGuardHashes();
      return { ok: true, stats };
    }
    case "PASSWORD_DIGEST_EVENT": {
      const tabId = sender.tab?.id;
      const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;
      const clientDigest = message.clientDigest || "";
      const hostname = (message.hostname || "").toLowerCase();
      const url = message.url || sender.tab?.url || "";

      const settings = { ...DEFAULT_SETTINGS, ...(await chrome.storage.sync.get(DEFAULT_SETTINGS)) };
      if (!settings.enabled || settings.pwdGuardEnabled === false) {
        return { ok: true, action: "disabled" };
      }

      const wlInfo = await getWhitelistInfo(hostname);
      if (wlInfo.whitelisted) {
        await recordTrustedPasswordHash(clientDigest, hostname);
        return { ok: true, action: "recorded" };
      }

      const reuse = await checkPasswordReuse(clientDigest, hostname);
      if (!reuse.reused) {
        return { ok: true, action: "clean" };
      }

      if (isValidTabId(tabId)) {
        const continuedHost = await getContinued(tabId);
        if (continuedHost && continuedHost === hostname) {
          return { ok: true, action: "continued" };
        }

        const prev = (await getFrameState(tabId, frameId)) || (await getTabState(tabId)) || {};
        const dangerState = {
          ...prev,
          url,
          hostname,
          stage: "analysis",
          status: "danger",
          risk: 99,
          shouldWarn: true,
          analyzed: true,
          title: `Внимание: вы вводите свой пароль от ${reuse.trustedDomain}!`,
          reasons: [
            reuse.reason,
            ...(prev.reasons || []).filter((r) => !r.includes("манипулятивных маркеров не обнаружено"))
          ].slice(0, 6),
          source: "zk_password_guard"
        };
        clearPendingTimer(tabId);
        const derived = await setFrameState(tabId, frameId, dangerState);
        await updateBadge(tabId, derived);
        maybeReportStats(dangerState, { frameId });

        const opts = Number.isInteger(sender.frameId) ? { frameId: sender.frameId } : {};
        await chrome.tabs
          .sendMessage(tabId, { type: "SHOW_WARNING", payload: dangerState }, opts)
          .catch(() => {});
        return { ok: true, action: "blocked", state: dangerState };
      }
      return { ok: true, action: "flagged", reuse };
    }
    case "DEMO_SHOW_WARNING": {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return { ok: false, error: "no active tab" };
      let hostname = "example.com";
      try {
        hostname = new URL(tab.url || "https://example.com").hostname || "local-file";
      } catch (_) {}

      const demoState = {
        stage: "analysis",
        status: "danger",
        risk: 92,
        shouldWarn: true,
        title: "Демо: подозрительная страница",
        reasons: [
          "Сайт неизвестен системам защиты",
          "Обнаружена форма ввода пароля",
          "Текст создаёт ощущение срочности и давления"
        ],
        hostname,
        url: tab.url,
        analyzed: true,
        demo: true,
        source: "demo"
      };

      clearPendingTimer(tab.id);
      await clearContinued(tab.id);
      const derived = await setFrameState(tab.id, 0, demoState);
      await updateBadge(tab.id, derived);
      await chrome.tabs
        .sendMessage(tab.id, { type: "SHOW_WARNING", payload: demoState })
        .catch(() => {});
      return { ok: true, state: demoState };
    }
    default:
      return { ok: false, error: "unknown message" };
  }
}

function isValidTabId(tabId) {
  return Number.isInteger(tabId) && tabId >= 0;
}

function isScannableUrl(url) {
  return !!url && /^https?:|^file:/i.test(url);
}

function clearPendingTimer(tabId) {
  const t = pendingTimers.get(tabId);
  if (t) {
    clearTimeout(t);
    pendingTimers.delete(tabId);
  }
}

/**
 * До вердикта индикатор показывает «идёт проверка», а не пустоту.
 * Если скан так и не пришёл — переводим в «не проверено», чтобы «…» не висело вечно.
 */
async function markPending(tabId, url) {
  if (!isValidTabId(tabId)) return;
  if (url && !isScannableUrl(url)) {
    clearPendingTimer(tabId);
    await clearBadge(tabId);
    return;
  }

  const pending = {
    status: "pending",
    stage: "init",
    title: "Идёт проверка…",
    url: url || "",
    reasons: []
  };
  const derived = await setFrameState(tabId, 0, pending);
  await updateBadge(tabId, derived);

  clearPendingTimer(tabId);
  pendingTimers.set(
    tabId,
    setTimeout(async () => {
      pendingTimers.delete(tabId);
      const current = await getFrameState(tabId, 0);
      if (current?.status !== "pending") return;
      const unknown = {
        ...current,
        status: "unknown",
        stage: "unknown",
        title: "Страница не проверена",
        reasons: ["Сканер не смог прочитать эту страницу — нажми «Пересканировать»"]
      };
      const next = await setFrameState(tabId, 0, unknown);
      await updateBadge(tabId, next);
    }, PENDING_TIMEOUT_MS)
  );
}

async function clearBadge(tabId) {
  if (!isValidTabId(tabId)) return;
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch (_) {}
}

const REPORTABLE = new Set(["safe", "caution", "danger", "continued"]);

/**
 * Отчёт в backend-статистику. Не ждём ответа и не ломаем скан:
 * нет backend / ошибка сети → просто тишина.
 */
function maybeReportStats(state, { frameId = 0, fromCache = false } = {}) {
  try {
    if (!state || !REPORTABLE.has(state.status)) return;
    // только top-frame; кэш и iframe не раздувают цифры
    if (frameId !== 0) return;
    if (fromCache || state.fromCache) return;
    if (state.status === "restricted" || state.demo) return;

    chrome.storage.sync.get(DEFAULT_SETTINGS).then((stored) => {
      const settings = { ...DEFAULT_SETTINGS, ...stored };
      if (!settings.useBackend || !settings.backendUrl) return;
      backendReportVerdict(settings.backendUrl, {
        status: state.status,
        hostname: state.hostname || "",
        source: state.source || "",
        stage: state.stage || "",
        risk: state.risk
      });
    }).catch(() => {});
  } catch (_) {}
}

const BADGE = {
  pending: { text: "…", color: "#64748b" },
  idle: { text: "…", color: "#64748b" },
  safe: { text: "✓", color: "#22c55e" },
  caution: { text: "?", color: "#f59e0b" },
  danger: { text: "!", color: "#ef4444" },
  continued: { text: "·", color: "#94a3b8" },
  unknown: { text: "·", color: "#64748b" },
  restricted: { text: "·", color: "#64748b" },
  off: { text: "off", color: "#94a3b8" }
};

async function updateBadge(tabId, state) {
  if (!isValidTabId(tabId) || !state) return;
  const conf = BADGE[state.status] || BADGE.pending;
  try {
    await chrome.action.setBadgeText({ tabId, text: conf.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: conf.color });
  } catch (_) {}
}
