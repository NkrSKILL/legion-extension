const enabledToggle = document.getElementById("enabledToggle");
const toggleSettingsBtn = document.getElementById("toggleSettingsBtn");
const backToMainBtn = document.getElementById("backToMainBtn");
const openFullOptionsBtn = document.getElementById("openFullOptionsBtn");

const mainView = document.getElementById("mainView");
const settingsView = document.getElementById("settingsView");

const statusCard = document.getElementById("statusCard");
const statusIcon = document.getElementById("statusIcon");
const statusTitle = document.getElementById("statusTitle");
const statusHost = document.getElementById("statusHost");
const riskPill = document.getElementById("riskPill");
const stepsBar = document.getElementById("stepsBar");
const stageLine = document.getElementById("stageLine");
const fieldChips = document.getElementById("fieldChips");
const reasonsList = document.getElementById("reasonsList");

const whitelistBar = document.getElementById("whitelistBar");
const addWhitelistBtn = document.getElementById("addWhitelistBtn");
const addWhitelistLabel = document.getElementById("addWhitelistLabel");
const wlCustomRow = document.getElementById("wlCustomRow");
const wlBuiltinRow = document.getElementById("wlBuiltinRow");
const removeWhitelistBtn = document.getElementById("removeWhitelistBtn");

const backendPill = document.getElementById("backendPill");
const backendLine = document.getElementById("backendLine");
const rescanBtn = document.getElementById("rescanBtn");
const versionEl = document.getElementById("version");

// Статистика
const statsCard = document.getElementById("statsCard");
const statsFoot = document.getElementById("statsFoot");
const statsResetBtn = document.getElementById("statsResetBtn");
const statTotal = document.getElementById("statTotal");
const statSafe = document.getElementById("statSafe");
const statCaution = document.getElementById("statCaution");
const statDanger = document.getElementById("statDanger");

// Элементы окна настроек внутри плагина
const strictness = document.getElementById("strictness");
const cautionEnabledToggle = document.getElementById("cautionEnabledToggle");
const brandSpoofToggle = document.getElementById("brandSpoofToggle");
const mlEnabledToggle = document.getElementById("mlEnabledToggle");
const pwdGuardToggle = document.getElementById("pwdGuardToggle");
const pwdGuardFoot = document.getElementById("pwdGuardFoot");
const clearPwdGuardBtn = document.getElementById("clearPwdGuardBtn");
const demoForceWarnToggle = document.getElementById("demoForceWarnToggle");
const useBackendToggle = document.getElementById("useBackendToggle");
const useLlmToggle = document.getElementById("useLlmToggle");
const backendUrlInput = document.getElementById("backendUrlInput");
const saveBackendUrlBtn = document.getElementById("saveBackendUrlBtn");
const feedsFoot = document.getElementById("feedsFoot");
const refreshFeedsBtn = document.getElementById("refreshFeedsBtn");

const wlCountBadge = document.getElementById("wlCountBadge");
const wlNewDomainInput = document.getElementById("wlNewDomainInput");
const wlAddManualBtn = document.getElementById("wlAddManualBtn");
const wlChipsList = document.getElementById("wlChipsList");

const STAGE_LABELS = {
  init: "проверка…",
  unknown: "страница не проверена",
  restricted: "защищено браузером",
  disabled: "защита выключена",
  whitelist: "шаг 1 · белый список",
  blacklist: "шаг 2 · база угроз",
  no_form: "шаг 3 · чувствительных форм нет",
  analysis: "шаг 3 · глубокий анализ",
  caution: "шаг 3 · жёлтый режим (осторожность)",
  continued: "пользователь продолжил"
};

const FIELD_NAMES = [
  { key: "password", label: "Пароль", crit: true },
  { key: "card", label: "Банковская карта", crit: true },
  { key: "otp", label: "Код / 2FA", crit: true },
  { key: "govId", label: "Документы / Госуслуги", crit: true },
  { key: "email", label: "Email / логин", crit: false },
  { key: "phone", label: "Телефон", crit: false },
  { key: "name", label: "ФИО / имя", crit: false }
];

let activeTab = null;
let currentHostname = "";

versionEl.textContent = chrome.runtime.getManifest().version;

/* ===== ПЕРЕКЛЮЧЕНИЕ ОКОН (ГЛАВНЫЙ / НАСТРОЙКИ) ===== */
function showView(viewName) {
  const isSettings = viewName === "settings";
  mainView.hidden = isSettings;
  settingsView.hidden = !isSettings;
  toggleSettingsBtn.classList.toggle("active", isSettings);
}

toggleSettingsBtn.addEventListener("click", () => {
  showView(settingsView.hidden ? "settings" : "main");
});
backToMainBtn.addEventListener("click", async () => {
  showView("main");
  await refreshTabState();
});
openFullOptionsBtn.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

/* ===== ЗАГРУЗКА И СОХРАНЕНИЕ НАСТРОЕК ===== */
async function loadSettings() {
  const res = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  const s = res?.settings || {};
  enabledToggle.checked = s.enabled !== false;
  strictness.value = s.strictness || "normal";
  cautionEnabledToggle.checked = s.cautionEnabled !== false;
  brandSpoofToggle.checked = s.checkBrandSpoof !== false;
  mlEnabledToggle.checked = s.mlEnabled !== false;
  pwdGuardToggle.checked = s.pwdGuardEnabled !== false;
  demoForceWarnToggle.checked = !!s.demoForceWarn;
  useBackendToggle.checked = s.useBackend !== false;
  useLlmToggle.checked = s.useLlmWhenUncertain !== false;
  backendUrlInput.value = s.backendUrl || "http://127.0.0.1:8787";
  renderCustomWhitelistChips(s.customWhitelist || []);
  await refreshPwdGuardStats();
}

async function refreshPwdGuardStats() {
  try {
    const res = await chrome.runtime.sendMessage({ type: "GET_PWD_GUARD_STATS" });
    const count = res?.stats?.count || 0;
    const domains = res?.stats?.domains || [];
    pwdGuardFoot.textContent = count
      ? `Защищено паролей: ${count} (${domains.slice(0, 3).join(", ")})`
      : "Отпечатков паролей: 0 (сохраняются при входе на сайты из белого списка)";
  } catch {
    pwdGuardFoot.textContent = "Отпечатков паролей: 0";
  }
}

async function savePartial(partial) {
  const res = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  const merged = { ...(res?.settings || {}), ...partial };
  await chrome.runtime.sendMessage({
    type: "SAVE_SETTINGS",
    settings: merged
  });
  return merged;
}

function renderCustomWhitelistChips(list) {
  const clean = Array.isArray(list) ? list.filter(Boolean) : [];
  wlCountBadge.textContent = String(clean.length);
  wlChipsList.innerHTML = "";

  if (!clean.length) {
    const empty = document.createElement("div");
    empty.className = "wl-empty";
    empty.textContent = "Пока пусто — добавьте сайты кнопкой на главном экране или выше";
    wlChipsList.appendChild(empty);
    return;
  }

  clean.forEach((domain) => {
    const chip = document.createElement("span");
    chip.className = "wl-chip";
    const text = document.createElement("span");
    text.textContent = domain;
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.title = "Удалить из белого списка";
    delBtn.textContent = "×";
    delBtn.addEventListener("click", async () => {
      const res = await chrome.runtime.sendMessage({
        type: "REMOVE_FROM_WHITELIST",
        hostname: domain,
        tabId: activeTab?.id
      });
      if (res?.ok) {
        renderCustomWhitelistChips(res.customWhitelist || []);
        await refreshWhitelistBar(currentHostname);
      }
    });
    chip.appendChild(text);
    chip.appendChild(delBtn);
    wlChipsList.appendChild(chip);
  });
}

/* ===== УТИЛИТЫ ОТОБРАЖЕНИЯ ===== */
function shortUrl(url) {
  if (!url) return "—";
  try {
    const u = new URL(url);
    if (u.protocol === "file:") {
      const parts = u.pathname.split(/[/\\]/).filter(Boolean);
      return "file: …/" + (parts[parts.length - 1] || "");
    }
    return u.hostname + (u.pathname === "/" ? "" : u.pathname);
  } catch {
    return url.slice(0, 60);
  }
}

function extractHost(url, stateHost) {
  if (stateHost && !stateHost.startsWith("local-file") && stateHost !== "unknown-host") {
    return stateHost;
  }
  try {
    return new URL(url || "").hostname || "";
  } catch {
    return "";
  }
}

function setCardVisual(status) {
  const map = {
    safe: { tone: "safe", icon: "✓" },
    caution: { tone: "caution", icon: "?" },
    danger: { tone: "danger", icon: "!" },
    pending: { tone: "pending", icon: "…" },
    idle: { tone: "pending", icon: "…" },
    continued: { tone: "neutral", icon: "·" },
    unknown: { tone: "neutral", icon: "·" },
    restricted: { tone: "neutral", icon: "·" },
    off: { tone: "off", icon: "⏸" }
  };
  const conf = map[status] || map.pending;
  statusCard.setAttribute("data-tone", conf.tone);
  statusIcon.textContent = conf.icon;
}

function updateStepsBar(stage) {
  const items = stepsBar.querySelectorAll(".step-item");
  items.forEach((el) => el.classList.remove("active", "done"));

  const s1 = stepsBar.querySelector('[data-step="1"]');
  const s2 = stepsBar.querySelector('[data-step="2"]');
  const s3 = stepsBar.querySelector('[data-step="3"]');
  if (!s1 || !s2 || !s3) return;

  if (stage === "whitelist") {
    s1.classList.add("active");
  } else if (stage === "blacklist") {
    s1.classList.add("done");
    s2.classList.add("active");
  } else if (stage === "no_form" || stage === "analysis" || stage === "caution" || stage === "continued") {
    s1.classList.add("done");
    s2.classList.add("done");
    s3.classList.add("active");
  }
}

function renderFieldChips(state) {
  fieldChips.innerHTML = "";
  const fields = state?.fields || {};
  const found = FIELD_NAMES.filter((f) => fields[f.key]);

  if (!found.length && !state?.formCrossOrigin) {
    fieldChips.hidden = true;
    return;
  }

  fieldChips.hidden = false;
  found.forEach((f) => {
    const span = document.createElement("span");
    span.className = "field-chip" + (f.crit ? " crit" : "");
    span.textContent = f.label;
    fieldChips.appendChild(span);
  });

  if (state?.formCrossOrigin) {
    const span = document.createElement("span");
    span.className = "field-chip crit";
    span.textContent = "Форма → чужой домен";
    fieldChips.appendChild(span);
  }
}

/* ===== КНОПКА БЕЛОГО СПИСКА НА ГЛАВНОМ ЭКРАНЕ ===== */
async function refreshWhitelistBar(hostname) {
  currentHostname = hostname || "";
  if (!currentHostname) {
    whitelistBar.hidden = true;
    return;
  }

  const res = await chrome.runtime.sendMessage({
    type: "GET_WHITELIST_STATUS",
    hostname: currentHostname
  });

  if (!res?.ok || !res.canWhitelist) {
    whitelistBar.hidden = true;
    return;
  }

  whitelistBar.hidden = false;
  renderCustomWhitelistChips(res.customWhitelist || []);

  if (res.inCustom) {
    addWhitelistBtn.hidden = true;
    wlCustomRow.hidden = false;
    wlBuiltinRow.hidden = true;
  } else if (res.inBuiltin) {
    addWhitelistBtn.hidden = true;
    wlCustomRow.hidden = true;
    wlBuiltinRow.hidden = false;
  } else {
    addWhitelistBtn.hidden = false;
    wlCustomRow.hidden = true;
    wlBuiltinRow.hidden = true;
    addWhitelistLabel.textContent = `Добавить ${res.normalizedHost} в белый список`;
  }
}

addWhitelistBtn.addEventListener("click", async () => {
  if (!currentHostname) return;
  addWhitelistBtn.disabled = true;
  const res = await chrome.runtime.sendMessage({
    type: "ADD_TO_WHITELIST",
    hostname: currentHostname,
    tabId: activeTab?.id,
    tabUrl: activeTab?.url
  });
  addWhitelistBtn.disabled = false;

  if (res?.ok) {
    if (res.state) renderState(res.state, activeTab?.url);
    await refreshWhitelistBar(currentHostname);
  }
});

removeWhitelistBtn.addEventListener("click", async () => {
  if (!currentHostname) return;
  removeWhitelistBtn.disabled = true;
  const res = await chrome.runtime.sendMessage({
    type: "REMOVE_FROM_WHITELIST",
    hostname: currentHostname,
    tabId: activeTab?.id
  });
  removeWhitelistBtn.disabled = false;

  if (res?.ok) {
    await refreshWhitelistBar(currentHostname);
    await doRescan();
  }
});

/* ===== РЕНДЕР СТАТУСА ВКЛАДКИ ===== */
function renderState(state, tabUrl) {
  const host = extractHost(tabUrl || state?.url, state?.hostname);
  refreshWhitelistBar(host).catch(() => {});

  if (!state) {
    const isFile = tabUrl && tabUrl.startsWith("file:");
    setCardVisual("pending");
    statusTitle.textContent = isFile ? "Локальный файл не просканирован" : "Ожидание проверки вкладки";
    statusHost.textContent = isFile
      ? "Включи Allow access to file URLs или открой демо-сервер"
      : shortUrl(tabUrl);
    riskPill.hidden = true;
    updateStepsBar("init");
    stageLine.textContent = "Этап: ожидание сканирования";
    fieldChips.hidden = true;
    reasonsList.innerHTML = "";
    return;
  }

  setCardVisual(state.status || "idle");
  statusTitle.textContent = state.title || "Статус неизвестен";
  statusHost.textContent = shortUrl(tabUrl || state.url);

  if (state.analyzed || typeof state.risk === "number" && state.risk > 0) {
    riskPill.hidden = false;
    riskPill.textContent = `Риск ${state.risk}%`;
  } else {
    riskPill.hidden = true;
  }

  updateStepsBar(state.stage);

  const extra = [];
  if (state.cautionTier) extra.push(`уровень ${state.cautionTier}`);
  if (typeof state.mlPct === "number" && state.mlPct > 0) extra.push(`ML ${state.mlPct}%`);
  if (state.fromSubframe) extra.push("во фрейме");
  if (state.used_llm) extra.push("LLM");
  if (state.fromCache) extra.push("кэш");
  stageLine.textContent = `Этап: ${STAGE_LABELS[state.stage] || state.stage}${
    extra.length ? " · " + extra.join(" · ") : ""
  }`;

  renderFieldChips(state);

  reasonsList.innerHTML = "";
  (state.reasons || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });
}

/* ===== BACKEND И СТАТИСТИКА ===== */
async function refreshBackend() {
  try {
    const res = await chrome.runtime.sendMessage({ type: "BACKEND_STATUS" });
    if (res?.backend?.ok) {
      const d = res.backend.data || {};
      const llm = d.llm_configured ? "LLM on" : "LLM off";
      const sb = d.safe_browsing_configured ? "SB on" : "SB off";
      const feedsCount = d.feeds?.total_domains || 0;
      backendPill.textContent = "Server ON";
      backendPill.className = "backend-pill ok";
      backendLine.textContent = `Backend: online · ${llm} · ${sb} · Feeds (${feedsCount})`;
      backendLine.className = "backend-line ok";
      if (feedsFoot) {
        feedsFoot.textContent = `OpenPhish / URLhaus: ${feedsCount} доменов в базе Stage 2`;
      }
      if (d.stats) renderStats(d.stats);
      else await refreshStats();
    } else {
      backendPill.textContent = "Local";
      backendPill.className = "backend-pill offline";
      backendLine.textContent = "Backend: offline (работают локальные эвристики)";
      backendLine.className = "backend-line bad";
      if (feedsFoot) {
        feedsFoot.textContent = "Backend офлайн — используется локальная база blacklist.json";
      }
      statsCard.hidden = true;
    }
  } catch {
    backendPill.textContent = "Local";
    backendPill.className = "backend-pill";
    backendLine.textContent = "Backend: неизвестно";
    backendLine.className = "backend-line";
    statsCard.hidden = true;
  }
}

function renderStats(stats) {
  if (!stats || typeof stats.total !== "number") {
    statsCard.hidden = true;
    return;
  }
  statsCard.hidden = false;
  statTotal.textContent = String(stats.total || 0);
  statSafe.textContent = String(stats.safe || 0);
  statCaution.textContent = String(stats.caution || 0);
  statDanger.textContent = String(stats.danger || 0);
  const hosts = stats.unique_hosts || 0;
  const cont = stats.continued || 0;
  const bits = [`уникальных сайтов: ${hosts}`];
  if (cont) bits.push(`продолжили: ${cont}`);
  statsFoot.textContent = bits.join(" · ");
}

async function refreshStats() {
  try {
    const res = await chrome.runtime.sendMessage({ type: "GET_STATS" });
    if (res?.offline || !res?.stats) {
      statsCard.hidden = true;
      return;
    }
    renderStats(res.stats);
  } catch {
    statsCard.hidden = true;
  }
}

/* ===== СКАНИРОВАНИЕ ВКЛАДКИ ===== */
async function doRescan() {
  statusTitle.textContent = "Сканирование…";
  setCardVisual("pending");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || activeTab;
  const res = await chrome.runtime.sendMessage({
    type: "RESCAN_ACTIVE_TAB",
    tabId: tab?.id,
    tabUrl: tab?.url
  });
  if (!res || !res.ok) {
    setCardVisual("danger");
    statusTitle.textContent = "Не удалось просканировать";
    statusHost.textContent =
      res?.hint || res?.error || "Открой обычный http/https сайт и нажми Пересканировать";
    stageLine.textContent = "Этап: ошибка сканирования";
    return null;
  }
  renderState(res.state, res.tabUrl);
  if (!res.state) {
    statusTitle.textContent = "Скрипт поднимается…";
    statusHost.textContent = "Нажми «Пересканировать» ещё раз через секунду";
  }
  refreshStats().catch(() => {});
  return res.state;
}

async function refreshTabState() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;
  if (!tab?.id) {
    renderState(null, null);
    return;
  }

  if (tab.url && !/^(https?:|file:)/i.test(tab.url)) {
    setCardVisual("restricted");
    statusTitle.textContent = "Служебная страница браузера";
    statusHost.textContent = shortUrl(tab.url);
    riskPill.hidden = true;
    updateStepsBar("restricted");
    stageLine.textContent = "Этап: служебный URL (Legion работает на http/https)";
    fieldChips.hidden = true;
    reasonsList.innerHTML = "";
    whitelistBar.hidden = true;
    return;
  }

  if (tab.url && /chromewebstore\.google\.com|chrome\.google\.com\/webstore/i.test(tab.url)) {
    setCardVisual("restricted");
    statusTitle.textContent = "Магазин расширений защищён браузером";
    statusHost.textContent = shortUrl(tab.url);
    riskPill.hidden = true;
    updateStepsBar("restricted");
    stageLine.textContent = "Этап: Chrome блокирует скрипты в Web Store";
    fieldChips.hidden = true;
    reasonsList.innerHTML = "";
    whitelistBar.hidden = true;
    return;
  }

  const res = await chrome.runtime.sendMessage({
    type: "GET_TAB_STATE",
    tabId: tab.id,
    tabUrl: tab.url
  });

  const needsScan =
    !res.state || res.state.status === "pending" || res.state.status === "unknown";
  if (needsScan && tab.url && /^(https?:|file:)/i.test(tab.url)) {
    renderState(res.state, tab.url);
    await doRescan();
    return;
  }
  renderState(res.state, tab.url);
}

/* ===== ОБРАБОТЧИКИ СОБЫТИЙ ===== */
enabledToggle.addEventListener("change", async () => {
  await savePartial({ enabled: enabledToggle.checked });
  await doRescan();
});

strictness.addEventListener("change", async () => {
  await savePartial({ strictness: strictness.value });
});

cautionEnabledToggle.addEventListener("change", async () => {
  await savePartial({ cautionEnabled: cautionEnabledToggle.checked });
});

brandSpoofToggle.addEventListener("change", async () => {
  await savePartial({ checkBrandSpoof: brandSpoofToggle.checked });
});

mlEnabledToggle.addEventListener("change", async () => {
  await savePartial({ mlEnabled: mlEnabledToggle.checked });
});

pwdGuardToggle.addEventListener("change", async () => {
  await savePartial({ pwdGuardEnabled: pwdGuardToggle.checked });
});

clearPwdGuardBtn.addEventListener("click", async () => {
  const res = await chrome.runtime.sendMessage({ type: "CLEAR_PWD_GUARD" });
  if (res?.ok) {
    await refreshPwdGuardStats();
  }
});

refreshFeedsBtn.addEventListener("click", async () => {
  refreshFeedsBtn.disabled = true;
  if (feedsFoot) feedsFoot.textContent = "Обновление фидов OpenPhish / URLhaus…";
  const res = await chrome.runtime.sendMessage({ type: "REFRESH_FEEDS" });
  refreshFeedsBtn.disabled = false;
  if (res?.ok && res.feeds) {
    const count = res.feeds.total_domains || 0;
    if (feedsFoot) feedsFoot.textContent = `Фиды обновлены: ${count} доменов в базе`;
    await refreshBackend();
  } else {
    if (feedsFoot) feedsFoot.textContent = "Не удалось обновить фиды (проверьте Backend)";
  }
});

demoForceWarnToggle.addEventListener("change", async () => {
  await savePartial({ demoForceWarn: demoForceWarnToggle.checked });
});

useBackendToggle.addEventListener("change", async () => {
  await savePartial({ useBackend: useBackendToggle.checked });
  await refreshBackend();
});

useLlmToggle.addEventListener("change", async () => {
  await savePartial({ useLlmWhenUncertain: useLlmToggle.checked });
});

saveBackendUrlBtn.addEventListener("click", async () => {
  const url = backendUrlInput.value.trim() || "http://127.0.0.1:8787";
  backendUrlInput.value = url;
  await savePartial({ backendUrl: url });
  await refreshBackend();
});

async function handleManualAddDomain() {
  const raw = wlNewDomainInput.value.trim();
  if (!raw) return;
  const res = await chrome.runtime.sendMessage({
    type: "ADD_TO_WHITELIST",
    hostname: raw,
    tabId: activeTab?.id,
    tabUrl: activeTab?.url
  });
  if (res?.ok) {
    wlNewDomainInput.value = "";
    renderCustomWhitelistChips(res.customWhitelist || []);
    await refreshWhitelistBar(currentHostname);
  }
}

wlAddManualBtn.addEventListener("click", handleManualAddDomain);
wlNewDomainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    handleManualAddDomain();
  }
});

rescanBtn.addEventListener("click", () => {
  doRescan();
});

statsResetBtn.addEventListener("click", async () => {
  const res = await chrome.runtime.sendMessage({ type: "RESET_STATS" });
  if (res?.ok && res.stats) renderStats(res.stats);
  else await refreshStats();
});

await loadSettings();
await Promise.all([refreshTabState(), refreshBackend()]);
