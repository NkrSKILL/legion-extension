function normalizeDomain(raw) {
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

const enabled = document.getElementById("enabled");
const strictness = document.getElementById("strictness");
const cautionEnabled = document.getElementById("cautionEnabled");
const checkBrandSpoof = document.getElementById("checkBrandSpoof");
const mlEnabled = document.getElementById("mlEnabled");
const pwdGuardEnabled = document.getElementById("pwdGuardEnabled");
const demoForceWarn = document.getElementById("demoForceWarn");
const useBackend = document.getElementById("useBackend");
const useLlmWhenUncertain = document.getElementById("useLlmWhenUncertain");
const backendUrl = document.getElementById("backendUrl");
const customWhitelist = document.getElementById("customWhitelist");
const quickDomainInput = document.getElementById("quickDomainInput");
const quickAddBtn = document.getElementById("quickAddBtn");
const wlCount = document.getElementById("wlCount");
const verBadge = document.getElementById("verBadge");
const saveBtn = document.getElementById("saveBtn");
const pingBtn = document.getElementById("pingBtn");
const toast = document.getElementById("toast");
const backendHint = document.getElementById("backendHint");

verBadge.textContent = "v" + chrome.runtime.getManifest().version;

function parseTextareaList() {
  return [
    ...new Set(
      customWhitelist.value
        .split(/\n+/)
        .map((x) => normalizeDomain(x))
        .filter(Boolean)
    )
  ];
}

function updateCount() {
  const n = parseTextareaList().length;
  wlCount.textContent = `${n} доменов`;
}

async function load() {
  const res = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  const s = res.settings || {};
  enabled.checked = s.enabled !== false;
  strictness.value = s.strictness || "normal";
  cautionEnabled.checked = s.cautionEnabled !== false;
  checkBrandSpoof.checked = s.checkBrandSpoof !== false;
  mlEnabled.checked = s.mlEnabled !== false;
  pwdGuardEnabled.checked = s.pwdGuardEnabled !== false;
  demoForceWarn.checked = !!s.demoForceWarn;
  useBackend.checked = s.useBackend !== false;
  useLlmWhenUncertain.checked = s.useLlmWhenUncertain !== false;
  backendUrl.value = s.backendUrl || "http://127.0.0.1:8787";
  customWhitelist.value = (s.customWhitelist || []).join("\n");
  updateCount();
  await ping();
}

async function ping() {
  const res = await chrome.runtime.sendMessage({ type: "BACKEND_STATUS" });
  if (res?.backend?.ok) {
    const d = res.backend.data || {};
    const feedsCount = d.feeds?.total_domains || 0;
    backendHint.textContent = `Статус: online · LLM ${d.llm_configured ? "on" : "off"} · Safe Browsing ${d.safe_browsing_configured ? "on" : "off"} · Feeds (${feedsCount} доменов)`;
  } else {
    backendHint.textContent = "Статус: offline — расширение работает на локальных эвристиках";
  }
}

async function saveAll() {
  const list = parseTextareaList();
  customWhitelist.value = list.join("\n");
  updateCount();

  await chrome.runtime.sendMessage({
    type: "SAVE_SETTINGS",
    settings: {
      enabled: enabled.checked,
      strictness: strictness.value,
      cautionEnabled: cautionEnabled.checked,
      checkBrandSpoof: checkBrandSpoof.checked,
      mlEnabled: mlEnabled.checked,
      pwdGuardEnabled: pwdGuardEnabled.checked,
      demoForceWarn: demoForceWarn.checked,
      useBackend: useBackend.checked,
      useLlmWhenUncertain: useLlmWhenUncertain.checked,
      backendUrl: backendUrl.value.trim() || "http://127.0.0.1:8787",
      customWhitelist: list
    }
  });

  toast.hidden = false;
  setTimeout(() => {
    toast.hidden = true;
  }, 1800);
  await ping();
}

quickAddBtn.addEventListener("click", async () => {
  const d = normalizeDomain(quickDomainInput.value);
  if (!d) return;
  const list = [...new Set([...parseTextareaList(), d])];
  customWhitelist.value = list.join("\n");
  quickDomainInput.value = "";
  await saveAll();
});

quickDomainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    quickAddBtn.click();
  }
});

customWhitelist.addEventListener("input", updateCount);
saveBtn.addEventListener("click", saveAll);
pingBtn.addEventListener("click", ping);

await load();
