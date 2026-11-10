/**
 * Legion content script
 * Автодетект модалок + периодический скан.
 *
 * Принципы:
 * - один обход DOM за скан (раньше их было ~60: findModalRoots × 12 селекторов × 4 вызова);
 * - fields = только реальные поля ввода; догадки по тексту идут отдельно в textHints,
 *   иначе справочная модалка со словом «пароль» давала hasCritical;
 * - скрытый password в DOM ≠ активная форма (иначе кэш "safe" до открытия модалки).
 */

(function () {
  const BUILD = "0.7.0";
  // После «Обновить» на chrome://extensions старый флаг остаётся на странице,
  // а новый скрипт раньше сразу выходил — сканер «умирал» до перезагрузки вкладки.
  if (window.__legionBuild === BUILD) return;
  window.__legionBuild = BUILD;
  window.__legionLoaded = true;

  const isTop = window === window.top;
  const okProtocol = /^(https?:|file:)$/.test(location.protocol);
  // крошечные рекламные фреймы не сканируем, но top-фрейм — всегда
  if (!okProtocol) return;
  if (!isTop && (window.innerWidth < 120 || window.innerHeight < 80)) return;

  const OVERLAY_ID = "legion-overlay-root";
  const SCAN_MS_ACTIVE = 4000;
  const SCAN_MS_IDLE = 15000;
  const MUTATION_DEBOUNCE_MS = 600;

  const MODAL_SELECTOR =
    "dialog[open], [role='dialog'], [role='alertdialog'], [aria-modal='true']," +
    ".modal.show, .modal.open, .modal.is-open, .modal--open," +
    ".ReactModal__Content, .ReactModal__Overlay, [data-state='open'], .login-modal, .auth-modal";

  const CUSTOM_HOST_SELECTOR =
    "faceplate-text-input, [type='password'], [autocomplete='current-password']," +
    "[autocomplete='new-password'], [autocomplete='username'], [name='password'], [name='username']";

  const SNIPPET_SELECTOR =
    "h1, h2, h3, button, [type=submit], label, legend, p, .alert, .warning, .timer, .btn, a.button";

  let lastFingerprint = "";
  let mutationScheduled = false;
  let periodicTimer = null;
  let periodicMs = SCAN_MS_ACTIVE;
  let stopped = false;

  /** Кэши на время одного скана — getComputedStyle/getBoundingClientRect дорогие */
  let visCache = new Map();
  let modalCache = new Map();

  function resetScanCaches() {
    visCache = new Map();
    modalCache = new Map();
  }

  function matchesSafe(el, selector) {
    try {
      return el.matches(selector);
    } catch (_) {
      return false;
    }
  }

  /**
   * Единственный обход документа и открытых shadow-root за скан.
   */
  function collectDom() {
    const ctx = { inputs: [], modals: [], customHosts: [], snippetNodes: [], assetUrls: [], linkCount: 0 };

    const visit = (root) => {
      let all;
      try {
        all = root.querySelectorAll("*");
      } catch (_) {
        return;
      }
      for (const el of all) {
        const tag = el.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA") ctx.inputs.push(el);
        else if (tag === "A") ctx.linkCount += 1;
        else if (tag === "IMG") {
          const src = el.getAttribute("src") || el.getAttribute("data-src");
          if (src) ctx.assetUrls.push(src);
        } else if (tag === "LINK") {
          const rel = (el.getAttribute("rel") || "").toLowerCase();
          const href = el.getAttribute("href");
          if (href && (rel.includes("icon") || rel.includes("stylesheet"))) {
            ctx.assetUrls.push(href);
          }
        } else if (tag === "SCRIPT") {
          const src = el.getAttribute("src");
          if (src) ctx.assetUrls.push(src);
        }
        if (matchesSafe(el, MODAL_SELECTOR)) ctx.modals.push(el);
        if (matchesSafe(el, SNIPPET_SELECTOR)) ctx.snippetNodes.push(el);
        if (el.shadowRoot) {
          ctx.customHosts.push(el);
          visit(el.shadowRoot);
        } else if (matchesSafe(el, CUSTOM_HOST_SELECTOR)) {
          ctx.customHosts.push(el);
        }
      }
    };

    visit(document);
    return ctx;
  }

  /** Сбор внешних доменов картинок/иконок/стилей для детекта визуальной мимикрии */
  function collectAssetMeta(ctx) {
    const pageHost = (location.hostname || "").toLowerCase().replace(/^www\./, "");
    const extHosts = new Set();
    let total = 0;
    let external = 0;

    for (const raw of (ctx.assetUrls || []).slice(0, 80)) {
      try {
        const u = new URL(raw, location.href);
        if (u.protocol !== "http:" && u.protocol !== "https:") continue;
        const h = (u.hostname || "").toLowerCase().replace(/^www\./, "");
        if (!h) continue;
        total += 1;
        if (pageHost && h !== pageHost && !h.endsWith("." + pageHost)) {
          external += 1;
          extHosts.add(h);
        }
      } catch (_) {}
    }

    return {
      assetHosts: [...extHosts].slice(0, 25),
      domStats: {
        externalAssetRatio: total > 0 ? Number((external / total).toFixed(2)) : 0,
        linkCount: ctx.linkCount || 0
      }
    };
  }

  /**
   * Видимость с учётом модалок:
   * многие сайты ставят aria-hidden на фон, а поля логина живут в dialog —
   * старая проверка из-за этого их выкидывала.
   */
  function isInsideOpenModal(el) {
    if (!(el instanceof Element)) return false;
    const modal = el.closest(
      "dialog[open], [role='dialog'], [role='alertdialog'], [aria-modal='true'], .ReactModal__Content, [data-state='open']"
    );
    if (!modal) return false;
    if (modalCache.has(modal)) return modalCache.get(modal);

    let open;
    if (modal instanceof HTMLDialogElement) {
      open = modal.open || modal.hasAttribute("open");
    } else {
      const st = window.getComputedStyle(modal);
      if (st.display === "none" || st.visibility === "hidden") {
        open = false;
      } else {
        const r = modal.getBoundingClientRect();
        open = r.width > 20 && r.height > 20;
      }
    }
    modalCache.set(modal, open);
    return open;
  }

  function isVisible(el) {
    if (!(el instanceof Element)) return false;
    if (visCache.has(el)) return visCache.get(el);
    const v = computeVisible(el);
    visCache.set(el, v);
    return v;
  }

  function isFieldElement(el) {
    return el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;
  }

  function computeVisible(el) {
    const inModal = isInsideOpenModal(el);

    // aria-hidden на фоне страницы не должен прятать поля внутри открытой модалки
    if (!inModal) {
      if (el.closest("[hidden], [aria-hidden='true']")) return false;
    } else if (el.closest("[hidden]")) return false;

    if (typeof el.checkVisibility === "function") {
      // opacity:0 часто бывает на анимации появления модалки — в modal допускаем
      const ok = el.checkVisibility({ checkOpacity: !inModal, checkVisibilityCSS: true });
      if (!ok) return inModal && isFieldElement(el);
    } else {
      const style = window.getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") return false;
      if (!inModal && Number(style.opacity) === 0) return false;
    }

    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) {
      // кастомные поля иногда 1px / visually hidden native input
      return inModal && isFieldElement(el);
    }
    return true;
  }

  /**
   * Текст label / aria / соседних узлов.
   * Только прямые соседи: querySelectorAll по поддереву на каждое поле
   * собирал тысячи узлов, если родителем была форма или body.
   */
  function labelTextFor(el) {
    const bits = [];
    if (el.id) {
      try {
        document.querySelectorAll(`label[for="${CSS.escape(el.id)}"]`).forEach((l) => {
          bits.push(l.textContent || "");
        });
      } catch (_) {}
    }
    const wrapLabel = el.closest("label");
    if (wrapLabel) bits.push(wrapLabel.textContent || "");

    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      labelledBy
        .split(/\s+/)
        .slice(0, 4)
        .forEach((id) => {
          const node = document.getElementById(id);
          if (node) bits.push(node.textContent || "");
        });
    }

    // плавающие label рядом с полем (Reddit / Material)
    const parent = el.parentElement;
    if (parent) {
      let used = 0;
      for (const child of parent.children) {
        if (used >= 8) break;
        if (child === el) continue;
        const tag = child.tagName;
        if (tag !== "LABEL" && tag !== "SPAN" && tag !== "P" && tag !== "DIV" && tag !== "LEGEND") {
          continue;
        }
        const t = (child.textContent || "").trim();
        if (t && t.length < 80) {
          bits.push(t);
          used += 1;
        }
      }
    }
    return bits.join(" ").toLowerCase();
  }

  /**
   * @param {Element} el
   * @param {boolean} skipVisibility — для внутренних проверок
   */
  function classifyInput(el, skipVisibility = false) {
    if (!isFieldElement(el)) return null;
    if (!skipVisibility && !isVisible(el) && !isInsideOpenModal(el)) return null;

    const type = (el.type || "").toLowerCase();
    if (type === "hidden") return null;

    const blob = [
      el.name || "",
      el.id || "",
      el.autocomplete || "",
      el.placeholder || "",
      el.className || "",
      el.getAttribute("aria-label") || "",
      labelTextFor(el)
    ]
      .join(" ")
      .toLowerCase();
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();

    if (
      type === "password" ||
      ac.includes("password") ||
      /парол|password|passwd|passcode/.test(blob)
    ) {
      return "password";
    }
    if (
      ac.includes("cc-") ||
      /cardnumber|card-number|cc-number|cvv|cvc|cc-csc|cc-exp|номер.?карт|пан\b/.test(blob) ||
      (type === "tel" && /card|cvv|карт/.test(blob))
    ) {
      return "card";
    }
    if (/паспорт|снилс|инн|serie|номер.?документ|gosuslugi|gov.?id/.test(blob)) {
      return "govId";
    }
    if (/otp|one.?time|код\s*подтвержд|sms.?code|2fa|one-time|одноразов/.test(blob)) {
      return "otp";
    }
    if (
      type === "email" ||
      ac === "email" ||
      ac === "username" ||
      /e-?mail|электронн(ая|ой)\s+почт|почта|логин|login|username|имя\s+пользователя|user\s*name/.test(
        blob
      )
    ) {
      return "email";
    }
    if (type === "tel" || ac === "tel" || /телефон|phone|mobile|мобил/.test(blob)) {
      return "phone";
    }
    if (ac.includes("name") || /фамилия|имя|отчество|first.?name|last.?name|фио|surname/.test(blob)) {
      return "name";
    }
    return null;
  }

  function isSensitiveInput(el) {
    const kind = classifyInput(el, true);
    return kind === "password" || kind === "card";
  }

  function emptyFields() {
    return {
      password: false,
      card: false,
      govId: false,
      otp: false,
      email: false,
      phone: false,
      name: false
    };
  }

  /**
   * Реальные поля ввода (включая web-components с атрибутами).
   * Текстовые догадки здесь НЕ учитываем — они идут в textHints.
   */
  function collectFields(ctx) {
    const fields = emptyFields();
    const mark = (kind) => {
      if (kind && fields[kind] !== undefined) fields[kind] = true;
    };

    for (const el of ctx.inputs) {
      mark(classifyInput(el));
    }

    // кастомные web-components (Reddit faceplate-text-input и аналоги):
    // реальный <input> часто спрятан в shadow, а type/name висят на хосте
    for (const host of ctx.customHosts) {
      if (!(host instanceof HTMLElement) || isFieldElement(host)) continue;

      const type = (host.getAttribute("type") || "").toLowerCase();
      const name = (host.getAttribute("name") || "").toLowerCase();
      const ac = (host.getAttribute("autocomplete") || "").toLowerCase();
      const id = (host.id || "").toLowerCase();
      const blob = `${type} ${name} ${ac} ${id} ${host.tagName}`.toLowerCase();

      if (type === "password" || ac.includes("password") || name === "password") {
        mark("password");
      } else if (type === "email" || ac === "email" || ac === "username" || name === "username") {
        mark("email");
      } else if (ac.includes("one-time") || /otp|2fa|backup/.test(name + id)) {
        mark("otp");
      } else if (/phone|tel/.test(blob)) {
        mark("phone");
      }
    }

    return fields;
  }

  /**
   * Догадки по тексту модалки: это лишь повод проанализировать страницу,
   * но НЕ доказательство критичного поля (иначе справка «Забыли пароль?»
   * превращалась в hasCritical и давала жёлтый/красный на ровном месте).
   */
  function collectTextHints(ctx) {
    const hints = { password: false, email: false, loginUi: false };
    for (const modal of ctx.modals) {
      if (!isVisible(modal)) continue;
      const t = (modal.textContent || "").toLowerCase();
      if (!t) continue;
      const hasLoginUi =
        /войти|вход|регистр|sign\s*up|sign\s*in|log\s*in|create\s*account|зарегистрир/.test(t);
      if (hasLoginUi) hints.loginUi = true;
      if (/парол|password/.test(t) && hasLoginUi) hints.password = true;
      if (/электронн(ая|ой)\s+почт|e-?mail|имя\s+пользователя|username|логин/.test(t)) {
        hints.email = true;
      }
    }
    return hints;
  }

  /**
   * Cross-origin считаем только по формам с чувствительными полями:
   * иначе поиск с action="https://google.com/search" или подписка на рассылку
   * давали formCrossOrigin и жёлтый режим на нормальном сайте.
   */
  function collectFormMeta(ctx) {
    const pageOrigin = location.origin;
    const formActions = [];
    let formCrossOrigin = false;

    // один проход по полям вместо перебора «каждая форма × все поля»
    const piiForms = new Set();
    for (const el of ctx.inputs) {
      if (!classifyInput(el, true)) continue;
      const form = el.closest("form");
      if (form) piiForms.add(form);
    }

    for (const form of piiForms) {
      const raw = form.getAttribute("action");
      try {
        const u = new URL(raw || location.href, location.href);
        if (u.protocol === "http:" || u.protocol === "https:") {
          formActions.push(u.origin + u.pathname);
          if (pageOrigin && pageOrigin !== "null" && u.origin !== pageOrigin) {
            formCrossOrigin = true;
          }
        }
      } catch (_) {}
    }

    return { formActions: [...new Set(formActions)].slice(0, 6), formCrossOrigin };
  }

  /** Критичные поля, реально видимые пользователю (или в открытой модалке) */
  function pageHasSensitiveForm(ctx) {
    return ctx.inputs.some((el) => isSensitiveInput(el) && (isVisible(el) || isInsideOpenModal(el)));
  }

  function collectSnippets(ctx) {
    const parts = [];
    const title = document.title?.trim();
    if (title) parts.push(title);

    const push = (raw) => {
      const t = (raw || "").trim().replace(/\s+/g, " ");
      if (t && t.length < 220) parts.push(t);
    };

    const visibleModals = ctx.modals.filter(isVisible);
    for (const modal of visibleModals.slice(0, 3)) {
      const block = (modal.textContent || "").trim().replace(/\s+/g, " ");
      if (block) parts.push(block.slice(0, 500));
    }

    let taken = 0;
    for (const el of ctx.snippetNodes) {
      if (taken >= 45) break;
      if (!isVisible(el)) continue;
      push(el.textContent || el.getAttribute("aria-label") || "");
      taken += 1;
    }

    for (const el of ctx.inputs.slice(0, 20)) {
      push(el.placeholder || el.getAttribute("aria-label") || "");
    }

    if (visibleModals.length) parts.push("[legion:modal-ui-detected]");
    return [...new Set(parts)].slice(0, 50);
  }

  function resolveHostname() {
    let hostname = location.hostname;
    if (!hostname) {
      if (location.protocol === "file:") {
        const parts = location.pathname.split(/[/\\]/).filter(Boolean);
        hostname = parts.length ? `local-file/${parts[parts.length - 1]}` : "local-file";
      } else {
        hostname = "unknown-host";
      }
    }
    return hostname;
  }

  function fingerprint(payload) {
    return [
      payload.hostname,
      payload.hasSensitiveForm ? "1" : "0",
      payload.hasRelevantForm ? "r1" : "r0",
      payload.modalDetected ? "m1" : "m0",
      payload.formCrossOrigin ? "x1" : "x0",
      JSON.stringify(payload.fields || {}),
      JSON.stringify(payload.textHints || {}),
      (payload.snippets || []).slice(0, 12).join("|")
    ].join("::");
  }

  async function send(message) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch (e) {
      // расширение перезагрузили — дальше слать некуда
      if (/context invalidated|Receiving end does not exist/i.test(String(e))) shutdown();
      return null;
    }
  }

  async function scanAndReport(force = false) {
    if (stopped) return;
    try {
      if (!force && document.hidden) return;

      resetScanCaches();
      const ctx = collectDom();

      // дешёвый выход: анализировать нечего
      const nothingToScan =
        ctx.inputs.length === 0 && ctx.customHosts.length === 0 && ctx.modals.length === 0;

      const fields = nothingToScan ? emptyFields() : collectFields(ctx);
      const textHints = nothingToScan
        ? { password: false, email: false, loginUi: false }
        : collectTextHints(ctx);
      const formMeta = nothingToScan
        ? { formActions: [], formCrossOrigin: false }
        : collectFormMeta(ctx);
      const assetMeta = nothingToScan
        ? { assetHosts: [], domStats: { externalAssetRatio: 0, linkCount: 0 } }
        : collectAssetMeta(ctx);

      const hasCritical = fields.password || fields.card || fields.govId || fields.otp;
      const hasSoftPii = fields.email || fields.phone || fields.name;

      const payload = {
        url: location.href,
        hostname: resolveHostname(),
        hasSensitiveForm: nothingToScan ? false : pageHasSensitiveForm(ctx),
        hasRelevantForm: !!(hasCritical || hasSoftPii || textHints.password || textHints.email),
        fields,
        textHints,
        formActions: formMeta.formActions,
        formCrossOrigin: formMeta.formCrossOrigin,
        assetHosts: assetMeta.assetHosts,
        domStats: assetMeta.domStats,
        snippets: nothingToScan ? [document.title || ""].filter(Boolean) : collectSnippets(ctx),
        title: document.title || "",
        modalDetected: nothingToScan ? false : ctx.modals.some(isVisible),
        frame: isTop ? "top" : "iframe"
      };

      const fp = fingerprint(payload);
      if (!force && fp === lastFingerprint) return;
      lastFingerprint = fp;

      const res = await send({ type: "PAGE_SCAN_RESULT", payload });
      applyScanHint(res?.state, payload);
    } catch (_) {}
  }

  /** Терминально-безопасный вердикт — сканируем реже */
  function applyScanHint(state, payload) {
    if (!state) return;
    const terminalSafe =
      state.status === "safe" &&
      (state.stage === "whitelist" || state.stage === "no_form") &&
      !payload.hasRelevantForm;
    const next = terminalSafe ? SCAN_MS_IDLE : SCAN_MS_ACTIVE;
    if (next !== periodicMs) {
      periodicMs = next;
      startPeriodic();
    }
  }

  function removeOverlay() {
    const el = document.getElementById(OVERLAY_ID);
    if (!el) return;
    try {
      if (typeof el.close === "function") el.close();
    } catch (_) {}
    el.remove();
  }

  function overlayStyles() {
    return `
      #${OVERLAY_ID} {
        position: fixed !important;
        inset: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        max-width: none !important;
        max-height: none !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        background: rgba(2, 6, 23, 0.92) !important;
        color: #f8fafc !important;
        font-family: "Segoe UI", system-ui, -apple-system, sans-serif !important;
        z-index: 2147483647 !important;
        box-sizing: border-box !important;
      }
      #${OVERLAY_ID}::backdrop {
        background: rgba(2, 6, 23, 0.88) !important;
        backdrop-filter: blur(6px);
      }
      #${OVERLAY_ID} .pg-wrap {
        min-height: 100%;
        display: flex;
        align-items: flex-start;
        justify-content: center;
        padding: 8vh 16px 24px;
        box-sizing: border-box;
      }
      #${OVERLAY_ID} .pg-card {
        width: 100%;
        max-width: 520px;
        padding: 28px 28px 22px;
        background: #0a0c10;
        border: 1px solid rgba(239, 68, 68, 0.55);
        border-radius: 14px;
        box-shadow: 0 24px 80px rgba(0, 0, 0, 0.78);
      }
      #${OVERLAY_ID} .pg-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 11.5px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #ffffff;
        font-weight: 800;
        margin-bottom: 12px;
        padding: 5px 10px;
        border-radius: 6px;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.4);
      }
      #${OVERLAY_ID} .pg-title {
        margin: 0 0 10px;
        font-size: 24px;
        line-height: 1.25;
        font-weight: 700;
        color: #f8fafc;
      }
      #${OVERLAY_ID} .pg-sub {
        margin: 0 0 18px;
        font-size: 14px;
        line-height: 1.5;
        color: #cbd5e1;
      }
      #${OVERLAY_ID} .pg-meter { margin-bottom: 14px; }
      #${OVERLAY_ID} .pg-meter-label { font-size: 13px; margin-bottom: 6px; color: #e2e8f0; }
      #${OVERLAY_ID} .pg-meter-bar {
        height: 8px; border-radius: 999px; background: #334155; overflow: hidden;
      }
      #${OVERLAY_ID} .pg-meter-bar span {
        display: block; height: 100%;
        background: linear-gradient(90deg, #f59e0b, #ef4444);
      }
      #${OVERLAY_ID} .pg-reasons {
        margin: 0 0 20px; padding-left: 18px; color: #fecaca;
        font-size: 13px; line-height: 1.45;
      }
      #${OVERLAY_ID} .pg-reasons li { margin-bottom: 6px; }
      #${OVERLAY_ID} .pg-actions { display: flex; flex-wrap: wrap; gap: 10px; }
      #${OVERLAY_ID} .pg-btn {
        border: none; cursor: pointer; border-radius: 10px;
        padding: 11px 16px; font-size: 14px; font-weight: 600;
      }
      #${OVERLAY_ID} .pg-btn-primary { background: #ef4444; color: #fff; }
      #${OVERLAY_ID} .pg-btn-primary:hover { background: #dc2626; }
      #${OVERLAY_ID} .pg-btn-ghost {
        background: transparent; color: #94a3b8; border: 1px solid #475569;
      }
      #${OVERLAY_ID} .pg-btn-ghost:hover { color: #e2e8f0; border-color: #64748b; }
      #${OVERLAY_ID} .pg-btn-trust {
        background: rgba(34, 197, 94, 0.12);
        color: #86efac;
        border: 1px solid rgba(34, 197, 94, 0.35);
      }
      #${OVERLAY_ID} .pg-btn-trust:hover {
        background: rgba(34, 197, 94, 0.22);
        border-color: rgba(34, 197, 94, 0.55);
      }
      #${OVERLAY_ID} .pg-fine { margin: 16px 0 0; font-size: 11px; color: #64748b; }
    `;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function showWarning(state) {
    // не мерцаем: если уже открыто то же предупреждение — выходим
    const existing = document.getElementById(OVERLAY_ID);
    if (existing && existing.open) return;
    removeOverlay();

    const risk = Math.max(0, Math.min(100, Number(state.risk) || 0));

    // <dialog>.showModal() = top layer браузера, поверх любых z-index/модалок сайта
    const root = document.createElement("dialog");
    root.id = OVERLAY_ID;
    root.setAttribute("aria-label", "Предупреждение Legion");

    const style = document.createElement("style");
    style.textContent = overlayStyles();

    const wrap = el("div", "pg-wrap");
    const card = el("div", "pg-card");

    card.appendChild(el("div", "pg-badge", "⬡ LEGION · PERIMETER SHIELD"));
    card.appendChild(el("h1", "pg-title", state.title || "Подозрительная страница"));

    // текст страницы в DOM только через textContent — без innerHTML
    const sub = el("p", "pg-sub");
    sub.appendChild(document.createTextNode("Сайт "));
    const strong = document.createElement("strong");
    strong.textContent = state.hostname || location.hostname;
    sub.appendChild(strong);
    sub.appendChild(
      document.createTextNode(
        " может быть фишинговым. Анализ сработал только после проверки — не из-за одной лишь формы входа."
      )
    );
    card.appendChild(sub);

    const meter = el("div", "pg-meter");
    const meterLabel = el("div", "pg-meter-label", `Уровень риска: ${risk}%`);
    const bar = el("div", "pg-meter-bar");
    const fill = document.createElement("span");
    fill.style.width = `${risk}%`;
    bar.appendChild(fill);
    meter.appendChild(meterLabel);
    meter.appendChild(bar);
    card.appendChild(meter);

    const reasons = el("ul", "pg-reasons");
    (state.reasons || []).slice(0, 8).forEach((r) => reasons.appendChild(el("li", null, r)));
    card.appendChild(reasons);

    const actions = el("div", "pg-actions");
    const leaveBtn = el("button", "pg-btn pg-btn-primary", "Уйти с сайта");
    leaveBtn.type = "button";
    const continueBtn = el("button", "pg-btn pg-btn-ghost", "Всё равно продолжить");
    continueBtn.type = "button";
    actions.appendChild(leaveBtn);
    actions.appendChild(continueBtn);

    const host = (state.hostname || location.hostname || "").toLowerCase();
    const canTrust = host && host.includes(".") && !host.startsWith("local-file");
    let trustBtn = null;
    if (canTrust && !state.demo) {
      trustBtn = el("button", "pg-btn pg-btn-trust", "Доверять сайту (в белый список)");
      trustBtn.type = "button";
      actions.appendChild(trustBtn);
    }
    card.appendChild(actions);

    card.appendChild(
      el("p", "pg-fine", "Дополнительная защита от страниц-однодневок. Не замена антивируса.")
    );

    wrap.appendChild(card);
    root.appendChild(style);
    root.appendChild(wrap);

    leaveBtn.addEventListener("click", () => {
      try {
        if (!isTop) window.top.location.href = "about:blank";
        else location.href = "about:blank";
      } catch (_) {
        location.href = "about:blank";
      }
    });
    continueBtn.addEventListener("click", async () => {
      removeOverlay();
      await send({ type: "USER_CONTINUE" });
    });
    if (trustBtn) {
      trustBtn.addEventListener("click", async () => {
        removeOverlay();
        await send({ type: "ADD_TO_WHITELIST", hostname: host, tabUrl: location.href });
      });
    }

    // блокируем закрытие по Escape — только через кнопки
    root.addEventListener("cancel", (e) => e.preventDefault());

    (document.body || document.documentElement).appendChild(root);
    try {
      root.showModal();
    } catch (_) {
      // fallback, если dialog недоступен
      root.setAttribute("open", "");
      root.style.cssText =
        "position:fixed;inset:0;z-index:2147483647;width:100vw;height:100vh;border:none;margin:0;padding:0;background:rgba(2,6,23,.92);";
    }
  }

  function scheduleMutationScan() {
    if (mutationScheduled || stopped) return;
    mutationScheduled = true;
    setTimeout(() => {
      mutationScheduled = false;
      scanAndReport(false);
    }, MUTATION_DEBOUNCE_MS);
  }

  function startPeriodic() {
    stopPeriodic();
    if (stopped) return;
    periodicTimer = setInterval(() => {
      if (!document.hidden) scanAndReport(false);
    }, periodicMs);
  }

  function stopPeriodic() {
    if (periodicTimer) {
      clearInterval(periodicTimer);
      periodicTimer = null;
    }
  }

  function shutdown() {
    stopped = true;
    stopPeriodic();
    try {
      obs.disconnect();
    } catch (_) {}
  }

  function pathHasSensitive(path) {
    for (const node of path) {
      if (isFieldElement(node) && isSensitiveInput(node)) return true;
      if (node instanceof HTMLElement && node.tagName === "LABEL") {
        const t = (node.textContent || node.getAttribute("aria-label") || "").trim().toLowerCase();
        if (/^password$|^пароль$/.test(t)) return true;
      }
    }
    return false;
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SHOW_WARNING") showWarning(message.payload || {});
    if (message?.type === "HIDE_WARNING") removeOverlay();
    if (message?.type === "RESCAN") scanAndReport(true);
  });

  let pwdTimer = null;
  let lastSentPwdDigest = "";

  async function computeClientDigest(passwordValue) {
    try {
      const data = new TextEncoder().encode(`legion-client-zk-v1::${passwordValue}`);
      const buf = await crypto.subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
    } catch {
      return "";
    }
  }

  function schedulePasswordCheck(el) {
    if (!(el instanceof HTMLInputElement)) return;
    if (classifyInput(el, true) !== "password") return;
    if (pwdTimer) clearTimeout(pwdTimer);
    pwdTimer = setTimeout(async () => {
      const val = el.value || "";
      if (val.length < 6) return;
      const clientDigest = await computeClientDigest(val);
      if (!clientDigest || clientDigest === lastSentPwdDigest) return;
      lastSentPwdDigest = clientDigest;
      await send({
        type: "PASSWORD_DIGEST_EVENT",
        clientDigest,
        hostname: resolveHostname(),
        url: location.href
      });
    }, 320);
  }

  // composedPath — ловит поля внутри Shadow DOM (в т.ч. закрытого при фокусе)
  const onInteraction = (e) => {
    const path = typeof e.composedPath === "function" ? e.composedPath() : [e.target];
    resetScanCaches();
    if (pathHasSensitive(path)) scanAndReport(true);
    for (const node of path) {
      if (node instanceof HTMLInputElement) {
        schedulePasswordCheck(node);
        break;
      }
    }
  };

  document.addEventListener("focusin", onInteraction, true);
  document.addEventListener("input", onInteraction, true);
  document.addEventListener("change", onInteraction, true);

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scanAndReport(false);
  });

  // клик по "Log in" / открытие модалки
  document.addEventListener(
    "click",
    () => {
      setTimeout(() => scanAndReport(false), 300);
    },
    true
  );

  const obs = new MutationObserver(scheduleMutationScan);
  obs.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["class", "open", "aria-hidden", "hidden", "data-state", "type", "autocomplete"]
  });

  scanAndReport(true);
  startPeriodic();
})();
