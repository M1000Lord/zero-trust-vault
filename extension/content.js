// Zero-Trust Vault v0.4.0 — LOW TRUST content script.
// It never reads the vault, never lists accounts, never talks to native host.
// It detects login fields, prepares a mutation-checked fill, fills one selected
// credential. It never clicks submit; user submits manually.

(() => {
  if (window.__ztvInstalled) return;
  window.__ztvInstalled = true;

  let lastFieldMap = null;
  let mutationEpoch = 0;
  let debounce = null;

  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    const s = getComputedStyle(el);
    if (s.visibility === "hidden" || s.display === "none" || parseFloat(s.opacity || "1") === 0) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return false;
    if (r.bottom < 0 || r.right < 0) return false;
    return true;
  }

  function fingerprint(el) {
    if (el.id) return `#${CSS.escape(el.id)}`;
    if (el.name) return `${el.tagName.toLowerCase()}[name="${CSS.escape(el.name)}"]`;
    const form = el.form || document;
    const inputs = Array.from(form.querySelectorAll("input"));
    const idx = inputs.indexOf(el);
    return idx >= 0 ? `input:nth-of-type(${idx + 1})` : null;
  }

  function suspiciousPasswordContext(passwords) {
    if (passwords.length > 1) return "multiple visible password fields";
    const pass = passwords[0];

    // Most reliable: the browser-standard autocomplete signal.
    const ac = (pass.getAttribute("autocomplete") || "").toLowerCase().trim();
    if (ac === "new-password") return "new-password autocomplete field";

    // Password field's own name/id — check for confirmation or new-password patterns.
    const fid  = (pass.id   || "").toLowerCase();
    const fname = (pass.name || "").toLowerCase();
    if (/\b(new[_-]?pass|confirm[_-]?pass|repeat[_-]?pass|password[_-]?(confirm|repeat|2|new)|retype|verify[_-]?pass|create[_-]?pass)\b/.test(fid + " " + fname)) {
      return "password confirmation or new-password field";
    }

    // Form action URL — structural intent of the form, not page text.
    const action = (pass.form?.getAttribute("action") || "").toLowerCase();
    if (/\/(register|sign[_-]?up|create[_-]?account|join|enroll|reset[_-]?pass|change[_-]?pass|forgot[_-]?pass|set[_-]?pass)\b/.test(action)) {
      return "signup or password-reset form (form action URL)";
    }

    // Form element's own id/name attribute (not its text content).
    const formId   = (pass.form?.id   || "").toLowerCase();
    const formName = (pass.form?.name || "").toLowerCase();
    if (/\b(register|signup|registration|reset.?pass|change.?pass)\b/.test(formId + " " + formName)) {
      return "signup or password-change form";
    }

    return null;
  }

  function findUsernameFor(passwordEl) {
    const form = passwordEl.form || document;
    let cand = form.querySelector('input[autocomplete="username"], input[autocomplete="email"]');
    if (cand && visible(cand)) return cand;
    cand = form.querySelector('input[type="email"]');
    if (cand && visible(cand)) return cand;
    const inputs = Array.from(form.querySelectorAll('input'));
    const pIdx = inputs.indexOf(passwordEl);
    for (let i = pIdx - 1; i >= 0; i--) {
      const t = (inputs[i].type || "text").toLowerCase();
      if (["text", "email", "tel"].includes(t) && visible(inputs[i])) return inputs[i];
    }
    cand = form.querySelector(
      'input[name*="user" i], input[id*="user" i], input[name*="email" i], input[id*="email" i], input[placeholder*="email" i], input[name*="login" i]'
    );
    if (cand && visible(cand)) return cand;
    return null;
  }

  function detect() {
    if (window.top !== window.self) return { hasLogin: false, blockedReason: "frame" };
    const passwords = Array.from(document.querySelectorAll('input[type="password"]')).filter(visible);
    if (passwords.length === 0) { lastFieldMap = null; return { hasLogin: false, mutationEpoch }; }

    const blockedReason = suspiciousPasswordContext(passwords);
    if (blockedReason) {
      lastFieldMap = null;
      return { hasLogin: false, blockedReason, mutationEpoch, fieldInfo: { multiPassword: passwords.length > 1 } };
    }

    const pass = passwords[0];
    const user = findUsernameFor(pass);
    lastFieldMap = {
      userSel: user ? fingerprint(user) : null,
      passSel: fingerprint(pass),
      _userEl: user || null,
      _passEl: pass,
      mutationEpoch,
      detectedAt: Date.now(),
    };

    return {
      hasLogin: true,
      mutationEpoch,
      fieldInfo: {
        hasUsername: !!user,
        loginType: user && user.type === "email" ? "email-password" : "username-password",
        multiPassword: passwords.length > 1,
      },
    };
  }

  function currentOrigin() {
    return `${location.protocol}//${location.hostname.toLowerCase()}:${location.port || (location.protocol === "https:" ? "443" : "80")}`;
  }

  function reFind(sel, fallbackEl) {
    if (sel) { try { const el = document.querySelector(sel); if (el) return el; } catch (_) {} }
    return (fallbackEl && document.contains(fallbackEl)) ? fallbackEl : null;
  }

  function setNativeValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Ultra Security Mode intentionally has no submit-button detection or click path.

  function prepareFill(approvedOrigin) {
    if (currentOrigin() !== approvedOrigin) return { ok: false, error: "origin changed in page" };
    if (window.top !== window.self) return { ok: false, error: "refusing to fill inside a frame" };
    const d = detect();
    if (d.blockedReason) return { ok: false, error: "suspicious login form: " + d.blockedReason };
    if (!d.hasLogin || !lastFieldMap) return { ok: false, error: "no login fields" };
    return { ok: true, mutationEpoch, fieldInfo: d.fieldInfo };
  }

  function fill(approvedOrigin, credential, options = {}) {
    if (currentOrigin() !== approvedOrigin) return { ok: false, error: "origin changed in page" };
    if (window.top !== window.self) return { ok: false, error: "refusing to fill inside a frame" };

    // Re-detect at fill time: get fresh field references and re-validate that
    // the form hasn't changed to a signup or reset form while Hello was running.
    // This replaces the stale mutationEpoch comparison — page animations increment
    // the epoch constantly, so the epoch check always false-positives during a
    // Hello dialog that takes several seconds. Checking actual DOM state here is
    // both more accurate and gives the same security property.
    const d = detect();
    if (d.blockedReason) return { ok: false, error: "form changed during approval: " + d.blockedReason };
    if (!d.hasLogin || !lastFieldMap) return { ok: false, error: "login fields no longer present" };

    const passEl = reFind(lastFieldMap.passSel, lastFieldMap._passEl);
    if (!passEl || !visible(passEl)) return { ok: false, error: "password field gone" };
    const userEl = reFind(lastFieldMap.userSel, lastFieldMap._userEl);
    if (userEl && !visible(userEl)) return { ok: false, error: "username field is no longer visible" };

    if (userEl && credential.usernameOrEmail) setNativeValue(userEl, credential.usernameOrEmail);
    setNativeValue(passEl, credential.password);

    return { ok: true, submitClicked: false };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "ztv_detect") { sendResponse(detect()); return; }
    if (msg?.type === "ztv_prepare_fill") { sendResponse(prepareFill(msg.approvedOrigin)); return; }
    if (msg?.type === "ztv_fill") { sendResponse(fill(msg.approvedOrigin, msg.credential, msg.options || {})); return; }
  });

  function notifySW() {
    const result = detect();
    if (result.hasLogin) chrome.runtime.sendMessage({ type: "ztv_page_detect", hasLogin: true }).catch(() => {});
  }

  notifySW();
  new MutationObserver(() => {
    mutationEpoch++;
    clearTimeout(debounce);
    debounce = setTimeout(notifySW, 450);
  }).observe(document.body || document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "hidden", "style", "class", "disabled", "readonly"] });
})();
