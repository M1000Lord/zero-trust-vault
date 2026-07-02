// Zero-Trust Vault v2.0.0 — MV3 service worker
//
// Security policy:
//   - Local-only. No cloud, no remote code, no broad host permission by default.
//   - No auto-submit, ever.
//   - Vault metadata encrypted: saved origins/labels/timestamps invisible while locked.
//   - Windows Hello required for unlock; fresh Hello before every fill and delete.
//   - HTTP, IDN/punycode, cross-origin frames, and suspicious DOM fail closed.
//
// Architecture note — detached popup window:
//   Chrome's action popup auto-closes the instant ANY other window takes focus,
//   including the Windows Hello credential dialog. Every unlock and every fill
//   would silently fail. We fix this by removing "default_popup" and opening
//   the vault UI via chrome.windows.create({ type: "popup" }) instead. A detached
//   Chrome window stays open regardless of focus changes, so the Hello dialog can
//   appear and complete normally.

// ---- CSPRNG guard (fail closed if WebCrypto is unavailable) -----------------
if (typeof crypto === "undefined" ||
    typeof crypto.subtle === "undefined" ||
    typeof crypto.getRandomValues !== "function") {
  throw new Error("[ZTV] WebCrypto unavailable — refusing to start.");
}

// ---- Runtime file integrity hashes ------------------------------------------
//
// Stamped by tools/update-extension-hashes.ps1 and checked offline by
// tools/verify-extension-integrity.ps1.  While null (dev/first-run) the check is
// SKIPPED — run the updater before distributing to anyone.  When populated,
// every startup re-hashes each file listed here and refuses all SECRET
// operations if any hash does not match (read-only diagnostics stay reachable so
// the dashboard can report the failure).  This catches post-install filesystem
// tampering that Web Store signatures do not protect against.
//
// Files excluded: service_worker.js itself (cannot hash itself).
// Files covered: every file that could influence behaviour or steal credentials.
const INTEGRITY_HASHES = {
  "manifest.json": "4ece72759346dd4a99ac3aa24807f76a2a31003d77996435a066d4ade564dc05",
  "popup.html": "f7bd0d2486ba9b6bb2f08d8e4c12ee4c0e5f84feafc50f2b41dd4b68d8669918",
  "popup.js": "3cfe96a111133de935c4ac20ba40979e12911daaf450906b283100aaeee2c039",
  "popup.css": "22422d3fd00e2c80cdc3d32443f3081897fee749c0477e25eb6f863c612cbed0",
  "content.js": "95926de016241e2df0ac59e51e80bdcd6aa9a212b397f887bb72110bb8e3080c",
};

const NATIVE_HOST            = "com.zerotrust.vault";
const NATIVE_TIMEOUT_MS      = 120000;
const DETECTOR_ID            = "ztv-login-detector";
const SESSION_TIMEOUT_ALARM  = "ztv-session-timeout";

const DEFAULT_SETTINGS = {
  securityMode:          "ultra",
  convenienceEnabled:    false,
  clipboardCopyEnabled:  false,
  sessionTimeoutMinutes: 15,
  site:                  {},
};

// ---- Vault window state (in-memory; reset on SW restart) --------------------

let vaultWindowId = null;   // the open detached vault popup window id
let triggerTabId  = null;   // the browsing tab that launched the vault
let session       = null;   // { sessionId, origin, tabId, presenceMode }
let port          = null;
const pending     = new Map();

// ---- Detached popup management ----------------------------------------------

chrome.windows.onRemoved.addListener((id) => {
  if (id === vaultWindowId) {
    vaultWindowId = null;
    triggerTabId  = null;
    startSessionTimeout();
  }
});

chrome.action.onClicked.addListener(async (tab) => {
  await chrome.alarms.clear(SESSION_TIMEOUT_ALARM);
  triggerTabId = tab?.id ?? null;

  if (vaultWindowId !== null) {
    try { await chrome.windows.update(vaultWindowId, { focused: true }); return; }
    catch (_) { vaultWindowId = null; }
  }

  const win = await chrome.windows.create({
    url:     chrome.runtime.getURL("popup.html"),
    type:    "popup",
    width:   420,
    height:  620,
    focused: true,
  });
  vaultWindowId = win.id;
});

// ---- Startup / install ------------------------------------------------------

chrome.runtime.onInstalled.addListener(async () => {
  await verifyIntegrity();
  await hardenStorage();
  await ensureSettings();
  await refreshDetectorRegistration();
});
chrome.runtime.onStartup.addListener(async () => {
  await verifyIntegrity();
  await hardenStorage();
  await ensureSettings();
  await refreshDetectorRegistration();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === SESSION_TIMEOUT_ALARM) { await lock(); }
});

async function hardenStorage() {
  try { await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }); }
  catch (_) {}
}

async function ensureSettings() {
  const s = await readSettings();
  await chrome.storage.local.set({ ztvSecuritySettings: normalizeSettings(s) });
}

async function readSettings() {
  const r = await chrome.storage.local.get("ztvSecuritySettings");
  return normalizeSettings(r.ztvSecuritySettings || DEFAULT_SETTINGS);
}

function normalizeSettings(raw) {
  const clean = {
    ...DEFAULT_SETTINGS,
    ...(raw || {}),
    site: { ...((raw && raw.site) || {}) },
  };
  clean.securityMode = clean.convenienceEnabled ? "convenience-detector" : "ultra";
  clean.clipboardCopyEnabled = clean.clipboardCopyEnabled === true;
  if (typeof clean.sessionTimeoutMinutes !== "number" || clean.sessionTimeoutMinutes < 0)
    clean.sessionTimeoutMinutes = 15; // clamp out "Never" — not permitted in production
  for (const [origin, value] of Object.entries(clean.site || {})) {
    clean.site[origin] = { autoPrompt: value?.autoPrompt === true };
  }
  return clean;
}

function siteSettings(settings, origin) {
  const entry = origin ? settings.site?.[origin] : null;
  return { autoPrompt: entry?.autoPrompt === true };
}

async function hasHttpsHostPermission() {
  try { return await chrome.permissions.contains({ origins: ["https://*/*"] }); }
  catch (_) { return false; }
}

// ---- Runtime integrity verification -----------------------------------------

let _integrityPassed = null; // null = unchecked, true = ok, false = failed

// Structured result for the health dashboard. Failing files carry expected vs.
// actual hashes so a developer can see exactly what drifted; the popup only ever
// surfaces file NAMES, never asks the user to eyeball hashes.
let _integrityResult = {
  status:            "unchecked", // "unchecked" | "passed" | "failed" | "skipped"
  checkedFilesCount: 0,
  failingFilesCount: 0,
  failingFiles:      [],          // [{ file, expected?, actual?, error? }]
  lastCheckedAt:     null,        // ISO string
};

const INTEGRITY_REMEDIATION =
  "Extension integrity check failed. Run tools/update-extension-hashes.ps1 after legitimate source changes, then reload the extension.";

async function verifyIntegrity() {
  const checkedAt = new Date().toISOString();

  if (INTEGRITY_HASHES === null) {
    console.warn("[ZTV] Integrity hashes not set — run tools/update-extension-hashes.ps1 before distributing.");
    _integrityPassed = true;
    _integrityResult = {
      status: "skipped", checkedFilesCount: 0, failingFilesCount: 0,
      failingFiles: [], lastCheckedAt: checkedAt,
    };
    return { ok: true, skipped: true };
  }

  const entries  = Object.entries(INTEGRITY_HASHES);
  const failures = [];
  for (const [file, expectedHex] of entries) {
    try {
      const resp = await fetch(chrome.runtime.getURL(file), { cache: "no-store" });
      if (!resp.ok) { failures.push({ file, error: "HTTP " + resp.status }); continue; }
      const buf  = await resp.arrayBuffer();
      const raw  = await crypto.subtle.digest("SHA-256", buf);
      const hex  = Array.from(new Uint8Array(raw)).map(b => b.toString(16).padStart(2, "0")).join("");
      if (hex !== expectedHex) failures.push({ file, expected: expectedHex, actual: hex });
    } catch (e) {
      failures.push({ file, error: String(e?.message || e) });
    }
  }

  if (failures.length > 0) {
    _integrityPassed = false;
    session = null;
    // Log each failing file on its own line so the cause is unambiguous in the
    // service-worker console (chrome://extensions -> service worker -> Inspect).
    console.error("[ZTV] INTEGRITY FAILURE — " + failures.length + " file(s) do not match:");
    for (const f of failures) {
      if (f.error) {
        console.error("  • " + f.file + " : ERROR " + f.error);
      } else {
        console.error("  • " + f.file + " : MISMATCH");
        console.error("      expected " + f.expected);
        console.error("      actual   " + f.actual);
      }
    }
    console.error("[ZTV] " + INTEGRITY_REMEDIATION);

    _integrityResult = {
      status:            "failed",
      checkedFilesCount: entries.length,
      failingFilesCount: failures.length,
      failingFiles:      failures,
      lastCheckedAt:     checkedAt,
    };

    chrome.action.setBadgeText({ text: "!!" });
    chrome.action.setBadgeBackgroundColor({ color: "#e34948" });
    chrome.action.setTitle({
      title: "Zero-Trust Vault: INTEGRITY FAILURE — " +
             failures.map(f => f.file).join(", ") + " — secret operations blocked",
    });
    return { ok: false, failures };
  }

  _integrityPassed = true;
  _integrityResult = {
    status:            "passed",
    checkedFilesCount: entries.length,
    failingFilesCount: 0,
    failingFiles:      [],
    lastCheckedAt:     checkedAt,
  };
  // Clear any stale failure badge from a previous load.
  try { chrome.action.setBadgeText({ text: "" }); } catch (_) {}
  return { ok: true, failures: [] };
}

// True when the extension is loaded unpacked (developer mode): no packed key and
// no store update_url. In this mode a hash mismatch is almost always "edited a
// file, didn't reload the service worker yet" rather than real tampering.
function isUnpackedDevMode() {
  const m = chrome.runtime.getManifest();
  return !m.key && !(typeof m.update_url === "string" && m.update_url.length > 0);
}

// Gate for SECRET operations. Per the security spec, a *production* integrity
// mismatch blocks secret operations. In UNPACKED DEV mode we warn loudly but do
// NOT block — otherwise a stale service worker silently kills unlock/fill and the
// Windows Hello prompt never appears. Read-only diagnostics are never gated, so
// the dashboard can always report the failure.
async function assertIntegrity() {
  if (_integrityPassed === null) await verifyIntegrity();
  if (_integrityPassed === false) {
    const names = _integrityResult.failingFiles.map(f => f.file).join(", ") || "unknown file(s)";
    if (isUnpackedDevMode()) {
      console.warn("[ZTV] Integrity mismatch in UNPACKED DEV mode (" + names +
        "). Not blocking secret operations. Reload the extension after legitimate " +
        "edits (tools/update-extension-hashes.ps1 keeps the map current).");
      return;
    }
    throw new Error(
      "Integrity check failed (" + names + "). " + INTEGRITY_REMEDIATION);
  }
}

// Returns the structured integrity status; never throws, never exposes secrets.
async function getIntegrityStatus() {
  if (_integrityPassed === null) await verifyIntegrity();
  return {
    ok: _integrityResult.status === "passed" || _integrityResult.status === "skipped",
    integrity: {
      status:            _integrityResult.status,
      checkedFilesCount: _integrityResult.checkedFilesCount,
      failingFilesCount: _integrityResult.failingFilesCount,
      failingFileNames:  _integrityResult.failingFiles.map(f => f.file),
      lastCheckedAt:     _integrityResult.lastCheckedAt,
      remediation:       _integrityResult.status === "failed" ? INTEGRITY_REMEDIATION : null,
    },
  };
}

async function startSessionTimeout() {
  if (!session) return;
  const settings = await readSettings();
  const timeout  = settings.sessionTimeoutMinutes;
  if (timeout === 0)  { await lock(); return; }
  if (timeout < 0)    return;
  chrome.alarms.create(SESSION_TIMEOUT_ALARM, { delayInMinutes: timeout });
}

async function refreshDetectorRegistration() {
  const settings = await readSettings();
  const hasPerm  = await hasHttpsHostPermission();
  const shouldRegister = settings.convenienceEnabled === true && hasPerm === true;

  try { await chrome.scripting.unregisterContentScripts({ ids: [DETECTOR_ID] }); }
  catch (_) {}

  if (!shouldRegister) return;

  await chrome.scripting.registerContentScripts([{
    id:                    DETECTOR_ID,
    matches:               ["https://*/*"],
    js:                    ["content.js"],
    runAt:                 "document_idle",
    allFrames:             false,
    persistAcrossSessions: true,
  }]);
}

// ---- Origin helpers ---------------------------------------------------------

function normalizeOrigin(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const port = u.port || (u.protocol === "https:" ? "443" : "80");
    return `${u.protocol}//${u.hostname.toLowerCase()}:${port}`;
  } catch { return null; }
}

function originHost(origin) {
  try { return new URL(origin).hostname.toLowerCase(); } catch { return ""; }
}

function isHttpOrigin(origin)  { return !!origin && origin.startsWith("http://"); }
function isIdnOrigin(origin)   { return !!origin && origin.includes("xn--"); }

function isHighRiskOrigin(origin) {
  const h = originHost(origin);
  const risky = [
    "bank", "paypal", "stripe", "wise", "revolut", "skrill", "payoneer",
    "visa", "mastercard", "coinbase", "binance", "kraken", "bitfinex",
    "bybit", "okx", "crypto", "wallet", "accounts.google",
    "login.microsoftonline", "appleid.apple", "icloud", "facebook", "instagram",
  ];
  return risky.some(x => h.includes(x));
}

function assertSafeOriginForCredentialUse(origin) {
  if (!origin)              throw new Error("No valid origin");
  if (isHttpOrigin(origin)) throw new Error("HTTP origin blocked — credentials are never released on insecure pages");
  if (isIdnOrigin(origin))  throw new Error("Punycode/IDN origin blocked — verify the real domain before saving");
}

// ---- Tab resolution ---------------------------------------------------------

// Returns the target browsing tab (the login page to fill into).
// Preference: tab that triggered the vault → active HTTP/HTTPS tab in the
// last-focused normal window. Returns null if no suitable tab found.
async function targetTab() {
  if (triggerTabId !== null) {
    try {
      const tab = await chrome.tabs.get(triggerTabId);
      if (tab?.url?.startsWith("http")) return tab;
    } catch (_) { triggerTabId = null; }
  }

  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true, windowType: "normal" });
  return tabs.find(t => t.url?.startsWith("http")) || tabs[0] || null;
}

// ---- Native messaging -------------------------------------------------------

function ensurePort() {
  if (port) return port;
  port = chrome.runtime.connectNative(NATIVE_HOST);
  port.onMessage.addListener((msg) => {
    const p = pending.get(msg.requestId);
    if (p) { pending.delete(msg.requestId); p.resolve(msg); }
  });
  port.onDisconnect.addListener(() => {
    const why = chrome.runtime.lastError?.message || "native host disconnected";
    port = null;
    for (const [, p] of pending) p.reject(new Error(why));
    pending.clear();
    session = null;
  });
  return port;
}

function nativeCall(command, { origin, sessionId, payload, tab } = {}) {
  return new Promise((resolve, reject) => {
    let p;
    try { p = ensurePort(); }
    catch (e) { return reject(new Error("Native host not installed: " + e.message)); }

    const requestId = crypto.randomUUID();
    pending.set(requestId, { resolve, reject });

    const req = {
      protocolVersion: 1,
      requestId,
      command,
      timestamp:   new Date().toISOString(),
      clientNonce: crypto.randomUUID(),
      extensionId: chrome.runtime.id,
      origin,
      tabId:       Number.isInteger(tab?.id) ? tab.id : undefined,
      windowId:    Number.isInteger(tab?.windowId) ? tab.windowId : undefined,
      frameId:     0,
      sessionId,
      payload:     payload || {},
    };

    try { p.postMessage(req); }
    catch (e) { pending.delete(requestId); return reject(e); }

    setTimeout(() => {
      if (pending.has(requestId)) {
        pending.delete(requestId);
        reject(new Error("native host timeout after " + NATIVE_TIMEOUT_MS / 1000 + "s"));
      }
    }, NATIVE_TIMEOUT_MS);
  });
}

// ---- Message router ---------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "ztv_page_detect") {
    handlePageDetect(sender).catch(() => {});
    return;
  }
  handle(msg, sender).then(sendResponse).catch((e) =>
    sendResponse({ ok: false, error: String(e?.message || e) }));
  return true;
});

// Badge the tab when the detector content script finds a login form.
// We never auto-open the popup — that always requires an explicit user click.
async function handlePageDetect(sender) {
  const tabId = sender?.tab?.id;
  const url   = sender?.tab?.url;
  if (!tabId || !url) return;
  const origin = normalizeOrigin(url);
  if (!origin) return;

  const settings = await readSettings();
  if (!settings.convenienceEnabled) return;

  chrome.action.setBadgeBackgroundColor({ color: "#5b8cff", tabId });
  chrome.action.setBadgeText({ text: "·", tabId });
  chrome.action.setTitle({ title: "Zero-Trust Vault — login form detected", tabId });
}

// Read-only diagnostics that must remain reachable EVEN when integrity has
// failed, so the popup can explain why the vault is locked down. None of these
// release a secret or mutate the vault.
const INTEGRITY_EXEMPT = new Set([
  "getIntegrityStatus",
  "securityHealthCheck",
  "getSecuritySettings",
  "getSessionTimeout",
]);

async function handle(msg, sender) {
  if (!INTEGRITY_EXEMPT.has(msg.type)) await assertIntegrity();
  switch (msg.type) {
    case "getIntegrityStatus":     return getIntegrityStatus();
    case "getContext":             return getContext();
    case "status":                 return nativeStatus();
    case "countOrigin":            return countForOrigin();
    case "checkSession":           return checkSession();
    case "getSecuritySettings":    return getSecuritySettings();
    case "updateSecuritySettings": return updateSecuritySettings(msg.patch || {});
    case "getSessionTimeout":      return getSessionTimeout();
    case "setSessionTimeout":      return setSessionTimeout(msg.minutes);
    case "unlock":                 return unlock();
    case "listFill":               return listFill();
    case "fill":                   return fill(msg.credentialId);
    case "add":                    return addCredential(msg);
    case "update":                 return updateCredential(msg);
    case "delete":                 return deleteCredential(msg.credentialId);
    case "lock":                   return lock();
    case "generateTotp":           return generateTotp(msg);
    case "copyTotp":               return copyTotpWithTimedClear(msg);
    case "securityHealthCheck":    return securityHealthCheck();
    default:                       throw new Error("unknown message type: " + msg.type);
  }
}

// ---- Command implementations ------------------------------------------------

async function getContext() {
  const tab = await targetTab();
  if (!tab || !tab.url) return { ok: true, origin: null, reason: "no target tab" };
  const origin = normalizeOrigin(tab.url);
  if (!origin) return { ok: true, origin: null, reason: "unsupported scheme" };

  let detect = { hasLogin: false };
  try {
    if (tab.url.startsWith("http")) {
      await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: false }, files: ["content.js"] });
      detect = await chrome.tabs.sendMessage(tab.id, { type: "ztv_detect", approvedOrigin: origin });
    }
  } catch (_) {}

  return {
    ok:            true,
    origin,
    tabId:         tab.id,
    isHttp:        isHttpOrigin(origin),
    isIdn:         isIdnOrigin(origin),
    isHighRisk:    isHighRiskOrigin(origin),
    hasLogin:      !!detect?.hasLogin,
    blockedReason: detect?.blockedReason || null,
    fieldInfo:     detect?.fieldInfo || null,
  };
}

async function nativeStatus() {
  const r = await nativeCall("getVaultStatus");
  return { ok: r.status === "ok", result: r.result, error: r.error };
}

async function countForOrigin() {
  const tab    = await targetTab();
  const origin = tab?.url ? normalizeOrigin(tab.url) : null;
  if (!origin) return { ok: true, count: 0, privateMetadata: true };
  const r = await nativeCall("countCredentialsForOrigin", { origin, tab });
  return { ok: r.status === "ok", count: r.result?.count ?? 0, privateMetadata: r.result?.privateMetadata === true };
}

async function checkSession() {
  if (!session) return { ok: true, valid: false };
  const tab    = await targetTab();
  const origin = tab?.url ? normalizeOrigin(tab.url) : null;
  if (!origin || origin !== session.origin) return { ok: true, valid: false };
  return { ok: true, valid: true };
}

async function getSecuritySettings() {
  const settings = await readSettings();
  const tab      = await targetTab();
  const origin   = tab?.url ? normalizeOrigin(tab.url) : null;
  const site     = siteSettings(settings, origin);
  return {
    ok: true,
    settings: {
      securityMode:           settings.securityMode,
      convenienceEnabled:     settings.convenienceEnabled,
      httpsHostPermission:    await hasHttpsHostPermission(),
      clipboardCopyEnabled:   settings.clipboardCopyEnabled === true,
      site,
      origin,
      isHighRisk:             isHighRiskOrigin(origin),
      isHttp:                 isHttpOrigin(origin),
      isIdn:                  isIdnOrigin(origin),
      autoSubmitAvailable:    false,
      privateMetadata:        true,
      fillRequiresFreshHello: true,
      sessionTimeoutMinutes:  settings.sessionTimeoutMinutes,
    },
  };
}

async function updateSecuritySettings(patch) {
  const current = await readSettings();
  const tab     = await targetTab();
  const origin  = tab?.url ? normalizeOrigin(tab.url) : null;

  if (typeof patch.convenienceEnabled === "boolean") current.convenienceEnabled = patch.convenienceEnabled;
  if (typeof patch.clipboardCopyEnabled === "boolean") current.clipboardCopyEnabled = patch.clipboardCopyEnabled;
  current.securityMode = current.convenienceEnabled ? "convenience-detector" : "ultra";

  if (origin && patch.site) {
    const old = siteSettings(current, origin);
    current.site[origin] = {
      autoPrompt: typeof patch.site.autoPrompt === "boolean" ? patch.site.autoPrompt : old.autoPrompt,
    };
  }

  await chrome.storage.local.set({ ztvSecuritySettings: current });
  await refreshDetectorRegistration();
  return getSecuritySettings();
}

async function unlock() {
  const tab    = await targetTab();
  const origin = tab?.url ? normalizeOrigin(tab.url) : null;
  assertSafeOriginForCredentialUse(origin);

  const r = await nativeCall("unlockOrigin", { origin, tab });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "unlock failed");

  session = { sessionId: r.result.sessionId, origin, tabId: tab?.id ?? null, presenceMode: r.result.presenceMode };
  return { ok: true, accounts: r.result.accounts || [], presenceMode: r.result.presenceMode, fillRequiresFreshHello: true };
}

async function listFill() {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);
  const r = await nativeCall("listSummariesForOrigin", { origin: session.origin, sessionId: session.sessionId, tab: { id: session.tabId } });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "list failed");
  return { ok: true, accounts: r.result.accounts || [], fillRequiresFreshHello: true };
}

async function fill(credentialId) {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);

  let tab = null;
  try {
    if (session.tabId !== null && session.tabId !== undefined)
      tab = await chrome.tabs.get(session.tabId);
  } catch (_) { tab = null; }

  const nowOrigin = tab?.url ? normalizeOrigin(tab.url) : null;

  // Require the tab to still be the active tab in its window (prevents filling
  // into a hidden background tab). We do NOT require the window to be focused
  // because the vault popup itself is the currently focused window.
  if (tab && !tab.active) throw new Error("Login tab is not active — switch to the login page, then click Fill");
  if (!tab || nowOrigin !== session.origin) throw new Error("Login tab changed since unlock — fill blocked for safety");

  // Pre-check the DOM state before decrypting anything.
  await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: false }, files: ["content.js"] }).catch(() => {});

  const prep = await chrome.tabs.sendMessage(tab.id, { type: "ztv_prepare_fill", approvedOrigin: session.origin }).catch(() => null);
  if (!prep?.ok) throw new Error(prep?.error || "Fill pre-check failed — is the login form still visible?");

  // Decrypt for fill (triggers fresh Windows Hello in the native host). Uses
  // the dedicated fill command, NOT the generic reveal command — the native
  // host requires tab/window binding for this command specifically, so a
  // reveal-only credential release can never happen through the autofill path.
  const r = await nativeCall("fillCredentialForExactOrigin", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab,
    payload:   { credentialId },
  });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "decrypt failed");

  let cred = r.result;
  try {
    const fillResult = await chrome.tabs.sendMessage(tab.id, {
      type:           "ztv_fill",
      approvedOrigin: session.origin,
      credential:     { usernameOrEmail: cred.usernameOrEmail, password: cred.password },
      options:        { submitAfterFill: false },
    });
    if (!fillResult?.ok) throw new Error(fillResult?.error || "fill rejected by page");

    // Bring the login page into focus so the user can click Sign in.
    try {
      await chrome.tabs.update(tab.id, { active: true });
      if (typeof tab.windowId === "number") await chrome.windows.update(tab.windowId, { focused: true });
    } catch (_) {}

    return { ok: true, submitClicked: false, fillRequiresFreshHello: true };
  } finally {
    if (cred) { cred.usernameOrEmail = ""; cred.password = ""; }
    cred = null;
  }
}

async function addCredential(msg) {
  const tab    = await targetTab();
  const origin = tab?.url ? normalizeOrigin(tab.url) : null;
  assertSafeOriginForCredentialUse(origin);
  if (!msg.usernameOrEmail || !msg.password) throw new Error("username and password required");

  const r = await nativeCall("addCredentialForExactOrigin", {
    origin,
    tab,
    payload: {
      usernameOrEmail: msg.usernameOrEmail,
      password:        msg.password,
      label:           msg.displayLabel || "",
      totpSecret:      msg.totpSecret   || null,
    },
  });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "save failed");

  session = { sessionId: r.result.sessionId, origin, tabId: tab.id, presenceMode: r.result.presenceMode };
  return { ok: true, fillRequiresFreshHello: true };
}

async function updateCredential(msg) {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);
  if (!msg.credentialId)      throw new Error("credential id required");
  if (!msg.usernameOrEmail)   throw new Error("username required");
  if (!msg.password)          throw new Error("password required");

  // Prefer atomic update (native host v2 — no duplicate risk).
  const atomicR = await nativeCall("updateCredentialAtomic", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab:       { id: session.tabId },
    payload:   {
      credentialId:    msg.credentialId,
      usernameOrEmail: msg.usernameOrEmail,
      password:        msg.password,
      label:           msg.displayLabel || "",
      totpSecret:      msg.totpSecret   || null,
    },
  }).catch(() => null);

  if (atomicR?.status === "ok") {
    session = { ...session, sessionId: atomicR.result?.sessionId || session.sessionId };
    return { ok: true, accounts: atomicR.result.accounts || [] };
  }

  // Fall back to add-then-delete for native host v1 (no atomic update command).
  const addR = await nativeCall("addCredentialForExactOrigin", {
    origin:  session.origin,
    tab:     { id: session.tabId },
    payload: {
      usernameOrEmail:  msg.usernameOrEmail,
      password:         msg.password,
      label:            msg.displayLabel || "",
      totpSecret:       msg.totpSecret   || null,
    },
  });
  if (addR.status !== "ok") throw new Error(addR.error?.safeMessage || "update failed");
  // Preserve the existing sessionId if the native host did not return one, so a
  // successful add never corrupts the session (same guard as the atomic path).
  session = { ...session, sessionId: addR.result?.sessionId || session.sessionId };

  try {
    await nativeCall("deleteCredentialTombstone", {
      origin:    session.origin,
      sessionId: session.sessionId,
      tab:       { id: session.tabId },
      payload:   { credentialId: msg.credentialId },
    });
  } catch (e) {
    console.warn("[ZTV] Old credential not removed after update:", e.message);
  }

  const listR = await nativeCall("listSummariesForOrigin", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab:       { id: session.tabId },
  });
  return { ok: true, accounts: listR.result?.accounts || [] };
}

async function deleteCredential(credentialId) {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);
  if (!credentialId) throw new Error("credential id required");

  const r = await nativeCall("deleteCredentialTombstone", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab:       { id: session.tabId },
    payload:   { credentialId },
  });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "delete failed");
  return { ok: true };
}

async function getSessionTimeout() {
  const settings = await readSettings();
  const alarm    = await chrome.alarms.get(SESSION_TIMEOUT_ALARM);
  return {
    ok:                    true,
    sessionTimeoutMinutes: settings.sessionTimeoutMinutes,
    locksAt:               alarm ? alarm.scheduledTime : null,
  };
}

async function setSessionTimeout(minutes) {
  if (typeof minutes !== "number" || minutes < 0)
    throw new Error("'Never' timeout is not permitted in production security mode. Use 0 (immediate), 5, 15, or 30 minutes.");
  const current = await readSettings();
  current.sessionTimeoutMinutes = minutes;
  await chrome.storage.local.set({ ztvSecuritySettings: current });
  await chrome.alarms.clear(SESSION_TIMEOUT_ALARM);
  if (session) {
    const t = current.sessionTimeoutMinutes;
    if (t === 0)  { await lock(); }
    else if (t > 0) chrome.alarms.create(SESSION_TIMEOUT_ALARM, { delayInMinutes: t });
  }
  return { ok: true, sessionTimeoutMinutes: current.sessionTimeoutMinutes };
}

async function generateTotp(msg) {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);
  if (!msg.credentialId) throw new Error("credential id required");

  const r = await nativeCall("generateTotpForCredential", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab:       { id: session.tabId },
    payload:   { credentialId: msg.credentialId },
  });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "TOTP generation failed — native host v2 required");
  return { ok: true, code: r.result.code, secondsRemaining: r.result.secondsRemaining };
}

async function copyTotpWithTimedClear(msg) {
  if (!session) throw new Error("locked");
  assertSafeOriginForCredentialUse(session.origin);
  if (!msg.credentialId) throw new Error("credential id required");

  const settings = await readSettings();
  if (settings.clipboardCopyEnabled !== true)
    throw new Error("Clipboard copy is disabled. Enable the advanced clipboard setting first.");

  const r = await nativeCall("copySecretWithTimedClear", {
    origin:    session.origin,
    sessionId: session.sessionId,
    tab:       { id: session.tabId },
    payload:   { credentialId: msg.credentialId, secretType: "totp" },
  });
  if (r.status !== "ok") throw new Error(r.error?.safeMessage || "copy failed");
  return { ok: true, clearsInSeconds: r.result?.clearsInSeconds ?? 15 };
}

async function securityHealthCheck() {
  let nativeHealth = {};
  try {
    const r = await nativeCall("securityHealthCheck");
    if (r.status === "ok") nativeHealth = r.result || {};
  } catch (_) {}

  const settings = await readSettings();
  const manifest = chrome.runtime.getManifest();

  // Make sure the integrity check has run at least once so the dashboard never
  // shows a stale "unchecked".
  if (_integrityPassed === null) { try { await verifyIntegrity(); } catch (_) {} }

  return {
    ok: true,
    health: {
      ...nativeHealth,
      // Legacy boolean kept for backward compatibility with older popups.
      extensionIntegrityPassed: _integrityPassed,
      // Rich, truthful integrity status for the dashboard.
      extensionIntegrity: {
        status:            _integrityResult.status,
        checkedFilesCount: _integrityResult.checkedFilesCount,
        failingFilesCount: _integrityResult.failingFilesCount,
        failingFileNames:  _integrityResult.failingFiles.map(f => f.file),
        lastCheckedAt:     _integrityResult.lastCheckedAt,
      },
      extensionVersion:         manifest.version,
      extensionUnpacked:        !manifest.key,
      // Honest packaging classification — unpacked dev loads are NOT a signed
      // store package, and we never claim otherwise.
      packageMode:              classifyPackageMode(manifest),
      sessionTimeoutMinutes:    settings.sessionTimeoutMinutes,
      clipboardCopyEnabled:     settings.clipboardCopyEnabled ?? false,
      usbBackupEnabled:         settings.usbBackupEnabled ?? false,
      totpInNativeHost:         true,
      neverTimeoutAllowed:      false,
    },
  };
}

// Classify how this extension was loaded. We can reliably distinguish unpacked
// developer mode (no manifest.key, dev install) from a packed/store build, but
// we cannot prove WHICH store from inside the page — so anything not provably
// unpacked is reported as "packed_unsigned" / "unknown", never a false
// "webstore_signed".
function classifyPackageMode(manifest) {
  // update_url is injected by Chrome only for store-distributed extensions.
  const fromStore = typeof manifest.update_url === "string" && manifest.update_url.length > 0;
  if (!manifest.key && !fromStore) return "unpacked_developer_mode";
  if (fromStore) return "store_managed_unverified"; // cannot prove which store from here
  return "packed_unsigned";
}

async function lock() {
  await chrome.alarms.clear(SESSION_TIMEOUT_ALARM);
  try { await nativeCall("lockOriginSession", { sessionId: session?.sessionId }); } catch (_) {}
  session = null;
  return { ok: true };
}
