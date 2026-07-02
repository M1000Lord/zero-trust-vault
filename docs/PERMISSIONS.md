# Zero-Trust Vault — Chrome Extension Permission Justification

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. Overview

ZTV requests the minimum set of Chrome extension permissions required to function. This document explains exactly why each permission is needed, what it allows, and what it does not allow. For each permission, the specific API calls that use it are identified.

ZTV does not request, and explicitly does not use:
- `cookies` — not needed; ZTV does not interact with session cookies
- `history` — not needed; ZTV does not access browsing history
- `bookmarks` — not needed
- `identity` — not needed; ZTV has its own identity model (Windows Hello + device graph)
- `webRequest` or `declarativeNetRequest` — not needed; ZTV does not inspect or modify network traffic
- `clipboardRead` or `clipboardWrite` — not needed; fill is done via DOM assignment, not clipboard
- `<all_urls>` — not requested as a static permission; see host permissions below
- `management` — not needed; ZTV does not manage other extensions

---

## 2. Required Permissions

### 2.1 `nativeMessaging`

**What this permission allows:**  
The extension can open a native messaging channel to a registered native host application, identified by a name string (`com.zerotrustvault.host`). The native host must be registered in the Windows registry under the extension's ID.

**Why ZTV needs it:**  
All cryptographic operations, origin validation, TOTP generation, and vault read/write operations are performed by the native host (`ZeroTrustVault.Host.exe`). The extension is a UI front-end only. Without `nativeMessaging`, the extension cannot communicate with the native host, and no security operations can be performed.

**APIs used:**  
`chrome.runtime.connectNative('com.zerotrustvault.host')` — called from `service_worker.js` to establish the message channel.

**What this permission does NOT allow:**  
The permission allows connection only to the specific named host. The `allowed_origins` field in the host manifest restricts which extension IDs can connect to the native host — a side benefit is that other extensions cannot connect to the ZTV native host even if they have `nativeMessaging` permission.

---

### 2.2 `activeTab`

**What this permission allows:**  
When the user invokes the extension (e.g., clicks the toolbar icon), the extension gains temporary access to the currently active tab's URL, title, and the ability to run scripts in that tab.

**Why ZTV needs it:**  
`service_worker.js` uses `chrome.tabs.query({active: true, currentWindow: true})` to obtain the current tab's URL and extract the origin (`https://host:port`). This origin is sent to the native host for credential matching. Without knowing the current tab's origin, the native host cannot look up the correct credential.

**APIs used:**  
`chrome.tabs.query({active: true, currentWindow: true})` in `service_worker.js`.

**What this permission does NOT allow:**  
`activeTab` does not grant persistent access to all tabs. It grants access only to the single currently active tab, only at the moment the user interacts with the extension. Background access to tabs is not granted by this permission.

---

### 2.3 `scripting`

**What this permission allows:**  
The extension can inject scripts (`content.js`) into web pages and execute them in the page's context.

**Why ZTV needs it:**  
ZTV injects `content.js` into the active tab to:
1. Detect login form fields (username and password inputs).
2. Fill those fields with the credential value returned by the native host.

Without `scripting`, ZTV cannot interact with the web page's DOM at all.

**APIs used:**  
`chrome.scripting.executeScript({target: {tabId}, files: ['content.js']})` — called from `service_worker.js` when a fill is triggered.

**What this permission does NOT allow:**  
`scripting` alone does not grant access to all pages. Without a host permission or `activeTab` grant, the extension cannot inject into arbitrary pages. ZTV relies on `activeTab` to scope script injection to the current user-active tab only.

---

### 2.4 `storage`

**What this permission allows:**  
The extension can read and write to `chrome.storage.local` and `chrome.storage.sync`.

**Why ZTV needs it:**  
ZTV uses `chrome.storage.local` to persist user settings:
- Session timeout duration
- IDN opt-in preference
- Popup window size and position preferences
- Last-used settings

**Critical constraint:** ZTV never stores secrets, credential values, vault keys, or any sensitive material in `chrome.storage`. All sensitive data is in the native host's vault file. The extension's storage contains only non-sensitive configuration.

**APIs used:**  
`chrome.storage.local.get(...)` and `chrome.storage.local.set(...)` in `service_worker.js` and `popup.js`.

---

### 2.5 `alarms`

**What this permission allows:**  
The extension can create, manage, and respond to Chrome alarms — periodic or one-shot timer events that fire even when the service worker is not active.

**Why ZTV needs it:**  
Chrome MV3 service workers are ephemeral — they are stopped by the browser when idle and restarted on demand. Standard JavaScript timers (`setTimeout`, `setInterval`) do not survive a service worker restart. ZTV uses `chrome.alarms` to implement session timeout reliably: the alarm fires after the configured idle period, and the service worker (restarted by the alarm event) sends a "lock vault" command to the native host.

Without `alarms`, a user who sets a 15-minute session timeout might find their session never locks if Chrome decides to stop the service worker before the timer fires.

**APIs used:**  
`chrome.alarms.create('sessionTimeout', {delayInMinutes: N})` and `chrome.alarms.onAlarm.addListener(...)` in `service_worker.js`.

---

### 2.6 `tabs`

**What this permission allows:**  
The extension can query and interact with browser tabs (read URLs of all open tabs when using `chrome.tabs.query` with broad parameters; focus or create tabs).

**Why ZTV needs it:**  
ZTV uses `tabs` for two purposes:
1. To retrieve the active tab's URL more reliably in edge cases where `activeTab` is insufficient (e.g., when the popup is opened as a detached window).
2. To bring the correct login page tab into focus after a fill is triggered from the popup.

**APIs used:**  
`chrome.tabs.query(...)`, `chrome.tabs.update({active: true})` in `service_worker.js`.

**Security note:** The `tabs` permission grants the ability to read URLs of all open tabs (not just the active one) when used without `activeTab`. ZTV restricts its tab queries to `{active: true, currentWindow: true}` to avoid reading URLs of non-active tabs. This restriction is enforced in code, not by the permission itself. The AUDIT_CHECKLIST.md includes a check for this.

---

### 2.7 `windows`

**What this permission allows:**  
The extension can create, query, and manage Chrome windows.

**Why ZTV needs it:**  
The ZTV popup is created as a detached Chrome window (`chrome.windows.create({type: 'popup', ...})`) rather than as the standard extension action popup. This is necessary because Windows Hello triggers a system-level UI prompt that takes focus away from the browser window. When a standard extension popup loses focus, Chrome closes it. A detached window survives focus changes, which means the ZTV popup remains open while Windows Hello is in progress.

**APIs used:**  
`chrome.windows.create({type: 'popup', url: 'popup.html', ...})` in `service_worker.js`.

---

## 3. Optional Host Permission

### 3.1 `https://*/*` (Optional Host Permission)

**What this permission allows:**  
The extension can access all HTTPS pages as a host permission. This grants `scripting` injection rights and `activeTab`-equivalent access across all HTTPS sites without requiring user interaction.

**Why ZTV requests this optionally:**  
By default, ZTV relies on `activeTab` to restrict form detection and fill to only the tab the user is actively interacting with. The optional host permission enables a "convenience form detector" feature: when enabled, the extension proactively detects login forms as they load, allowing it to show the fill badge without the user needing to click the toolbar icon first.

**Default status:** Off. The user must explicitly enable "Convenience Form Detector" in Settings, which triggers Chrome's permission request dialog for `https://*/*`.

**Why it is optional, not required:**  
This broad permission is not required for core fill functionality. Making it optional and requiring explicit user opt-in follows the principle of minimum viable permissions. Users who prefer not to grant broad site access can use ZTV's full credential fill capability without it.

**APIs used (when enabled):**  
`chrome.scripting.registerContentScripts([{matches: ['https://*/*'], js: ['content.js'], ...}])`.

---

## 4. Permissions Summary Table

| Permission | Required | Granted By | Primary Use in ZTV |
|-----------|----------|-----------|-------------------|
| `nativeMessaging` | Yes | Manifest | All crypto via native host |
| `activeTab` | Yes | Manifest | Current tab origin for credential match |
| `scripting` | Yes | Manifest | Inject content.js for form detection and fill |
| `storage` | Yes | Manifest | Settings persistence only (no secrets) |
| `alarms` | Yes | Manifest | Session timeout across SW restarts |
| `tabs` | Yes | Manifest | Tab focus management; popup coordination |
| `windows` | Yes | Manifest | Detached popup window (survives Hello focus change) |
| `https://*/*` | No | User opt-in | Convenience form detector (off by default) |

---

## 5. Security Principle

ZTV's permission model follows the principle: **request only what is needed, and explain every permission explicitly.**

No permission is requested "for future use." If a future feature requires a new permission, the permission will be added at that version and documented here. The absence of broad permissions (no `<all_urls>`, no `cookies`, no `webRequest`) is a deliberate security choice that limits the blast radius of a compromised extension update.
