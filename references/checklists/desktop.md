# Desktop, local daemon and localhost-service checklist

For Electron, Tauri, Wails and native apps with web views; local daemons; any
process that listens on a loopback port or a Unix socket; custom URL schemes.
Standards: CWE-1385, CWE-346, CWE-306, CWE-749, Electron and Tauri security
guides, OWASP A01/A05/A08:2025.

**Threat model, written first.** Attackers here are: any web page the user
visits (it can send requests to `127.0.0.1` and, via DNS rebinding, read
responses), content the app renders (chats, documents, LLM output, repo files),
links the user clicks (deep links), and other local users on shared machines
(lower priority). Malware already running as the user is out of scope: it can
do everything anyway.

---

## DSK-01 Localhost services reachable from a web page
Tier S · Yield high · Maps: CWE-306, CWE-346, CWE-350, CWE-1385

**Hunt**
- Every HTTP, WebSocket, SSE or gRPC listener on `127.0.0.1`, `localhost`,
  `0.0.0.0` or `::`. For each: is there an auth token the browser cannot know?
  Is the `Host` header checked (DNS rebinding)? Is `Origin` checked
  (cross-site requests, WebSocket hijacking)? Are CORS headers permissive?
- `0.0.0.0` binds also expose the service to the LAN.
- "Simple" requests: browsers send cross-site `POST` with `text/plain` or form
  bodies without preflight, so a JSON API that does not check `Content-Type`
  is reachable.
- Tokens: where do clients get them? A token readable via an unauthenticated
  endpoint, a predictable value, or a token in a URL the page can guess is no
  token.

**Prove:** O-LOCALHOST: a page served from a different local origin (and a
`Host: attacker.test` request for rebinding) performs a state change or reads a
canary. Control: with the right token or origin, works; with the guard on a
sibling route, blocked.
**Kill if:** a secret token the web page cannot obtain is required and checked;
`Host` and `Origin` are both validated.
**Cases:** C12.

---

## DSK-02 Renderer-to-privileged bridge is too wide
Tier S · Yield high · Maps: CWE-749, CWE-284, CWE-829

**Hunt**
- Electron: `nodeIntegration: true`, `contextIsolation: false`,
  `sandbox: false`, `webviewTag: true`, `allowRunningInsecureContent`; preload
  scripts exposing `ipcRenderer` itself or generic `invoke(channel, ...)`;
  `ipcMain.handle` handlers that run commands, read/write arbitrary paths, or
  open URLs without validating `event.senderFrame` origin.
- Tauri: commands registered in `invoke_handler` that take paths, commands or
  URLs; capabilities granting `shell:allow-execute`, `fs` scopes like `**` or
  `$HOME/**`, `http` scopes to any URL; `dangerousRemoteDomainIpcAccess` or
  remote URLs allowed to call IPC; windows loading remote content with IPC.
- Any IPC that is a generic proxy (`run(command)`, `fetch(url)`, `readFile(path)`).

**Prove:** from script running in the renderer (the state an XSS would give),
call the bridge and create a marker file or read a canary outside the app's
data dir. Report the XSS-to-bridge chain only with a real XSS (DSK-03); a wide
bridge alone is a hardening note unless remote content can reach it.
**Kill if:** remote and untrusted content can never execute in a window that
has the bridge.

---

## DSK-03 Untrusted content executing in the renderer
Tier S (when DSK-02 is wide) · Yield medium-high · Maps: CWE-79, CWE-1021

**Hunt**
- Rendering paths for content the user did not write: chat messages, LLM
  output, markdown, notifications, file previews, repo READMEs, issue bodies,
  HTML emails, link unfurls. Same sinks as WEB-03.
- Navigation: does `will-navigate`/`setWindowOpenHandler` (Electron) or the
  Tauri navigation policy stop a link from loading a remote page in a
  privileged window? Iframes of remote content with IPC access?
- CSP present and actually enforced on the app's pages.

**Prove:** O-XSS inside the app's renderer (devtools-free: use the app's own
rendering path with a fixture), then one bridge call as in DSK-02.
**Kill if:** the content is escaped; the window has no bridge and no secrets.

---

## DSK-04 Deep links, custom schemes and file associations
Tier A-S · Yield medium · Maps: CWE-88, CWE-22, CWE-939

**Hunt**
- Handlers for `myapp://` URLs, `open-url` events, protocol handlers, and
  opened files: which parameters reach paths, commands, IPC, settings, or
  "connect to server X" flows? Does any sensitive action run without a
  confirmation showing what will happen?
- On Windows, scheme handlers registered with `"%1"` can receive extra
  arguments (argument injection into the app's own CLI parser).

**Prove:** clicking (or `open`-ing) a crafted link from a web page performs the
action or writes outside the app data dir (marker). Control: a well-formed link
does only the intended thing.
**Kill if:** the handler only navigates within the app and requires confirmation
for anything with side effects.

---

## DSK-05 Opening external URLs and files
Tier A-S · Yield medium · Maps: CWE-78, CWE-601

Same as CLI-03, applied to `shell.openExternal`, Tauri `shell.open`/opener,
and native open calls fed by rendered content or IPC from the renderer.
Allow-list `https:` (and maybe `mailto:`) on the parsed URL.

**Cases:** C11.

---

## DSK-06 Local privilege boundaries
Tier B-A · Yield low · Maps: CWE-276, CWE-732, CWE-269

Unix socket and named-pipe permissions, token and database files readable by
other local users, daemons running with more privilege than the UI, helper
tools with setuid or elevated launchd/systemd services that accept commands
from any local user. Only material on multi-user machines or when an elevated
helper exists; say which.

---

## DSK-07 Update and integrity chain
Tier S · Yield low · Maps: A08:2025, CWE-494, CWE-347

Updater feeds over HTTP, signature verification disabled or keyed to a
replaceable file, downgrade attacks, unsigned plugins. Code-integrity bypasses
that need local write access as the same user (C21) are usually outside the
threat model; report as hardening unless the product promises tamper resistance.

**Cases:** C21.
