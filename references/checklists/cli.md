# CLI and developer-tool checklist

For tools a user runs on their own machine: CLIs, build tools, package
managers, git helpers, AI coding CLIs, language servers. Standards: CWE Top 25
2025 (CWE-78, CWE-77, CWE-88, CWE-22, CWE-94), OWASP A05/A08:2025, CERT
argument-injection guidance.

**Threat model, written first.** The user is trusted. The attacker controls an
*input* the user hands to the tool without reading it closely: a repository
they clone or open, a file or archive, a URL, a package, a server the tool
talks to (registry, update server, MCP or OAuth server), a pasted string.
Executing what the **user** asks is the tool's job and never a finding.
Executing, writing, or leaking what the **input's author** asks is.

---

## CLI-01 Repository- or project-controlled config that executes
Tier S · Yield high · Maps: CWE-94, CWE-829, CWE-426, A08:2025

**Hunt**
- Every config file the tool reads from the working directory or repo:
  `.toolrc`, `./.tool/config.*`, `package.json` fields, `.env`, editor and
  agent settings (`.vscode/`, `.claude/`, `.codex/`, `.cursor/`, `.mcp.json`),
  git config included from the repo, hook definitions, plugin lists, aliases,
  pager/editor/diff-tool/credential-helper settings.
- For each: can it name a command, a binary path, an interpreter, a plugin to
  load, an env var like `*_HOME`/`PATH`/`NODE_OPTIONS`/`LD_PRELOAD`, or a
  redirect to another config dir?
- When does it run: at startup before any trust prompt, after a one-time
  approval that is keyed on the name rather than the content, or only after
  explicit consent? Does a later change to an approved entry re-prompt?
- `.env` files loaded from the project that can redirect the tool's home or
  config directory.

**Prove:** O-CONFIG-EXEC: a scratch repo with the malicious config, a fresh
clone, the tool run with default flags; a marker file is created before or
without any approval. Control: the same command from a global config the
user wrote works as designed; with the trust prompt declined, no marker.
**Kill if:** the tool asks for informed approval showing the exact command, and
any change re-prompts; the config only affects the tool's own output.
**Cases:** C06, C07, C08, C09, C10.

---

## CLI-02 Argument injection into subprocesses
Tier S · Yield medium-high · Maps: CWE-88, CWE-78, A05:2025

**Hunt**
- Values from inputs (branch names, refs, remote URLs, file names, package
  names, hostnames) passed as arguments to `git`, `ssh`, `scp`, `rsync`, `curl`,
  `wget`, `tar`, `zip`, `find`, `ffmpeg`, `psql`, `docker`, `kubectl`, `npm`.
  A value starting with `-` becomes an option: `--upload-pack=`, `-oProxyCommand=`,
  `--output=`, `-exec`, `--config`, `-c core.sshCommand=`.
- Missing `--` before positional arguments; URL schemes like `ext::` for git.
- Shell construction: `exec(\`git ${x}\`)`, `shell=True`, `sh -c "$x"`,
  `os.system`. Windows: arguments to `.bat`/`.cmd` files go through `cmd.exe`
  parsing even via safe-looking APIs.

**Prove:** O-CMDI: an input value from the attacker-controlled source makes the
subprocess create the marker file. Control: a benign value with the same shape.
**Kill if:** the value cannot begin with `-` (validated after normalization) or
the tool inserts `--`; the value comes only from the user's own typed flags.
**Cases:** C22.

---

## CLI-03 Opening URLs and files with the OS handler
Tier S-A · Yield medium · Maps: CWE-78, CWE-88, CWE-601

**Hunt**
- `open`, `xdg-open`, `start`, `cmd /c start`, `ShellExecute`,
  `shell.openExternal`, `open::that`, `webbrowser.open`, `NSWorkspace.open`
  called with a URL from a server response, a repo file, or an LLM.
- Is the scheme allow-listed to `https:` (and maybe `http:`)? `file:`, `smb:`,
  `ms-*`, custom app schemes, and strings starting with `-` are the risk.
- Strings passed through a shell to reach `open` (command injection via the URL).

**Prove:** O-CMDI or O-OPEN: a malicious URL from the attacker's server makes
the handler run a local command (marker file) or open a local executable.
**Kill if:** a scheme allow-list on the parsed URL; only user-typed URLs reach it.
**Cases:** C11.

---

## CLI-04 Archive extraction and writes outside the target
Tier S-A · Yield medium · Maps: CWE-22, CWE-59, CWE-61, CWE-29, ASVS V5

**Hunt**
- Extracting tar/zip/7z/npm/wheel/gem/VSIX/model archives: entries with `..`,
  absolute paths, drive letters, symlinks or hardlinks pointing outside, a
  symlink entry followed by a file entry through it, case-insensitive name
  collisions on macOS/Windows, Unicode normalization collisions.
- Library "safe" filters you rely on: check the exact version (tarfile filters
  were bypassed).
- Writes to paths derived from input (cache keys, download names, `--output`
  defaults from server headers like `Content-Disposition`).

**Prove:** O-PATH write: extraction places a canary file outside the target
directory (in a scratch dir), N/N. Control: a benign archive stays inside.
**Kill if:** the tool rejects links and resolves real paths after creating each
directory; extraction runs in an isolated temp root that is discarded.
**Cases:** C07, C13, C16.

---

## CLI-05 Server-supplied values used as paths, commands or code
Tier S · Yield medium · Maps: CWE-20, CWE-22, CWE-78, CWE-494

**Hunt**
- Responses from registries, update servers, OAuth/OIDC discovery, MCP servers,
  plugin indexes, telemetry or license servers: fields that become file paths
  (`digest`, `name`, `path`), commands, URLs to open, or code to load.
- Content-addressed ids (`sha256:...`) that are not validated as hex before use
  in a path.

**Prove:** a local fake server returns the malicious field; marker file or a
canary written outside the cache directory.
**Kill if:** the server is first-party and pinned with signature verification
the attacker cannot bypass.
**Cases:** C11, C13.

---

## CLI-06 Credentials sent to the wrong place
Tier A · Yield medium · Maps: CWE-522, CWE-200, CWE-201, A07:2025

**Hunt**
- HTTP clients that keep `Authorization` or cookies across redirects to a
  different host; credential helpers that answer for any host a repo config
  names; tokens chosen by a host string the input controls.
- Tokens placed in URLs, process arguments (visible in `ps`), or logs and error
  output that other users or CI viewers can read.

**Prove:** a local fake server redirects; the second host receives the canary
token. Control: same-host redirect keeps it, which is fine.
**Kill if:** the token goes only to the host the user configured. Tokens on the
user's own disk are excluded (gates.md).

---

## CLI-07 Terminal escape injection
Tier B · Yield low · Maps: CWE-150

Untrusted text (server messages, file names, commit messages, LLM output)
printed raw with ANSI/OSC sequences: spoofed prompts or output, OSC 52 clipboard
writes, hyperlink spoofing. Report only when it hides or forges a security
decision (an approval prompt, a diff the user signs off on).

**Prove:** captured terminal output shows the forged prompt or the clipboard write.

---

## CLI-08 Integrity of updates and installs
Tier S · Yield low-medium · Maps: A08:2025, CWE-494, CWE-345

**Hunt:** self-update or plugin install over plain HTTP, without signature or
checksum verification, from a mutable ref; checksum fetched from the same
place as the binary; `curl | sh` installers pinned to a branch.

**Prove:** a local fake update server serves a modified binary that the tool
installs and runs (marker).
**Kill if:** signatures are verified against a pinned key.

---

## CLI-09 Shared temp files and local races
Tier B · Yield low · Maps: CWE-377, CWE-367, CWE-59

Predictable names in `/tmp`, files created then chmod-ed, symlink following
in shared directories. Only matters on multi-user machines or CI runners that
mix trust levels; say which.
