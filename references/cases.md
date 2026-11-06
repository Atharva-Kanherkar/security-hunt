# Casebook: real bugs behind the checklist items

Each case is distilled to the pattern a code reader can spot, so the checklist
items are grounded in things that actually shipped and were exploited or
fixed. Details were checked against public advisories and write-ups in
November 2026; re-check an advisory before quoting it in a report.

Use them two ways: as hunting patterns (does this codebase have the same
shape?) and as variant-analysis seeds (CMN-01: if the target depends on or
resembles the affected code, look for the sibling).

---

### C01 Next.js middleware skipped by a client header (CVE-2025-29927, 2025)
Next.js marked internal sub-requests with `x-middleware-subrequest` to avoid
loops, and trusted that header on *incoming* requests too. Sending it skipped
middleware entirely, including auth. Versions 11.1.4 to 15.2.2.
**Pattern:** an internal-only signal accepted from outside, plus authorization
that lives only in an edge layer. **Spot it:** headers the framework or your
proxy sets internally; handlers that never re-check auth.
**Items:** CMN-02, CMN-05, WEB-01.

### C02 React Server Components deserialization RCE, "React2Shell" (CVE-2025-55182, 2025)
CVSS 10. The React Flight payload decoder in `react-server-dom-*` 19.0 to 19.2.0
did not validate structure; one crafted request gave server code execution,
reachable by default without any user-defined Server Action.
**Pattern:** a framework-level deserializer on every request. **Spot it:**
lockfile versions of framework protocol packages; do not assume "we don't use
that feature" means the decoder is unreachable.
**Items:** CMN-07, WEB-01, LIB-02.

### C03 Next.js Server Actions SSRF via the Host header (CVE-2024-34351, 2024)
Self-hosted Next.js 13.4 to 14.1.0: when a Server Action redirected to a
relative path, the server built an absolute URL from the `Host` header and
fetched it, returning the full response. Not exploitable where the platform
routes by Host (Vercel).
**Pattern:** absolute URLs built from request headers, then fetched.
**Lesson:** deployment config decides exploitability; say which you checked.
**Items:** CMN-05, API-08.

### C04 ruby-saml signature wrapping via parser differential (CVE-2025-25291/25292, 2025)
ruby-saml verified the signature with one XML parser (REXML) and read the
assertion with another (Nokogiri). Crafted XML made them see different
documents, so one valid signature from the IdP let an attacker log in as any
user. Fixed in 1.12.4 and 1.18.0; GitLab shipped patches.
**Pattern:** verify with parser A, use with parser B. **Spot it:** two parsing
libraries, or parse-verify-reparse, on the same security-relevant input.
**Items:** CMN-04, API-07, LIB-04.

### C05 nOAuth: accounts keyed on a mutable email claim (2023, re-reported 2025)
Apps using "Log in with Microsoft" matched users by the `email` claim, which a
multi-tenant Entra ID let any tenant admin set to an unverified address. An
attacker set their email to the victim's and logged in as them. Descope found
it; later testing still found about 9% of a sample of gallery apps vulnerable.
**Pattern:** identity from a mutable, unverified, or attacker-tenant attribute.
**Fix shape:** key on `sub` + issuer (+ tenant id).
**Items:** CMN-09, WEB-02, API-13.

### C06 git: carriage return stripped on read, kept on write (CVE-2025-48384, 2025, CISA KEV)
git stripped a trailing CR from config values when reading but did not quote
it when writing. A malicious `.gitmodules` path ending in CR made the
submodule check out into a different path; with a symlink into `.git/hooks`,
a recursive clone ran attacker code. Exploited in the wild.
**Pattern:** read/write asymmetry in one program's serializer. **Spot it:**
values that round-trip through config or manifest files; trailing whitespace
and control characters.
**Items:** CMN-01, CMN-04, CLI-01.

### C07 git: submodule symlink on case-insensitive filesystems (CVE-2024-32002, 2024)
A repository with submodules and a symlink could, on case-insensitive
filesystems (macOS, Windows defaults), write files into `.git/` and run a hook
during `git clone --recursive`.
**Pattern:** path checks that ignore filesystem case folding and symlinks.
**Items:** CMN-01, CLI-01, CLI-04, LIB-03.

### C08 Codex CLI: project `.env` redirected its config home (CVE-2025-61260, 2025)
A project-local `.env` could set `CODEX_HOME=./.codex`; Codex CLI then loaded
the repo's `config.toml` and started the MCP servers it declared, running
their commands at startup with no prompt. Fixed in 0.23.0. (Check Point)
**Pattern:** repo-controlled config that executes, reached through an
environment redirection. **Spot it:** any `*_HOME`/config-dir variable that a
project file can set.
**Items:** CLI-01, AGT-03.

### C09 Claude Code: project config executed before the trust dialog (CVE-2025-59536, 2025)
Repository settings could define MCP servers and hooks that ran when Claude
Code started in the project, before the user saw the trust prompt. Fixed in
1.0.111. Check Point reported a set of related config issues.
**Pattern:** execution ordered before consent. **Spot it:** what the tool does
between process start and the first prompt.
**Items:** CLI-01, AGT-02, AGT-03.

### C10 Cursor: CurXecute and MCPoison (CVE-2025-54135, CVE-2025-54136, 2025)
CurXecute (Aim Labs): prompt injection made the agent write a new MCP entry
into the project config, which then ran. MCPoison (Check Point): approval was
bound to the MCP server's name, so a later change to an approved entry's
command ran without re-approval. Fixed in Cursor 1.3.
**Pattern:** the agent can edit its own execution config; approval bound to an
identifier instead of the content.
**Items:** CLI-01, AGT-02, AGT-03, AGT-07.

### C11 mcp-remote: OAuth endpoint URL to OS command (CVE-2025-6514, 2025)
mcp-remote opened the `authorization_endpoint` URL that an MCP server returned
during OAuth discovery; a malicious server supplied a URL that became an OS
command. CVSS 9.6. Fixed in 0.1.16.
**Pattern:** server-supplied URL handed to the OS opener. **Spot it:** any
`open(url)` whose URL came from a network response; check for a scheme allow-list.
**Items:** CLI-03, CLI-05, DSK-05, AGT-07.

### C12 MCP Inspector: local proxy reachable from any web page (CVE-2025-49596, 2025)
The Inspector's local proxy had no authentication and no Host/Origin checks.
A malicious website could drive it through CSRF, the "0.0.0.0 day" browser
behavior, or DNS rebinding, and get code execution on the developer's machine.
CVSS 9.4. Fixed in 0.14.1 with a session token and Host/Origin validation.
**Pattern:** loopback is not a trust boundary for browsers.
**Items:** DSK-01, AGT-07.

### C13 Ollama "Probllama": digest used as a path (CVE-2024-37032, 2024)
`/api/pull` accepted a model manifest from a remote registry and used its
`digest` field in a file path without validating the format, giving path
traversal, arbitrary file write and then code execution. Fixed in 0.1.34. (Wiz)
**Pattern:** content-addressed ids from a remote server trusted as safe path parts.
**Items:** API-10, CLI-04, CLI-05.

### C14 Langflow unauthenticated code validation endpoint (CVE-2025-3248, 2025, CISA KEV)
`/api/v1/validate/code` was reachable without authentication and executed the
submitted Python while "validating" it. Exploited in the wild; fixed in 1.3.0.
(Horizon3.ai)
**Pattern:** a dangerous helper endpoint outside the auth middleware.
**Items:** API-06, AGT-04, AGT-08.

### C15 PyTorch `torch.load(weights_only=True)` still executed code (CVE-2025-32434, 2025)
The "safe" loading mode could be bypassed by a crafted model file, giving code
execution in 2.5.1 and earlier. Fixed in 2.6.0.
**Pattern:** a library's safe mode treated as proof of safety. **Lesson:** a
safety flag is a version-specific claim; check the version.
**Items:** CMN-07, LIB-02, AGT-09.

### C16 Python `tarfile` extraction filters bypassed (CVE-2025-4517 and siblings, 2025)
`filter="data"` and `filter="tar"`, added to make extraction safe, could be
bypassed with crafted symlinks and hard links to write outside the target
directory (CVSS 9.4). Python 3.14 made `data` the default, so code relying on
the default is affected too.
**Pattern:** a fix that became the thing people relied on, then got bypassed.
**Items:** CMN-01, API-10, CLI-04, LIB-03.

### C17 GitHub MCP "toxic agent flow" (Invariant Labs, May 2025)
A user asked an agent with the GitHub MCP server to look at a public repo's
issues. A malicious issue told the agent to read the user's private repos and
open a PR in the public repo containing that data. No tool was buggy; the flow
was: private data + untrusted content + a public write channel.
**Pattern:** the lethal trifecta (Simon Willison). **Spot it:** one session
with all three and no gate.
**Items:** AGT-01.

### C18 tj-actions/changed-files tag hijack (CVE-2025-30066, March 2025)
Attackers repointed the action's version tags to a malicious commit that dumped
runner memory, printing secrets into build logs of over 23,000 repositories.
**Pattern:** mutable references in CI. **Lesson:** pinning is hardening until a
compromise happens; classify accordingly.
**Items:** CI-03.

### C19 Nx "s1ngularity" (August 2025)
Per Nx's postmortem, a workflow interpolated a pull request title into a shell
step; the injected command stole the npm publish token, and malicious Nx
versions were published. The payload then used AI coding CLIs installed on
victims' machines to search for secrets.
**Pattern:** CI expression injection on a privileged trigger.
**Items:** CI-01, CI-02.

### C20 Shai-Hulud npm worm (September 2025)
A `postinstall` payload stole npm and GitHub tokens, published infected
versions of every package the victim maintained, and pushed a workflow that
exfiltrated repository secrets.
**Pattern:** install-time code execution with publish credentials present.
**Items:** CI-07.

### C21 Electron integrity checks skipped heap snapshots (CVE-2025-55305, 2025)
Electron's ASAR integrity fuses did not cover V8 heap snapshot files, so anyone
with write access to the app's directory could backdoor signed apps (Slack,
1Password, Signal were demonstrated). (Trail of Bits)
**Pattern:** an integrity guarantee with a gap. **Lesson:** needs local write as
the user; outside most threat models, so usually hardening.
**Items:** DSK-07.

### C22 "BatBadBut": argument escaping for batch files on Windows (CVE-2024-24576, 2024)
Rust's `Command` (and other languages' equivalents) did not escape arguments
correctly when running `.bat`/`.cmd` files, because `cmd.exe` re-parses them.
Untrusted arguments led to command execution. CVSS 10; fixed in Rust 1.77.2,
with fixes in Node.js, PHP, Haskell and yt-dlp. (RyotaK)
**Pattern:** a "safe" argv API that is not safe on one platform.
**Items:** CLI-02.

### C23 ORM leaks through filter parameters (PortSwigger top 10 of 2025, #2)
Search and filter APIs that pass user-chosen field names and operators to the
ORM let attackers filter on fields they cannot read (password hashes, reset
tokens, other tenants' relations) and recover them one character at a time.
Alex Brown (elttam) generalized this from framework-specific bugs.
**Items:** API-03.

### C24 Error-based blind SSTI (PortSwigger top 10 of 2025, #1)
Vladislav Korchagin showed error-based techniques and polyglots that detect and
exploit blind server-side template injection across engines.
**Items:** API-09.

### C25 Unicode normalization bypasses (PortSwigger top 10 of 2025, #4)
Ryan and Isabella Barnett showed checks performed before normalization being
bypassed by characters that normalize into the forbidden ones afterwards.
**Items:** CMN-04, LIB-04.

### C26 Next.js internal cache poisoning (PortSwigger top 10 of 2025, #7)
Rachid Allam chained Next.js internal caching behavior so that other users
were served attacker-shaped responses.
**Items:** WEB-06.

### C27 Blind SSRF made visible with redirect loops (PortSwigger top 10 of 2025, #3)
Shubham Shah showed redirect loops that make HTTP clients reveal information
about blind SSRF responses.
**Lesson:** "blind" is not the same as "no impact"; still prove impact with O-SSRF.
**Items:** API-08.

### C28 Single-packet attack for race conditions (James Kettle, 2023)
Sending many HTTP/2 requests so they complete in one packet removes network
jitter and makes limit-overrun races practical (one coupon redeemed many
times, 2FA bypasses).
**Items:** API-11.

---

## Methodology cases (how real hunts found or wrongly found bugs)

- **Big Sleep (Google, 2024):** variant analysis from a previous SQLite bug and
  recent diffs found an exploitable stack underflow that fuzzing had missed.
- **Claude Opus 4.6 (Anthropic, Feb 2026):** after fuzzing and manual review
  failed on GhostScript, reading the git history found a bounds-check fix and
  an unpatched sibling. Over 500 high-severity bugs, each validated by a human
  before reporting, because hallucinated reports burden maintainers.
- **curl (2025 to 2026):** a flood of confident AI-written reports citing
  functions that did not exist led curl to end its bug bounty. A citation check
  (`scripts/check-citations.sh`) is the cheapest defense.
- **Refute-or-Promote (2026):** adversarial kill-mandate reviewers removed
  about 79% of candidates; 80+ agents once endorsed a false bug; cross-model
  critics caught correlated errors; adversarial agents lowered CVSS in 8 of 9 cases.
