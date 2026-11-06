<h1 align="center">security-hunt</h1>

<p align="center">
  Find real security bugs with a coding agent, and report only the ones that survive proof.<br />
  Zero findings is an honest result. A wrong finding is worse than none.
</p>

<p align="center">
  <a href="#install"><img alt="Install" src="https://img.shields.io/badge/install-one%20command-111111?style=flat-square&labelColor=000000" /></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-111111?style=flat-square&labelColor=000000" /></a>
  <img alt="Agent skill" src="https://img.shields.io/badge/format-agent%20skill-111111?style=flat-square&labelColor=000000" />
  <img alt="Checklist items" src="https://img.shields.io/badge/checklist%20items-72-111111?style=flat-square&labelColor=000000" />
  <img alt="Real cases" src="https://img.shields.io/badge/real%20cases-28-111111?style=flat-square&labelColor=000000" />
</p>

---

`security-hunt` is a skill for coding agents (Claude Code, Codex, Cursor, OpenCode). It turns
"find security issues in this repo" into a workflow where the model is a **candidate generator,
never the authority**:

1. **Fingerprint** the target's stack with a script: web, API, CLI, desktop and localhost
   services, LLM agents and MCP, library, CI.
2. **Load only the checklists that apply**, built from OWASP Top 10 2025, the OWASP API, LLM
   and Agentic Top 10s, ASVS 5.0, CWE Top 25 2025, and 28 real CVE write-ups.
3. **Rank the items by likely impact** (impact + exposure + how often the class turns into real
   findings + signals in this repo) and hunt them in that order.
4. **Prove** each candidate with a deterministic oracle (a canary, a marker file, a headless
   browser run) and a control, N/N times.
5. **Try to kill it**: a cold, independent agent with a kill mandate reruns the proof and
   looks for the auth layer, config, or maintainer ruling you missed.
6. **Report the top survivors**, plus a coverage table, the leads that need more evidence,
   and every rejected candidate with the gate it failed.

It runs the three gates from [kairo](https://github.com/Atharva-Kanherkar/kairo):
**correctness** (does it reproduce, exactly), **usefulness** (is it actually a bug and not a
design choice), and **upstream status** (is it already reported or fixed).

## What it checks, per stack

| Checklist | Items | Built from |
| --- | --- | --- |
| [`common`](references/checklists/common.md) | Variants of past fixes, skipped invariants, fail-open errors, parser differentials, trusted internal headers, secret exposure, reachable vulnerable deps, sink sweep, identity on mutable claims | OWASP A01/A03/A05/A10:2025, CWE Top 25 |
| [`api`](references/checklists/api.md) | BOLA, function-level authz, mass assignment and ORM leaks, tenant isolation, revocation gaps, missing auth, tokens and sessions, SSRF, injection, uploads, races and business logic, GraphQL, webhooks, upstream trust | OWASP API Top 10 2023, ASVS V4/V6-V10 |
| [`web`](references/checklists/web.md) | Edge-only auth (middleware, Server Actions), login/reset/OAuth, XSS with real victims, CSRF, CORS, cache poisoning and deception, postMessage, XS-leaks | ASVS V3, WSTG |
| [`cli`](references/checklists/cli.md) | Repo-controlled config that executes, argument injection, OS URL openers, archive extraction, server-supplied paths, credentials to the wrong host, terminal escapes, update integrity | CWE-78/88/22/94 |
| [`desktop`](references/checklists/desktop.md) | Localhost services reachable from web pages (DNS rebinding, CSRF), wide Electron/Tauri bridges, untrusted content in the renderer, deep links, update chain | Electron and Tauri guidance, CWE-1385 |
| [`agent`](references/checklists/agent.md) | Lethal trifecta, tool authority vs approval, repo-controlled agent config, model output as code, confused deputy and RAG ACLs, memory poisoning, MCP server bugs, sandboxes, model loading, approval UI | OWASP LLM Top 10 2025, Agentic Top 10 2026 |
| [`library`](references/checklists/library.md) | Memory safety with sanitizers, deserialization and prototype pollution, archive and path helpers, security controls that do not hold, unsafe defaults, FFI | CWE Top 25 memory entries |
| [`ci`](references/checklists/ci.md) | Pwn requests, expression injection, mutable refs, over-broad tokens and OIDC trust, cache poisoning, self-hosted runners, publish path | OWASP CI/CD Top 10 |

Every item says how to hunt it, which oracle proves it, when to kill it, and which real case it
comes from. The [casebook](references/cases.md) covers bugs like the Next.js middleware bypass,
React2Shell, ruby-saml's parser differential, the git CR bug, the Codex CLI, Claude Code and
Cursor config-execution CVEs, MCP Inspector, mcp-remote, Ollama, Langflow, the GitHub MCP toxic
flow, tj-actions, Nx and Shai-Hulud.

## Why it is strict about false positives

AI-written security reports have a bad name for a reason: curl ended its bug bounty after a
flood of confident reports about functions that did not exist. The rules here come from the
research on what actually removes noise without killing real bugs:

- **Oracles, not arguments.** In one study ten agents unanimously confirmed a padding oracle
  that did not exist; one test killed it. Proof is a canary the target produced, not text
  the model wrote.
- **Cold reviewers with a kill mandate, no debate.** Fresh-context review beats same-session
  review, and persuasion rounds make it worse (Refute-or-Promote).
- **Agreement is weak evidence.** Same-family models make the same mistakes together; use a
  second model family for high-severity findings when you can.
- **Deterministic checks go to tools.** Versions from lockfiles, routes from the router,
  citations from [`check-citations.sh`](scripts/check-citations.sh).
- **Do not over-filter.** Even the best filtering setup discarded about a fifth of real bugs,
  and more than half in crypto and trust-boundary classes. Unproven candidates are listed as
  `NEEDS EVIDENCE`, not deleted.

[`references/gates.md`](references/gates.md) has the gates, the exclusion list, the review rules,
and the near misses that only independent review caught. [`references/sources.md`](references/sources.md)
lists the standards and papers.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Atharva-Kanherkar/security-hunt/main/install.sh | bash
```

That installs into every agent it finds. To pick:

```bash
git clone https://github.com/Atharva-Kanherkar/security-hunt.git
cd security-hunt
./install.sh --agent claude          # or codex, cursor, opencode, all
./install.sh --dir ~/somewhere       # any other agent's skills directory
./install.sh --project               # ./.claude/skills in the current project
```

| Agent | Skills directory |
| --- | --- |
| Claude Code | `~/.claude/skills/security-hunt` |
| Codex CLI | `~/.codex/skills/security-hunt` |
| Cursor | `~/.cursor/skills/security-hunt` |
| OpenCode | `~/.config/opencode/skills/security-hunt` |

Any other agent: copy `SKILL.md`, `references/` and `scripts/` into its skills directory.

## Use

Start a new session in the repo you want to audit and ask:

```
/security-hunt
find a real security bug in this repo
triage this suspected vuln: <paste report>
```

You can run the fingerprint on its own to see what the skill will look at:

```bash
~/.claude/skills/security-hunt/scripts/fingerprint.sh path/to/repo
```

To run the hunters in parallel (one per profile), ask for a workflow explicitly.

## Hard rules

- Authorized targets only: your own repos, local emulators, fake upstreams, scratch repos and
  accounts, staging with synthetic identities. No prod data, no other tenants, no live
  destructive actions, never the real upstream's CI.
- Never print or persist a credential.
- Work on a pinned commit of the latest default branch.
- Check upstream before hunting a candidate; drop it if it is already filed or fixed.
- Repro tests are scratch and never committed.
- Nothing is filed, commented, or messaged without your explicit ask. You get drafts.

## Project notes

Codebases differ in where bugs hide, how to run a faithful repro, and where decisions are
recorded. Copy [`references/projects/example.md`](references/projects/example.md) to
`references/projects/<project>.md` in your installed skill and fill it in: past real bugs,
things already tracked upstream, repro commands, known flaky tests. The skill reads it when
hunting that target, and the installer never overwrites it.

Those notes usually name unfixed bugs. Keep them local. This repo's `.gitignore` blocks
everything in `references/projects/` except the template.

## License

MIT
