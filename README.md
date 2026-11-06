<h1 align="center">security-hunt</h1>

<p align="center">
  Find real security bugs with a coding agent, and report only the ones that survive proof.<br />
  Zero findings is an honest result. A wrong finding is worse than none.
</p>

<p align="center">
  <a href="#install"><img alt="Install" src="https://img.shields.io/badge/install-one%20command-111111?style=flat-square&labelColor=000000" /></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-111111?style=flat-square&labelColor=000000" /></a>
  <img alt="Agent skill" src="https://img.shields.io/badge/format-agent%20skill-111111?style=flat-square&labelColor=000000" />
</p>

---

`security-hunt` is a skill for coding agents (Claude Code, Codex, Cursor, OpenCode). It turns
"find security issues in this repo" into a phased workflow where the model is a **candidate
generator, never the authority**. A candidate becomes a finding only after it is reproduced
through the real entry point, checked against a control, confirmed novel upstream, and then
survives an independent agent whose only job is to break it.

It runs the three gates from [kairo](https://github.com/Atharva-Kanherkar/kairo): **correctness**
(does it reproduce, exactly), **usefulness** (is it actually a bug and not a design choice), and
**upstream status** (is it already reported or fixed).

## The workflow

| Phase | What happens | Exit criterion |
| --- | --- | --- |
| 0. Scope | Pin the SHA, write the security model, list the invariants the code itself enforces | Model + invariant list |
| 1. Hunt | Differential reading: sibling routes, identity mismatches, lifecycle gaps, fail-open defaults, trust-boundary crossings | Ranked list, upstream-checked, 1 to 3 picked |
| 2. Trace | Read the real path from router to sink, every authz check and which principal it uses | Precise claim with file:line per hop |
| 3. Prove | Faithful repro, N/N attack runs (N >= 5), a control, canary strings, fixed-build control | Transcript, or `NEEDS EVIDENCE` |
| 4. Matter | Bug-or-not questions, named attacker and victim roles, severity, the fix and its reverse risk | Label is `bug` |
| 5. Upstream | Issues, PRs, PR bodies of the commits that touched the path, infra repos | `novel` / `duplicate-open` / `fixed` / ... |
| 6. Falsify | A fresh agent with no shared context tries to reject the claim | `ACCEPT` from both |
| 7. Report | Only survivors, plus one line per rejected candidate and the gate it failed | |

[`references/gates.md`](references/gates.md) holds the gate checklists, the hard exclusion list
(DoS, missing headers, self-only impact, theoretical input validation, ...), the confidence scale,
and a list of false-positive near misses that only independent review caught.

## Hard rules

- Authorized targets only: your own repos, local emulators, fake upstreams, staging with
  synthetic identities. No prod data, no other tenants, no live destructive actions.
- Never print or persist a credential.
- Work on a pinned commit of the latest default branch.
- Check upstream before hunting a candidate; drop it if it is already filed or fixed.
- Repro tests are scratch and never committed.
- Nothing is filed, commented, or messaged without your explicit ask. You get drafts.

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

Any other agent: copy `SKILL.md` and `references/` into its skills directory.

## Use

Start a new session in the repo you want to audit and ask:

```
/security-hunt
find a real security bug in this repo
triage this suspected vuln: <paste report>
```

To run Phase 1 as parallel hunters (one per subsystem), ask for a workflow explicitly.

## Project notes

Codebases differ in where bugs hide, how to run a faithful repro, and where decisions are
recorded. Copy [`references/project-notes.example.md`](references/project-notes.example.md) to
`references/<project>.md` in your installed skill and fill it in: past real bugs, things already
tracked upstream, repro commands, known flaky tests. The skill reads it when hunting that target.

Those notes usually name unfixed bugs. Keep them in your local install only. This repo's
`.gitignore` blocks any other file under `references/` from being committed.

## License

MIT
