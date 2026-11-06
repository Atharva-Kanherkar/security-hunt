# LLM app, agent and MCP checklist

For apps that call LLMs with tools, coding agents, chat products with
retrieval, MCP servers and clients, agent frameworks, model-serving code.
Standards: OWASP Top 10 for LLM Applications 2025 (LLM01 to LLM10), OWASP Top
10 for Agentic Applications 2026 (ASI01 to ASI10), CWE-1427 (prompt injection),
OWASP A01/A05:2025.

**Threat model, written first.** Prompt injection is assumed to always work
sometimes: any text an attacker can get into the context (web pages, issues,
PR comments, emails, documents, file contents, tool results, MCP server
responses, other users' messages, memory) can steer the model. So
"the model can be talked into X" is not the finding. **The finding is what the
steered model can do without a human gate, with whose authority, and where
the result can go.** Also write down whose credentials each tool uses.

Not findings on their own (gates.md): jailbreaks, offensive output, system
prompt disclosure without secrets in it, hallucinated facts, token-cost abuse.

---

## AGT-01 Lethal trifecta: private data + untrusted content + an exit
Tier S · Yield high · Maps: LLM01/LLM02:2025, ASI01/ASI02, CWE-1427, CWE-200

**Hunt**
1. For each agent or chat surface, list in one session: (a) tools or context
   that read private data (repos, mail, files, DBs, memory, other tenants'
   documents), (b) every source of untrusted text, (c) every exit channel.
2. Exit channels people miss: markdown images and links auto-rendered by the
   UI (the URL carries the data; read the client-side renderer for the chat
   surface, since this is usually decided in the frontend, not the agent code), link unfurling, web fetch/search tools,
   creating issues/PRs/comments/gists, sending mail or chat, writing files that
   sync, DNS lookups, `git push`, MCP tools on other servers.
3. Is there a gate between (b) entering and (c) firing: human approval showing
   the full payload, an egress allow-list, taint tracking that disables exits
   after untrusted content is read?

**Prove:** O-AGENT: a fixture document or issue with an instruction to send a
private canary to a local listener; the listener receives it with no approval.
Show the gate is absent deterministically (the tool call executes without a
prompt), then report the model compliance rate (k of N).
**Kill if:** every exit requires approval that shows the destination and
content; the private data reachable is the attacker's own.
**Cases:** C17.

---

## AGT-02 Tool authority exceeds what the user approved
Tier S · Yield high · Maps: LLM06:2025 Excessive Agency, ASI02, ASI03, CWE-863, CWE-284

**Hunt**
- Shell and file tools: what runs without approval? Allow-lists of commands
  checked by prefix or first word (`git status && curl ...`, `$(...)`,
  backticks, `;`, newlines, `find -exec`, `git -c core.pager=...`,
  `npm test` running repo scripts, env assignments `FOO=1 cmd`).
- Path restrictions checked with `startsWith(root)` (sibling `root-evil`),
  before symlink resolution, or only on the first argument.
- Approval bound to a name, not the content (an approved MCP server or command
  whose definition later changes runs without re-approval).
- The agent can write its own config, allow-list, hooks or MCP definitions,
  then use them (approval laundering).
- Read-only modes that still allow writes through a side door (a "read" tool
  that runs git hooks, a formatter with plugins, a language server).

**Prove:** O-AGENT or O-CMDI: an action outside the approved scope executes
(marker file, write outside root) through the same tool path, N/N for the
deterministic part. Control: the plainly forbidden action is blocked.
**Kill if:** the user explicitly chose a full-access mode that documents this.
**Cases:** C09, C10.

---

## AGT-03 Repository-controlled agent configuration
Tier S · Yield high · Maps: ASI04, ASI05, CWE-94, CWE-829

Same as CLI-01, for agent tooling: `.mcp.json`, `.claude/settings*.json`,
`.codex/`, `.cursor/`, `.vscode/` tasks and settings, hook definitions, rule
files that reference executables, `.env` that redirects config homes. Opening
or running the agent in a cloned repo must not execute anything before an
informed trust decision. Instruction files (`AGENTS.md`, `CLAUDE.md`) are
untrusted *text*, covered by AGT-01/02, not code execution by themselves.

**Prove:** O-CONFIG-EXEC.
**Cases:** C08, C09, C10.

---

## AGT-04 Model output used as code, markup, paths or queries
Tier S-A · Yield medium-high · Maps: LLM05:2025 Improper Output Handling, CWE-79, CWE-78, CWE-89, CWE-22, CWE-94

**Hunt**
- LLM output rendered as HTML/markdown without sanitizing (chat UI XSS, image
  exfiltration; read the frontend component that renders model messages); passed to `eval`, `exec`, SQL, shell, file paths, URLs to fetch
  or open, YAML/pickle loaders, or template engines.
- "Code interpreter" features that run model output outside a real sandbox.
- Structured output trusted for authorization (`{"approved": true}` from the
  model gates an action).

**Prove:** the oracle for the sink class, with the payload arriving through
injected content rather than the user's own prompt.
**Kill if:** the output only reaches the user who wrote the prompt and harms
only them (self-only).
**Cases:** C14.

---

## AGT-05 Confused deputy: agent credentials broader than the requester
Tier S · Yield high · Maps: ASI03 Identity and Privilege Abuse, LLM06/LLM08:2025, CWE-441, CWE-639

**Hunt**
- Tools that run with a service account, an org-wide token, or the bot's
  installation token on behalf of any user: can user A ask the agent for
  user B's or tenant B's data?
- Retrieval (RAG, vector search, full-text) not filtered by the caller's ACL at
  query time; embeddings stored in a shared index with tenant filters applied
  after ranking or only in the UI.
- Agent memory, conversation history or shared caches keyed without tenant/user.
- Delegated workers or subagents receiving the parent's full token.

**Prove:** O-AUTHZ through the agent: user A's prompt returns user B's canary
document, N/N for retrieval (deterministic part) and k/N for the model path.
**Kill if:** every tool call is authorized as the requesting user at the
data layer.

---

## AGT-06 Memory and context poisoning across users or sessions
Tier A · Yield medium · Maps: ASI06, LLM04/LLM08:2025, CWE-1427

**Hunt:** shared memory, knowledge bases, cached tool results or skills that
one user can write and another user's agent reads as trusted context;
persistence of injected instructions across sessions.

**Prove:** user A writes a poisoned entry; user B's session acts on it (canary
request), with B never seeing A's content directly.
**Kill if:** stores are per-user, or content is marked untrusted and gated by AGT-01 controls.

---

## AGT-07 MCP server implementation bugs
Tier S · Yield high · Maps: ASI02/ASI04, CWE-306, CWE-918, CWE-22, CWE-78, CWE-346

**Hunt**
- HTTP/SSE MCP servers: authentication present? Token passthrough (forwarding
  the client's token to upstream APIs without audience checks)? Session ids
  usable as auth? DNS rebinding and `Origin` checks on local servers (DSK-01).
- Tool implementations: SSRF in fetch tools (API-08), path traversal in file
  tools (allowed-directory checks with `startsWith`, symlinks), command or
  argument injection in tools that wrap CLIs (CLI-02), SQL tools with
  "read-only" enforced by prefix matching.
- MCP clients: server-provided metadata (OAuth endpoints, URLs, tool
  descriptions) used to open URLs or run commands (C11); tool descriptions that
  change after approval (C10).

**Prove:** call the tool directly over the protocol (no model needed) with the
malicious argument; the oracle for the class. Model-free proof is stronger.
**Kill if:** the tool's documented purpose is the behavior (a shell MCP server
runs commands; the bug must be crossing *its* stated boundary).
**Cases:** C10, C11, C12.

---

## AGT-08 Code execution features and sandboxes
Tier S · Yield medium · Maps: ASI05 Unexpected Code Execution, LLM05:2025, CWE-94, CWE-306

**Hunt:** endpoints that validate, run, or "test" code (flows, custom
components, notebook cells); sandbox boundaries (network egress, mounted
secrets, env vars, host filesystem, Docker socket, cloud metadata); whether
the endpoint requires auth.

**Prove:** marker or canary read from outside the sandbox, as the lowest role
that can reach the feature.
**Kill if:** the role reaching it is meant to have full execution (an admin
console on their own instance).
**Cases:** C14.

---

## AGT-09 Unsafe model and artifact loading
Tier S · Yield medium · Maps: LLM03:2025, ASI04, CWE-502, CWE-494

**Hunt:** `torch.load`, `pickle`, `joblib`, `numpy.load(allow_pickle=True)`,
`trust_remote_code=True`, Keras Lambda layers, GGUF/ONNX parsers, model ids or
URLs chosen by users, model hub downloads without pinning. Check library
versions: "safe" flags have been bypassed.

**Prove:** O-DESER with a crafted artifact loaded through the app's own path.
**Kill if:** only operator-chosen, pinned artifacts are loaded.
**Cases:** C15.

---

## AGT-10 Secrets placed in model context or logs
Tier A · Yield medium · Maps: LLM02/LLM07:2025, CWE-200, CWE-532

API keys, tokens or other tenants' data put in system prompts, tool results,
traces or logs that the user (or other users, or a third-party model
provider the product does not disclose) can read back. A system prompt is not
a secret store.

**Prove:** a normal user extracts the canary secret via the product's own UI or API.
**Kill if:** the only "secret" is the prompt text itself.

---

## AGT-11 Approval UI that does not show what will run
Tier A · Yield medium · Maps: ASI09 Human-Agent Trust Exploitation, CWE-451, CWE-1021

**Hunt:** approval prompts that truncate commands, hide arguments, render
Unicode lookalikes or bidi controls, show a summary written by the model
instead of the literal action, or approve a batch where later items differ.

**Prove:** a captured approval prompt next to the action that executed, showing
the mismatch.
**Kill if:** the full literal action is shown and executed byte for byte.

---

## AGT-12 Inter-agent trust
Tier A · Yield low-medium · Maps: ASI07, ASI08, ASI10

Workers' outputs treated as instructions by an orchestrator; unauthenticated
agent-to-agent channels; a low-trust agent able to message a high-trust one;
retry or fan-out loops that amplify one injected step. Prove as AGT-01/02 with
the injection entering through the lower-trust agent.
