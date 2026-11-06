# Sources

Checked November 2026. Standards change; re-check versions before citing them
in a report.

## Standards the checklists map to

- OWASP Top 10:2025. A01 Broken Access Control (SSRF merged in), A02 Security
  Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic
  Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures,
  A08 Software or Data Integrity Failures, A09 Security Logging and Alerting
  Failures, A10 Mishandling of Exceptional Conditions. https://top10.owasp.org/2025
- OWASP API Security Top 10 2023 (API1 BOLA to API10 Unsafe Consumption of APIs).
  https://owasp.org/API-Security/
- OWASP ASVS 5.0.0 (May 2025), chapters V1 Encoding and Sanitization through
  V17 WebRTC. https://github.com/OWASP/ASVS/tree/master/5.0/en
- OWASP Web Security Testing Guide (test procedures). https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 for LLM Applications 2025 (LLM01 Prompt Injection to LLM10
  Unbounded Consumption). https://genai.owasp.org/
- OWASP Top 10 for Agentic Applications 2026 (ASI01 Agent Goal Hijack to ASI10
  Rogue Agents), December 2025. https://genai.owasp.org/
- OWASP Top 10 CI/CD Security Risks (CICD-SEC-1 to 10).
  https://owasp.org/www-project-top-10-ci-cd-security-risks/
- 2025 CWE Top 25 Most Dangerous Software Weaknesses, with KEV counts.
  https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- CISA Known Exploited Vulnerabilities catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Research on hunting and false positives

- Refute-or-Promote: adversarial stage-gated multi-agent review (2026).
  https://arxiv.org/abs/2604.19049
- Sifting the Noise: LLM agents in vulnerability false-positive filtering (2026).
  https://arxiv.org/abs/2601.22952
- OpenAnt: decomposition, adversarial verification and dynamic testing (2026).
  https://arxiv.org/abs/2606.19149
- VulAgent: hypothesis-validation multi-agent detection (2025).
  https://arxiv.org/abs/2509.11523
- Reducing False Positives in Static Bug Detection with LLMs, ICSE 2026.
  https://arxiv.org/abs/2601.18844
- GitHub Security Lab, "How to scan for vulnerabilities with GitHub Security
  Lab's open source AI-powered framework" and "AI-supported vulnerability triage
  with the GitHub Security Lab Taskflow Agent". https://github.blog/security/
- Anthropic Frontier Red Team, "Evaluating and mitigating the growing risk of
  LLM-discovered 0-days" (Feb 2026). https://www.anthropic.com/research/zero-days
- Google Project Zero, "From Naptime to Big Sleep" (2024).
  https://projectzero.google/2024/10/from-naptime-to-big-sleep.html
- OpenAI, "Introducing Aardvark" (threat model, commit scanning, sandbox
  validation; renamed Codex Security in 2026). https://openai.com/index/introducing-aardvark/
- XBOW validators and canary-based confirmation (Black Hat USA 2025, "AI Agents
  for Offsec with Zero False Positives"). https://xbow.com/platform
- Anthropic claude-code-security-review (exclusion list, confidence threshold).
  https://github.com/anthropics/claude-code-security-review
- Trail of Bits skills (audit-context-building, variant-analysis,
  differential-review). https://github.com/trailofbits/skills
- Simon Willison, "The lethal trifecta for AI agents" (June 2025).
  https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- Daniel Stenberg on AI-generated security reports to curl (2025 to 2026).
  https://daniel.haxx.se/blog/
- HackerOne Hacker-Powered Security Report 2025 (access control and IDOR payouts rising).
- PortSwigger, Top 10 web hacking techniques of 2025.
  https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

## Case write-ups

Listed in `cases.md` next to each case: Next.js (CVE-2025-29927,
CVE-2024-34351), React2Shell (CVE-2025-55182), ruby-saml (CVE-2025-25291/25292,
GitHub Security Lab), nOAuth (Descope, Semperis), git (CVE-2025-48384,
CVE-2024-32002), Codex CLI (CVE-2025-61260, Check Point), Claude Code
(CVE-2025-59536, Check Point), Cursor (CVE-2025-54135 Aim Labs, CVE-2025-54136
Check Point), mcp-remote (CVE-2025-6514), MCP Inspector (CVE-2025-49596,
Oligo), Ollama (CVE-2024-37032, Wiz), Langflow (CVE-2025-3248, Horizon3.ai),
PyTorch (CVE-2025-32434), CPython tarfile (CVE-2025-4517), Invariant Labs
GitHub MCP, tj-actions (CVE-2025-30066, CISA), Nx s1ngularity, Shai-Hulud,
Electron (CVE-2025-55305, Trail of Bits), BatBadBut (CVE-2024-24576, RyotaK),
PortSwigger research (single-packet attack 2023; 2025 top 10 entries).
