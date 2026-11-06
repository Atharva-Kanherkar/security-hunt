#!/usr/bin/env bash
# Fingerprint a target repository so security-hunt can pick its checklists.
#
#   scripts/fingerprint.sh [--offline] [repo-dir]
#
# Without --offline it makes one network call: `gh api` for the repo's
# published security advisories (only when gh is installed and origin is on
# GitHub).
#
# Prints: the pinned commit, languages, which stack profiles apply (with the
# evidence for each), the checklists to load, hot sink counts, and recent
# security-flavoured commits for variant analysis. Read-only. Signals are
# hints for the agent, not findings.

set -uo pipefail

OFFLINE=0; ROOT="."
for a in "$@"; do
  case "$a" in
    --offline) OFFLINE=1 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ROOT="$a" ;;
  esac
done
cd "$ROOT" 2>/dev/null || { printf 'error: cannot cd to %s\n' "$ROOT" >&2; exit 1; }

USE_GIT=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then USE_GIT=1; fi

EXCL_DIRS="node_modules vendor dist build target .git .worktrees .next out coverage third_party bower_components .venv venv __pycache__ site-packages"

# All tracked (or found) files, one per line, minus excluded directories.
all_files() {
  if [ "$USE_GIT" = 1 ]; then
    git ls-files 2>/dev/null
  else
    find . -type f 2>/dev/null | sed 's#^\./##'
  fi | grep -vE '(^|/)(node_modules|vendor|dist|build|target|\.git|\.worktrees|\.next|out|coverage|third_party|bower_components|\.venv|venv|__pycache__|site-packages)/' \
     | grep -vE '\.(min\.js|map|lock|svg|png|jpg|jpeg|gif|ico|woff2?|ttf|pdf|zip|gz)$' \
     | grep -vE '(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|go\.sum|poetry\.lock)$'
}

FILES="$(all_files)"
NFILES="$(printf '%s\n' "$FILES" | grep -c . || true)"

# Files whose path matches an extended regex.
paths() { printf '%s\n' "$FILES" | grep -E -e "$1" || true; }

# Source files (by extension list, e.g. "js ts py") containing an extended regex.
SRC_EXT_DEFAULT="js jsx ts tsx mjs cjs vue svelte py rb go rs java kt scala cs php ex exs swift c cc cpp h hpp m mm"
grep_src() {
  local re="$1" exts="${2:-$SRC_EXT_DEFAULT}" e list=""
  for e in $exts; do list="${list}|\\.${e}"; done
  list="${list#|}"
  printf '%s\n' "$FILES" | grep -E "(${list})$" | grep -vE '(^|/)(test|tests|__tests__|spec|specs|fixtures|examples?|samples?|docs?|e2e|cypress|benchmarks?|bench|profiling|extras|mocks?|__mocks__|stories|storybook|testdata|testing)/|[._-](test|spec|stories)\.' \
    | tr '\n' '\0' | xargs -0 grep -lIE -e "$re" 2>/dev/null || true
}

MANIFEST_RE='(^|/)(package\.json|Cargo\.toml|go\.mod|requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg|Gemfile|[^/]*\.gemspec|composer\.json|pom\.xml|build\.gradle(\.kts)?|[^/]*\.csproj|mix\.exs)$'
MANIFESTS="$(paths "$MANIFEST_RE")"

# Manifests mentioning a dependency regex. Prints "name (file)" for the first hit.
dep() {
  [ -n "$MANIFESTS" ] || return 0
  local f
  f="$(printf '%s\n' "$MANIFESTS" | tr '\n' '\0' | xargs -0 grep -lE -e "$1" 2>/dev/null | head -1 || true)"
  [ -n "$f" ] && printf '%s' "$f"
}

# Regex for a bare package name as a dependency entry (requirements, pyproject,
# Pipfile), not prose or an email address: "name>=1", name==1, name = "*".
pyd() { printf '%s' "(^|[\"'[:space:]])($1)([[:space:]]*[<>=~!;\\[,\"']|\$)"; }

count() { printf '%s\n' "$1" | grep -c . || true; }
first3() {
  local n; n="$(count "$1")"
  printf '%s' "$(printf '%s\n' "$1" | grep . | head -3 | paste -sd ',' - | sed 's/,/, /g')"
  [ "$n" -gt 3 ] && printf ' (+%s more)' "$((n - 3))"
  return 0
}

EV_web=""; EV_api=""; EV_cli=""; EV_desktop=""; EV_agent=""; EV_library=""; EV_ci=""
ev() { # ev <profile> <evidence>
  local cur
  eval "cur=\${EV_$1}"
  if [ -z "$cur" ]; then eval "EV_$1=\"\$2\""; else eval "EV_$1=\"\$cur; \$2\""; fi
}
check_dep() { # check_dep <profile> <label> <regex>
  local f; f="$(dep "$3")"
  [ -n "$f" ] && ev "$1" "$2 ($f)"
  return 0
}

# --- web: browser-facing UI or server-rendered pages ---
check_dep web "react"        '"react(-dom)?"[[:space:]]*:'
check_dep web "next"         '"next"[[:space:]]*:'
check_dep web "vue/nuxt"     '"(vue|nuxt)"[[:space:]]*:'
check_dep web "svelte/kit"   '"(svelte|@sveltejs/kit)"[[:space:]]*:'
check_dep web "angular"      '"@angular/core"'
check_dep web "remix/astro"  '"(@remix-run/[a-z-]+|astro)"[[:space:]]*:'
check_dep web "django"       "$(pyd '[Dd]jango')"
check_dep web "rails"        "gem ['\"]rails['\"]"
check_dep web "laravel"      'laravel/framework'

# --- api: server-side request handling ---
check_dep api "express"      '"express"[[:space:]]*:'
check_dep api "fastify/koa/hono/nest" '"(fastify|koa|hono|@nestjs/core|@hapi/hapi|elysia)"[[:space:]]*:'
check_dep api "next route handlers/server actions" '"next"[[:space:]]*:'
check_dep api "django/drf"   "$(pyd '[Dd]jango|djangorestframework')"
check_dep api "flask/fastapi/starlette" "$(pyd '[Ff]lask|fastapi|starlette|sanic|aiohttp|tornado|litestar')"
check_dep api "rails/sinatra" "gem ['\"](rails|sinatra|grape)['\"]"
check_dep api "laravel/symfony" '(laravel/framework|symfony/http-kernel|slim/slim)'
check_dep api "spring"       'spring-boot|org\.springframework'
check_dep api "go http"      '(gin-gonic/gin|labstack/echo|go-chi/chi|gofiber/fiber|gorilla/mux|connectrpc|grpc)'
check_dep api "rust http"    '^(axum|actix-web|rocket|warp|poem|tonic|hyper)[[:space:]]*='
check_dep api "aspnet"       'Microsoft\.AspNetCore'
spec="$(paths '(openapi|swagger)[^/]*\.(ya?ml|json)$|\.graphqls?$|\.proto$')"
[ -n "$spec" ] && ev api "api specs: $(count "$spec") (openapi/graphql/proto)"
if [ -n "$EV_web$EV_api" ]; then
  tpl="$(paths '\.(erb|jinja2?|j2|ejs|hbs|handlebars|pug|twig|cshtml|razor)$|(^|/)templates/[^/]+\.html$')"
  [ -n "$tpl" ] && ev web "server templates: $(count "$tpl") files"
fi
gohttp="$(grep_src 'http\.HandleFunc|http\.ListenAndServe' "go")"
[ -n "$gohttp" ] && ev api "net/http handlers: $(count "$gohttp") files"

# --- cli: tools a user runs on inputs that may come from someone else ---
binpkg="$(printf '%s\n' "$MANIFESTS" | grep -E '(^|/)package\.json$' | tr '\n' '\0' | xargs -0 grep -lE '"bin"[[:space:]]*:' 2>/dev/null | head -1 || true)"
[ -n "$binpkg" ] && ev cli "npm bin ($binpkg)"
check_dep cli "commander/yargs/oclif/cac" '"(commander|yargs|@oclif/core|cac|meow|citty|clipanion)"[[:space:]]*:'
check_dep cli "clap/argh"    '^(clap|structopt|argh|pico-args)[[:space:]]*='
check_dep cli "cobra/urfave"  '(spf13/cobra|urfave/cli|alecthomas/kong)'
check_dep cli "click/typer"  "$(pyd 'click|typer|docopt|fire')"
pyscripts="$(printf '%s\n' "$MANIFESTS" | tr '\n' '\0' | xargs -0 grep -lE '^\[project\.scripts\]|console_scripts|^\[tool\.poetry\.scripts\]' 2>/dev/null | head -1 || true)"
[ -n "$pyscripts" ] && ev cli "python entry points ($pyscripts)"
rsbin="$(paths '(^|/)src/(main\.rs|bin/[^/]+\.rs)$')"
[ -n "$rsbin" ] && ev cli "rust binaries: $(count "$rsbin")"
gomain="$(paths '(^|/)cmd/[^/]+/main\.go$')"
[ -n "$gomain" ] && ev cli "go cmd/: $(count "$gomain")"

# --- desktop: native/web-view apps, local daemons, localhost servers ---
check_dep desktop "electron" '"electron"[[:space:]]*:'
check_dep desktop "tauri"    '(^tauri[[:space:]]*=|"@tauri-apps/api")'
check_dep desktop "wails/neutralino" '(wailsapp/wails|"@neutralinojs)'
tconf="$(paths '(^|/)tauri\.conf\.json5?$|(^|/)src-tauri/capabilities/')"
[ -n "$tconf" ] && ev desktop "tauri config/capabilities: $(count "$tconf")"
# A local listener is a desktop/daemon signal only next to a client-side app
# (CLI, desktop shell), not on an ordinary web server.
listen="$(grep_src '\.listen\(|createServer\(|TcpListener|UnixListener|unix_listener|ListenAndServe|HTTPServer\(|socket\.AF_UNIX|uvicorn\.run|serve_forever|axum::serve|HttpServer::new' \
  | tr '\n' '\0' | xargs -0 grep -lE '127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|AF_UNIX|UnixListener|unix_listener|\.sock' 2>/dev/null || true)"
if [ -n "$listen" ] && { [ -n "$EV_desktop$EV_cli" ] || [ -z "$EV_api" ]; }; then
  ev desktop "local listeners/sockets: $(count "$listen") files"
fi
deeplink="$(grep_src 'setAsDefaultProtocolClient|tauri_plugin_deep_link|deep-link|CFBundleURLSchemes|open-url|registerProtocol|protocol\.handle')"
[ -n "$deeplink" ] && ev desktop "deep links/custom schemes: $(count "$deeplink") files"

# --- agent: LLM apps, agents, MCP servers and clients, AI coding tools ---
check_dep agent "anthropic sdk"   "\"@anthropic-ai/(sdk|claude-agent-sdk|claude-code)\"|^anthropic-sdk|$(pyd 'anthropic')"
check_dep agent "openai sdk"      "\"(openai|@openai/[a-z-]+)\"[[:space:]]*:|^async-openai|$(pyd 'openai|openai-agents')"
check_dep agent "vercel ai sdk"   '"(ai|@ai-sdk/[a-z-]+)"[[:space:]]*:'
check_dep agent "langchain/llamaindex" "\"(langchain|@langchain/[a-z-]+|llamaindex)\"[[:space:]]*:|$(pyd 'langchain[a-z_-]*|langgraph|llama[-_]index[a-z_-]*')"
check_dep agent "mcp sdk"         "\"@modelcontextprotocol/sdk\"|^rmcp[[:space:]]*=|$(pyd 'mcp|fastmcp')"
check_dep agent "agent frameworks" "\"(@mastra/core|@openai/agents|autogen)\"|$(pyd 'autogen[a-z_-]*|crewai|pydantic-ai|smolagents|semantic-kernel')"
check_dep agent "model loading"   "$(pyd 'torch|transformers|vllm|llama-cpp-python|onnxruntime|joblib|safetensors')"
# App-level MCP config is evidence; contributor tool folders (.claude/, .cursor/,
# ...) at the repo root usually are not, so they are only reported as a note.
mcpcfg="$(paths '(^|/)\.?mcp\.json$|(^|/)\.mcp/' | grep -vE '^\.(claude|codex|cursor|gemini|vscode)/' || true)"
[ -n "$mcpcfg" ] && ev agent "mcp config files: $(first3 "$mcpcfg")"
devtool="$(paths '^\.(claude|codex|cursor|gemini)/')"
llmcalls="$(grep_src 'messages\.create|chat\.completions|responses\.create|generateText|streamText|tool_use|function_call|ToolCall|CallToolRequest|McpServer|registerTool')"
[ -n "$llmcalls" ] && ev agent "llm/tool-call code: $(count "$llmcalls") files"

# --- ci ---
wf="$(paths '(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.yml$|(^|/)azure-pipelines\.ya?ml$|(^|/)Jenkinsfile$|(^|/)\.circleci/config\.yml$|(^|/)\.buildkite/')"
# Load ci.md only when a pipeline has something an outsider could abuse:
# privileged triggers, event text in expressions, publishing, cloud OIDC, or
# self-hosted runners. Plain PR builds with read-only tokens are not worth it.
if [ -n "$wf" ]; then
  wfx() { printf '%s\n' "$wf" | tr '\n' '\0' | xargs -0 grep -lE "$1" 2>/dev/null || true; }
  prt="$(wfx 'pull_request_target|workflow_run|issue_comment|pull_request_review|issues:|discussion')"
  inj="$(wfx '\$\{\{[[:space:]]*github\.(event\.(issue|pull_request|comment|review|head_commit|commits|discussion)|head_ref)')"
  pub="$(wfx 'npm publish|pnpm publish|yarn npm publish|twine upload|pypa/gh-action-pypi-publish|cargo publish|gem push|docker/build-push-action|goreleaser|semantic-release|changesets/action')"
  # id-token: write alone is common for Pages deploys; cloud role assumption is what matters.
  oidc="$(wfx 'id-token:[[:space:]]*write' | tr '\n' '\0' | xargs -0 grep -lE 'aws-actions/configure-aws-credentials|google-github-actions/auth|azure/login|hashicorp/vault-action|workload_identity_provider|role-to-assume' 2>/dev/null || true)"
  shr="$(wfx 'runs-on:.*self-hosted')"
  [ -n "$prt" ] && ev ci "privileged triggers: $(first3 "$prt")"
  [ -n "$inj" ] && ev ci "event text in expressions: $(first3 "$inj")"
  [ -n "$pub" ] && ev ci "publish/release jobs: $(first3 "$pub")"
  [ -n "$oidc" ] && ev ci "cloud OIDC role assumption: $(first3 "$oidc")"
  [ -n "$shr" ] && ev ci "self-hosted runners: $(first3 "$shr")"
fi

# --- library: packages consumed by other code ---
APP="$EV_web$EV_api$EV_cli$EV_desktop$EV_agent"
npmlib="$(printf '%s\n' "$MANIFESTS" | grep -E '(^|/)package\.json$' | tr '\n' '\0' | xargs -0 grep -LE '"private"[[:space:]]*:[[:space:]]*true|"bin"[[:space:]]*:' 2>/dev/null | tr '\n' '\0' | xargs -0 grep -lE '"(main|exports|module)"[[:space:]]*:' 2>/dev/null | head -3 || true)"
[ -n "$npmlib" ] && ev library "publishable npm packages without bin: $(first3 "$npmlib")"
gem="$(paths '(^|/)[^/]*\.gemspec$')"
[ -n "$gem" ] && ev library "gemspec: $(first3 "$gem")"
if [ -z "$APP" ]; then
  libmark="$(paths '(^|/)src/lib\.rs$|(^|/)setup\.py$|(^|/)pyproject\.toml$|(^|/)go\.mod$')"
  if [ -n "$libmark" ]; then ev library "no app entry point; library markers: $(first3 "$libmark")"
  elif [ -n "$MANIFESTS" ]; then ev library "no app entry point found; treat as a library"; fi
fi
native="$(paths '\.(c|cc|cpp|cxx|h|hpp)$')"
[ -n "$native" ] && ev library "C/C++ sources: $(count "$native") (memory safety in scope)"

# --- output ---
SHA="(not a git repo)"
if [ "$USE_GIT" = 1 ]; then
  SHA="$(git rev-parse HEAD 2>/dev/null) on $(git rev-parse --abbrev-ref HEAD 2>/dev/null), committed $(git log -1 --format=%cs 2>/dev/null)"
fi
printf 'target   %s\n' "$(pwd)"
printf 'commit   %s\n' "$SHA"
printf 'files    %s (excluding deps, builds, lockfiles, binaries)\n' "$NFILES"
printf 'langs    %s\n\n' "$(printf '%s\n' "$FILES" | sed -n 's/.*\.\([A-Za-z0-9]\{1,6\}\)$/\1/p' | sort | uniq -c | sort -rn | head -8 | awk '{printf "%s %s, ", $2, $1}' | sed 's/, $//')"

printf 'profiles (checklists to load; common.md always)\n'
LOAD="common.md"
for p in web api cli desktop agent library ci; do
  eval "e=\${EV_$p}"
  if [ -n "$e" ]; then
    printf '  %-8s yes  %s\n' "$p" "$e"
    LOAD="$LOAD $p.md"
  else
    printf '  %-8s no\n' "$p"
  fi
done
case " $LOAD " in *" web.md "*) case " $LOAD " in *" api.md "*) ;; *) LOAD="$LOAD api.md";; esac;; esac
[ -n "$devtool" ] && printf '  note     %s files in contributor agent folders (.claude/ .codex/ .cursor/ .gemini/): dev tooling, not app evidence; in scope only via CLI-01/AGT-03 if the product reads them\n' "$(count "$devtool")"
printf '\nload     references/checklists/{%s}\n' "$(printf '%s' "$LOAD" | tr ' ' ',')"
[ -n "$EV_web" ] && printf '         (web implies api.md: every web app has a server side)\n'
printf '\n'

printf 'hot sinks (non-test source files containing a match; leads, not findings)\n'
sink() { # sink <label> <regex>
  local h; h="$(grep_src "$2")"
  printf '  %-22s %4s  %s\n' "$1" "$(count "$h")" "$(first3 "$h")"
}
sink "process exec"        'child_process|execSync|execFile|spawn\(|subprocess\.|os\.system|os\.popen|Popen\(|exec\.Command|Command::new|std::process::Command|ProcessBuilder|Runtime\.getRuntime|shell=True'
sink "code eval"           '(^|[^a-zA-Z_.])eval\(|new Function\(|vm\.run|vm\.Script|exec\(compile|__import__\(|ScriptEngine|instance_eval|class_eval|PythonInterpreter'
sink "deserialization"     'pickle\.loads?|cPickle|yaml\.load\(|yaml\.unsafe_load|Marshal\.load|ObjectInputStream|BinaryFormatter|XMLDecoder|node-serialize|unserialize\(|torch\.load|joblib\.load|trust_remote_code|jsonpickle'
sink "raw sql"             '\$queryRaw|\$executeRaw|queryRawUnsafe|\.raw\(|sequelize\.query|knex\.raw|createQuery\(|cursor\.execute\(|\.execute\(f"|db\.(Exec|Query)\(|Sprintf\("(SELECT|INSERT|UPDATE|DELETE)|format!\("(SELECT|INSERT|UPDATE|DELETE)|sql\.raw|text\(f"'
sink "html/template raw"   'dangerouslySetInnerHTML|v-html|innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write|\|\s*safe\b|mark_safe|html_safe|\.raw\(|render_template_string|Markup\(|bypassSecurityTrust|\{\{\{'
sink "file paths"          '(fs|fsp|fsPromises|fsm)\.(open|write|writeFile|mkdir|symlink|link|rename|unlink|chmod|realpath|lstat)(Sync)?\(|path\.(join|resolve)\(|os\.path\.join|filepath\.Join|Path::new|PathBuf::from|sendFile|send_file|res\.download|FileResponse|createReadStream|readFile(Sync)?\(|fs::read|open\(.*["'"'"']w'
sink "archives"            'extractall|tarfile|zipfile|adm-zip|yauzl|unzipper|node-tar|tar\.x|archiver|zip::ZipArchive|tar::Archive|archive/zip|archive/tar|ZipInputStream'
sink "outbound http"       '(^|[^a-zA-Z_])fetch\(|axios|got\(|undici|requests\.(get|post|request)|httpx\.|urllib|aiohttp\.ClientSession|http\.(Get|Post|NewRequest)|reqwest|HttpClient|urlopen|RestTemplate|WebClient'
sink "open url/file"       'shell\.openExternal|openExternal|open::that|opener::|xdg-open|webbrowser\.open|Desktop\.browse|NSWorkspace|"open"\]|exec\(.*open '
sink "authn/tokens"        'jsonwebtoken|jwt\.(decode|verify)|jose|passport|next-auth|@auth/|oauth|openid|saml|devise|omniauth|firebase-admin|clerk|supabase\.auth|bcrypt|argon2|session\['
sink "webhooks"            'webhook|x-hub-signature|stripe-signature|svix|x-slack-signature|hmac'
sink "electron/tauri ipc"  'ipcMain\.|ipcRenderer|contextBridge|nodeIntegration|webPreferences|tauri::command|invoke_handler|dangerousRemoteDomainIpcAccess|webviewTag'
sink "llm output to sink"  'tool_use|tool_calls|function_call|toolCall|CallToolRequest|execute_command|run_shell|bash_tool|code_interpreter'

tenant="$(grep_src '(org|organization|tenant|workspace|team|account|project)_?[Ii]d\b|(org|organization|tenant|workspace|team|account)Id\b')"
nt="$(count "$tenant")"
if [ "$nt" -ge 3 ]; then tnote=" (tenant isolation items likely apply; confirm in the data model)"
elif [ "$nt" -gt 0 ]; then tnote=" (1-2 files is likely incidental; confirm before scoring API-04)"
else tnote=""; fi
printf '\nmulti-tenant signals  %s files mention org/tenant/workspace/team/account ids%s\n' "$nt" "$tnote"

if [ -n "$wf" ]; then
  unpinned="$(printf '%s\n' "$wf" | tr '\n' '\0' | xargs -0 grep -hE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^./][^@]+@' 2>/dev/null | grep -vE '@[0-9a-f]{40}' | grep -vE 'uses:[[:space:]]*(actions|github)/' | wc -l | tr -d ' ' || true)"
  printf 'ci signals            %s pipeline files; privileged triggers in %s, event expressions in %s, publish jobs in %s, OIDC in %s; %s unpinned third-party uses\n' \
    "$(count "$wf")" "$(count "$prt")" "$(count "$inj")" "$(count "$pub")" "$(count "$oidc")" "${unpinned:-0}"
  [ -z "$EV_ci" ] && printf '                      (read-only PR builds only: ci.md not loaded)\n'
fi

if [ "$USE_GIT" = 1 ]; then
  SEC_RE='secur|cve-|ghsa|cwe-|vuln|bypass|travers|inject|sanitiz|escap|xss|ssrf|csrf|idor|unauthori|authz|permission|privilege|leak|exploit|harden|tenant|access control|symlink|hardlink|toctou|(^|[^a-z])race|overflow|underflow|out.of.bounds|use.after.free|zip.?slip|prototype|pollut|redos|denial|decompression|recursion|negative|nul byte|null byte|fuzz|(^|[^a-z])rce([^a-z]|$)'
  scanned="$(git rev-list --count --no-merges HEAD 2>/dev/null || echo 0)"
  [ "$scanned" -gt 1500 ] && scanned=1500
  sec="$(git log -n 1500 --no-merges --format='%h %cs %s' 2>/dev/null | grep -iE "$SEC_RE" || true)"
  printf '\nsecurity-flavoured commits in last %s: %s  (seed CMN-01 variant analysis)\n' "$scanned" "$(count "$sec")"
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
    printf '  shallow clone: history is truncated; run `git fetch --unshallow` before CMN-01 if allowed\n'
  fi
  printf '%s\n' "$sec" | grep . | head -12 | sed 's/^/  /'
  if [ "$OFFLINE" = 0 ] && command -v gh >/dev/null 2>&1; then
    origin="$(git remote get-url origin 2>/dev/null | sed -E 's#(git@github\.com:|https://github\.com/)##; s#\.git$##')"
    case "$origin" in
      */*) adv="$(gh api "repos/$origin/security-advisories" --jq 'length' 2>/dev/null || true)"
           [ -n "$adv" ] && printf 'published advisories   %s (gh api repos/%s/security-advisories)\n' "$adv" "$origin" ;;
    esac
  fi
fi
