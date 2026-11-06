#!/usr/bin/env bash
# Install the security-hunt skill for one or more coding agents.
#
#   ./install.sh                      # every agent found on this machine
#   ./install.sh --agent claude       # one agent
#   ./install.sh --agent claude,codex # several
#   ./install.sh --dir ~/somewhere    # any other agent's skills directory
#   ./install.sh --project           # this repo's ./.claude/skills, for one project
#
# Or without cloning:
#   curl -fsSL https://raw.githubusercontent.com/Atharva-Kanherkar/security-hunt/main/install.sh | bash

set -euo pipefail

REPO_URL="https://github.com/Atharva-Kanherkar/security-hunt.git"
SKILL="security-hunt"
REF="main"
AGENTS=""
EXTRA_DIRS=()
PROJECT=0

say()  { printf '%s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  say ""
  say "agents: claude, codex, cursor, opencode, all"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --agent|-a) AGENTS="${AGENTS}${AGENTS:+,}${2:?--agent needs a value}"; shift 2 ;;
    --dir|-d)   EXTRA_DIRS+=("${2:?--dir needs a path}"); shift 2 ;;
    --ref)      REF="${2:?--ref needs a value}"; shift 2 ;;
    --project)  PROJECT=1; shift ;;
    --help|-h)  usage ;;
    *)          die "unknown option: $1 (try --help)" ;;
  esac
done

# --- find the source tree: this checkout, or a shallow clone ---
SRC=""
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$here" ] && [ -f "$here/SKILL.md" ] && [ -d "$here/references" ]; then
  SRC="$here"
else
  command -v git >/dev/null 2>&1 || die "git is required when running from a pipe"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  say "  cloning $REPO_URL ($REF)"
  git clone --depth 1 --branch "$REF" "$REPO_URL" "$TMP/src" >/dev/null 2>&1 \
    || die "clone failed"
  SRC="$TMP/src"
fi

# --- work out the targets ---
declare -a TARGETS=()

add_target() { TARGETS+=("$1"); }

agent_dir() {
  case "$1" in
    claude)   printf '%s\n' "$HOME/.claude/skills" ;;
    codex)    printf '%s\n' "$HOME/.codex/skills" ;;
    cursor)   printf '%s\n' "$HOME/.cursor/skills" ;;
    opencode) printf '%s\n' "$HOME/.config/opencode/skills" ;;
    *)        return 1 ;;
  esac
}

agent_base() {
  case "$1" in
    claude)   printf '%s\n' "$HOME/.claude" ;;
    codex)    printf '%s\n' "$HOME/.codex" ;;
    cursor)   printf '%s\n' "$HOME/.cursor" ;;
    opencode) printf '%s\n' "$HOME/.config/opencode" ;;
    *)        return 1 ;;
  esac
}

if [ "$PROJECT" = "1" ]; then
  add_target "$PWD/.claude/skills"
fi

for d in "${EXTRA_DIRS[@]+"${EXTRA_DIRS[@]}"}"; do
  add_target "${d/#\~/$HOME}"
done

if [ -z "$AGENTS" ] && [ "$PROJECT" = "0" ] && [ ${#TARGETS[@]} -eq 0 ]; then
  AGENTS="all"
fi

if [ -n "$AGENTS" ]; then
  IFS=',' read -r -a wanted <<< "$AGENTS"
  for a in "${wanted[@]}"; do
    a="$(printf '%s' "$a" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    [ -z "$a" ] && continue
    if [ "$a" = "all" ]; then
      for known in claude codex cursor opencode; do
        base="$(agent_base "$known")"
        if [ -d "$base" ]; then add_target "$(agent_dir "$known")"; fi
      done
      continue
    fi
    dir="$(agent_dir "$a")" || die "unknown agent: $a (claude, codex, cursor, opencode)"
    add_target "$dir"
  done
fi

[ ${#TARGETS[@]} -gt 0 ] || die "no install targets found. Pass --agent or --dir."

# --- copy ---
installed=0
for dir in "${TARGETS[@]}"; do
  dest="$dir/$SKILL"
  mkdir -p "$dest"
  # Replace what this repo ships; leave private notes in references/projects/ alone.
  rm -rf "$dest/references/checklists" "$dest/scripts"
  rm -f "$dest/SKILL.md" "$dest/references/project-notes.example.md"
  mkdir -p "$dest/references/projects"
  cp "$SRC/SKILL.md" "$dest/SKILL.md"
  cp "$SRC"/references/*.md "$dest/references/"
  cp -R "$SRC/references/checklists" "$dest/references/"
  cp "$SRC/references/projects/example.md" "$dest/references/projects/example.md"
  cp -R "$SRC/scripts" "$dest/"
  chmod +x "$dest/scripts"/*.sh
  say "  installed  $dest"
  for f in "$dest"/references/*.md; do
    case "$(basename "$f")" in
      gates.md|ranking.md|oracles.md|cases.md|sources.md) ;;
      *) warn "$(basename "$f") looks like project notes; move it to references/projects/ so the skill finds it" ;;
    esac
  done
  installed=$((installed + 1))
done

say ""
say "  $installed target(s). Start a new agent session, then ask for a hunt:"
say "  \"/security-hunt this repo\""
