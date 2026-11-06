#!/usr/bin/env bash
# Verify every file:line a report cites exists at the pinned commit, and print
# the cited line so it can be compared with what the report claims it says.
#
#   scripts/check-citations.sh <report.md> [sha] [repo-dir]
#
# Exit 1 when any cited file is missing or a line is past the end of the file.
# A citation that resolves is not proof the claim is right; read the printed
# lines. This catches the cheapest hallucination: a function, file, or line
# that does not exist.

set -uo pipefail

REPORT="${1:?usage: check-citations.sh <report.md> [sha] [repo-dir]}"
SHA="${2:-}"
REPO="${3:-.}"
[ -f "$REPORT" ] || { printf 'error: no such report: %s\n' "$REPORT" >&2; exit 2; }

show() { # show <path>  -> file contents at SHA or in the working tree
  if [ -n "$SHA" ]; then git -C "$REPO" show "$SHA:$1" 2>/dev/null
  else cat "$REPO/$1" 2>/dev/null; fi
}
exists() {
  if [ -n "$SHA" ]; then git -C "$REPO" cat-file -e "$SHA:$1" 2>/dev/null
  else [ -f "$REPO/$1" ]; fi
}

bad=0; ok=0; skipped=0
# path.ext:LINE or path.ext:LINE-LINE, extension must start with a letter
# (so 127.0.0.1:8080 is not a citation).
cites="$(grep -oE '[A-Za-z0-9_@./+-]*[A-Za-z0-9_-]\.[A-Za-z][A-Za-z0-9]*:[0-9]+(-[0-9]+)?' "$REPORT" | sed 's#^\./##' | sort -u)"

while IFS= read -r c; do
  [ -n "$c" ] || continue
  path="${c%%:*}"; range="${c#*:}"
  start="${range%%-*}"; end="${range#*-}"; [ "$end" = "$range" ] && end="$start"
  if ! exists "$path"; then
    case "$path" in
      */*) printf 'MISSING   %s\n' "$c"; bad=$((bad + 1)) ;;
      *)   printf 'skip      %s (not a repo path)\n' "$c"; skipped=$((skipped + 1)) ;;
    esac
    continue
  fi
  total="$(show "$path" | wc -l | tr -d ' ')"
  if [ "$end" -gt "$total" ] || [ "$start" -lt 1 ]; then
    printf 'RANGE     %s (file has %s lines)\n' "$c" "$total"; bad=$((bad + 1)); continue
  fi
  printf 'ok        %s\n' "$c"; ok=$((ok + 1))
  show "$path" | sed -n "${start},$(( end < start + 4 ? end : start + 4 ))p" | cut -c1-160 | sed 's/^/            | /'
done <<EOF
$cites
EOF

printf '\n%s ok, %s bad, %s skipped%s\n' "$ok" "$bad" "$skipped" "${SHA:+ at $SHA}"
[ "$bad" -eq 0 ]
