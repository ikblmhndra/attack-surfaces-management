#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# changelog.sh — Append entries to CHANGELOG.md
# Usage:
#   ./scripts/changelog.sh add "2026-05-18" "Bug Fixes" \
#     "Fixed: trailing slash mismatch on GET /organizations" \
#     "organizations.py" \
#     "Frontend called GET /organizations (no slash) but backend registered @router.get(\"/\")" \
#     "Changed @router.get(\"/\") to @router.get(\"\")"
#
#   ./scripts/changelog.sh add "$(date +%F)" "Features" \
#     "Added: PUT /workspaces endpoint" \
#     "workspaces.py" \
#     "Settings page got 405 when saving workspace name" \
#     "Added update_workspace handler with settings JSONB merge"
#
#   ./scripts/changelog.sh entry           # interactive prompt
# ──────────────────────────────────────────────────────────────
set -euo pipefail

CHANGELOG="CHANGELOG.md"
SELF="$0"

usage() {
  sed -n '3,18p' "$SELF" | sed 's/^# \?//'
  exit 0
}

# ── Interactively build an entry ──────────────────────────────
interactive() {
  echo "=== Changelog Entry Builder ==="
  printf "Date (default: $(date +%F)): "; read -r date; date="${date:-$(date +%F)}"
  printf "Section title: "; read -r title
  printf "Category (e.g. Fixed, Added, Changed, Removed): "; read -r category
  printf "Short description: "; read -r desc
  printf "File path: "; read -r file
  printf "Issue/context: "; read -r issue
  printf "Fix description: "; read -r fix
  echo ""
  echo "--- Preview ---"
  echo "## $date — $title"
  echo ""
  echo "### $category: $desc"
  echo "- **File**: $file"
  echo "- **Issue**: $issue"
  echo "- **Fix**: $fix"
  echo "---------------"
  printf "Append this entry? [Y/n]: "; read -r confirm
  case "$confirm" in
    n|N|no|NO) echo "Cancelled."; exit 0 ;;
    *) append_entry "$date" "$title" "$category" "$desc" "$file" "$issue" "$fix" ;;
  esac
}

# ── Append a single entry ─────────────────────────────────────
append_entry() {
  local date="$1" title="$2" category="$3" desc="$4" file="$5" issue="$6" fix="$7"

  # Ensure file ends with newline
  if [ -s "$CHANGELOG" ] && [ "$(tail -c1 "$CHANGELOG" | wc -l)" -eq 0 ]; then
    echo "" >> "$CHANGELOG"
  fi

  {
    echo ""
    echo "## $date — $title"
    echo ""
    echo "### $category: $desc"
    echo "- **File**: $file"
    echo "- **Issue**: $issue"
    echo "- **Fix**: $fix"
  } >> "$CHANGELOG"

  echo "✓ Appended to $CHANGELOG"
}

# ── CLI dispatch ──────────────────────────────────────────────
case "${1:-}" in
  add)
    [ $# -lt 6 ] && { echo "Usage: $0 add <date> <title> <category> <desc> <file> <issue> <fix>"; exit 1; }
    shift
    append_entry "$1" "$2" "$3" "$4" "$5" "$6" "$7"
    ;;
  entry|interactive|--interactive)
    interactive
    ;;
  *)
    usage
    ;;
esac
