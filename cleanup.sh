#!/usr/bin/env bash
# Removes everything a run of this artifact created, inside the clone and outside it.
# It never touches anything tracked by git, and never removes the clone itself.
#
#   ./cleanup.sh --dry-run   list what would be removed, delete nothing
#   ./cleanup.sh             remove it
set -euo pipefail
cd "$(dirname "$0")"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

total=0
gone() {   # gone <path> <what it is>
  local p="$1" what="$2" sz
  [ -e "$p" ] || return 0
  sz=$(du -sm "$p" 2>/dev/null | cut -f1); sz=${sz:-0}
  total=$((total + sz))
  printf '  %-42s %5s MB  %s\n' "$p" "$sz" "$what"
  [ "$DRY" = "1" ] || rm -rf "$p"
}

echo "Removing what a run of this artifact leaves behind:"
gone .venv                     "the Python environment"
gone .uv                       "the uv binary fetched by bootstrap.sh"
gone data                      "the 10.3 GB database and its download"
gone .pytest_cache             "test cache"
for f in figures/*.pdf; do gone "$f" "regenerated figure"; done

echo
if [ "$DRY" = "1" ]; then
  echo "Dry run: nothing was removed. ${total} MB would be freed."
else
  echo "Done. ${total} MB freed. Nothing tracked by git was touched."
fi
