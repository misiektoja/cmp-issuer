#!/usr/bin/env bash
#
# Checks that every non-merge commit in a range carries a Developer Certificate of Origin sign-off.
#
# A commit passes when one of its Signed-off-by trailers names the commit author's email address,
# compared without regard to case. Dependabot authors commits with its GitHub noreply address but signs
# them off with a different one, so its commits only need a Signed-off-by trailer.
#
#   check-dco.sh <base> [head]   checks the commits reachable from head, default HEAD, but not from base

set -euo pipefail

dependabot_author="49699333+dependabot[bot]@users.noreply.github.com"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <base> [head]" >&2
  exit 2
fi
base="$1"
head="${2:-HEAD}"

for ref in "$base" "$head"; do
  if ! git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
    echo "error: $ref does not name a commit in this repository" >&2
    exit 2
  fi
done

# Prints a string in lower case
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Succeeds when one of the sign-off lines certifies a commit by the given lower-case author email
signed_off() {
  local author="$1" signoffs="$2" line email
  [ -n "$signoffs" ] || return 1
  [ "$author" != "$dependabot_author" ] || return 0
  while IFS= read -r line; do
    email="$(printf '%s\n' "$line" | sed -n 's/.*<\([^>]*\)>.*/\1/p')"
    if [ -n "$email" ] && [ "$(lower "$email")" = "$author" ]; then
      return 0
    fi
  done <<<"$signoffs"
  return 1
}

commits="$(git rev-list --no-merges --reverse "$base..$head")"
checked=0
failed=0
for commit in $commits; do
  checked=$((checked + 1))
  author="$(lower "$(git log -1 --format='%ae' "$commit")")"
  signoffs="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly,unfold)' "$commit")"
  if ! signed_off "$author" "$signoffs"; then
    failed=$((failed + 1))
    echo "$(git log -1 --format='%h %s' "$commit"): no Signed-off-by trailer for $author" >&2
  fi
done

if [ "$failed" -gt 0 ]; then
  echo "error: $failed of $checked commits lack a DCO sign-off. Sign off with 'git commit -s', or add it to every commit since $base with 'git rebase --signoff $base'." >&2
  exit 1
fi
echo "Every commit since $base carries a DCO sign-off ($checked checked)."
