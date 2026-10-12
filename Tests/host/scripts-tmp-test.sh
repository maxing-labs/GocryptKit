#!/bin/bash
# F-22: build and release scripts must not use fixed paths under /tmp. Anyone on
# the Mac can create them first (as a symlink, or with files that then end up in
# a signed bundle); scratch space comes from mktemp.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
hits="$(grep -n '/tmp' "$REPO"/Scripts/*.sh "$REPO"/Engine/*.sh | grep -v ':[[:space:]]*#')"
if [ -n "$hits" ]; then
  echo "$hits" | sed "s|$REPO/||; s|^|  FAIL |"
  exit 1
fi
echo "  ok   no fixed /tmp paths in Scripts/ and Engine/"
