#!/bin/bash
# I-7: after unmounting, the empty "_READ_ONLY" mount point is removed with
# rmdir(2), which only removes an empty directory. "Check it is empty, then
# removeItem" deletes recursively whatever appeared in between. The race
# cannot be staged from outside, so this checks the code.
set -uo pipefail
FILE="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/App/MountManager.swift}"
body="$(awk '/func unmountVault\(/,/^    }$/' "$FILE" | grep -v '^[[:space:]]*//')"
fail=0
if ! grep -q 'rmdir(mountPoint.path)' <<<"$body"; then
  echo "  FAIL unmountVault does not remove the read-only mount point with rmdir(2)"; fail=1
fi
if grep -q 'removeItem' <<<"$body"; then
  echo "  FAIL unmountVault removes something recursively"; fail=1
fi
[ $fail -eq 0 ] && echo "  ok   read-only mount point removed with rmdir(2)"
exit $fail
