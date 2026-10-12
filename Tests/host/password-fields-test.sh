#!/bin/bash
# F-23: a password shown in clear text is a plain TextField. Each one must turn
# autocorrection off, or the system may rewrite the password while it is typed.
# (Tests/host/textfield-substitution.swift shows what the modifier changes.)
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail=0; seen=0
while IFS=: read -r file line _; do
  seen=$((seen + 1))
  if ! sed -n "$((line + 1))p" "$file" | grep -q '\.autocorrectionDisabled()'; then
    echo "  FAIL $file:$line password TextField without .autocorrectionDisabled()"
    fail=$((fail + 1))
  fi
done < <(grep -n 'TextField(loc("[^"]*password[^"]*")' "$REPO"/App/*.swift)
echo "password fields: $seen checked, $fail failed"
[ "$seen" -ge 3 ] && [ "$fail" -eq 0 ]
