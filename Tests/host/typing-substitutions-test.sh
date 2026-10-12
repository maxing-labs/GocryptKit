#!/bin/bash
# F-23: the system's typing substitutions (text replacement, smart quotes and
# dashes, spelling correction) must not rewrite what is typed into the app's
# text fields, the shown-password field above all.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

if grep -q 'TypingSubstitutions.disableInTextFields()' "$REPO/App/GocryptKitApp.swift"; then
  echo "  ok   the app turns substitutions off at launch"
else
  echo "  FAIL App/GocryptKitApp.swift does not call TypingSubstitutions.disableInTextFields()"
  fail=1
fi

# Top-level code is only allowed in main.swift when compiling several files.
cp "$REPO/Tests/host/typing-substitutions-probe.swift" "$WORK/main.swift"
if swiftc -swift-version 6 -o "$WORK/probe" "$REPO/App/TypingSubstitutions.swift" "$WORK/main.swift" 2>"$WORK/build.log"; then
  "$WORK/probe"
  status=$?
  case $status in
    0) echo "  ok   typed text arrives unchanged" ;;
    2) echo "  SKIP the probe could not observe a substitution" ;;
    *) echo "  FAIL a typing substitution is still on"; fail=1 ;;
  esac
else
  cat "$WORK/build.log"
  echo "  FAIL probe did not build"
  fail=1
fi
exit $fail
