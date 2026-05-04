#!/usr/bin/env bash
set -euo pipefail

required_docs=(
  docs/platform/ios.md
  src/platform/ios/ios_adapter.c
)

for path in "${required_docs[@]}"; do
  if [[ ! -s "$path" ]]; then
    echo "missing iOS logical acceptance input: $path" >&2
    exit 50
  fi
done

if grep -R --line-number -E 'mmap\(.*PROT_EXEC|mprotect\(.*PROT_EXEC' src/platform/ios; then
  echo "iOS logical check found runtime executable-memory code that needs review" >&2
  exit 51
fi

echo "ios logical acceptance passed"
