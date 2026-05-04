#!/usr/bin/env bash
set -euo pipefail

tests/platform/linux_smoke.sh
tests/platform/ios_logic_check.sh

echo "local platform checks passed"
