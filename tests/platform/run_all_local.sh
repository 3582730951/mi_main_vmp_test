#!/usr/bin/env bash
set -euo pipefail

bash tests/platform/linux_smoke.sh
bash tests/platform/ios_logic_check.sh

echo "local platform checks passed"
