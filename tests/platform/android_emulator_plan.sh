#!/usr/bin/env bash
set -euo pipefail

required_vars=(
  ANDROID_HOME
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "missing required environment variable: $var" >&2
    exit 40
  fi
done

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required" >&2
  exit 41
fi

if ! command -v adb >/dev/null 2>&1; then
  echo "adb is required" >&2
  exit 42
fi

if [[ "${RUN_ANDROID_EMULATOR_SMOKE:-0}" == "1" ]]; then
  exec bash tests/platform/android_emulator_smoke.sh
fi

echo "Android emulator acceptance plan:"
echo "1. Build protected native libraries for arm64-v8a and x86_64 with the NDK toolchain."
echo "2. Package protected .so files under app/src/main/jniLibs/<abi>/."
echo "3. Install the APK on an x86_64 emulator and run JNI smoke tests."
echo "4. Record hostile-environment checks separately from normal emulator smoke results."
