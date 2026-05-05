#!/usr/bin/env bash
set -euo pipefail

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
api_level="${ANDROID_API_LEVEL:-35}"
system_image="${ANDROID_SYSTEM_IMAGE:-system-images;android-${api_level};default;x86_64}"
avd_name="${ANDROID_AVD_NAME:-vmp_api${api_level}_x86_64}"
ndk_version="${ANDROID_NDK_VERSION:-26.3.11579264}"
build_tools_version="${ANDROID_BUILD_TOOLS_VERSION:-35.0.1}"
emulator_log="${ANDROID_EMULATOR_LOG:-build/android-emulator.log}"

export ANDROID_HOME="$sdk_root"
export ANDROID_SDK_ROOT="$sdk_root"
export PATH="$sdk_root/cmdline-tools/latest/bin:$sdk_root/emulator:$sdk_root/platform-tools:$sdk_root/build-tools/$build_tools_version:$PATH"

mkdir -p "$(dirname "$emulator_log")"

cleanup() {
  adb emu kill >/dev/null 2>&1 || true
  adb kill-server >/dev/null 2>&1 || true
  pkill -f '[a]db wait-for-device' >/dev/null 2>&1 || true
  pkill -f '[q]emu-system-.*-headless.*-avd' >/dev/null 2>&1 || true
  pkill -f '[/]opt/android-sdk/emulator/qemu' >/dev/null 2>&1 || true
  pkill -f '[/]opt/android-sdk/emulator/netsimd' >/dev/null 2>&1 || true
  pkill -f '[/]opt/android-sdk/emulator/crashpad_handler' >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v sdkmanager >/dev/null 2>&1; then
  echo "sdkmanager is required on PATH" >&2
  exit 50
fi
if ! command -v avdmanager >/dev/null 2>&1; then
  echo "avdmanager is required on PATH" >&2
  exit 51
fi

{ yes || true; } | sdkmanager --licenses >/dev/null
sdkmanager \
  "platform-tools" \
  "emulator" \
  "platforms;android-${api_level}" \
  "build-tools;${build_tools_version}" \
  "ndk;${ndk_version}" \
  "$system_image" >/dev/null

export ANDROID_NDK_HOME="$sdk_root/ndk/$ndk_version"
export PATH="$sdk_root/build-tools/$build_tools_version:$PATH"

if ! command -v emulator >/dev/null 2>&1; then
  echo "emulator is required on PATH after sdkmanager installation" >&2
  exit 52
fi
if ! command -v adb >/dev/null 2>&1; then
  echo "adb is required on PATH after sdkmanager installation" >&2
  exit 53
fi

if ! emulator -list-avds | grep -Fxq "$avd_name"; then
  echo "no" | avdmanager create avd \
    --force \
    --name "$avd_name" \
    --package "$system_image" \
    --device "pixel" >/dev/null
fi

if [[ -e /dev/kvm ]]; then
  kvm_user="${USER:-$(id -un 2>/dev/null || true)}"
  if [[ -n "$kvm_user" ]]; then
    sudo chown "$kvm_user" /dev/kvm || true
  fi
fi

emulator -avd "$avd_name" \
  -no-window \
  -no-audio \
  -no-snapshot \
  -gpu swiftshader_indirect \
  -no-boot-anim \
  -no-metrics \
  >"$emulator_log" 2>&1 &

if ! timeout 180 adb wait-for-device; then
  echo "Android emulator did not become visible to adb" >&2
  tail -n 120 "$emulator_log" >&2 || true
  exit 54
fi
for _ in $(seq 1 180); do
  boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  if [[ "$boot_completed" == "1" ]]; then
    break
  fi
  sleep 2
done

boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
if [[ "$boot_completed" != "1" ]]; then
  echo "Android emulator did not finish booting" >&2
  tail -n 120 "$emulator_log" >&2 || true
  exit 55
fi

adb shell input keyevent 82 >/dev/null 2>&1 || true

bash tests/platform/android_environment_check.sh
bash tests/platform/android_emulator_smoke.sh
bash tests/platform/android_apk_smoke.sh
bash tests/platform/android_hostile_trigger_report.sh

echo "android CI emulator smoke passed"
