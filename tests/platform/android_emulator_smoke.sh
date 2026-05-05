#!/usr/bin/env bash
set -euo pipefail

report_path="${1:-docs/qa/reports/android-emulator-smoke.json}"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
ndk_home="${ANDROID_NDK_HOME:-}"
if [[ -z "$ndk_home" && -d "$sdk_root/ndk" ]]; then
  ndk_home="$(find "$sdk_root/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
fi

mkdir -p "$(dirname "$report_path")"

cleanup_waiters() {
  pkill -f '[a]db wait-for-device' >/dev/null 2>&1 || true
}
trap cleanup_waiters EXIT

write_blocked_report() {
  local note="$1"
  python3 - "$report_path" "$note" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "schema": "vmp.platform.android_emulator_smoke.v1",
    "status": "blocked",
    "blocking_note": sys.argv[2],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

if [[ ! -d "$sdk_root" ]]; then
  write_blocked_report "Android SDK root is missing."
  echo "Android SDK root is missing: $sdk_root" >&2
  exit 40
fi
if [[ -z "$ndk_home" || ! -x "$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android23-clang" ]]; then
  write_blocked_report "Android NDK x86_64 compiler is missing."
  echo "Android NDK compiler is missing under: ${ndk_home:-<unset>}" >&2
  exit 41
fi

export ANDROID_HOME="$sdk_root"
export ANDROID_SDK_ROOT="$sdk_root"
export ANDROID_NDK_HOME="$ndk_home"
export PATH="$sdk_root/cmdline-tools/latest/bin:$sdk_root/emulator:$sdk_root/platform-tools:$PATH"

if ! command -v adb >/dev/null 2>&1; then
  write_blocked_report "adb is not available on PATH."
  echo "adb is not available" >&2
  exit 42
fi

build_abi() {
  local abi="$1"
  local dir="$2"
  cmake -S src/platform -B "$dir" \
    -DCMAKE_TOOLCHAIN_FILE="$ndk_home/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$abi" \
    -DANDROID_PLATFORM=android-23 \
    -DPLATFORM_ADAPTER_TARGET=android \
    -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$dir" --target vmp_platform -j2 >/dev/null
}

build_abi x86_64 build/android-x86_64
build_abi arm64-v8a build/android-arm64-v8a

runner="build/android-x86_64/mi_android_native_smoke"
"$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android23-clang" \
  -O2 -I src/platform tests/platform/android_native_smoke.c -ldl -o "$runner"

adb start-server >/dev/null
if ! timeout 180 adb wait-for-device; then
  write_blocked_report "No booted Android emulator/device became available to adb."
  echo "No booted Android emulator/device became available to adb" >&2
  exit 43
fi

boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
if [[ "$boot_completed" != "1" ]]; then
  write_blocked_report "adb device is present, but sys.boot_completed is not 1."
  echo "Android device is not fully booted" >&2
  exit 44
fi

remote_dir="/data/local/tmp/mi_platform"
adb shell "rm -rf '$remote_dir' && mkdir -p '$remote_dir'" >/dev/null
adb push build/android-x86_64/libmi_platform.so "$remote_dir/libmi_platform.so" >/dev/null
adb push "$runner" "$remote_dir/mi_android_native_smoke" >/dev/null
adb shell "chmod 755 '$remote_dir/mi_android_native_smoke'" >/dev/null

set +e
smoke_output="$(adb shell "cd '$remote_dir' && LD_LIBRARY_PATH=. ./mi_android_native_smoke ./libmi_platform.so" 2>&1)"
smoke_status=$?
set -e

abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
api_level="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
device_model="$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"

python3 - "$report_path" "$smoke_status" "$smoke_output" "$abi" "$api_level" "$device_model" <<'PY'
import json
import os
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
smoke_status = int(sys.argv[2])
smoke_output = sys.argv[3]
abi = sys.argv[4]
api_level = sys.argv[5]
device_model = sys.argv[6]
artifacts = [
    pathlib.Path("build/android-x86_64/libmi_platform.so"),
    pathlib.Path("build/android-arm64-v8a/libmi_platform.so"),
    pathlib.Path("build/android-x86_64/mi_android_native_smoke"),
]
data = {
    "schema": "vmp.platform.android_emulator_smoke.v1",
    "status": "pass" if smoke_status == 0 else "fail",
    "device": {
        "abi": abi,
        "api_level": api_level,
        "model": device_model,
    },
    "artifacts": [
        {"path": str(path), "bytes": path.stat().st_size}
        for path in artifacts
    ],
    "ci_execution": os.environ.get("GITHUB_ACTIONS") == "true",
    "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
    "github_run_id": os.environ.get("GITHUB_RUN_ID"),
    "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "github_workflow": os.environ.get("GITHUB_WORKFLOW"),
    "github_repository": os.environ.get("GITHUB_REPOSITORY"),
    "github_sha": os.environ.get("GITHUB_SHA"),
    "github_event_name": os.environ.get("GITHUB_EVENT_NAME"),
    "github_ref": os.environ.get("GITHUB_REF"),
    "github_ref_name": os.environ.get("GITHUB_REF_NAME"),
    "github_ref_protected": os.environ.get("GITHUB_REF_PROTECTED"),
    "github_job": os.environ.get("GITHUB_JOB"),
    "github_run_url": (
        f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID")
        else None
    ),
    "runner_os": os.environ.get("RUNNER_OS"),
    "runner_name": os.environ.get("RUNNER_NAME"),
    "emulator_execution": smoke_status == 0,
    "protected_so_loaded": "android native smoke passed" in smoke_output,
    "jni_on_load_called": "jni_on_load=" in smoke_output,
    "core_logic_consistent": "add_20_22=42" in smoke_output,
    "smoke_exit_code": smoke_status,
    "smoke_output": smoke_output.splitlines(),
    "blocking_note": None if smoke_status == 0 else "Android native .so smoke failed in emulator.",
    "scope_note": "This is real emulator execution of the Android x86_64 .so through a native dlopen/JNI_OnLoad smoke harness. It is not APK install evidence and does not satisfy hostile-environment triggers.",
}
report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if [[ "$smoke_status" -ne 0 ]]; then
  printf '%s\n' "$smoke_output" >&2
  exit "$smoke_status"
fi

printf '%s\n' "$smoke_output"
