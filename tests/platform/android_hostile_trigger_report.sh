#!/usr/bin/env bash
set -euo pipefail

report_path="${1:-docs/qa/reports/android-hostile-triggers.json}"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
if [[ ! -d "$sdk_root" && -d /usr/lib/android-sdk ]]; then
  sdk_root="/usr/lib/android-sdk"
fi
export ANDROID_HOME="$sdk_root"
export ANDROID_SDK_ROOT="$sdk_root"
export PATH="$sdk_root/platform-tools:$PATH"
mkdir -p "$(dirname "$report_path")"

cleanup_waiters() {
  pkill -f '[a]db wait-for-device' >/dev/null 2>&1 || true
}
trap cleanup_waiters EXIT

write_blocked_report() {
  local note="$1"
  python3 - "$report_path" "$note" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
github_run_url = None
if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
    github_run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
path.write_text(json.dumps({
    "schema": "vmp.platform.android_hostile_triggers.v1",
    "status": "blocked",
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
    "github_run_url": github_run_url,
    "runner_os": os.environ.get("RUNNER_OS"),
    "runner_name": os.environ.get("RUNNER_NAME"),
    "authorized_hostile_profile": False,
    "hostile_profile_id": None,
    "emulator_probe_executed": False,
    "hostile_trigger_executed": False,
    "hostile_trigger_types": [],
    "device": None,
    "raw_probe_summary": {},
    "normal_environment_findings": None,
    "findings": [],
    "missing_required_triggers": [
        "root_trigger_device_or_image",
        "xposed_or_lsposed_trigger",
        "frida_or_hook_trigger",
    ],
    "blocking_note": sys.argv[2],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

if ! command -v adb >/dev/null 2>&1; then
  write_blocked_report "adb is required for Android hostile-environment probing."
  echo "adb is required" >&2
  exit 50
fi

adb start-server >/dev/null
if ! timeout 180 adb wait-for-device; then
  write_blocked_report "No booted Android emulator/device became available to adb."
  echo "No booted Android emulator/device became available to adb" >&2
  exit 51
fi

boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
if [[ "$boot_completed" != "1" ]]; then
  write_blocked_report "adb device is present, but sys.boot_completed is not 1."
  echo "Android device is not fully booted" >&2
  exit 52
fi

getprop_text="$(adb shell getprop 2>/dev/null | tr -d '\r' || true)"
process_text="$(adb shell ps -A 2>/dev/null | tr -d '\r' || true)"
package_text="$(adb shell pm list packages 2>/dev/null | tr -d '\r' || true)"
mount_text="$(adb shell mount 2>/dev/null | tr -d '\r' || true)"
tcp_text="$(adb shell 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null' 2>/dev/null | tr -d '\r' || true)"
unix_socket_text="$(adb shell 'cat /proc/net/unix 2>/dev/null' 2>/dev/null | tr -d '\r' || true)"
magisk_paths=()
su_paths=()
for candidate in /system/xbin/su /system/bin/su /sbin/su /vendor/bin/su /system/bin/.ext/su /apex/com.android.runtime/bin/su; do
  if adb shell "test -e '$candidate'" >/dev/null 2>&1; then
    su_paths+=("$candidate")
  fi
done
for candidate in /sbin/.magisk /debug_ramdisk/.magisk /data/adb/magisk /data/adb/ksu /data/adb/ap; do
  if adb shell "test -e '$candidate'" >/dev/null 2>&1; then
    magisk_paths+=("$candidate")
  fi
done
xposed_paths=()
for candidate in /data/adb/modules/zygisk_lsposed /data/adb/modules/lsposed /data/adb/lspd /data/misc/lspd /system/framework/XposedBridge.jar; do
  if adb shell "test -e '$candidate'" >/dev/null 2>&1; then
    xposed_paths+=("$candidate")
  fi
done
su_id_text="$(timeout 5 adb shell su -c id 2>/dev/null | tr -d '\r' || true)"
serial="$(adb get-serialno 2>/dev/null | tr -d '\r' || true)"
abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' || true)"
fingerprint="$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' || true)"
build_tags="$(adb shell getprop ro.build.tags 2>/dev/null | tr -d '\r' || true)"
verified_boot="$(adb shell getprop ro.boot.verifiedbootstate 2>/dev/null | tr -d '\r' || true)"
vbmeta_state="$(adb shell getprop ro.boot.vbmeta.device_state 2>/dev/null | tr -d '\r' || true)"

python3 - "$report_path" "$getprop_text" "$process_text" "$package_text" "$mount_text" "$tcp_text" "$unix_socket_text" "$su_id_text" "$serial" "$abi" "$fingerprint" "$build_tags" "$verified_boot" "$vbmeta_state" -- "${su_paths[@]}" --magisk "${magisk_paths[@]}" --xposed "${xposed_paths[@]}" <<'PY'
import json
import os
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
getprop_text = sys.argv[2].lower()
process_text = sys.argv[3].lower()
package_text = sys.argv[4].lower()
mount_text = sys.argv[5].lower()
tcp_text = sys.argv[6].lower()
unix_socket_text = sys.argv[7].lower()
su_id_text = sys.argv[8].strip()
serial = sys.argv[9].strip()
abi = sys.argv[10].strip()
fingerprint = sys.argv[11].strip()
build_tags = sys.argv[12].strip()
verified_boot = sys.argv[13].strip()
vbmeta_state = sys.argv[14].strip()

remaining = sys.argv[15:]
su_paths = []
magisk_paths = []
xposed_paths = []
target = su_paths
for item in remaining:
    if item == "--":
        target = su_paths
        continue
    if item == "--magisk":
        target = magisk_paths
        continue
    if item == "--xposed":
        target = xposed_paths
        continue
    target.append(item)

findings = []

def add(category, signal, source, value):
    findings.append({
        "category": category,
        "signal": signal,
        "source": source,
        "severity": "hostile",
        "action": "deny_protected_execution",
        "evidence": value,
    })

if su_paths:
    add("root", "su_or_magisk_path_present", "android_filesystem", su_paths)
if magisk_paths:
    add("root", "magisk_or_root_manager_path_present", "android_filesystem", magisk_paths)
if "uid=0" in su_id_text.lower():
    add("root", "su_grants_uid0", "android_su_command", su_id_text)
if build_tags == "test-keys":
    add("root", "test_keys_build_tags", "android_getprop", "ro.build.tags=test-keys")
if "[ro.debuggable]: [1]" in getprop_text:
    add("root", "ro_debuggable_enabled", "android_getprop", "ro.debuggable=1")
if "[ro.secure]: [0]" in getprop_text:
    add("root", "ro_secure_disabled", "android_getprop", "ro.secure=0")
if verified_boot in {"orange", "yellow", "red"}:
    add("root", "verified_boot_not_green", "android_getprop", f"ro.boot.verifiedbootstate={verified_boot}")
if vbmeta_state == "unlocked":
    add("root", "vbmeta_device_unlocked", "android_getprop", "ro.boot.vbmeta.device_state=unlocked")
for name in ("magisk", "supersu", "ksu"):
    if name in package_text or name in process_text:
        add("root", f"{name}_indicator", "android_packages_processes", name)
if "magisk" in mount_text or "zygisk" in mount_text:
    add("root", "magisk_mount_indicator", "android_mounts", "magisk/zygisk")
for name in ("xposed", "lsposed", "edxposed", "zygisk"):
    if name in package_text or name in process_text or name in getprop_text:
        add("hook_framework", f"{name}_indicator", "android_packages_processes_props", name)
if xposed_paths:
    add("hook_framework", "xposed_lsposed_path_present", "android_filesystem", xposed_paths)
for package in ("org.lsposed.manager", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager"):
    if package in package_text:
        add("hook_framework", "xposed_lsposed_manager_package", "android_packages", package)
for name in ("frida-server", "frida-agent", "frida-gadget", "gum-js-loop"):
    if name in process_text or name in package_text:
        add("hook_framework", f"{name}_indicator", "android_packages_processes", name)
if "frida" in unix_socket_text or "gum-js-loop" in unix_socket_text:
    add("hook_framework", "frida_unix_socket_indicator", "android_proc_net_unix", "frida/gum-js-loop")
if "69a2" in tcp_text or "69a3" in tcp_text:
    add("hook_framework", "frida_default_tcp_port_listening", "android_proc_net_tcp", "27042/27043")

has_root = any(finding["category"] == "root" for finding in findings)
has_xposed = any(
    marker in finding["signal"]
    for finding in findings
    for marker in ("xposed", "lsposed", "edxposed", "zygisk")
)
has_frida = any(
    marker in finding["signal"]
    for finding in findings
    for marker in ("frida", "hook")
)

missing_required = []
if not has_root:
    missing_required.append("root_trigger_device_or_image")
if not has_xposed:
    missing_required.append("xposed_or_lsposed_trigger")
if not has_frida:
    missing_required.append("frida_or_hook_trigger")
authorized_hostile_profile = os.environ.get("ANDROID_HOSTILE_PROFILE_AUTHORIZED") == "true" and bool(os.environ.get("ANDROID_HOSTILE_PROFILE_ID"))
if not authorized_hostile_profile:
    missing_required.append("authorized_hostile_profile")

blocking_note = (
    "Android hostile probes detected root, Xposed/LSPosed, and Frida/hook indicators on an authorized hostile profile."
    if not missing_required
    else "Android emulator probes detected partial hostile indicators, but hard acceptance still requires: " + ", ".join(missing_required) + "."
    if findings
    else "Android emulator baseline probes executed. Hard acceptance still requires real root, Xposed/LSPosed, Frida, and hook trigger reports; absence on a normal emulator is not trigger evidence."
)

github_run_url = None
if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
    github_run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"

data = {
    "schema": "vmp.platform.android_hostile_triggers.v1",
    "status": "pass" if not missing_required else "blocked",
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
    "github_run_url": github_run_url,
    "runner_os": os.environ.get("RUNNER_OS"),
    "runner_name": os.environ.get("RUNNER_NAME"),
    "authorized_hostile_profile": authorized_hostile_profile,
    "hostile_profile_id": os.environ.get("ANDROID_HOSTILE_PROFILE_ID"),
    "emulator_probe_executed": True,
    "hostile_trigger_executed": bool(findings),
    "hostile_trigger_types": sorted({finding["category"] for finding in findings}),
    "device": {
        "adb_serial": serial,
        "abi": abi,
        "build_fingerprint": fingerprint,
        "build_tags": build_tags,
        "verified_boot_state": verified_boot,
        "vbmeta_device_state": vbmeta_state,
    },
    "raw_probe_summary": {
        "su_paths": su_paths,
        "magisk_paths": magisk_paths,
        "xposed_paths": xposed_paths,
        "su_command_returned_uid0": "uid=0" in su_id_text.lower(),
        "process_text_bytes": len(process_text),
        "package_text_bytes": len(package_text),
        "tcp_table_bytes": len(tcp_text),
        "unix_socket_table_bytes": len(unix_socket_text),
    },
    "normal_environment_findings": 0 if not findings else None,
    "findings": findings,
    "missing_required_triggers": missing_required,
    "blocking_note": blocking_note,
}
report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "android hostile trigger baseline report written"
