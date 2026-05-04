#!/usr/bin/env bash
set -euo pipefail

report_path="${1:-docs/qa/reports/android-environment.json}"
mkdir -p "$(dirname "$report_path")"

python3 - "$report_path" <<'PY'
import json
import os
import pathlib
import shutil
import subprocess
import sys

report = pathlib.Path(sys.argv[1])
sdk_root = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ""
if not sdk_root:
    for candidate in ("/opt/android-sdk", "/usr/lib/android-sdk"):
        if pathlib.Path(candidate).exists():
            sdk_root = candidate
            break
ndk_home = os.environ.get("ANDROID_NDK_HOME") or ""
if not ndk_home and sdk_root:
    ndk_root = pathlib.Path(sdk_root) / "ndk"
    if ndk_root.exists():
        ndks = sorted([path for path in ndk_root.iterdir() if path.is_dir()])
        if ndks:
            ndk_home = str(ndks[-1])

path_entries = []
if sdk_root:
    path_entries.extend([
        str(pathlib.Path(sdk_root) / "cmdline-tools" / "latest" / "bin"),
        str(pathlib.Path(sdk_root) / "emulator"),
        str(pathlib.Path(sdk_root) / "platform-tools"),
    ])
if ndk_home:
    path_entries.append(ndk_home)
path = os.pathsep.join([*path_entries, os.environ.get("PATH", "")])

def which(name):
    return shutil.which(name, path=path)

commands = {
    "adb": which("adb"),
    "emulator": which("emulator"),
    "sdkmanager": which("sdkmanager"),
    "ndk_build": which("ndk-build"),
    "cmake": which("cmake"),
    "avdmanager": which("avdmanager"),
}
env = {
    "ANDROID_HOME": os.environ.get("ANDROID_HOME", sdk_root),
    "ANDROID_SDK_ROOT": os.environ.get("ANDROID_SDK_ROOT", sdk_root),
    "ANDROID_NDK_HOME": os.environ.get("ANDROID_NDK_HOME", ndk_home),
}

apt_android = subprocess.run(
    ["apt-cache", "search", "android"],
    check=False,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)
apt_lines = [
    line for line in apt_android.stdout.splitlines()
    if any(term in line.lower() for term in ("emulator", "ndk", "sdk"))
]

system_images = []
if sdk_root:
    root = pathlib.Path(sdk_root) / "system-images"
    if root.exists():
        system_images = [
            path.relative_to(root).as_posix()
            for path in root.glob("*/*/*")
            if path.is_dir()
        ]

avds = []
if commands["emulator"]:
    avd_proc = subprocess.run(
        [commands["emulator"], "-list-avds"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "ANDROID_HOME": sdk_root, "ANDROID_SDK_ROOT": sdk_root, "PATH": path},
    )
    avds = [line.strip() for line in avd_proc.stdout.splitlines() if line.strip()]

emulator_ready = commands["emulator"] is not None and bool(system_images) and bool(avds)
ndk_ready = commands["ndk_build"] is not None or bool(ndk_home)

data = {
    "schema": "vmp.platform.android_environment.v1",
    "status": "partial" if emulator_ready and ndk_ready else "blocked",
    "commands": commands,
    "environment": env,
    "emulator_available": commands["emulator"] is not None,
    "ndk_available": ndk_ready,
    "system_images": system_images,
    "avds": avds,
    "apt_android_relevant_packages": apt_lines,
    "blocking_note": "Android APK/JNI and native .so emulator smoke evidence now exists; hard acceptance still requires release-strength CI/signing evidence and hostile-environment trigger evidence.",
}
report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "android environment report written"
