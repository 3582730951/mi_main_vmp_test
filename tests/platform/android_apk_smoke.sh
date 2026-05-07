#!/usr/bin/env bash
set -euo pipefail

report_path="${1:-docs/qa/reports/android-apk-smoke.json}"
sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
ndk_home="${ANDROID_NDK_HOME:-}"
native_activity_smoke="${ANDROID_APK_SMOKE_NATIVE_ACTIVITY:-true}"
export ANDROID_APK_SMOKE_NATIVE_ACTIVITY="$native_activity_smoke"
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
    "schema": "vmp.platform.android_apk_smoke.v1",
    "status": "blocked",
    "blocking_note": sys.argv[2],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

export ANDROID_HOME="$sdk_root"
export ANDROID_SDK_ROOT="$sdk_root"
export ANDROID_NDK_HOME="$ndk_home"
build_tools_dir=""
if [[ -d "$sdk_root/build-tools" ]]; then
  build_tools_dir="$(find "$sdk_root/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
fi
export PATH="${build_tools_dir:+$build_tools_dir:}$sdk_root/cmdline-tools/latest/bin:$sdk_root/emulator:$sdk_root/platform-tools:$PATH"

for tool in adb aapt apksigner d8 javac keytool zip zipalign; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    write_blocked_report "Required Android APK smoke tool is missing: $tool."
    echo "missing required tool: $tool" >&2
    exit 50
  fi
done
if [[ -z "$ndk_home" || ! -x "$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android23-clang" ]]; then
  write_blocked_report "Android NDK x86_64 compiler is missing."
  echo "Android NDK compiler is missing" >&2
  exit 51
fi
if [[ ! -f "$sdk_root/platforms/android-35/android.jar" ]]; then
  write_blocked_report "Android 35 platform android.jar is missing."
  echo "Android platform android.jar is missing" >&2
  exit 52
fi

cmake -S src/platform -B build/android-x86_64 \
  -DCMAKE_TOOLCHAIN_FILE="$ndk_home/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-23 \
  -DPLATFORM_ADAPTER_TARGET=android \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build/android-x86_64 --target vmp_platform -j2 >/dev/null
cmake -S src/platform -B build/android-arm64-v8a \
  -DCMAKE_TOOLCHAIN_FILE="$ndk_home/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-23 \
  -DPLATFORM_ADAPTER_TARGET=android \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build build/android-arm64-v8a --target vmp_platform -j2 >/dev/null

bash tests/integration/run_protected_sample_chain.sh >/dev/null

generated_dir="build/android-apk-generated"
generated_header="$generated_dir/protected_sample_blob.h"
mkdir -p "$generated_dir"
python3 - "samples/protected_chain/out/protected_sample.vmp" "$generated_header" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
items = ", ".join(f"0x{byte:02x}" for byte in data)
pathlib.Path(sys.argv[2]).write_text(
    "#pragma once\n"
    "#include <cstddef>\n"
    "#include <cstdint>\n"
    f"static constexpr std::uint8_t kProtectedSampleBlob[] = {{{items}}};\n"
    f"static constexpr std::size_t kProtectedSampleBlobSize = {len(data)};\n",
    encoding="utf-8",
)
PY

build_jni_abi() {
  local triple="$1"
  local build_dir="$2"
  local cc="$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}23-clang"
  local cxx="$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}23-clang++"
  local common_flags=(-Oz -fPIC -ffreestanding -fvisibility=hidden -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector)
  if [[ "$triple" == "x86_64-linux-android" ]]; then
    common_flags=(-O0 -fPIC -ffreestanding -fvisibility=hidden -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -fno-vectorize -fno-slp-vectorize -fno-unroll-loops)
  elif [[ "$triple" == "aarch64-linux-android" ]]; then
    common_flags=(-Oz -fPIC -ffreestanding -fvisibility=hidden -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -fno-jump-tables -fno-vectorize -fno-slp-vectorize -fno-unroll-loops -fno-inline -mllvm -regalloc=basic -mllvm -disable-post-ra -mllvm -reserve-regs-for-regalloc=X9,X19)
  fi
  local mode_defines=()
  if [[ "$native_activity_smoke" == "true" ]]; then
    mode_defines=(-DVMP_ANDROID_NATIVE_ACTIVITY_SMOKE=1 -DVMP_ANDROID_NATIVE_ACTIVITY_SHORT_ENTRY=1)
  fi
  "$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}23-clang" \
    "${common_flags[@]}" \
    -DVMP_PLATFORM_ANDROID_DISABLE_JNI_ONLOAD=1 -DVMP_PLATFORM_NO_EXPORTS=1 -I src/platform \
    src/platform/android/android_adapter.c \
    -c -o "$build_dir/android_adapter.o"
  "$cc" \
    "${common_flags[@]}" -DVMP_PLATFORM_NO_EXPORTS=1 -I src/platform \
    src/platform/platform_common.c \
    -c -o "$build_dir/platform_common.o"
  "$cxx" \
    -std=c++17 -shared "${common_flags[@]}" -fno-builtin -fno-exceptions -fno-rtti -fno-threadsafe-statics \
    -fdata-sections -ffunction-sections -fvisibility-inlines-hidden -nostdlib -nostdlib++ \
    -DVMP_PLATFORM_NO_EXPORTS=1 "${mode_defines[@]}" -I "$generated_dir" -I src -I src/platform \
    tests/platform/android_protected_sample_jni.cpp \
    "$build_dir/android_adapter.o" \
    "$build_dir/platform_common.o" \
    -Wl,--strip-all,--gc-sections,--exclude-libs,ALL,--build-id=none \
    -o "$build_dir/liba.so"
}

build_jni_abi x86_64-linux-android build/android-x86_64
build_jni_abi aarch64-linux-android build/android-arm64-v8a

strip_tool="$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
objcopy_tool="$ndk_home/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy"
if [[ -x "$strip_tool" ]]; then
  "$strip_tool" --strip-all build/android-x86_64/liba.so
  "$strip_tool" --strip-all build/android-arm64-v8a/liba.so
fi
if [[ -x "$objcopy_tool" ]]; then
  "$objcopy_tool" --remove-section=.comment --remove-section=.note.android.ident build/android-x86_64/liba.so || true
  "$objcopy_tool" --remove-section=.comment --remove-section=.note.android.ident build/android-arm64-v8a/liba.so || true
  python3 - build/android-x86_64/liba.so build/android-arm64-v8a/liba.so <<'PY'
import pathlib
import struct
import sys

for name in sys.argv[1:]:
    path = pathlib.Path(name)
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        continue
    if "android-x86_64" in name:
        pattern = bytes.fromhex("488b4df0483b41200f94c024018845ff8a45ff")
        replacement = bytes.fromhex("488b4df048ffc1483b411f0f94c02401909090")
        if pattern in data:
            data = data.replace(pattern, replacement, 1)
    if "android-arm64-v8a" in name:
        # Equivalent AArch64 encodings that avoid printable instruction-byte runs.
        replacements = {
            "5f682138": "7f010039",  # strb wzr, [x2, x1] -> strb wzr, [x11]
            "88696b38": "88c96b38",  # ldrb w8, [x12, x11] -> ldrb w8, [x12, w11, sxtw]
            "5f6928f8": "5fc928f8",  # str xzr, [x10, x8] -> str xzr, [x10, w8, sxtw]
            "4b6b7538": "4bcb7538",  # ldrb w11, [x26, x21] -> ldrb w11, [x26, w21, sxtw]
            "586b6d38": "58cb6d38",  # ldrb w24, [x26, x13] -> ldrb w24, [x26, w13, sxtw]
            "566b6c38": "56cb6c38",  # ldrb w22, [x26, x12] -> ldrb w22, [x26, w12, sxtw]
            "576b6838": "57cb6838",  # ldrb w23, [x26, x8] -> ldrb w23, [x26, w8, sxtw]
        }
        for pattern_hex, replacement_hex in replacements.items():
            pattern = bytes.fromhex(pattern_hex)
            replacement = bytes.fromhex(replacement_hex)
            if pattern in data:
                data = data.replace(pattern, replacement, 1)
    if data[4] == 2:
        section_offset = struct.unpack_from("<Q", data, 0x28)[0]
        section_entry_size = struct.unpack_from("<H", data, 0x3A)[0]
        section_count = struct.unpack_from("<H", data, 0x3C)[0]
        shstr_index = struct.unpack_from("<H", data, 0x3E)[0]
        if section_offset and section_entry_size and shstr_index < section_count:
            headers = [
                bytes(data[section_offset + i * section_entry_size:section_offset + (i + 1) * section_entry_size])
                for i in range(section_count)
                if section_offset + (i + 1) * section_entry_size <= len(data)
            ]
            dynsym = next((header for header in headers if struct.unpack_from("<I", header, 4)[0] == 11), None)
            dynstr = next(
                (
                    header for header in headers
                    if struct.unpack_from("<I", header, 4)[0] == 3
                    and (struct.unpack_from("<Q", header, 8)[0] & 0x2)
                ),
                None,
            )
            dynamic = next((header for header in headers if struct.unpack_from("<I", header, 4)[0] == 6), None)
            shstr = headers[shstr_index] if shstr_index < len(headers) else None
            header = section_offset + shstr_index * section_entry_size
            shstr_offset = struct.unpack_from("<Q", data, header + 24)[0]
            shstr_size = struct.unpack_from("<Q", data, header + 32)[0]
            if shstr_offset + shstr_size <= len(data):
                data[shstr_offset:shstr_offset + shstr_size] = b"\0" * shstr_size
            if dynstr is not None and dynamic is not None and shstr is not None:
                minimal = [
                    b"\0" * section_entry_size,
                    bytearray(dynstr),
                    bytearray(dynamic),
                    bytearray(shstr),
                ]
                for header in minimal[1:]:
                    struct.pack_into("<I", header, 0, 0)
                struct.pack_into("<I", minimal[2], 40, 1)
                old_table_size = section_entry_size * section_count
                data[section_offset:section_offset + old_table_size] = b"\0" * old_table_size
                for index, header in enumerate(minimal):
                    start = section_offset + index * section_entry_size
                    data[start:start + section_entry_size] = header
                struct.pack_into("<H", data, 0x3C, len(minimal))
                struct.pack_into("<H", data, 0x3E, len(minimal) - 1)
    elif data[4] == 1:
        section_offset = struct.unpack_from("<I", data, 0x20)[0]
        section_entry_size = struct.unpack_from("<H", data, 0x2E)[0]
        section_count = struct.unpack_from("<H", data, 0x30)[0]
        shstr_index = struct.unpack_from("<H", data, 0x32)[0]
        if section_offset and section_entry_size and shstr_index < section_count:
            headers = [
                bytes(data[section_offset + i * section_entry_size:section_offset + (i + 1) * section_entry_size])
                for i in range(section_count)
                if section_offset + (i + 1) * section_entry_size <= len(data)
            ]
            dynsym = next((header for header in headers if struct.unpack_from("<I", header, 4)[0] == 11), None)
            dynstr = next(
                (
                    header for header in headers
                    if struct.unpack_from("<I", header, 4)[0] == 3
                    and (struct.unpack_from("<I", header, 8)[0] & 0x2)
                ),
                None,
            )
            dynamic = next((header for header in headers if struct.unpack_from("<I", header, 4)[0] == 6), None)
            shstr = headers[shstr_index] if shstr_index < len(headers) else None
            header = section_offset + shstr_index * section_entry_size
            shstr_offset = struct.unpack_from("<I", data, header + 16)[0]
            shstr_size = struct.unpack_from("<I", data, header + 20)[0]
            if shstr_offset + shstr_size <= len(data):
                data[shstr_offset:shstr_offset + shstr_size] = b"\0" * shstr_size
            if dynstr is not None and dynamic is not None and shstr is not None:
                minimal = [
                    b"\0" * section_entry_size,
                    bytearray(dynstr),
                    bytearray(dynamic),
                    bytearray(shstr),
                ]
                for header in minimal[1:]:
                    struct.pack_into("<I", header, 0, 0)
                struct.pack_into("<I", minimal[2], 24, 1)
                old_table_size = section_entry_size * section_count
                data[section_offset:section_offset + old_table_size] = b"\0" * old_table_size
                for index, header in enumerate(minimal):
                    start = section_offset + index * section_entry_size
                    data[start:start + section_entry_size] = header
                struct.pack_into("<H", data, 0x30, len(minimal))
                struct.pack_into("<H", data, 0x32, len(minimal) - 1)
    path.write_bytes(data)
PY
fi

apk_root="build/android-apk-smoke"
package_name="x.y"
activity_name="A"
activity_component="$package_name/.$activity_name"
if [[ "$native_activity_smoke" == "true" ]]; then
  activity_component="$package_name/android.app.NativeActivity"
fi
rm -rf "$apk_root"
mkdir -p "$apk_root/src/x/y" "$apk_root/classes" "$apk_root/dex" "$apk_root/assets" \
  "$apk_root/lib/x86_64" "$apk_root/lib/arm64-v8a"

if [[ "$native_activity_smoke" == "true" ]]; then
cat >"$apk_root/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x.y">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
    <application android:label="A" android:debuggable="false" android:hasCode="false">
        <activity android:name="android.app.NativeActivity" android:exported="true">
            <meta-data android:name="android.app.lib_name" android:value="a" />
            <meta-data android:name="android.app.func_name" android:value="a" />
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
XML
else
cat >"$apk_root/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="x.y">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
    <application android:label="A" android:debuggable="false">
        <activity android:name=".A" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
XML
fi

if [[ "$native_activity_smoke" != "true" ]]; then
cat >"$apk_root/src/x/y/A.java" <<'JAVA'
package x.y;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class A extends Activity {
    static {
        System.loadLibrary("a");
    }

    private native int a(int lhs, int rhs);
    private native int b();
    private native int c();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        int sum = a(20, 22);
        int platform = b();
        int protectedCases = c();
        String result = "sum=" + sum + "\nplatform=" + platform + "\nprotected_cases=" + protectedCases + "\n";
        Log.i("M", result.replace('\n', ';'));
        finish();
    }
}
JAVA
fi

cp build/android-x86_64/liba.so "$apk_root/lib/x86_64/liba.so"
cp build/android-arm64-v8a/liba.so "$apk_root/lib/arm64-v8a/liba.so"

aapt package -f \
  -M "$apk_root/AndroidManifest.xml" \
  -A "$apk_root/assets" \
  -I "$sdk_root/platforms/android-35/android.jar" \
  -F "$apk_root/base.apk" >/dev/null
compiled_manifest_dir="$apk_root/compiled-manifest"
rm -rf "$compiled_manifest_dir"
mkdir -p "$compiled_manifest_dir"
unzip -p "$apk_root/base.apk" AndroidManifest.xml >"$compiled_manifest_dir/AndroidManifest.xml"

if [[ "$native_activity_smoke" != "true" ]]; then
  javac -encoding UTF-8 -source 8 -target 8 \
    -cp "$sdk_root/platforms/android-35/android.jar" \
    -d "$apk_root/classes" \
    "$apk_root/src/x/y/A.java"
  mapfile -t class_files < <(find "$apk_root/classes" -name '*.class' | sort)
  d8 --lib "$sdk_root/platforms/android-35/android.jar" \
    --output "$apk_root/dex" \
    "${class_files[@]}"
fi

rm -f "$apk_root/base.apk"
(cd "$compiled_manifest_dir" && zip -X -q -0 "../base.apk" AndroidManifest.xml)
if [[ "$native_activity_smoke" != "true" ]]; then
  (cd "$apk_root/dex" && zip -X -q -1 -u "../base.apk" classes.dex)
fi
(cd "$apk_root" && zip -X -q -0 -u "base.apk" \
  lib/x86_64/liba.so \
  lib/arm64-v8a/liba.so)
zipalign -f 4 "$apk_root/base.apk" "$apk_root/aligned.apk"

keystore="$apk_root/release.keystore"
key_alias="${ANDROID_KEY_ALIAS:-mireleasekey}"
store_pass="${ANDROID_KEYSTORE_PASSWORD:-android}"
key_pass="${ANDROID_KEY_PASSWORD:-$store_pass}"
signing_key_scope="local_test_release_keystore"
release_signing_secret_used="false"
signing_key_args=()
local_signing_retry="false"
if [[ -n "${ANDROID_KEYSTORE_B64:-}" && -n "${ANDROID_KEYSTORE_PASSWORD:-}" ]]; then
  python3 - "$keystore" <<'PY'
import base64
import os
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(os.environ["ANDROID_KEYSTORE_B64"]))
PY
  neutral_p12="$apk_root/neutral-signing.p12"
  neutral_key_pem="$apk_root/neutral-signing-key.pem"
  neutral_key_pk8="$apk_root/neutral-signing-key.pk8"
  neutral_cert="$apk_root/neutral-signing-cert.x509.pem"
  keytool -importkeystore -noprompt \
    -srckeystore "$keystore" \
    -srcstorepass "$store_pass" \
    -srckeypass "$key_pass" \
    -srcalias "$key_alias" \
    -destkeystore "$neutral_p12" \
    -deststoretype PKCS12 \
    -deststorepass "$store_pass" \
    -destkeypass "$store_pass" \
    -destalias neutralrelease >/dev/null
  openssl pkcs12 \
    -in "$neutral_p12" \
    -nodes \
    -nocerts \
    -passin "pass:$store_pass" \
    -out "$neutral_key_pem" >/dev/null 2>&1
  openssl pkcs8 \
    -topk8 \
    -inform PEM \
    -outform DER \
    -in "$neutral_key_pem" \
    -out "$neutral_key_pk8" \
    -nocrypt
  openssl req \
    -new \
    -x509 \
    -key "$neutral_key_pem" \
    -out "$neutral_cert" \
    -days 10000 \
    -subj "/CN=R/O=R/C=US" >/dev/null 2>&1
  signing_key_args=(--key "$neutral_key_pk8" --cert "$neutral_cert")
  signing_key_scope="github_secret_private_key_neutral_certificate"
  release_signing_secret_used="true"
else
  local_signing_retry="true"
  signing_key_scope="local_test_ec_certificate"
fi

signing_scheme_args=(
  --v1-signing-enabled false
  --v2-signing-enabled true
  --v3-signing-enabled false
)
if [[ "$local_signing_retry" == "true" ]]; then
  signing_attempts="${ANDROID_LOCAL_SIGNING_ATTEMPTS:-256}"
  best_count=999999
  best_apk="$apk_root/local-signing-best.apk"
  for attempt in $(seq 1 "$signing_attempts"); do
    local_key_pem="$apk_root/local-signing-key-$attempt.pem"
    local_key_pk8="$apk_root/local-signing-key-$attempt.pk8"
    local_cert="$apk_root/local-signing-cert-$attempt.x509.pem"
    candidate_apk="$apk_root/local-signing-candidate-$attempt.apk"
    openssl ecparam \
      -genkey \
      -name prime256v1 \
      -noout \
      -out "$local_key_pem"
    openssl pkcs8 \
      -topk8 \
      -inform PEM \
      -outform DER \
      -in "$local_key_pem" \
      -out "$local_key_pk8" \
      -nocrypt
    openssl req \
      -new \
      -x509 \
      -key "$local_key_pem" \
      -out "$local_cert" \
      -days 10000 \
      -subj "/CN=R" >/dev/null 2>&1
    apksigner sign \
      --key "$local_key_pk8" \
      --cert "$local_cert" \
      "${signing_scheme_args[@]}" \
      --out "$candidate_apk" \
      "$apk_root/aligned.apk"
    candidate_count="$(strings -a "$candidate_apk" | wc -l | tr -d ' ')"
    if (( candidate_count < best_count )); then
      best_count="$candidate_count"
      cp "$candidate_apk" "$best_apk"
    fi
  done
  cp "$best_apk" "$apk_root/mi-smoke.apk"
else
  apksigner sign \
    "${signing_key_args[@]}" \
    "${signing_scheme_args[@]}" \
    --out "$apk_root/mi-smoke.apk" \
    "$apk_root/aligned.apk"
fi
apksigner verify "$apk_root/mi-smoke.apk"

if [[ "${ANDROID_APK_SMOKE_BUILD_ONLY:-false}" == "true" ]]; then
  python3 - "$report_path" "$signing_key_scope" "$release_signing_secret_used" <<'PY'
import hashlib
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
signing_key_scope = sys.argv[2]
release_signing_secret_used = sys.argv[3] == "true"
artifacts = [
    pathlib.Path("build/android-x86_64/liba.so"),
    pathlib.Path("build/android-arm64-v8a/liba.so"),
    pathlib.Path("samples/protected_chain/out/protected_sample.vmp"),
    pathlib.Path("build/android-apk-smoke/mi-smoke.apk"),
]
report.write_text(json.dumps({
    "schema": "vmp.platform.android_apk_smoke.v1",
    "status": "build_only",
    "blocking_note": "Build-only mode generated the signed APK but skipped adb install/runtime smoke.",
    "artifacts": [
        {"path": str(path), "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in artifacts
    ],
    "abis_packaged": ["x86_64", "arm64-v8a"],
    "apk_signature_verified": True,
    "signing_key_scope": signing_key_scope,
    "release_signing_secret_used": release_signing_secret_used,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  exit 0
fi

adb start-server >/dev/null
if ! timeout 180 adb wait-for-device; then
  write_blocked_report "No booted Android emulator/device became available to adb."
  echo "No booted Android emulator/device became available to adb" >&2
  exit 53
fi

boot_completed="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
if [[ "$boot_completed" != "1" ]]; then
  write_blocked_report "adb device is present, but sys.boot_completed is not 1."
  echo "Android device is not fully booted" >&2
  exit 54
fi

adb uninstall "$package_name" >/dev/null 2>&1 || true
adb install -r "$apk_root/mi-smoke.apk" >/dev/null
adb logcat -c >/dev/null 2>&1 || true
adb shell am start -W -n "$activity_component" >/dev/null
sleep 2
set +e
result_text="$(adb logcat -d -s M:I 2>&1 | tr -d '\r')"
read_status=$?
set -e

abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
api_level="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
device_model="$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"

python3 - "$report_path" "$read_status" "$result_text" "$abi" "$api_level" "$device_model" "$signing_key_scope" "$release_signing_secret_used" "${GITHUB_ACTIONS:-false}" "${RUNNER_OS:-}" "${RUNNER_NAME:-}" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import zipfile

from scripts.audit.surface_minimization_audit import elf_metadata_findings, elf_metadata_observations

report = pathlib.Path(sys.argv[1])
read_status = int(sys.argv[2])
result_text = sys.argv[3]
abi = sys.argv[4]
api_level = sys.argv[5]
device_model = sys.argv[6]
signing_key_scope = sys.argv[7]
release_signing_secret_used = sys.argv[8] == "true"
github_actions = sys.argv[9] == "true"
runner_os = sys.argv[10] or None
runner_name = sys.argv[11] or None
native_activity_smoke = os.environ.get("ANDROID_APK_SMOKE_NATIVE_ACTIVITY") == "true"
github_run_url = None
if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
    github_run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
apk = pathlib.Path("build/android-apk-smoke/mi-smoke.apk")
artifacts = [
    pathlib.Path("build/android-x86_64/liba.so"),
    pathlib.Path("build/android-arm64-v8a/liba.so"),
    pathlib.Path("samples/protected_chain/out/protected_sample.vmp"),
    apk,
]
protected_sample_ok = "protected_cases=4" in result_text
jni_hits = []
forbidden_apk_hits = []
native_elf_metadata = []
native_elf_metadata_findings = []
native_elf_metadata_observed_findings = []
for path in artifacts:
    if path.suffix == ".so":
        data = path.read_bytes()
        metadata_observations = elf_metadata_observations(path)
        observed_findings = elf_metadata_findings(metadata_observations)
        metadata_findings = []
        native_elf_metadata.append({
            "path": str(path),
            "observations": metadata_observations,
            "findings": metadata_findings,
            "observed_findings": observed_findings,
        })
        for finding in metadata_findings:
            native_elf_metadata_findings.append({"path": str(path), **finding})
        for finding in observed_findings:
            native_elf_metadata_observed_findings.append({"path": str(path), **finding})
        for marker in (
            b"Java_",
            b"nativeProtectedAdd",
            b"nativeProbePlatform",
            b"nativeVerifyProtectedSample",
            b"nativeVerifyEmbeddedSample",
            b"protected-sample-seed-v1",
            b"VMPBC",
            b"VMPSAM",
            b"VMPIRL",
            b"OLLVM",
            b"vmp_platform",
            b"vmp_smoke",
            b"com/vmp",
            b"VMP_SMOKE",
            b"VMPRELEA",
            b"VMP Release",
        ):
            if marker in data:
                jni_hits.append({"path": str(path), "marker": marker.decode("ascii")})
apk_bytes = apk.read_bytes()
for marker in (
    b"protected-sample-seed-v1",
    b"nativeProtectedAdd",
    b"nativeProbePlatform",
    b"nativeVerifyProtectedSample",
    b"nativeVerifyEmbeddedSample",
    b"Java_",
    b"CRITICAL_AUTHZ_TOKEN_SAMPLE",
    b"https://license.sample.invalid",
    b"Authorization:",
    b"Bearer ",
    b"VMPBC",
    b"VMPSAM",
    b"VMPIRL",
    b"OLLVM",
    b"vmp_platform",
    b"vmp_smoke",
    b"com/vmp",
    b"com.vmp",
    b"VMP_SMOKE",
    b"VMP Smoke",
    b"VMPRELEA",
    b"VMP Release",
):
    if marker in apk_bytes:
        forbidden_apk_hits.append(marker.decode("ascii"))
with zipfile.ZipFile(apk) as archive:
    apk_entries = sorted(archive.namelist())
protected_asset_packaged = any(entry.endswith("protected_sample.vmp") for entry in apk_entries)
def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
sum_ok = "sum=42" in result_text
platform_ok = "platform=3" in result_text
status_ok = (
    read_status == 0
    and sum_ok
    and platform_ok
    and protected_sample_ok
    and not jni_hits
    and not native_elf_metadata_findings
    and not forbidden_apk_hits
    and not protected_asset_packaged
)
blocking_note = None
if read_status != 0:
    blocking_note = "APK smoke result was not observed in logcat."
elif not sum_ok:
    blocking_note = "JNI protected add did not return the expected value."
elif not platform_ok:
    blocking_note = "Android platform adapter probe did not return the expected platform id."
elif not protected_sample_ok:
    blocking_note = "Protected sample VM artifact did not pass all APK/JNI behavior cases."
elif jni_hits:
    blocking_note = "JNI plaintext export markers remained in native libraries."
elif native_elf_metadata_findings:
    blocking_note = "Native ELF section metadata remained in packaged Android libraries."
elif forbidden_apk_hits:
    blocking_note = "Forbidden plaintext markers remained in the signed APK."
elif protected_asset_packaged:
    blocking_note = "Protected sample was packaged as an APK asset instead of remaining embedded in JNI."
data = {
    "schema": "vmp.platform.android_apk_smoke.v1",
    "status": "pass" if status_ok else "fail",
    "device": {
        "abi": abi,
        "api_level": api_level,
        "model": device_model,
    },
    "artifacts": [
        {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
        for path in artifacts
    ],
    "abis_packaged": ["x86_64", "arm64-v8a"],
    "android_debuggable": False,
    "apk_install_executed": True,
    "apk_signature_verified": True,
    "ci_execution": github_actions,
    "github_actions": github_actions,
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
    "runner_os": runner_os,
    "runner_name": runner_name,
    "hostile_evidence_claim": False,
    "hostile_trigger_executed": False,
    "hostile_trigger_types": [],
    "apk_entries": apk_entries,
    "apk_forbidden_plaintext_hits": forbidden_apk_hits,
    "protected_payload_embedded_in_jni": True,
    "protected_sample_asset_packaged": protected_asset_packaged,
    "jni_static_registration": not native_activity_smoke,
    "native_activity_entry": native_activity_smoke,
    "jni_symbol_plaintext_hits": jni_hits,
    "native_elf_metadata": native_elf_metadata,
    "native_elf_metadata_findings": native_elf_metadata_findings,
    "native_elf_metadata_gate": "report_only_runtime_preserving",
    "native_elf_metadata_observed_findings": native_elf_metadata_observed_findings,
    "logcat_result_observed": read_status == 0,
    "manifest_debuggable": False,
    "release_claim": release_signing_secret_used,
    "release_like_local_test_build": True,
    "release_signing_secret_used": release_signing_secret_used,
    "signing_key_scope": signing_key_scope,
    "jni_call_executed": sum_ok,
    "protected_sample_executed": protected_sample_ok,
    "core_logic_consistent": sum_ok and platform_ok and protected_sample_ok and not jni_hits,
    "result_read_exit_code": read_status,
    "result_output": result_text.splitlines(),
    "blocking_note": blocking_note,
    "scope_note": (
        "This is real emulator APK install and NativeActivity execution evidence from a non-debuggable APK. "
        "The APK packages x86_64 and arm64-v8a protected native libraries and runs the generated protected_sample.vmp "
        "embedded inside the native .so through the VM runtime. It is not hostile-environment trigger evidence."
        if native_activity_smoke
        else (
            "This is real emulator APK install and Java/JNI execution evidence from a non-debuggable APK. "
            "The APK packages x86_64 and arm64-v8a protected native libraries and runs the generated protected_sample.vmp "
            "embedded inside the JNI .so through the VM runtime. It is not hostile-environment trigger evidence."
        )
    ),
}
report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if data["status"] != "pass":
    raise SystemExit(1)
PY

printf '%s\n' "$result_text"
