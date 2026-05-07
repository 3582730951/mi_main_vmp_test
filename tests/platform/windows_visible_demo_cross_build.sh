#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build/windows-visible-demo}"
report_path="${2:-docs/qa/reports/windows-visible-demo-cross-build.json}"
cc="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
objdump="${MINGW_OBJDUMP:-x86_64-w64-mingw32-objdump}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "MinGW C++ compiler not found: $cc" >&2
  exit 40
fi
if ! command -v "$objdump" >/dev/null 2>&1; then
  echo "MinGW objdump not found: $objdump" >&2
  exit 41
fi

mkdir -p "$build_dir" "$(dirname "$report_path")"

bash tests/integration/run_protected_sample_chain.sh >/dev/null
sample_copy="$build_dir/protected_sample.vmp"
cp samples/protected_chain/out/protected_sample.vmp "$sample_copy"

python3 - "$sample_copy" "$build_dir/protected_sample_blob.h" <<'PY'
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

python3 - "$sample_copy" "$build_dir/protected_demo_text.h" <<'PY'
import hashlib
import pathlib
import struct
import sys

sample = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2])

PURPOSE_HASH = 0x04D6D739B676C5FF
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

def u64(offset):
    return struct.unpack_from("<Q", sample, offset)[0]

platform_salt = u64(28)
nonce = u64(36)
auth_tag = u64(44)
build_salt = int.from_bytes(hashlib.sha256(sample + b"vmp-visible-demo-text-v2").digest()[:8], "little")

def mix64(value):
    value = (value + 0x9E3779B97F4A7C15) & MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
    return (value ^ (value >> 31)) & MASK64

def stable_hash64(data, seed):
    h = seed & MASK64
    for b in data:
        h ^= b
        h = (h * 1099511628211) & MASK64
    return h

def rotl32(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & MASK32

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl32(s[b] ^ s[c], 7)

def lo(value):
    return value & MASK32

def hi(value):
    return (value >> 32) & MASK32

runtime_salt = mix64(build_salt ^ auth_tag ^ nonce ^ platform_salt ^ PURPOSE_HASH)

def block(nonce0, nonce1, counter):
    state = [
        0xA9F13D57, 0xC2E7B46B, 0x6D8A2F91, 0xB5C0E33D,
        lo(runtime_salt), hi(runtime_salt),
        lo(nonce0), hi(nonce0),
        lo(nonce1), hi(nonce1),
        lo(build_salt), hi(build_salt),
        counter & MASK32, (counter ^ 0x9E3779B9) & MASK32,
        lo(runtime_salt ^ nonce1), hi(runtime_salt ^ nonce0),
    ]
    working = state[:]
    for _ in range(10):
        qr(working, 0, 4, 8, 12)
        qr(working, 1, 5, 9, 13)
        qr(working, 2, 6, 10, 14)
        qr(working, 3, 7, 11, 15)
        qr(working, 0, 5, 10, 15)
        qr(working, 1, 6, 11, 12)
        qr(working, 2, 7, 8, 13)
        qr(working, 3, 4, 9, 14)
    words = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return b"".join(word.to_bytes(4, "little") for word in words)

messages = {
    "kMsgVisible": b"visible windows protected demo\n",
    "kMsgFunction": b"demo_function=authorized_sample_behavior(left, right)\n",
    "kMsgCase": b"case ",
    "kMsgLeft": b": left=",
    "kMsgRight": b" right=",
    "kMsgBaseline": b" baseline=",
    "kMsgProtected": b" protected=",
    "kMsgVmStatus": b" vm_status=",
    "kMsgMatch": b" match=",
    "kMsgNewline": b"\n",
    "kMsgArtifactBytes": b"artifact_embedded_bytes=",
    "kMsgGetcharPause": b"windows_getchar_pause=3\n",
    "kMsgOk": b"Ok",
    "kMsgFail": b"Fail",
    "kMsgYes": b"yes",
    "kMsgNo": b"no",
}

def encrypt(name, plain):
    digest = hashlib.sha256(sample + name.encode("ascii") + plain).digest()
    nonce0 = int.from_bytes(digest[:8], "little")
    nonce1 = int.from_bytes(digest[8:16], "little")
    cipher = bytearray()
    stream = b""
    for i, byte in enumerate(plain):
        if i % 64 == 0:
            stream = block(nonce0, nonce1, i // 64)
        cipher.append(byte ^ stream[i % 64])
    tag = stable_hash64(plain, runtime_salt ^ nonce0 ^ nonce1)
    return nonce0, nonce1, tag, bytes(cipher)

def hex_array(data):
    return ", ".join(f"0x{b:02x}" for b in data)

lines = [
    "#pragma once",
    "#include <cstddef>",
    "#include <cstdint>",
    "",
    "struct DemoTextBlob {",
    "  const std::uint8_t *data;",
    "  std::size_t size;",
    "  std::uint64_t nonce0;",
    "  std::uint64_t nonce1;",
    "  std::uint64_t tag;",
    "};",
    "",
    f"constexpr std::uint64_t kDemoTextBuildSalt = 0x{build_salt:016x}ULL;",
]
for name, plain in messages.items():
    nonce0, nonce1, tag, cipher = encrypt(name, plain)
    lines.append(f"constexpr std::uint8_t {name}Data[] = {{{hex_array(cipher)}}};")
    lines.append(
        f"constexpr DemoTextBlob {name} = {{{name}Data, sizeof({name}Data), "
        f"0x{nonce0:016x}ULL, 0x{nonce1:016x}ULL, 0x{tag:016x}ULL}};"
    )
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

exe="$build_dir/protected_visible_demo.exe"
"$cc" -std=c++17 -O2 -s -DVMP_VISIBLE_PROTECTED_DEMO=1 -DVMP_FREESTANDING_WINDOWS_ENTRY=1 \
  -fno-exceptions -fno-rtti -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -fvisibility=hidden -fdata-sections -ffunction-sections \
  -I "$build_dir" -I src \
  tools/vmp/protected_release_main.cpp \
  -nostdlib -nostartfiles -Wl,--gc-sections -Wl,-e,mainCRTStartup -lkernel32 \
  -o "$exe"

decoy_manifest="$build_dir/protected_visible_demo.decoy_sections.json"
python3 scripts/audit/add_pe_decoy_sections.py "$exe" --report "$decoy_manifest" >/dev/null
section_report="$build_dir/protected_visible_demo.sections.json"
python3 scripts/audit/scrub_pe_section_names.py "$exe" --report "$section_report" >/dev/null

"$objdump" -f "$exe" | grep -q 'pei-x86-64'
strings_path="$build_dir/protected_visible_demo.strings.txt"
strings -a "$exe" >"$strings_path"
if grep -E 'visible windows protected demo|parse_status=failed|demo_function=authorized_sample_behavior|case %u|windows_getchar_pause=3|CRITICAL_AUTHZ_TOKEN_SAMPLE|https://license\.sample\.invalid|Authorization:|Bearer |JNI_OnLoad|Java_|dlopen|dlsym|VMPBC|VMPSAM|VMPIRL|OLLVM|Mingw-w64 runtime failure|GCC: \\(GNU\\)|msvcrt\\.dll|printf|fprintf|vfprintf|getchar' "$strings_path"; then
  echo "Forbidden protected marker found in Windows visible demo PE artifact" >&2
  exit 42
fi

wine_tool=""
if command -v wine64 >/dev/null 2>&1; then
  wine_tool="$(command -v wine64)"
elif command -v wine >/dev/null 2>&1; then
  wine_tool="$(command -v wine)"
fi

output_path="$build_dir/protected_visible_demo.output.txt"
execution_status="skipped"
execution_note="Wine is not available in this Linux environment; the PE was cross-built and statically checked."
if [[ -n "$wine_tool" ]]; then
  printf '\n\n\n' | "$wine_tool" "$exe" >"$output_path"
  grep -q 'visible windows protected demo' "$output_path"
  grep -q 'case 1: left=7 right=11 baseline=23142 protected=23142 vm_status=Ok match=yes' "$output_path"
  grep -q 'case 4: left=4294967295 right=1437226410 baseline=2857764015 protected=2857764015 vm_status=Ok match=yes' "$output_path"
  grep -q 'windows_getchar_pause=3' "$output_path"
  execution_status="pass"
  execution_note="Executed through Wine with three newline bytes provided for the three getchar() calls."
fi

python3 - "$report_path" "$exe" "$sample_copy" "$output_path" "$execution_status" "$execution_note" "$section_report" "$decoy_manifest" <<'PY'
import json
import pathlib
import subprocess
import sys

report = pathlib.Path(sys.argv[1])
exe = pathlib.Path(sys.argv[2])
sample = pathlib.Path(sys.argv[3])
output = pathlib.Path(sys.argv[4])
execution_status = sys.argv[5]
execution_note = sys.argv[6]
section_report = json.loads(pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"))
decoy_manifest = json.loads(pathlib.Path(sys.argv[8]).read_text(encoding="utf-8"))
strings = subprocess.run(["strings", "-a", str(exe)], check=False, text=True, stdout=subprocess.PIPE)
forbidden = [
    "visible windows protected demo",
    "parse_status=failed",
    "demo_function=authorized_sample_behavior",
    "case %u",
    "windows_getchar_pause=3",
    "CRITICAL_AUTHZ_TOKEN_SAMPLE",
    "https://license.sample.invalid",
    "Authorization:",
    "Bearer ",
    "JNI_OnLoad",
    "Java_",
    "dlopen",
    "dlsym",
    "VMPBC",
    "VMPSAM",
    "VMPIRL",
    "OLLVM",
    "Mingw-w64 runtime failure",
    "GCC: (GNU)",
    "msvcrt.dll",
    "printf",
    "fprintf",
    "vfprintf",
    "getchar",
]
forbidden_hits = [needle for needle in forbidden if needle in strings.stdout]
report.write_text(json.dumps({
    "schema": "vmp.platform.windows_visible_demo_cross_build.v1",
    "status": "pass",
    "artifact": str(exe),
    "artifact_bytes": exe.stat().st_size,
    "embedded_sample": str(sample),
    "embedded_sample_bytes": sample.stat().st_size,
    "pe_format": "pei-x86-64",
    "visible_demo_strings_encrypted": True,
    "dynamic_string_protection": {
        "mode": "per_build_stream_cipher_chunked_runtime_decode",
        "ciphertext_generated_per_build": True,
        "chunked_runtime_decode": True,
        "full_plaintext_string_buffer": False,
        "two_pass_plaintext_tag_validation": True,
        "per_call_stateful_chunk_schedule": True,
        "chunk_plaintext_wiped_after_use": True,
        "max_plaintext_chunk_bytes": 20,
    },
    "windows_console_api_policy": {
        "mode": "minimal_fixed_kernel32_console_api",
        "direct_windows_syscalls_enabled": False,
        "generic_syscall_resolver_allowed": False,
        "fixed_imports": ["ExitProcess", "GetStdHandle", "ReadFile", "WriteFile"],
        "stdout_handle_cached": True,
        "stdin_handle_cached": True,
        "writefile_calls_batched": True,
        "reason": "The visible release must print and pause reliably; syscall-only Windows I/O is kept out of the accepted release gate under docs/SECURITY_POLICY.md.",
    },
    "decoy_sections": decoy_manifest,
    "section_names_randomized": section_report.get("randomized_nonprintable_section_names") is True,
    "section_name_seed_fingerprint": section_report.get("seed_fingerprint"),
    "section_name_hex": section_report.get("section_name_hex", []),
    "windows_getchar_calls": 3,
    "wine_execution_status": execution_status,
    "wine_execution_note": execution_note,
    "output": str(output) if output.exists() else None,
    "strings_count": len(strings.stdout.splitlines()),
    "forbidden_plaintext_hits": forbidden_hits,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat "$output_path" 2>/dev/null || true
echo "windows visible demo cross-build produced"
