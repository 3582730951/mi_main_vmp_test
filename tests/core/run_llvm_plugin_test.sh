#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/core/.llvm-build"
OUT_DIR="${ROOT_DIR}/tests/core/.llvm-out"

mkdir -p "${BUILD_DIR}" "${OUT_DIR}"

cmake -S "${ROOT_DIR}/src/core" -B "${BUILD_DIR}" \
  -G Ninja \
  -DLLVM_DIR="$(llvm-config-14 --cmakedir)" \
  -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "${BUILD_DIR}" --target VMPPassPlugin --clean-first >/dev/null

PLUGIN="${BUILD_DIR}/VMPPassPlugin.so"
if [[ ! -f "${PLUGIN}" ]]; then
  echo "VMPPassPlugin.so was not produced" >&2
  exit 20
fi

PIPELINE="vmp-config-load,vmp-function-marker,vmp-hotspot-policy,vmp-ir-normalize,vmp-block-split,vmp-flatten,vmp-bogus-branch,vmp-instruction-substitution,vmp-const-string-encryption,vmp-ir-to-bytecode,vmp-opcode-randomize,vmp-bytecode-encrypt,vmp-nesting,vmp-anti-analysis-hooks,vmp-function-replacement,vmp-report"

opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="${PIPELINE}" \
  -S "${ROOT_DIR}/tests/core/fixtures/sample.ll" \
  -o "${OUT_DIR}/sample.protected.ll" \
  2>"${OUT_DIR}/plugin.log"

grep -Fxq 'VMPPassPlugin report: selected_functions=73 lowered_functions=56 replaced_functions=56 unsupported_functions=17 stages=16' "${OUT_DIR}/plugin.log"
sed -n 's/^VMPPassPlugin stage_manifest_json: //p' "${OUT_DIR}/plugin.log" >"${OUT_DIR}/vmp-stage-manifest.json"
python3 - "${OUT_DIR}/vmp-stage-manifest.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest["schema"] == "vmp.llvm.stage_manifest.v1"
pipeline = manifest["pipeline"]
assert pipeline["executed_count"] == 16
assert pipeline["implemented_count"] == 9
assert pipeline["placeholder_noop_count"] == 6
assert pipeline["report_only_count"] == 1
stages = {stage["name"]: stage for stage in manifest["stages"]}
for name in (
    "vmp-ir-normalize",
    "vmp-flatten",
    "vmp-const-string-encryption",
    "vmp-opcode-randomize",
    "vmp-bytecode-encrypt",
    "vmp-nesting",
):
    assert stages[name]["kind"] == "placeholder_noop"
    assert stages[name]["implemented"] is False
    assert stages[name]["capability_effects"] == []
assert stages["vmp-config-load"]["kind"] == "config"
assert stages["vmp-config-load"]["implemented"] is True
assert stages["vmp-hotspot-policy"]["implemented"] is True
assert "performance.hotspot_static_policy" in stages["vmp-hotspot-policy"]["capability_effects"]
assert stages["vmp-anti-analysis-hooks"]["implemented"] is True
assert "anti_analysis.decompiler_traps" in stages["vmp-anti-analysis-hooks"]["capability_effects"]
assert stages["vmp-ir-to-bytecode"]["implemented"] is True
assert "code_virtualization.bytecode_lowering" in stages["vmp-ir-to-bytecode"]["capability_effects"]
assert "callsite_obfuscation.per_callsite_thunks" in stages["vmp-function-replacement"]["capability_effects"]
PY
FileCheck-14 --input-file="${OUT_DIR}/sample.protected.ll" "${ROOT_DIR}/tests/core/fixtures/sample-protected.check"
if grep -q '@vmp.bytecode.secret_side_effect' "${OUT_DIR}/sample.protected.ll"; then
  echo "side-effecting function was materialized as bytecode" >&2
  exit 22
fi
if grep -q '@vmp.bytecode.secret_dynamic_shift' "${OUT_DIR}/sample.protected.ll"; then
  echo "dynamic-shift function was materialized as bytecode" >&2
  exit 28
fi
if grep -q '@vmp.bytecode.secret_wide_shift' "${OUT_DIR}/sample.protected.ll"; then
  echo "wide-shift function was materialized as bytecode" >&2
  exit 30
fi
if grep -q '@vmp.bytecode.secret_nsw_add' "${OUT_DIR}/sample.protected.ll"; then
  echo "nsw-add function was materialized as bytecode" >&2
  exit 58
fi
if grep -q '@vmp.bytecode.secret_exact_lshr' "${OUT_DIR}/sample.protected.ll"; then
  echo "exact-lshr function was materialized as bytecode" >&2
  exit 59
fi
if grep -q '@vmp.bytecode.secret_local_uninit_branch' "${OUT_DIR}/sample.protected.ll"; then
  echo "uninitialized branched local-memory function was materialized as bytecode" >&2
  exit 24
fi
if grep -q '@vmp.bytecode.secret_load_before_branch' "${OUT_DIR}/sample.protected.ll"; then
  echo "load-before-branch local-memory function was materialized as bytecode" >&2
  exit 32
fi
if grep -q '@vmp.bytecode.secret_global_store' "${OUT_DIR}/sample.protected.ll"; then
  echo "global-store function was materialized as bytecode" >&2
  exit 26
fi
if grep -Eq '^define i32 @secret_stale_global.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "stale bytecode global bypassed current IR validation" >&2
  exit 38
fi
if grep -Eq '^define i32 @secret_stale_global.*!vmp\.bytecode' "${OUT_DIR}/sample.protected.ll"; then
  echo "unsupported stale-global function kept stale bytecode metadata" >&2
  exit 40
fi
if grep -Eq '^define i32 @secret_side_effect.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "side-effecting function was replaced instead of left native" >&2
  exit 23
fi
if grep -Eq '^define i32 @secret_local_uninit_branch.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "uninitialized branched local-memory function was replaced instead of left native" >&2
  exit 25
fi
if grep -Eq '^define i32 @secret_load_before_branch.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "load-before-branch local-memory function was replaced instead of left native" >&2
  exit 33
fi
if grep -Eq '^define i32 @secret_global_store.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "global-store function was replaced instead of left native" >&2
  exit 27
fi
if grep -Eq '^define i32 @secret_dynamic_shift.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "dynamic-shift function was replaced instead of left native" >&2
  exit 29
fi
if grep -Eq '^define i32 @secret_wide_shift.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "wide-shift function was replaced instead of left native" >&2
  exit 31
fi
if grep -Eq '^define i32 @secret_nsw_add.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "nsw-add function was replaced instead of left native" >&2
  exit 60
fi
if grep -Eq '^define i32 @secret_exact_lshr.*!vmp\.replaced' "${OUT_DIR}/sample.protected.ll"; then
  echo "exact-lshr function was replaced instead of left native" >&2
  exit 61
fi
for unsupported_target in \
  secret_dynamic_shift \
  secret_dynamic_lshr \
  secret_dynamic_ashr \
  secret_wide_shift \
  secret_wide_shl \
  secret_wide_ashr \
  secret_nsw_add \
  secret_nuw_sub \
  secret_nsw_mul \
  secret_nuw_shl \
  secret_exact_lshr \
  secret_exact_ashr \
  secret_local_uninit_branch \
  secret_load_before_branch \
  secret_global_store \
  secret_stale_global \
  secret_side_effect; do
  if grep -Eq "^define i32 @${unsupported_target}.*!vmp\\.bytecode" "${OUT_DIR}/sample.protected.ll"; then
    echo "unsupported function kept bytecode metadata: ${unsupported_target}" >&2
    exit 40
  fi
  if grep -Eq "^define i32 @${unsupported_target}.*!vmp\\.lowering" "${OUT_DIR}/sample.protected.ll"; then
    echo "unsupported function kept lowering metadata: ${unsupported_target}" >&2
    exit 55
  fi
  if grep -Eq "^define i32 @${unsupported_target}.*!vmp\\.replaced" "${OUT_DIR}/sample.protected.ll"; then
    echo "unsupported function kept replacement metadata: ${unsupported_target}" >&2
    exit 56
  fi
done
if grep -Eq '^define i32 @.*!vmp\.bytecode.*!vmp\.unsupported|^define i32 @.*!vmp\.unsupported.*!vmp\.bytecode' "${OUT_DIR}/sample.protected.ll"; then
  echo "lowered function kept unsupported metadata" >&2
  exit 57
fi
if grep -Eq '^define internal i32 @.*\.vmp\.outline.*!vmp\.(protect|bytecode|lowering|replaced|unsupported)' "${OUT_DIR}/sample.protected.ll"; then
  echo "outlined function kept protected-function metadata" >&2
  exit 21
fi
opt-14 -S -passes=verify "${OUT_DIR}/sample.protected.ll" -o /dev/null

opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="vmp-function-replacement,vmp-report" \
  -S "${ROOT_DIR}/tests/core/fixtures/replacement-stale-metadata.ll" \
  -o "${OUT_DIR}/replacement-stale-metadata.protected.ll" \
  2>"${OUT_DIR}/replacement-stale-metadata.log"
grep -Fxq 'VMPPassPlugin report: selected_functions=3 lowered_functions=1 replaced_functions=1 unsupported_functions=1 stages=2' "${OUT_DIR}/replacement-stale-metadata.log"
FileCheck-14 --check-prefix=STALE-MD --input-file="${OUT_DIR}/replacement-stale-metadata.protected.ll" "${ROOT_DIR}/tests/core/fixtures/replacement-stale-metadata.ll"
if grep -Fq '!{[8 x i8]* @vmp.bytecode.stale_metadata}' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement preserved stale bytecode metadata" >&2
  exit 39
fi
if grep -Eq '^define i32 @secret_stale_metadata_replacement.*!vmp\.unsupported' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement-only pass kept unsupported metadata on replaced IR" >&2
  exit 46
fi
if grep -Fq '@vmp.bytecode.secret_no_metadata_replacement' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement-only pass materialized orphan bytecode without source metadata" >&2
  exit 41
fi
if grep -Eq '^define i32 @secret_stale_metadata_unsupported.*!vmp\.bytecode' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement-only pass kept bytecode metadata on unsupported IR" >&2
  exit 42
fi
if grep -Eq '^define i32 @secret_stale_metadata_unsupported.*!vmp\.replaced' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement-only pass kept replaced metadata on unsupported IR" >&2
  exit 45
fi
if grep -Eq '^define internal i32 @.*\.vmp\.outline.*!vmp\.(protect|bytecode|lowering|replaced|unsupported)' "${OUT_DIR}/replacement-stale-metadata.protected.ll"; then
  echo "replacement-only outline kept protected-function metadata" >&2
  exit 50
fi
opt-14 -S -passes=verify "${OUT_DIR}/replacement-stale-metadata.protected.ll" -o /dev/null

opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="vmp-function-replacement,vmp-report" \
  -S "${ROOT_DIR}/tests/core/fixtures/outline-collision.ll" \
  -o "${OUT_DIR}/outline-collision.protected.ll" \
  2>"${OUT_DIR}/outline-collision.log"
grep -Fxq 'VMPPassPlugin report: selected_functions=2 lowered_functions=0 replaced_functions=0 unsupported_functions=2 stages=2' "${OUT_DIR}/outline-collision.log"
FileCheck-14 --check-prefix=OUTLINE-COLLISION --input-file="${OUT_DIR}/outline-collision.protected.ll" "${ROOT_DIR}/tests/core/fixtures/outline-collision.ll"
if grep -Eq '^define internal i32 @secret_outline_.*\.vmp\.outline.*!vmp\.(protect|bytecode|lowering|replaced|unsupported)' "${OUT_DIR}/outline-collision.protected.ll"; then
  echo "pre-existing outline collision kept stale VMP metadata" >&2
  exit 62
fi
if grep -Eq '^define i32 @secret_outline_.*!vmp\.(bytecode|lowering|replaced)' "${OUT_DIR}/outline-collision.protected.ll"; then
  echo "outline collision target kept replacement metadata" >&2
  exit 63
fi
opt-14 -S -passes=verify "${OUT_DIR}/outline-collision.protected.ll" -o /dev/null

opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="${PIPELINE}" \
  -S "${ROOT_DIR}/tests/core/fixtures/opaque-name-spoof.ll" \
  -o "${OUT_DIR}/opaque-name-spoof.protected.ll" \
  2>"${OUT_DIR}/opaque-name-spoof.log"
grep -Fxq 'VMPPassPlugin report: selected_functions=1 lowered_functions=0 replaced_functions=0 unsupported_functions=1 stages=16' "${OUT_DIR}/opaque-name-spoof.log"
FileCheck-14 --check-prefix=OPAQUE-SPOOF --input-file="${OUT_DIR}/opaque-name-spoof.protected.ll" "${ROOT_DIR}/tests/core/fixtures/opaque-name-spoof.ll"
if grep -Fq '@vmp.bytecode.secret_opaque_name_spoof' "${OUT_DIR}/opaque-name-spoof.protected.ll"; then
  echo "spoofed opaque-false branch was materialized as bytecode" >&2
  exit 43
fi
if grep -Eq '^define i32 @secret_opaque_name_spoof.*!vmp\.replaced' "${OUT_DIR}/opaque-name-spoof.protected.ll"; then
  echo "spoofed opaque-false branch was replaced instead of left native" >&2
  exit 44
fi
if grep -Eq '^define i32 @secret_opaque_name_spoof.*!vmp\.bytecode' "${OUT_DIR}/opaque-name-spoof.protected.ll"; then
  echo "spoofed opaque-false branch kept bytecode metadata" >&2
  exit 53
fi
opt-14 -S -passes=verify "${OUT_DIR}/opaque-name-spoof.protected.ll" -o /dev/null

opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="${PIPELINE}" \
  -S "${ROOT_DIR}/tests/core/fixtures/runtime-entry-collision.ll" \
  -o "${OUT_DIR}/runtime-entry-collision.protected.ll" \
  2>"${OUT_DIR}/runtime-entry-collision.log"
grep -Fxq 'VMPPassPlugin report: selected_functions=4 lowered_functions=0 replaced_functions=0 unsupported_functions=4 stages=16' "${OUT_DIR}/runtime-entry-collision.log"
FileCheck-14 --check-prefix=RUNTIME-COLLISION --input-file="${OUT_DIR}/runtime-entry-collision.protected.ll" "${ROOT_DIR}/tests/core/fixtures/runtime-entry-collision.ll"
if grep -Fq '@vmp.bytecode.secret_runtime_entry_body_collision' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry body collision was materialized as bytecode" >&2
  exit 47
fi
if grep -Fq '@vmp.bytecode.secret_runtime_entry_type_collision' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry type collision was materialized as bytecode" >&2
  exit 48
fi
if grep -Fq '@vmp.bytecode.secret_runtime_entry_attr_collision' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry attribute collision was materialized as bytecode" >&2
  exit 51
fi
if grep -Fq '@vmp.bytecode.secret_runtime_entry_cc_collision' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry calling-convention collision was materialized as bytecode" >&2
  exit 52
fi
if grep -Eq '^define i32 @secret_runtime_entry_.*!vmp\.replaced' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry collision target was replaced instead of left native" >&2
  exit 49
fi
if grep -Eq '^define i32 @secret_runtime_entry_.*!vmp\.bytecode' "${OUT_DIR}/runtime-entry-collision.protected.ll"; then
  echo "runtime-entry collision target kept bytecode metadata" >&2
  exit 54
fi
opt-14 -S -passes=verify "${OUT_DIR}/runtime-entry-collision.protected.ll" -o /dev/null

CONFIG_PIPELINE="vmp-config-load,vmp-function-marker,vmp-ir-to-bytecode,vmp-report"
cat >"${OUT_DIR}/config-seed-a.yml" <<'YAML'
profile: hardened
seed: "config-seed-a"
vm_level: 2
functions:
  - name: ordinary_add
    vm_level: 2
    protect: true
YAML
cat >"${OUT_DIR}/config-seed-b.yml" <<'YAML'
profile: hardened
seed: "config-seed-b"
vm_level: 2
functions:
  - name: ordinary_add
    vm_level: 2
    protect: true
YAML
cat >"${OUT_DIR}/config-vm1.yml" <<'YAML'
profile: hardened
seed: "config-same-seed"
vm_level: 3
functions:
  - name: ordinary_add
    vm_level: 1
    protect: true
YAML
cat >"${OUT_DIR}/config-vm3.yml" <<'YAML'
profile: hardened
seed: "config-same-seed"
vm_level: 1
functions:
  - name: ordinary_add
    vm_level: 3
    protect: true
YAML

run_config_case() {
  local name="$1"
  local config="$2"
  VMP_PROTECT_CONFIG="${config}" opt-14 \
    -load-pass-plugin "${PLUGIN}" \
    -passes="${CONFIG_PIPELINE}" \
    -S "${ROOT_DIR}/tests/core/fixtures/sample.ll" \
    -o "${OUT_DIR}/${name}.protected.ll" \
    2>"${OUT_DIR}/${name}.log"
  grep -Fxq 'VMPPassPlugin report: selected_functions=1 lowered_functions=1 replaced_functions=0 unsupported_functions=0 stages=4' "${OUT_DIR}/${name}.log"
  grep -Fq '@vmp.bytecode.ordinary_add = private unnamed_addr constant' "${OUT_DIR}/${name}.protected.ll"
  if grep -Eq 'config-seed-a|config-seed-b|config-same-seed' "${OUT_DIR}/${name}.log" ||
     grep -Eq 'config-seed-a|config-seed-b|config-same-seed' "${OUT_DIR}/${name}.protected.ll"; then
    echo "configured seed leaked into plugin output: ${name}" >&2
    exit 64
  fi
}

bytecode_global_hash() {
  python3 - "$1" <<'PY'
import hashlib
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"@vmp\.bytecode\.ordinary_add = private unnamed_addr constant \[[^\n]+", text)
if not match:
    raise SystemExit("missing ordinary_add bytecode global")
print(hashlib.sha256(match.group(0).encode("utf-8")).hexdigest())
PY
}

run_config_case "config-seed-a" "${OUT_DIR}/config-seed-a.yml"
run_config_case "config-seed-b" "${OUT_DIR}/config-seed-b.yml"
seed_a_fingerprint="$(sed -n 's/^VMPPassPlugin config: seed_fingerprint=\([0-9][0-9]*\).*$/\1/p' "${OUT_DIR}/config-seed-a.log")"
seed_b_fingerprint="$(sed -n 's/^VMPPassPlugin config: seed_fingerprint=\([0-9][0-9]*\).*$/\1/p' "${OUT_DIR}/config-seed-b.log")"
if [[ -z "${seed_a_fingerprint}" || -z "${seed_b_fingerprint}" || "${seed_a_fingerprint}" == "${seed_b_fingerprint}" ]]; then
  echo "configured seed fingerprints were not distinct" >&2
  exit 65
fi
if [[ "$(bytecode_global_hash "${OUT_DIR}/config-seed-a.protected.ll")" == "$(bytecode_global_hash "${OUT_DIR}/config-seed-b.protected.ll")" ]]; then
  echo "different configured seeds produced identical bytecode globals" >&2
  exit 66
fi

run_config_case "config-vm1" "${OUT_DIR}/config-vm1.yml"
run_config_case "config-vm3" "${OUT_DIR}/config-vm3.yml"
grep -Fq 'vm_levels=ordinary_add:1' "${OUT_DIR}/config-vm1.log"
grep -Fq 'vm_levels=ordinary_add:3' "${OUT_DIR}/config-vm3.log"
if [[ "$(bytecode_global_hash "${OUT_DIR}/config-vm1.protected.ll")" == "$(bytecode_global_hash "${OUT_DIR}/config-vm3.protected.ll")" ]]; then
  echo "different configured vm_level values produced identical bytecode globals" >&2
  exit 67
fi
opt-14 -S -passes=verify "${OUT_DIR}/config-vm1.protected.ll" -o /dev/null
opt-14 -S -passes=verify "${OUT_DIR}/config-vm3.protected.ll" -o /dev/null

cat >"${OUT_DIR}/hotspot-callsite.ll" <<'LLVM'
; ModuleID = 'hotspot-callsite'
source_filename = "hotspot-callsite.c"

define i32 @secret_hot(i32 %x) {
entry:
  %sum = add i32 %x, 7
  ret i32 %sum
}

define i32 @caller_a(i32 %x) {
entry:
  %first = call i32 @secret_hot(i32 %x)
  %second = call i32 @secret_hot(i32 %first)
  ret i32 %second
}

define i32 @caller_b(i32 %x) {
entry:
  %out = call i32 @secret_hot(i32 %x)
  ret i32 %out
}
LLVM
cat >"${OUT_DIR}/hotspot-callsite.yml" <<'YAML'
profile: hardened
seed: "hotspot-seed"
vm_level: 3
hotspot_analysis:
  enabled: true
  call_site_threshold: 2
  hot_vm_level: 1
  defense_floor: 1
callsite_obfuscation:
  enabled: true
  indirect_thunks: true
  hash_resolver: true
  jump_table: true
  per_callsite_thunks: true
  hide_exports: true
decompiler_traps:
  enabled: true
  intensity: 2
random_stack_backtrace:
  randomized: true
  min_interval_ms: 10
  jitter_ms: 30
  max_frames: 8
YAML
VMP_PROTECT_CONFIG="${OUT_DIR}/hotspot-callsite.yml" opt-14 \
  -load-pass-plugin "${PLUGIN}" \
  -passes="${PIPELINE}" \
  -S "${OUT_DIR}/hotspot-callsite.ll" \
  -o "${OUT_DIR}/hotspot-callsite.protected.ll" \
  2>"${OUT_DIR}/hotspot-callsite.log"
grep -Fxq 'VMPPassPlugin hotspot: function=secret_hot call_sites=3 vm_level=1' "${OUT_DIR}/hotspot-callsite.log"
grep -Fxq 'VMPPassPlugin callsite_obfuscation: rewritten_calls=3' "${OUT_DIR}/hotspot-callsite.log"
grep -Fxq 'VMPPassPlugin callsite_obfuscation: unique_thunks=3' "${OUT_DIR}/hotspot-callsite.log"
grep -Fxq 'VMPPassPlugin report: selected_functions=1 lowered_functions=1 replaced_functions=1 unsupported_functions=0 stages=16' "${OUT_DIR}/hotspot-callsite.log"
grep -Fq 'vm_levels=secret_hot:1' "${OUT_DIR}/hotspot-callsite.log"
grep -Eq '^define hidden i32 @secret_hot' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq '!vmp.hotspot' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq '!vmp.vm_level' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq '!vmp.decompiler.trap' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq 'vmp.decompiler.trap:' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq 'switch i32 0' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Eq 'define internal i32 @vmp\.call\.thunk\.[0-9a-f]{16}' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Eq 'define internal i8\* @vmp\.call\.resolve\.[0-9a-f]{16}' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Eq '@vmp\.call\.slot\.[0-9a-f]{16} = private unnamed_addr constant' "${OUT_DIR}/hotspot-callsite.protected.ll"
if [ "$(grep -Ec '^define internal i32 @vmp\.call\.thunk\.[0-9a-f]{16}' "${OUT_DIR}/hotspot-callsite.protected.ll")" -ne 3 ]; then
  echo "per-callsite thunk count mismatch" >&2
  exit 69
fi
if [ "$(grep -Ec '^define internal i8\* @vmp\.call\.resolve\.[0-9a-f]{16}' "${OUT_DIR}/hotspot-callsite.protected.ll")" -ne 3 ]; then
  echo "per-callsite resolver count mismatch" >&2
  exit 70
fi
if [ "$(grep -Ec '^@vmp\.call\.slot\.[0-9a-f]{16} = private unnamed_addr constant' "${OUT_DIR}/hotspot-callsite.protected.ll")" -ne 3 ]; then
  echo "per-callsite jump slot count mismatch" >&2
  exit 71
fi
grep -Eq 'call i32 @vmp_runtime_entry_i32_i32\(i8\* %vmp\.resolved\.i8, i64 [0-9]+, i32 %0\)' "${OUT_DIR}/hotspot-callsite.protected.ll"
grep -Fq '!vmp.anti_analysis.policy' "${OUT_DIR}/hotspot-callsite.protected.ll"
if grep -Eq 'call i32 @secret_hot' "${OUT_DIR}/hotspot-callsite.protected.ll"; then
  echo "direct protected callsite was not obfuscated" >&2
  exit 68
fi
if grep -Eq '(bitcast|ptrtoint) \(i32 \(i32\)\* @secret_hot|constant i32 \(i32\)\* @secret_hot' "${OUT_DIR}/hotspot-callsite.protected.ll"; then
  echo "protected function address leaked through callsite thunk materialization" >&2
  exit 72
fi
opt-14 -S -passes=verify "${OUT_DIR}/hotspot-callsite.protected.ll" -o /dev/null

clang++-14 -std=c++17 -O2 -I "${ROOT_DIR}/src" \
  "${OUT_DIR}/sample.protected.ll" \
  "${ROOT_DIR}/tests/core/fixtures/runtime_entry_smoke.cpp" \
  "${ROOT_DIR}/src/core/Deterministic.cpp" \
  "${ROOT_DIR}/src/core/OpcodeMap.cpp" \
  "${ROOT_DIR}/src/core/Bytecode.cpp" \
  "${ROOT_DIR}/src/runtime/VMRuntime.cpp" \
  -o "${OUT_DIR}/runtime_entry_smoke"
"${OUT_DIR}/runtime_entry_smoke" >/dev/null

echo "llvm plugin test passed"
