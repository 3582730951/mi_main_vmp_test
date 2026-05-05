#include "../../src/core/IRLoweringSkeleton.h"
#include "../../src/core/ProtectionConfig.h"
#include "../../src/runtime/NestedVM.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace vmp;

void require(bool condition, const std::string &message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<core::Instruction> addProgram(std::uint64_t a, std::uint64_t b) {
    return {
        {core::SemanticOpcode::LoadImm, 1, 0, 0, a},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, b},
        {core::SemanticOpcode::Add, 0, 1, 2, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
    };
}

std::vector<core::Instruction> integrityProgram(std::uint64_t value) {
    return {
        {core::SemanticOpcode::LoadImm, 0, 0, 0, value},
        {core::SemanticOpcode::CheckIntegrity, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
    };
}

std::vector<core::Instruction> hostThenIntegrityProgram() {
    return {
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 20},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 22},
        {core::SemanticOpcode::CallHost, 7, 1, 2, 0},
        {core::SemanticOpcode::CheckIntegrity, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
    };
}

std::vector<core::Instruction> hostBranchIntegrityProgram() {
    return {
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 20},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 22},
        {core::SemanticOpcode::CallHost, 7, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 5},
        {core::SemanticOpcode::CheckIntegrity, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
    };
}

void testConfigParser() {
    const auto config = core::parseProtectionConfigText(R"cfg(
profile: hardened
seed: "unit-seed"
vm_level: 2
anti_debug: true
ollvm:
  block_split: 2
  flatten: 1
  bogus_branch: 1
  instruction_substitution: 3
  const_string_encryption: true
functions:
  - name: add_secret
    vm_level: 3
    protect: true
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
)cfg");

    require(config.profile == "hardened", "profile parse failed");
    require(config.seed == "unit-seed", "seed parse failed");
    require(config.vmLevel == 2, "vm_level parse failed");
    require(config.antiDebugHooks, "anti_debug parse failed");
    require(config.antiAnalysis.debug, "anti_analysis debug mirror failed");
    require(config.ollvm.instructionSubstitution == 3, "ollvm parse failed");
    const auto fn = config.findFunction("add_secret");
    require(fn.has_value(), "function selector missing");
    require(fn->vmLevel == 3, "function vm_level parse failed");
    require(fn->explicitVmLevel, "function explicit vm_level marker missing");
    require(config.hotspot.enabled, "hotspot policy parse failed");
    require(config.hotspot.callSiteThreshold == 2, "hotspot threshold parse failed");
    require(config.hotspot.hotVmLevel == 1, "hotspot vm_level parse failed");
    require(config.callsiteObfuscation.enabled, "callsite obfuscation parse failed");
    require(config.callsiteObfuscation.hashResolver, "callsite hash resolver parse failed");
    require(config.callsiteObfuscation.perCallsiteThunks, "callsite per-site thunk parse failed");
    require(config.callsiteObfuscation.hideExports, "callsite export hiding parse failed");
    require(config.decompilerTraps.enabled && config.decompilerTraps.intensity == 2, "decompiler trap parse failed");
    require(config.stackBacktrace.randomized && config.stackBacktrace.maxFrames == 8, "stack backtrace parse failed");

    const auto explicitVm1 = core::parseProtectionConfigText(R"cfg(
profile: hardened
seed: "unit-seed"
vm_level: 3
functions:
  - name: low_level_secret
    vm_level: 1
)cfg");
    const auto lowLevel = explicitVm1.findFunction("low_level_secret");
    require(lowLevel.has_value(), "explicit function vm_level selector missing");
    require(lowLevel->vmLevel == 1, "explicit function vm_level=1 must not inherit top-level vm_level");
}

void testConfigParserAcceptsFrozenProtectSpec() {
    const auto config = core::parseProtectionConfigFile(std::filesystem::path("examples/protect.sample.yml"));
    require(config.version == 1, "version parse failed");
    require(config.profile == "hardened", "spec profile parse failed");
    require(config.seed == "demo-seed-001", "spec seed parse failed");
    require(config.antiDebugHooks, "target anti_analysis debug parse failed");
    require(config.antiAnalysis.hardwareBreakpoints, "target anti_analysis hardware breakpoint parse failed");
    require(config.antiAnalysis.memoryBreakpoints, "target anti_analysis memory breakpoint parse failed");
    require(config.antiAnalysis.injection, "target anti_analysis injection parse failed");
    require(config.antiAnalysis.hooks, "target anti_analysis hooks parse failed");
    require(config.antiAnalysis.rootOrJailbreak == "platform", "target anti_analysis root policy parse failed");
    const auto byReportName = config.findFunction("license_core");
    require(byReportName.has_value(), "target name missing");
    require(byReportName->match == "function:license_check", "target match parse failed");
    const auto byFunctionName = config.findFunction("license_check");
    require(byFunctionName.has_value(), "target function selector missing");
    require(byFunctionName->vmLevel == 3, "target vm_level parse failed");
    require(config.ollvm.blockSplit == 1, "target split parse failed");
    require(config.ollvm.instructionSubstitution == 1, "target substitution parse failed");
    require(config.hotspot.enabled && config.hotspot.callSiteThreshold == 3, "spec hotspot parse failed");
    require(config.callsiteObfuscation.enabled && config.callsiteObfuscation.hashResolver &&
                config.callsiteObfuscation.perCallsiteThunks,
            "spec callsite parse failed");
    require(config.decompilerTraps.enabled, "spec decompiler trap parse failed");
    require(config.stackBacktrace.randomized && config.stackBacktrace.maxFrames == 16, "spec stack backtrace parse failed");
}

void testConfigValidationRejectsUnsafeValues() {
    bool rejectedProfile = false;
    try {
        (void)core::parseProtectionConfigText(R"cfg(
profile: fastest
seed: "unit-seed"
functions:
  - name: add_secret
)cfg");
    } catch (const std::invalid_argument &) {
        rejectedProfile = true;
    }
    require(rejectedProfile, "invalid profile should be rejected");

    bool rejectedRootPolicy = false;
    try {
        (void)core::parseProtectionConfigText(R"cfg(
profile: hardened
seed: "unit-seed"
targets:
  - name: add_secret
    anti_analysis:
      root_or_jailbreak: bypass
)cfg");
    } catch (const std::invalid_argument &) {
        rejectedRootPolicy = true;
    }
    require(rejectedRootPolicy, "invalid root_or_jailbreak policy should be rejected");

    bool rejectedWeakHotspot = false;
    try {
        (void)core::parseProtectionConfigText(R"cfg(
profile: hardened
seed: "unit-seed"
hotspot_analysis:
  enabled: true
  hot_vm_level: 1
  defense_floor: 2
)cfg");
    } catch (const std::invalid_argument &) {
        rejectedWeakHotspot = true;
    }
    require(rejectedWeakHotspot, "hotspot policy must not weaken below defense floor");
}

void testOpcodeDeterminism() {
    const auto hash = core::stableHash64("fn");
    const auto a = core::buildOpcodeMap("seed-a", hash, 0x1234, 2);
    const auto b = core::buildOpcodeMap("seed-a", hash, 0x1234, 2);
    const auto c = core::buildOpcodeMap("seed-b", hash, 0x1234, 2);
    require(a.encode == b.encode, "same seed should reproduce opcode map");
    require(a.encode != c.encode, "different seed should change opcode map");
    require(a.byteFor(core::SemanticOpcode::LoadImm) != 0, "opcode zero is reserved");
}

void testChunkEncryptionAndTamperFailure() {
    const auto hash = core::stableHash64("add_secret");
    const auto map = core::buildOpcodeMap("unit-seed", hash, 0x42, 2);
    const auto chunk = core::encryptChunk(addProgram(7, 9), map, "unit-seed", hash, 0x42, 2);
    const auto plain = core::serializeInstructions(addProgram(7, 9), map);

    require(chunk.encryptedPayload != plain, "encrypted payload must differ from plaintext serialization");
    const auto decrypted = core::decryptChunk(chunk, map, "unit-seed");
    require(decrypted.ok, "decrypt should succeed");
    require(decrypted.instructions.size() == 4, "instruction count mismatch");

    auto tampered = chunk;
    tampered.encryptedPayload.at(0) ^= 0x55;
    const auto rejected = core::decryptChunk(tampered, map, "unit-seed");
    require(!rejected.ok, "tampered bytecode must fail authentication");

    auto tamperedMap = map;
    std::swap(tamperedMap.encode[static_cast<std::size_t>(core::SemanticOpcode::LoadImm)],
              tamperedMap.encode[static_cast<std::size_t>(core::SemanticOpcode::Add)]);
    const auto rejectedMap = core::decryptChunk(chunk, tamperedMap, "unit-seed");
    require(!rejectedMap.ok, "tampered opcode map must fail authentication");
}

void testDispatcherAndNestedPolicy() {
    auto lowered = core::lowerAuthorizedFunctionSkeleton("add_secret", addProgram(11, 31), "unit-seed", 0x7777, 3);
    runtime::VMContext ctx;
    bool authorized = false;
    bool integrity = false;
    bool after = false;
    ctx.hooks.authorizeChunk = [&](const core::BytecodeChunk &chunk) {
        authorized = true;
        return chunk.functionHash == lowered.report.functionHash;
    };
    ctx.hooks.validateIntegrity = [&](const runtime::VMContext &, const core::BytecodeChunk &chunk) {
        integrity = true;
        return chunk.authTag != 0;
    };
    ctx.hooks.afterDispatch = [&](const runtime::VMContext &, runtime::VMStatus status) {
        after = status == runtime::VMStatus::Ok;
    };

    const auto result = runtime::executeWithNestedPolicy(ctx, lowered.chunk, lowered.opcodeMap, "unit-seed");
    require(result.status == runtime::VMStatus::Ok, std::string("vm failed: ") + runtime::statusName(result.status));
    require(result.returnValue == 42, "VM return mismatch");
    require(result.vm0Used && result.vm2Used, "nested policy flags incorrect");
    require(authorized && integrity && after, "policy hooks were not invoked");
}

void testNestedPolicyMatrix() {
    for (std::uint32_t level = 1; level <= 3; ++level) {
        auto lowered = core::lowerAuthorizedFunctionSkeleton("add_secret", addProgram(20, 22), "matrix-seed", 0x8888, level);
        runtime::VMContext ctx;
        ctx.hooks.authorizeChunk = [&](const core::BytecodeChunk &chunk) {
            return chunk.functionHash == lowered.report.functionHash;
        };
        ctx.hooks.validateIntegrity = [](const runtime::VMContext &, const core::BytecodeChunk &chunk) {
            return chunk.authTag != 0;
        };

        const auto result = runtime::executeWithNestedPolicy(ctx, lowered.chunk, lowered.opcodeMap, "matrix-seed");
        require(result.status == runtime::VMStatus::Ok, "nested matrix VM failed");
        require(result.returnValue == 42, "nested matrix return mismatch");
        require(result.vm0Used == (level >= 2), "VM0 nesting flag mismatch");
        require(result.vm2Used == (level >= 3), "VM2 nesting flag mismatch");
    }
}

void requireNestedVM2TamperRejected(const core::BytecodeChunk &chunk,
                                    const core::OpcodeMap &map,
                                    const std::string &seed,
                                    const std::string &caseName) {
    runtime::VMContext ctx;
    ctx.returnValue = 0xdeadbeefULL;
    bool beforeDispatch = false;
    bool afterDispatch = false;
    ctx.hooks.authorizeChunk = [](const core::BytecodeChunk &) {
        return true;
    };
    ctx.hooks.validateIntegrity = [](const runtime::VMContext &, const core::BytecodeChunk &) {
        return true;
    };
    ctx.hooks.beforeDispatch = [&](const runtime::VMContext &) {
        beforeDispatch = true;
    };
    ctx.hooks.afterDispatch = [&](const runtime::VMContext &, runtime::VMStatus) {
        afterDispatch = true;
    };

    const auto result = runtime::executeWithNestedPolicy(ctx, chunk, map, seed);
    require(result.status == runtime::VMStatus::IntegrityFailure,
            "VM2 tamper should be integrity failure: " + caseName);
    require(result.vm2Used, "VM2 tamper should route through VM2: " + caseName);
    require(!beforeDispatch && !afterDispatch, "VM2 tamper must fail before dispatch hooks: " + caseName);
    require(result.returnValue == 0, "VM2 tamper result must not leak stale return value: " + caseName);
}

void testNestedVM2TamperRejected() {
    auto lowered = core::lowerAuthorizedFunctionSkeleton("add_secret", addProgram(11, 31), "tamper-seed", 0x9999, 3);

    auto tamperedPayload = lowered.chunk;
    tamperedPayload.encryptedPayload.at(0) ^= 0x55;
    requireNestedVM2TamperRejected(tamperedPayload, lowered.opcodeMap, "tamper-seed", "payload");

    auto tamperedFunctionHash = lowered.chunk;
    tamperedFunctionHash.functionHash ^= 0x101;
    requireNestedVM2TamperRejected(tamperedFunctionHash, lowered.opcodeMap, "tamper-seed", "function_hash");

    auto tamperedNonce = lowered.chunk;
    tamperedNonce.nonce ^= 0x202;
    requireNestedVM2TamperRejected(tamperedNonce, lowered.opcodeMap, "tamper-seed", "nonce");

    auto tamperedAuthTag = lowered.chunk;
    tamperedAuthTag.authTag ^= 0x303;
    requireNestedVM2TamperRejected(tamperedAuthTag, lowered.opcodeMap, "tamper-seed", "auth_tag");

    auto tamperedMap = lowered.opcodeMap;
    std::swap(tamperedMap.encode[static_cast<std::size_t>(core::SemanticOpcode::LoadImm)],
              tamperedMap.encode[static_cast<std::size_t>(core::SemanticOpcode::Add)]);
    requireNestedVM2TamperRejected(lowered.chunk, tamperedMap, "tamper-seed", "opcode_map");
}

void testCheckIntegrityOpcodeHooks() {
    const auto functionHash = core::stableHash64("integrity_check");
    const auto platformSalt = 0x6161ULL;
    const auto map = core::buildOpcodeMap("integrity-seed", functionHash, platformSalt, 2);
    const auto chunk = core::encryptChunk(integrityProgram(42), map, "integrity-seed", functionHash, platformSalt, 2);

    runtime::VMContext ctx;
    runtime::VMContext copiedDuringDispatch;
    unsigned integrityChecks = 0;
    bool beforeSawActiveChunk = false;
    bool afterSawActiveChunk = false;
    ctx.hooks.validateIntegrity = [&](const runtime::VMContext &hookCtx, const core::BytecodeChunk &hookChunk) {
        ++integrityChecks;
        return hookCtx.activeChunk() == &chunk && &hookChunk == &chunk && hookChunk.authTag == chunk.authTag;
    };
    ctx.hooks.beforeDispatch = [&](const runtime::VMContext &hookCtx) {
        copiedDuringDispatch = hookCtx;
        beforeSawActiveChunk = hookCtx.activeChunk() == &chunk && hookCtx.pc == 0;
    };
    ctx.hooks.afterDispatch = [&](const runtime::VMContext &hookCtx, runtime::VMStatus hookStatus) {
        afterSawActiveChunk = hookCtx.activeChunk() == &chunk && hookStatus == runtime::VMStatus::Ok;
    };
    const auto status = runtime::executeEncryptedChunk(ctx, chunk, map, "integrity-seed");
    require(status == runtime::VMStatus::Ok, "CheckIntegrity opcode should pass when hook approves active chunk");
    require(ctx.returnValue == 42, "CheckIntegrity opcode should continue execution after hook approval");
    require(integrityChecks == 1, "CheckIntegrity opcode hook count mismatch");
    require(beforeSawActiveChunk && afterSawActiveChunk, "dispatch hooks should observe active chunk");
    require(ctx.activeChunk() == nullptr, "active chunk should be restored after successful dispatch");

    bool copiedHookCalled = false;
    copiedDuringDispatch.hooks.validateIntegrity = [&](const runtime::VMContext &, const core::BytecodeChunk &) {
        copiedHookCalled = true;
        return true;
    };
    copiedDuringDispatch.pc = 0;
    copiedDuringDispatch.halted = false;
    const auto copiedDirectStatus = runtime::execute(copiedDuringDispatch, integrityProgram(5));
    require(copiedDirectStatus == runtime::VMStatus::IntegrityFailure,
            "copied context must not retain active chunk after dispatch hook copy");
    require(!copiedHookCalled, "copied context must not invoke integrity hook without active chunk");

    runtime::VMContext noHookCtx;
    const auto noHookStatus = runtime::executeEncryptedChunk(noHookCtx, chunk, map, "integrity-seed");
    require(noHookStatus == runtime::VMStatus::IntegrityFailure,
            "CheckIntegrity opcode should fail closed when active chunk has no integrity hook");
    require(noHookCtx.activeChunk() == nullptr, "active chunk should be restored after no-hook failure");

    runtime::VMContext deniedCtx;
    unsigned deniedChecks = 0;
    bool allowDeniedContext = false;
    deniedCtx.hooks.validateIntegrity = [&](const runtime::VMContext &hookCtx, const core::BytecodeChunk &hookChunk) {
        ++deniedChecks;
        return hookCtx.activeChunk() == &chunk && &hookChunk == &chunk && allowDeniedContext;
    };
    const auto deniedStatus = runtime::executeEncryptedChunk(deniedCtx, chunk, map, "integrity-seed");
    require(deniedStatus == runtime::VMStatus::IntegrityFailure,
            "CheckIntegrity opcode should fail closed when hook denies active chunk");
    require(deniedChecks == 1, "denied CheckIntegrity opcode hook count mismatch");
    require(deniedCtx.returnValue == 0, "denied CheckIntegrity opcode must not reach return");
    require(deniedCtx.activeChunk() == nullptr, "active chunk should be restored after failed dispatch");

    allowDeniedContext = true;
    const auto retryStatus = runtime::executeEncryptedChunk(deniedCtx, chunk, map, "integrity-seed");
    require(retryStatus == runtime::VMStatus::Ok, "retry should restart VM1 dispatch instead of skipping CheckIntegrity");
    require(deniedChecks == 2, "retry should invoke CheckIntegrity hook again");
    require(deniedCtx.returnValue == 42, "retry should complete after hook approval");

    const auto vm3Map = core::buildOpcodeMap("integrity-seed", functionHash, platformSalt, 3);
    const auto vm3Chunk = core::encryptChunk(integrityProgram(9), vm3Map, "integrity-seed", functionHash, platformSalt, 3);
    runtime::VMContext vm3NoHookCtx;
    bool vm3BeforeDispatch = false;
    vm3NoHookCtx.hooks.beforeDispatch = [&](const runtime::VMContext &) {
        vm3BeforeDispatch = true;
    };
    const auto vm3NoHookStatus = runtime::executeEncryptedChunk(vm3NoHookCtx, vm3Chunk, vm3Map, "integrity-seed");
    require(vm3NoHookStatus == runtime::VMStatus::IntegrityFailure,
            "vm_level 3 chunk should fail closed without an integrity hook");
    require(!vm3BeforeDispatch, "vm_level 3 no-hook failure must happen before dispatch");
    require(vm3NoHookCtx.activeChunk() == nullptr, "active chunk should be restored after vm_level 3 no-hook failure");

    runtime::VMContext vm3Ctx;
    unsigned vm3Checks = 0;
    vm3Ctx.hooks.validateIntegrity = [&](const runtime::VMContext &hookCtx, const core::BytecodeChunk &hookChunk) {
        ++vm3Checks;
        return hookCtx.activeChunk() == &vm3Chunk && &hookChunk == &vm3Chunk && hookChunk.authTag == vm3Chunk.authTag;
    };
    const auto vm3Status = runtime::executeEncryptedChunk(vm3Ctx, vm3Chunk, vm3Map, "integrity-seed");
    require(vm3Status == runtime::VMStatus::Ok, "vm_level 3 CheckIntegrity should pass when hook sees active chunk");
    require(vm3Checks == 2, "vm_level 3 should run pre-dispatch and opcode integrity checks");
    require(vm3Ctx.returnValue == 9, "vm_level 3 CheckIntegrity return mismatch");

    runtime::VMContext throwingCtx;
    throwingCtx.hooks.validateIntegrity = [](const runtime::VMContext &, const core::BytecodeChunk &) -> bool {
        throw std::runtime_error("integrity hook failed");
    };
    const auto throwingStatus = runtime::executeEncryptedChunk(throwingCtx, chunk, map, "integrity-seed");
    require(throwingStatus == runtime::VMStatus::IntegrityFailure,
            "throwing CheckIntegrity hook should fail closed as integrity failure");
    require(throwingCtx.activeChunk() == nullptr, "active chunk should be restored after throwing hook failure");

    const auto hostTamperChunk =
        core::encryptChunk(hostThenIntegrityProgram(), map, "integrity-seed", functionHash, platformSalt, 2);
    runtime::VMContext hostTamperCtx;
    bool originalIntegrityHookCalled = false;
    hostTamperCtx.hooks.validateIntegrity = [&](const runtime::VMContext &, const core::BytecodeChunk &) {
        originalIntegrityHookCalled = true;
        return false;
    };
    hostTamperCtx.hostCalls[7] = [](runtime::VMContext &hostCtx, std::uint8_t) {
        hostCtx.pc = 4;
        hostCtx.halted = true;
        hostCtx.hooks.validateIntegrity = [](const runtime::VMContext &, const core::BytecodeChunk &) {
            return true;
        };
        return static_cast<std::uint64_t>(42);
    };
    const auto hostTamperStatus = runtime::executeEncryptedChunk(hostTamperCtx, hostTamperChunk, map, "integrity-seed");
    require(hostTamperStatus == runtime::VMStatus::IntegrityFailure,
            "host call must not bypass CheckIntegrity by changing pc or hooks");
    require(originalIntegrityHookCalled, "host call tamper should still reach original CheckIntegrity hook");
    require(hostTamperCtx.returnValue == 0, "host call tamper must not reach return");
    require(hostTamperCtx.activeChunk() == nullptr, "active chunk should be restored after host tamper failure");

    const auto hostBranchChunk =
        core::encryptChunk(hostBranchIntegrityProgram(), map, "integrity-seed", functionHash, platformSalt, 2);
    runtime::VMContext hostBranchCtx;
    bool branchIntegrityHookCalled = false;
    hostBranchCtx.hooks.validateIntegrity = [&](const runtime::VMContext &, const core::BytecodeChunk &) {
        branchIntegrityHookCalled = true;
        return false;
    };
    hostBranchCtx.hostCalls[7] = [](runtime::VMContext &hostCtx, std::uint8_t) {
        hostCtx.zf = true;
        hostCtx.regs[1] = 0;
        hostCtx.stack.push_back(0xff);
        return static_cast<std::uint64_t>(42);
    };
    const auto hostBranchStatus = runtime::executeEncryptedChunk(hostBranchCtx, hostBranchChunk, map, "integrity-seed");
    require(hostBranchStatus == runtime::VMStatus::IntegrityFailure,
            "host call must not bypass CheckIntegrity through zf/register/stack tampering");
    require(branchIntegrityHookCalled, "host branch tamper should still reach original CheckIntegrity hook");
    require(hostBranchCtx.returnValue == 0, "host branch tamper must not reach return");

    runtime::VMContext directCtx;
    bool directHookCalled = false;
    directCtx.hooks.validateIntegrity = [&](const runtime::VMContext &, const core::BytecodeChunk &) {
        directHookCalled = true;
        return true;
    };
    const auto directStatus = runtime::execute(directCtx, integrityProgram(7));
    require(directStatus == runtime::VMStatus::IntegrityFailure,
            "direct CheckIntegrity opcode execution should fail without an active chunk");
    require(!directHookCalled, "direct CheckIntegrity opcode should not invoke hook without active chunk");
}

void testLoadStoreInstructions() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 0x1122334455667788ULL},
        {core::SemanticOpcode::Store, 0, 3, 0, 8},
        {core::SemanticOpcode::Load, 4, 0, 0, 8},
        {core::SemanticOpcode::Ret, 0, 4, 0, 0},
    };
    runtime::VMContext ctx;
    ctx.stack.resize(32);

    const auto status = runtime::execute(ctx, program);

    require(status == runtime::VMStatus::Ok, "stack load/store failed");
    require(ctx.returnValue == 0x1122334455667788ULL, "stack load/store value mismatch");

    runtime::VMContext shortStack;
    shortStack.stack.resize(4);
    const auto bounds = runtime::execute(shortStack, program);
    require(bounds == runtime::VMStatus::StackOutOfBounds, "stack bounds check failed");
}

void testArithmeticInstructions() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 9},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 4},
        {core::SemanticOpcode::Sub, 3, 1, 2, 0},
        {core::SemanticOpcode::Mul, 4, 3, 2, 0},
        {core::SemanticOpcode::Ret, 0, 4, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "arithmetic sub/mul failed");
    require(ctx.returnValue == 20, "arithmetic sub/mul value mismatch");
}

void testBitwiseInstructions() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0xf0},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 0x3c},
        {core::SemanticOpcode::And, 3, 1, 2, 0},
        {core::SemanticOpcode::LoadImm, 4, 0, 0, 0x22},
        {core::SemanticOpcode::Or, 5, 3, 4, 0},
        {core::SemanticOpcode::Ret, 0, 5, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "bitwise and/or failed");
    require(ctx.returnValue == 0x32, "bitwise and/or value mismatch");
}

void testShiftInstructions() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0x40000000ULL},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 2},
        {core::SemanticOpcode::Shl, 3, 1, 2, 0},
        {core::SemanticOpcode::LoadImm, 4, 0, 0, 0xfffffff0ULL},
        {core::SemanticOpcode::LoadImm, 5, 0, 0, 4},
        {core::SemanticOpcode::LShr, 6, 4, 5, 0},
        {core::SemanticOpcode::AShr, 7, 4, 2, 0},
        {core::SemanticOpcode::Add, 8, 3, 6, 0},
        {core::SemanticOpcode::Add, 9, 8, 7, 0},
        {core::SemanticOpcode::Ret, 0, 9, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "shift instruction program failed");
    require(static_cast<std::uint32_t>(ctx.regs[3]) == 0, "left shift must wrap to low32");
    require(ctx.regs[6] == 0x0fffffffULL, "logical right shift value mismatch");
    require(static_cast<std::uint32_t>(ctx.regs[7]) == 0xfffffffcULL, "arithmetic right shift value mismatch");
    require(static_cast<std::uint32_t>(ctx.returnValue) == 0x0ffffffbU, "combined shift return mismatch");

    const auto map = core::buildOpcodeMap("shift-seed", core::stableHash64("shift"), 0x5151, 2);
    const auto chunk = core::encryptChunk(program, map, "shift-seed", core::stableHash64("shift"), 0x5151, 2);
    runtime::VMContext encryptedCtx;
    const auto encryptedStatus = runtime::executeEncryptedChunk(encryptedCtx, chunk, map, "shift-seed");
    require(encryptedStatus == runtime::VMStatus::Ok, "encrypted shift bytecode round-trip failed");
    require(static_cast<std::uint32_t>(encryptedCtx.returnValue) == 0x0ffffffbU,
            "encrypted shift bytecode return mismatch");
}

void testHostCallBridge() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 20},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 22},
        {core::SemanticOpcode::CallHost, 7, 1, 2, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
    };
    runtime::VMContext ctx;
    ctx.hostCalls[7] = [](runtime::VMContext &ctx, std::uint8_t id) {
        require(id == 7, "host call id mismatch");
        require(ctx.regs[14] == 20, "host call first argument mismatch");
        require(ctx.regs[15] == 22, "host call second argument mismatch");
        return static_cast<std::uint64_t>(42);
    };
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "host call bridge failed");
    require(ctx.regs[0] == 42, "host call r0 result mismatch");
    require(ctx.returnValue == 42, "host call return mismatch");

    const auto preservedProgram = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 10},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 7},
        {core::SemanticOpcode::CallHost, 7, 1, 2, 0},
        {core::SemanticOpcode::Mov, 3, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 4, 0, 0, 3},
        {core::SemanticOpcode::CallHost, 7, 1, 4, 0},
        {core::SemanticOpcode::Add, 5, 3, 0, 0},
        {core::SemanticOpcode::Ret, 0, 5, 0, 0},
    };
    runtime::VMContext preservedCtx;
    preservedCtx.hostCalls[7] = [](runtime::VMContext &ctx, std::uint8_t) {
        const auto lhs = static_cast<std::uint32_t>(ctx.regs[14] & 0xffffffffULL);
        const auto rhs = static_cast<std::uint32_t>(ctx.regs[15] & 0xffffffffULL);
        return static_cast<std::uint32_t>(lhs + rhs);
    };
    const auto preservedStatus = runtime::execute(preservedCtx, preservedProgram);
    require(preservedStatus == runtime::VMStatus::Ok, "preserved host call bridge failed");
    require(preservedCtx.returnValue == 30, "preserved host call result mismatch");
}

void testSelectInstruction() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 12},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 10},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 100},
        {core::SemanticOpcode::LoadImm, 4, 0, 0, 200},
        {core::SemanticOpcode::CmpSgt, 0, 1, 2, 0},
        {core::SemanticOpcode::Select, 5, 3, 4, 0},
        {core::SemanticOpcode::Ret, 0, 5, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "select instruction failed");
    require(ctx.returnValue == 100, "select instruction value mismatch");
}

void testSignedGreaterThanComparison() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 12},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 10},
        {core::SemanticOpcode::CmpSgt, 0, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
        {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
        {core::SemanticOpcode::Ret, 0, 3, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "signed greater-than branch failed");
    require(ctx.returnValue == 1, "signed greater-than return mismatch");

    const auto low32SignedProgram = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 0xffffffffULL},
        {core::SemanticOpcode::CmpSgt, 0, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
        {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
        {core::SemanticOpcode::Ret, 0, 3, 0, 0},
    };
    runtime::VMContext low32SignedCtx;
    const auto low32SignedStatus = runtime::execute(low32SignedCtx, low32SignedProgram);
    require(low32SignedStatus == runtime::VMStatus::Ok, "signed low32 greater-than branch failed");
    require(low32SignedCtx.returnValue == 1, "signed low32 greater-than return mismatch");
}

void testSignedInclusiveComparisons() {
    const auto returnsOneWhenTrue = [](core::SemanticOpcode op, std::uint64_t lhs, std::uint64_t rhs) {
        const auto program = std::vector<core::Instruction>{
            {core::SemanticOpcode::LoadImm, 1, 0, 0, lhs},
            {core::SemanticOpcode::LoadImm, 2, 0, 0, rhs},
            {op, 0, 1, 2, 0},
            {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
            {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
            {core::SemanticOpcode::Ret, 0, 0, 0, 0},
            {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
            {core::SemanticOpcode::Ret, 0, 3, 0, 0},
        };
        runtime::VMContext ctx;
        const auto status = runtime::execute(ctx, program);
        require(status == runtime::VMStatus::Ok, "signed inclusive comparison branch failed");
        return ctx.returnValue;
    };

    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSge, 0xffffffffULL, 0xffffffffULL) == 1,
            "signed greater-or-equal equality mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSge, 0xffffffffULL, 0) == 0,
            "signed greater-or-equal false mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSge, 0x7fffffffULL, 0x80000000ULL) == 1,
            "signed greater-or-equal intmax/intmin mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSle, 0xffffffffULL, 0xffffffffULL) == 1,
            "signed less-or-equal equality mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSle, 0xffffffffULL, 0) == 1,
            "signed less-or-equal true mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSle, 1, 0) == 0,
            "signed less-or-equal false mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpSle, 0x80000000ULL, 0x7fffffffULL) == 1,
            "signed less-or-equal intmin/intmax mismatch");
}

void testUnsignedComparisons() {
    const auto returnsOneWhenTrue = [](core::SemanticOpcode op, std::uint64_t lhs, std::uint64_t rhs) {
        const auto program = std::vector<core::Instruction>{
            {core::SemanticOpcode::LoadImm, 1, 0, 0, lhs},
            {core::SemanticOpcode::LoadImm, 2, 0, 0, rhs},
            {op, 0, 1, 2, 0},
            {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
            {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
            {core::SemanticOpcode::Ret, 0, 0, 0, 0},
            {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
            {core::SemanticOpcode::Ret, 0, 3, 0, 0},
        };
        runtime::VMContext ctx;
        const auto status = runtime::execute(ctx, program);
        require(status == runtime::VMStatus::Ok, "unsigned comparison branch failed");
        return ctx.returnValue;
    };

    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUgt, 0xffffffffULL, 0) == 1,
            "unsigned greater-than max/zero mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUgt, 0xffffffffULL, 0xffffffffULL) == 0,
            "unsigned greater-than equality mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUgt, 0, 0xffffffffULL) == 0,
            "unsigned greater-than false mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUge, 0xffffffffULL, 0xffffffffULL) == 1,
            "unsigned greater-or-equal equality mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUge, 0xffffffffULL, 0) == 1,
            "unsigned greater-or-equal max/zero mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUge, 0, 1) == 0,
            "unsigned greater-or-equal false mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUge, 0x100000000ULL, 0) == 1,
            "unsigned greater-or-equal must compare low32 equality");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUle, 0xffffffffULL, 0xffffffffULL) == 1,
            "unsigned less-or-equal equality mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUle, 0, 0xffffffffULL) == 1,
            "unsigned less-or-equal zero/max mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUle, 0xffffffffULL, 0) == 0,
            "unsigned less-or-equal false mismatch");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUle, 0x100000000ULL, 0) == 1,
            "unsigned less-or-equal must compare low32 equality");
    require(returnsOneWhenTrue(core::SemanticOpcode::CmpUgt, 0x100000000ULL, 0xffffffffULL) == 0,
            "unsigned greater-than must compare low32 values");
}

void testLow32EqualityComparison() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0x100000000ULL},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 0},
        {core::SemanticOpcode::CmpEq, 0, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
        {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
        {core::SemanticOpcode::Ret, 0, 3, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "low32 equality branch failed");
    require(ctx.returnValue == 1, "low32 equality return mismatch");
}

void testLow32NotEqualComparison() {
    const auto program = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0x100000001ULL},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 0},
        {core::SemanticOpcode::CmpNe, 0, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
        {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
        {core::SemanticOpcode::Ret, 0, 3, 0, 0},
    };
    runtime::VMContext ctx;
    const auto status = runtime::execute(ctx, program);
    require(status == runtime::VMStatus::Ok, "low32 not-equal branch failed");
    require(ctx.returnValue == 1, "low32 not-equal return mismatch");

    const auto falseProgram = std::vector<core::Instruction>{
        {core::SemanticOpcode::LoadImm, 1, 0, 0, 0x100000000ULL},
        {core::SemanticOpcode::LoadImm, 2, 0, 0, 0},
        {core::SemanticOpcode::CmpNe, 0, 1, 2, 0},
        {core::SemanticOpcode::JumpIfZero, 0, 0, 0, 6},
        {core::SemanticOpcode::LoadImm, 0, 0, 0, 0},
        {core::SemanticOpcode::Ret, 0, 0, 0, 0},
        {core::SemanticOpcode::LoadImm, 3, 0, 0, 1},
        {core::SemanticOpcode::Ret, 0, 3, 0, 0},
    };
    runtime::VMContext falseCtx;
    const auto falseStatus = runtime::execute(falseCtx, falseProgram);
    require(falseStatus == runtime::VMStatus::Ok, "low32 not-equal false branch failed");
    require(falseCtx.returnValue == 0, "low32 not-equal false return mismatch");
}

} // namespace

int main() {
    try {
        testConfigParser();
        testConfigParserAcceptsFrozenProtectSpec();
        testConfigValidationRejectsUnsafeValues();
        testOpcodeDeterminism();
        testChunkEncryptionAndTamperFailure();
        testDispatcherAndNestedPolicy();
        testNestedPolicyMatrix();
        testNestedVM2TamperRejected();
        testCheckIntegrityOpcodeHooks();
        testLoadStoreInstructions();
        testArithmeticInstructions();
        testBitwiseInstructions();
        testShiftInstructions();
        testHostCallBridge();
        testSelectInstruction();
        testSignedGreaterThanComparison();
        testSignedInclusiveComparisons();
        testUnsignedComparisons();
        testLow32EqualityComparison();
        testLow32NotEqualComparison();
    } catch (const std::exception &ex) {
        std::cerr << "core_tests failed: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "core_tests passed\n";
    return EXIT_SUCCESS;
}
