#include "VMRuntime.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace vmp::runtime {
namespace {

bool validReg(std::uint8_t reg) {
    return reg < 16;
}

bool validStackAccess(const VMContext &ctx, std::uint64_t offset) {
    return offset <= ctx.stack.size() && (ctx.stack.size() - static_cast<std::size_t>(offset)) >= sizeof(std::uint64_t);
}

std::uint32_t low32(std::uint64_t value) {
    return static_cast<std::uint32_t>(value & 0xffffffffULL);
}

std::uint32_t shiftAmount32(std::uint64_t value) {
    return low32(value) & 31U;
}

std::uint32_t arithmeticShiftRight32(std::uint32_t value, std::uint32_t amount) {
    if (amount == 0) {
        return value;
    }
    const std::uint32_t shifted = value >> amount;
    if ((value & 0x80000000U) == 0) {
        return shifted;
    }
    return shifted | (~std::uint32_t{0} << (32U - amount));
}

std::uint64_t loadStack64(const VMContext &ctx, std::uint64_t offset) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(ctx.stack[static_cast<std::size_t>(offset) + i]) << (i * 8U);
    }
    return value;
}

void storeStack64(VMContext &ctx, std::uint64_t offset, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        ctx.stack[static_cast<std::size_t>(offset) + i] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
    }
}

} // namespace

namespace detail {

class ActiveChunkScope {
  public:
    ActiveChunkScope(VMContext &ctx, const core::BytecodeChunk &chunk)
        : ctx_(ctx), previous_(ctx.activeChunk_) {
        ctx_.activeChunk_ = &chunk;
    }

    ~ActiveChunkScope() {
        ctx_.activeChunk_ = previous_;
    }

    ActiveChunkScope(const ActiveChunkScope &) = delete;
    ActiveChunkScope &operator=(const ActiveChunkScope &) = delete;

  private:
    VMContext &ctx_;
    const core::BytecodeChunk *previous_;
};

} // namespace detail

VMStatus execute(VMContext &ctx, const std::vector<core::Instruction> &program) {
    ctx.halted = false;
    while (!ctx.halted) {
        if (ctx.pc >= program.size()) {
            return VMStatus::InvalidBranch;
        }
        const auto inst = program[static_cast<std::size_t>(ctx.pc)];
        ++ctx.pc;

        switch (inst.op) {
        case core::SemanticOpcode::Nop:
            break;
        case core::SemanticOpcode::LoadImm:
            if (!validReg(inst.dst)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = inst.imm;
            break;
        case core::SemanticOpcode::Mov:
            if (!validReg(inst.dst) || !validReg(inst.src0)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0];
            break;
        case core::SemanticOpcode::Load:
            if (!validReg(inst.dst)) {
                return VMStatus::InvalidRegister;
            }
            if (!validStackAccess(ctx, inst.imm)) {
                return VMStatus::StackOutOfBounds;
            }
            ctx.regs[inst.dst] = loadStack64(ctx, inst.imm);
            break;
        case core::SemanticOpcode::Store:
            if (!validReg(inst.src0)) {
                return VMStatus::InvalidRegister;
            }
            if (!validStackAccess(ctx, inst.imm)) {
                return VMStatus::StackOutOfBounds;
            }
            storeStack64(ctx, inst.imm, ctx.regs[inst.src0]);
            break;
        case core::SemanticOpcode::Add:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] + ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Sub:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] - ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Mul:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] * ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::And:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] & ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Or:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] | ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Xor:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.regs[inst.src0] ^ ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Shl:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = static_cast<std::uint32_t>(low32(ctx.regs[inst.src0]) << shiftAmount32(ctx.regs[inst.src1]));
            break;
        case core::SemanticOpcode::LShr:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = low32(ctx.regs[inst.src0]) >> shiftAmount32(ctx.regs[inst.src1]);
            break;
        case core::SemanticOpcode::AShr:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = arithmeticShiftRight32(low32(ctx.regs[inst.src0]), shiftAmount32(ctx.regs[inst.src1]));
            break;
        case core::SemanticOpcode::CmpEq:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = (ctx.regs[inst.src0] & 0xffffffffULL) == (ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpNe:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = (ctx.regs[inst.src0] & 0xffffffffULL) != (ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpSgt:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::int32_t>(ctx.regs[inst.src0] & 0xffffffffULL) >
                     static_cast<std::int32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpSge:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::int32_t>(ctx.regs[inst.src0] & 0xffffffffULL) >=
                     static_cast<std::int32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpSle:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::int32_t>(ctx.regs[inst.src0] & 0xffffffffULL) <=
                     static_cast<std::int32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpUgt:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::uint32_t>(ctx.regs[inst.src0] & 0xffffffffULL) >
                     static_cast<std::uint32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpUge:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::uint32_t>(ctx.regs[inst.src0] & 0xffffffffULL) >=
                     static_cast<std::uint32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::CmpUle:
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.zf = static_cast<std::uint32_t>(ctx.regs[inst.src0] & 0xffffffffULL) <=
                     static_cast<std::uint32_t>(ctx.regs[inst.src1] & 0xffffffffULL);
            break;
        case core::SemanticOpcode::Select:
            if (!validReg(inst.dst) || !validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            ctx.regs[inst.dst] = ctx.zf ? ctx.regs[inst.src0] : ctx.regs[inst.src1];
            break;
        case core::SemanticOpcode::Jump:
            if (inst.imm >= program.size()) {
                return VMStatus::InvalidBranch;
            }
            ctx.pc = inst.imm;
            break;
        case core::SemanticOpcode::JumpIfZero:
            if (ctx.zf) {
                if (inst.imm >= program.size()) {
                    return VMStatus::InvalidBranch;
                }
                ctx.pc = inst.imm;
            }
            break;
        case core::SemanticOpcode::CallHost: {
            if (!validReg(inst.src0) || !validReg(inst.src1)) {
                return VMStatus::InvalidRegister;
            }
            const auto it = ctx.hostCalls.find(inst.dst);
            if (it == ctx.hostCalls.end()) {
                return VMStatus::MissingHostCall;
            }
            HostCall callback = it->second;
            const auto preservedRegs = ctx.regs;
            const auto preservedZf = ctx.zf;
            const auto preservedReturnValue = ctx.returnValue;
            const auto preservedStack = ctx.stack;
            const auto preservedHostCalls = ctx.hostCalls;
            ctx.regs[14] = ctx.regs[inst.src0];
            ctx.regs[15] = ctx.regs[inst.src1];
            const auto resumePc = ctx.pc;
            const auto resumeHalted = ctx.halted;
            VMPolicyHooks preservedHooks = ctx.hooks;
            std::uint64_t hostResult = 0;
            try {
                hostResult = callback(ctx, inst.dst);
            } catch (...) {
                ctx.regs = preservedRegs;
                ctx.zf = preservedZf;
                ctx.returnValue = preservedReturnValue;
                ctx.stack = preservedStack;
                ctx.hostCalls = preservedHostCalls;
                ctx.pc = resumePc;
                ctx.halted = resumeHalted;
                ctx.hooks = preservedHooks;
                return VMStatus::PolicyDenied;
            }
            ctx.regs = preservedRegs;
            ctx.zf = preservedZf;
            ctx.returnValue = preservedReturnValue;
            ctx.stack = preservedStack;
            ctx.hostCalls = preservedHostCalls;
            ctx.pc = resumePc;
            ctx.halted = resumeHalted;
            ctx.hooks = preservedHooks;
            ctx.regs[0] = hostResult;
            break;
        }
        case core::SemanticOpcode::CheckIntegrity:
            if (ctx.activeChunk() == nullptr || !ctx.hooks.validateIntegrity) {
                return VMStatus::IntegrityFailure;
            }
            try {
                if (!ctx.hooks.validateIntegrity(ctx, *ctx.activeChunk())) {
                    return VMStatus::IntegrityFailure;
                }
            } catch (...) {
                return VMStatus::IntegrityFailure;
            }
            break;
        case core::SemanticOpcode::Ret:
            if (!validReg(inst.src0)) {
                return VMStatus::InvalidRegister;
            }
            ctx.returnValue = ctx.regs[inst.src0];
            ctx.halted = true;
            break;
        case core::SemanticOpcode::Halt:
            ctx.halted = true;
            break;
        case core::SemanticOpcode::Count:
            return VMStatus::InvalidProgram;
        }
    }
    return VMStatus::Ok;
}

VMStatus executeEncryptedChunk(VMContext &ctx, const core::BytecodeChunk &chunk, const core::OpcodeMap &map,
                               std::string_view seed) {
    const detail::ActiveChunkScope activeChunk(ctx, chunk);
    if (ctx.hooks.authorizeChunk) {
        try {
            if (!ctx.hooks.authorizeChunk(chunk)) {
                return VMStatus::PolicyDenied;
            }
        } catch (...) {
            return VMStatus::PolicyDenied;
        }
    }
    if (chunk.vmLevel == 3) {
        if (!ctx.hooks.validateIntegrity) {
            return VMStatus::IntegrityFailure;
        }
        try {
            if (!ctx.hooks.validateIntegrity(ctx, chunk)) {
                return VMStatus::IntegrityFailure;
            }
        } catch (...) {
            return VMStatus::IntegrityFailure;
        }
    }

    const auto decrypted = core::decryptChunk(chunk, map, seed);
    if (!decrypted.ok) {
        if (chunk.vmLevel == 3) {
            return VMStatus::IntegrityFailure;
        }
        return VMStatus::DecodeFailure;
    }

    ctx.pc = 0;
    ctx.halted = false;
    if (ctx.hooks.beforeDispatch) {
        try {
            ctx.hooks.beforeDispatch(ctx);
        } catch (...) {
            return VMStatus::PolicyDenied;
        }
    }
    const VMStatus status = execute(ctx, decrypted.instructions);
    if (ctx.hooks.afterDispatch) {
        try {
            ctx.hooks.afterDispatch(ctx, status);
        } catch (...) {
            return VMStatus::PolicyDenied;
        }
    }
    return status;
}

const char *statusName(VMStatus status) {
    switch (status) {
    case VMStatus::Ok:
        return "Ok";
    case VMStatus::InvalidProgram:
        return "InvalidProgram";
    case VMStatus::InvalidRegister:
        return "InvalidRegister";
    case VMStatus::StackOutOfBounds:
        return "StackOutOfBounds";
    case VMStatus::InvalidBranch:
        return "InvalidBranch";
    case VMStatus::MissingHostCall:
        return "MissingHostCall";
    case VMStatus::PolicyDenied:
        return "PolicyDenied";
    case VMStatus::IntegrityFailure:
        return "IntegrityFailure";
    case VMStatus::DecodeFailure:
        return "DecodeFailure";
    }
    return "Unknown";
}

} // namespace vmp::runtime

namespace {

void ensureReadable(std::size_t offset, std::size_t count, std::size_t totalSize, const char *what) {
    if (offset > totalSize || count > (totalSize - offset)) {
        throw std::runtime_error(what);
    }
}

std::uint32_t readU32(const std::uint8_t *bytes, std::size_t &offset, std::size_t totalSize) {
    ensureReadable(offset, 4, totalSize, "truncated runtime artifact u32");
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(bytes[offset++]) << (index * 8U);
    }
    return value;
}

std::uint64_t readU64(const std::uint8_t *bytes, std::size_t &offset, std::size_t totalSize) {
    ensureReadable(offset, 8, totalSize, "truncated runtime artifact u64");
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(bytes[offset++]) << (index * 8U);
    }
    return value;
}

struct RuntimeArtifact {
    vmp::core::OpcodeMap map;
    vmp::core::BytecodeChunk chunk;
    std::string seedMaterial;
};

RuntimeArtifact parseRuntimeArtifact(const std::uint8_t *bytes, std::size_t bytecodeSize) {
    if (bytes == nullptr) {
        throw std::runtime_error("null runtime artifact");
    }
    if (bytecodeSize < 12U) {
        throw std::runtime_error("runtime artifact is too short");
    }

    const std::array<std::uint8_t, 8> expected{'V', 'M', 'P', 'I', 'R', 'L', '4', '\0'};
    for (std::size_t index = 0; index < expected.size(); ++index) {
        if (bytes[index] != expected[index]) {
            throw std::runtime_error("invalid runtime artifact magic");
        }
    }

    std::size_t offset = expected.size();
    RuntimeArtifact artifact;
    const auto totalSize = readU32(bytes, offset, bytecodeSize);
    if (totalSize != bytecodeSize) {
        throw std::runtime_error("runtime artifact size mismatch");
    }
    if (totalSize < expected.size() + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 4 + artifact.map.encode.size() + 4 ||
        totalSize > 8192U) {
        throw std::runtime_error("invalid runtime artifact size");
    }
    artifact.chunk.version = readU32(bytes, offset, totalSize);
    artifact.chunk.vmLevel = readU32(bytes, offset, totalSize);
    artifact.chunk.functionHash = readU64(bytes, offset, totalSize);
    artifact.chunk.platformSalt = readU64(bytes, offset, totalSize);
    artifact.chunk.nonce = readU64(bytes, offset, totalSize);
    artifact.chunk.authTag = readU64(bytes, offset, totalSize);
    artifact.seedMaterial = std::to_string(readU64(bytes, offset, totalSize));

    const auto opcodeCount = readU32(bytes, offset, totalSize);
    if (opcodeCount != artifact.map.encode.size()) {
        throw std::runtime_error("unexpected opcode map size");
    }
    for (std::size_t index = 0; index < artifact.map.encode.size(); ++index) {
        ensureReadable(offset, 1, totalSize, "truncated runtime artifact opcode map");
        const std::uint8_t byte = bytes[offset++];
        if (byte == 0 || artifact.map.decode[byte].has_value()) {
            throw std::runtime_error("invalid runtime artifact opcode map");
        }
        artifact.map.encode[index] = byte;
        artifact.map.decode[byte] = static_cast<vmp::core::SemanticOpcode>(index);
        artifact.map.handlerOrder.push_back(static_cast<vmp::core::SemanticOpcode>(index));
    }

    const auto payloadSize = readU32(bytes, offset, totalSize);
    if (payloadSize > 4096U) {
        throw std::runtime_error("runtime artifact payload is too large");
    }
    if (offset + payloadSize != totalSize) {
        throw std::runtime_error("unexpected runtime artifact payload length");
    }
    artifact.chunk.encryptedPayload.assign(bytes + offset, bytes + offset + payloadSize);
    return artifact;
}

std::int32_t executeRuntimeEntry(const std::uint8_t *bytecode,
                                 std::uint64_t bytecodeSize,
                                 std::int32_t arg0,
                                 std::int32_t arg1,
                                 std::int32_t arg2,
                                 std::int32_t arg3,
                                 unsigned argCount) {
    try {
        const RuntimeArtifact artifact = parseRuntimeArtifact(bytecode, static_cast<std::size_t>(bytecodeSize));
        vmp::runtime::VMContext ctx;
        ctx.stack.resize(256);
        if (argCount >= 1U) {
            ctx.regs[1] = static_cast<std::uint32_t>(arg0);
        }
        if (argCount >= 2U) {
            ctx.regs[2] = static_cast<std::uint32_t>(arg1);
        }
        if (argCount >= 3U) {
            ctx.regs[3] = static_cast<std::uint32_t>(arg2);
        }
        if (argCount >= 4U) {
            ctx.regs[4] = static_cast<std::uint32_t>(arg3);
        }
        ctx.hostCalls[1] = [](vmp::runtime::VMContext &ctx, std::uint8_t) {
            const auto lhs = static_cast<std::uint32_t>(ctx.regs[14] & 0xffffffffULL);
            const auto rhs = static_cast<std::uint32_t>(ctx.regs[15] & 0xffffffffULL);
            return static_cast<std::uint32_t>(lhs + rhs);
        };
        ctx.hooks.authorizeChunk = [](const vmp::core::BytecodeChunk &chunk) {
            return chunk.magic == "VMPBC1" && chunk.encryptedPayload.size() <= 4096;
        };
        ctx.hooks.validateIntegrity = [](const vmp::runtime::VMContext &ctx,
                                         const vmp::core::BytecodeChunk &chunk) {
            return ctx.activeChunk() == &chunk && chunk.magic == "VMPBC1" && chunk.authTag != 0 &&
                   !chunk.encryptedPayload.empty();
        };
        const auto status = vmp::runtime::executeEncryptedChunk(ctx, artifact.chunk, artifact.map, artifact.seedMaterial);
        if (status != vmp::runtime::VMStatus::Ok) {
            return -2147483647;
        }
        return static_cast<std::int32_t>(ctx.returnValue & 0xffffffffULL);
    } catch (...) {
        return -2147483646;
    }
}

} // namespace

extern "C" std::int32_t vmp_runtime_entry_i32(const std::uint8_t *bytecode,
                                               std::uint64_t bytecodeSize) {
    return executeRuntimeEntry(bytecode, bytecodeSize, 0, 0, 0, 0, 0);
}

extern "C" std::int32_t vmp_runtime_entry_i32_i32(const std::uint8_t *bytecode,
                                                   std::uint64_t bytecodeSize,
                                                   std::int32_t arg) {
    return executeRuntimeEntry(bytecode, bytecodeSize, arg, 0, 0, 0, 1);
}

extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32(const std::uint8_t *bytecode,
                                                       std::uint64_t bytecodeSize,
                                                       std::int32_t arg0,
                                                       std::int32_t arg1) {
    return executeRuntimeEntry(bytecode, bytecodeSize, arg0, arg1, 0, 0, 2);
}

extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32_i32(const std::uint8_t *bytecode,
                                                           std::uint64_t bytecodeSize,
                                                           std::int32_t arg0,
                                                           std::int32_t arg1,
                                                           std::int32_t arg2) {
    return executeRuntimeEntry(bytecode, bytecodeSize, arg0, arg1, arg2, 0, 3);
}

extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32_i32_i32(const std::uint8_t *bytecode,
                                                               std::uint64_t bytecodeSize,
                                                               std::int32_t arg0,
                                                               std::int32_t arg1,
                                                               std::int32_t arg2,
                                                               std::int32_t arg3) {
    return executeRuntimeEntry(bytecode, bytecodeSize, arg0, arg1, arg2, arg3, 4);
}
