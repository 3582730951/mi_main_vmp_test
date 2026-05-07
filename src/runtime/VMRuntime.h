#pragma once

#include "../core/Bytecode.h"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vmp::runtime {

namespace detail {
class ActiveChunkScope;
}

enum class VMStatus {
    Ok,
    InvalidProgram,
    InvalidRegister,
    StackOutOfBounds,
    InvalidBranch,
    MissingHostCall,
    PolicyDenied,
    IntegrityFailure,
    DecodeFailure
};

struct VMContext;
using HostCall = std::function<std::uint64_t(VMContext &, std::uint8_t)>;

struct VMPolicyHooks {
    std::function<bool(const core::BytecodeChunk &)> authorizeChunk;
    std::function<void(const VMContext &)> beforeDispatch;
    std::function<void(const VMContext &, VMStatus)> afterDispatch;
    std::function<bool(const VMContext &, const core::BytecodeChunk &)> validateIntegrity;
};

struct VMContext {
    VMContext() = default;

    VMContext(const VMContext &other) {
        copyFrom(other);
    }

    VMContext &operator=(const VMContext &other) {
        if (this != &other) {
            copyFrom(other);
        }
        return *this;
    }

    VMContext(VMContext &&other) {
        moveFrom(std::move(other));
    }

    VMContext &operator=(VMContext &&other) {
        if (this != &other) {
            moveFrom(std::move(other));
        }
        return *this;
    }

    std::array<std::uint64_t, 16> regs{};
    std::uint64_t pc = 0;
    bool zf = false;
    std::uint64_t returnValue = 0;
    bool halted = false;
    std::vector<std::uint8_t> stack;
    std::unordered_map<std::uint8_t, HostCall> hostCalls;
    VMPolicyHooks hooks;
    const core::BytecodeChunk *activeChunk() const {
        return activeChunk_;
    }

  private:
    friend class detail::ActiveChunkScope;
    const core::BytecodeChunk *activeChunk_ = nullptr;

    void copyFrom(const VMContext &other) {
        regs = other.regs;
        pc = other.pc;
        zf = other.zf;
        returnValue = other.returnValue;
        halted = other.halted;
        stack = other.stack;
        hostCalls = other.hostCalls;
        hooks = other.hooks;
        activeChunk_ = nullptr;
    }

    void moveFrom(VMContext &&other) {
        regs = std::move(other.regs);
        pc = other.pc;
        zf = other.zf;
        returnValue = other.returnValue;
        halted = other.halted;
        stack = std::move(other.stack);
        hostCalls = std::move(other.hostCalls);
        hooks = std::move(other.hooks);
        activeChunk_ = nullptr;
    }
};

VMStatus execute(VMContext &ctx, const std::vector<core::Instruction> &program);
VMStatus executeEncryptedChunk(VMContext &ctx, const core::BytecodeChunk &chunk, const core::OpcodeMap &map,
                               std::string_view seed);
const char *statusName(VMStatus status);

} // namespace vmp::runtime

extern "C" std::int32_t vmp_runtime_entry_i32(const std::uint8_t *bytecode,
                                               std::uint64_t bytecodeSize);
extern "C" std::int32_t vmp_runtime_entry_i32_i32(const std::uint8_t *bytecode,
                                                   std::uint64_t bytecodeSize,
                                                   std::int32_t arg);
extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32(const std::uint8_t *bytecode,
                                                       std::uint64_t bytecodeSize,
                                                       std::int32_t arg0,
                                                       std::int32_t arg1);
extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32_i32(const std::uint8_t *bytecode,
                                                           std::uint64_t bytecodeSize,
                                                           std::int32_t arg0,
                                                           std::int32_t arg1,
                                                           std::int32_t arg2);
extern "C" std::int32_t vmp_runtime_entry_i32_i32_i32_i32_i32(const std::uint8_t *bytecode,
                                                               std::uint64_t bytecodeSize,
                                                               std::int32_t arg0,
                                                               std::int32_t arg1,
                                                               std::int32_t arg2,
                                                               std::int32_t arg3);

extern "C" std::int64_t vmp_runtime_entry_i64(const std::uint8_t *bytecode,
                                               std::uint64_t bytecodeSize);
extern "C" std::int64_t vmp_runtime_entry_i64_i64(const std::uint8_t *bytecode,
                                                   std::uint64_t bytecodeSize,
                                                   std::int64_t arg);
extern "C" std::int64_t vmp_runtime_entry_i64_i64_i64(const std::uint8_t *bytecode,
                                                       std::uint64_t bytecodeSize,
                                                       std::int64_t arg0,
                                                       std::int64_t arg1);
extern "C" std::int64_t vmp_runtime_entry_i64_i64_i64_i64(const std::uint8_t *bytecode,
                                                           std::uint64_t bytecodeSize,
                                                           std::int64_t arg0,
                                                           std::int64_t arg1,
                                                           std::int64_t arg2);
extern "C" std::int64_t vmp_runtime_entry_i64_i64_i64_i64_i64(const std::uint8_t *bytecode,
                                                               std::uint64_t bytecodeSize,
                                                               std::int64_t arg0,
                                                               std::int64_t arg1,
                                                               std::int64_t arg2,
                                                               std::int64_t arg3);
