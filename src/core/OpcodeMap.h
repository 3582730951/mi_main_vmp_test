#pragma once

#include "Deterministic.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace vmp::core {

enum class SemanticOpcode : std::uint8_t {
    Nop = 0,
    LoadImm,
    Mov,
    Load,
    Store,
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    CmpEq,
    CmpNe,
    CmpSgt,
    Select,
    Jump,
    JumpIfZero,
    CallHost,
    CheckIntegrity,
    Ret,
    Halt,
    CmpSge,
    CmpSle,
    CmpUgt,
    CmpUge,
    CmpUle,
    Shl,
    LShr,
    AShr,
    Count
};

struct OpcodeMap {
    std::array<std::uint8_t, static_cast<std::size_t>(SemanticOpcode::Count)> encode{};
    std::array<std::optional<SemanticOpcode>, 256> decode{};
    std::vector<SemanticOpcode> handlerOrder;

    std::uint8_t byteFor(SemanticOpcode semantic) const;
    std::optional<SemanticOpcode> semanticFor(std::uint8_t byte) const;
    std::uint64_t fingerprint() const;
};

OpcodeMap buildOpcodeMap(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                         std::uint32_t vmLevel);

} // namespace vmp::core
