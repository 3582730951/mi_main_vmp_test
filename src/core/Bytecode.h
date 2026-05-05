#pragma once

#include "OpcodeMap.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vmp::core {

constexpr std::uint64_t kBytecodeMagic = 0x9de4b1a7c85f2301ULL;

struct Instruction {
    SemanticOpcode op = SemanticOpcode::Nop;
    std::uint8_t dst = 0;
    std::uint8_t src0 = 0;
    std::uint8_t src1 = 0;
    std::uint64_t imm = 0;
};

struct BytecodeChunk {
    std::uint64_t magic = kBytecodeMagic;
    std::uint32_t version = 1;
    std::uint32_t vmLevel = 1;
    std::uint64_t functionHash = 0;
    std::uint64_t platformSalt = 0;
    std::uint64_t nonce = 0;
    std::vector<std::uint8_t> encryptedPayload;
    std::uint64_t authTag = 0;
};

struct DecryptResult {
    bool ok = false;
    std::string error;
    std::vector<Instruction> instructions;
};

std::vector<std::uint8_t> serializeInstructions(const std::vector<Instruction> &instructions, const OpcodeMap &map);
std::optional<std::vector<Instruction>> deserializeInstructions(const std::vector<std::uint8_t> &bytes,
                                                                const OpcodeMap &map);

BytecodeChunk encryptChunk(const std::vector<Instruction> &instructions, const OpcodeMap &map,
                           std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                           std::uint32_t vmLevel);
DecryptResult decryptChunk(const BytecodeChunk &chunk, const OpcodeMap &map, std::string_view seed);

} // namespace vmp::core
