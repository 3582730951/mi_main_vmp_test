#include "Bytecode.h"

#include <cstring>
#include <stdexcept>

namespace vmp::core {
namespace {

constexpr std::size_t kInstructionSize = 12;

void appendU64(std::vector<std::uint8_t> &out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU));
    }
}

std::uint64_t readU64(const std::vector<std::uint8_t> &bytes, std::size_t offset) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes.at(offset + i)) << (i * 8U);
    }
    return value;
}

std::uint64_t keyWord(const Key256 &key, std::size_t index) {
    std::uint64_t word = 0;
    std::memcpy(&word, key.data() + ((index % 4) * sizeof(std::uint64_t)), sizeof(word));
    return word;
}

std::vector<std::uint8_t> xorStream(const std::vector<std::uint8_t> &input, const Key256 &key, std::uint64_t nonce) {
    std::vector<std::uint8_t> out = input;
    std::uint64_t block = 0;
    for (std::size_t i = 0; i < out.size(); ++i) {
        if ((i % 8) == 0) {
            block = mix64(keyWord(key, i / 8) ^ nonce ^ static_cast<std::uint64_t>(i / 8));
        }
        out[i] ^= static_cast<std::uint8_t>((block >> ((i % 8) * 8U)) & 0xffU);
    }
    return out;
}

std::uint64_t tagChunk(const BytecodeChunk &chunk, const OpcodeMap &map, const Key256 &key) {
    std::uint64_t tag = 0xfeedfacedeadbeefULL;
    tag ^= keyWord(key, 0);
    tag = mix64(tag ^ chunk.version);
    tag = mix64(tag ^ chunk.vmLevel);
    tag = mix64(tag ^ chunk.functionHash);
    tag = mix64(tag ^ chunk.platformSalt);
    tag = mix64(tag ^ chunk.nonce);
    for (std::uint8_t byte : map.encode) {
        tag = stableHash64(std::string_view(reinterpret_cast<const char *>(&byte), 1), tag);
    }
    for (std::uint8_t byte : chunk.encryptedPayload) {
        tag = stableHash64(std::string_view(reinterpret_cast<const char *>(&byte), 1), tag);
    }
    return tag;
}

} // namespace

std::vector<std::uint8_t> serializeInstructions(const std::vector<Instruction> &instructions, const OpcodeMap &map) {
    std::vector<std::uint8_t> out;
    out.reserve(instructions.size() * kInstructionSize);
    for (const auto &inst : instructions) {
        out.push_back(map.byteFor(inst.op));
        out.push_back(inst.dst);
        out.push_back(inst.src0);
        out.push_back(inst.src1);
        appendU64(out, inst.imm);
    }
    return out;
}

std::optional<std::vector<Instruction>> deserializeInstructions(const std::vector<std::uint8_t> &bytes,
                                                                const OpcodeMap &map) {
    if ((bytes.size() % kInstructionSize) != 0) {
        return std::nullopt;
    }
    std::vector<Instruction> out;
    out.reserve(bytes.size() / kInstructionSize);
    for (std::size_t offset = 0; offset < bytes.size(); offset += kInstructionSize) {
        const auto semantic = map.semanticFor(bytes[offset]);
        if (!semantic.has_value()) {
            return std::nullopt;
        }
        out.push_back(Instruction{*semantic, bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                                  readU64(bytes, offset + 4)});
    }
    return out;
}

BytecodeChunk encryptChunk(const std::vector<Instruction> &instructions, const OpcodeMap &map,
                           std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                           std::uint32_t vmLevel) {
    if (vmLevel < 1 || vmLevel > 3) {
        throw std::invalid_argument("vm_level must be 1, 2, or 3");
    }
    BytecodeChunk chunk;
    chunk.vmLevel = vmLevel;
    chunk.functionHash = functionHash;
    chunk.platformSalt = platformSalt;
    chunk.nonce = deriveNonce(seed, functionHash, platformSalt, vmLevel, "bytecode-chunk");
    const auto key = deriveKey(seed, functionHash, platformSalt, vmLevel, "bytecode-chunk");
    chunk.encryptedPayload = xorStream(serializeInstructions(instructions, map), key, chunk.nonce);
    chunk.authTag = tagChunk(chunk, map, key);
    return chunk;
}

DecryptResult decryptChunk(const BytecodeChunk &chunk, const OpcodeMap &map, std::string_view seed) {
    if (chunk.magic != "VMPBC1") {
        return {false, "invalid bytecode magic", {}};
    }
    if (chunk.version != 1) {
        return {false, "unsupported bytecode version", {}};
    }
    if (chunk.vmLevel < 1 || chunk.vmLevel > 3) {
        return {false, "invalid vm_level", {}};
    }
    const auto key = deriveKey(seed, chunk.functionHash, chunk.platformSalt, chunk.vmLevel, "bytecode-chunk");
    if (tagChunk(chunk, map, key) != chunk.authTag) {
        return {false, "bytecode authentication failed", {}};
    }
    const auto plain = xorStream(chunk.encryptedPayload, key, chunk.nonce);
    const auto instructions = deserializeInstructions(plain, map);
    if (!instructions.has_value()) {
        return {false, "bytecode decode failed", {}};
    }
    return {true, {}, *instructions};
}

} // namespace vmp::core
