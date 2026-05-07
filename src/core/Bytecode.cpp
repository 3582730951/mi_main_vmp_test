#include "Bytecode.h"
#include "Aead.h"

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

std::vector<std::uint8_t> associatedData(const BytecodeChunk &chunk, const OpcodeMap &map) {
    std::vector<std::uint8_t> aad;
    aad.reserve(8 + 4 + 4 + 8 + 8 + 8 + map.encode.size());
    appendU64(aad, chunk.magic);
    for (unsigned i = 0; i < 4; ++i) {
        aad.push_back(static_cast<std::uint8_t>((chunk.version >> (i * 8U)) & 0xffU));
    }
    for (unsigned i = 0; i < 4; ++i) {
        aad.push_back(static_cast<std::uint8_t>((chunk.vmLevel >> (i * 8U)) & 0xffU));
    }
    appendU64(aad, chunk.functionHash);
    appendU64(aad, chunk.platformSalt);
    appendU64(aad, chunk.nonce);
    for (std::uint8_t byte : map.encode) {
        aad.push_back(byte);
    }
    return aad;
}

std::uint64_t foldTag64(const std::uint8_t tag[aead::kTagSize]) {
    std::uint64_t out = 0;
    for (unsigned i = 0; i < 8; ++i) {
        out |= static_cast<std::uint64_t>(tag[i]) << (i * 8U);
    }
    return out;
}

std::vector<std::uint8_t> sealPayloadAEAD(const std::vector<std::uint8_t> &plain, const BytecodeChunk &chunk,
                                          const OpcodeMap &map, const Key256 &key,
                                          std::uint8_t tag[aead::kTagSize]) {
    std::vector<std::uint8_t> sealed(plain.size() + aead::kTagSize);
    std::uint8_t nonce[12]{};
    aead::nonce96(chunk.nonce, chunk.functionHash, chunk.vmLevel, nonce);
    aead::chacha20Xor(key.data(), nonce, 1, plain.data(), sealed.data(), plain.size());
    const auto aad = associatedData(chunk, map);
    std::uint8_t polyKey[64]{};
    aead::chacha20Block(key.data(), nonce, 0, polyKey);
    aead::poly1305Mac(polyKey, aad.data(), aad.size(), sealed.data(), plain.size(), tag);
    std::memcpy(sealed.data() + plain.size(), tag, aead::kTagSize);
    return sealed;
}

std::optional<std::vector<std::uint8_t>> openPayloadAEAD(const BytecodeChunk &chunk, const OpcodeMap &map,
                                                         const Key256 &key) {
    if (chunk.encryptedPayload.size() < aead::kTagSize) {
        return std::nullopt;
    }
    const std::size_t cipherSize = chunk.encryptedPayload.size() - aead::kTagSize;
    const std::uint8_t *ciphertext = chunk.encryptedPayload.data();
    const std::uint8_t *providedTag = chunk.encryptedPayload.data() + cipherSize;
    std::uint8_t nonce[12]{};
    aead::nonce96(chunk.nonce, chunk.functionHash, chunk.vmLevel, nonce);
    const auto aad = associatedData(chunk, map);
    std::uint8_t polyKey[64]{};
    std::uint8_t expectedTag[aead::kTagSize]{};
    aead::chacha20Block(key.data(), nonce, 0, polyKey);
    aead::poly1305Mac(polyKey, aad.data(), aad.size(), ciphertext, cipherSize, expectedTag);
    if (!aead::constantTimeEquals(providedTag, expectedTag, aead::kTagSize) ||
        foldTag64(expectedTag) != chunk.authTag) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> plain(cipherSize);
    aead::chacha20Xor(key.data(), nonce, 1, ciphertext, plain.data(), plain.size());
    return plain;
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
    std::uint8_t tag[aead::kTagSize]{};
    // AEAD seal: ChaCha20 payload encryption plus Poly1305 authentication over chunk metadata and opcode map.
    chunk.encryptedPayload = sealPayloadAEAD(serializeInstructions(instructions, map), chunk, map, key, tag);
    chunk.authTag = foldTag64(tag);
    return chunk;
}

DecryptResult decryptChunk(const BytecodeChunk &chunk, const OpcodeMap &map, std::string_view seed) {
    if (chunk.magic != kBytecodeMagic) {
        return {false, "invalid bytecode magic", {}};
    }
    if (chunk.version != 1) {
        return {false, "unsupported bytecode version", {}};
    }
    if (chunk.vmLevel < 1 || chunk.vmLevel > 3) {
        return {false, "invalid vm_level", {}};
    }
    const auto key = deriveKey(seed, chunk.functionHash, chunk.platformSalt, chunk.vmLevel, "bytecode-chunk");
    const auto plain = openPayloadAEAD(chunk, map, key);
    if (!plain.has_value()) {
        return {false, "bytecode authentication failed", {}};
    }
    const auto instructions = deserializeInstructions(*plain, map);
    if (!instructions.has_value()) {
        return {false, "bytecode decode failed", {}};
    }
    return {true, {}, *instructions};
}

} // namespace vmp::core
