#include "OpcodeMap.h"

#include <algorithm>
#include <stdexcept>

namespace vmp::core {

std::uint8_t OpcodeMap::byteFor(SemanticOpcode semantic) const {
    return encode.at(static_cast<std::size_t>(semantic));
}

std::optional<SemanticOpcode> OpcodeMap::semanticFor(std::uint8_t byte) const {
    return decode.at(byte);
}

std::uint64_t OpcodeMap::fingerprint() const {
    std::uint64_t hash = 0x3141592653589793ULL;
    for (std::uint8_t byte : encode) {
        hash = stableHash64(std::string_view(reinterpret_cast<const char *>(&byte), 1), hash);
    }
    return hash;
}

OpcodeMap buildOpcodeMap(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                         std::uint32_t vmLevel) {
    if (vmLevel < 1 || vmLevel > 3) {
        throw std::invalid_argument("vm_level must be 1, 2, or 3");
    }

    OpcodeMap map;
    const std::uint64_t rngSeed = deriveNonce(seed, functionHash, platformSalt, vmLevel, "opcode-map");
    DeterministicRng rng(rngSeed);

    for (std::size_t i = 0; i < static_cast<std::size_t>(SemanticOpcode::Count); ++i) {
        std::uint8_t byte = 0;
        do {
            byte = rng.nextByteNonZero();
        } while (map.decode[byte].has_value());
        const auto semantic = static_cast<SemanticOpcode>(i);
        map.encode[i] = byte;
        map.decode[byte] = semantic;
        map.handlerOrder.push_back(semantic);
    }

    std::shuffle(map.handlerOrder.begin(), map.handlerOrder.end(), rng);
    return map;
}

} // namespace vmp::core
