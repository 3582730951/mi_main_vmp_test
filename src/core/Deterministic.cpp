#include "Deterministic.h"

#include <cstring>

namespace vmp::core {

std::uint64_t stableHash64(std::string_view data, std::uint64_t seed) {
    std::uint64_t hash = seed;
    for (unsigned char c : data) {
        hash ^= static_cast<std::uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::uint64_t mix64(std::uint64_t value) {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

Key256 deriveKey(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                 std::uint32_t vmLevel, std::string_view purpose) {
    Key256 key{};
    std::uint64_t state = stableHash64(seed);
    state ^= mix64(functionHash);
    state ^= mix64(platformSalt);
    state ^= mix64(static_cast<std::uint64_t>(vmLevel));
    state ^= stableHash64(purpose, 0x84222325cbf29ce4ULL);

    for (std::size_t i = 0; i < key.size(); i += sizeof(std::uint64_t)) {
        state = mix64(state + static_cast<std::uint64_t>(i));
        std::uint64_t word = state;
        std::memcpy(key.data() + i, &word, sizeof(word));
    }
    return key;
}

std::uint64_t deriveNonce(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                          std::uint32_t vmLevel, std::string_view purpose) {
    std::uint64_t state = stableHash64(seed, 0x6eed0e9da4d94a4fULL);
    state ^= mix64(functionHash);
    state ^= mix64(platformSalt);
    state ^= mix64(static_cast<std::uint64_t>(vmLevel) << 32U);
    state ^= stableHash64(purpose, 0xa4d94a4f6eed0e9dULL);
    return mix64(state);
}

DeterministicRng::DeterministicRng(std::uint64_t seed) : state_(seed) {}

DeterministicRng::result_type DeterministicRng::operator()() {
    return next();
}

std::uint64_t DeterministicRng::next() {
    state_ = mix64(state_);
    return state_;
}

std::uint32_t DeterministicRng::nextU32() {
    return static_cast<std::uint32_t>(next() >> 32U);
}

std::uint8_t DeterministicRng::nextByteNonZero() {
    std::uint8_t out = 0;
    while (out == 0) {
        out = static_cast<std::uint8_t>(next() & 0xffU);
    }
    return out;
}

} // namespace vmp::core
