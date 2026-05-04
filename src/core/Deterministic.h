#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace vmp::core {

using Key256 = std::array<std::uint8_t, 32>;

std::uint64_t stableHash64(std::string_view data, std::uint64_t seed = 0xcbf29ce484222325ULL);
std::uint64_t mix64(std::uint64_t value);
Key256 deriveKey(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                 std::uint32_t vmLevel, std::string_view purpose);
std::uint64_t deriveNonce(std::string_view seed, std::uint64_t functionHash, std::uint64_t platformSalt,
                          std::uint32_t vmLevel, std::string_view purpose);

class DeterministicRng {
public:
    using result_type = std::uint64_t;

    explicit DeterministicRng(std::uint64_t seed);
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return UINT64_MAX; }
    result_type operator()();
    std::uint64_t next();
    std::uint32_t nextU32();
    std::uint8_t nextByteNonZero();

private:
    std::uint64_t state_;
};

} // namespace vmp::core
