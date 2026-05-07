#pragma once

#include <cstddef>
#include <cstdint>

namespace vmp::core::aead {

constexpr std::size_t kTagSize = 16;

inline std::uint32_t load32le(const std::uint8_t *in) {
    return static_cast<std::uint32_t>(in[0]) |
           (static_cast<std::uint32_t>(in[1]) << 8U) |
           (static_cast<std::uint32_t>(in[2]) << 16U) |
           (static_cast<std::uint32_t>(in[3]) << 24U);
}

inline void store32le(std::uint8_t *out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>(value & 0xffU);
    out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    out[2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    out[3] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

inline void store64le(std::uint8_t *out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
    }
}

inline std::uint32_t rotl32(std::uint32_t value, unsigned bits) {
    return (value << bits) | (value >> (32U - bits));
}

inline std::uint32_t chachaConstant(unsigned index) {
    volatile std::uint32_t mask = 0xa5a5a5a5U;
    switch (index) {
    case 0:
        return 0xc4d5ddc0U ^ mask;
    case 1:
        return 0x9685c1cbU ^ mask;
    case 2:
        return 0xdcc78897U ^ mask;
    default:
        return 0xce85c0d1U ^ mask;
    }
}

inline void quarterRound(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c, std::uint32_t &d) {
    a += b;
    d = rotl32(d ^ a, 16);
    c += d;
    b = rotl32(b ^ c, 12);
    a += b;
    d = rotl32(d ^ a, 8);
    c += d;
    b = rotl32(b ^ c, 7);
}

inline void chacha20Block(const std::uint8_t key[32], const std::uint8_t nonce[12],
                          std::uint32_t counter, std::uint8_t out[64]) {
    std::uint32_t state[16] = {
        chachaConstant(0), chachaConstant(1), chachaConstant(2), chachaConstant(3),
        load32le(key + 0), load32le(key + 4), load32le(key + 8), load32le(key + 12),
        load32le(key + 16), load32le(key + 20), load32le(key + 24), load32le(key + 28),
        counter, load32le(nonce + 0), load32le(nonce + 4), load32le(nonce + 8),
    };
    std::uint32_t working[16];
    for (unsigned i = 0; i < 16; ++i) {
        working[i] = state[i];
    }
    for (unsigned round = 0; round < 10; ++round) {
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);
        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }
    for (unsigned i = 0; i < 16; ++i) {
        store32le(out + (i * 4U), working[i] + state[i]);
    }
}

inline void chacha20Xor(const std::uint8_t key[32], const std::uint8_t nonce[12],
                        std::uint32_t counter, const std::uint8_t *in,
                        std::uint8_t *out, std::size_t size) {
    std::uint8_t block[64];
    std::size_t offset = 0;
    while (offset < size) {
        chacha20Block(key, nonce, counter++, block);
        const std::size_t remaining = size - offset;
        const std::size_t chunk = remaining < sizeof(block) ? remaining : sizeof(block);
        for (std::size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        offset += chunk;
    }
}

inline void poly1305ProcessBlock(const std::uint8_t block[16], std::uint32_t hibit,
                                 std::uint64_t h[5], const std::uint64_t r[5],
                                 const std::uint64_t s[4]) {
    constexpr std::uint64_t mask = 0x3ffffffULL;
    const std::uint32_t t0 = load32le(block + 0);
    const std::uint32_t t1 = load32le(block + 4);
    const std::uint32_t t2 = load32le(block + 8);
    const std::uint32_t t3 = load32le(block + 12);

    h[0] += t0 & mask;
    h[1] += ((static_cast<std::uint64_t>(t0) >> 26U) | (static_cast<std::uint64_t>(t1) << 6U)) & mask;
    h[2] += ((static_cast<std::uint64_t>(t1) >> 20U) | (static_cast<std::uint64_t>(t2) << 12U)) & mask;
    h[3] += ((static_cast<std::uint64_t>(t2) >> 14U) | (static_cast<std::uint64_t>(t3) << 18U)) & mask;
    h[4] += (static_cast<std::uint64_t>(t3) >> 8U) | hibit;

    const std::uint64_t d0 = (h[0] * r[0]) + (h[1] * s[3]) + (h[2] * s[2]) + (h[3] * s[1]) + (h[4] * s[0]);
    const std::uint64_t d1 = (h[0] * r[1]) + (h[1] * r[0]) + (h[2] * s[3]) + (h[3] * s[2]) + (h[4] * s[1]);
    const std::uint64_t d2 = (h[0] * r[2]) + (h[1] * r[1]) + (h[2] * r[0]) + (h[3] * s[3]) + (h[4] * s[2]);
    const std::uint64_t d3 = (h[0] * r[3]) + (h[1] * r[2]) + (h[2] * r[1]) + (h[3] * r[0]) + (h[4] * s[3]);
    const std::uint64_t d4 = (h[0] * r[4]) + (h[1] * r[3]) + (h[2] * r[2]) + (h[3] * r[1]) + (h[4] * r[0]);

    std::uint64_t c = d0 >> 26U;
    h[0] = d0 & mask;
    std::uint64_t v = d1 + c;
    c = v >> 26U;
    h[1] = v & mask;
    v = d2 + c;
    c = v >> 26U;
    h[2] = v & mask;
    v = d3 + c;
    c = v >> 26U;
    h[3] = v & mask;
    v = d4 + c;
    c = v >> 26U;
    h[4] = v & mask;
    h[0] += c * 5U;
    c = h[0] >> 26U;
    h[0] &= mask;
    h[1] += c;
}

inline void poly1305UpdatePadded(const std::uint8_t *data, std::size_t size, std::uint64_t h[5],
                                 const std::uint64_t r[5], const std::uint64_t s[4]) {
    while (size >= 16U) {
        poly1305ProcessBlock(data, 1U << 24U, h, r, s);
        data += 16U;
        size -= 16U;
    }
    if (size != 0U) {
        std::uint8_t block[16]{};
        for (std::size_t i = 0; i < size; ++i) {
            block[i] = data[i];
        }
        poly1305ProcessBlock(block, 1U << 24U, h, r, s);
    }
}

inline void poly1305Finish(std::uint64_t h[5], const std::uint8_t pad[16], std::uint8_t tag[16]) {
    constexpr std::uint64_t mask = 0x3ffffffULL;
    std::uint64_t c = h[1] >> 26U;
    h[1] &= mask;
    h[2] += c;
    c = h[2] >> 26U;
    h[2] &= mask;
    h[3] += c;
    c = h[3] >> 26U;
    h[3] &= mask;
    h[4] += c;
    c = h[4] >> 26U;
    h[4] &= mask;
    h[0] += c * 5U;
    c = h[0] >> 26U;
    h[0] &= mask;
    h[1] += c;

    std::uint64_t g0 = h[0] + 5U;
    c = g0 >> 26U;
    g0 &= mask;
    std::uint64_t g1 = h[1] + c;
    c = g1 >> 26U;
    g1 &= mask;
    std::uint64_t g2 = h[2] + c;
    c = g2 >> 26U;
    g2 &= mask;
    std::uint64_t g3 = h[3] + c;
    c = g3 >> 26U;
    g3 &= mask;
    std::uint64_t g4 = h[4] + c - (1ULL << 26U);

    const std::uint64_t useG = (g4 >> 63U) - 1U;
    const std::uint64_t useH = ~useG;
    h[0] = (h[0] & useH) | (g0 & useG);
    h[1] = (h[1] & useH) | (g1 & useG);
    h[2] = (h[2] & useH) | (g2 & useG);
    h[3] = (h[3] & useH) | (g3 & useG);
    h[4] = (h[4] & useH) | (g4 & useG);

    std::uint64_t f0 = (h[0] | (h[1] << 26U)) + load32le(pad + 0);
    std::uint64_t f1 = ((h[1] >> 6U) | (h[2] << 20U)) + load32le(pad + 4) + (f0 >> 32U);
    std::uint64_t f2 = ((h[2] >> 12U) | (h[3] << 14U)) + load32le(pad + 8) + (f1 >> 32U);
    std::uint64_t f3 = ((h[3] >> 18U) | (h[4] << 8U)) + load32le(pad + 12) + (f2 >> 32U);

    store32le(tag + 0, static_cast<std::uint32_t>(f0));
    store32le(tag + 4, static_cast<std::uint32_t>(f1));
    store32le(tag + 8, static_cast<std::uint32_t>(f2));
    store32le(tag + 12, static_cast<std::uint32_t>(f3));
}

inline void poly1305Mac(const std::uint8_t oneTimeKey[32], const std::uint8_t *aad,
                        std::size_t aadSize, const std::uint8_t *ciphertext,
                        std::size_t ciphertextSize, std::uint8_t tag[16]) {
    const std::uint64_t r[5] = {
        load32le(oneTimeKey + 0) & 0x3ffffffULL,
        (load32le(oneTimeKey + 3) >> 2U) & 0x3ffff03ULL,
        (load32le(oneTimeKey + 6) >> 4U) & 0x3ffc0ffULL,
        (load32le(oneTimeKey + 9) >> 6U) & 0x3f03fffULL,
        (load32le(oneTimeKey + 12) >> 8U) & 0x00fffffULL,
    };
    const std::uint64_t s[4] = {
        r[1] * 5U,
        r[2] * 5U,
        r[3] * 5U,
        r[4] * 5U,
    };
    std::uint64_t h[5]{};
    poly1305UpdatePadded(aad, aadSize, h, r, s);
    poly1305UpdatePadded(ciphertext, ciphertextSize, h, r, s);
    std::uint8_t lengths[16]{};
    store64le(lengths + 0, static_cast<std::uint64_t>(aadSize));
    store64le(lengths + 8, static_cast<std::uint64_t>(ciphertextSize));
    poly1305UpdatePadded(lengths, sizeof(lengths), h, r, s);
    poly1305Finish(h, oneTimeKey + 16, tag);
}

inline bool constantTimeEquals(const std::uint8_t *left, const std::uint8_t *right, std::size_t size) {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < size; ++i) {
        diff |= static_cast<std::uint8_t>(left[i] ^ right[i]);
    }
    return diff == 0U;
}

inline void nonce96(std::uint64_t nonce, std::uint64_t functionHash, std::uint32_t vmLevel,
                    std::uint8_t out[12]) {
    store64le(out, nonce);
    const std::uint32_t domain = static_cast<std::uint32_t>(functionHash >> 32U) ^
                                 static_cast<std::uint32_t>(functionHash) ^
                                 (vmLevel * 0x9e3779b9U);
    store32le(out + 8, domain);
}

} // namespace vmp::core::aead
