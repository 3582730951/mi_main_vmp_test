#include "protected_sample_blob.h"

#include <cstddef>
#include <cstdint>

#if defined(_WIN32) && defined(VMP_FREESTANDING_WINDOWS_ENTRY)
extern "C" void *memset(void *dest, int value, std::size_t count) {
  auto *out = static_cast<std::uint8_t *>(dest);
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = static_cast<std::uint8_t>(value);
  }
  return dest;
}

extern "C" void *memcpy(void *dest, const void *src, std::size_t count) {
  auto *out = static_cast<std::uint8_t *>(dest);
  const auto *in = static_cast<const std::uint8_t *>(src);
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = in[i];
  }
  return dest;
}

extern "C" void __main() {}

#if defined(_MSC_VER)
#define VMP_STDCALL __stdcall
#else
#define VMP_STDCALL __attribute__((stdcall))
#endif
extern "C" __declspec(dllimport) void VMP_STDCALL ExitProcess(unsigned int exitCode);
#endif

namespace {

constexpr std::uint64_t kBytecodeMagic = 0x9de4b1a7c85f2301ULL;
constexpr std::uint64_t kPurposeHash = 0x04d6d739b676c5ffULL;
constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kInstructionSize = 12;
constexpr std::size_t kMaxPayloadBytes = 4096;

constexpr std::uint8_t kEncodedSeed[] = {
    0x2a, 0x28, 0x35, 0x2e, 0x3f, 0x39, 0x2e, 0x3f, 0x3e, 0x77, 0x29, 0x3b,
    0x37, 0x2a, 0x36, 0x3f, 0x77, 0x29, 0x3f, 0x3f, 0x3e, 0x77, 0x2c, 0x6b,
};
constexpr std::uint8_t kSampleArtifactMagic[] = {
    0x8e, 0x52, 0xb9, 0x04, 0xd7, 0x6a, 0x31, 0xc8,
};

enum SemanticOpcode : std::uint8_t {
  OpNop = 0,
  OpLoadImm,
  OpMov,
  OpLoad,
  OpStore,
  OpAdd,
  OpSub,
  OpMul,
  OpAnd,
  OpOr,
  OpXor,
  OpCmpEq,
  OpCmpNe,
  OpCmpSgt,
  OpSelect,
  OpJump,
  OpJumpIfZero,
  OpCallHost,
  OpCheckIntegrity,
  OpRet,
  OpHalt,
  OpCmpSge,
  OpCmpSle,
  OpCmpUgt,
  OpCmpUge,
  OpCmpUle,
  OpShl,
  OpLShr,
  OpAShr,
  OpCount,
};

struct Artifact {
  std::uint32_t version;
  std::uint32_t vmLevel;
  std::uint64_t functionHash;
  std::uint64_t platformSalt;
  std::uint64_t nonce;
  std::uint64_t authTag;
  std::uint8_t encode[OpCount];
  std::uint8_t decode[256];
  const std::uint8_t *payload;
  std::uint32_t payloadSize;
};

std::uint64_t mix64(std::uint64_t value) {
  value += 0x9e3779b97f4a7c15ULL;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

std::uint64_t stableHash64(const std::uint8_t *data, std::size_t size, std::uint64_t seed) {
  std::uint64_t hash = seed;
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= static_cast<std::uint64_t>(data[i]);
    hash *= 1099511628211ULL;
  }
  return hash;
}

std::uint32_t readU32At(const std::uint8_t *data) {
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data[i]) << (i * 8U);
  }
  return value;
}

std::uint64_t readU64At(const std::uint8_t *data) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (i * 8U);
  }
  return value;
}

bool readU32(std::size_t &offset, std::uint32_t &value) {
  if (offset + 4 > kProtectedSampleBlobSize) {
    return false;
  }
  value = readU32At(kProtectedSampleBlob + offset);
  offset += 4;
  return true;
}

bool readU64(std::size_t &offset, std::uint64_t &value) {
  if (offset + 8 > kProtectedSampleBlobSize) {
    return false;
  }
  value = readU64At(kProtectedSampleBlob + offset);
  offset += 8;
  return true;
}

void deriveSeed(std::uint8_t *out) {
  for (std::size_t i = 0; i < sizeof(kEncodedSeed); ++i) {
    out[i] = static_cast<std::uint8_t>(kEncodedSeed[i] ^ 0x5aU);
  }
}

void deriveKey(const Artifact &artifact, std::uint8_t *key) {
  std::uint8_t seed[sizeof(kEncodedSeed)]{};
  deriveSeed(seed);
  std::uint64_t state = stableHash64(seed, sizeof(seed), 0xcbf29ce484222325ULL);
  state ^= mix64(artifact.functionHash);
  state ^= mix64(artifact.platformSalt);
  state ^= mix64(static_cast<std::uint64_t>(artifact.vmLevel));
  state ^= kPurposeHash;
  for (std::size_t i = 0; i < kKeyBytes; i += sizeof(std::uint64_t)) {
    state = mix64(state + static_cast<std::uint64_t>(i));
    const std::uint64_t word = state;
    for (unsigned b = 0; b < 8; ++b) {
      key[i + b] = static_cast<std::uint8_t>((word >> (b * 8U)) & 0xffU);
    }
  }
}

std::uint64_t keyWord(const std::uint8_t *key, std::size_t index) {
  return readU64At(key + ((index % 4U) * sizeof(std::uint64_t)));
}

std::uint64_t tagArtifact(const Artifact &artifact, const std::uint8_t *key) {
  std::uint64_t tag = 0xfeedfacedeadbeefULL;
  tag ^= keyWord(key, 0);
  tag = mix64(tag ^ artifact.version);
  tag = mix64(tag ^ artifact.vmLevel);
  tag = mix64(tag ^ artifact.functionHash);
  tag = mix64(tag ^ artifact.platformSalt);
  tag = mix64(tag ^ artifact.nonce);
  for (std::uint8_t byte : artifact.encode) {
    tag = stableHash64(&byte, 1, tag);
  }
  for (std::uint32_t i = 0; i < artifact.payloadSize; ++i) {
    tag = stableHash64(artifact.payload + i, 1, tag);
  }
  return tag;
}

bool parseArtifact(Artifact &artifact) {
  if (kProtectedSampleBlobSize < sizeof(kSampleArtifactMagic)) {
    return false;
  }
  for (std::size_t i = 0; i < sizeof(kSampleArtifactMagic); ++i) {
    if (kProtectedSampleBlob[i] != kSampleArtifactMagic[i]) {
      return false;
    }
  }
  for (std::size_t i = 0; i < 256; ++i) {
    artifact.decode[i] = 0xffU;
  }

  std::size_t offset = sizeof(kSampleArtifactMagic);
  if (!readU32(offset, artifact.version) || !readU32(offset, artifact.vmLevel) ||
      !readU64(offset, artifact.functionHash) || !readU64(offset, artifact.platformSalt) ||
      !readU64(offset, artifact.nonce) || !readU64(offset, artifact.authTag)) {
    return false;
  }

  std::uint32_t opcodeCount = 0;
  if (!readU32(offset, opcodeCount) || opcodeCount != OpCount || artifact.version != 1 ||
      artifact.vmLevel < 1 || artifact.vmLevel > 3) {
    return false;
  }
  for (std::uint32_t i = 0; i < opcodeCount; ++i) {
    if (offset >= kProtectedSampleBlobSize) {
      return false;
    }
    const std::uint8_t byte = kProtectedSampleBlob[offset++];
    if (byte == 0 || artifact.decode[byte] != 0xffU) {
      return false;
    }
    artifact.encode[i] = byte;
    artifact.decode[byte] = static_cast<std::uint8_t>(i);
  }
  if (!readU32(offset, artifact.payloadSize) || artifact.payloadSize > kMaxPayloadBytes ||
      offset + artifact.payloadSize != kProtectedSampleBlobSize) {
    return false;
  }
  artifact.payload = kProtectedSampleBlob + offset;

  std::uint8_t key[kKeyBytes]{};
  deriveKey(artifact, key);
  return artifact.authTag == tagArtifact(artifact, key);
}

void decryptPayload(const Artifact &artifact, std::uint8_t *plain) {
  std::uint8_t key[kKeyBytes]{};
  deriveKey(artifact, key);
  std::uint64_t block = 0;
  for (std::uint32_t i = 0; i < artifact.payloadSize; ++i) {
    if ((i % 8U) == 0) {
      block = mix64(keyWord(key, i / 8U) ^ artifact.nonce ^ static_cast<std::uint64_t>(i / 8U));
    }
    plain[i] = static_cast<std::uint8_t>(
        artifact.payload[i] ^ static_cast<std::uint8_t>((block >> ((i % 8U) * 8U)) & 0xffU));
  }
}

std::uint64_t baseline(std::uint64_t left, std::uint64_t right) {
  return (left ^ right) + 0x5a5aULL;
}

bool executeCase(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
  if ((artifact.payloadSize % kInstructionSize) != 0) {
    return false;
  }
  std::uint8_t plain[kMaxPayloadBytes]{};
  decryptPayload(artifact, plain);

  std::uint64_t regs[16]{};
  regs[1] = left;
  regs[2] = right;
  for (std::uint32_t pc = 0; pc < artifact.payloadSize / kInstructionSize; ++pc) {
    const std::size_t offset = static_cast<std::size_t>(pc) * kInstructionSize;
    const std::uint8_t semantic = artifact.decode[plain[offset]];
    const std::uint8_t dst = plain[offset + 1];
    const std::uint8_t src0 = plain[offset + 2];
    const std::uint8_t src1 = plain[offset + 3];
    const std::uint64_t imm = readU64At(plain + offset + 4);
    if (dst >= 16 || src0 >= 16 || src1 >= 16) {
      return false;
    }
    switch (semantic) {
    case OpLoadImm:
      regs[dst] = imm;
      break;
    case OpAdd:
      regs[dst] = regs[src0] + regs[src1];
      break;
    case OpXor:
      regs[dst] = regs[src0] ^ regs[src1];
      break;
    case OpRet:
      return regs[src0] == baseline(left, right);
    default:
      return false;
    }
  }
  return false;
}

} // namespace

int protectedReleaseMain() {
  Artifact artifact{};
  if (!parseArtifact(artifact)) {
    return 40;
  }
  int passed = 0;
  passed += executeCase(artifact, 7, 11) ? 1 : 0;
  passed += executeCase(artifact, 0, 0) ? 1 : 0;
  passed += executeCase(artifact, 0x1234, 0x00ff) ? 1 : 0;
  passed += executeCase(artifact, 0xffffffffULL, 0x55aa55aaULL) ? 1 : 0;
  return passed == 4 ? 0 : 30 + passed;
}

#if defined(_WIN32) && defined(VMP_FREESTANDING_WINDOWS_ENTRY)
extern "C" void mainCRTStartup() {
  ExitProcess(static_cast<unsigned int>(protectedReleaseMain()));
}
#else
int main() {
  return protectedReleaseMain();
}
#endif
