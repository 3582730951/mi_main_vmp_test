#include "protected_sample_blob.h"
#include "core/Aead.h"

#include <cstddef>
#include <cstdint>

#if defined(__GNUC__)
#define VMP_NOINLINE __attribute__((noinline))
#define VMP_USED __attribute__((used))
#else
#define VMP_NOINLINE
#define VMP_USED
#endif

#if defined(VMP_FREESTANDING_WINDOWS_ENTRY) || defined(VMP_FREESTANDING_LINUX_ENTRY)
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
#endif

#if defined(_WIN32) && defined(VMP_FREESTANDING_WINDOWS_ENTRY) && !defined(VMP_WINDOWS_ENTRY_RETURNS_STATUS)
#if defined(_MSC_VER)
#define VMP_STDCALL __stdcall
#else
#define VMP_STDCALL __attribute__((stdcall))
#endif
extern "C" __declspec(dllimport) void VMP_STDCALL ExitProcess(unsigned int exitCode);
#if defined(VMP_VISIBLE_PROTECTED_DEMO)
extern "C" __declspec(dllimport) void *VMP_STDCALL GetStdHandle(unsigned long handle);
extern "C" __declspec(dllimport) int VMP_STDCALL WriteFile(
    void *handle, const void *buffer, unsigned long bytesToWrite, unsigned long *bytesWritten, void *overlapped);
extern "C" __declspec(dllimport) int VMP_STDCALL ReadFile(
    void *handle, void *buffer, unsigned long bytesToRead, unsigned long *bytesRead, void *overlapped);

static void *gVmpVisibleDemoInput = nullptr;

extern "C" int getchar() {
  unsigned char byte = 0;
  unsigned long bytesRead = 0;
  if (gVmpVisibleDemoInput == nullptr) {
    gVmpVisibleDemoInput = GetStdHandle(static_cast<unsigned long>(-10));
  }
  if (!ReadFile(gVmpVisibleDemoInput, &byte, 1, &bytesRead, nullptr) || bytesRead != 1) {
    return -1;
  }
  return static_cast<int>(byte);
}
#endif
#endif

namespace {

constexpr std::uint64_t kBytecodeMagic = 0x9de4b1a7c85f2301ULL;
constexpr std::uint64_t kPurposeHash = 0x04d6d739b676c5ffULL;
constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kInstructionSize = 12;
constexpr std::size_t kMaxPayloadBytes = 4096;

constexpr std::uint8_t kEncodedSeed[] = {
    0xd5, 0xd7, 0xca, 0xd1, 0xc0, 0xc6, 0xd1, 0xc0, 0xc1, 0x88, 0xd6, 0xc4,
    0xc8, 0xd5, 0xc9, 0xc0, 0x88, 0xd6, 0xc0, 0xc0, 0xc1, 0x88, 0xd3, 0x94,
};
constexpr std::uint8_t kSampleArtifactMagic[] = {
    0x8e, 0x52, 0xb9, 0x04, 0xd7, 0x6a, 0x31, 0xc8,
};

#if defined(VMP_VISIBLE_PROTECTED_DEMO)
#include "protected_demo_text.h"
#endif

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
  std::uint8_t encode[OpCount];
  std::uint8_t decode[256];
  std::uint64_t authTag;
  const std::uint8_t *payload;
  std::uint32_t payloadSize;
};

struct CaseOutcome {
  std::uint64_t left;
  std::uint64_t right;
  std::uint64_t baselineValue;
  std::uint64_t protectedValue;
  bool ok;
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
    out[i] = static_cast<std::uint8_t>(kEncodedSeed[i] ^ 0xa5U);
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

void appendU64(std::uint8_t *out, std::size_t &offset, std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    out[offset++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
  }
}

void appendU32(std::uint8_t *out, std::size_t &offset, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    out[offset++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
  }
}

std::uint64_t foldTag64(const std::uint8_t tag[vmp::core::aead::kTagSize]) {
  return readU64At(tag);
}

std::size_t associatedData(const Artifact &artifact, std::uint8_t *aad) {
  std::size_t offset = 0;
  appendU64(aad, offset, kBytecodeMagic);
  appendU32(aad, offset, artifact.version);
  appendU32(aad, offset, artifact.vmLevel);
  appendU64(aad, offset, artifact.functionHash);
  appendU64(aad, offset, artifact.platformSalt);
  appendU64(aad, offset, artifact.nonce);
  for (std::uint8_t byte : artifact.encode) {
    aad[offset++] = byte;
  }
  return offset;
}

bool verifyArtifactAEAD(const Artifact &artifact, const std::uint8_t *key) {
  if (artifact.payloadSize < vmp::core::aead::kTagSize) {
    return false;
  }
  const std::uint32_t cipherSize =
      artifact.payloadSize - static_cast<std::uint32_t>(vmp::core::aead::kTagSize);
  const std::uint8_t *providedTag = artifact.payload + cipherSize;
  std::uint8_t aad[8 + 4 + 4 + 8 + 8 + 8 + OpCount]{};
  const std::size_t aadSize = associatedData(artifact, aad);
  std::uint8_t nonce[12]{};
  std::uint8_t polyKey[64]{};
  std::uint8_t expectedTag[vmp::core::aead::kTagSize]{};
  vmp::core::aead::nonce96(artifact.nonce, artifact.functionHash, artifact.vmLevel, nonce);
  vmp::core::aead::chacha20Block(key, nonce, 0, polyKey);
  vmp::core::aead::poly1305Mac(polyKey, aad, aadSize, artifact.payload, cipherSize, expectedTag);
  return vmp::core::aead::constantTimeEquals(providedTag, expectedTag, vmp::core::aead::kTagSize) &&
         foldTag64(expectedTag) == artifact.authTag;
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
  return verifyArtifactAEAD(artifact, key);
}

bool decryptPayload(const Artifact &artifact, std::uint8_t *plain, std::uint32_t &plainSize) {
  if (artifact.payloadSize < vmp::core::aead::kTagSize) {
    return false;
  }
  plainSize = artifact.payloadSize - static_cast<std::uint32_t>(vmp::core::aead::kTagSize);
  std::uint8_t key[kKeyBytes]{};
  deriveKey(artifact, key);
  if (!verifyArtifactAEAD(artifact, key)) {
    return false;
  }
  std::uint8_t nonce[12]{};
  vmp::core::aead::nonce96(artifact.nonce, artifact.functionHash, artifact.vmLevel, nonce);
  vmp::core::aead::chacha20Xor(key, nonce, 1, artifact.payload, plain, plainSize);
  return true;
}

std::uint64_t baseline(std::uint64_t left, std::uint64_t right) {
  return (left ^ right) + 0x5a5aULL;
}

#if defined(VMP_VISIBLE_PROTECTED_DEMO) && defined(_WIN32)
struct DemoIoContext {
  void *stdoutHandle;
  char pending[192];
  std::size_t pendingSize;
};

void demoClear(char *data, std::size_t size) {
  volatile char *wipe = data;
  for (std::size_t i = 0; i < size; ++i) {
    wipe[i] = 0;
  }
}

VMP_NOINLINE void demoIoInit(DemoIoContext &io) {
  io.stdoutHandle = GetStdHandle(static_cast<unsigned long>(-11));
  io.pendingSize = 0;
}

VMP_NOINLINE void demoIoFlush(DemoIoContext &io) {
  if (io.pendingSize == 0) {
    return;
  }
  unsigned long written = 0;
  WriteFile(io.stdoutHandle, io.pending, static_cast<unsigned long>(io.pendingSize), &written, nullptr);
  demoClear(io.pending, io.pendingSize);
  io.pendingSize = 0;
}

VMP_NOINLINE void demoWriteBytes(DemoIoContext &io, const char *data, std::size_t size) {
  std::size_t offset = 0;
  while (offset < size) {
    if (io.pendingSize == sizeof(io.pending)) {
      demoIoFlush(io);
    }
    const std::size_t capacity = sizeof(io.pending) - io.pendingSize;
    const std::size_t remaining = size - offset;
    const std::size_t chunk = remaining < capacity ? remaining : capacity;
    for (std::size_t i = 0; i < chunk; ++i) {
      io.pending[io.pendingSize + i] = data[offset + i];
    }
    io.pendingSize += chunk;
    offset += chunk;
  }
}

std::uint32_t demoRotl32(std::uint32_t value, unsigned bits) {
  return static_cast<std::uint32_t>((value << bits) | (value >> (32U - bits)));
}

void demoQuarterRound(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c, std::uint32_t &d) {
  a += b;
  d = demoRotl32(d ^ a, 16);
  c += d;
  b = demoRotl32(b ^ c, 12);
  a += b;
  d = demoRotl32(d ^ a, 8);
  c += d;
  b = demoRotl32(b ^ c, 7);
}

void demoStore32(std::uint8_t *out, std::uint32_t value) {
  out[0] = static_cast<std::uint8_t>(value & 0xffU);
  out[1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
  out[2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
  out[3] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

std::uint32_t demoLo32(std::uint64_t value) {
  return static_cast<std::uint32_t>(value & 0xffffffffULL);
}

std::uint32_t demoHi32(std::uint64_t value) {
  return static_cast<std::uint32_t>((value >> 32U) & 0xffffffffULL);
}

std::uint64_t demoRuntimeSalt(const Artifact &artifact) {
  return mix64(kDemoTextBuildSalt ^ artifact.authTag ^ artifact.nonce ^ artifact.platformSalt ^ kPurposeHash);
}

void demoTextBlock(const Artifact &artifact, const DemoTextBlob &blob, std::uint32_t counter, std::uint8_t *out) {
  const std::uint64_t runtimeSalt = demoRuntimeSalt(artifact);
  std::uint32_t state[16] = {
      0xa9f13d57U, 0xc2e7b46bU, 0x6d8a2f91U, 0xb5c0e33dU,
      demoLo32(runtimeSalt), demoHi32(runtimeSalt),
      demoLo32(blob.nonce0), demoHi32(blob.nonce0),
      demoLo32(blob.nonce1), demoHi32(blob.nonce1),
      demoLo32(kDemoTextBuildSalt), demoHi32(kDemoTextBuildSalt),
      counter, counter ^ 0x9e3779b9U,
      demoLo32(runtimeSalt ^ blob.nonce1), demoHi32(runtimeSalt ^ blob.nonce0),
  };
  std::uint32_t working[16];
  for (unsigned i = 0; i < 16; ++i) {
    working[i] = state[i];
  }
  for (unsigned round = 0; round < 10; ++round) {
    demoQuarterRound(working[0], working[4], working[8], working[12]);
    demoQuarterRound(working[1], working[5], working[9], working[13]);
    demoQuarterRound(working[2], working[6], working[10], working[14]);
    demoQuarterRound(working[3], working[7], working[11], working[15]);
    demoQuarterRound(working[0], working[5], working[10], working[15]);
    demoQuarterRound(working[1], working[6], working[11], working[12]);
    demoQuarterRound(working[2], working[7], working[8], working[13]);
    demoQuarterRound(working[3], working[4], working[9], working[14]);
  }
  for (unsigned i = 0; i < 16; ++i) {
    demoStore32(out + i * 4U, working[i] + state[i]);
  }
}

VMP_NOINLINE std::size_t demoNextTextChunk(std::uint64_t &route, std::size_t cursor, std::size_t remaining) {
  route = mix64(route ^ (static_cast<std::uint64_t>(cursor) * 0x100000001b3ULL));
  const std::size_t wanted = 5U + static_cast<std::size_t>((route >> ((cursor & 7U) * 8U)) & 0x0fU);
  return wanted < remaining ? wanted : remaining;
}

VMP_NOINLINE void demoDecodeTextChunk(
    const Artifact &artifact,
    const DemoTextBlob &blob,
    std::size_t cursor,
    char *out,
    std::size_t size) {
  std::uint8_t block[64];
  std::uint32_t cachedCounter = 0xffffffffU;
  for (std::size_t i = 0; i < size; ++i) {
    const std::size_t source = cursor + i;
    const std::uint32_t counter = static_cast<std::uint32_t>(source >> 6U);
    if (counter != cachedCounter) {
      demoTextBlock(artifact, blob, counter, block);
      cachedCounter = counter;
    }
    out[i] = static_cast<char>(blob.data[source] ^ block[source & 63U]);
  }
  demoClear(reinterpret_cast<char *>(block), sizeof(block));
}

VMP_NOINLINE bool demoVisitText(
    const Artifact &artifact,
    const DemoTextBlob &blob,
    DemoIoContext *io,
    std::uint64_t seedBias) {
  char chunk[23];
  std::size_t cursor = 0;
  std::uint64_t route = mix64(blob.nonce0 ^ blob.nonce1 ^ artifact.authTag ^ seedBias);
  std::uint64_t tag = demoRuntimeSalt(artifact) ^ blob.nonce0 ^ blob.nonce1;
  while (cursor < blob.size) {
    const std::size_t remaining = blob.size - cursor;
    const std::size_t chunkSize = demoNextTextChunk(route, cursor, remaining);
    demoDecodeTextChunk(artifact, blob, cursor, chunk, chunkSize);
    tag = stableHash64(reinterpret_cast<const std::uint8_t *>(chunk), chunkSize, tag);
    if (io != nullptr) {
      demoWriteBytes(*io, chunk, chunkSize);
    }
    demoClear(chunk, chunkSize);
    route = mix64(route ^ tag ^ static_cast<std::uint64_t>(chunkSize) ^ (static_cast<std::uint64_t>(cursor) << 17U));
    cursor += chunkSize;
  }
  return tag == blob.tag;
}

VMP_NOINLINE void demoWriteText(DemoIoContext &io, const Artifact &artifact, const DemoTextBlob &blob) {
  const std::uint64_t validationSeed = mix64(blob.tag ^ artifact.nonce);
  if (!demoVisitText(artifact, blob, nullptr, validationSeed)) {
    return;
  }
  demoVisitText(artifact, blob, &io, validationSeed ^ 0x3f84d5b5b5470917ULL);
}

void demoWriteU64(DemoIoContext &io, std::uint64_t value) {
  char reversed[20];
  std::size_t count = 0;
  do {
    reversed[count++] = static_cast<char>('0' + (value % 10U));
    value /= 10U;
  } while (value != 0);
  char out[20];
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = reversed[count - 1U - i];
  }
  demoWriteBytes(io, out, count);
  demoClear(reversed, count);
  demoClear(out, count);
}

void demoDecompilerTrap(std::uint64_t value) {
  volatile std::uint64_t left = value;
  volatile std::uint64_t right = value;
  if ((left ^ right) == 0xa5a5a5a5a5a5a5a5ULL) {
#if defined(__GNUC__)
    asm volatile(
        "jmp 1f\n"
        ".byte 0x0f, 0x0b, 0xeb, 0xfe, 0xe8, 0xff, 0xff, 0xff, 0xff\n"
        "1:\n"
        :
        :
        : "memory");
#endif
  }
}

void demoWriteCase(DemoIoContext &io, const Artifact &artifact, unsigned index, const CaseOutcome &item) {
  demoWriteText(io, artifact, kMsgCase);
  demoWriteU64(io, index);
  demoWriteText(io, artifact, kMsgLeft);
  demoWriteU64(io, item.left);
  demoWriteText(io, artifact, kMsgRight);
  demoWriteU64(io, item.right);
  demoWriteText(io, artifact, kMsgBaseline);
  demoWriteU64(io, item.baselineValue);
  demoWriteText(io, artifact, kMsgProtected);
  demoWriteU64(io, item.protectedValue);
  demoWriteText(io, artifact, kMsgVmStatus);
  demoWriteText(io, artifact, item.ok ? kMsgOk : kMsgFail);
  demoWriteText(io, artifact, kMsgMatch);
  demoWriteText(io, artifact, item.ok ? kMsgYes : kMsgNo);
  demoWriteText(io, artifact, kMsgNewline);
}

VMP_NOINLINE VMP_USED bool demoOpaqueFalse(std::uint64_t value) {
  volatile std::uint64_t first = mix64(value ^ 0x6c8e9cf570932bd5ULL);
  volatile std::uint64_t second = first ^ first;
  return second == 0x4f1bbcdc2f6a83d1ULL;
}

VMP_NOINLINE VMP_USED void demoTrapIsland(std::uint64_t value) {
  volatile std::uint64_t gate = mix64(value ^ 0xd1b54a32d192ed03ULL);
  if (demoOpaqueFalse(gate)) {
#if defined(__GNUC__)
    asm volatile(
        "jmp 9f\n"
        ".byte 0xe8, 0x00, 0x00, 0x00, 0x00\n"
        ".byte 0x0f, 0x0b, 0xeb, 0xfe, 0x48, 0xff, 0xc7\n"
        ".byte 0xc3, 0xcc, 0xf1, 0x64, 0x67, 0x2e, 0x3e\n"
        "9:\n"
        :
        :
        : "memory");
#endif
  }
}

VMP_NOINLINE CaseOutcome runCaseThreaded(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
  CaseOutcome outcome{left, right, baseline(left, right), 0, false};
  static std::uint8_t plain[kMaxPayloadBytes];
  std::uint32_t plainSize = 0;
  if (!decryptPayload(artifact, plain, plainSize) || (plainSize % kInstructionSize) != 0) {
    return outcome;
  }

  std::uint64_t regs[16]{};
  regs[1] = left;
  regs[2] = right;
  std::uint32_t pc = 0;
  const std::uint32_t instructionCount = plainSize / kInstructionSize;
  std::uint8_t semantic = 0;
  std::uint8_t dst = 0;
  std::uint8_t src0 = 0;
  std::uint8_t src1 = 0;
  std::uint64_t imm = 0;
  std::uint64_t salt = mix64(artifact.authTag ^ left ^ (right << 1U));

#if defined(__GNUC__)
  static void *const dispatch[OpCount] = {
      &&op_bad,     &&op_load_imm, &&op_bad, &&op_bad, &&op_bad, &&op_add,
      &&op_bad,     &&op_bad,      &&op_bad, &&op_bad, &&op_xor,  &&op_bad,
      &&op_bad,     &&op_bad,      &&op_bad, &&op_bad, &&op_bad,  &&op_bad,
      &&op_bad,     &&op_ret,      &&op_bad, &&op_bad, &&op_bad,  &&op_bad,
      &&op_bad,     &&op_bad,      &&op_bad, &&op_bad, &&op_bad,
  };

entry:
  demoTrapIsland(salt ^ pc);
  if (pc >= instructionCount) {
    goto done;
  }
  {
    const std::size_t offset = static_cast<std::size_t>(pc) * kInstructionSize;
    semantic = artifact.decode[plain[offset]];
    dst = plain[offset + 1];
    src0 = plain[offset + 2];
    src1 = plain[offset + 3];
    imm = readU64At(plain + offset + 4);
  }
  if (semantic >= OpCount || dst >= 16 || src0 >= 16 || src1 >= 16) {
    goto done;
  }
  salt = mix64(salt ^ semantic ^ (static_cast<std::uint64_t>(pc) << 32U));
  goto *dispatch[semantic];

op_load_imm:
  if (demoOpaqueFalse(salt ^ imm)) {
    goto op_bad;
  }
  regs[dst] = imm ^ (salt & 0U);
  ++pc;
  goto entry;

op_add:
  if (demoOpaqueFalse(salt ^ regs[src0])) {
    goto op_bad;
  }
  regs[dst] = regs[src0] + regs[src1];
  ++pc;
  goto entry;

op_xor:
  if (demoOpaqueFalse(salt ^ regs[src1])) {
    goto op_bad;
  }
  regs[dst] = regs[src0] ^ regs[src1];
  ++pc;
  goto entry;

op_ret:
  outcome.protectedValue = regs[src0];
  outcome.ok = outcome.protectedValue == outcome.baselineValue;
  demoTrapIsland(salt ^ outcome.protectedValue);
  goto done;

op_bad:
  demoTrapIsland(salt ^ 0xbadc0ffee0ddf00dULL);

done:
  demoClear(reinterpret_cast<char *>(plain), plainSize);
  return outcome;
#else
  return runCase(artifact, left, right);
#endif
}
#endif

CaseOutcome runCase(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
  CaseOutcome outcome{left, right, baseline(left, right), 0, false};
  static std::uint8_t plain[kMaxPayloadBytes];
  std::uint32_t plainSize = 0;
  if (!decryptPayload(artifact, plain, plainSize) || (plainSize % kInstructionSize) != 0) {
    return outcome;
  }

  std::uint64_t regs[16]{};
  regs[1] = left;
  regs[2] = right;
  for (std::uint32_t pc = 0; pc < plainSize / kInstructionSize; ++pc) {
    const std::size_t offset = static_cast<std::size_t>(pc) * kInstructionSize;
    const std::uint8_t semantic = artifact.decode[plain[offset]];
    const std::uint8_t dst = plain[offset + 1];
    const std::uint8_t src0 = plain[offset + 2];
    const std::uint8_t src1 = plain[offset + 3];
    const std::uint64_t imm = readU64At(plain + offset + 4);
    if (dst >= 16 || src0 >= 16 || src1 >= 16) {
      return outcome;
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
      outcome.protectedValue = regs[src0];
      outcome.ok = outcome.protectedValue == outcome.baselineValue;
      return outcome;
    default:
      return outcome;
    }
  }
  return outcome;
}

bool executeCase(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
  return runCase(artifact, left, right).ok;
}

} // namespace

int protectedReleaseMain() {
  Artifact artifact{};
  if (!parseArtifact(artifact)) {
    return 40;
  }
#if defined(VMP_VISIBLE_PROTECTED_DEMO) && defined(_WIN32)
  const CaseOutcome cases[] = {
      runCaseThreaded(artifact, 7, 11),
      runCaseThreaded(artifact, 0, 0),
      runCaseThreaded(artifact, 0x1234, 0x00ff),
      runCaseThreaded(artifact, 0xffffffffULL, 0x55aa55aaULL),
  };
  int passed = 0;
  DemoIoContext io{};
  demoIoInit(io);
  demoDecompilerTrap(artifact.authTag);
  demoWriteText(io, artifact, kMsgVisible);
  demoWriteText(io, artifact, kMsgFunction);
  for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    passed += cases[i].ok ? 1 : 0;
    demoWriteCase(io, artifact, i + 1U, cases[i]);
  }
  demoWriteText(io, artifact, kMsgArtifactBytes);
  demoWriteU64(io, kProtectedSampleBlobSize);
  demoWriteText(io, artifact, kMsgNewline);
  demoWriteText(io, artifact, kMsgGetcharPause);
  demoIoFlush(io);
  getchar();
  getchar();
  getchar();
  demoClear(io.pending, sizeof(io.pending));
  return passed == 4 ? 0 : 30 + passed;
#else
  int passed = 0;
  passed += executeCase(artifact, 7, 11) ? 1 : 0;
  passed += executeCase(artifact, 0, 0) ? 1 : 0;
  passed += executeCase(artifact, 0x1234, 0x00ff) ? 1 : 0;
  passed += executeCase(artifact, 0xffffffffULL, 0x55aa55aaULL) ? 1 : 0;
  return passed == 4 ? 0 : 30 + passed;
#endif
}

#if defined(_WIN32) && defined(VMP_FREESTANDING_WINDOWS_ENTRY)
#if defined(VMP_WINDOWS_ENTRY_RETURNS_STATUS)
extern "C" int mainCRTStartup() {
  return protectedReleaseMain();
}
#else
extern "C" void mainCRTStartup() {
  ExitProcess(static_cast<unsigned int>(protectedReleaseMain()));
}
#endif
#elif defined(__linux__) && defined(VMP_FREESTANDING_LINUX_ENTRY)
#if !defined(__x86_64__)
#error "VMP_FREESTANDING_LINUX_ENTRY currently supports x86_64 only"
#endif
extern "C" int vmp_protected_release_main_entry() {
  return protectedReleaseMain();
}

extern "C" void _start();
asm(
    ".global _start\n"
    "_start:\n"
    "  xor %rbp, %rbp\n"
    "  andq $-16, %rsp\n"
    "  call vmp_protected_release_main_entry\n"
    "  movslq %eax, %rdi\n"
    "  mov $60, %rax\n"
    "  syscall\n"
    "  hlt\n");
#else
int main() {
  return protectedReleaseMain();
}
#endif
