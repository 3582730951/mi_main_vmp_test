#include "protected_sample_blob.h"
#include "core/Aead.h"

#include "../../src/platform/platform_adapter.h"

#include <jni.h>
#ifdef VMP_ANDROID_NATIVE_ACTIVITY_SMOKE
#include <android/native_activity.h>
#ifdef VMP_ANDROID_NATIVE_ACTIVITY_SHORT_ENTRY
#define VMP_NATIVE_ACTIVITY_ENTRY a
#else
#define VMP_NATIVE_ACTIVITY_ENTRY ANativeActivity_onCreate
#endif
#endif

#include <cstddef>
#include <cstdint>

namespace {

constexpr std::uint8_t kMask = 0xa5U;
static const volatile std::uint8_t kSeed[] = {
    0xd5, 0xd7, 0xca, 0xd1, 0xc0, 0xc6, 0xd1, 0xc0, 0xc1, 0x88, 0xd6, 0xc4,
    0xc8, 0xd5, 0xc9, 0xc0, 0x88, 0xd6, 0xc0, 0xc0, 0xc1, 0x88, 0xd3, 0x94,
};
static const volatile std::uint8_t kPurpose[] = {
    0xc7, 0xdc, 0xd1, 0xc0, 0xc6, 0xca, 0xc1, 0xc0, 0x88, 0xc6, 0xcd, 0xd0, 0xcb, 0xce,
};
static const volatile std::uint8_t kClassName[] = {
    0xdd, 0x8a, 0xdc, 0x8a, 0xe4,
};
static const volatile std::uint8_t kSigBinary[] = {0x8d, 0xec, 0xec, 0x8c, 0xec};
static const volatile std::uint8_t kSigInt[] = {0x8d, 0x8c, 0xec};
#ifdef VMP_ANDROID_NATIVE_ACTIVITY_SMOKE
static const volatile std::uint8_t kLogClass[] = {
    0xc4, 0xcb, 0xc1, 0xd7, 0xca, 0xcc, 0xc1, 0x8a,
    0xd0, 0xd1, 0xcc, 0xc9, 0x8a, 0xe9, 0xca, 0xc2,
};
static const volatile std::uint8_t kLogSig[] = {
    0x8d, 0xe9, 0xcf, 0xc4, 0xd3, 0xc4, 0x8a, 0xc9, 0xc4, 0xcb,
    0xc2, 0x8a, 0xf6, 0xd1, 0xd7, 0xcc, 0xcb, 0xc2, 0x9e, 0xe9,
    0xcf, 0xc4, 0xd3, 0xc4, 0x8a, 0xc9, 0xc4, 0xcb, 0xc2, 0x8a,
    0xf6, 0xd1, 0xd7, 0xcc, 0xcb, 0xc2, 0x9e, 0x8c, 0xec,
};
static const volatile std::uint8_t kFinishName[] = {0xc3, 0xcc, 0xcb, 0xcc, 0xd6, 0xcd};
static const volatile std::uint8_t kVoidSig[] = {0x8d, 0x8c, 0xf3};
static const volatile std::uint8_t kSumLabel[] = {0xd6, 0xd0, 0xc8, 0x98};
static const volatile std::uint8_t kPlatformLabel[] = {
    0xd5, 0xc9, 0xc4, 0xd1, 0xc3, 0xca, 0xd7, 0xc8, 0x98,
};
static const volatile std::uint8_t kCasesLabel[] = {
    0xd5, 0xd7, 0xca, 0xd1, 0xc0, 0xc6, 0xd1, 0xc0,
    0xc1, 0xfa, 0xc6, 0xc4, 0xd6, 0xc0, 0xd6, 0x98,
};
#endif
constexpr std::uint8_t kSampleArtifactMagic[] = {0x8e, 0x52, 0xb9, 0x04, 0xd7, 0x6a, 0x31, 0xc8};
constexpr std::uint64_t kBytecodeMagic = 0x9de4b1a7c85f2301ULL;
constexpr std::size_t kOpcodeCount = 29;
constexpr std::size_t kMaxPayload = 512;

enum Op : std::uint8_t {
  OpNop = 0,
  OpLoadImm = 1,
  OpMov = 2,
  OpLoad = 3,
  OpStore = 4,
  OpAdd = 5,
  OpSub = 6,
  OpMul = 7,
  OpAnd = 8,
  OpOr = 9,
  OpXor = 10,
  OpRet = 19,
  OpHalt = 20,
};

struct ArtifactView {
  std::uint32_t version;
  std::uint32_t vmLevel;
  std::uint64_t functionHash;
  std::uint64_t platformSalt;
  std::uint64_t nonce;
  std::uint64_t authTag;
  std::uint8_t decode[256];
  const std::uint8_t *payload;
  std::uint32_t payloadSize;
};

void decodeBytes(const volatile std::uint8_t *encoded, std::size_t size, char *out) {
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<char>(encoded[i] ^ kMask);
  }
  out[size] = '\0';
}

std::uint32_t readU32(const std::uint8_t *data, std::size_t size, std::size_t *offset) {
  if (*offset + 4U > size) {
    return 0;
  }
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data[(*offset)++]) << (i * 8U);
  }
  return value;
}

std::uint64_t readU64(const std::uint8_t *data, std::size_t size, std::size_t *offset) {
  if (*offset + 8U > size) {
    return 0;
  }
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[(*offset)++]) << (i * 8U);
  }
  return value;
}

std::uint64_t stableHash64Decoded(const volatile std::uint8_t *data, std::size_t size, std::uint64_t seed) {
  std::uint64_t hash = seed;
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= static_cast<std::uint64_t>(data[i] ^ kMask);
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

void deriveKey(const ArtifactView &artifact, std::uint8_t key[32]) {
  std::uint64_t state = stableHash64Decoded(kSeed, sizeof(kSeed), 0xcbf29ce484222325ULL);
  state ^= mix64(artifact.functionHash);
  state ^= mix64(artifact.platformSalt);
  state ^= mix64(static_cast<std::uint64_t>(artifact.vmLevel));
  state ^= stableHash64Decoded(kPurpose, sizeof(kPurpose), 0x84222325cbf29ce4ULL);
  for (std::size_t i = 0; i < 32U; i += 8U) {
    state = mix64(state + static_cast<std::uint64_t>(i));
    for (unsigned j = 0; j < 8; ++j) {
      key[i + j] = static_cast<std::uint8_t>((state >> (j * 8U)) & 0xffU);
    }
  }
}

void writeU32(std::uint8_t *out, std::size_t *offset, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    out[(*offset)++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
  }
}

void writeU64(std::uint8_t *out, std::size_t *offset, std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    out[(*offset)++] = static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU);
  }
}

std::uint64_t foldTag64(const std::uint8_t tag[vmp::core::aead::kTagSize]) {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(tag[i]) << (i * 8U);
  }
  return value;
}

std::size_t associatedData(const ArtifactView &artifact, const std::uint8_t *encodedOpcodes, std::uint8_t *aad) {
  std::size_t offset = 0;
  writeU64(aad, &offset, kBytecodeMagic);
  writeU32(aad, &offset, artifact.version);
  writeU32(aad, &offset, artifact.vmLevel);
  writeU64(aad, &offset, artifact.functionHash);
  writeU64(aad, &offset, artifact.platformSalt);
  writeU64(aad, &offset, artifact.nonce);
  for (std::size_t i = 0; i < kOpcodeCount; ++i) {
    aad[offset++] = encodedOpcodes[i];
  }
  return offset;
}

bool verifyArtifactAEAD(const ArtifactView &artifact, const std::uint8_t key[32],
                        const std::uint8_t *encodedOpcodes) {
  if (artifact.payloadSize < vmp::core::aead::kTagSize) {
    return false;
  }
  const std::size_t cipherSize = artifact.payloadSize - vmp::core::aead::kTagSize;
  const std::uint8_t *providedTag = artifact.payload + cipherSize;
  std::uint8_t aad[8 + 4 + 4 + 8 + 8 + 8 + kOpcodeCount];
  const std::size_t aadSize = associatedData(artifact, encodedOpcodes, aad);
  std::uint8_t nonce[12];
  std::uint8_t polyKey[64];
  std::uint8_t expectedTag[vmp::core::aead::kTagSize];
  vmp::core::aead::nonce96(artifact.nonce, artifact.functionHash, artifact.vmLevel, nonce);
  vmp::core::aead::chacha20Block(key, nonce, 0, polyKey);
  vmp::core::aead::poly1305Mac(polyKey, aad, aadSize, artifact.payload, cipherSize, expectedTag);
  return vmp::core::aead::constantTimeEquals(providedTag, expectedTag, vmp::core::aead::kTagSize) &&
         foldTag64(expectedTag) == artifact.authTag;
}

bool parseArtifact(ArtifactView *artifact, const std::uint8_t **encodedOpcodes) {
  if (kProtectedSampleBlobSize < sizeof(kSampleArtifactMagic)) {
    return false;
  }
  for (std::size_t i = 0; i < sizeof(kSampleArtifactMagic); ++i) {
    if (kProtectedSampleBlob[i] != kSampleArtifactMagic[i]) {
      return false;
    }
  }
  for (std::size_t i = 0; i < 256U; ++i) {
    artifact->decode[i] = 0xffU;
  }
  std::size_t offset = sizeof(kSampleArtifactMagic);
  artifact->version = readU32(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  artifact->vmLevel = readU32(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  artifact->functionHash = readU64(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  artifact->platformSalt = readU64(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  artifact->nonce = readU64(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  artifact->authTag = readU64(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  const std::uint32_t opcodeCount = readU32(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  if (artifact->version != 1U || artifact->vmLevel < 1U || artifact->vmLevel > 3U || opcodeCount != kOpcodeCount ||
      offset + kOpcodeCount + 4U > kProtectedSampleBlobSize) {
    return false;
  }
  *encodedOpcodes = kProtectedSampleBlob + offset;
  for (std::size_t i = 0; i < kOpcodeCount; ++i) {
    const std::uint8_t byte = kProtectedSampleBlob[offset++];
    if (byte == 0U || artifact->decode[byte] != 0xffU) {
      return false;
    }
    artifact->decode[byte] = static_cast<std::uint8_t>(i);
  }
  artifact->payloadSize = readU32(kProtectedSampleBlob, kProtectedSampleBlobSize, &offset);
  if (artifact->payloadSize > kMaxPayload || offset + artifact->payloadSize != kProtectedSampleBlobSize) {
    return false;
  }
  artifact->payload = kProtectedSampleBlob + offset;
  std::uint8_t key[32];
  deriveKey(*artifact, key);
  return verifyArtifactAEAD(*artifact, key, *encodedOpcodes);
}

bool decryptPayload(const ArtifactView &artifact, const std::uint8_t *encodedOpcodes,
                    std::uint8_t out[kMaxPayload], std::size_t *plainSize) {
  if (artifact.payloadSize < vmp::core::aead::kTagSize) {
    return false;
  }
  *plainSize = artifact.payloadSize - vmp::core::aead::kTagSize;
  std::uint8_t key[32];
  deriveKey(artifact, key);
  if (!verifyArtifactAEAD(artifact, key, encodedOpcodes)) {
    return false;
  }
  std::uint8_t nonce[12];
  vmp::core::aead::nonce96(artifact.nonce, artifact.functionHash, artifact.vmLevel, nonce);
  vmp::core::aead::chacha20Xor(key, nonce, 1, artifact.payload, out, *plainSize);
  return true;
}

bool validReg(std::uint8_t reg) {
  return reg < 16U;
}

bool executeSample(const ArtifactView &artifact, const std::uint8_t *encodedOpcodes,
                   std::uint64_t left, std::uint64_t right) {
  std::uint8_t plain[kMaxPayload];
  std::size_t plainSize = 0;
  if (!decryptPayload(artifact, encodedOpcodes, plain, &plainSize) || (plainSize % 12U) != 0U) {
    return false;
  }
  std::uint64_t regs[16];
  for (std::size_t i = 0; i < 16U; ++i) {
    regs[i] = 0;
  }
  regs[1] = left;
  regs[2] = right;
  for (std::size_t pc = 0; pc < plainSize; pc += 12U) {
    const std::uint8_t op = artifact.decode[plain[pc]];
    const std::uint8_t dst = plain[pc + 1U];
    const std::uint8_t src0 = plain[pc + 2U];
    const std::uint8_t src1 = plain[pc + 3U];
    std::uint64_t imm = 0;
    for (unsigned i = 0; i < 8U; ++i) {
      imm |= static_cast<std::uint64_t>(plain[pc + 4U + i]) << (i * 8U);
    }
    switch (op) {
    case OpNop:
      break;
    case OpLoadImm:
      if (!validReg(dst)) return false;
      regs[dst] = imm;
      break;
    case OpMov:
      if (!validReg(dst) || !validReg(src0)) return false;
      regs[dst] = regs[src0];
      break;
    case OpAdd:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] + regs[src1];
      break;
    case OpSub:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] - regs[src1];
      break;
    case OpMul:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] * regs[src1];
      break;
    case OpAnd:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] & regs[src1];
      break;
    case OpOr:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] | regs[src1];
      break;
    case OpXor:
      if (!validReg(dst) || !validReg(src0) || !validReg(src1)) return false;
      regs[dst] = regs[src0] ^ regs[src1];
      break;
    case OpRet:
      if (!validReg(src0)) return false;
      return regs[src0] == ((left ^ right) + 0x5a5aULL);
    case OpHalt:
      return true;
    default:
      return false;
    }
  }
  return false;
}

int verifyProtectedSample() {
  ArtifactView artifact;
  const std::uint8_t *encodedOpcodes = nullptr;
  if (!parseArtifact(&artifact, &encodedOpcodes)) {
    return -1;
  }
  int passed = 0;
  passed += executeSample(artifact, encodedOpcodes, 7, 11) ? 1 : 0;
  passed += executeSample(artifact, encodedOpcodes, 0, 0) ? 1 : 0;
  passed += executeSample(artifact, encodedOpcodes, 0x1234, 0x00ff) ? 1 : 0;
  passed += executeSample(artifact, encodedOpcodes, 0xffffffffULL, 0x55aa55aaULL) ? 1 : 0;
  return passed;
}

} // namespace

#ifdef VMP_ANDROID_NATIVE_ACTIVITY_SMOKE
namespace {

char *appendDecoded(char *out, const volatile std::uint8_t *encoded, std::size_t size) {
  for (std::size_t i = 0; i < size; ++i) {
    *out++ = static_cast<char>(encoded[i] ^ kMask);
  }
  return out;
}

char *appendInt(char *out, int value) {
  if (value < 0) {
    *out++ = '-';
    value = -value;
  }
  char tmp[12];
  int count = 0;
  do {
    tmp[count++] = static_cast<char>('0' + (value % 10));
    value /= 10;
  } while (value != 0 && count < static_cast<int>(sizeof(tmp)));
  while (count > 0) {
    *out++ = tmp[--count];
  }
  return out;
}

void logNativeResult(JNIEnv *env, int sum, int platform, int cases) {
  char logClassName[sizeof(kLogClass) + 1U];
  char logSig[sizeof(kLogSig) + 1U];
  decodeBytes(kLogClass, sizeof(kLogClass), logClassName);
  decodeBytes(kLogSig, sizeof(kLogSig), logSig);
  jclass logClass = env->FindClass(logClassName);
  if (logClass == nullptr) {
    return;
  }
  char methodName[] = {'i', '\0'};
  jmethodID logMethod = env->GetStaticMethodID(logClass, methodName, logSig);
  if (logMethod == nullptr) {
    return;
  }

  char message[80];
  char *cursor = message;
  cursor = appendDecoded(cursor, kSumLabel, sizeof(kSumLabel));
  cursor = appendInt(cursor, sum);
  *cursor++ = ';';
  cursor = appendDecoded(cursor, kPlatformLabel, sizeof(kPlatformLabel));
  cursor = appendInt(cursor, platform);
  *cursor++ = ';';
  cursor = appendDecoded(cursor, kCasesLabel, sizeof(kCasesLabel));
  cursor = appendInt(cursor, cases);
  *cursor++ = ';';
  *cursor = '\0';

  char tag[] = {'M', '\0'};
  jstring tagString = env->NewStringUTF(tag);
  jstring messageString = env->NewStringUTF(message);
  if (tagString != nullptr && messageString != nullptr) {
    env->CallStaticIntMethod(logClass, logMethod, tagString, messageString);
  }
  if (messageString != nullptr) {
    env->DeleteLocalRef(messageString);
  }
  if (tagString != nullptr) {
    env->DeleteLocalRef(tagString);
  }
}

void finishNativeActivity(ANativeActivity *activity) {
  if (activity == nullptr || activity->env == nullptr || activity->clazz == nullptr) {
    return;
  }
  char finishName[sizeof(kFinishName) + 1U];
  char voidSig[sizeof(kVoidSig) + 1U];
  decodeBytes(kFinishName, sizeof(kFinishName), finishName);
  decodeBytes(kVoidSig, sizeof(kVoidSig), voidSig);
  jclass activityClass = activity->env->GetObjectClass(activity->clazz);
  if (activityClass == nullptr) {
    return;
  }
  jmethodID finishMethod = activity->env->GetMethodID(activityClass, finishName, voidSig);
  if (finishMethod != nullptr) {
    activity->env->CallVoidMethod(activity->clazz, finishMethod);
  }
}

} // namespace

extern "C" __attribute__((visibility("default"), used)) void VMP_NATIVE_ACTIVITY_ENTRY(
    ANativeActivity *activity,
    void *,
    std::size_t) {
  if (activity == nullptr || activity->env == nullptr) {
    return;
  }
  vmp_platform_init();
  const int sum = vmp_platform_protected_add(20, 22);
  const int platform = vmp_platform_probe().platform;
  const int cases = verifyProtectedSample();
  logNativeResult(activity->env, sum, platform, cases);
  finishNativeActivity(activity);
}
#else
static jint nativeProtectedAdd(JNIEnv *, jobject, jint lhs, jint rhs) {
  return static_cast<jint>(vmp_platform_protected_add(static_cast<int>(lhs), static_cast<int>(rhs)));
}

static jint nativeProbePlatform(JNIEnv *, jobject) {
  return static_cast<jint>(vmp_platform_probe().platform);
}

static jint nativeVerifyEmbeddedSample(JNIEnv *, jobject) {
  return verifyProtectedSample();
}

extern "C" __attribute__((visibility("default"), used)) jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  JNIEnv *env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
    return JNI_ERR;
  }

  char className[sizeof(kClassName) + 1U];
  char sigBinary[sizeof(kSigBinary) + 1U];
  char sigInt[sizeof(kSigInt) + 1U];
  decodeBytes(kClassName, sizeof(kClassName), className);
  decodeBytes(kSigBinary, sizeof(kSigBinary), sigBinary);
  decodeBytes(kSigInt, sizeof(kSigInt), sigInt);

  jclass smokeClass = env->FindClass(className);
  if (smokeClass == nullptr) {
    return JNI_ERR;
  }

  char nameA[] = {'a', '\0'};
  char nameB[] = {'b', '\0'};
  char nameC[] = {'c', '\0'};
  JNINativeMethod methods[] = {
      {nameA, sigBinary, reinterpret_cast<void *>(nativeProtectedAdd)},
      {nameB, sigInt, reinterpret_cast<void *>(nativeProbePlatform)},
      {nameC, sigInt, reinterpret_cast<void *>(nativeVerifyEmbeddedSample)},
  };
  if (env->RegisterNatives(smokeClass, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
    return JNI_ERR;
  }
  vmp_platform_init();
  return JNI_VERSION_1_6;
}
#endif
