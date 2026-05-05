#include "protected_sample_blob.h"

#include "../../src/core/Bytecode.h"
#include "../../src/runtime/VMRuntime.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace vmp;

constexpr std::array<std::uint8_t, 24> kEncodedSeed{
    0x2a, 0x28, 0x35, 0x2e, 0x3f, 0x39, 0x2e, 0x3f, 0x3e, 0x77, 0x29, 0x3b,
    0x37, 0x2a, 0x36, 0x3f, 0x77, 0x29, 0x3f, 0x3f, 0x3e, 0x77, 0x2c, 0x6b,
};
constexpr std::array<std::uint8_t, 8> kSampleArtifactMagic{
    0x8e, 0x52, 0xb9, 0x04, 0xd7, 0x6a, 0x31, 0xc8,
};

struct Artifact {
  core::OpcodeMap map;
  core::BytecodeChunk chunk;
};

void ensure(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

std::string seed() {
  std::string out;
  out.reserve(kEncodedSeed.size());
  for (std::uint8_t byte : kEncodedSeed) {
    out.push_back(static_cast<char>(byte ^ 0x5aU));
  }
  return out;
}

std::uint32_t readU32(std::size_t &offset) {
  ensure(offset + 4 <= kProtectedSampleBlobSize, "truncated u32");
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(kProtectedSampleBlob[offset++]) << (i * 8U);
  }
  return value;
}

std::uint64_t readU64(std::size_t &offset) {
  ensure(offset + 8 <= kProtectedSampleBlobSize, "truncated u64");
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(kProtectedSampleBlob[offset++]) << (i * 8U);
  }
  return value;
}

Artifact parseEmbeddedArtifact() {
  ensure(kProtectedSampleBlobSize >= kSampleArtifactMagic.size(), "artifact too short");
  ensure(std::equal(kSampleArtifactMagic.begin(), kSampleArtifactMagic.end(), kProtectedSampleBlob),
         "invalid artifact magic");

  std::size_t offset = kSampleArtifactMagic.size();
  Artifact artifact;
  artifact.chunk.version = readU32(offset);
  artifact.chunk.vmLevel = readU32(offset);
  artifact.chunk.functionHash = readU64(offset);
  artifact.chunk.platformSalt = readU64(offset);
  artifact.chunk.nonce = readU64(offset);
  artifact.chunk.authTag = readU64(offset);

  const auto opcodeCount = readU32(offset);
  ensure(opcodeCount == artifact.map.encode.size(), "unexpected opcode count");
  for (std::size_t i = 0; i < artifact.map.encode.size(); ++i) {
    ensure(offset < kProtectedSampleBlobSize, "truncated opcode map");
    const auto byte = kProtectedSampleBlob[offset++];
    artifact.map.encode[i] = byte;
    artifact.map.decode[byte] = static_cast<core::SemanticOpcode>(i);
    artifact.map.handlerOrder.push_back(static_cast<core::SemanticOpcode>(i));
  }

  const auto payloadSize = readU32(offset);
  ensure(offset + payloadSize == kProtectedSampleBlobSize, "unexpected payload size");
  artifact.chunk.encryptedPayload.assign(kProtectedSampleBlob + offset, kProtectedSampleBlob + kProtectedSampleBlobSize);
  return artifact;
}

std::uint64_t baseline(std::uint64_t left, std::uint64_t right) {
  return (left ^ right) + 0x5a5aULL;
}

bool runCase(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
  runtime::VMContext ctx;
  ctx.regs[1] = left;
  ctx.regs[2] = right;
  const auto status = runtime::executeEncryptedChunk(ctx, artifact.chunk, artifact.map, seed());
  return status == runtime::VMStatus::Ok && ctx.returnValue == baseline(left, right);
}

} // namespace

int main() {
  try {
    const auto artifact = parseEmbeddedArtifact();
    int passed = 0;
    passed += runCase(artifact, 7, 11) ? 1 : 0;
    passed += runCase(artifact, 0, 0) ? 1 : 0;
    passed += runCase(artifact, 0x1234, 0x00ff) ? 1 : 0;
    passed += runCase(artifact, 0xffffffffULL, 0x55aa55aaULL) ? 1 : 0;
    if (passed != 4) {
      return 30 + passed;
    }
    return 0;
  } catch (...) {
    return 40;
  }
}
