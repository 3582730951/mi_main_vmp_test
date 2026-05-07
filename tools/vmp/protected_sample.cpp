#include "../../src/core/IRLoweringSkeleton.h"
#include "../../src/core/ProtectionConfig.h"
#include "../../src/runtime/VMRuntime.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace vmp;

constexpr std::uint64_t kPlatformSaltBase = 0x9f82cda4f63b18e7ULL;
constexpr std::uint64_t kPlatformSaltStep = 0x6a09e667f3bcc909ULL;
constexpr std::string_view kFunctionName = "authorized_sample_behavior";
constexpr std::string_view kSeed = "protected-sample-seed-v1";
constexpr std::uint32_t kVmLevel = 2;
constexpr std::array<std::uint8_t, 8> kSampleArtifactMagic{
    0x8e, 0x52, 0xb9, 0x04, 0xd7, 0x6a, 0x31, 0xc8,
};

struct Artifact {
    core::OpcodeMap map;
    core::BytecodeChunk chunk;
};

struct CaseResult {
    std::uint64_t left;
    std::uint64_t right;
    std::uint64_t baseline;
    std::uint64_t protectedValue;
    runtime::VMStatus status;
};

void ensure(bool condition, const std::string &message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<core::Instruction> sampleProgram() {
    return {
        {core::SemanticOpcode::Xor, 3, 1, 2, 0},
        {core::SemanticOpcode::LoadImm, 4, 0, 0, 0x5a5aULL},
        {core::SemanticOpcode::Add, 5, 3, 4, 0},
        {core::SemanticOpcode::Ret, 0, 5, 0, 0},
    };
}

std::uint64_t baselineBehavior(std::uint64_t left, std::uint64_t right) {
    return (left ^ right) + 0x5a5aULL;
}

void appendU32(std::vector<std::uint8_t> &out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU));
    }
}

void appendU64(std::vector<std::uint8_t> &out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8U)) & 0xffU));
    }
}

std::uint32_t readU32(const std::vector<std::uint8_t> &bytes, std::size_t &offset) {
    ensure(offset + 4 <= bytes.size(), "truncated artifact while reading u32");
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset++]) << (i * 8U);
    }
    return value;
}

std::uint64_t readU64(const std::vector<std::uint8_t> &bytes, std::size_t &offset) {
    ensure(offset + 8 <= bytes.size(), "truncated artifact while reading u64");
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset++]) << (i * 8U);
    }
    return value;
}

std::vector<std::uint8_t> readFileBytes(const std::filesystem::path &path) {
    std::ifstream in(path, std::ios::binary);
    ensure(static_cast<bool>(in), "unable to open file: " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void writeFileBytes(const std::filesystem::path &path, const std::vector<std::uint8_t> &bytes) {
    std::ofstream out(path, std::ios::binary);
    ensure(static_cast<bool>(out), "unable to write file: " + path.string());
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

std::string jsonEscape(std::string_view value) {
    std::ostringstream out;
    for (char ch : value) {
        switch (ch) {
        case '\\':
            out << "\\\\";
            break;
        case '"':
            out << "\\\"";
            break;
        case '\n':
            out << "\\n";
            break;
        default:
            out << ch;
            break;
        }
    }
    return out.str();
}

std::string hex64(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

std::vector<std::uint8_t> serializeArtifact(const Artifact &artifact);

Artifact buildArtifactForSalt(std::uint64_t platformSalt) {
    const auto lowered = core::lowerAuthorizedFunctionSkeleton(kFunctionName, sampleProgram(), kSeed, platformSalt, kVmLevel);
    return {lowered.opcodeMap, lowered.chunk};
}

unsigned printableRunCount(const std::vector<std::uint8_t> &bytes, std::size_t minLength = 4) {
    unsigned count = 0;
    std::size_t run = 0;
    for (std::uint8_t byte : bytes) {
        if (byte >= 0x20 && byte <= 0x7e) {
            ++run;
            continue;
        }
        if (run >= minLength) {
            ++count;
        }
        run = 0;
    }
    if (run >= minLength) {
        ++count;
    }
    return count;
}

Artifact buildArtifact() {
    Artifact best = buildArtifactForSalt(kPlatformSaltBase);
    unsigned bestCount = printableRunCount(serializeArtifact(best));
    if (bestCount == 0) {
        return best;
    }
    for (std::uint64_t attempt = 1; attempt < 512; ++attempt) {
        Artifact candidate = buildArtifactForSalt(kPlatformSaltBase + attempt * kPlatformSaltStep);
        const unsigned count = printableRunCount(serializeArtifact(candidate));
        if (count < bestCount) {
            best = candidate;
            bestCount = count;
            if (bestCount == 0) {
                break;
            }
        }
    }
    return best;
}

std::vector<std::uint8_t> serializeArtifact(const Artifact &artifact) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), kSampleArtifactMagic.begin(), kSampleArtifactMagic.end());
    appendU32(out, artifact.chunk.version);
    appendU32(out, artifact.chunk.vmLevel);
    appendU64(out, artifact.chunk.functionHash);
    appendU64(out, artifact.chunk.platformSalt);
    appendU64(out, artifact.chunk.nonce);
    appendU64(out, artifact.chunk.authTag);
    appendU32(out, static_cast<std::uint32_t>(artifact.map.encode.size()));
    out.insert(out.end(), artifact.map.encode.begin(), artifact.map.encode.end());
    appendU32(out, static_cast<std::uint32_t>(artifact.chunk.encryptedPayload.size()));
    out.insert(out.end(), artifact.chunk.encryptedPayload.begin(), artifact.chunk.encryptedPayload.end());
    return out;
}

Artifact parseArtifact(const std::filesystem::path &path) {
    const auto bytes = readFileBytes(path);
    std::size_t offset = 0;
    ensure(bytes.size() >= kSampleArtifactMagic.size(), "artifact is too short");
    ensure(std::equal(kSampleArtifactMagic.begin(), kSampleArtifactMagic.end(), bytes.begin()),
           "invalid sample artifact magic");
    offset += kSampleArtifactMagic.size();

    Artifact artifact;
    artifact.chunk.version = readU32(bytes, offset);
    artifact.chunk.vmLevel = readU32(bytes, offset);
    artifact.chunk.functionHash = readU64(bytes, offset);
    artifact.chunk.platformSalt = readU64(bytes, offset);
    artifact.chunk.nonce = readU64(bytes, offset);
    artifact.chunk.authTag = readU64(bytes, offset);

    const auto opcodeCount = readU32(bytes, offset);
    ensure(opcodeCount == artifact.map.encode.size(), "unexpected opcode map size");
    for (std::size_t i = 0; i < artifact.map.encode.size(); ++i) {
        ensure(offset < bytes.size(), "truncated opcode map");
        const auto byte = bytes[offset++];
        artifact.map.encode[i] = byte;
        artifact.map.decode[byte] = static_cast<core::SemanticOpcode>(i);
        artifact.map.handlerOrder.push_back(static_cast<core::SemanticOpcode>(i));
    }

    const auto payloadSize = readU32(bytes, offset);
    ensure(offset + payloadSize == bytes.size(), "unexpected payload length");
    artifact.chunk.encryptedPayload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end());
    return artifact;
}

CaseResult runCase(const Artifact &artifact, std::uint64_t left, std::uint64_t right) {
    runtime::VMContext ctx;
    ctx.regs[1] = left;
    ctx.regs[2] = right;
    ctx.hooks.authorizeChunk = [](const core::BytecodeChunk &chunk) {
        return chunk.magic == core::kBytecodeMagic && chunk.encryptedPayload.size() <= 4096;
    };
    const auto status = runtime::executeEncryptedChunk(ctx, artifact.chunk, artifact.map, kSeed);
    return {left, right, baselineBehavior(left, right), ctx.returnValue, status};
}

std::vector<CaseResult> runBehaviorCases(const Artifact &artifact) {
    return {
        runCase(artifact, 7, 11),
        runCase(artifact, 0, 0),
        runCase(artifact, 0x1234, 0x00ff),
        runCase(artifact, 0xffffffffULL, 0x55aa55aaULL),
    };
}

std::uint64_t runBaselineLoop(std::uint32_t iterations) {
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 4> cases{{
        {7, 11},
        {0, 0},
        {0x1234, 0x00ff},
        {0xffffffffULL, 0x55aa55aaULL},
    }};
    std::uint64_t checksum = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        for (const auto &item : cases) {
            checksum ^= baselineBehavior(item.first + i, item.second);
        }
    }
    return checksum;
}

std::uint64_t runProtectedLoop(const Artifact &artifact, std::uint32_t iterations) {
    const std::array<std::pair<std::uint64_t, std::uint64_t>, 4> cases{{
        {7, 11},
        {0, 0},
        {0x1234, 0x00ff},
        {0xffffffffULL, 0x55aa55aaULL},
    }};
    std::uint64_t checksum = 0;
    for (std::uint32_t i = 0; i < iterations; ++i) {
        for (const auto &item : cases) {
            const auto result = runCase(artifact, item.first + i, item.second);
            ensure(result.status == runtime::VMStatus::Ok, "protected benchmark VM run failed");
            checksum ^= result.protectedValue;
        }
    }
    return checksum;
}

template <typename Fn>
std::pair<std::uint64_t, std::uint64_t> timeLoop(Fn &&fn) {
    const auto start = std::chrono::steady_clock::now();
    const auto checksum = fn();
    const auto stop = std::chrono::steady_clock::now();
    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
    return {static_cast<std::uint64_t>(nanos), checksum};
}

bool containsBytes(const std::vector<std::uint8_t> &haystack, std::string_view needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

void writeBehaviorReport(const std::filesystem::path &path, const Artifact &artifact) {
    const auto cases = runBehaviorCases(artifact);
    bool consistent = true;
    for (const auto &item : cases) {
        consistent = consistent && item.status == runtime::VMStatus::Ok && item.baseline == item.protectedValue;
    }

    std::ofstream out(path);
    ensure(static_cast<bool>(out), "unable to write behavior report");
    out << "{\n  \"schema\": \"vmp.sample.behavior.v1\",\n";
    out << "  \"consistent\": " << (consistent ? "true" : "false") << ",\n";
    out << "  \"cases\": [\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const auto &item = cases[i];
        out << "    {\"left\": " << item.left << ", \"right\": " << item.right << ", \"baseline\": "
            << item.baseline << ", \"protected\": " << item.protectedValue << ", \"status\": \""
            << runtime::statusName(item.status) << "\"}" << (i + 1 == cases.size() ? "\n" : ",\n");
    }
    out << "  ]\n}\n";
}

void writeStringReport(const std::filesystem::path &path, const std::filesystem::path &artifactPath) {
    const auto bytes = readFileBytes(artifactPath);
    const std::vector<std::pair<std::string, std::string_view>> critical = {
        {"authorization_token_marker", "CRITICAL_AUTHZ_TOKEN_SAMPLE"},
        {"license_endpoint_marker", "https://license.sample.invalid"},
        {"operator_note_marker", "AUTHORIZED_SOFTWARE_ONLY_MARKER"},
    };

    bool clean = true;
    std::ofstream out(path);
    ensure(static_cast<bool>(out), "unable to write string report");
    out << "{\n  \"schema\": \"vmp.sample.strings.v1\",\n";
    out << "  \"artifact\": \"" << jsonEscape(artifactPath.string()) << "\",\n";
    out << "  \"artifact_size\": " << bytes.size() << ",\n";
    out << "  \"critical_strings_absent\": ";
    for (const auto &item : critical) {
        clean = clean && !containsBytes(bytes, item.second);
    }
    out << (clean ? "true" : "false") << ",\n";
    out << "  \"checks\": [\n";
    for (std::size_t i = 0; i < critical.size(); ++i) {
        const auto present = containsBytes(bytes, critical[i].second);
        out << "    {\"label\": \"" << critical[i].first << "\", \"stable_hash\": \""
            << hex64(core::stableHash64(critical[i].second)) << "\", \"present\": "
            << (present ? "true" : "false") << "}" << (i + 1 == critical.size() ? "\n" : ",\n");
    }
    out << "  ]\n}\n";
}

void writeRandomnessReport(const std::filesystem::path &path, const Artifact &artifact) {
    const auto rebuilt = buildArtifact();
    const auto alternate = core::lowerAuthorizedFunctionSkeleton(kFunctionName, sampleProgram(), "alternate-sample-seed-v1",
                                                                 artifact.chunk.platformSalt, kVmLevel);
    std::set<std::uint8_t> uniqueOpcodes(artifact.map.encode.begin(), artifact.map.encode.end());

    std::ofstream out(path);
    ensure(static_cast<bool>(out), "unable to write randomness report");
    out << "{\n  \"schema\": \"vmp.sample.randomness.v1\",\n";
    out << "  \"vm_level\": " << artifact.chunk.vmLevel << ",\n";
    out << "  \"function_hash\": \"" << hex64(artifact.chunk.functionHash) << "\",\n";
    out << "  \"opcode_map_fingerprint\": \"" << hex64(artifact.map.fingerprint()) << "\",\n";
    out << "  \"nonce\": \"" << hex64(artifact.chunk.nonce) << "\",\n";
    out << "  \"auth_tag\": \"" << hex64(artifact.chunk.authTag) << "\",\n";
    out << "  \"payload_bytes\": " << artifact.chunk.encryptedPayload.size() << ",\n";
    out << "  \"unique_opcode_bytes\": " << uniqueOpcodes.size() << ",\n";
    out << "  \"deterministic_rebuild_match\": "
        << ((rebuilt.map.fingerprint() == artifact.map.fingerprint() && rebuilt.chunk.nonce == artifact.chunk.nonce)
                ? "true"
                : "false")
        << ",\n";
    out << "  \"alternate_seed_changes_opcode_map\": "
        << (alternate.opcodeMap.fingerprint() != artifact.map.fingerprint() ? "true" : "false") << "\n";
    out << "}\n";
}

void writeReports(const std::filesystem::path &outDir, const std::filesystem::path &artifactPath) {
    const auto artifact = parseArtifact(artifactPath);
    std::filesystem::create_directories(outDir);
    writeBehaviorReport(outDir / "behavior.json", artifact);
    writeStringReport(outDir / "strings.json", artifactPath);
    writeRandomnessReport(outDir / "randomness.json", artifact);
}

void writePerformanceReport(const std::filesystem::path &path, const std::filesystem::path &artifactPath,
                            std::uint32_t iterations) {
    const auto artifact = parseArtifact(artifactPath);
    const auto artifactBytes = readFileBytes(artifactPath).size();
    const auto baseline = timeLoop([&]() { return runBaselineLoop(iterations); });
    const auto protectedRun = timeLoop([&]() { return runProtectedLoop(artifact, iterations); });
    const double ratio = baseline.first == 0 ? 0.0 : static_cast<double>(protectedRun.first) / static_cast<double>(baseline.first);

    std::ofstream out(path);
    ensure(static_cast<bool>(out), "unable to write performance report");
    out << "{\n  \"schema\": \"vmp.sample.performance.v1\",\n";
    out << "  \"status\": \"pass\",\n";
    out << "  \"iterations\": " << iterations << ",\n";
    out << "  \"cases_per_iteration\": 4,\n";
    out << "  \"baseline_ns\": " << baseline.first << ",\n";
    out << "  \"protected_ns\": " << protectedRun.first << ",\n";
    out << "  \"baseline_checksum\": \"" << hex64(baseline.second) << "\",\n";
    out << "  \"protected_checksum\": \"" << hex64(protectedRun.second) << "\",\n";
    out << "  \"overhead_ratio\": " << std::fixed << std::setprecision(3) << ratio << ",\n";
    out << "  \"artifact_bytes\": " << artifactBytes << ",\n";
    out << "  \"defense_priority\": true,\n";
    out << "  \"scope_note\": \"Local sample benchmark; performance optimizations must not disable configured protection.\"\n";
    out << "}\n";
}

void buildCommand(const std::filesystem::path &outDir) {
    std::filesystem::create_directories(outDir);
    const auto artifactPath = outDir / "protected_sample.vmp";
    writeFileBytes(artifactPath, serializeArtifact(buildArtifact()));
    writeReports(outDir, artifactPath);
    std::cout << artifactPath.string() << '\n';
}

void verifyCommand(const std::filesystem::path &artifactPath) {
    const auto artifact = parseArtifact(artifactPath);
    const auto cases = runBehaviorCases(artifact);
    for (const auto &item : cases) {
        ensure(item.status == runtime::VMStatus::Ok, std::string("protected run failed: ") + runtime::statusName(item.status));
        ensure(item.baseline == item.protectedValue, "protected behavior diverged from baseline");
    }
    std::cout << "behavior consistent\n";
}

void demoCommand(const std::filesystem::path &artifactPath) {
    const auto artifact = parseArtifact(artifactPath);
    const auto bytes = readFileBytes(artifactPath);
    const auto cases = runBehaviorCases(artifact);
    const bool artifactHasPlaintext =
        containsBytes(bytes, "CRITICAL_AUTHZ_TOKEN_SAMPLE") ||
        containsBytes(bytes, "https://license.sample.invalid") ||
        containsBytes(bytes, "AUTHORIZED_SOFTWARE_ONLY_MARKER") ||
        printableRunCount(bytes) != 0;

    std::cout << "visible protected demo\n";
    std::cout << "demo_function=authorized_sample_behavior(left, right)\n";
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const auto &item = cases[i];
        const bool match = item.status == runtime::VMStatus::Ok && item.baseline == item.protectedValue;
        std::cout << "case " << (i + 1)
                  << ": left=" << item.left
                  << " right=" << item.right
                  << " baseline=" << item.baseline
                  << " protected=" << item.protectedValue
                  << " vm_status=" << runtime::statusName(item.status)
                  << " match=" << (match ? "yes" : "no")
                  << '\n';
    }
    std::cout << "artifact=" << artifactPath.string() << '\n';
    std::cout << "artifact_bytes=" << bytes.size() << '\n';
    std::cout << "artifact_printable_string_runs=" << printableRunCount(bytes) << '\n';
    std::cout << "artifact_plaintext_markers=" << (artifactHasPlaintext ? "present" : "absent") << '\n';
}

void usage(const char *argv0) {
    std::cerr << "usage:\n"
              << "  " << argv0 << " build <out-dir>\n"
              << "  " << argv0 << " verify <artifact>\n"
              << "  " << argv0 << " report <artifact> <out-dir>\n"
              << "  " << argv0 << " demo <artifact>\n"
              << "  " << argv0 << " benchmark <artifact> <report> [iterations]\n";
}

} // namespace

int main(int argc, char **argv) {
    try {
        if (argc < 3) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        const std::string command = argv[1];
        if (command == "build" && argc == 3) {
            buildCommand(argv[2]);
        } else if (command == "verify" && argc == 3) {
            verifyCommand(argv[2]);
        } else if (command == "report" && argc == 4) {
            writeReports(argv[3], argv[2]);
        } else if (command == "demo" && argc == 3) {
            demoCommand(argv[2]);
        } else if (command == "benchmark" && (argc == 4 || argc == 5)) {
            const auto iterations = argc == 5 ? static_cast<std::uint32_t>(std::stoul(argv[4])) : 2000U;
            ensure(iterations > 0, "benchmark iterations must be positive");
            writePerformanceReport(argv[3], argv[2], iterations);
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    } catch (const std::exception &ex) {
        std::cerr << "protected_sample failed: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
