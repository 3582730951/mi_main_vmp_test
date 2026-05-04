#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace vmp::core {

struct OllvmStrength {
    std::uint32_t blockSplit = 0;
    std::uint32_t flatten = 0;
    std::uint32_t bogusBranch = 0;
    std::uint32_t instructionSubstitution = 0;
    bool constStringEncryption = true;
};

struct AntiAnalysisOptions {
    bool debug = false;
    bool hardwareBreakpoints = false;
    bool memoryBreakpoints = false;
    bool injection = false;
    bool hooks = false;
    std::string rootOrJailbreak = "false";
};

struct FunctionProtection {
    std::string name;
    std::string match;
    std::uint32_t vmLevel = 0;
    bool protect = true;
};

struct ProtectionConfig {
    std::uint32_t version = 1;
    std::string profile = "hardened";
    std::string seed = "development-seed";
    std::uint32_t vmLevel = 1;
    bool antiDebugHooks = false;
    AntiAnalysisOptions antiAnalysis;
    OllvmStrength ollvm;
    std::vector<FunctionProtection> functions;

    std::optional<FunctionProtection> findFunction(std::string_view name) const;
    void validate() const;
};

ProtectionConfig parseProtectionConfigText(std::string_view text);
ProtectionConfig parseProtectionConfigFile(const std::filesystem::path &path);

} // namespace vmp::core
