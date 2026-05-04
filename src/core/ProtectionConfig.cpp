#include "ProtectionConfig.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace vmp::core {
namespace {

std::string trim(std::string_view input) {
    std::size_t first = 0;
    while (first < input.size() && std::isspace(static_cast<unsigned char>(input[first]))) {
        ++first;
    }
    std::size_t last = input.size();
    while (last > first && std::isspace(static_cast<unsigned char>(input[last - 1]))) {
        --last;
    }
    return std::string(input.substr(first, last - first));
}

std::string stripQuotes(std::string value) {
    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
                              (value.front() == '\'' && value.back() == '\''))) {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

bool parseBool(const std::string &value) {
    if (value == "true" || value == "yes" || value == "1") {
        return true;
    }
    if (value == "false" || value == "no" || value == "0") {
        return false;
    }
    throw std::invalid_argument("invalid boolean: " + value);
}

bool isAllowedProfile(const std::string &profile) {
    return profile == "balanced" || profile == "hardened" || profile == "paranoid";
}

bool isAllowedRootPolicy(const std::string &value) {
    return value == "false" || value == "true" || value == "platform";
}

std::uint32_t parseU32(const std::string &value) {
    std::size_t consumed = 0;
    const unsigned long parsed = std::stoul(value, &consumed, 10);
    if (consumed != value.size()) {
        throw std::invalid_argument("invalid integer: " + value);
    }
    return static_cast<std::uint32_t>(parsed);
}

std::pair<std::string, std::string> splitKeyValue(const std::string &line) {
    const auto pos = line.find(':');
    if (pos == std::string::npos) {
        throw std::invalid_argument("expected key: value line: " + line);
    }
    return {trim(std::string_view(line).substr(0, pos)), stripQuotes(trim(std::string_view(line).substr(pos + 1)))};
}

} // namespace

std::optional<FunctionProtection> ProtectionConfig::findFunction(std::string_view name) const {
    const auto it = std::find_if(functions.begin(), functions.end(), [&](const FunctionProtection &fn) {
        return fn.name == name || fn.match == name || fn.match == ("function:" + std::string(name));
    });
    if (it == functions.end()) {
        return std::nullopt;
    }
    return *it;
}

void ProtectionConfig::validate() const {
    if (version != 1) {
        throw std::invalid_argument("version must be 1");
    }
    if (vmLevel < 1 || vmLevel > 3) {
        throw std::invalid_argument("vm_level must be 1, 2, or 3");
    }
    if (seed.empty()) {
        throw std::invalid_argument("seed must not be empty");
    }
    if (!isAllowedProfile(profile)) {
        throw std::invalid_argument("profile must be balanced, hardened, or paranoid");
    }
    if (!isAllowedRootPolicy(antiAnalysis.rootOrJailbreak)) {
        throw std::invalid_argument("root_or_jailbreak must be false, true, or platform");
    }
    for (const auto &fn : functions) {
        if (fn.name.empty()) {
            throw std::invalid_argument("function name must not be empty");
        }
        if (!fn.match.empty() && fn.match.rfind("function:", 0) != 0) {
            throw std::invalid_argument("target match must use function:<name>");
        }
        if (fn.vmLevel < 1 || fn.vmLevel > 3) {
            throw std::invalid_argument("function vm_level must be 1, 2, or 3");
        }
    }
}

ProtectionConfig parseProtectionConfigText(std::string_view text) {
    ProtectionConfig config;
    std::istringstream in{std::string(text)};
    std::string raw;
    std::string section;
    std::string nestedSection;
    FunctionProtection *currentFunction = nullptr;

    while (std::getline(in, raw)) {
        const auto comment = raw.find('#');
        if (comment != std::string::npos) {
            raw.erase(comment);
        }
        std::size_t indent = 0;
        while (indent < raw.size() && raw[indent] == ' ') {
            ++indent;
        }
        std::string line = trim(raw);
        if (line.empty()) {
            continue;
        }

        if (indent == 0 && (line == "functions:" || line == "targets:" || line == "ollvm:" || line == "platforms:")) {
            section = line.substr(0, line.size() - 1);
            currentFunction = nullptr;
            nestedSection.clear();
            continue;
        }

        if ((section == "functions" || section == "targets") && indent <= 2 && line.rfind("- ", 0) == 0) {
            config.functions.push_back(FunctionProtection{});
            currentFunction = &config.functions.back();
            nestedSection.clear();
            line = trim(std::string_view(line).substr(2));
            if (!line.empty()) {
                const auto [key, value] = splitKeyValue(line);
                if (key == "name") {
                    currentFunction->name = value;
                } else if (key == "match") {
                    currentFunction->match = value;
                } else {
                    throw std::invalid_argument("unsupported function field: " + key);
                }
            }
            continue;
        }

        if (section == "targets" && currentFunction != nullptr && indent >= 4 && line.back() == ':') {
            nestedSection = line.substr(0, line.size() - 1);
            continue;
        }

        if (section == "targets" && (nestedSection == "strings" || nestedSection == "critical") &&
            line.rfind("- ", 0) == 0) {
            continue;
        }

        const auto [key, value] = splitKeyValue(line);
        if (section == "functions" && currentFunction != nullptr) {
            if (key == "name") {
                currentFunction->name = value;
            } else if (key == "match") {
                currentFunction->match = value;
            } else if (key == "vm_level") {
                currentFunction->vmLevel = parseU32(value);
            } else if (key == "protect") {
                currentFunction->protect = parseBool(value);
            } else {
                throw std::invalid_argument("unsupported function field: " + key);
            }
        } else if (section == "targets" && currentFunction != nullptr) {
            if (nestedSection.empty()) {
                if (key == "name") {
                    currentFunction->name = value;
                } else if (key == "match") {
                    currentFunction->match = value;
                } else if (key == "vm_level") {
                    currentFunction->vmLevel = parseU32(value);
                } else if (key == "protect") {
                    currentFunction->protect = parseBool(value);
                } else {
                    throw std::invalid_argument("unsupported target field: " + key);
                }
            } else if (nestedSection == "ollvm") {
                if (key == "split" || key == "block_split") {
                    config.ollvm.blockSplit = parseBool(value) ? 1U : 0U;
                } else if (key == "flatten") {
                    config.ollvm.flatten = parseBool(value) ? 1U : 0U;
                } else if (key == "bogus_branches" || key == "bogus_branch") {
                    config.ollvm.bogusBranch = parseBool(value) ? 1U : 0U;
                } else if (key == "substitution" || key == "instruction_substitution") {
                    config.ollvm.instructionSubstitution = parseBool(value) ? 1U : 0U;
                } else if (key == "const_string_encryption") {
                    config.ollvm.constStringEncryption = parseBool(value);
                } else {
                    throw std::invalid_argument("unsupported target ollvm field: " + key);
                }
            } else if (nestedSection == "anti_analysis") {
                if (key == "debug") {
                    config.antiAnalysis.debug = parseBool(value);
                    config.antiDebugHooks = config.antiAnalysis.debug;
                } else if (key == "hardware_breakpoints") {
                    config.antiAnalysis.hardwareBreakpoints = parseBool(value);
                } else if (key == "memory_breakpoints") {
                    config.antiAnalysis.memoryBreakpoints = parseBool(value);
                } else if (key == "injection") {
                    config.antiAnalysis.injection = parseBool(value);
                } else if (key == "hooks") {
                    config.antiAnalysis.hooks = parseBool(value);
                } else if (key == "root_or_jailbreak") {
                    config.antiAnalysis.rootOrJailbreak = value;
                } else {
                    throw std::invalid_argument("unsupported target anti_analysis field: " + key);
                }
            }
        } else if (section == "ollvm") {
            if (key == "block_split" || key == "split") {
                config.ollvm.blockSplit = value == "true" || value == "false" ? (parseBool(value) ? 1U : 0U) : parseU32(value);
            } else if (key == "flatten") {
                config.ollvm.flatten = value == "true" || value == "false" ? (parseBool(value) ? 1U : 0U) : parseU32(value);
            } else if (key == "bogus_branch" || key == "bogus_branches") {
                config.ollvm.bogusBranch = value == "true" || value == "false" ? (parseBool(value) ? 1U : 0U) : parseU32(value);
            } else if (key == "instruction_substitution" || key == "substitution") {
                config.ollvm.instructionSubstitution = value == "true" || value == "false" ? (parseBool(value) ? 1U : 0U) : parseU32(value);
            } else if (key == "const_string_encryption") {
                config.ollvm.constStringEncryption = parseBool(value);
            } else {
                throw std::invalid_argument("unsupported ollvm field: " + key);
            }
        } else if (section == "platforms") {
            continue;
        } else {
            if (key == "version") {
                config.version = parseU32(value);
            } else if (key == "profile") {
                config.profile = value;
            } else if (key == "seed") {
                config.seed = value;
            } else if (key == "vm_level") {
                config.vmLevel = parseU32(value);
            } else if (key == "anti_debug") {
                config.antiAnalysis.debug = parseBool(value);
                config.antiDebugHooks = config.antiAnalysis.debug;
            } else {
                throw std::invalid_argument("unsupported config field: " + key);
            }
        }
    }

    for (auto &fn : config.functions) {
        if (fn.vmLevel == 0) {
            fn.vmLevel = config.vmLevel;
        }
    }
    config.validate();
    return config;
}

ProtectionConfig parseProtectionConfigFile(const std::filesystem::path &path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("unable to open config file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return parseProtectionConfigText(buffer.str());
}

} // namespace vmp::core
