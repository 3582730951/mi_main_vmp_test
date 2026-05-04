#pragma once

#include "Bytecode.h"

#include <string>
#include <vector>

namespace vmp::core {

struct LoweringReport {
    std::string functionName;
    std::uint64_t functionHash = 0;
    std::uint64_t opcodeMapFingerprint = 0;
    std::vector<std::string> diagnostics;
};

struct LoweringOutput {
    BytecodeChunk chunk;
    OpcodeMap opcodeMap;
    LoweringReport report;
};

LoweringOutput lowerAuthorizedFunctionSkeleton(std::string_view functionName, std::vector<Instruction> normalized,
                                               std::string_view seed, std::uint64_t platformSalt,
                                               std::uint32_t vmLevel);

} // namespace vmp::core
