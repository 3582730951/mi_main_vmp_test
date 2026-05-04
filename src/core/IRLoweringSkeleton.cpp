#include "IRLoweringSkeleton.h"

#include <stdexcept>

namespace vmp::core {

LoweringOutput lowerAuthorizedFunctionSkeleton(std::string_view functionName, std::vector<Instruction> normalized,
                                               std::string_view seed, std::uint64_t platformSalt,
                                               std::uint32_t vmLevel) {
    if (functionName.empty()) {
        throw std::invalid_argument("function name must not be empty");
    }
    if (normalized.empty()) {
        throw std::invalid_argument("normalized instruction list must not be empty");
    }

    const std::uint64_t functionHash = stableHash64(functionName);
    auto map = buildOpcodeMap(seed, functionHash, platformSalt, vmLevel);
    auto chunk = encryptChunk(normalized, map, seed, functionHash, platformSalt, vmLevel);

    LoweringReport report;
    report.functionName = std::string(functionName);
    report.functionHash = functionHash;
    report.opcodeMapFingerprint = map.fingerprint();
    report.diagnostics.push_back("skeleton lowering accepted pre-normalized VM instructions");

    return {chunk, map, report};
}

} // namespace vmp::core
