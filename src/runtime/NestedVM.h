#pragma once

#include "VMRuntime.h"

namespace vmp::runtime {

struct NestedVMResult {
    VMStatus status = VMStatus::InvalidProgram;
    std::uint64_t returnValue = 0;
    bool vm0Used = false;
    bool vm2Used = false;
};

NestedVMResult executeWithNestedPolicy(VMContext &ctx, const core::BytecodeChunk &chunk,
                                       const core::OpcodeMap &map, std::string_view seed);

} // namespace vmp::runtime
