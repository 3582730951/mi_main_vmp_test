#include "NestedVM.h"

namespace vmp::runtime {

NestedVMResult executeWithNestedPolicy(VMContext &ctx, const core::BytecodeChunk &chunk,
                                       const core::OpcodeMap &map, std::string_view seed) {
    NestedVMResult result;
    if (chunk.vmLevel < 1 || chunk.vmLevel > 3) {
        result.status = VMStatus::PolicyDenied;
        return result;
    }

    result.vm0Used = chunk.vmLevel >= 2;
    result.vm2Used = chunk.vmLevel >= 3;
    result.status = executeEncryptedChunk(ctx, chunk, map, seed);
    if (result.status == VMStatus::Ok) {
        result.returnValue = ctx.returnValue;
    }
    return result;
}

} // namespace vmp::runtime
