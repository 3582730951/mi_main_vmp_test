#include "../Bytecode.h"
#include "../ProtectionConfig.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace llvm;

namespace {

constexpr StringLiteral kPluginVersion = "0.1.0";

constexpr std::array<StringLiteral, 16> kPipelineStages = {
    "vmp-config-load",
    "vmp-function-marker",
    "vmp-hotspot-policy",
    "vmp-ir-normalize",
    "vmp-block-split",
    "vmp-flatten",
    "vmp-bogus-branch",
    "vmp-instruction-substitution",
    "vmp-const-string-encryption",
    "vmp-ir-to-bytecode",
    "vmp-opcode-randomize",
    "vmp-bytecode-encrypt",
    "vmp-nesting",
    "vmp-anti-analysis-hooks",
    "vmp-function-replacement",
    "vmp-report",
};

constexpr std::uint64_t kRuntimePlatformSalt = 0x766d706c6c766d70ULL;
constexpr std::uint32_t kDefaultRuntimeVmLevel = 2;
constexpr StringLiteral kLoweringName =
    "ir-subset-i32-i64-recursive-cfg-expr-bitwise-safe-dynshift-trunccast-stack-select-callhost-branch-phi-vm-runtime";
constexpr StringLiteral kGeneratedBytecodeMarker = "llvm-plugin-generated-bytecode-v1";
constexpr std::uint8_t kHostArgScratch0 = 14;
constexpr std::uint8_t kHostArgScratch1 = 15;

cl::opt<std::string> VMPConfigPath(
    "vmp-config",
    cl::desc("Path to a VM protection YAML config used by the VMP pass plugin"),
    cl::value_desc("path"),
    cl::init(""));

const vmp::core::ProtectionConfig &activeConfig() {
    static const vmp::core::ProtectionConfig Config = [] {
        if (!VMPConfigPath.empty()) {
            try {
                return vmp::core::parseProtectionConfigFile(VMPConfigPath.getValue());
            } catch (const std::exception &Error) {
                report_fatal_error(Twine("failed to load vmp config: ") + Error.what());
            }
        }
        if (const char *EnvConfig = std::getenv("VMP_PROTECT_CONFIG")) {
            if (EnvConfig[0] != '\0') {
                try {
                    return vmp::core::parseProtectionConfigFile(EnvConfig);
                } catch (const std::exception &Error) {
                    report_fatal_error(Twine("failed to load VMP_PROTECT_CONFIG: ") + Error.what());
                }
            }
        }
        vmp::core::ProtectionConfig DefaultConfig;
        if (const char *BuildSeed = std::getenv("VMP_BUILD_SEED")) {
            if (BuildSeed[0] != '\0') {
                DefaultConfig.seed = std::string("env-build:") + BuildSeed;
            }
        }
        if (DefaultConfig.seed.empty()) {
            std::random_device Random;
            const auto Now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            std::ostringstream Seed;
            Seed << "ephemeral-build:" << std::hex << static_cast<std::uint64_t>(Now) << ":"
                 << static_cast<std::uint64_t>(Random()) << ":" << static_cast<std::uint64_t>(Random());
            DefaultConfig.seed = Seed.str();
        }
        DefaultConfig.vmLevel = kDefaultRuntimeVmLevel;
        return DefaultConfig;
    }();
    return Config;
}

std::string seedMaterialForConfig(const vmp::core::ProtectionConfig &Config) {
    return std::to_string(vmp::core::stableHash64(Config.seed));
}

std::uint64_t seedHashForConfig(const vmp::core::ProtectionConfig &Config) {
    return vmp::core::stableHash64(Config.seed);
}

std::optional<std::uint32_t> metadataVmLevelForFunction(const Function &F) {
    MDNode *Node = F.getMetadata("vmp.vm_level");
    if (Node == nullptr || Node->getNumOperands() != 1) {
        return std::nullopt;
    }
    auto *Value = dyn_cast<ConstantAsMetadata>(Node->getOperand(0));
    if (Value == nullptr) {
        return std::nullopt;
    }
    auto *Level = dyn_cast<ConstantInt>(Value->getValue());
    if (Level == nullptr) {
        return std::nullopt;
    }
    const auto Parsed = static_cast<std::uint32_t>(Level->getZExtValue());
    if (Parsed < 1 || Parsed > 3) {
        return std::nullopt;
    }
    return Parsed;
}

std::uint32_t vmLevelForFunction(const vmp::core::ProtectionConfig &Config, const Function &F) {
    if (auto MetadataLevel = metadataVmLevelForFunction(F)) {
        return *MetadataLevel;
    }
    const std::string Name = F.getName().str();
    if (const auto FunctionConfig = Config.findFunction(Name)) {
        return FunctionConfig->vmLevel;
    }
    return Config.vmLevel;
}

bool functionHasExplicitVmLevel(const vmp::core::ProtectionConfig &Config, const Function &F) {
    const std::string Name = F.getName().str();
    if (const auto FunctionConfig = Config.findFunction(Name)) {
        return FunctionConfig->explicitVmLevel;
    }
    return false;
}

bool isKnownStage(StringRef Name) {
    for (StringRef Stage : kPipelineStages) {
        if (Name == Stage) {
            return true;
        }
    }
    return false;
}

StringRef stageKind(StringRef Name) {
    if (Name == "vmp-config-load") {
        return "config";
    }
    if (Name == "vmp-function-marker") {
        return "selector";
    }
    if (Name == "vmp-hotspot-policy") {
        return "analysis";
    }
    if (Name == "vmp-ir-normalize") {
        return "normalize";
    }
    if (Name == "vmp-block-split" || Name == "vmp-flatten" || Name == "vmp-bogus-branch" ||
        Name == "vmp-instruction-substitution") {
        return "transform";
    }
    if (Name == "vmp-const-string-encryption") {
        return "transform";
    }
    if (Name == "vmp-anti-analysis-hooks") {
        return "transform";
    }
    if (Name == "vmp-ir-to-bytecode") {
        return "lowering";
    }
    if (Name == "vmp-opcode-randomize" || Name == "vmp-bytecode-encrypt" || Name == "vmp-nesting") {
        return "bytecode_prep";
    }
    if (Name == "vmp-function-replacement") {
        return "replacement";
    }
    if (Name == "vmp-report") {
        return "report_only";
    }
    return "placeholder_noop";
}

bool stageIsImplemented(StringRef Name) {
    return stageKind(Name) != "placeholder_noop" && stageKind(Name) != "report_only";
}

bool shouldMarkFunction(const Function &F) {
    if (F.isDeclaration()) {
        return false;
    }
    const auto &Config = activeConfig();
    if (!Config.functions.empty()) {
        const std::string Name = F.getName().str();
        const auto FunctionConfig = Config.findFunction(Name);
        return FunctionConfig.has_value() && FunctionConfig->protect;
    }
    if (F.hasFnAttribute("vmp.protect")) {
        return true;
    }
    return F.getName().contains_insensitive("license") ||
           F.getName().contains_insensitive("secret") ||
           F.getName().contains_insensitive("auth");
}

bool isSelectedFunction(const Function &F) {
    return !F.isDeclaration() && F.getMetadata("vmp.protect") != nullptr;
}

std::string hex64(std::uint64_t Value) {
    std::ostringstream Out;
    Out << std::hex << std::setw(16) << std::setfill('0') << Value;
    return Out.str();
}

unsigned directCallSiteCount(const Function &Target) {
    unsigned Count = 0;
    for (const User *User : Target.users()) {
        if (isa<CallInst>(User)) {
            ++Count;
        }
    }
    return Count;
}

void setVmLevelMetadata(Function &F, std::uint32_t VmLevel) {
    LLVMContext &Ctx = F.getContext();
    auto *Value = ConstantInt::get(Type::getInt32Ty(Ctx), VmLevel);
    F.setMetadata("vmp.vm_level", MDNode::get(Ctx, ConstantAsMetadata::get(Value)));
}

bool applyHotspotPolicy(Module &M) {
    const auto &Config = activeConfig();
    if (!Config.hotspot.enabled) {
        return false;
    }

    bool Changed = false;
    LLVMContext &Ctx = M.getContext();
    const std::uint32_t HotVmLevel = std::max(Config.hotspot.hotVmLevel, Config.hotspot.defenseFloor);
    for (Function &F : M) {
        if (!isSelectedFunction(F)) {
            continue;
        }
        const unsigned Calls = directCallSiteCount(F);
        if (Calls < Config.hotspot.callSiteThreshold) {
            continue;
        }
        F.setMetadata("vmp.hotspot", MDNode::get(Ctx, MDString::get(Ctx, "static-callsite-threshold")));
        if (!(Config.hotspot.preserveExplicitVmLevel && functionHasExplicitVmLevel(Config, F))) {
            setVmLevelMetadata(F, HotVmLevel);
        }
        errs() << "VMPPassPlugin hotspot: function=" << F.getName() << " call_sites=" << Calls
               << " vm_level=" << vmLevelForFunction(Config, F) << "\n";
        Changed = true;
    }
    return Changed;
}

void recordStage(Module &M, StringRef StageName) {
    LLVMContext &Ctx = M.getContext();
    NamedMDNode *Stages = M.getOrInsertNamedMetadata("vmp.pipeline.stages");
    Stages->addOperand(MDNode::get(Ctx, MDString::get(Ctx, StageName)));
}

Value *buildOpaqueFalse(Function &F, IRBuilder<> &B) {
    for (Argument &Arg : F.args()) {
        if (!Arg.getType()->isIntegerTy()) {
            continue;
        }
        Value *Masked = B.CreateAnd(&Arg, ConstantInt::get(Arg.getType(), 0), "vmp.opaque.mask");
        return B.CreateICmpNE(Masked, ConstantInt::get(Arg.getType(), 0), "vmp.opaque.false");
    }
    return ConstantInt::getFalse(F.getContext());
}

bool insertBogusDispatch(Module &M) {
    bool Changed = false;
    for (Function &F : M) {
        if (!isSelectedFunction(F) || F.empty()) {
            continue;
        }

        BranchInst *Branch = nullptr;
        for (BasicBlock &BB : F) {
            auto *Candidate = dyn_cast<BranchInst>(BB.getTerminator());
            if (Candidate != nullptr && Candidate->isConditional()) {
                Branch = Candidate;
                break;
            }
        }
        if (Branch == nullptr) {
            continue;
        }
        BasicBlock *Source = Branch->getParent();

        BasicBlock *Dispatch = BasicBlock::Create(F.getContext(), "vmp.dispatch", &F, Branch->getSuccessor(0));
        BasicBlock *FakeXref = BasicBlock::Create(F.getContext(), "vmp.fake.xref", &F, Dispatch);

        Branch->removeFromParent();
        Dispatch->getInstList().push_back(Branch);

        for (unsigned Index = 0; Index < Branch->getNumSuccessors(); ++Index) {
            BasicBlock *Successor = Branch->getSuccessor(Index);
            for (PHINode &Phi : Successor->phis()) {
                Phi.replaceIncomingBlockWith(Source, Dispatch);
            }
        }

        IRBuilder<> FakeBuilder(FakeXref);
        FakeBuilder.CreateBr(Dispatch);

        IRBuilder<> EntryBuilder(Source);
        EntryBuilder.CreateCondBr(buildOpaqueFalse(F, EntryBuilder), FakeXref, Dispatch);
        Changed = true;
    }
    return Changed;
}

bool splitProtectedBlocks(Module &M) {
    SmallVector<Instruction *, 16> SplitPoints;
    for (Function &F : M) {
        if (!isSelectedFunction(F)) {
            continue;
        }
        for (BasicBlock &BB : F) {
            if (BB.getName().startswith("vmp.")) {
                continue;
            }
            Instruction *Terminator = BB.getTerminator();
            if (Terminator == nullptr || Terminator == &BB.front()) {
                continue;
            }
            unsigned NonPhiCount = 0;
            for (Instruction &I : BB) {
                if (isa<PHINode>(&I)) {
                    continue;
                }
                ++NonPhiCount;
            }
            if (NonPhiCount >= 2) {
                SplitPoints.push_back(Terminator);
            }
        }
    }

    for (Instruction *Point : SplitPoints) {
        Point->getParent()->splitBasicBlock(Point, "vmp.split");
    }
    return !SplitPoints.empty();
}

bool functionRequestsFlattening(const Function &F) {
    return F.hasFnAttribute("vmp.flatten") || F.getMetadata("vmp.flatten") != nullptr;
}

bool flattenOptInBranches(Module &M) {
    bool Changed = false;
    LLVMContext &Ctx = M.getContext();
    auto *I32Ty = Type::getInt32Ty(Ctx);
    for (Function &F : M) {
        if (!isSelectedFunction(F) || !functionRequestsFlattening(F)) {
            continue;
        }

        BranchInst *Branch = nullptr;
        for (BasicBlock &BB : F) {
            auto *Candidate = dyn_cast<BranchInst>(BB.getTerminator());
            if (Candidate == nullptr || !Candidate->isConditional() ||
                Candidate->getParent()->getName().startswith("vmp.flatten")) {
                continue;
            }
            if (!Candidate->getSuccessor(0)->phis().empty() || !Candidate->getSuccessor(1)->phis().empty()) {
                continue;
            }
            Branch = Candidate;
            break;
        }
        if (Branch == nullptr) {
            continue;
        }

        BasicBlock *Source = Branch->getParent();
        BasicBlock *TrueTarget = Branch->getSuccessor(0);
        BasicBlock *FalseTarget = Branch->getSuccessor(1);
        IRBuilder<> StateBuilder(Branch);
        Value *State = StateBuilder.CreateSelect(
            Branch->getCondition(),
            ConstantInt::get(I32Ty, 1),
            ConstantInt::get(I32Ty, 2),
            "vmp.flatten.state");

        BasicBlock *Dispatch = BasicBlock::Create(Ctx, "vmp.flatten.dispatch", &F, TrueTarget);
        BasicBlock *Trap = BasicBlock::Create(Ctx, "vmp.flatten.trap", &F, Dispatch);
        Branch->eraseFromParent();

        IRBuilder<> SourceBuilder(Source);
        SourceBuilder.CreateBr(Dispatch);

        IRBuilder<> DispatchBuilder(Dispatch);
        auto *Switch = DispatchBuilder.CreateSwitch(State, Trap, 2);
        Switch->addCase(ConstantInt::get(I32Ty, 1), TrueTarget);
        Switch->addCase(ConstantInt::get(I32Ty, 2), FalseTarget);

        IRBuilder<> TrapBuilder(Trap);
        TrapBuilder.CreateUnreachable();
        F.setMetadata("vmp.flattened", MDNode::get(Ctx, MDString::get(Ctx, "switch-dispatch")));
        Changed = true;
    }
    return Changed;
}

bool normalizeProtectedIr(Module &M) {
    unsigned Selected = 0;
    unsigned SwappedComparisons = 0;
    unsigned SwappedCommutativeOps = 0;
    for (Function &F : M) {
        if (!isSelectedFunction(F)) {
            continue;
        }
        ++Selected;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
                    if (isa<ConstantInt>(Cmp->getOperand(0)) && !isa<ConstantInt>(Cmp->getOperand(1))) {
                        Value *Left = Cmp->getOperand(0);
                        Cmp->setOperand(0, Cmp->getOperand(1));
                        Cmp->setOperand(1, Left);
                        Cmp->setPredicate(CmpInst::getSwappedPredicate(Cmp->getPredicate()));
                        ++SwappedComparisons;
                    }
                    continue;
                }
                auto *Binary = dyn_cast<BinaryOperator>(&I);
                if (Binary == nullptr || !Binary->isCommutative()) {
                    continue;
                }
                if (isa<ConstantInt>(Binary->getOperand(0)) && !isa<ConstantInt>(Binary->getOperand(1))) {
                    Value *Left = Binary->getOperand(0);
                    Binary->setOperand(0, Binary->getOperand(1));
                    Binary->setOperand(1, Left);
                    ++SwappedCommutativeOps;
                }
            }
        }
    }
    if (Selected == 0) {
        return false;
    }

    LLVMContext &Ctx = M.getContext();
    const std::string SelectedCount = "selected_functions=" + std::to_string(Selected);
    const std::string ComparisonCount = "swapped_comparisons=" + std::to_string(SwappedComparisons);
    const std::string CommutativeCount = "swapped_commutative_ops=" + std::to_string(SwappedCommutativeOps);
    Metadata *Operands[] = {
        MDString::get(Ctx, "vmp-ir-normalize"),
        MDString::get(Ctx, SelectedCount),
        MDString::get(Ctx, ComparisonCount),
        MDString::get(Ctx, CommutativeCount),
    };
    M.getOrInsertNamedMetadata("vmp.ir.normalization")->addOperand(MDNode::get(Ctx, Operands));
    return true;
}

bool hasPrintableRun(ArrayRef<std::uint8_t> Bytes, std::size_t MinRun = 4) {
    std::size_t Run = 0;
    for (std::uint8_t Byte : Bytes) {
        if (Byte >= 0x20 && Byte <= 0x7e) {
            ++Run;
            if (Run >= MinRun) {
                return true;
            }
            continue;
        }
        Run = 0;
    }
    return false;
}

std::optional<std::vector<std::uint8_t>> encryptableStringInitializer(const GlobalVariable &Global) {
    if (!Global.hasInitializer() || !Global.isConstant() || Global.getAddressSpace() != 0 ||
        Global.getName().startswith("vmp.")) {
        return std::nullopt;
    }
    if (!Global.hasPrivateLinkage() && !Global.hasInternalLinkage()) {
        return std::nullopt;
    }
    auto *ArrayTy = dyn_cast<ArrayType>(Global.getValueType());
    auto *Data = dyn_cast<ConstantDataArray>(Global.getInitializer());
    if (ArrayTy == nullptr || Data == nullptr || !ArrayTy->getElementType()->isIntegerTy(8) ||
        !Data->getElementType()->isIntegerTy(8) || Data->getNumElements() == 0) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> Bytes;
    Bytes.reserve(Data->getNumElements());
    for (unsigned Index = 0; Index < Data->getNumElements(); ++Index) {
        Bytes.push_back(static_cast<std::uint8_t>(Data->getElementAsInteger(Index)));
    }
    if (!hasPrintableRun(Bytes)) {
        return std::nullopt;
    }
    return Bytes;
}

std::string uniqueInternalName(Module &M, StringRef Base) {
    std::string Name = Base.str();
    unsigned Suffix = 0;
    while (M.getNamedValue(Name) != nullptr) {
        Name = (Base + "." + Twine(++Suffix)).str();
    }
    return Name;
}

bool encryptConstantStrings(Module &M) {
    struct EncryptedString {
        GlobalVariable *Global;
        std::uint8_t Key;
        std::uint64_t Length;
    };

    SmallVector<EncryptedString, 8> Encrypted;
    std::uint64_t TotalBytes = 0;
    LLVMContext &Ctx = M.getContext();
    for (GlobalVariable &Global : M.globals()) {
        auto Plain = encryptableStringInitializer(Global);
        if (!Plain.has_value()) {
            continue;
        }
        std::uint8_t Key = static_cast<std::uint8_t>(
            (vmp::core::stableHash64(Global.getName().str(), 0x6d1f2a4b9c3779b1ULL) & 0xffU) ^ 0xa5U);
        if (Key == 0) {
            Key = 0xa5;
        }
        std::vector<std::uint8_t> Cipher = *Plain;
        for (std::uint8_t &Byte : Cipher) {
            Byte ^= Key;
        }
        Global.setConstant(false);
        Global.setInitializer(ConstantDataArray::get(Ctx, Cipher));
        Global.setMetadata("vmp.const_string.encrypted", MDNode::get(Ctx, MDString::get(Ctx, "xor-ctor-decode")));
        Encrypted.push_back(EncryptedString{&Global, Key, static_cast<std::uint64_t>(Cipher.size())});
        TotalBytes += Cipher.size();
    }
    if (Encrypted.empty()) {
        return false;
    }

    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I8Ty = Type::getInt8Ty(Ctx);
    auto *I64Ty = Type::getInt64Ty(Ctx);
    auto *DecodeTy = FunctionType::get(VoidTy, false);
    auto *Decode = Function::Create(DecodeTy, GlobalValue::InternalLinkage, uniqueInternalName(M, "vmp.conststr.decode"), M);
    Decode->setVisibility(GlobalValue::HiddenVisibility);
    Decode->setDSOLocal(true);

    BasicBlock *Done = BasicBlock::Create(Ctx, "done", Decode);
    BasicBlock *Current = BasicBlock::Create(Ctx, "entry", Decode, Done);
    for (const EncryptedString &Item : Encrypted) {
        BasicBlock *Loop = BasicBlock::Create(Ctx, "vmp.str.loop", Decode, Done);
        BasicBlock *After = BasicBlock::Create(Ctx, "vmp.str.next", Decode, Done);
        IRBuilder<> CurrentBuilder(Current);
        CurrentBuilder.CreateBr(Loop);

        IRBuilder<> B(Loop);
        auto *Index = B.CreatePHI(I64Ty, 2, "vmp.str.i");
        Value *Zero = ConstantInt::get(I64Ty, 0);
        Value *Ptr = B.CreateInBoundsGEP(Item.Global->getValueType(), Item.Global, {Zero, Index}, "vmp.str.ptr");
        Value *Byte = B.CreateLoad(I8Ty, Ptr, "vmp.str.byte");
        Value *Decoded = B.CreateXor(Byte, ConstantInt::get(I8Ty, Item.Key), "vmp.str.decoded");
        B.CreateStore(Decoded, Ptr);
        Value *Next = B.CreateAdd(Index, ConstantInt::get(I64Ty, 1), "vmp.str.next");
        Value *Finished = B.CreateICmpEQ(Next, ConstantInt::get(I64Ty, Item.Length), "vmp.str.done");
        B.CreateCondBr(Finished, After, Loop);
        Index->addIncoming(Zero, Current);
        Index->addIncoming(Next, Loop);
        Current = After;
    }
    IRBuilder<> CurrentBuilder(Current);
    CurrentBuilder.CreateBr(Done);
    IRBuilder<> DoneBuilder(Done);
    DoneBuilder.CreateRetVoid();
    appendToGlobalCtors(M, Decode, 0);

    const std::string Count = "encrypted_globals=" + std::to_string(Encrypted.size());
    const std::string Bytes = "encrypted_bytes=" + std::to_string(TotalBytes);
    Metadata *Operands[] = {
        MDString::get(Ctx, "vmp-const-string-encryption"),
        MDString::get(Ctx, Count),
        MDString::get(Ctx, Bytes),
    };
    M.getOrInsertNamedMetadata("vmp.const_string.encryption")->addOperand(MDNode::get(Ctx, Operands));
    return true;
}

bool substituteIntegerComparisons(Module &M) {
    SmallVector<ICmpInst *, 16> Comparisons;
    for (Function &F : M) {
        if (!isSelectedFunction(F)) {
            continue;
        }
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *Cmp = dyn_cast<ICmpInst>(&I);
                if (Cmp == nullptr || !Cmp->getOperand(0)->getType()->isIntegerTy()) {
                    continue;
                }
                Comparisons.push_back(Cmp);
            }
        }
    }

    for (ICmpInst *Cmp : Comparisons) {
        auto *IntTy = cast<IntegerType>(Cmp->getOperand(0)->getType());
        const unsigned Width = IntTy->getBitWidth();
        IRBuilder<> B(Cmp);
        Value *Key = ConstantInt::get(IntTy, APInt(Width, 0x5a5a5a5a5a5a5a5aULL));
        Value *Mixed = B.CreateXor(Cmp->getOperand(0), Key, "vmp.sub.xor");
        Value *Restored = B.CreateXor(Mixed, Key, "vmp.sub.restore");
        Cmp->setOperand(0, Restored);
    }

    return !Comparisons.empty();
}

bool isRuntimeScalarType(const Type *Ty) {
    return Ty->isIntegerTy(32) || Ty->isIntegerTy(64);
}

unsigned runtimeScalarWidth(const Type *Ty) {
    auto *IntTy = dyn_cast<IntegerType>(Ty);
    return IntTy == nullptr ? 0U : IntTy->getBitWidth();
}

bool supportsVirtualizedRuntimeSignature(const Function &F) {
    if (!isRuntimeScalarType(F.getReturnType()) || F.arg_size() > 4) {
        return false;
    }
    const unsigned ReturnWidth = runtimeScalarWidth(F.getReturnType());
    for (const Argument &Arg : F.args()) {
        if (runtimeScalarWidth(Arg.getType()) != ReturnWidth) {
            return false;
        }
    }
    return true;
}

bool isExactOrdinaryAddBridge(const Function &Callee) {
    if (Callee.getName() != "ordinary_add" || Callee.isDeclaration() || Callee.arg_size() != 2 ||
        !Callee.hasLocalLinkage() || !Callee.getReturnType()->isIntegerTy(32) || Callee.size() != 1) {
        return false;
    }
    for (const Argument &Arg : Callee.args()) {
        if (!Arg.getType()->isIntegerTy(32)) {
            return false;
        }
    }

    const BasicBlock &Entry = Callee.getEntryBlock();
    const BinaryOperator *Add = nullptr;
    const ReturnInst *Ret = nullptr;
    for (const Instruction &I : Entry) {
        if (auto *BinOp = dyn_cast<BinaryOperator>(&I)) {
            if (Add != nullptr || BinOp->getOpcode() != Instruction::Add || !BinOp->getType()->isIntegerTy(32)) {
                return false;
            }
            Add = BinOp;
            continue;
        }
        if (auto *Return = dyn_cast<ReturnInst>(&I)) {
            if (Ret != nullptr || Return->getReturnValue() != Add) {
                return false;
            }
            Ret = Return;
            continue;
        }
        return false;
    }
    if (Add == nullptr || Ret == nullptr) {
        return false;
    }

    auto ArgIt = Callee.arg_begin();
    const Argument *First = &*ArgIt++;
    const Argument *Second = &*ArgIt;
    return (Add->getOperand(0) == First && Add->getOperand(1) == Second) ||
           (Add->getOperand(0) == Second && Add->getOperand(1) == First);
}

bool isSupportedHostBridgeCall(const CallInst &Call) {
    Function *Callee = Call.getCalledFunction();
    return Callee != nullptr && Call.arg_size() == 2 && Call.getType()->isIntegerTy(32) &&
           isExactOrdinaryAddBridge(*Callee);
}

bool isSupportedSelect(const SelectInst &Select) {
    if (!Select.getType()->isIntegerTy(32) || !Select.getTrueValue()->getType()->isIntegerTy(32) ||
        !Select.getFalseValue()->getType()->isIntegerTy(32)) {
        return false;
    }
    auto *Cmp = dyn_cast<ICmpInst>(Select.getCondition());
    return Cmp != nullptr && Cmp->getOperand(0)->getType()->isIntegerTy(32) &&
           Cmp->getOperand(1)->getType()->isIntegerTy(32) &&
           (Cmp->getPredicate() == ICmpInst::ICMP_EQ || Cmp->getPredicate() == ICmpInst::ICMP_NE ||
            Cmp->getPredicate() == ICmpInst::ICMP_SGT || Cmp->getPredicate() == ICmpInst::ICMP_SLT ||
            Cmp->getPredicate() == ICmpInst::ICMP_SGE || Cmp->getPredicate() == ICmpInst::ICMP_SLE ||
            Cmp->getPredicate() == ICmpInst::ICMP_UGT || Cmp->getPredicate() == ICmpInst::ICMP_ULT ||
            Cmp->getPredicate() == ICmpInst::ICMP_UGE || Cmp->getPredicate() == ICmpInst::ICMP_ULE);
}

bool isSupportedBoolToI32Cast(const CastInst &Cast) {
    if ((Cast.getOpcode() != Instruction::ZExt && Cast.getOpcode() != Instruction::SExt) ||
        !Cast.getType()->isIntegerTy(32) || !Cast.getOperand(0)->getType()->isIntegerTy(1)) {
        return false;
    }
    auto *Cmp = dyn_cast<ICmpInst>(Cast.getOperand(0));
    return Cmp != nullptr && Cmp->getOperand(0)->getType()->isIntegerTy(32) &&
           Cmp->getOperand(1)->getType()->isIntegerTy(32) &&
           (Cmp->getPredicate() == ICmpInst::ICMP_EQ || Cmp->getPredicate() == ICmpInst::ICMP_NE ||
            Cmp->getPredicate() == ICmpInst::ICMP_SGT || Cmp->getPredicate() == ICmpInst::ICMP_SLT ||
            Cmp->getPredicate() == ICmpInst::ICMP_SGE || Cmp->getPredicate() == ICmpInst::ICMP_SLE ||
            Cmp->getPredicate() == ICmpInst::ICMP_UGT || Cmp->getPredicate() == ICmpInst::ICMP_ULT ||
            Cmp->getPredicate() == ICmpInst::ICMP_UGE || Cmp->getPredicate() == ICmpInst::ICMP_ULE);
}

bool isSupportedI32ToNarrowTrunc(const CastInst &Cast) {
    if (Cast.getOpcode() != Instruction::Trunc || !Cast.getOperand(0)->getType()->isIntegerTy(32)) {
        return false;
    }
    auto *ResultTy = dyn_cast<IntegerType>(Cast.getType());
    if (ResultTy == nullptr) {
        return false;
    }
    const unsigned Width = ResultTy->getBitWidth();
    return Width == 1 || Width == 8 || Width == 16;
}

bool isSupportedNarrowTruncToI32Cast(const CastInst &Cast) {
    if ((Cast.getOpcode() != Instruction::ZExt && Cast.getOpcode() != Instruction::SExt) ||
        !Cast.getType()->isIntegerTy(32)) {
        return false;
    }
    auto *Trunc = dyn_cast<CastInst>(Cast.getOperand(0));
    return Trunc != nullptr && isSupportedI32ToNarrowTrunc(*Trunc);
}

bool isSupportedNarrowTruncToWideCast(const CastInst &Cast) {
    if (Cast.getOpcode() != Instruction::ZExt && Cast.getOpcode() != Instruction::SExt) {
        return false;
    }
    auto *ResultTy = dyn_cast<IntegerType>(Cast.getType());
    if (ResultTy == nullptr || ResultTy->getBitWidth() <= 32U) {
        return false;
    }
    auto *Trunc = dyn_cast<CastInst>(Cast.getOperand(0));
    return Trunc != nullptr && isSupportedI32ToNarrowTrunc(*Trunc);
}

bool isSupportedNarrowTruncViaWideToI32Cast(const CastInst &Cast) {
    if (Cast.getOpcode() != Instruction::Trunc || !Cast.getType()->isIntegerTy(32)) {
        return false;
    }
    auto *Wide = dyn_cast<CastInst>(Cast.getOperand(0));
    if (Wide == nullptr || !isSupportedNarrowTruncToWideCast(*Wide)) {
        return false;
    }
    return true;
}

bool isSupportedLocalScalarAlloca(const AllocaInst &Alloca) {
    auto *ArraySize = dyn_cast<ConstantInt>(Alloca.getArraySize());
    return Alloca.getType()->getPointerAddressSpace() == 0 && isRuntimeScalarType(Alloca.getAllocatedType()) &&
           ArraySize != nullptr && ArraySize->isOne();
}

const AllocaInst *asSupportedLocalScalarAlloca(const Value *Pointer) {
    if (Pointer == nullptr) {
        return nullptr;
    }
    auto *Alloca = dyn_cast<AllocaInst>(Pointer);
    if (Alloca == nullptr || !isSupportedLocalScalarAlloca(*Alloca)) {
        return nullptr;
    }
    return Alloca;
}

bool isSupportedLocalScalarLoad(const LoadInst &Load) {
    const AllocaInst *Slot = asSupportedLocalScalarAlloca(Load.getPointerOperand());
    return Load.isSimple() && isRuntimeScalarType(Load.getType()) && Slot != nullptr &&
           Slot->getAllocatedType() == Load.getType();
}

bool isSupportedLocalScalarStore(const StoreInst &Store) {
    const AllocaInst *Slot = asSupportedLocalScalarAlloca(Store.getPointerOperand());
    return Store.isSimple() && isRuntimeScalarType(Store.getValueOperand()->getType()) && Slot != nullptr &&
           Slot->getAllocatedType() == Store.getValueOperand()->getType();
}

bool isLocalMemoryInstruction(const Instruction &I) {
    return isa<AllocaInst>(&I) || isa<LoadInst>(&I) || isa<StoreInst>(&I);
}

bool isSupportedI32ShiftAmount(const Value *V) {
    auto *Constant = dyn_cast<ConstantInt>(V);
    if (Constant != nullptr) {
        return Constant->getType()->isIntegerTy(32) && Constant->getValue().getLimitedValue(32) < 32;
    }

    auto *Mask = dyn_cast<BinaryOperator>(V);
    if (Mask == nullptr || Mask->getOpcode() != Instruction::And || !Mask->getType()->isIntegerTy(32)) {
        return false;
    }
    auto *Lhs = dyn_cast<ConstantInt>(Mask->getOperand(0));
    auto *Rhs = dyn_cast<ConstantInt>(Mask->getOperand(1));
    return (Lhs != nullptr && Lhs->getType()->isIntegerTy(32) && Lhs->getZExtValue() == 31U) ||
           (Rhs != nullptr && Rhs->getType()->isIntegerTy(32) && Rhs->getZExtValue() == 31U);
}

bool isSupportedI32Shift(const BinaryOperator &BinOp) {
    return BinOp.getType()->isIntegerTy(32) &&
           (BinOp.getOpcode() == Instruction::Shl || BinOp.getOpcode() == Instruction::LShr ||
            BinOp.getOpcode() == Instruction::AShr) &&
           isSupportedI32ShiftAmount(BinOp.getOperand(1));
}

bool hasUnsupportedPoisonGeneratingFlags(const BinaryOperator &BinOp) {
    switch (BinOp.getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::Shl:
        return BinOp.hasNoUnsignedWrap() || BinOp.hasNoSignedWrap();
    case Instruction::LShr:
    case Instruction::AShr:
        return BinOp.isExact();
    default:
        return false;
    }
}

bool hasLocalMemoryInstructions(const Function &F) {
    for (const BasicBlock &BB : F) {
        for (const Instruction &I : BB) {
            if (isLocalMemoryInstruction(I)) {
                return true;
            }
        }
    }
    return false;
}

bool localMemoryShapeIsSafe(const Function &F) {
    unsigned SlotCount = 0;

    for (const BasicBlock &BB : F) {
        for (const Instruction &I : BB) {
            if (isa<PHINode>(&I)) {
                return false;
            }
            if (auto *Alloca = dyn_cast<AllocaInst>(&I)) {
                if (!isSupportedLocalScalarAlloca(*Alloca) || ++SlotCount > 32U) {
                    return false;
                }
                continue;
            }
            if (auto *Store = dyn_cast<StoreInst>(&I)) {
                if (!isSupportedLocalScalarStore(*Store)) {
                    return false;
                }
                continue;
            }
            if (auto *Load = dyn_cast<LoadInst>(&I)) {
                if (!isSupportedLocalScalarLoad(*Load)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool isLoweringSubsetInstruction(const Instruction &I) {
    if (auto *Alloca = dyn_cast<AllocaInst>(&I)) {
        return isSupportedLocalScalarAlloca(*Alloca);
    }
    if (auto *Load = dyn_cast<LoadInst>(&I)) {
        return isSupportedLocalScalarLoad(*Load);
    }
    if (auto *Store = dyn_cast<StoreInst>(&I)) {
        return isSupportedLocalScalarStore(*Store);
    }
    if (auto *BinOp = dyn_cast<BinaryOperator>(&I)) {
        if (!isRuntimeScalarType(BinOp->getType()) || hasUnsupportedPoisonGeneratingFlags(*BinOp)) {
            return false;
        }
        if (BinOp->getOpcode() == Instruction::Add || BinOp->getOpcode() == Instruction::Sub ||
            BinOp->getOpcode() == Instruction::Mul || BinOp->getOpcode() == Instruction::And ||
            BinOp->getOpcode() == Instruction::Or || BinOp->getOpcode() == Instruction::Xor) {
            return true;
        }
        return isSupportedI32Shift(*BinOp);
    }
    if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {
        if (!Cmp->getOperand(0)->getType()->isIntegerTy(32) || !Cmp->getOperand(1)->getType()->isIntegerTy(32)) {
            return false;
        }
        return Cmp->getPredicate() == ICmpInst::ICMP_EQ || Cmp->getPredicate() == ICmpInst::ICMP_NE ||
               Cmp->getPredicate() == ICmpInst::ICMP_SGT || Cmp->getPredicate() == ICmpInst::ICMP_SLT ||
               Cmp->getPredicate() == ICmpInst::ICMP_SGE || Cmp->getPredicate() == ICmpInst::ICMP_SLE ||
               Cmp->getPredicate() == ICmpInst::ICMP_UGT || Cmp->getPredicate() == ICmpInst::ICMP_ULT ||
               Cmp->getPredicate() == ICmpInst::ICMP_UGE || Cmp->getPredicate() == ICmpInst::ICMP_ULE;
    }
    if (auto *Select = dyn_cast<SelectInst>(&I)) {
        return isSupportedSelect(*Select);
    }
    if (auto *Cast = dyn_cast<CastInst>(&I)) {
        return isSupportedBoolToI32Cast(*Cast) || isSupportedI32ToNarrowTrunc(*Cast) ||
               isSupportedNarrowTruncToI32Cast(*Cast) || isSupportedNarrowTruncToWideCast(*Cast) ||
               isSupportedNarrowTruncViaWideToI32Cast(*Cast);
    }
    if (auto *Phi = dyn_cast<PHINode>(&I)) {
        if (!Phi->getType()->isIntegerTy(32)) {
            return false;
        }
        for (Value *Incoming : Phi->incoming_values()) {
            if (!Incoming->getType()->isIntegerTy(32)) {
                return false;
            }
        }
        return true;
    }
    if (auto *Branch = dyn_cast<BranchInst>(&I)) {
        return Branch->isConditional() || Branch->isUnconditional();
    }
    if (auto *Ret = dyn_cast<ReturnInst>(&I)) {
        return Ret->getNumOperands() == 1 && isRuntimeScalarType(Ret->getReturnValue()->getType());
    }
    if (auto *Call = dyn_cast<CallInst>(&I)) {
        return isSupportedHostBridgeCall(*Call);
    }
    return false;
}

bool fitsLoweringSubset(const Function &F) {
    for (const BasicBlock &BB : F) {
        for (const Instruction &I : BB) {
            if (!isLoweringSubsetInstruction(I)) {
                return false;
            }
        }
    }
    return true;
}

void appendU32(std::vector<std::uint8_t> &Out, std::uint32_t Value) {
    for (unsigned Index = 0; Index < 4; ++Index) {
        Out.push_back(static_cast<std::uint8_t>((Value >> (Index * 8U)) & 0xffU));
    }
}

void writeU32(std::vector<std::uint8_t> &Out, std::size_t Offset, std::uint32_t Value) {
    for (unsigned Index = 0; Index < 4; ++Index) {
        Out.at(Offset + Index) = static_cast<std::uint8_t>((Value >> (Index * 8U)) & 0xffU);
    }
}

void appendU64(std::vector<std::uint8_t> &Out, std::uint64_t Value) {
    for (unsigned Index = 0; Index < 8; ++Index) {
        Out.push_back(static_cast<std::uint8_t>((Value >> (Index * 8U)) & 0xffU));
    }
}

std::vector<std::uint8_t> serializeRuntimeArtifact(const vmp::core::OpcodeMap &Map,
                                                   const vmp::core::BytecodeChunk &Chunk,
                                                   std::uint64_t SeedHash) {
    std::vector<std::uint8_t> Out;
    const std::array<std::uint8_t, 8> Magic{0xd4, 0x13, 0x8a, 0x61, 0x2e, 0xc7, 0x90, 0x5b};
    Out.insert(Out.end(), Magic.begin(), Magic.end());
    const std::size_t SizeOffset = Out.size();
    appendU32(Out, 0);
    appendU32(Out, Chunk.version);
    appendU32(Out, Chunk.vmLevel);
    appendU64(Out, Chunk.functionHash);
    appendU64(Out, Chunk.platformSalt);
    appendU64(Out, Chunk.nonce);
    appendU64(Out, Chunk.authTag);
    appendU64(Out, SeedHash);
    appendU32(Out, static_cast<std::uint32_t>(Map.encode.size()));
    Out.insert(Out.end(), Map.encode.begin(), Map.encode.end());
    appendU32(Out, static_cast<std::uint32_t>(Chunk.encryptedPayload.size()));
    Out.insert(Out.end(), Chunk.encryptedPayload.begin(), Chunk.encryptedPayload.end());
    writeU32(Out, SizeOffset, static_cast<std::uint32_t>(Out.size()));
    return Out;
}

std::uint32_t readRuntimeArtifactU32(const std::vector<std::uint8_t> &Bytes, std::size_t Offset) {
    std::uint32_t Value = 0;
    for (unsigned Index = 0; Index < 4; ++Index) {
        Value |= static_cast<std::uint32_t>(Bytes.at(Offset + Index)) << (Index * 8U);
    }
    return Value;
}

std::uint64_t readRuntimeArtifactU64(const std::vector<std::uint8_t> &Bytes, std::size_t Offset) {
    std::uint64_t Value = 0;
    for (unsigned Index = 0; Index < 8; ++Index) {
        Value |= static_cast<std::uint64_t>(Bytes.at(Offset + Index)) << (Index * 8U);
    }
    return Value;
}

std::optional<std::vector<std::uint8_t>> globalInitializerBytes(const GlobalVariable &Global) {
    if (!Global.hasInitializer()) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> Bytes;
    if (auto *Data = dyn_cast<ConstantDataArray>(Global.getInitializer())) {
        if (!Data->getElementType()->isIntegerTy(8)) {
            return std::nullopt;
        }
        Bytes.reserve(Data->getNumElements());
        for (unsigned Index = 0; Index < Data->getNumElements(); ++Index) {
            Bytes.push_back(static_cast<std::uint8_t>(Data->getElementAsInteger(Index)));
        }
        return Bytes;
    }
    auto *Array = dyn_cast<ConstantArray>(Global.getInitializer());
    if (Array == nullptr) {
        return std::nullopt;
    }
    Bytes.reserve(Array->getNumOperands());
    for (Value *Operand : Array->operands()) {
        auto *Byte = dyn_cast<ConstantInt>(Operand);
        if (Byte == nullptr || Byte->getBitWidth() != 8) {
            return std::nullopt;
        }
        Bytes.push_back(static_cast<std::uint8_t>(Byte->getZExtValue()));
    }
    return Bytes;
}

struct RuntimeArtifactAudit {
    unsigned artifacts = 0;
    unsigned randomizedOpcodeMaps = 0;
    unsigned sealedPayloads = 0;
    unsigned vmLevelPolicies = 0;
};

bool auditRuntimeArtifact(const std::vector<std::uint8_t> &Bytes, RuntimeArtifactAudit &Audit) {
    constexpr std::array<std::uint8_t, 8> Magic{0xd4, 0x13, 0x8a, 0x61, 0x2e, 0xc7, 0x90, 0x5b};
    constexpr std::size_t MinimumHeaderBytes = 64;
    if (Bytes.size() < MinimumHeaderBytes || !std::equal(Magic.begin(), Magic.end(), Bytes.begin())) {
        return false;
    }
    const std::uint32_t TotalSize = readRuntimeArtifactU32(Bytes, 8);
    const std::uint32_t Version = readRuntimeArtifactU32(Bytes, 12);
    const std::uint32_t VmLevel = readRuntimeArtifactU32(Bytes, 16);
    const std::uint64_t Nonce = readRuntimeArtifactU64(Bytes, 36);
    const std::uint64_t AuthTag = readRuntimeArtifactU64(Bytes, 44);
    if (TotalSize != Bytes.size() || Version != 1 || VmLevel < 1 || VmLevel > 3) {
        return false;
    }

    std::size_t Offset = 64;
    const std::uint32_t MapSize = readRuntimeArtifactU32(Bytes, 60);
    if (MapSize != static_cast<std::uint32_t>(vmp::core::SemanticOpcode::Count) ||
        Offset + MapSize + sizeof(std::uint32_t) > Bytes.size()) {
        return false;
    }
    std::array<bool, 256> SeenOpcodes{};
    bool UniqueNonZeroOpcodes = true;
    for (std::size_t Index = 0; Index < MapSize; ++Index) {
        const std::uint8_t Opcode = Bytes.at(Offset + Index);
        if (Opcode == 0 || SeenOpcodes[Opcode]) {
            UniqueNonZeroOpcodes = false;
            break;
        }
        SeenOpcodes[Opcode] = true;
    }
    Offset += MapSize;
    const std::uint32_t PayloadSize = readRuntimeArtifactU32(Bytes, Offset);
    Offset += sizeof(std::uint32_t);
    if (PayloadSize == 0 || Offset + PayloadSize != Bytes.size()) {
        return false;
    }

    ++Audit.artifacts;
    if (UniqueNonZeroOpcodes) {
        ++Audit.randomizedOpcodeMaps;
    }
    if (Nonce != 0 && AuthTag != 0) {
        ++Audit.sealedPayloads;
    }
    ++Audit.vmLevelPolicies;
    return true;
}

RuntimeArtifactAudit auditRuntimeArtifacts(const Module &M) {
    RuntimeArtifactAudit Audit;
    for (const GlobalVariable &Global : M.globals()) {
        if (Global.getMetadata("vmp.generated.bytecode") == nullptr) {
            continue;
        }
        auto Bytes = globalInitializerBytes(Global);
        if (!Bytes.has_value()) {
            continue;
        }
        auditRuntimeArtifact(*Bytes, Audit);
    }
    return Audit;
}

bool recordIntegratedBytecodeStage(Module &M, StringRef StageName) {
    const RuntimeArtifactAudit Audit = auditRuntimeArtifacts(M);
    if (Audit.artifacts == 0) {
        return false;
    }
    bool StageSatisfied = false;
    if (StageName == "vmp-opcode-randomize") {
        StageSatisfied = Audit.randomizedOpcodeMaps == Audit.artifacts;
    } else if (StageName == "vmp-bytecode-encrypt") {
        StageSatisfied = Audit.sealedPayloads == Audit.artifacts;
    } else if (StageName == "vmp-nesting") {
        StageSatisfied = Audit.vmLevelPolicies == Audit.artifacts;
    }
    if (!StageSatisfied) {
        return false;
    }

    LLVMContext &Ctx = M.getContext();
    NamedMDNode *Preparation = M.getOrInsertNamedMetadata("vmp.bytecode.preparation");
    const std::string ArtifactCount = "artifacts=" + std::to_string(Audit.artifacts);
    const std::string OpcodeCount = "randomized_opcode_maps=" + std::to_string(Audit.randomizedOpcodeMaps);
    const std::string SealedCount = "sealed_payloads=" + std::to_string(Audit.sealedPayloads);
    const std::string VmPolicyCount = "vm_level_policies=" + std::to_string(Audit.vmLevelPolicies);
    Metadata *Operands[] = {
        MDString::get(Ctx, StageName),
        MDString::get(Ctx, ArtifactCount),
        MDString::get(Ctx, OpcodeCount),
        MDString::get(Ctx, SealedCount),
        MDString::get(Ctx, VmPolicyCount),
    };
    Preparation->addOperand(MDNode::get(Ctx, Operands));
    return true;
}

class RuntimeScalarLowering final {
public:
    explicit RuntimeScalarLowering(const Function &F) : Function_(F) {
        std::uint8_t Reg = 1;
        for (const Argument &Arg : F.args()) {
            ValueRegs_[&Arg] = Reg++;
        }
        NextReg_ = Reg;
    }

    std::optional<std::vector<vmp::core::Instruction>> lower() {
        resetFunctionState();
        if (!appendControlPath(&Function_.getEntryBlock())) {
            return std::nullopt;
        }
        return Program_;
    }

private:
    struct BranchCandidate {
        const BranchInst *branch = nullptr;
        SmallVector<const BasicBlock *, 8> prefixPath;
        bool unsupportedControl = false;
    };

    static bool isSupportedRuntimeScalar(const Value *V) {
        return isRuntimeScalarType(V->getType());
    }

    static bool isZeroIntegerConstant(const Value *V) {
        auto *Constant = dyn_cast<ConstantInt>(V);
        return Constant != nullptr && Constant->isZero();
    }

    static const Value *stripRestoringXor(const Value *V) {
        auto *Outer = dyn_cast<BinaryOperator>(V);
        if (Outer == nullptr || Outer->getOpcode() != Instruction::Xor) {
            return V;
        }

        const ConstantInt *OuterKey = dyn_cast<ConstantInt>(Outer->getOperand(0));
        const Value *InnerValue = Outer->getOperand(1);
        if (OuterKey == nullptr) {
            OuterKey = dyn_cast<ConstantInt>(Outer->getOperand(1));
            InnerValue = Outer->getOperand(0);
        }
        auto *Inner = dyn_cast<BinaryOperator>(InnerValue);
        if (OuterKey == nullptr || Inner == nullptr || Inner->getOpcode() != Instruction::Xor) {
            return V;
        }

        const ConstantInt *InnerKey = dyn_cast<ConstantInt>(Inner->getOperand(0));
        const Value *BaseValue = Inner->getOperand(1);
        if (InnerKey == nullptr) {
            InnerKey = dyn_cast<ConstantInt>(Inner->getOperand(1));
            BaseValue = Inner->getOperand(0);
        }
        if (InnerKey == nullptr || InnerKey->getValue() != OuterKey->getValue()) {
            return V;
        }
        return BaseValue;
    }

    static bool isOpaqueFalseMask(const Value *V) {
        V = stripRestoringXor(V);
        auto *Mask = dyn_cast<BinaryOperator>(V);
        return Mask != nullptr && Mask->getOpcode() == Instruction::And &&
               (isZeroIntegerConstant(Mask->getOperand(0)) || isZeroIntegerConstant(Mask->getOperand(1)));
    }

    static bool isGeneratedOpaqueFalseCondition(const Value *Condition) {
        if (isZeroIntegerConstant(Condition)) {
            return true;
        }
        auto *Cmp = dyn_cast<ICmpInst>(Condition);
        if (Cmp == nullptr || Cmp->getPredicate() != ICmpInst::ICMP_NE) {
            return false;
        }
        return (isOpaqueFalseMask(Cmp->getOperand(0)) && isZeroIntegerConstant(Cmp->getOperand(1))) ||
               (isOpaqueFalseMask(Cmp->getOperand(1)) && isZeroIntegerConstant(Cmp->getOperand(0)));
    }

    static bool isOpaqueFalseDispatchBranch(const BranchInst &Branch) {
        if (!Branch.isConditional() || !isGeneratedOpaqueFalseCondition(Branch.getCondition())) {
            return false;
        }
        const BasicBlock *FakeXref = Branch.getSuccessor(0);
        auto *FakeBranch = dyn_cast<BranchInst>(FakeXref->getTerminator());
        return FakeXref->size() == 1 && FakeBranch != nullptr && FakeBranch->isUnconditional() &&
               FakeBranch->getSuccessor(0) == Branch.getSuccessor(1);
    }

    static bool hasReservedOpaqueDispatchNames(const BranchInst &Branch) {
        if (!Branch.isConditional()) {
            return false;
        }
        if (Branch.getCondition()->hasName() &&
            Branch.getCondition()->getName().startswith("vmp.opaque.false")) {
            return true;
        }
        for (unsigned Index = 0; Index < Branch.getNumSuccessors(); ++Index) {
            if (Branch.getSuccessor(Index)->getName().startswith("vmp.fake.xref")) {
                return true;
            }
        }
        return false;
    }

    BranchCandidate findEntryConditionalBranch() const {
        SmallPtrSet<const BasicBlock *, 8> Seen;
        SmallVector<const BasicBlock *, 8> Path;
        const BasicBlock *Current = &Function_.getEntryBlock();
        while (Current != nullptr && Seen.insert(Current).second) {
            Path.push_back(Current);
            auto *Ret = dyn_cast<ReturnInst>(Current->getTerminator());
            if (Ret != nullptr) {
                return {};
            }

            auto *Branch = dyn_cast<BranchInst>(Current->getTerminator());
            if (Branch == nullptr) {
                return {nullptr, {}, true};
            }
            if (Branch->isUnconditional()) {
                Current = Branch->getSuccessor(0);
                continue;
            }
            if (isOpaqueFalseDispatchBranch(*Branch)) {
                Current = Branch->getSuccessor(1);
                continue;
            }
            return {Branch, Path, false};
        }
        return {nullptr, {}, true};
    }

    static bool isSupportedPredicate(ICmpInst::Predicate Predicate) {
        return Predicate == ICmpInst::ICMP_EQ || Predicate == ICmpInst::ICMP_NE ||
               Predicate == ICmpInst::ICMP_SGT || Predicate == ICmpInst::ICMP_SLT ||
               Predicate == ICmpInst::ICMP_SGE || Predicate == ICmpInst::ICMP_SLE ||
               Predicate == ICmpInst::ICMP_UGT || Predicate == ICmpInst::ICMP_ULT ||
               Predicate == ICmpInst::ICMP_UGE || Predicate == ICmpInst::ICMP_ULE;
    }

    static vmp::core::SemanticOpcode compareOpcode(ICmpInst::Predicate Predicate) {
        switch (Predicate) {
        case ICmpInst::ICMP_EQ:
            return vmp::core::SemanticOpcode::CmpEq;
        case ICmpInst::ICMP_NE:
            return vmp::core::SemanticOpcode::CmpNe;
        case ICmpInst::ICMP_SGT:
        case ICmpInst::ICMP_SLT:
            return vmp::core::SemanticOpcode::CmpSgt;
        case ICmpInst::ICMP_SGE:
            return vmp::core::SemanticOpcode::CmpSge;
        case ICmpInst::ICMP_SLE:
            return vmp::core::SemanticOpcode::CmpSle;
        case ICmpInst::ICMP_UGT:
        case ICmpInst::ICMP_ULT:
            return vmp::core::SemanticOpcode::CmpUgt;
        case ICmpInst::ICMP_UGE:
            return vmp::core::SemanticOpcode::CmpUge;
        case ICmpInst::ICMP_ULE:
            return vmp::core::SemanticOpcode::CmpUle;
        default:
            llvm_unreachable("unsupported i32 compare predicate");
        }
    }

    void appendCompare(ICmpInst::Predicate Predicate, std::uint8_t Lhs, std::uint8_t Rhs) {
        const bool SwapOperands = Predicate == ICmpInst::ICMP_SLT || Predicate == ICmpInst::ICMP_ULT;
        const std::uint8_t Left = SwapOperands ? Rhs : Lhs;
        const std::uint8_t Right = SwapOperands ? Lhs : Rhs;
        Program_.push_back({compareOpcode(Predicate), 0, Left, Right, 0});
    }

    struct LoweringState {
        DenseMap<const Value *, std::uint8_t> valueRegs;
        std::uint8_t nextReg = 1;
    };

    struct PathLowering {
        std::vector<vmp::core::Instruction> instructions;
        std::uint8_t returnReg = 0;
    };

    struct ControlPathLowering {
        std::vector<vmp::core::Instruction> instructions;
    };

    void resetFunctionState() {
        Program_.clear();
        ValueRegs_.clear();
        StackSlots_.clear();
        EmittedStores_.clear();
        std::uint8_t Reg = 1;
        for (const Argument &Arg : Function_.args()) {
            ValueRegs_[&Arg] = Reg++;
        }
        NextReg_ = Reg;
        ActiveReturnPath_.clear();
        AllowHostCalls_ = true;
    }

    LoweringState captureState() const {
        return LoweringState{ValueRegs_, NextReg_};
    }

    void restoreState(const LoweringState &State) {
        ValueRegs_ = State.valueRegs;
        NextReg_ = State.nextReg;
        StackSlots_.clear();
        EmittedStores_.clear();
        AllowHostCalls_ = true;
    }

    std::optional<PathLowering> lowerIsolatedReturnPath(const BasicBlock *Start, const LoweringState &BaseState) {
        Program_.clear();
        restoreState(BaseState);
        auto ReturnReg = lowerReturnPath(Start);
        if (!ReturnReg) {
            return std::nullopt;
        }
        return PathLowering{Program_, *ReturnReg};
    }

    std::optional<ControlPathLowering> lowerIsolatedControlPath(const BasicBlock *Start,
                                                                const LoweringState &BaseState) {
        Program_.clear();
        restoreState(BaseState);
        if (!appendControlPath(Start)) {
            return std::nullopt;
        }
        return ControlPathLowering{Program_};
    }

    std::optional<std::vector<vmp::core::Instruction>> lowerBranch(const ICmpInst &Cmp, const BranchInst &Branch,
                                                                   ArrayRef<const BasicBlock *> BranchPrefixPath) {
        Program_.clear();
        ValueRegs_.clear();
        StackSlots_.clear();
        EmittedStores_.clear();
        std::uint8_t Reg = 1;
        for (const Argument &Arg : Function_.args()) {
            ValueRegs_[&Arg] = Reg++;
        }
        NextReg_ = Reg;
        AllowHostCalls_ = true;

        const auto SavedPath = ActiveReturnPath_;
        ActiveReturnPath_.assign(BranchPrefixPath.begin(), BranchPrefixPath.end());
        auto Lhs = lowerValue(Cmp.getOperand(0));
        auto Rhs = lowerValue(Cmp.getOperand(1));
        ActiveReturnPath_ = SavedPath;
        if (!Lhs || !Rhs) {
            return std::nullopt;
        }

        appendCompare(Cmp.getPredicate(), *Lhs, *Rhs);
        const auto Prefix = Program_;
        const auto BranchBaseState = captureState();

        auto FalsePath = lowerIsolatedReturnPath(Branch.getSuccessor(1), BranchBaseState);
        auto TruePath = lowerIsolatedReturnPath(Branch.getSuccessor(0), BranchBaseState);
        if (!FalsePath || !TruePath) {
            return std::nullopt;
        }

        Program_ = Prefix;
        const std::size_t JumpIndex = Program_.size();
        Program_.push_back({vmp::core::SemanticOpcode::JumpIfZero, 0, 0, 0, 0});

        Program_.insert(Program_.end(), FalsePath->instructions.begin(), FalsePath->instructions.end());
        Program_.push_back({vmp::core::SemanticOpcode::Ret, 0, FalsePath->returnReg, 0, 0});

        const std::uint64_t TrueTarget = Program_.size();
        Program_[JumpIndex].imm = TrueTarget;

        Program_.insert(Program_.end(), TruePath->instructions.begin(), TruePath->instructions.end());
        Program_.push_back({vmp::core::SemanticOpcode::Ret, 0, TruePath->returnReg, 0, 0});
        return Program_;
    }

    std::optional<std::uint8_t> allocateReg() {
        while (NextReg_ == kHostArgScratch0 || NextReg_ == kHostArgScratch1) {
            ++NextReg_;
        }
        if (NextReg_ >= 16) {
            return std::nullopt;
        }
        return NextReg_++;
    }

    std::uint64_t stackOffsetFor(const AllocaInst *Alloca) {
        auto Found = StackSlots_.find(Alloca);
        if (Found != StackSlots_.end()) {
            return Found->second;
        }
        const std::uint64_t Offset = static_cast<std::uint64_t>(StackSlots_.size()) * 8ULL;
        StackSlots_[Alloca] = Offset;
        return Offset;
    }

    std::optional<std::uint8_t> emitLoadImm(std::uint64_t Imm) {
        auto Reg = allocateReg();
        if (!Reg) {
            return std::nullopt;
        }
        Program_.push_back({vmp::core::SemanticOpcode::LoadImm, *Reg, 0, 0, Imm});
        return Reg;
    }

    const StoreInst *findStoreForLoad(const LoadInst &Load) const {
        const AllocaInst *Slot = asSupportedLocalScalarAlloca(Load.getPointerOperand());
        if (Slot == nullptr) {
            return nullptr;
        }

        const StoreInst *LastStore = nullptr;
        for (const BasicBlock *BB : ActiveReturnPath_) {
            for (const Instruction &I : *BB) {
                if (&I == &Load) {
                    return LastStore;
                }
                auto *Store = dyn_cast<StoreInst>(&I);
                if (Store == nullptr || !isSupportedLocalScalarStore(*Store)) {
                    continue;
                }
                if (asSupportedLocalScalarAlloca(Store->getPointerOperand()) == Slot) {
                    LastStore = Store;
                }
            }
        }
        return nullptr;
    }

    bool emitStoreForLoad(const LoadInst &Load) {
        const StoreInst *Store = findStoreForLoad(Load);
        if (Store == nullptr) {
            return false;
        }
        if (EmittedStores_.count(Store) != 0) {
            return true;
        }
        const AllocaInst *Slot = asSupportedLocalScalarAlloca(Store->getPointerOperand());
        auto StoredReg = lowerValue(Store->getValueOperand());
        if (Slot == nullptr || !StoredReg) {
            return false;
        }
        Program_.push_back({vmp::core::SemanticOpcode::Store, 0, *StoredReg, 0, stackOffsetFor(Slot)});
        EmittedStores_.insert(Store);
        return true;
    }

    std::optional<std::uint8_t> lowerNarrowTruncExtensionToI32(unsigned ExtensionOpcode, const CastInst &Trunc) {
        auto SourceReg = lowerValue(Trunc.getOperand(0));
        if (!SourceReg) {
            return std::nullopt;
        }

        const unsigned Width = cast<IntegerType>(Trunc.getType())->getBitWidth();
        if (ExtensionOpcode == Instruction::ZExt) {
            auto MaskReg = emitLoadImm((1ULL << Width) - 1ULL);
            auto Reg = allocateReg();
            if (!MaskReg || !Reg) {
                return std::nullopt;
            }
            Program_.push_back({vmp::core::SemanticOpcode::And, *Reg, *SourceReg, *MaskReg, 0});
            return Reg;
        }

        if (ExtensionOpcode != Instruction::SExt) {
            return std::nullopt;
        }

        const unsigned ShiftAmount = 32U - Width;
        auto ShiftReg = emitLoadImm(ShiftAmount);
        auto ShiftedReg = allocateReg();
        auto Reg = allocateReg();
        if (!ShiftReg || !ShiftedReg || !Reg) {
            return std::nullopt;
        }
        Program_.push_back({vmp::core::SemanticOpcode::Shl, *ShiftedReg, *SourceReg, *ShiftReg, 0});
        Program_.push_back({vmp::core::SemanticOpcode::AShr, *Reg, *ShiftedReg, *ShiftReg, 0});
        return Reg;
    }

    void appendRebasedInstructions(ArrayRef<vmp::core::Instruction> Instructions, std::uint64_t Base) {
        for (vmp::core::Instruction Inst : Instructions) {
            if (Inst.op == vmp::core::SemanticOpcode::Jump ||
                Inst.op == vmp::core::SemanticOpcode::JumpIfZero) {
                Inst.imm += Base;
            }
            Program_.push_back(Inst);
        }
    }

    std::optional<std::uint8_t> lowerValue(const Value *V) {
        if (!isSupportedRuntimeScalar(V)) {
            return std::nullopt;
        }
        if (auto Found = ValueRegs_.find(V); Found != ValueRegs_.end()) {
            return Found->second;
        }

        if (auto *Constant = dyn_cast<ConstantInt>(V)) {
            auto Reg = emitLoadImm(Constant->getValue().getZExtValue());
            if (!Reg) {
                return std::nullopt;
            }
            ValueRegs_[V] = *Reg;
            return Reg;
        }

        auto *Load = dyn_cast<LoadInst>(V);
        if (Load != nullptr) {
            const AllocaInst *Slot = asSupportedLocalScalarAlloca(Load->getPointerOperand());
            if (Slot == nullptr || !emitStoreForLoad(*Load)) {
                return std::nullopt;
            }
            auto Reg = allocateReg();
            if (!Reg) {
                return std::nullopt;
            }
            Program_.push_back({vmp::core::SemanticOpcode::Load, *Reg, 0, 0, stackOffsetFor(Slot)});
            ValueRegs_[V] = *Reg;
            return Reg;
        }

        auto *BinOp = dyn_cast<BinaryOperator>(V);
        if (BinOp != nullptr) {
            vmp::core::SemanticOpcode Op;
            switch (BinOp->getOpcode()) {
            case Instruction::Add:
                Op = vmp::core::SemanticOpcode::Add;
                break;
            case Instruction::Sub:
                Op = vmp::core::SemanticOpcode::Sub;
                break;
            case Instruction::Mul:
                Op = vmp::core::SemanticOpcode::Mul;
                break;
            case Instruction::And:
                Op = vmp::core::SemanticOpcode::And;
                break;
            case Instruction::Or:
                Op = vmp::core::SemanticOpcode::Or;
                break;
            case Instruction::Xor:
                Op = vmp::core::SemanticOpcode::Xor;
                break;
            case Instruction::Shl:
                if (!isSupportedI32Shift(*BinOp)) {
                    return std::nullopt;
                }
                Op = vmp::core::SemanticOpcode::Shl;
                break;
            case Instruction::LShr:
                if (!isSupportedI32Shift(*BinOp)) {
                    return std::nullopt;
                }
                Op = vmp::core::SemanticOpcode::LShr;
                break;
            case Instruction::AShr:
                if (!isSupportedI32Shift(*BinOp)) {
                    return std::nullopt;
                }
                Op = vmp::core::SemanticOpcode::AShr;
                break;
            default:
                return std::nullopt;
            }

            auto Lhs = lowerValue(BinOp->getOperand(0));
            auto Rhs = lowerValue(BinOp->getOperand(1));
            auto Reg = allocateReg();
            if (!Lhs || !Rhs || !Reg) {
                return std::nullopt;
            }
            Program_.push_back({Op, *Reg, *Lhs, *Rhs, 0});
            ValueRegs_[V] = *Reg;
            return Reg;
        }

        auto *Call = dyn_cast<CallInst>(V);
        if (Call != nullptr) {
            if (!AllowHostCalls_ || !isSupportedHostBridgeCall(*Call)) {
                return std::nullopt;
            }
            auto First = lowerValue(Call->getArgOperand(0));
            auto Second = lowerValue(Call->getArgOperand(1));
            auto Reg = allocateReg();
            if (!First || !Second || !Reg) {
                return std::nullopt;
            }
            Program_.push_back({vmp::core::SemanticOpcode::CallHost, 1, *First, *Second, 0});
            Program_.push_back({vmp::core::SemanticOpcode::Mov, *Reg, 0, 0, 0});
            ValueRegs_[V] = *Reg;
            return Reg;
        }

        auto *Cast = dyn_cast<CastInst>(V);
        if (Cast != nullptr) {
            if (isSupportedBoolToI32Cast(*Cast)) {
                auto *Cmp = cast<ICmpInst>(Cast->getOperand(0));
                auto Lhs = lowerValue(Cmp->getOperand(0));
                auto Rhs = lowerValue(Cmp->getOperand(1));
                auto TrueReg = emitLoadImm(Cast->getOpcode() == Instruction::SExt ? 0xffffffffULL : 1ULL);
                auto FalseReg = emitLoadImm(0);
                auto Reg = allocateReg();
                if (!Lhs || !Rhs || !TrueReg || !FalseReg || !Reg) {
                    return std::nullopt;
                }
                appendCompare(Cmp->getPredicate(), *Lhs, *Rhs);
                Program_.push_back({vmp::core::SemanticOpcode::Select, *Reg, *TrueReg, *FalseReg, 0});
                ValueRegs_[V] = *Reg;
                return Reg;
            }

            if (!isSupportedNarrowTruncToI32Cast(*Cast)) {
                if (!isSupportedNarrowTruncViaWideToI32Cast(*Cast)) {
                    return std::nullopt;
                }
                auto *Wide = cast<CastInst>(Cast->getOperand(0));
                auto *Trunc = cast<CastInst>(Wide->getOperand(0));
                auto Reg = lowerNarrowTruncExtensionToI32(Wide->getOpcode(), *Trunc);
                if (!Reg) {
                    return std::nullopt;
                }
                ValueRegs_[V] = *Reg;
                return Reg;
            }

            auto *Trunc = cast<CastInst>(Cast->getOperand(0));
            auto Reg = lowerNarrowTruncExtensionToI32(Cast->getOpcode(), *Trunc);
            if (!Reg) {
                return std::nullopt;
            }
            ValueRegs_[V] = *Reg;
            return Reg;
        }

        auto *Select = dyn_cast<SelectInst>(V);
        if (Select == nullptr || !isSupportedSelect(*Select)) {
            return std::nullopt;
        }
        auto *Cmp = cast<ICmpInst>(Select->getCondition());
        auto TrueReg = lowerValue(Select->getTrueValue());
        auto FalseReg = lowerValue(Select->getFalseValue());
        auto Lhs = lowerValue(Cmp->getOperand(0));
        auto Rhs = lowerValue(Cmp->getOperand(1));
        auto Reg = allocateReg();
        if (!TrueReg || !FalseReg || !Lhs || !Rhs || !Reg) {
            return std::nullopt;
        }
        appendCompare(Cmp->getPredicate(), *Lhs, *Rhs);
        Program_.push_back({vmp::core::SemanticOpcode::Select, *Reg, *TrueReg, *FalseReg, 0});
        ValueRegs_[V] = *Reg;
        return Reg;
    }

    bool appendControlPath(const BasicBlock *Start) {
        SmallPtrSet<const BasicBlock *, 8> Seen;
        SmallVector<const BasicBlock *, 8> Path;
        const BasicBlock *Current = Start;
        const BasicBlock *Previous = nullptr;
        while (Current != nullptr && Seen.insert(Current).second) {
            Path.push_back(Current);
            auto *Ret = dyn_cast<ReturnInst>(Current->getTerminator());
            if (Ret != nullptr) {
                if (Ret->getNumOperands() != 1) {
                    return false;
                }
                const Value *ReturnValue = Ret->getReturnValue();
                if (auto *Phi = dyn_cast<PHINode>(ReturnValue)) {
                    if (Previous == nullptr) {
                        return false;
                    }
                    ReturnValue = Phi->getIncomingValueForBlock(Previous);
                    if (ReturnValue == nullptr) {
                        return false;
                    }
                }

                const auto SavedPath = ActiveReturnPath_;
                ActiveReturnPath_ = Path;
                auto ReturnReg = lowerValue(ReturnValue);
                ActiveReturnPath_ = SavedPath;
                if (!ReturnReg) {
                    return false;
                }
                Program_.push_back({vmp::core::SemanticOpcode::Ret, 0, *ReturnReg, 0, 0});
                return true;
            }

            auto *Branch = dyn_cast<BranchInst>(Current->getTerminator());
            if (Branch == nullptr) {
                return false;
            }
            if (Branch->isUnconditional()) {
                Previous = Current;
                Current = Branch->getSuccessor(0);
                continue;
            }
            if (isOpaqueFalseDispatchBranch(*Branch)) {
                Previous = Current;
                Current = Branch->getSuccessor(1);
                continue;
            }
            if (hasReservedOpaqueDispatchNames(*Branch)) {
                return false;
            }

            auto *Cmp = dyn_cast<ICmpInst>(Branch->getCondition());
            if (Cmp == nullptr || !isSupportedPredicate(Cmp->getPredicate())) {
                return false;
            }

            const auto SavedPath = ActiveReturnPath_;
            ActiveReturnPath_ = Path;
            auto Lhs = lowerValue(Cmp->getOperand(0));
            auto Rhs = lowerValue(Cmp->getOperand(1));
            ActiveReturnPath_ = SavedPath;
            if (!Lhs || !Rhs) {
                return false;
            }

            appendCompare(Cmp->getPredicate(), *Lhs, *Rhs);
            const auto Prefix = Program_;
            const auto BranchBaseState = captureState();

            auto FalsePath = lowerIsolatedControlPath(Branch->getSuccessor(1), BranchBaseState);
            auto TruePath = lowerIsolatedControlPath(Branch->getSuccessor(0), BranchBaseState);
            if (!FalsePath || !TruePath) {
                return false;
            }

            Program_ = Prefix;
            const std::size_t JumpIndex = Program_.size();
            Program_.push_back({vmp::core::SemanticOpcode::JumpIfZero, 0, 0, 0, 0});

            const std::uint64_t FalseBase = Program_.size();
            appendRebasedInstructions(FalsePath->instructions, FalseBase);

            const std::uint64_t TrueTarget = Program_.size();
            Program_[JumpIndex].imm = TrueTarget;

            appendRebasedInstructions(TruePath->instructions, TrueTarget);
            return true;
        }
        return false;
    }

    std::optional<std::uint8_t> lowerReturnPath(const BasicBlock *Start) {
        SmallPtrSet<const BasicBlock *, 8> Seen;
        SmallVector<const BasicBlock *, 8> Path;
        const BasicBlock *Current = Start;
        const BasicBlock *Previous = nullptr;
        while (Current != nullptr && Seen.insert(Current).second) {
            Path.push_back(Current);
            auto *Ret = dyn_cast<ReturnInst>(Current->getTerminator());
            if (Ret != nullptr) {
                if (Ret->getNumOperands() != 1) {
                    return std::nullopt;
                }
                const Value *ReturnValue = Ret->getReturnValue();
                if (auto *Phi = dyn_cast<PHINode>(ReturnValue)) {
                    if (Previous == nullptr) {
                        return std::nullopt;
                    }
                    ReturnValue = Phi->getIncomingValueForBlock(Previous);
                    if (ReturnValue == nullptr) {
                        return std::nullopt;
                    }
                }
                const auto SavedPath = ActiveReturnPath_;
                ActiveReturnPath_ = Path;
                auto ReturnReg = lowerValue(ReturnValue);
                ActiveReturnPath_ = SavedPath;
                return ReturnReg;
            }

            auto *Branch = dyn_cast<BranchInst>(Current->getTerminator());
            if (Branch == nullptr || !Branch->isUnconditional()) {
                return std::nullopt;
            }
            Previous = Current;
            Current = Branch->getSuccessor(0);
        }
        return std::nullopt;
    }

    std::optional<std::vector<vmp::core::Instruction>> lowerLinearReturn() {
        Program_.clear();
        ValueRegs_.clear();
        StackSlots_.clear();
        EmittedStores_.clear();
        std::uint8_t Reg = 1;
        for (const Argument &Arg : Function_.args()) {
            ValueRegs_[&Arg] = Reg++;
        }
        NextReg_ = Reg;
        AllowHostCalls_ = true;

        auto ReturnReg = lowerReturnPath(&Function_.getEntryBlock());
        if (!ReturnReg) {
            return std::nullopt;
        }
        Program_.push_back({vmp::core::SemanticOpcode::Ret, 0, *ReturnReg, 0, 0});
        return Program_;
    }

    const Function &Function_;
    std::vector<vmp::core::Instruction> Program_;
    DenseMap<const Value *, std::uint8_t> ValueRegs_;
    DenseMap<const AllocaInst *, std::uint64_t> StackSlots_;
    SmallPtrSet<const StoreInst *, 16> EmittedStores_;
    SmallVector<const BasicBlock *, 8> ActiveReturnPath_;
    std::uint8_t NextReg_ = 1;
    bool AllowHostCalls_ = true;
};

std::optional<std::vector<std::uint8_t>> lowerRuntimeArtifact(const Function &F,
                                                              const vmp::core::ProtectionConfig &Config) {
    if (!supportsVirtualizedRuntimeSignature(F)) {
        return std::nullopt;
    }
    if (!fitsLoweringSubset(F)) {
        return std::nullopt;
    }
    if (hasLocalMemoryInstructions(F) && !localMemoryShapeIsSafe(F)) {
        return std::nullopt;
    }

    const std::uint64_t FunctionHash = vmp::core::stableHash64(F.getName().str());
    const auto SeedMaterial = seedMaterialForConfig(Config);
    const auto VmLevel = vmLevelForFunction(Config, F);
    const auto Map = vmp::core::buildOpcodeMap(SeedMaterial, FunctionHash, kRuntimePlatformSalt, VmLevel);

    auto Program = RuntimeScalarLowering(F).lower();
    if (!Program) {
        return std::nullopt;
    }

    const auto Chunk = vmp::core::encryptChunk(*Program, Map, SeedMaterial, FunctionHash, kRuntimePlatformSalt, VmLevel);
    return serializeRuntimeArtifact(Map, Chunk, seedHashForConfig(Config));
}

bool bytecodeGlobalMatchesArtifact(const GlobalVariable &Global, const std::vector<std::uint8_t> &Artifact) {
    if (!Global.isConstant() || !Global.hasPrivateLinkage() || Global.getAddressSpace() != 0 ||
        Global.isThreadLocal() || Global.isExternallyInitialized() ||
        Global.getUnnamedAddr() != GlobalValue::UnnamedAddr::Global ||
        Global.getMetadata("vmp.generated.bytecode") == nullptr) {
        return false;
    }

    auto *ArrayTy = dyn_cast<ArrayType>(Global.getValueType());
    if (ArrayTy == nullptr || !ArrayTy->getElementType()->isIntegerTy(8) ||
        ArrayTy->getNumElements() != Artifact.size() || !Global.hasInitializer()) {
        return false;
    }

    auto *Data = dyn_cast<ConstantDataArray>(Global.getInitializer());
    if (Data != nullptr) {
        if (!Data->getElementType()->isIntegerTy(8) || Data->getNumElements() != Artifact.size()) {
            return false;
        }
        for (std::size_t Index = 0; Index < Artifact.size(); ++Index) {
            if (Data->getElementAsInteger(Index) != Artifact[Index]) {
                return false;
            }
        }
        return true;
    }

    auto *Array = dyn_cast<ConstantArray>(Global.getInitializer());
    if (Array == nullptr || Array->getNumOperands() != Artifact.size()) {
        return false;
    }
    for (std::size_t Index = 0; Index < Artifact.size(); ++Index) {
        auto *Byte = dyn_cast<ConstantInt>(Array->getOperand(Index));
        if (Byte == nullptr || Byte->getZExtValue() != Artifact[Index]) {
            return false;
        }
    }
    return true;
}

GlobalVariable *getOrCreateBytecodeGlobal(Module &M, Function &F, const vmp::core::ProtectionConfig &Config) {
    const std::string GlobalName = ("vmp.bytecode." + F.getName()).str();
    const auto Artifact = lowerRuntimeArtifact(F, Config);
    if (!Artifact.has_value()) {
        return nullptr;
    }

    if (auto *Existing = M.getNamedGlobal(GlobalName)) {
        return bytecodeGlobalMatchesArtifact(*Existing, *Artifact) ? Existing : nullptr;
    }

    LLVMContext &Ctx = M.getContext();
    SmallVector<Constant *, 128> Bytes;
    for (std::uint8_t Byte : *Artifact) {
        Bytes.push_back(ConstantInt::get(Type::getInt8Ty(Ctx), Byte));
    }

    auto *ArrayTy = ArrayType::get(Type::getInt8Ty(Ctx), Bytes.size());
    auto *Init = ConstantArray::get(ArrayTy, Bytes);
    auto *GV = new GlobalVariable(M, ArrayTy, true, GlobalValue::PrivateLinkage, Init, GlobalName);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(1));
    GV->setMetadata("vmp.generated.bytecode", MDNode::get(Ctx, MDString::get(Ctx, kGeneratedBytecodeMarker)));
    return GV;
}

const char *runtimeEntryNameFor(const Function &Target) {
    const bool IsI64 = Target.getReturnType()->isIntegerTy(64);
    if (IsI64) {
        switch (Target.arg_size()) {
        case 0:
            return "vmp_runtime_entry_i64";
        case 1:
            return "vmp_runtime_entry_i64_i64";
        case 2:
            return "vmp_runtime_entry_i64_i64_i64";
        case 3:
            return "vmp_runtime_entry_i64_i64_i64_i64";
        case 4:
            return "vmp_runtime_entry_i64_i64_i64_i64_i64";
        default:
            llvm_unreachable("unsupported runtime-entry argument count");
        }
    }
    switch (Target.arg_size()) {
    case 0:
        return "vmp_runtime_entry_i32";
    case 1:
        return "vmp_runtime_entry_i32_i32";
    case 2:
        return "vmp_runtime_entry_i32_i32_i32";
    case 3:
        return "vmp_runtime_entry_i32_i32_i32_i32";
    case 4:
        return "vmp_runtime_entry_i32_i32_i32_i32_i32";
    default:
        llvm_unreachable("unsupported runtime-entry argument count");
    }
}

FunctionType *runtimeEntryTypeFor(LLVMContext &Ctx, const Function &Target) {
    Type *I8PtrTy = Type::getInt8PtrTy(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *ScalarTy = Target.getReturnType()->isIntegerTy(64) ? I64Ty : I32Ty;
    SmallVector<Type *, 5> Params;
    Params.push_back(I8PtrTy);
    Params.push_back(I64Ty);
    Params.append(Target.arg_size(), ScalarTy);
    return FunctionType::get(ScalarTy, Params, false);
}

bool isAcceptableRuntimeEntryDeclaration(const Function &RuntimeEntry, FunctionType *ExpectedType) {
    return RuntimeEntry.isDeclaration() && RuntimeEntry.getFunctionType() == ExpectedType &&
           RuntimeEntry.hasExternalLinkage() && RuntimeEntry.getVisibility() == GlobalValue::DefaultVisibility &&
           RuntimeEntry.getDLLStorageClass() == GlobalValue::DefaultStorageClass &&
           RuntimeEntry.getCallingConv() == CallingConv::C && RuntimeEntry.getAttributes().isEmpty() &&
           RuntimeEntry.getSection().empty() && RuntimeEntry.getComdat() == nullptr && !RuntimeEntry.hasGC() &&
           !RuntimeEntry.hasPersonalityFn() && RuntimeEntry.getUnnamedAddr() == GlobalValue::UnnamedAddr::None;
}

bool runtimeEntrySymbolIsAvailable(Module &M, const Function &Target) {
    FunctionType *FnTy = runtimeEntryTypeFor(M.getContext(), Target);
    GlobalValue *Existing = M.getNamedValue(runtimeEntryNameFor(Target));
    if (Existing == nullptr) {
        return true;
    }
    auto *ExistingFunction = dyn_cast<Function>(Existing);
    return ExistingFunction != nullptr && isAcceptableRuntimeEntryDeclaration(*ExistingFunction, FnTy);
}

Function *getOrCreateRuntimeEntry(Module &M, const Function &Target) {
    FunctionType *FnTy = runtimeEntryTypeFor(M.getContext(), Target);
    const char *Name = runtimeEntryNameFor(Target);
    if (GlobalValue *Existing = M.getNamedValue(Name)) {
        auto *ExistingFunction = dyn_cast<Function>(Existing);
        if (ExistingFunction == nullptr || !isAcceptableRuntimeEntryDeclaration(*ExistingFunction, FnTy)) {
            return nullptr;
        }
        return ExistingFunction;
    }
    return Function::Create(FnTy, GlobalValue::ExternalLinkage, Name, M);
}

void markUnsupportedLowering(Function &F, StringRef Reason) {
    F.setMetadata("vmp.bytecode", nullptr);
    F.setMetadata("vmp.lowering", nullptr);
    F.setMetadata("vmp.replaced", nullptr);
    F.setMetadata("vmp.unsupported", MDNode::get(F.getContext(), MDString::get(F.getContext(), Reason)));
    errs() << "VMPPassPlugin unsupported lowering: function=" << F.getName() << " reason=" << Reason << "\n";
}

void clearVmpProtectionMetadata(Function &F) {
    F.setMetadata("vmp.protect", nullptr);
    F.setMetadata("vmp.bytecode", nullptr);
    F.setMetadata("vmp.lowering", nullptr);
    F.setMetadata("vmp.replaced", nullptr);
    F.setMetadata("vmp.unsupported", nullptr);
    F.setMetadata("vmp.hotspot", nullptr);
    F.setMetadata("vmp.vm_level", nullptr);
    F.setMetadata("vmp.decompiler.trap", nullptr);
}

bool materializeBytecodeGlobals(Module &M) {
    bool Changed = false;
    LLVMContext &Ctx = M.getContext();
    const auto &Config = activeConfig();
    for (Function &F : M) {
        if (!isSelectedFunction(F) || F.isDeclaration()) {
            continue;
        }
        if (!supportsVirtualizedRuntimeSignature(F)) {
            markUnsupportedLowering(F, "unsupported-signature");
            Changed = true;
            continue;
        }
        if (!runtimeEntrySymbolIsAvailable(M, F)) {
            markUnsupportedLowering(F, "runtime-entry-collision");
            Changed = true;
            continue;
        }
        GlobalVariable *Bytecode = getOrCreateBytecodeGlobal(M, F, Config);
        if (Bytecode == nullptr) {
            markUnsupportedLowering(F, "unsupported-ir-subset");
            Changed = true;
            continue;
        }
        Metadata *Ops[] = {ValueAsMetadata::get(Bytecode)};
        F.setMetadata("vmp.bytecode", MDNode::get(Ctx, Ops));
        F.setMetadata("vmp.lowering", MDNode::get(Ctx, MDString::get(Ctx, kLoweringName)));
        F.setMetadata("vmp.unsupported", nullptr);
        Changed = true;
    }
    return Changed;
}

void normalizeOutlinedClone(Function &Clone) {
    Clone.setLinkage(GlobalValue::InternalLinkage);
    Clone.setVisibility(GlobalValue::DefaultVisibility);
    Clone.setDLLStorageClass(GlobalValue::DefaultStorageClass);
    Clone.setDSOLocal(true);
    Clone.setComdat(nullptr);
    Clone.setSection("");
    Clone.setUnnamedAddr(GlobalValue::UnnamedAddr::None);
}

void outlineOriginalBody(Function &F) {
    Module &M = *F.getParent();
    const std::string CloneName = (F.getName() + ".vmp.outline").str();
    if (M.getFunction(CloneName) != nullptr) {
        return;
    }

    auto *Clone = Function::Create(F.getFunctionType(), GlobalValue::InternalLinkage, CloneName, M);
    Clone->copyAttributesFrom(&F);
    normalizeOutlinedClone(*Clone);

    ValueToValueMapTy VMap;
    auto DestArg = Clone->arg_begin();
    for (const Argument &Arg : F.args()) {
        DestArg->setName(Arg.getName());
        VMap[&Arg] = &*DestArg++;
    }

    SmallVector<ReturnInst *, 4> Returns;
    CloneFunctionInto(Clone, &F, VMap, CloneFunctionChangeType::LocalChangesOnly, Returns);
    normalizeOutlinedClone(*Clone);
    clearVmpProtectionMetadata(*Clone);
    Clone->setMetadata("vmp.outlined.original", MDNode::get(M.getContext(), MDString::get(M.getContext(), F.getName())));
}

bool outlineCloneSlotIsAvailable(const Function &F) {
    const Function *Clone = F.getParent()->getFunction((F.getName() + ".vmp.outline").str());
    if (Clone == nullptr) {
        return true;
    }
    return false;
}

void sanitizeOutlineCloneCollision(Function &F) {
    if (Function *Clone = F.getParent()->getFunction((F.getName() + ".vmp.outline").str())) {
        clearVmpProtectionMetadata(*Clone);
    }
}

void emitDecompilerTrapGuard(Function &F, BasicBlock *RealEntry) {
    LLVMContext &Ctx = F.getContext();
    BasicBlock *Entry = BasicBlock::Create(Ctx, "vmp.entry", &F, RealEntry);
    BasicBlock *Trap = BasicBlock::Create(Ctx, "vmp.decompiler.trap", &F, RealEntry);
    BasicBlock *Poison = BasicBlock::Create(Ctx, "vmp.decompiler.poison", &F, RealEntry);

    IRBuilder<> EntryBuilder(Entry);
    EntryBuilder.CreateCondBr(buildOpaqueFalse(F, EntryBuilder), Trap, RealEntry);

    IRBuilder<> TrapBuilder(Trap);
    auto *Switch = TrapBuilder.CreateSwitch(ConstantInt::get(Type::getInt32Ty(Ctx), 0), RealEntry, 1);
    Switch->addCase(ConstantInt::get(Type::getInt32Ty(Ctx), 1), Poison);

    IRBuilder<> PoisonBuilder(Poison);
    PoisonBuilder.CreateUnreachable();
    F.setMetadata("vmp.decompiler.trap", MDNode::get(Ctx, MDString::get(Ctx, "opaque-switch-trap")));
}

GlobalVariable *bytecodeGlobalFromMetadata(Function &Target) {
    MDNode *Node = Target.getMetadata("vmp.bytecode");
    if (Node == nullptr || Node->getNumOperands() != 1) {
        return nullptr;
    }
    auto *Value = dyn_cast<ValueAsMetadata>(Node->getOperand(0));
    if (Value == nullptr) {
        return nullptr;
    }
    return dyn_cast<GlobalVariable>(Value->getValue());
}

bool metadataStringEquals(const GlobalObject &Object, StringRef Kind, StringRef Expected) {
    MDNode *Node = Object.getMetadata(Kind);
    if (Node == nullptr || Node->getNumOperands() != 1) {
        return false;
    }
    auto *Value = dyn_cast<MDString>(Node->getOperand(0));
    return Value != nullptr && Value->getString() == Expected;
}

std::string callsiteMetadataTag(const Function &Target, std::uint64_t Hash,
                                const vmp::core::ProtectionConfig &Config) {
    if (!Config.callsiteObfuscation.perCallsiteThunks) {
        return Target.getName().str();
    }
    return (Target.getName() + ":" + hex64(Hash)).str();
}

std::uint64_t callsiteThunkHash(const vmp::core::ProtectionConfig &Config, const Function &Target,
                                const CallInst &Call, unsigned CallsiteIndex) {
    if (!Config.callsiteObfuscation.perCallsiteThunks) {
        return vmp::core::stableHash64(Target.getName().str());
    }
    const Function *Caller = Call.getFunction();
    std::string Material = Config.seed;
    Material += ":";
    Material += Target.getName().str();
    Material += ":";
    Material += Caller == nullptr ? "<module>" : Caller->getName().str();
    Material += ":";
    Material += std::to_string(CallsiteIndex);
    return vmp::core::stableHash64(Material);
}

Function *getOrCreateCallResolver(Module &M, GlobalVariable &Bytecode, std::uint64_t Hash,
                                  StringRef CallsiteTag) {
    LLVMContext &Ctx = M.getContext();
    const std::string Name = "vmp.call.resolve." + hex64(Hash);
    auto *ResolverTy = FunctionType::get(Type::getInt8PtrTy(Ctx), {Type::getInt64Ty(Ctx)}, false);
    if (GlobalValue *ExistingValue = M.getNamedValue(Name)) {
        auto *Existing = dyn_cast<Function>(ExistingValue);
        if (Existing == nullptr || Existing->getFunctionType() != ResolverTy ||
            !Existing->hasInternalLinkage() ||
            !metadataStringEquals(*Existing, "vmp.callsite.resolver", CallsiteTag)) {
            return nullptr;
        }
        return Existing;
    }

    auto *Resolver = Function::Create(ResolverTy, GlobalValue::InternalLinkage, Name, M);
    Resolver->setDSOLocal(true);
    Resolver->setMetadata("vmp.callsite.resolver", MDNode::get(Ctx, MDString::get(Ctx, CallsiteTag)));

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Resolver);
    BasicBlock *Hit = BasicBlock::Create(Ctx, "hit", Resolver);
    BasicBlock *Miss = BasicBlock::Create(Ctx, "miss", Resolver);

    IRBuilder<> B(Entry);
    auto *Switch = B.CreateSwitch(&*Resolver->arg_begin(), Miss, 1);
    Switch->addCase(ConstantInt::get(Type::getInt64Ty(Ctx), Hash), Hit);

    IRBuilder<> HitBuilder(Hit);
    HitBuilder.CreateRet(HitBuilder.CreatePointerCast(&Bytecode, Type::getInt8PtrTy(Ctx), "vmp.call.bytecode"));

    IRBuilder<> MissBuilder(Miss);
    MissBuilder.CreateRet(ConstantPointerNull::get(Type::getInt8PtrTy(Ctx)));
    return Resolver;
}

GlobalVariable *getOrCreateCallJumpSlot(Module &M, GlobalVariable &Bytecode, std::uint64_t Hash,
                                        StringRef CallsiteTag) {
    const std::string Name = "vmp.call.slot." + hex64(Hash);
    if (GlobalValue *ExistingValue = M.getNamedValue(Name)) {
        auto *Existing = dyn_cast<GlobalVariable>(ExistingValue);
        if (Existing == nullptr || Existing->getValueType() != Bytecode.getType() || !Existing->isConstant() ||
            !Existing->hasPrivateLinkage() || Existing->getInitializer() != &Bytecode ||
            !metadataStringEquals(*Existing, "vmp.callsite.jump_table", CallsiteTag)) {
            return nullptr;
        }
        return Existing;
    }
    auto *Slot = new GlobalVariable(M, Bytecode.getType(), true, GlobalValue::PrivateLinkage, &Bytecode, Name);
    Slot->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Slot->setAlignment(Align(1));
    Slot->setMetadata("vmp.callsite.jump_table", MDNode::get(M.getContext(), MDString::get(M.getContext(), CallsiteTag)));
    return Slot;
}

Function *getOrCreateCallThunk(Module &M, Function &Target, const vmp::core::ProtectionConfig &Config,
                               std::uint64_t Hash) {
    GlobalVariable *Bytecode = bytecodeGlobalFromMetadata(Target);
    if (Bytecode == nullptr) {
        return nullptr;
    }
    auto *BytecodeArrayTy = dyn_cast<ArrayType>(Bytecode->getValueType());
    if (BytecodeArrayTy == nullptr) {
        return nullptr;
    }
    Function *RuntimeEntry = getOrCreateRuntimeEntry(M, Target);
    if (RuntimeEntry == nullptr) {
        return nullptr;
    }

    const std::string CallsiteTag = callsiteMetadataTag(Target, Hash, Config);
    const std::string Name = "vmp.call.thunk." + hex64(Hash);
    if (GlobalValue *ExistingValue = M.getNamedValue(Name)) {
        auto *Existing = dyn_cast<Function>(ExistingValue);
        if (Existing == nullptr || Existing->getFunctionType() != Target.getFunctionType() ||
            !Existing->hasInternalLinkage() ||
            !metadataStringEquals(*Existing, "vmp.callsite.thunk", CallsiteTag)) {
            return nullptr;
        }
        return Existing;
    }

    Function *Resolver = nullptr;
    if (Config.callsiteObfuscation.hashResolver) {
        Resolver = getOrCreateCallResolver(M, *Bytecode, Hash, CallsiteTag);
        if (Resolver == nullptr) {
            return nullptr;
        }
    }

    GlobalVariable *Slot = nullptr;
    if (Config.callsiteObfuscation.jumpTable) {
        Slot = getOrCreateCallJumpSlot(M, *Bytecode, Hash, CallsiteTag);
        if (Slot == nullptr) {
            return nullptr;
        }
    }

    LLVMContext &Ctx = M.getContext();
    auto *Thunk = Function::Create(Target.getFunctionType(), GlobalValue::InternalLinkage, Name, M);
    Thunk->setDSOLocal(true);
    Thunk->setMetadata("vmp.callsite.thunk", MDNode::get(Ctx, MDString::get(Ctx, CallsiteTag)));

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Thunk);
    BasicBlock *Trap = BasicBlock::Create(Ctx, "resolver.miss", Thunk);
    BasicBlock *Call = BasicBlock::Create(Ctx, "call", Thunk);
    IRBuilder<> B(Entry);

    Value *Resolved = nullptr;
    if (Config.callsiteObfuscation.hashResolver) {
        Resolved = B.CreateCall(Resolver, ConstantInt::get(Type::getInt64Ty(Ctx), Hash), "vmp.resolved.i8");
    } else {
        Resolved = B.CreatePointerCast(Bytecode, Type::getInt8PtrTy(Ctx), "vmp.resolved.i8");
    }

    if (Config.callsiteObfuscation.jumpTable) {
        Value *SlotValue = B.CreateLoad(Bytecode->getType(), Slot, "vmp.jump.slot");
        Value *SlotAsI8 = B.CreatePointerCast(SlotValue, Type::getInt8PtrTy(Ctx), "vmp.jump.slot.i8");
        Value *Mix = B.CreatePtrToInt(SlotAsI8, Type::getInt64Ty(Ctx), "vmp.jump.mix");
        Value *Mask = B.CreateICmpNE(Mix, ConstantInt::get(Type::getInt64Ty(Ctx), 0), "vmp.jump.nonnull");
        Value *ResolvedNonNull = B.CreateICmpNE(Resolved, ConstantPointerNull::get(Type::getInt8PtrTy(Ctx)), "vmp.resolved.nonnull");
        Value *Ok = B.CreateAnd(Mask, ResolvedNonNull, "vmp.callsite.ok");
        B.CreateCondBr(Ok, Call, Trap);
    } else {
        Value *Ok = B.CreateICmpNE(Resolved, ConstantPointerNull::get(Type::getInt8PtrTy(Ctx)), "vmp.resolved.nonnull");
        B.CreateCondBr(Ok, Call, Trap);
    }

    IRBuilder<> TrapBuilder(Trap);
    Function *TrapIntrinsic = Intrinsic::getDeclaration(&M, Intrinsic::trap);
    TrapBuilder.CreateCall(TrapIntrinsic);
    TrapBuilder.CreateUnreachable();

    IRBuilder<> CallBuilder(Call);
    SmallVector<Value *, 6> Args;
    Args.push_back(Resolved);
    Args.push_back(ConstantInt::get(Type::getInt64Ty(Ctx), BytecodeArrayTy->getNumElements()));
    for (Argument &Arg : Thunk->args()) {
        Args.push_back(&Arg);
    }
    CallInst *RuntimeCall = CallBuilder.CreateCall(RuntimeEntry, Args,
                                                   Target.getReturnType()->isVoidTy() ? "" : "vmp.callsite.result");
    if (Target.getReturnType()->isVoidTy()) {
        CallBuilder.CreateRetVoid();
    } else {
        CallBuilder.CreateRet(RuntimeCall);
    }
    return Thunk;
}

bool obfuscateProtectedCallSites(Module &M) {
    const auto &Config = activeConfig();
    if (!Config.callsiteObfuscation.enabled || !Config.callsiteObfuscation.indirectThunks) {
        return false;
    }

    SmallPtrSet<Function *, 16> Targets;
    for (Function &F : M) {
        if (isSelectedFunction(F) && F.getMetadata("vmp.replaced") != nullptr) {
            Targets.insert(&F);
            if (Config.callsiteObfuscation.hideExports) {
                F.setVisibility(GlobalValue::HiddenVisibility);
                F.setDSOLocal(true);
            }
        }
    }

    SmallVector<CallInst *, 16> Calls;
    for (Function &F : M) {
        if (F.getName().startswith("vmp.call.")) {
            continue;
        }
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *Call = dyn_cast<CallInst>(&I);
                if (Call == nullptr) {
                    continue;
                }
                Function *Callee = Call->getCalledFunction();
                if (Callee != nullptr && Targets.contains(Callee)) {
                    Calls.push_back(Call);
                }
            }
        }
    }

    unsigned RewrittenCalls = 0;
    unsigned CallsiteIndex = 0;
    SmallPtrSet<Function *, 16> UniqueThunks;
    for (CallInst *Call : Calls) {
        Function *Target = Call->getCalledFunction();
        const std::uint64_t Hash = callsiteThunkHash(Config, *Target, *Call, CallsiteIndex++);
        Function *Thunk = getOrCreateCallThunk(M, *Target, Config, Hash);
        if (Thunk == nullptr) {
            continue;
        }
        IRBuilder<> B(Call);
        SmallVector<Value *, 4> Args;
        for (Value *Arg : Call->args()) {
            Args.push_back(Arg);
        }
        CallInst *Replacement = B.CreateCall(Thunk, Args, Call->getType()->isVoidTy() ? "" : "vmp.callsite.result");
        Replacement->setCallingConv(Call->getCallingConv());
        if (!Call->getType()->isVoidTy()) {
            Call->replaceAllUsesWith(Replacement);
        }
        Call->eraseFromParent();
        ++RewrittenCalls;
        UniqueThunks.insert(Thunk);
    }

    if (RewrittenCalls != 0) {
        errs() << "VMPPassPlugin callsite_obfuscation: rewritten_calls=" << RewrittenCalls << "\n";
        errs() << "VMPPassPlugin callsite_obfuscation: unique_thunks=" << UniqueThunks.size() << "\n";
    }
    return RewrittenCalls != 0;
}

bool recordAntiAnalysisPolicy(Module &M) {
    const auto &Config = activeConfig();
    if (!Config.decompilerTraps.enabled && !Config.stackBacktrace.randomized) {
        return false;
    }
    LLVMContext &Ctx = M.getContext();
    NamedMDNode *Policy = M.getOrInsertNamedMetadata("vmp.anti_analysis.policy");
    std::string Record = "decompiler_traps=";
    Record += Config.decompilerTraps.enabled ? "true" : "false";
    Record += ";random_stack_backtrace=";
    Record += Config.stackBacktrace.randomized ? "true" : "false";
    Record += ";stack_max_frames=" + std::to_string(Config.stackBacktrace.maxFrames);
    Policy->addOperand(MDNode::get(Ctx, MDString::get(Ctx, Record)));
    return true;
}

bool replaceWithRuntimeStub(Module &M) {
    bool Changed = false;
    LLVMContext &Ctx = M.getContext();
    const auto &Config = activeConfig();
    SmallVector<Function *, 8> Targets;
    for (Function &F : M) {
        if (isSelectedFunction(F) && !F.isDeclaration()) {
            Targets.push_back(&F);
        }
    }

    for (Function *F : Targets) {
        MDNode *Protected = F->getMetadata("vmp.protect");
        MDNode *Hotspot = F->getMetadata("vmp.hotspot");
        MDNode *VmLevel = F->getMetadata("vmp.vm_level");
        MDNode *BytecodeMetadata = F->getMetadata("vmp.bytecode");
        if (!supportsVirtualizedRuntimeSignature(*F)) {
            if (BytecodeMetadata != nullptr || F->getMetadata("vmp.lowering") != nullptr ||
                F->getMetadata("vmp.replaced") != nullptr) {
                markUnsupportedLowering(*F, "unsupported-signature");
                Changed = true;
            }
            continue;
        }
        if (BytecodeMetadata == nullptr) {
            continue;
        }
        if (!outlineCloneSlotIsAvailable(*F)) {
            sanitizeOutlineCloneCollision(*F);
            markUnsupportedLowering(*F, "outline-collision");
            Changed = true;
            continue;
        }
        if (!runtimeEntrySymbolIsAvailable(M, *F)) {
            markUnsupportedLowering(*F, "runtime-entry-collision");
            Changed = true;
            continue;
        }
        GlobalVariable *Bytecode = getOrCreateBytecodeGlobal(M, *F, Config);
        if (Bytecode == nullptr) {
            markUnsupportedLowering(*F, "unsupported-ir-subset");
            Changed = true;
            continue;
        }
        Function *RuntimeEntry = getOrCreateRuntimeEntry(M, *F);
        if (RuntimeEntry == nullptr) {
            markUnsupportedLowering(*F, "runtime-entry-collision");
            Changed = true;
            continue;
        }
        Metadata *BytecodeOps[] = {ValueAsMetadata::get(Bytecode)};
        MDNode *FreshBytecodeMetadata = MDNode::get(Ctx, BytecodeOps);
        outlineOriginalBody(*F);
        F->deleteBody();
        BasicBlock *RuntimeEntryBlock = BasicBlock::Create(
            Ctx, Config.decompilerTraps.enabled ? "vmp.vm.entry" : "vmp.entry", F);
        if (Config.decompilerTraps.enabled) {
            emitDecompilerTrapGuard(*F, RuntimeEntryBlock);
        }
        IRBuilder<> B(RuntimeEntryBlock);
        Value *BytecodePtr = B.CreatePointerCast(Bytecode, Type::getInt8PtrTy(Ctx), "vmp.bytecode.ptr");
        SmallVector<Value *, 3> Args;
        Args.push_back(BytecodePtr);
        auto *BytecodeArrayTy = cast<ArrayType>(Bytecode->getValueType());
        Args.push_back(ConstantInt::get(Type::getInt64Ty(Ctx), BytecodeArrayTy->getNumElements()));
        for (Argument &Arg : F->args()) {
            Args.push_back(&Arg);
        }
        Value *Result = B.CreateCall(RuntimeEntry, Args, "vmp.vm.result");
        B.CreateRet(Result);
        F->setMetadata("vmp.protect", Protected);
        F->setMetadata("vmp.hotspot", Hotspot);
        F->setMetadata("vmp.vm_level", VmLevel);
        F->setMetadata("vmp.bytecode", FreshBytecodeMetadata);
        F->setMetadata("vmp.lowering", MDNode::get(Ctx, MDString::get(Ctx, kLoweringName)));
        F->setMetadata("vmp.replaced", MDNode::get(Ctx, MDString::get(Ctx, "runtime-entry-stub")));
        F->setMetadata("vmp.unsupported", nullptr);
        Changed = true;
    }
    Changed |= obfuscateProtectedCallSites(M);
    return Changed;
}

PreservedAnalyses runStage(Module &M, StringRef StageName) {
    recordStage(M, StageName);

    if (StageName == "vmp-function-marker") {
        LLVMContext &Ctx = M.getContext();
        MDNode *Protected = MDNode::get(Ctx, MDString::get(Ctx, "selected"));
        for (Function &F : M) {
            if (shouldMarkFunction(F)) {
                F.setMetadata("vmp.protect", Protected);
            }
        }
        return PreservedAnalyses::none();
    }

    if (StageName == "vmp-hotspot-policy") {
        return applyHotspotPolicy(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-ir-normalize") {
        return normalizeProtectedIr(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-block-split") {
        return splitProtectedBlocks(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-flatten") {
        return flattenOptInBranches(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-bogus-branch") {
        return insertBogusDispatch(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-instruction-substitution") {
        return substituteIntegerComparisons(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-const-string-encryption") {
        return encryptConstantStrings(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-ir-to-bytecode") {
        return materializeBytecodeGlobals(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-opcode-randomize" || StageName == "vmp-bytecode-encrypt" ||
        StageName == "vmp-nesting") {
        return recordIntegratedBytecodeStage(M, StageName) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-anti-analysis-hooks") {
        return recordAntiAnalysisPolicy(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-function-replacement") {
        return replaceWithRuntimeStub(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    if (StageName == "vmp-report") {
        unsigned Selected = 0;
        unsigned Lowered = 0;
        unsigned Replaced = 0;
        unsigned Unsupported = 0;
        for (const Function &F : M) {
            if (!F.isDeclaration() && F.getMetadata("vmp.protect") != nullptr) {
                ++Selected;
                if (F.getMetadata("vmp.bytecode") != nullptr) {
                    ++Lowered;
                }
                if (F.getMetadata("vmp.replaced") != nullptr) {
                    ++Replaced;
                }
                if (F.getMetadata("vmp.unsupported") != nullptr) {
                    ++Unsupported;
                }
            }
        }
        unsigned RecordedStages = 0;
        if (NamedMDNode *Stages = M.getNamedMetadata("vmp.pipeline.stages")) {
            RecordedStages = Stages->getNumOperands();
        }
        errs() << "VMPPassPlugin report: selected_functions=" << Selected
               << " lowered_functions=" << Lowered
               << " replaced_functions=" << Replaced
               << " unsupported_functions=" << Unsupported
               << " stages=" << RecordedStages << "\n";
        const auto &Config = activeConfig();
        errs() << "VMPPassPlugin config: seed_fingerprint=" << seedHashForConfig(Config) << " vm_levels=";
        bool First = true;
        for (const Function &F : M) {
            if (!F.isDeclaration() && F.getMetadata("vmp.protect") != nullptr) {
                if (!First) {
                    errs() << ",";
                }
                First = false;
                errs() << F.getName() << ":" << vmLevelForFunction(Config, F);
            }
        }
        if (First) {
            errs() << "none";
        }
        errs() << "\n";
        unsigned ImplementedStages = 0;
        unsigned PlaceholderStages = 0;
        unsigned ReportOnlyStages = 0;
        errs() << "VMPPassPlugin stage_manifest_json: {\"schema\":\"vmp.llvm.stage_manifest.v1\","
               << "\"producer\":{\"name\":\"VMPPassPlugin\",\"version\":\"" << kPluginVersion << "\"},"
               << "\"pipeline\":{\"executed_count\":" << RecordedStages << ",\"implemented_count\":";
        for (StringRef Stage : kPipelineStages) {
            if (stageKind(Stage) == "report_only") {
                ++ReportOnlyStages;
            } else if (stageIsImplemented(Stage)) {
                ++ImplementedStages;
            } else {
                ++PlaceholderStages;
            }
        }
        errs() << ImplementedStages << ",\"placeholder_noop_count\":" << PlaceholderStages
               << ",\"report_only_count\":" << ReportOnlyStages << "},"
               << "\"totals\":{\"selected_functions\":" << Selected << ",\"lowered_functions\":" << Lowered
               << ",\"replaced_functions\":" << Replaced << ",\"unsupported_functions\":" << Unsupported << "},"
               << "\"stages\":[";
        for (std::size_t Index = 0; Index < kPipelineStages.size(); ++Index) {
            StringRef Stage = kPipelineStages[Index];
            StringRef Kind = stageKind(Stage);
            if (Index != 0) {
                errs() << ",";
            }
            errs() << "{\"order\":" << (Index + 1) << ",\"name\":\"" << Stage << "\",\"kind\":\"" << Kind
                   << "\",\"implemented\":" << (stageIsImplemented(Stage) ? "true" : "false")
                   << ",\"capability_effects\":[";
            if (Stage == "vmp-ir-to-bytecode") {
                errs() << "\"code_virtualization.bytecode_lowering\"";
            } else if (Stage == "vmp-ir-normalize") {
                errs() << "\"ir_normalization.canonical_integer_forms\"";
            } else if (Stage == "vmp-const-string-encryption") {
                errs() << "\"string_hiding.private_const_string_ctor_decode\"";
            } else if (Stage == "vmp-flatten") {
                errs() << "\"mutation_obfuscation.opt_in_switch_flattening\"";
            } else if (Stage == "vmp-opcode-randomize") {
                errs() << "\"code_virtualization.opcode_map_randomization\"";
            } else if (Stage == "vmp-bytecode-encrypt") {
                errs() << "\"code_virtualization.integrated_payload_sealing\"";
            } else if (Stage == "vmp-nesting") {
                errs() << "\"code_virtualization.vm_level_policy_encoding\"";
            } else if (Stage == "vmp-function-replacement") {
                errs() << "\"code_virtualization.runtime_replacement\",\"callsite_obfuscation.indirect_thunks\","
                          "\"callsite_obfuscation.per_callsite_thunks\"";
            } else if (Stage == "vmp-bogus-branch" || Stage == "vmp-instruction-substitution") {
                errs() << "\"mutation_obfuscation.local_transform\"";
            } else if (Stage == "vmp-hotspot-policy") {
                errs() << "\"performance.hotspot_static_policy\"";
            } else if (Stage == "vmp-anti-analysis-hooks") {
                errs() << "\"anti_analysis.decompiler_traps\",\"anti_analysis.random_stack_backtrace_policy\"";
            }
            errs() << "]}";
        }
        errs() << "]}\n";
    }

    return PreservedAnalyses::all();
}

class VMPStagePass final : public PassInfoMixin<VMPStagePass> {
public:
    explicit VMPStagePass(StringRef StageName) : StageName_(StageName.str()) {}

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        return runStage(M, StageName_);
    }

private:
    std::string StageName_;
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "VMPPassPlugin",
        kPluginVersion.data(),
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                    if (!isKnownStage(Name)) {
                        return false;
                    }
                    MPM.addPass(VMPStagePass(Name));
                    return true;
                });
        },
    };
}
