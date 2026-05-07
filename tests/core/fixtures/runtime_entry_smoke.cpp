#include <cstdlib>
#include <cstdint>
#include <iostream>

extern "C" int license_check(int);
extern "C" int auth_pair(int, int);
extern "C" int secret_gate(int);
extern "C" int secret_linear(int);
extern "C" int secret_const();
extern "C" int secret_arith(int, int);
extern "C" int secret_mix3(int, int, int);
extern "C" int secret_mix4(int, int, int, int);
extern "C" int secret_bits(int, int);
extern "C" int secret_shl(int);
extern "C" int secret_lshr(int);
extern "C" int secret_ashr(int);
extern "C" int secret_masked_shl(int, int);
extern "C" int secret_masked_lshr(int, int);
extern "C" int secret_masked_ashr(int, int);
extern "C" int secret_local(int);
extern "C" int secret_local_reuse(int);
extern "C" int secret_local_branch(int);
extern "C" int secret_branch_load_dead_store(int);
extern "C" int secret_nested_branch(int, int);
extern "C" int secret_nested_compute(int, int);
extern "C" int secret_wrap_eq(int);
extern "C" int secret_ne(int);
extern "C" int secret_select_ne(int);
extern "C" int secret_slt(int);
extern "C" int secret_select_slt(int);
extern "C" int secret_sle(int);
extern "C" int secret_sge(int);
extern "C" int secret_select_sle(int);
extern "C" int secret_select_sge(int);
extern "C" int secret_ugt(int);
extern "C" int secret_ult(int);
extern "C" int secret_uge(int);
extern "C" int secret_ule(int);
extern "C" int secret_select_ule(int);
extern "C" int secret_select_ugt(int);
extern "C" int secret_select_ult(int);
extern "C" int secret_select_uge(int);
extern "C" int secret_cmp_zext(int);
extern "C" int secret_cmp_sext(int);
extern "C" int secret_zext_i1(int);
extern "C" int secret_zext_i8(int);
extern "C" int secret_sext_i8(int);
extern "C" int secret_zext_i16(int);
extern "C" int secret_zext_i64(int);
extern "C" int secret_sext_i64(int);
extern "C" int secret_zext_i16_i64(int);
extern "C" int secret_sext_i16_i64(int);
extern "C" int secret_local_select(int);
extern "C" int secret_local_call(int);
extern "C" int secret_select(int);
extern "C" int secret_phi(int);
extern "C" int secret_call(int);
extern "C" int secret_call_chain(int);
extern "C" int secret_call_pair(int);
extern "C" int secret_call_branch(int);
extern "C" std::int64_t secret_i64_arith(std::int64_t, std::int64_t);
extern "C" std::int64_t secret_i64_local(std::int64_t);

int main() {
    if (license_check(7) != 49) {
        std::cerr << "license_check(7) mismatch\n";
        return EXIT_FAILURE;
    }
    if (license_check(6) != 0) {
        std::cerr << "license_check(6) mismatch\n";
        return EXIT_FAILURE;
    }
    if (auth_pair(12, 3) != 20) {
        std::cerr << "auth_pair greater-than path mismatch\n";
        return EXIT_FAILURE;
    }
    if (auth_pair(1, 2) != 2) {
        std::cerr << "auth_pair fallback path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_gate(9) != 10) {
        std::cerr << "secret_gate match path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_gate(8) != 12) {
        std::cerr << "secret_gate fallback path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_linear(10) != 15) {
        std::cerr << "secret_linear VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_const() != 46) {
        std::cerr << "secret_const VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_arith(6, 4) != 23) {
        std::cerr << "secret_arith VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_mix3(5, 7, 3) != 11) {
        std::cerr << "secret_mix3 VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint32_t>(secret_mix3(0x7fffffff, 2, 0x55)) != 0x80000050U) {
        std::cerr << "secret_mix3 wraparound path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_mix4(5, 7, 20, 3) != 42) {
        std::cerr << "secret_mix4 VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint32_t>(secret_mix4(0x7fffffff, 4, 3, 8)) != 0x80000005U) {
        std::cerr << "secret_mix4 wraparound path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_bits(0xf6, 0x22) != 0x25) {
        std::cerr << "secret_bits VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_shl(7) != 56) {
        std::cerr << "secret_shl VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_shl(0x40000000) != 0) {
        std::cerr << "secret_shl low32 wrap mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_lshr(-16) != 0x0fffffff) {
        std::cerr << "secret_lshr VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ashr(-16) != -4) {
        std::cerr << "secret_ashr negative VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ashr(16) != 4) {
        std::cerr << "secret_ashr positive VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_masked_shl(7, 35) != 56) {
        std::cerr << "secret_masked_shl VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_masked_lshr(-16, 36) != 0x0fffffff) {
        std::cerr << "secret_masked_lshr VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_masked_ashr(-16, 34) != -4) {
        std::cerr << "secret_masked_ashr VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local(10) != 8) {
        std::cerr << "secret_local VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_reuse(10) != 29) {
        std::cerr << "secret_local_reuse VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_branch(10) != 10) {
        std::cerr << "secret_local_branch true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_branch(-1) != 0) {
        std::cerr << "secret_local_branch false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_branch_load_dead_store(3) != 31) {
        std::cerr << "secret_branch_load_dead_store true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_branch_load_dead_store(-3) != 17) {
        std::cerr << "secret_branch_load_dead_store false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_branch(2, 3) != 11) {
        std::cerr << "secret_nested_branch high path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_branch(2, -1) != 7) {
        std::cerr << "secret_nested_branch middle path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_branch(-2, 3) != 3) {
        std::cerr << "secret_nested_branch low path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_compute(5, 3) != 8) {
        std::cerr << "secret_nested_compute high path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_compute(5, -2) != 7) {
        std::cerr << "secret_nested_compute middle path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_nested_compute(-4, 3) != 4) {
        std::cerr << "secret_nested_compute low path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_wrap_eq(-1) != 1) {
        std::cerr << "secret_wrap_eq wraparound mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_wrap_eq(1) != 0) {
        std::cerr << "secret_wrap_eq non-match mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ne(4) != 7) {
        std::cerr << "secret_ne true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ne(0) != 3) {
        std::cerr << "secret_ne false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ne(5) != 16) {
        std::cerr << "secret_select_ne true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ne(0) != 4) {
        std::cerr << "secret_select_ne false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_slt(-1) != 9) {
        std::cerr << "secret_slt true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_slt(1) != 2) {
        std::cerr << "secret_slt false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_slt(-2) != 18) {
        std::cerr << "secret_select_slt true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_slt(4) != 9) {
        std::cerr << "secret_select_slt false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sle(-2) != 13) {
        std::cerr << "secret_sle true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sle(0) != 4) {
        std::cerr << "secret_sle false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sge(0) != 14) {
        std::cerr << "secret_sge true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sge(-1) != 5) {
        std::cerr << "secret_sge false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_sle(-1) != 39) {
        std::cerr << "secret_select_sle true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_sle(2) != 9) {
        std::cerr << "secret_select_sle false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_sge(0) != 30) {
        std::cerr << "secret_select_sge true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_sge(-3) != 3) {
        std::cerr << "secret_select_sge false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ugt(-1) != 21) {
        std::cerr << "secret_ugt true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ugt(7) != 8) {
        std::cerr << "secret_ugt false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ugt(2147483647) != 8) {
        std::cerr << "secret_ugt equality boundary mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ult(9) != 22) {
        std::cerr << "secret_ult true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ult(10) != 9) {
        std::cerr << "secret_ult equality boundary mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ult(-1) != 9) {
        std::cerr << "secret_ult false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_uge(-1) != 23) {
        std::cerr << "secret_uge true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_uge(1) != 10) {
        std::cerr << "secret_uge false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ule(1) != 24) {
        std::cerr << "secret_ule true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_ule(-1) != 11) {
        std::cerr << "secret_ule false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ule(3) != 53) {
        std::cerr << "secret_select_ule true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ule(-1) != 7) {
        std::cerr << "secret_select_ule false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ugt(-1) != 54) {
        std::cerr << "secret_select_ugt true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ugt(2147483647) != -2147483637) {
        std::cerr << "secret_select_ugt equality boundary mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ult(9) != 69) {
        std::cerr << "secret_select_ult true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_ult(10) != 19) {
        std::cerr << "secret_select_ult equality boundary mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_uge(-1) != 69) {
        std::cerr << "secret_select_uge true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select_uge(1) != 11) {
        std::cerr << "secret_select_uge false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_cmp_zext(11) != 1) {
        std::cerr << "secret_cmp_zext true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_cmp_zext(10) != 0) {
        std::cerr << "secret_cmp_zext false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_cmp_sext(0) != -1) {
        std::cerr << "secret_cmp_sext true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_cmp_sext(1) != 0) {
        std::cerr << "secret_cmp_sext false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i1(3) != 1) {
        std::cerr << "secret_zext_i1 low bit mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i1(2) != 0) {
        std::cerr << "secret_zext_i1 cleared low bit mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i8(0x1234ab) != 0xab) {
        std::cerr << "secret_zext_i8 low byte mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i8(0x80) != -128) {
        std::cerr << "secret_sext_i8 negative low byte mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i8(0x7f) != 127) {
        std::cerr << "secret_sext_i8 positive low byte mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i16(0x1234abcd) != 0xabcd) {
        std::cerr << "secret_zext_i16 low word mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i64(0x1234ab) != 0xab) {
        std::cerr << "secret_zext_i64 wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i64(0x80) != -128) {
        std::cerr << "secret_sext_i64 negative wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i64(0x7f) != 127) {
        std::cerr << "secret_sext_i64 positive wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_zext_i16_i64(0x1234abcd) != 0xabcd) {
        std::cerr << "secret_zext_i16_i64 wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i16_i64(0x8000) != -32768) {
        std::cerr << "secret_sext_i16_i64 negative wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_sext_i16_i64(0x7fff) != 32767) {
        std::cerr << "secret_sext_i16_i64 positive wide round-trip mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_select(6) != 8) {
        std::cerr << "secret_local_select true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_select(-5) != 5) {
        std::cerr << "secret_local_select false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_local_call(10) != 18) {
        std::cerr << "secret_local_call VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select(12) != 24) {
        std::cerr << "secret_select true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_select(5) != 3) {
        std::cerr << "secret_select false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_phi(6) != 12) {
        std::cerr << "secret_phi true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_phi(4) != 3) {
        std::cerr << "secret_phi false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_call(10) != 17) {
        std::cerr << "secret_call VM path mismatch\n";
        return EXIT_FAILURE;
    }
    const auto wrappedSecretCall = static_cast<std::uint32_t>(0x7fffffffU + 7U);
    if (static_cast<std::uint32_t>(secret_call(0x7fffffff)) != wrappedSecretCall) {
        std::cerr << "secret_call wraparound mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_call_chain(10) != 20) {
        std::cerr << "secret_call_chain VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_call_pair(10) != 30) {
        std::cerr << "secret_call_pair VM path mismatch\n";
        return EXIT_FAILURE;
    }
    const auto wrappedCallPair = static_cast<std::uint32_t>((0x7fffffffU + 7U) + (0x7fffffffU + 3U));
    if (static_cast<std::uint32_t>(secret_call_pair(0x7fffffff)) != wrappedCallPair) {
        std::cerr << "secret_call_pair preserved-result wraparound mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_call_branch(10) != 17) {
        std::cerr << "secret_call_branch true path mismatch\n";
        return EXIT_FAILURE;
    }
    if (secret_call_branch(-1) != 2) {
        std::cerr << "secret_call_branch false path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint64_t>(secret_i64_arith(0x100000000LL, 0x55aa55aa55aa55aaLL)) !=
        0xc28406d94b0c8f3aULL) {
        std::cerr << "secret_i64_arith VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint64_t>(secret_i64_arith(0x7fffffffffffffffLL, 0x1234LL)) !=
        0x923456789abba96bULL) {
        std::cerr << "secret_i64_arith high-bit path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint64_t>(secret_i64_local(0x100000000LL)) != 0xcafebabc12345679ULL) {
        std::cerr << "secret_i64_local VM path mismatch\n";
        return EXIT_FAILURE;
    }
    if (static_cast<std::uint64_t>(secret_i64_local(-5)) != 0xcafebabeedcba984ULL) {
        std::cerr << "secret_i64_local negative path mismatch\n";
        return EXIT_FAILURE;
    }
    std::cout << "llvm runtime entry smoke passed\n";
    return EXIT_SUCCESS;
}
