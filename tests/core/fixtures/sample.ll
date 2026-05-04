; ModuleID = 'vmp-sample'
source_filename = "vmp-sample.c"

@side_effect_sink = global i32 0
@vmp.bytecode.secret_stale_global = private unnamed_addr constant [8 x i8] c"STALEBC\00", align 1

define i32 @license_check(i32 %x) {
entry:
  %cmp = icmp eq i32 %x, 7
  br i1 %cmp, label %ok, label %bad

ok:
  %inc = add i32 %x, 1
  %out = add i32 %inc, 41
  ret i32 %out

bad:
  ret i32 0
}

define internal i32 @ordinary_add(i32 %a, i32 %b) {
entry:
  %sum = add i32 %a, %b
  ret i32 %sum
}

define i32 @auth_pair(i32 %a, i32 %b) {
entry:
  %mix = xor i32 %a, %b
  %cmp = icmp sgt i32 %mix, 10
  br i1 %cmp, label %ok, label %bad

ok:
  %inc = add i32 %mix, 5
  ret i32 %inc

bad:
  ret i32 %b
}

define i32 @secret_gate(i32 %x) {
entry:
  %probe = add i32 %x, 2
  %cmp = icmp eq i32 %probe, 11
  br i1 %cmp, label %ok, label %bad

ok:
  %masked = xor i32 %x, 3
  ret i32 %masked

bad:
  %fallback = add i32 %x, 4
  ret i32 %fallback
}

define i32 @secret_linear(i32 %x) {
entry:
  %sum = add i32 %x, 5
  ret i32 %sum
}

define i32 @secret_const() {
entry:
  %out = xor i32 123, 85
  ret i32 %out
}

define i32 @secret_arith(i32 %x, i32 %y) {
entry:
  %scaled = mul i32 %x, 3
  %delta = sub i32 %scaled, %y
  %out = add i32 %delta, 9
  ret i32 %out
}

define i32 @secret_mix3(i32 %x, i32 %y, i32 %z) {
entry:
  %sum = add i32 %x, %y
  %mixed = xor i32 %sum, %z
  %out = sub i32 %mixed, 4
  ret i32 %out
}

define i32 @secret_mix4(i32 %a, i32 %b, i32 %c, i32 %d) {
entry:
  %sum = add i32 %a, %b
  %delta = sub i32 %c, %d
  %mixed = xor i32 %sum, %delta
  %out = add i32 %mixed, 13
  ret i32 %out
}

define i32 @secret_bits(i32 %x, i32 %y) {
entry:
  %masked = and i32 %x, 15
  %merged = or i32 %masked, %y
  %out = xor i32 %merged, 3
  ret i32 %out
}

define i32 @secret_shl(i32 %x) {
entry:
  %out = shl i32 %x, 3
  ret i32 %out
}

define i32 @secret_lshr(i32 %x) {
entry:
  %out = lshr i32 %x, 4
  ret i32 %out
}

define i32 @secret_ashr(i32 %x) {
entry:
  %out = ashr i32 %x, 2
  ret i32 %out
}

define i32 @secret_masked_shl(i32 %x, i32 %amount) {
entry:
  %masked = and i32 %amount, 31
  %out = shl i32 %x, %masked
  ret i32 %out
}

define i32 @secret_masked_lshr(i32 %x, i32 %amount) {
entry:
  %masked = and i32 %amount, 31
  %out = lshr i32 %x, %masked
  ret i32 %out
}

define i32 @secret_masked_ashr(i32 %x, i32 %amount) {
entry:
  %masked = and i32 %amount, 31
  %out = ashr i32 %x, %masked
  ret i32 %out
}

define i32 @secret_dynamic_shift(i32 %x, i32 %amount) {
entry:
  %out = shl i32 %x, %amount
  ret i32 %out
}

define i32 @secret_dynamic_lshr(i32 %x, i32 %amount) {
entry:
  %out = lshr i32 %x, %amount
  ret i32 %out
}

define i32 @secret_dynamic_ashr(i32 %x, i32 %amount) {
entry:
  %out = ashr i32 %x, %amount
  ret i32 %out
}

define i32 @secret_wide_shift(i32 %x) {
entry:
  %out = lshr i32 %x, 32
  ret i32 %out
}

define i32 @secret_wide_shl(i32 %x) {
entry:
  %out = shl i32 %x, 32
  ret i32 %out
}

define i32 @secret_wide_ashr(i32 %x) {
entry:
  %out = ashr i32 %x, 32
  ret i32 %out
}

define i32 @secret_nsw_add(i32 %x) {
entry:
  %out = add nsw i32 %x, 1
  ret i32 %out
}

define i32 @secret_nuw_sub(i32 %x) {
entry:
  %out = sub nuw i32 %x, 1
  ret i32 %out
}

define i32 @secret_nsw_mul(i32 %x) {
entry:
  %out = mul nsw i32 %x, 3
  ret i32 %out
}

define i32 @secret_nuw_shl(i32 %x) {
entry:
  %out = shl nuw i32 %x, 1
  ret i32 %out
}

define i32 @secret_exact_lshr(i32 %x) {
entry:
  %out = lshr exact i32 %x, 1
  ret i32 %out
}

define i32 @secret_exact_ashr(i32 %x) {
entry:
  %out = ashr exact i32 %x, 1
  ret i32 %out
}

define i32 @secret_local(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %sum = add i32 %x, 5
  store i32 %sum, i32* %slot, align 4
  %loaded = load i32, i32* %slot, align 4
  %out = xor i32 %loaded, 7
  ret i32 %out
}

define i32 @secret_local_reuse(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %sum = add i32 %x, 5
  store i32 %sum, i32* %slot, align 4
  %first = load i32, i32* %slot, align 4
  %second = load i32, i32* %slot, align 4
  %mixed = add i32 %first, %second
  %out = xor i32 %mixed, 3
  ret i32 %out
}

define i32 @secret_local_branch(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %cmp = icmp sgt i32 %x, 0
  br i1 %cmp, label %hi, label %lo

hi:
  store i32 %x, i32* %slot, align 4
  br label %merge

lo:
  store i32 0, i32* %slot, align 4
  br label %merge

merge:
  %loaded = load i32, i32* %slot, align 4
  ret i32 %loaded
}

define i32 @secret_branch_load_dead_store(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, i32* %slot, align 4
  br label %check

dead:
  store i32 0, i32* %slot, align 4
  br label %check

check:
  %loaded = load i32, i32* %slot, align 4
  %cmp = icmp sgt i32 %loaded, 0
  br i1 %cmp, label %hi, label %lo

hi:
  ret i32 31

lo:
  ret i32 17
}

define i32 @secret_local_uninit_branch(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %cmp = icmp sgt i32 %x, 0
  br i1 %cmp, label %hi, label %merge

hi:
  store i32 %x, i32* %slot, align 4
  br label %merge

merge:
  %loaded = load i32, i32* %slot, align 4
  ret i32 %loaded
}

define i32 @secret_load_before_branch(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 5, i32* %slot, align 4
  %loaded = load i32, i32* %slot, align 4
  %cmp = icmp sgt i32 %x, 0
  br i1 %cmp, label %hi, label %lo

hi:
  store i32 %x, i32* %slot, align 4
  br label %merge

lo:
  store i32 0, i32* %slot, align 4
  br label %merge

merge:
  ret i32 %loaded
}

define i32 @secret_nested_branch(i32 %x, i32 %y) {
entry:
  %outer = icmp sgt i32 %x, 0
  br i1 %outer, label %check_y, label %lo

check_y:
  %inner = icmp sgt i32 %y, 0
  br i1 %inner, label %hi, label %mid

hi:
  ret i32 11

mid:
  ret i32 7

lo:
  ret i32 3
}

define i32 @secret_nested_compute(i32 %x, i32 %y) {
entry:
  %outer = icmp sgt i32 %x, 0
  br i1 %outer, label %check_y, label %lo

check_y:
  %inner = icmp sgt i32 %y, 0
  br i1 %inner, label %hi, label %mid

hi:
  %sum = add i32 %x, %y
  ret i32 %sum

mid:
  %diff = sub i32 %x, %y
  ret i32 %diff

lo:
  %neg = sub i32 0, %x
  ret i32 %neg
}

define i32 @secret_global_store(i32 %x) {
entry:
  store i32 %x, i32* @side_effect_sink, align 4
  %out = add i32 %x, 2
  ret i32 %out
}

define i32 @secret_stale_global(i32 %x) {
entry:
  store i32 %x, i32* @side_effect_sink, align 4
  %out = add i32 %x, 6
  ret i32 %out
}

define i32 @secret_wrap_eq(i32 %x) {
entry:
  %sum = add i32 %x, 1
  %cmp = icmp eq i32 %sum, 0
  br i1 %cmp, label %ok, label %bad

ok:
  ret i32 1

bad:
  ret i32 0
}

define i32 @secret_ne(i32 %x) {
entry:
  %cmp = icmp ne i32 %x, 0
  br i1 %cmp, label %nz, label %zero

nz:
  ret i32 7

zero:
  ret i32 3
}

define i32 @secret_select_ne(i32 %x) {
entry:
  %cmp = icmp ne i32 %x, 0
  %nz = add i32 %x, 11
  %zero = add i32 %x, 4
  %out = select i1 %cmp, i32 %nz, i32 %zero
  ret i32 %out
}

define i32 @secret_slt(i32 %x) {
entry:
  %cmp = icmp slt i32 %x, 0
  br i1 %cmp, label %neg, label %nonneg

neg:
  ret i32 9

nonneg:
  ret i32 2
}

define i32 @secret_select_slt(i32 %x) {
entry:
  %cmp = icmp slt i32 %x, 3
  %lt = add i32 %x, 20
  %ge = add i32 %x, 5
  %out = select i1 %cmp, i32 %lt, i32 %ge
  ret i32 %out
}

define i32 @secret_sle(i32 %x) {
entry:
  %cmp = icmp sle i32 %x, -1
  br i1 %cmp, label %le, label %gt

le:
  ret i32 13

gt:
  ret i32 4
}

define i32 @secret_sge(i32 %x) {
entry:
  %cmp = icmp sge i32 %x, 0
  br i1 %cmp, label %ge, label %lt

ge:
  ret i32 14

lt:
  ret i32 5
}

define i32 @secret_select_sle(i32 %x) {
entry:
  %cmp = icmp sle i32 %x, 0
  %le = add i32 %x, 40
  %gt = add i32 %x, 7
  %out = select i1 %cmp, i32 %le, i32 %gt
  ret i32 %out
}

define i32 @secret_select_sge(i32 %x) {
entry:
  %cmp = icmp sge i32 %x, 0
  %ge = add i32 %x, 30
  %lt = add i32 %x, 6
  %out = select i1 %cmp, i32 %ge, i32 %lt
  ret i32 %out
}

define i32 @secret_ugt(i32 %x) {
entry:
  %cmp = icmp ugt i32 %x, 2147483647
  br i1 %cmp, label %hi, label %lo

hi:
  ret i32 21

lo:
  ret i32 8
}

define i32 @secret_ult(i32 %x) {
entry:
  %cmp = icmp ult i32 %x, 10
  br i1 %cmp, label %lt, label %ge

lt:
  ret i32 22

ge:
  ret i32 9
}

define i32 @secret_uge(i32 %x) {
entry:
  %cmp = icmp uge i32 %x, -1
  br i1 %cmp, label %ge, label %lt

ge:
  ret i32 23

lt:
  ret i32 10
}

define i32 @secret_ule(i32 %x) {
entry:
  %cmp = icmp ule i32 %x, 1
  br i1 %cmp, label %le, label %gt

le:
  ret i32 24

gt:
  ret i32 11
}

define i32 @secret_select_ule(i32 %x) {
entry:
  %cmp = icmp ule i32 %x, 3
  %le = add i32 %x, 50
  %gt = add i32 %x, 8
  %out = select i1 %cmp, i32 %le, i32 %gt
  ret i32 %out
}

define i32 @secret_select_ugt(i32 %x) {
entry:
  %cmp = icmp ugt i32 %x, 2147483647
  %hi = add i32 %x, 55
  %lo = add i32 %x, 12
  %out = select i1 %cmp, i32 %hi, i32 %lo
  ret i32 %out
}

define i32 @secret_select_ult(i32 %x) {
entry:
  %cmp = icmp ult i32 %x, 10
  %lt = add i32 %x, 60
  %ge = add i32 %x, 9
  %out = select i1 %cmp, i32 %lt, i32 %ge
  ret i32 %out
}

define i32 @secret_select_uge(i32 %x) {
entry:
  %cmp = icmp uge i32 %x, -1
  %ge = add i32 %x, 70
  %lt = add i32 %x, 10
  %out = select i1 %cmp, i32 %ge, i32 %lt
  ret i32 %out
}

define i32 @secret_cmp_zext(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 10
  %out = zext i1 %cmp to i32
  ret i32 %out
}

define i32 @secret_cmp_sext(i32 %x) {
entry:
  %cmp = icmp sle i32 %x, 0
  %out = sext i1 %cmp to i32
  ret i32 %out
}

define i32 @secret_zext_i1(i32 %x) {
entry:
  %narrow = trunc i32 %x to i1
  %out = zext i1 %narrow to i32
  ret i32 %out
}

define i32 @secret_zext_i8(i32 %x) {
entry:
  %narrow = trunc i32 %x to i8
  %out = zext i8 %narrow to i32
  ret i32 %out
}

define i32 @secret_sext_i8(i32 %x) {
entry:
  %narrow = trunc i32 %x to i8
  %out = sext i8 %narrow to i32
  ret i32 %out
}

define i32 @secret_zext_i16(i32 %x) {
entry:
  %narrow = trunc i32 %x to i16
  %out = zext i16 %narrow to i32
  ret i32 %out
}

define i32 @secret_zext_i64(i32 %x) {
entry:
  %narrow = trunc i32 %x to i8
  %wide = zext i8 %narrow to i64
  %out = trunc i64 %wide to i32
  ret i32 %out
}

define i32 @secret_sext_i64(i32 %x) {
entry:
  %narrow = trunc i32 %x to i8
  %wide = sext i8 %narrow to i64
  %out = trunc i64 %wide to i32
  ret i32 %out
}

define i32 @secret_zext_i16_i64(i32 %x) {
entry:
  %narrow = trunc i32 %x to i16
  %wide = zext i16 %narrow to i64
  %out = trunc i64 %wide to i32
  ret i32 %out
}

define i32 @secret_sext_i16_i64(i32 %x) {
entry:
  %narrow = trunc i32 %x to i16
  %wide = sext i16 %narrow to i64
  %out = trunc i64 %wide to i32
  ret i32 %out
}

define i32 @secret_local_select(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %cmp = icmp sgt i32 %x, 0
  %pos = add i32 %x, 2
  %neg = sub i32 0, %x
  %chosen = select i1 %cmp, i32 %pos, i32 %neg
  store i32 %chosen, i32* %slot, align 4
  %loaded = load i32, i32* %slot, align 4
  ret i32 %loaded
}

define i32 @secret_local_call(i32 %x) {
entry:
  %slot = alloca i32, align 4
  %sum = call i32 @ordinary_add(i32 %x, i32 9)
  store i32 %sum, i32* %slot, align 4
  %loaded = load i32, i32* %slot, align 4
  %out = xor i32 %loaded, 1
  ret i32 %out
}

define i32 @secret_select(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 10
  %hi = mul i32 %x, 2
  %lo = sub i32 %x, 2
  %out = select i1 %cmp, i32 %hi, i32 %lo
  ret i32 %out
}

define i32 @secret_phi(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 5
  br i1 %cmp, label %hi, label %lo

hi:
  %double = mul i32 %x, 2
  br label %merge

lo:
  %dec = sub i32 %x, 1
  br label %merge

merge:
  %out = phi i32 [ %double, %hi ], [ %dec, %lo ]
  ret i32 %out
}

define i32 @secret_call(i32 %x) {
entry:
  %sum = call i32 @ordinary_add(i32 %x, i32 7)
  ret i32 %sum
}

define i32 @secret_call_chain(i32 %x) {
entry:
  %first = call i32 @ordinary_add(i32 %x, i32 7)
  %second = call i32 @ordinary_add(i32 %first, i32 3)
  ret i32 %second
}

define i32 @secret_call_pair(i32 %x) {
entry:
  %first = call i32 @ordinary_add(i32 %x, i32 7)
  %second = call i32 @ordinary_add(i32 %x, i32 3)
  %out = add i32 %first, %second
  ret i32 %out
}

define i32 @secret_call_branch(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 0
  br i1 %cmp, label %hi, label %lo

hi:
  %first = call i32 @ordinary_add(i32 %x, i32 7)
  ret i32 %first

lo:
  %second = call i32 @ordinary_add(i32 %x, i32 3)
  ret i32 %second
}

define i32 @secret_side_effect(i32 %x) {
entry:
  store volatile i32 %x, i32* @side_effect_sink
  %sum = add i32 %x, 1
  ret i32 %sum
}
