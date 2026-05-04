; ModuleID = 'vmp-runtime-entry-collision'
source_filename = "vmp-runtime-entry-collision.c"

; RUNTIME-COLLISION-LABEL: define internal i32 @vmp_runtime_entry_i32_i32
; RUNTIME-COLLISION: ret i32 123
define internal i32 @vmp_runtime_entry_i32_i32(i8* %bytecode, i64 %size, i32 %x) {
entry:
  ret i32 123
}

; RUNTIME-COLLISION: declare void @vmp_runtime_entry_i32_i32_i32()
declare void @vmp_runtime_entry_i32_i32_i32()

; RUNTIME-COLLISION: declare i32 @vmp_runtime_entry_i32_i32_i32_i32
; RUNTIME-COLLISION-SAME: #0
declare i32 @vmp_runtime_entry_i32_i32_i32_i32(i8*, i64, i32, i32, i32) #0

; RUNTIME-COLLISION: declare fastcc i32 @vmp_runtime_entry_i32_i32_i32_i32_i32
declare fastcc i32 @vmp_runtime_entry_i32_i32_i32_i32_i32(i8*, i64, i32, i32, i32, i32)

; RUNTIME-COLLISION-LABEL: define i32 @secret_runtime_entry_body_collision(i32 %x)
; RUNTIME-COLLISION-SAME: !vmp.protect
; RUNTIME-COLLISION-SAME: !vmp.unsupported
; RUNTIME-COLLISION-NOT: !vmp.bytecode
; RUNTIME-COLLISION-NOT: !vmp.replaced
; RUNTIME-COLLISION: ret i32 %out
define i32 @secret_runtime_entry_body_collision(i32 %x) {
entry:
  %out = add i32 %x, 1
  ret i32 %out
}

; RUNTIME-COLLISION-LABEL: define i32 @secret_runtime_entry_type_collision(i32 %x, i32 %y)
; RUNTIME-COLLISION-SAME: !vmp.protect
; RUNTIME-COLLISION-SAME: !vmp.unsupported
; RUNTIME-COLLISION-NOT: !vmp.bytecode
; RUNTIME-COLLISION-NOT: !vmp.replaced
; RUNTIME-COLLISION: ret i32 %out
define i32 @secret_runtime_entry_type_collision(i32 %x, i32 %y) {
entry:
  %out = add i32 %x, %y
  ret i32 %out
}

; RUNTIME-COLLISION-LABEL: define i32 @secret_runtime_entry_attr_collision(i32 %x, i32 %y, i32 %z)
; RUNTIME-COLLISION-SAME: !vmp.protect
; RUNTIME-COLLISION-SAME: !vmp.unsupported
; RUNTIME-COLLISION-NOT: !vmp.bytecode
; RUNTIME-COLLISION-NOT: !vmp.replaced
; RUNTIME-COLLISION: ret i32 %out
define i32 @secret_runtime_entry_attr_collision(i32 %x, i32 %y, i32 %z) {
entry:
  %sum = add i32 %x, %y
  %out = add i32 %sum, %z
  ret i32 %out
}

; RUNTIME-COLLISION-LABEL: define i32 @secret_runtime_entry_cc_collision(i32 %a, i32 %b, i32 %c, i32 %d)
; RUNTIME-COLLISION-SAME: !vmp.protect
; RUNTIME-COLLISION-SAME: !vmp.unsupported
; RUNTIME-COLLISION-NOT: !vmp.bytecode
; RUNTIME-COLLISION-NOT: !vmp.replaced
; RUNTIME-COLLISION: ret i32 %out
define i32 @secret_runtime_entry_cc_collision(i32 %a, i32 %b, i32 %c, i32 %d) {
entry:
  %first = add i32 %a, %b
  %second = add i32 %c, %d
  %out = add i32 %first, %second
  ret i32 %out
}

; RUNTIME-COLLISION: attributes #0 = { noreturn }
attributes #0 = { noreturn }
