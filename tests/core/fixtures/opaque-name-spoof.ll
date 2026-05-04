; ModuleID = 'vmp-opaque-name-spoof'
source_filename = "vmp-opaque-name-spoof.c"

; OPAQUE-SPOOF-LABEL: define i32 @secret_opaque_name_spoof(i32 %x)
; OPAQUE-SPOOF-SAME: !vmp.protect
; OPAQUE-SPOOF-SAME: !vmp.unsupported
; OPAQUE-SPOOF-NOT: !vmp.bytecode
; OPAQUE-SPOOF-NOT: !vmp.replaced
; OPAQUE-SPOOF: vmp.fake.xref.user:
; OPAQUE-SPOOF: ret i32 99
define i32 @secret_opaque_name_spoof(i32 %x) {
entry:
  %vmp.opaque.false.user = icmp sgt i32 %x, 0
  br i1 %vmp.opaque.false.user, label %vmp.fake.xref.user, label %vmp.dispatch.user

vmp.fake.xref.user:
  ret i32 99

vmp.dispatch.user:
  %cmp = icmp eq i32 %x, 0
  br i1 %cmp, label %zero, label %other

zero:
  ret i32 7

other:
  ret i32 5
}
