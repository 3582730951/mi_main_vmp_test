; ModuleID = 'vmp-outline-collision'
source_filename = "vmp-outline-collision.c"

@vmp.bytecode.stale_outline = private unnamed_addr constant [8 x i8] c"OUTLINE\00", align 1

; OUTLINE-COLLISION-LABEL: define i32 @secret_outline_collision(i32 %x)
; OUTLINE-COLLISION-SAME: !vmp.protect
; OUTLINE-COLLISION-SAME: !vmp.unsupported
; OUTLINE-COLLISION-NOT: !vmp.bytecode
; OUTLINE-COLLISION-NOT: !vmp.replaced
; OUTLINE-COLLISION: %sum = add i32 %x, 1
; OUTLINE-COLLISION: ret i32 %sum
define i32 @secret_outline_collision(i32 %x) !vmp.protect !0 !vmp.bytecode !1 {
entry:
  %sum = add i32 %x, 1
  ret i32 %sum
}

; OUTLINE-COLLISION-LABEL: define internal i32 @secret_outline_collision.vmp.outline(i32 %x)
; OUTLINE-COLLISION-NOT: !vmp.bytecode
; OUTLINE-COLLISION-NOT: !vmp.replaced
; OUTLINE-COLLISION: ret i32 99
define internal i32 @secret_outline_collision.vmp.outline(i32 %x) !vmp.bytecode !1 !vmp.replaced !2 {
entry:
  ret i32 99
}

; OUTLINE-COLLISION-LABEL: define i32 @secret_outline_spoof(i32 %x)
; OUTLINE-COLLISION-SAME: !vmp.protect
; OUTLINE-COLLISION-SAME: !vmp.unsupported
; OUTLINE-COLLISION-NOT: !vmp.bytecode
; OUTLINE-COLLISION-NOT: !vmp.replaced
; OUTLINE-COLLISION: %sum = add i32 %x, 7
; OUTLINE-COLLISION: ret i32 %sum
define i32 @secret_outline_spoof(i32 %x) !vmp.protect !0 !vmp.bytecode !1 {
entry:
  %sum = add i32 %x, 7
  ret i32 %sum
}

; OUTLINE-COLLISION-LABEL: define internal i32 @secret_outline_spoof.vmp.outline(i32 %x)
; OUTLINE-COLLISION-NOT: !vmp.bytecode
; OUTLINE-COLLISION-NOT: !vmp.replaced
; OUTLINE-COLLISION: ret i32 123
define internal i32 @secret_outline_spoof.vmp.outline(i32 %x) !vmp.outlined.original !3 {
entry:
  ret i32 123
}

!0 = !{!"selected"}
!1 = !{[8 x i8]* @vmp.bytecode.stale_outline}
!2 = !{!"stale-replacement"}
!3 = !{!"secret_outline_spoof"}
