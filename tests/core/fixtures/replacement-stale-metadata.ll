; ModuleID = 'vmp-replacement-stale-metadata'
source_filename = "vmp-replacement-stale-metadata.c"

; STALE-MD: @vmp.bytecode.stale_metadata = private unnamed_addr constant
; STALE-MD: @vmp.bytecode.secret_stale_metadata_replacement = private unnamed_addr constant
; STALE-MD-NOT: @vmp.bytecode.secret_no_metadata_replacement
@side_effect_sink = global i32 0
@vmp.bytecode.stale_metadata = private unnamed_addr constant [8 x i8] c"STALEMD\00", align 1

; STALE-MD-LABEL: define i32 @secret_stale_metadata_replacement(i32 %x)
; STALE-MD-SAME: !vmp.protect
; STALE-MD-SAME: !vmp.bytecode [[BYTECODE_MD:![0-9]+]]
; STALE-MD-SAME: !vmp.lowering
; STALE-MD-SAME: !vmp.replaced
; STALE-MD: call i32 @vmp_runtime_entry_i32_i32(i8* getelementptr inbounds ([{{[0-9]+}} x i8], [{{[0-9]+}} x i8]* @vmp.bytecode.secret_stale_metadata_replacement, i32 0, i32 0), i64 {{[0-9]+}}, i32 %x)
define i32 @secret_stale_metadata_replacement(i32 %x) !vmp.protect !0 !vmp.bytecode !1 !vmp.unsupported !2 {
entry:
  %out = add i32 %x, 4
  ret i32 %out
}

; STALE-MD-LABEL: define i32 @secret_stale_metadata_unsupported(i32 %x)
; STALE-MD-SAME: !vmp.protect
; STALE-MD-SAME: !vmp.unsupported
; STALE-MD-NOT: !vmp.bytecode
; STALE-MD-NOT: !vmp.replaced
; STALE-MD: store i32 %x, i32* @side_effect_sink
define i32 @secret_stale_metadata_unsupported(i32 %x) !vmp.protect !0 !vmp.bytecode !1 {
entry:
  store i32 %x, i32* @side_effect_sink, align 4
  ret i32 %x
}

; STALE-MD-LABEL: define i32 @secret_no_metadata_replacement(i32 %x)
; STALE-MD-SAME: !vmp.protect
; STALE-MD-NOT: !vmp.bytecode
; STALE-MD-NOT: !vmp.replaced
; STALE-MD: ret i32 %out
define i32 @secret_no_metadata_replacement(i32 %x) !vmp.protect !0 {
entry:
  %out = add i32 %x, 8
  ret i32 %out
}

; STALE-MD: [[BYTECODE_MD]] = !{[{{[0-9]+}} x i8]* @vmp.bytecode.secret_stale_metadata_replacement}
!0 = !{!"selected"}
!1 = !{[8 x i8]* @vmp.bytecode.stale_metadata}
!2 = !{!"old-unsupported"}
