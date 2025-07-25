; RUN: llc -asm-verbose=false < %s -mattr=+vfp3,+fp16 | FileCheck -allow-deprecated-dag-overlap %s -check-prefix=CHECK-FP16  --check-prefix=CHECK-VFP -check-prefix=CHECK-ALL
; RUN: llc -asm-verbose=false < %s | FileCheck -allow-deprecated-dag-overlap %s -check-prefix=CHECK-LIBCALL --check-prefix=CHECK-VFP -check-prefix=CHECK-ALL --check-prefix=CHECK-LIBCALL-VFP
; RUN: llc -asm-verbose=false < %s -mattr=-fpregs | FileCheck -allow-deprecated-dag-overlap %s --check-prefix=CHECK-LIBCALL -check-prefix=CHECK-NOVFP -check-prefix=CHECK-ALL

target datalayout = "e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-a0:0:64-n32"
target triple = "armv7---eabihf"

define void @test_fadd(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fadd:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vadd.f32
; CHECK-NOVFP: bl __aeabi_fadd
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fadd half %a, %b
  store half %r, ptr %p
  ret void
}

define void @test_fsub(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fsub:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vsub.f32
; CHECK-NOVFP: bl __aeabi_fsub
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fsub half %a, %b
  store half %r, ptr %p
  ret void
}

define void @test_fmul(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fmul:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vmul.f32
; CHECK-NOVFP: bl __aeabi_fmul
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fmul half %a, %b
  store half %r, ptr %p
  ret void
}

define void @test_fdiv(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fdiv:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vdiv.f32
; CHECK-NOVFP: bl __aeabi_fdiv
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fdiv half %a, %b
  store half %r, ptr %p
  ret void
}

define void @test_frem(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_frem:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl fmodf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = frem half %a, %b
  store half %r, ptr %p
  ret void
}

define void @test_load_store(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_load_store:
; CHECK-ALL-NEXT: .fnstart
; CHECK-ALL: ldrh {{r[0-9]+}}, [{{r[0-9]+}}]
; CHECK-ALL: strh {{r[0-9]+}}, [{{r[0-9]+}}]
  %a = load half, ptr %p, align 2
  store half %a, ptr %q
  ret void
}

; Testing only successfull compilation of function calls.  In ARM ABI, half
; args and returns are handled as f32.

declare half @test_callee(half %a, half %b) #0

define half @test_call(half %a, half %b) #0 {
; CHECK-ALL-LABEL: test_call:
; CHECK-ALL-NEXT: .fnstart
; CHECK-ALL-NEXT: .save {r11, lr}
; CHECK-ALL-NEXT: push {r11, lr}
; CHECK-ALL-NEXT: bl test_callee
; CHECK-ALL-NEXT: pop {r11, pc}
  %r = call half @test_callee(half %a, half %b)
  ret half %r
}

define half @test_call_flipped(half %a, half %b) #0 {
; CHECK-ALL-LABEL: test_call_flipped:
; CHECK-ALL-NEXT: .fnstart
; CHECK-ALL-NEXT: .save {r11, lr}
; CHECK-ALL-NEXT: push {r11, lr}
; CHECK-VFP-NEXT: vmov.f32 s2, s0
; CHECK-VFP-NEXT: vmov.f32 s0, s1
; CHECK-VFP-NEXT: vmov.f32 s1, s2
; CHECK-NOVFP-NEXT: mov r2, r0
; CHECK-NOVFP-NEXT: mov r0, r1
; CHECK-NOVFP-NEXT: mov r1, r2
; CHECK-ALL-NEXT: bl test_callee
; CHECK-ALL-NEXT: pop {r11, pc}
  %r = call half @test_callee(half %b, half %a)
  ret half %r
}

define half @test_tailcall_flipped(half %a, half %b) #0 {
; CHECK-ALL-LABEL: test_tailcall_flipped:
; CHECK-ALL-NEXT: .fnstart
; CHECK-VFP-NEXT: vmov.f32 s2, s0
; CHECK-VFP-NEXT: vmov.f32 s0, s1
; CHECK-VFP-NEXT: vmov.f32 s1, s2
; CHECK-NOVFP-NEXT: mov r2, r0
; CHECK-NOVFP-NEXT: mov r0, r1
; CHECK-NOVFP-NEXT: mov r1, r2
; CHECK-ALL-NEXT: b test_callee
  %r = tail call half @test_callee(half %b, half %a)
  ret half %r
}

; Optimizer picks %p or %q based on %c and only loads that value
; No conversion is needed
define void @test_select(ptr %p, ptr %q, i1 zeroext %c) #0 {
; CHECK-ALL-LABEL: test_select:
; CHECK-ALL: cmp {{r[0-9]+}}, #0
; CHECK-ALL: movne {{r[0-9]+}}, {{r[0-9]+}}
; CHECK-ALL: ldrh {{r[0-9]+}}, [{{r[0-9]+}}]
; CHECK-ALL: strh {{r[0-9]+}}, [{{r[0-9]+}}]
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = select i1 %c, half %a, half %b
  store half %r, ptr %p
  ret void
}

; Test only two variants of fcmp.  These get translated to f32 vcmp
; instructions anyway.
define i1 @test_fcmp_une(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fcmp_une:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcmp.f32
; CHECK-NOVFP: bl __aeabi_fcmpeq
; CHECK-VFP-NEXT: vmrs APSR_nzcv, fpscr
; CHECK-VFP-NEXT: movwne
; CHECK-NOVFP-NEXT: clz r0, r0
; CHECK-NOVFP-NEXT: lsr r0, r0, #5
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fcmp une half %a, %b
  ret i1 %r
}

define i1 @test_fcmp_ueq(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_fcmp_ueq:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcmp.f32
; CHECK-NOVFP: bl __aeabi_fcmpeq
; CHECK-FP16: vmrs APSR_nzcv, fpscr
; CHECK-LIBCALL: movw{{ne|eq}}
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = fcmp ueq half %a, %b
  ret i1 %r
}

define void @test_br_cc(ptr %p, ptr %q, ptr %p1, ptr %p2) #0 {
; CHECK-ALL-LABEL: test_br_cc:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcmp.f32
; CHECK-NOVFP: bl __aeabi_fcmplt
; CHECK-FP16: vmrs APSR_nzcv, fpscr
; CHECK-VFP: movmi
; CHECK-VFP: str
; CHECK-NOVFP: str
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %c = fcmp uge half %a, %b
  br i1 %c, label %then, label %else
then:
  store i32 0, ptr %p1
  ret void
else:
  store i32 0, ptr %p2
  ret void
}

declare i1 @test_dummy(ptr %p) #0
; CHECK-ALL-LABEL: test_phi:
; CHECK-FP16: [[LOOP:.LBB[0-9_]+]]:
; CHECK-FP16: bl      test_dummy
; CHECK-FP16: bne     [[LOOP]]
; CHECK-LIBCALL: [[LOOP:.LBB[0-9_]+]]:
; CHECK-LIBCALL: bl test_dummy
; CHECK-LIBCALL: bne     [[LOOP]]
define void @test_phi(ptr %p) #0 {
entry:
  %a = load half, ptr %p
  br label %loop
loop:
  %r = phi half [%a, %entry], [%b, %loop]
  %b = load half, ptr %p
  %c = call i1 @test_dummy(ptr %p)
  br i1 %c, label %loop, label %return
return:
  store half %r, ptr %p
  ret void
}

define i32 @test_fptosi_i32(ptr %p) #0 {
; CHECK-ALL-LABEL: test_fptosi_i32:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcvt.s32.f32
; CHECK-NOVFP: bl __aeabi_f2iz
  %a = load half, ptr %p, align 2
  %r = fptosi half %a to i32
  ret i32 %r
}

define i64 @test_fptosi_i64(ptr %p) #0 {
; CHECK-ALL-LABEL: test_fptosi_i64:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-ALL: bl __aeabi_f2lz
  %a = load half, ptr %p, align 2
  %r = fptosi half %a to i64
  ret i64 %r
}

define i32 @test_fptoui_i32(ptr %p) #0 {
; CHECK-ALL-LABEL: test_fptoui_i32:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcvt.u32.f32
; CHECK-NOVFP: bl __aeabi_f2uiz
  %a = load half, ptr %p, align 2
  %r = fptoui half %a to i32
  ret i32 %r
}

define i64 @test_fptoui_i64(ptr %p) #0 {
; CHECK-ALL-LABEL: test_fptoui_i64:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-ALL: bl __aeabi_f2ulz
  %a = load half, ptr %p, align 2
  %r = fptoui half %a to i64
  ret i64 %r
}

define void @test_sitofp_i32(i32 %a, ptr %p) #0 {
; CHECK-ALL-LABEL: test_sitofp_i32:
; CHECK-VFP: vcvt.f32.s32
; CHECK-NOVFP: bl __aeabi_i2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %r = sitofp i32 %a to half
  store half %r, ptr %p
  ret void
}

define void @test_uitofp_i32(i32 %a, ptr %p) #0 {
; CHECK-ALL-LABEL: test_uitofp_i32:
; CHECK-VFP: vcvt.f32.u32
; CHECK-NOVFP: bl __aeabi_ui2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %r = uitofp i32 %a to half
  store half %r, ptr %p
  ret void
}

define void @test_sitofp_i64(i64 %a, ptr %p) #0 {
; CHECK-ALL-LABEL: test_sitofp_i64:
; CHECK-ALL: bl __aeabi_l2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %r = sitofp i64 %a to half
  store half %r, ptr %p
  ret void
}

define void @test_uitofp_i64(i64 %a, ptr %p) #0 {
; CHECK-ALL-LABEL: test_uitofp_i64:
; CHECK-ALL: bl __aeabi_ul2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_f2h
  %r = uitofp i64 %a to half
  store half %r, ptr %p
  ret void
}

define void @test_fptrunc_float(float %f, ptr %p) #0 {
; CHECK-FP16-LABEL: test_fptrunc_float:
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_fptrunc_float:
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = fptrunc float %f to half
  store half %a, ptr %p
  ret void
}

define void @test_fptrunc_double(double %d, ptr %p) #0 {
; CHECK-FP16-LABEL: test_fptrunc_double:
; CHECK-FP16: bl __aeabi_d2h
; CHECK-LIBCALL-LABEL: test_fptrunc_double:
; CHECK-LIBCALL: bl __aeabi_d2h
  %a = fptrunc double %d to half
  store half %a, ptr %p
  ret void
}

define float @test_fpextend_float(ptr %p) {
; CHECK-FP16-LABEL: test_fpextend_float:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL-LABEL: test_fpextend_float:
; CHECK-LIBCALL: bl __aeabi_h2f
  %a = load half, ptr %p, align 2
  %r = fpext half %a to float
  ret float %r
}

define double @test_fpextend_double(ptr %p) {
; CHECK-FP16-LABEL: test_fpextend_double:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL-LABEL: test_fpextend_double:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-VFP: vcvt.f64.f32
; CHECK-NOVFP: bl __aeabi_f2d
  %a = load half, ptr %p, align 2
  %r = fpext half %a to double
  ret double %r
}

define i16 @test_bitcast_halftoi16(ptr %p) #0 {
; CHECK-ALL-LABEL: test_bitcast_halftoi16:
; CHECK-ALL-NEXT: .fnstart
; CHECK-ALL-NEXT: ldrh r0, [r0]
; CHECK-ALL-NEXT: bx lr
  %a = load half, ptr %p, align 2
  %r = bitcast half %a to i16
  ret i16 %r
}

define void @test_bitcast_i16tohalf(i16 %a, ptr %p) #0 {
; CHECK-ALL-LABEL: test_bitcast_i16tohalf:
; CHECK-ALL-NEXT: .fnstart
; CHECK-ALL-NEXT: strh r0, [r1]
; CHECK-ALL-NEXT: bx lr
  %r = bitcast i16 %a to half
  store half %r, ptr %p
  ret void
}

declare half @llvm.sqrt.f16(half %a) #0
declare half @llvm.powi.f16.i32(half %a, i32 %b) #0
declare half @llvm.sin.f16(half %a) #0
declare half @llvm.cos.f16(half %a) #0
declare half @llvm.tan.f16(half %a) #0
declare half @llvm.pow.f16(half %a, half %b) #0
declare half @llvm.exp.f16(half %a) #0
declare half @llvm.exp2.f16(half %a) #0
declare half @llvm.log.f16(half %a) #0
declare half @llvm.log10.f16(half %a) #0
declare half @llvm.log2.f16(half %a) #0
declare half @llvm.fma.f16(half %a, half %b, half %c) #0
declare half @llvm.fabs.f16(half %a) #0
declare half @llvm.minnum.f16(half %a, half %b) #0
declare half @llvm.maxnum.f16(half %a, half %b) #0
declare half @llvm.copysign.f16(half %a, half %b) #0
declare half @llvm.floor.f16(half %a) #0
declare half @llvm.ceil.f16(half %a) #0
declare half @llvm.trunc.f16(half %a) #0
declare half @llvm.rint.f16(half %a) #0
declare half @llvm.nearbyint.f16(half %a) #0
declare half @llvm.round.f16(half %a) #0
declare half @llvm.roundeven.f16(half %a) #0
declare half @llvm.fmuladd.f16(half %a, half %b, half %c) #0

define void @test_sqrt(ptr %p) #0 {
; CHECK-ALL-LABEL: test_sqrt:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vsqrt.f32
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL-VFP: vsqrt.f32
; CHECK-NOVFP: bl sqrtf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.sqrt.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_fpowi(ptr %p, i32 %b) #0 {
; CHECK-FP16-LABEL: test_fpowi:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl __powisf2
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_fpowi:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __powisf2
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.powi.f16.i32(half %a, i32 %b)
  store half %r, ptr %p
  ret void
}

define void @test_sin(ptr %p) #0 {
; CHECK-FP16-LABEL: test_sin:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl sinf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_sin:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl sinf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.sin.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_cos(ptr %p) #0 {
; CHECK-FP16-LABEL: test_cos:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl cosf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_cos:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl cosf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.cos.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_tan(ptr %p) #0 {
; CHECK-FP16-LABEL: test_tan:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl tanf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_tan:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl tanf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.tan.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_pow(ptr %p, ptr %q) #0 {
; CHECK-FP16-LABEL: test_pow:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl powf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_pow:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl powf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = call half @llvm.pow.f16(half %a, half %b)
  store half %r, ptr %p
  ret void
}

define void @test_cbrt(ptr %p) #0 {
; CHECK-FP16-LABEL: test_cbrt:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl powf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_cbrt:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl powf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.pow.f16(half %a, half 0x3FD5540000000000)
  store half %r, ptr %p
  ret void
}

define void @test_exp(ptr %p) #0 {
; CHECK-FP16-LABEL: test_exp:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl expf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_exp:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl expf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.exp.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_exp2(ptr %p) #0 {
; CHECK-FP16-LABEL: test_exp2:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl exp2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_exp2:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl exp2f
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.exp2.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_log(ptr %p) #0 {
; CHECK-FP16-LABEL: test_log:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl logf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_log:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl logf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.log.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_log10(ptr %p) #0 {
; CHECK-FP16-LABEL: test_log10:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl log10f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_log10:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl log10f
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.log10.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_log2(ptr %p) #0 {
; CHECK-FP16-LABEL: test_log2:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl log2f
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_log2:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl log2f
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.log2.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_fma(ptr %p, ptr %q, ptr %r) #0 {
; CHECK-FP16-LABEL: test_fma:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl fmaf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_fma:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl fmaf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %c = load half, ptr %r, align 2
  %v = call half @llvm.fma.f16(half %a, half %b, half %c)
  store half %v, ptr %p
  ret void
}

define void @test_fabs(ptr %p) {
; CHECK-FP16-LABEL: test_fabs:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vabs.f32
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_fabs:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bic
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.fabs.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_minnum(ptr %p, ptr %q) #0 {
; CHECK-FP16-LABEL: test_minnum:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl fminf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_minnum:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl fminf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = call half @llvm.minnum.f16(half %a, half %b)
  store half %r, ptr %p
  ret void
}

define void @test_maxnum(ptr %p, ptr %q) #0 {
; CHECK-FP16-LABEL: test_maxnum:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl fmaxf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_maxnum:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl fmaxf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = call half @llvm.maxnum.f16(half %a, half %b)
  store half %r, ptr %p
  ret void
}

define void @test_minimum(ptr %p) #0 {
; CHECK-ALL-LABEL: test_minimum:
; CHECK-FP16: vmov.f32 s0, #1.000000e+00
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL-VFP: vmov.f32 s{{[0-9]+}}, #1.000000e+00
; CHECK-NOVFP: mov r{{[0-9]+}}, #1065353216
; CHECK-VFP: vcmp.f32
; CHECK-VFP: vmrs
; CHECK-VFP: movge
; CHECK-NOVFP: bl __aeabi_fcmpge
  %a = load half, ptr %p, align 2
  %c = fcmp ult half %a, 1.0
  %r = select i1 %c, half %a, half 1.0
  store half %r, ptr %p
  ret void
}

define void @test_maximum(ptr %p) #0 {
; CHECK-ALL-LABEL: test_maximum:
; CHECK-FP16: vmov.f32 s0, #1.000000e+00
; CHECK-FP16: vcvtb.f32.f16
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL-VFP: vmov.f32 s0, #1.000000e+00
; CHECK-NOVFP: mov r{{[0-9]+}}, #1065353216
; CHECK-VFP: vcmp.f32
; CHECK-VFP: vmrs
; CHECK-VFP: movls
; CHECK-NOVFP: bl __aeabi_fcmple
  %a = load half, ptr %p, align 2
  %c = fcmp ugt half %a, 1.0
  %r = select i1 %c, half %a, half 1.0
  store half %r, ptr %p
  ret void
}

define void @test_copysign(ptr %p, ptr %q) #0 {
; CHECK-ALL-LABEL: test_copysign:
; CHECK-ALL:         ldrh r2, [r0]
; CHECK-ALL-NEXT:    ldrh r1, [r1]
; CHECK-ALL-NEXT:    and r1, r1, #32768
; CHECK-ALL-NEXT:    bfc r2, #15, #17
; CHECK-ALL-NEXT:    orr r1, r2, r1
; CHECK-ALL-NEXT:    strh r1, [r0]
; CHECK-ALL-NEXT:    bx lr
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %r = call half @llvm.copysign.f16(half %a, half %b)
  store half %r, ptr %p
  ret void
}

define void @test_floor(ptr %p) {
; CHECK-FP16-LABEL: test_floor:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl floorf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_floor:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl floorf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.floor.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_ceil(ptr %p) {
; CHECK-FP16-LABEL: test_ceil:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl ceilf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_ceil:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl ceilf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.ceil.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_trunc(ptr %p) {
; CHECK-FP16-LABEL: test_trunc:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl truncf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_trunc:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl truncf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.trunc.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_rint(ptr %p) {
; CHECK-FP16-LABEL: test_rint:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl rintf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_rint:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl rintf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.rint.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_nearbyint(ptr %p) {
; CHECK-FP16-LABEL: test_nearbyint:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl nearbyintf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_nearbyint:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl nearbyintf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.nearbyint.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_round(ptr %p) {
; CHECK-FP16-LABEL: test_round:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl roundf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_round:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl roundf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.round.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_roundeven(ptr %p) {
; CHECK-FP16-LABEL: test_roundeven:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: bl roundevenf
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_roundeven:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl roundevenf
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %r = call half @llvm.roundeven.f16(half %a)
  store half %r, ptr %p
  ret void
}

define void @test_fmuladd(ptr %p, ptr %q, ptr %r) #0 {
; CHECK-FP16-LABEL: test_fmuladd:
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vmul.f32
; CHECK-FP16: vcvtb.f16.f32
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vcvtb.f32.f16
; CHECK-FP16: vadd.f32
; CHECK-FP16: vcvtb.f16.f32
; CHECK-LIBCALL-LABEL: test_fmuladd:
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL-VFP: vmul.f32
; CHECK-NOVFP: bl __aeabi_fmul
; CHECK-LIBCALL: bl __aeabi_f2h
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL: bl __aeabi_h2f
; CHECK-LIBCALL-VFP: vadd.f32
; CHECK-NOVFP: bl __aeabi_fadd
; CHECK-LIBCALL: bl __aeabi_f2h
  %a = load half, ptr %p, align 2
  %b = load half, ptr %q, align 2
  %c = load half, ptr %r, align 2
  %v = call half @llvm.fmuladd.f16(half %a, half %b, half %c)
  store half %v, ptr %p
  ret void
}

; f16 vectors are not legal in the backend.  Vector elements are not assigned
; to the register, but are stored in the stack instead.  Hence insertelement
; and extractelement have these extra loads and stores.
define void @test_insertelement(ptr %p, ptr %q, i32 %i) #0 {
; CHECK-ALL-LABEL: test_insertelement:
; CHECK-ALL: sub sp, sp, #8

; CHECK-ALL-DAG: and
; CHECK-ALL-DAG: mov
; CHECK-ALL-DAG: ldrd
; CHECK-ALL-DAG: orr
; CHECK-ALL-DAG: ldrh
; CHECK-ALL-DAG: stm
; CHECK-ALL: ldrh
; CHECK-ALL-DAG: ldrh
; CHECK-ALL-DAG: ldrh
; CHECK-ALL-DAG: ldrh
; CHECK-ALL-DAG: strh
; CHECK-ALL-DAG: strh
; CHECK-ALL-DAG: strh
; CHECK-ALL-DAG: strh
; CHECK-ALL: strh

; CHECK-ALL: add sp, sp, #8
  %a = load half, ptr %p, align 2
  %b = load <4 x half>, ptr %q, align 8
  %c = insertelement <4 x half> %b, half %a, i32 %i
  store volatile <4 x half> %c, ptr %q
  ret void
}

define void @test_extractelement(ptr %p, ptr %q, i32 %i) #0 {
; CHECK-ALL-LABEL: test_extractelement:
; CHECK-ALL: push {{{.*}}, lr}
; CHECK-ALL: sub sp, sp, #8
; CHECK-ALL: ldrd
; CHECK-ALL: mov
; CHECK-ALL: orr
; CHECK-ALL: ldrh
; CHECK-ALL: strh
; CHECK-ALL: add sp, sp, #8
; CHECK-ALL: pop {{{.*}}, pc}
  %a = load <4 x half>, ptr %q, align 8
  %b = extractelement <4 x half> %a, i32 %i
  store half %b, ptr %p
  ret void
}

; test struct operations

%struct.dummy = type { i32, half }

define void @test_insertvalue(ptr %p, ptr %q) {
; CHECK-ALL-LABEL: test_insertvalue:
; CHECK-ALL-DAG: ldr
; CHECK-ALL-DAG: ldrh
; CHECK-ALL-DAG: strh
; CHECK-ALL-DAG: str
  %a = load %struct.dummy, ptr %p
  %b = load half, ptr %q
  %c = insertvalue %struct.dummy %a, half %b, 1
  store %struct.dummy %c, ptr %p
  ret void
}

define void @test_extractvalue(ptr %p, ptr %q) {
; CHECK-ALL-LABEL: test_extractvalue:
; CHECK-ALL: .fnstart
; CHECK-ALL: ldrh
; CHECK-ALL: strh
  %a = load %struct.dummy, ptr %p
  %b = extractvalue %struct.dummy %a, 1
  store half %b, ptr %q
  ret void
}

define %struct.dummy @test_struct_return(ptr %p) {
; CHECK-ALL-LABEL: test_struct_return:
; CHECK-VFP-LIBCALL: bl __aeabi_h2f
; CHECK-NOVFP-DAG: ldr
; CHECK-NOVFP-DAG: ldrh
  %a = load %struct.dummy, ptr %p
  ret %struct.dummy %a
}

define half @test_struct_arg(%struct.dummy %p) {
; CHECK-ALL-LABEL: test_struct_arg:
; CHECK-ALL-NEXT: .fnstart
; CHECK-NOVFP-NEXT: mov r0, r1
; CHECK-ALL-NEXT: bx lr
  %a = extractvalue %struct.dummy %p, 1
  ret half %a
}

define half @test_uitofp_i32_fadd(i32 %a, half %b) #0 {
; CHECK-LABEL: test_uitofp_i32_fadd:
; CHECK-VFP-DAG: vcvt.f32.u32
; CHECK-NOVFP-DAG: bl __aeabi_ui2f

; CHECK-FP16-DAG: vcvtb.f16.f32
; CHECK-FP16-DAG: vcvtb.f32.f16
; CHECK-LIBCALL-DAG: bl __aeabi_h2f
; CHECK-LIBCALL-DAG: bl __aeabi_h2f

; CHECK-VFP-DAG: vadd.f32
; CHECK-NOVFP-DAG: bl __aeabi_fadd

; CHECK-FP16-DAG: vcvtb.f16.f32
; CHECK-LIBCALL-DAG: bl __aeabi_f2h
  %c = uitofp i32 %a to half
  %r = fadd half %b, %c
  ret half %r
}

define half @test_sitofp_i32_fadd(i32 %a, half %b) #0 {
; CHECK-LABEL: test_sitofp_i32_fadd:
; CHECK-VFP-DAG: vcvt.f32.s32
; CHECK-NOVFP-DAG: bl __aeabi_i2f

; CHECK-FP16-DAG: vcvtb.f16.f32
; CHECK-FP16-DAG: vcvtb.f32.f16
; CHECK-LIBCALL-DAG: bl __aeabi_h2f
; CHECK-LIBCALL-DAG: bl __aeabi_h2f

; CHECK-VFP-DAG: vadd.f32
; CHECK-NOVFP-DAG: bl __aeabi_fadd

; CHECK-FP16-DAG: vcvtb.f16.f32
; CHECK-LIBCALL-DAG: bl __aeabi_f2h
  %c = sitofp i32 %a to half
  %r = fadd half %b, %c
  ret half %r
}

attributes #0 = { nounwind }
