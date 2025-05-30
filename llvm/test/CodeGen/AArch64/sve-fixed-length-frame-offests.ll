; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 5
; RUN: llc -debug-only=isel < %s 2>&1 | FileCheck %s

; REQUIRES: asserts

target triple = "aarch64-unknown-linux-gnu"

; Ensure that only no offset frame indexes are folded into SVE load/stores when
; accessing fixed width objects.
define void @foo(ptr %a) #0 {
; CHECK-LABEL: foo:
; CHECK:       SelectionDAG has 13 nodes:
; CHECK-NEXT:    t0: ch,glue = EntryToken
; CHECK-NEXT:    t2: i64,ch = CopyFromReg t0, Register:i64 %0
; CHECK-NEXT:    t21: nxv2i64,ch = LDR_ZXI<Mem:(volatile load (<vscale x 1 x s128>) from %ir.a, align 64)> t2, TargetConstant:i64<0>, t0
; CHECK-NEXT:    t8: i64 = ADDXri TargetFrameIndex:i64<1>, TargetConstant:i32<0>, TargetConstant:i32<0>
; CHECK-NEXT:    t6: i64 = ADDXri TargetFrameIndex:i64<0>, TargetConstant:i32<0>, TargetConstant:i32<0>
; CHECK-NEXT:    t22: ch = STR_ZXI<Mem:(volatile store (<vscale x 1 x s128>) into %ir.r0, align 64)> t21, t6, TargetConstant:i64<0>, t21:1
; CHECK-NEXT:    t23: ch = STR_ZXI<Mem:(volatile store (<vscale x 1 x s128>) into %ir.r1, align 64)> t21, t8, TargetConstant:i64<0>, t22
; CHECK-NEXT:    t10: ch = RET_ReallyLR t23
; CHECK-EMPTY:
entry:
  %r0 = alloca <8 x i64>
  %r1 = alloca <8 x i64>
  %r = load volatile <8 x i64>, ptr %a
  store volatile <8 x i64> %r, ptr %r0
  store volatile <8 x i64> %r, ptr %r1
  ret void
}

attributes #0 = { nounwind "target-features"="+sve" vscale_range(4,4) }
