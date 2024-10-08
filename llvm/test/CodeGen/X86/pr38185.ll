; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -o - %s -mtriple=x86_64--unknown-linux-gnu | FileCheck %s

define void @foo(ptr %a, ptr %b, ptr noalias %c, i64 %s) {
; CHECK-LABEL: foo:
; CHECK:       # %bb.0:
; CHECK-NEXT:    movq $0, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    .p2align 4
; CHECK-NEXT:  .LBB0_1: # %loop
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    movq -{{[0-9]+}}(%rsp), %rax
; CHECK-NEXT:    cmpq %rcx, %rax
; CHECK-NEXT:    je .LBB0_3
; CHECK-NEXT:  # %bb.2: # %body
; CHECK-NEXT:    # in Loop: Header=BB0_1 Depth=1
; CHECK-NEXT:    movl $1, (%rdx,%rax,4)
; CHECK-NEXT:    movzbl (%rdi,%rax,4), %r8d
; CHECK-NEXT:    movzbl (%rsi,%rax,4), %r9d
; CHECK-NEXT:    andl %r8d, %r9d
; CHECK-NEXT:    andl $1, %r9d
; CHECK-NEXT:    movl %r9d, (%rdi,%rax,4)
; CHECK-NEXT:    incq %rax
; CHECK-NEXT:    movq %rax, -{{[0-9]+}}(%rsp)
; CHECK-NEXT:    jmp .LBB0_1
; CHECK-NEXT:  .LBB0_3: # %endloop
; CHECK-NEXT:    retq
%i = alloca i64
store i64 0, ptr %i
br label %loop

loop:
%ct = load i64, ptr %i
%comp = icmp eq i64 %ct, %s
br i1 %comp, label %endloop, label %body

body:
%var0 = getelementptr i32, ptr %c, i64 %ct
store i32 1, ptr %var0
%var1 = getelementptr i32, ptr %c, i64 %ct
%var2 = load i32, ptr %var1
%var3 = add i32 %var2, 1
%var4 = getelementptr i32, ptr %a, i64 %ct
%var5 = load i32, ptr %var4
%var6 = and i32 %var3, %var5
%var7 = add i32 %var6, 1
%var8 = getelementptr i32, ptr %a, i64 %ct
%var9 = load i32, ptr %var8
%var10 = and i32 %var7, %var9
%var11 = getelementptr i32, ptr %c, i64 %ct
%var12 = load i32, ptr %var11
%var13 = and i32 %var10, %var12
%var14 = getelementptr i32, ptr %b, i64 %ct
%var15 = load i32, ptr %var14
%var16 = and i32 %var15, 63
%var17 = and i32 %var13, %var16
%var18 = getelementptr i32, ptr %a, i64 %ct
store i32 %var17, ptr %var18
%z = add i64 1, %ct
store i64 %z, ptr %i
br label %loop

endloop:
ret void
}
