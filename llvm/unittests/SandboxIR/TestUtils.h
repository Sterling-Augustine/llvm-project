//===- unittests/SandboxIR/TestUtils.h
//-------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TEST_TESTUTILS_H
#define LLVM_TEST_TESTUTILS_H

#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/SandboxIR/Constant.h"
#include "llvm/SandboxIR/Context.h"
#include "llvm/SandboxIR/Function.h"
#include "llvm/Support/SourceMgr.h"
#include "gtest/gtest.h"

#include "gtest/gtest.h"
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// A class to make building SandboxIR from LLVM-IR for tests convenient without
// redeclaring and renaming all the commonly used variables.  Unfortunately,
// gtest doesn't support custom constructors, so anything that depends on the
// asm string is initialized after parsing, which makes some parts feel awkward.

struct SandboxIRTest : public testing::Test {
  struct LLVMData {
    explicit LLVMData() = delete;
    explicit LLVMData(llvm::Module *M, llvm::StringRef FName)
        : F(M->getFunction(FName)), DT(*F), TLII(), TLI(TLII),
          DL(M->getDataLayout()), AC(*F), BAA(DL, *F, TLI, AC, &DT), AA(TLI),
          LI(DT), SE(*F, TLI, AC, DT, LI) {
      assert(F && "Function FName not defined.");
    };
    llvm::Function *F;
    llvm::DominatorTree DT;
    llvm::TargetLibraryInfoImpl TLII;
    llvm::TargetLibraryInfo TLI;
    llvm::DataLayout DL;
    llvm::AssumptionCache AC;
    llvm::BasicAAResult BAA;
    llvm::AAResults AA;
    llvm::LoopInfo LI;
    llvm::ScalarEvolution SE;
  };

  llvm::LLVMContext LLVMCtx;
  std::unique_ptr<llvm::Module> M;
  std::unique_ptr<LLVMData> LLVM;
  std::unique_ptr<llvm::sandboxir::Context> Ctx;
  llvm::sandboxir::Function *F;

  // setup all the sandboxir boilerplate from \p IR, with \p FName as the
  // function of interest
  void setUp(llvm::StringRef FName, llvm::StringRef IR) {
    llvm::SMDiagnostic Err;
    M = parseAssemblyString(IR, Err, LLVMCtx);
    if (!M)
      Err.print("LegalityTest", llvm::errs());
    LLVM = std::make_unique<LLVMData>(M.get(), FName);
    Ctx = std::make_unique<llvm::sandboxir::Context>(LLVMCtx);
    F = Ctx->createFunction(LLVM->F);
  }

  llvm::BasicBlock *getBasicBlockByName(llvm::StringRef Name) {
    for (llvm::BasicBlock &BB : *LLVM->F)
      if (BB.getName() == Name)
        return &BB;
    llvm_unreachable("Expected to find basic block!");
  }
};

#endif // LLVM_TEST_TESTUTILS_H
