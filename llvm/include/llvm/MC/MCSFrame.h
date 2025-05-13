//===- MCSFrame.h - Machine Code SFrame support -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of MCSFrameEmitter to support emitting
// sframe unwinding info from .cfi_* directives. It relies on FDEs and CIEs
// created for Dwarf frame info, but emits that info in a different format.
//
// See https://sourceware.org/binutils/docs-2.41/sframe-spec.html
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCSFRAME_H
#define LLVM_MC_MCSFRAME_H

#include <cstdint>

#include "llvm/ADT/SmallVector.h"

namespace llvm {

class MCAsmBackend;
class MCContext;
class MCObjectStreamer;
class MCSFrameFragment;

class MCSFrameEmitter {
public:
  //
  // This emits the sframe section.
  //
  static void Emit(MCObjectStreamer &streamer);
  static void encodeFuncOffset(MCContext &C, uint64_t Offset,
                               SmallVectorImpl<char> &Data,
                               MCSFrameFragment *FDEFrag);
};

} // end namespace llvm
#endif // LLVM_MC_MCSFRAME_H
