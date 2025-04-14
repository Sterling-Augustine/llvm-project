//===- MCSFrame.h - Machine Code SFrame support -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the MCSFrame to support emitting
// sframe unwinding info from .cfi_* directives. It relies on FDEs and CIEs
// created for Dwarf frame info, but emits the info in a different format.
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCSFRAME_H
#define LLVM_MC_MCSFRAME_H

#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/MC/StringTableBuilder.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MD5.h"
#include "llvm/Support/SMLoc.h"
#include "llvm/Support/StringSaver.h"
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace llvm {


class MCSFrameEmitter {
public:
  //
  // This emits the sframe section.
  //
  static void Emit(MCObjectStreamer &streamer, MCAsmBackend *MAB);
};

} // end namespace llvm
#endif // LLVM_MC_MCSFRAME_H
