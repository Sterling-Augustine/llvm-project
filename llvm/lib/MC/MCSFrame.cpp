//===- lib/MC/MCDwarf.cpp - MCDwarf implementation ------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCSFrame.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/BinaryFormat/SFrame.h"
#include "llvm/Config/config.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectStreamer.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace llvm;
using namespace sframe;

namespace {

class SFrameEmitterImpl {
  int64_t CFAOffset = 0;
  int64_t InitialCFAOffset = 0;
  MCObjectStreamer &Streamer;

public:
  FrameEmitterImpl(MCObjectStreamer &Streamer)
      : Streamer(Streamer) {}

  EmitPreamble() {
    Streamer.emitInt16(SFRAME_MAGIC);
    Streamer.emitInt8(SFRAME_VERSION_2);
    // They aren't sorted at this point in the code, but they
    // will be when they are actually emitted.
    uint8_t flags = SFRAME_F_FDE_SORTED;
    if (Streamer.getContext().getTargetOptions()->
    // if (-fno-omit-frame-pointer)
    //   flags |= FRAME_F_FRAME_POINTER
    Streamer.emitInt8(flags);
  }

  EmitHeader() {
    EmitPreamble();
    MCContext &Context = Streamer.getContext();
    uint8_t ABIArch =
  }
  const MCSymbol &EmitCIE(const MCDwarfFrameInfo &F);
  void EmitFDE(const MCSymbol &cieStart, const MCDwarfFrameInfo &frame,
               bool LastInSection, const MCSymbol &SectionStart);
  void emitCFIInstructions(ArrayRef<MCCFIInstruction> Instrs,
                           MCSymbol *BaseLabel);
  void emitCFIInstruction(const MCCFIInstruction &Instr);
};

} // end anonymous namespace


void MCSFrameEmitter::Emit(MCObjectStreamer &Streamer, MCAsmBackend *MAB) {
  MCContext &Context = Streamer.getContext();
  const MCObjectFileInfo *MOFI = Context.getObjectFileInfo();
  const MCAsmInfo *AsmInfo = Context.getAsmInfo();
  FrameEmitterImpl Emitter(IsEH, Streamer);
  ArrayRef<MCDwarfFrameInfo> FrameArray = Streamer.getDwarfFrameInfos();

  MCSection &Section =
      const_cast<MCObjectFileInfo *>(MOFI)->getSFrameSection();

  Streamer.switchSection(&Section);
  MCSymbol *SectionStart = Context.createTempSymbol();
  Streamer.emitLabel(SectionStart);
  EmitPreamble(Streamer);

  const MCSymbol *LastCIEStart = nullptr;
  for (auto I = FrameArray.begin(), E = FrameArray.end(); I != E;) {
    const MCDwarfFrameInfo &Frame = *I;
    ++I;
    //    Emitter.EmitSFrame(*LastCIEStart, Frame, I == E, *SectionStart);
  }
}
