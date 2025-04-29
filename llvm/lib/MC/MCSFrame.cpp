//===- lib/MC/MCSFrame.cpp - MCSFrame implementation ----------------------===//
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


// Relying on MCStreamer by emitting these field-by-field lets Streamer do
// target endian-fixups for free.

class SFrameEmitterImpl {

  // High-level structure to track info needed to emit a
  // sframe_frame_row_entry_addrX. On disk these have both a fixed portion of
  // type sframe_frame_row_entry_addrX and trailing data of X * S bytes, where X
  // is the datum size, and S is 1, 2, or 3 depending on which of Cfa, SP, and
  // FP are being tracked.
  struct SFrameFRE {
    SFrameFRE(size_t FO) : FuncOffset(FO) {}

    // An FRE describes how to find the registers when the PC is at this
    // Offset from function start.
    size_t FuncOffset = 0;
    size_t CfaOffset = 0;
    size_t FPOffset = 0;
    size_t RAOffset = 0;
    bool FromFP = false;

  void Emit(MCStreamer& S, unsigned FDEI) {
    // sfre_start_address. Technically an offset. Field-width chosen according
    // to the enclosing function's size.
    switch (FDEI & fretype_mask) {
    case SFRAME_FRE_TYPE_ADDR1:
      assert(FuncOffset < std::numeric_limits<uint8_t>::max() &&
             "Miscalculated sdfe_func_info offset uint8_t");
      S.emitInt8(FuncOffset & 0xFF);
      break;
    case SFRAME_FRE_TYPE_ADDR2:
      assert(FuncOffset < std::numeric_limits<uint16_t>::max() &&
             "Miscalculated sdfe_func_info offset uint16_t");
      S.emitInt16(FuncOffset & 0xFFFF);
      break;
    case SFRAME_FRE_TYPE_ADDR4:
      assert(FuncOffset < std::numeric_limits<uint32_t>::max() &&
             "Miscalculated sdfe_func_info offset uint32_t");
      S.emitInt32(FuncOffset);
      break;
    default:
      // Should have errored long before this.
      llvm_unreachable("SFrame v2 doesn't support 4GB functions");
    }

    unsigned Info = 0;
    // fre_cfa_base_reg_id (sframe_fre_info_word:0)
    if (!FromFP)
      Info |= SFRAME_BASE_REG_SP;

    // fre_offset_count (sframe_fre_info_word:1-4)
    unsigned RegsTracked = 1; // always track the cfa.
    if (FPOffset != 0)
      RegsTracked++;
    if (RAOffset != 0)
      RegsTracked++;
    Info |= (RegsTracked << 1);

    // fre_offset_size (sframe_fre_info_word:5-6)
    unsigned OffsetSize;
    if ((CfaOffset <= std::numeric_limits<uint8_t>::max() &&
         FPOffset <= std::numeric_limits<uint8_t>::max() &&
         RAOffset <= std::numeric_limits<uint8_t>::max()))
      OffsetSize = SFRAME_FRE_OFFSET_1B;
    else if (CfaOffset <= std::numeric_limits<uint16_t>::max() &&
        FPOffset <= std::numeric_limits<uint16_t>::max() &&
        RAOffset <= std::numeric_limits<uint16_t>::max())
      OffsetSize = SFRAME_FRE_OFFSET_2B;
    else
      OffsetSize = SFRAME_FRE_OFFSET_4B;
    Info |= (OffsetSize << 5);

    // fre_mangled_ra_p (sframe_fre_info_word:7)
    // No support for fre_mangled_ra_p;

    // sframe_fre_info_word
    S.emitInt8(Info);

    unsigned OffsetsEmitted = 1;
    // FRE Offsets
    switch (OffsetSize) {
    case (SFRAME_FRE_OFFSET_1B):
      S.emitInt8(CfaOffset);
      break;
    case (SFRAME_FRE_OFFSET_2B):
      S.emitInt16(CfaOffset);
      break;
    case (SFRAME_FRE_OFFSET_4B):
      S.emitInt32(CfaOffset);
      break;
    }
    if (FPOffset != 0) {
      OffsetsEmitted++;
      switch (OffsetSize) {
      case (SFRAME_FRE_OFFSET_1B):
        S.emitInt8(FPOffset);
        break;
      case (SFRAME_FRE_OFFSET_2B):
        S.emitInt16(FPOffset);
        break;
      case (SFRAME_FRE_OFFSET_4B):
        S.emitInt32(FPOffset);
        break;
      }
    }
    if (RAOffset != 0) {
      switch (OffsetSize) {
      case (SFRAME_FRE_OFFSET_1B):
        S.emitInt8(RAOffset);
        break;
      case (SFRAME_FRE_OFFSET_2B):
        S.emitInt16(RAOffset);
        break;
      case (SFRAME_FRE_OFFSET_4B):
        S.emitInt32(RAOffset);
        break;
      }
    }
    assert(OffsetsEmitted == RegsTracked &&
           "Didn't emit the right number of offsets");
  }
  };

  // High-level structure to track info needed to emit a sframe_func_desc_entry
  // and its associated FREs.
  struct SFrameFDE {
    // Seed Dwarf frame to avoid copying too much from the original
    const MCDwarfFrameInfo& DFrame;
    // Used to create the offset from this FDE, but emitted with the FREs.
    MCSymbol *FREStart;
    unsigned FuncInfo;
    std::vector<SFrameFRE> FREs;

    SFrameFDE(const MCDwarfFrameInfo &DF, MCSymbol *FRES)
        : DFrame(DF), FREStart(FRES), FuncInfo(0) {

      // fretype (sfde_func_info:0-3)
      size_t CodeSize = DF.End->getOffset() - DF.Begin->getOffset();
      if (CodeSize <= std::numeric_limits<uint8_t>::max())
        FuncInfo |= SFRAME_FRE_TYPE_ADDR1;
      else if (CodeSize <= std::numeric_limits<uint16_t>::max())
        FuncInfo |= SFRAME_FRE_TYPE_ADDR2;
      else
        FuncInfo |= SFRAME_FRE_TYPE_ADDR4;

      // fde_type (sfde_func_info:4)
      // sfde_func_info PCMASK is typically used for PLTs. This is for normal
      // functions.
      FuncInfo |= SFRAME_FDE_TYPE_PCINC;

      // pauth_key (sfde_func_info:5)
      // No support.

      // unused (sfde_func_info:6-7)
      // Unused.
    }

    void Emit(MCStreamer& S, MCSymbol* FRESubSectionStart) {
      // sfde_func_start_address
      S.emitSymbolValue(DFrame.Begin, sizeof(int32_t));
      // sfde_func_size
      S.emitAbsoluteSymbolDiff(DFrame.End, DFrame.Begin, sizeof(uint32_t));
      // sfde_func_start_fre_off
      // In spite of the documentation, the gnu assembler always emits zero here.
      // Match that behavior for easier comparisons.
      // S.emitAbsoluteSymbolDiff(FREStart, FRESubSectionStart, sizeof(uint32_t));
      S.emitInt32(0);
      // sfde_func_start_num_fres
      S.emitInt32(FREs.size());
      // sfde_func_info
      S.emitInt8(FuncInfo);
      // sfde_func_rep_size. Not relevant in non-PCMASK fdes.
      S.emitInt8(0);
      // sfde_func_padding2
      S.emitInt16(0);
    }
  };

  MCObjectStreamer &Streamer;
  std::vector<SFrameFDE> FDEs;
  uint32_t TotalFREs;
  uint8_t SFrameABI;
  // Target-specific convenience variables to detect when a CFI instruction
  // references these registers. Unlike in dwarf frame descriptions, they never
  // escape into the sframe section itself.
  unsigned SPReg;
  unsigned FPReg;
  unsigned RAReg;

  MCSymbol *FDESubSectionStart;
  MCSymbol *FRESubSectionStart;
  MCSymbol *FRESubSectionEnd;

  // Add the effects of CFI to the current FRE, possibly creating a new
  // one. Returns the label of the CFI that most recently affected the FRE.
  MCSymbol *HandleCFI(SFrameFDE &FDE, const MCCFIInstruction &CFI,
                      MCSymbol *LastLabel) {
    // Create a new FRE if needed.
    MCSymbol *Label = CFI.getLabel();
    if (FDE.FREs.empty() ||
        (Label != LastLabel && Label->getOffset() != LastLabel->getOffset())) {
      TotalFREs++;
      FDE.FREs.emplace_back(
          Label ? Label->getOffset() - FDE.DFrame.Begin->getOffset() : 0);
    }
    SFrameFRE &FRE = FDE.FREs.back();

    switch (CFI.getOperation()) {
    case MCCFIInstruction::OpDefCfa:
    case MCCFIInstruction::OpDefCfaRegister:
    case MCCFIInstruction::OpLLVMDefAspaceCfa:
      FRE.CfaOffset = CFI.getOffset();
      if (CFI.getRegister() == SPReg)
        FRE.FromFP = false;
      else if (CFI.getRegister() == FPReg)
        FRE.FromFP = true;
      else
        llvm_unreachable("Cfa not in SP or FP");
      break;
    case MCCFIInstruction::OpDefCfaOffset:
      FRE.CfaOffset = CFI.getOffset();
      break;
    case MCCFIInstruction::OpAdjustCfaOffset:
      FRE.CfaOffset += CFI.getOffset();
      break;
    default:
      // We only track instructions that affect the Cfa, RA, and SP; Others can
      // be safely ignored.
      break;
    }
    return Label;
  }

public:
  SFrameEmitterImpl(MCObjectStreamer &Streamer)
      : Streamer(Streamer), TotalFREs(0) {
    FDEs.reserve(Streamer.getDwarfFrameInfos().size());
    SFrameABI =
        Streamer.getContext().getObjectFileInfo()->getSFrameABIArch();

    switch (SFrameABI) {
    case SFRAME_ABI_AARCH64_ENDIAN_BIG:
    case SFRAME_ABI_AARCH64_ENDIAN_LITTLE:
      SPReg = 31;
      RAReg = 29;
      FPReg = 30;
      break;
    case SFRAME_ABI_AMD64_ENDIAN_LITTLE:
      SPReg = 7;
      RAReg = 0; // RA is always on the stack
      FPReg = 6;
      break;
    }
    FDESubSectionStart = Streamer.getContext().createTempSymbol();
    FRESubSectionStart = Streamer.getContext().createTempSymbol();
    FRESubSectionEnd = Streamer.getContext().createTempSymbol();
  }

  void BuildFDE(const MCDwarfFrameInfo &DF) {
    auto &FDE = FDEs.emplace_back(DF, Streamer.getContext().createTempSymbol());

    MCSymbol* LastLabel = nullptr;
    const MCAsmInfo *AsmInfo = Streamer.getContext().getAsmInfo();
    for (const auto &CFI : AsmInfo->getInitialFrameState()) {
      LastLabel = HandleCFI(FDE, CFI, LastLabel);
    }

    for (const auto& CFI : DF.Instructions) {
      // Instructions from InitialFrameState may not have a label, but if these
      // instructions don't, then they are in dead code or otherwise unused.
      auto* L = CFI.getLabel();
      if (L && L->isDefined())
        LastLabel = HandleCFI(FDE, CFI, LastLabel);
    }
  }

  void EmitPreamble() {
    Streamer.emitInt16(SFRAME_MAGIC);
    Streamer.emitInt8(SFRAME_VERSION_2);
    uint8_t flags = 0;
    // Do not set SFRAME_F_FDE_SORTED. Sorting is up to the linker.
    // if (-fno-omit-frame-pointer)
    //   flags |= FRAME_F_FRAME_POINTER
    Streamer.emitInt8(flags);
  }

  void EmitHeader() {
    EmitPreamble();
    // sfh_abi_arch
    Streamer.emitInt8(SFrameABI);
    // sfh_cfa_fixed_fp_offset
    Streamer.emitInt8(0);
    // sfh_cfa_fixed_ra_offset
    int8_t FRAO = 0;
    if (SFrameABI == SFRAME_ABI_AMD64_ENDIAN_LITTLE) {
      FRAO = -8; // As specified by the AMD64 abi
    }
    Streamer.emitInt8(FRAO);
    // sfh_auxhdr_len
    Streamer.emitInt8(0);

    // shf_num_fdes
    Streamer.emitInt32(FDEs.size());
    // shf_num_fres
    Streamer.emitInt32(TotalFREs);
    // shf_fre_len
    Streamer.emitAbsoluteSymbolDiff(FRESubSectionEnd,
                                    FRESubSectionStart, sizeof(int32_t));
    // shf_fdeoff. With no sfh_auxhdr, these immediately follow this header.
    Streamer.emitInt32(0);
    // shf_freoff
    Streamer.emitAbsoluteSymbolDiff(FRESubSectionStart, FDESubSectionStart,
                                    sizeof(uint32_t));
  }

  void EmitFDEs() {
    Streamer.emitLabel(FDESubSectionStart);
    for (auto &FDE : FDEs)
      FDE.Emit(Streamer, FDESubSectionStart);
  }

  void EmitFREs() {
    Streamer.emitLabel(FRESubSectionStart);
    for (auto FDE : FDEs) {
      Streamer.emitLabel(FDE.FREStart);
      for (auto &FRE : FDE.FREs) {
        FRE.Emit(Streamer, FDE.FuncInfo);
      }
    }
    Streamer.emitLabel(FRESubSectionEnd);
  }
};

} // end anonymous namespace


void MCSFrameEmitter::Emit(MCObjectStreamer &Streamer, MCAsmBackend *MAB) {
  MCContext &Context = Streamer.getContext();
  //const MCAsmInfo *AsmInfo = Context.getAsmInfo();
  SFrameEmitterImpl Emitter(Streamer);
  ArrayRef<MCDwarfFrameInfo> FrameArray = Streamer.getDwarfFrameInfos();

  // Both the header itself and the FDEs include the fre count and certain
  // offsets. Therefore, all of this must be precomputed.
  for (const auto& DFrame : FrameArray)
    Emitter.BuildFDE(DFrame);

  MCSection *Section = Context.getObjectFileInfo()->getSFrameSection();
  Streamer.switchSection(Section);
  MCSymbol *SectionStart = Context.createTempSymbol();
  Streamer.emitLabel(SectionStart);
  Emitter.EmitHeader();
  Emitter.EmitFDEs();
  Emitter.EmitFREs();
}
