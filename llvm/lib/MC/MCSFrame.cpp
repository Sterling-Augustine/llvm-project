//===- lib/MC/MCSFrame.cpp - MCSFrame implementation ----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCSFrame.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/BinaryFormat/SFrame.h"
#include "llvm/DebugInfo/DWARF/DWARFDataExtractor.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectStreamer.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSymbol.h"

using namespace llvm;
using namespace sframe;

namespace {

// High-level structure to track info needed to emit a
// sframe_frame_row_entry_addrX. On disk these have both a fixed portion of type
// sframe_frame_row_entry_addrX and trailing data of X * S bytes, where X is the
// datum size, and S is 1, 2, or 3 depending on which of Cfa, SP, and FP are
// being tracked.
struct SFrameFRE {
  // An FRE describes how to find the registers when the PC is at this
  // Offset from function start.
  size_t FuncOffset = 0;
  size_t CfaOffset = 0;
  size_t FPOffset = 0;
  size_t RAOffset = 0;
  bool FromFP = false;
  bool CfaRegSet = false;

  void Emit(MCStreamer &S, unsigned FDEI) {
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
    Info |= OffsetSize;

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
    if (FPOffset) {
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
    if (RAOffset) {
      OffsetsEmitted++;
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
  // Reference to the original dwarf frame to avoid copying.
  const MCDwarfFrameInfo &DFrame;
  // Used to create the offset from this FDE, but emitted with the FREs.
  MCSymbol *FREStart;
  // Working copy of sfde_func_info word
  unsigned FuncInfo;
  // True when unwind info can't be described with an Sframe FDE.
  bool Invalid;
  std::vector<SFrameFRE> FREs;

  SFrameFDE(const MCDwarfFrameInfo &DF, MCSymbol *FRES)
      : DFrame(DF), FREStart(FRES), FuncInfo(0), Invalid(false) {
    // Start with one FRE at the zero offset. HandleCFI will fill
    // in the details.
    FREs.emplace_back();
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

  void Emit(MCStreamer &S, MCSymbol *FRESubSectionStart) {
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

// Relying on MCStreamer by emitting these field-by-field lets Streamer do
// target endian-fixups for free.

class SFrameEmitterImpl {
  MCObjectStreamer &Streamer;
  std::vector<SFrameFDE> FDEs;
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

  bool SetCfaRegister(SFrameFDE &FDE, SFrameFRE &FRE, const MCCFIInstruction &I) {
    if (I.getRegister() == SPReg) {
      FRE.CfaRegSet = true;
      FRE.FromFP = false;
      return true;
    } else if (I.getRegister() == FPReg) {
      FRE.CfaRegSet = true;
      FRE.FromFP = true;
      return true;
    }
    Streamer.getContext().reportWarning(
        I.getLoc(), "Canonical Frame Address not in stack- or frame-pointer. "
                    "Omitting SFrame unwind info.");
    FDE.Invalid = true;
    return false;
  }

  bool IsCfaRegisterSet(SFrameFDE &FDE, SFrameFRE &FRE,
                        const MCCFIInstruction &I) {
    if (FRE.CfaRegSet)
      return true;

    Streamer.getContext().reportWarning(
        I.getLoc(), "skipping SFrame FDE; .cfi_def_cfa_offset "
                      "without CFA base register in effect");
    FDE.Invalid = true;
    return false;
  }

  // Technically, the escape data could be anything, but it is commonly a dwarf
  // CFI program. Even then, it could contain an arbitrarily complicated Dwarf
  // expression. Following gnu-gas, look for certain common cases that could
  // invalidate an SFDE, emit a warning for those sequences. Allow any that are
  // known safe. It is likely that more thorough test cases could refine this
  // code, but it handles the most important ones compatibly with gas.
  bool IsCFIEscapeSafe(SFrameFDE &FDE, const MCCFIInstruction &CFI) {
    const MCAsmInfo *AI = Streamer.getContext().getAsmInfo();
    DWARFDataExtractor data(CFI.getValues(), AI->isLittleEndian(),
                            AI->getCodePointerSize());

    // Normally, both alignment factors are extracted from the enclosing Dwarf
    // FDE or CIE. We don't have one here. Alignments are used for scaling
    // factors for ops like CFA_def_cfa_offset_sf. But this particular function
    // is only interested in registers.
    dwarf::CFIProgram P(/* CodeAlignmentFactor */ 1,
                        /* DataAlignmentFactor*/ 1,
                        Streamer.getContext().getTargetTriple().getArch());
    uint64_t Offset = 0;
    if (P.parse(data, &Offset, CFI.getValues().size())) {
      // Not a parsable dwarf expression. Assume the worst.
      Streamer.getContext().reportWarning(
          CFI.getLoc(),
          "skipping SFrame FDE; .cfi_escape with unknown effects");
      return false;
    }

    // This loop deals with are dwarf::CFIProgram::Instructions. This file deals
    // with MCCFIInstructions everywhere but here.
    for (const dwarf::CFIProgram::Instruction &I : P) {
      switch (I.Opcode) {
        // Nops are fine.
      case dwarf::DW_CFA_nop:
        break;
      case dwarf::DW_CFA_val_offset: {
        // First argument is a register. Anything that touches CFA, FP, or RA is
        // a problem, but allow others through. As an even more special case,
        // allow SP + 0. For some reason gas doesn't allow this for
        // DW_CFA_expression.
        auto Reg = I.getOperandAsUnsigned(P, 0);
        if (!Reg) {
          Streamer.getContext().reportWarning(
              CFI.getLoc(),
              "skipping SFrame FDE; .cfi_escape with unknown effects");
        }
        bool SPOk = true;
        if (*Reg == SPReg) {
          auto Opnd = I.getOperandAsSigned(P, 1);
          if (!Opnd || *Opnd != 0)
            SPOk = false;
        }
        if (!SPOk || *Reg == RAReg || *Reg == FPReg) {
          StringRef RN = *Reg == SPReg
                             ? "SP reg "
                             : (*Reg == FPReg ? "FP reg " : "RA reg ");
          Streamer.getContext().reportWarning(
              CFI.getLoc(),
              Twine(
                  "skipping SFrame FDE; .cfi_escape DW_CFA_val_offset with ") +
                  RN + Twine(*Reg));
          return false;
        }
      } break;
      case dwarf::DW_CFA_expression: {
        // First argument is a register. Anything that touches CFA, FP, or RA is
        // a problem, but allow others through.
        auto Reg = I.getOperandAsUnsigned(P, 0);
        if (!Reg) {
          Streamer.getContext().reportWarning(
              CFI.getLoc(),
              "skipping SFrame FDE; .cfi_escape with unknown effects");
        }
        if (*Reg == SPReg || *Reg == RAReg || *Reg == FPReg) {
          StringRef RN = *Reg == SPReg
                             ? "SP reg "
                             : (*Reg == FPReg ? "FP reg " : "RA reg ");
          Streamer.getContext().reportWarning(
              CFI.getLoc(),
              Twine(
                  "skipping SFrame FDE; .cfi_escape DW_CFA_expression with ") +
                  RN + Twine(*Reg));
          return false;
        }
      } break;
      // Cases that gas doesn't specially handle. TODO: Some of these could
      // possibly be analyzed and handled instead of just punting. But the fact
      // that they appear via .cfi_escape rather than the normal mechanism means
      // they are part of complicated expressions that might not translate
      // easily. The dwarf::CFIProgram will need corrected scaling factors for
      // some of these. And if gas doesn't handle them, they are less important
      // than the above.
      case dwarf::DW_CFA_advance_loc:
      case dwarf::DW_CFA_offset:
      case dwarf::DW_CFA_restore:
      case dwarf::DW_CFA_set_loc:
      case dwarf::DW_CFA_advance_loc1:
      case dwarf::DW_CFA_advance_loc2:
      case dwarf::DW_CFA_advance_loc4:
      case dwarf::DW_CFA_offset_extended:
      case dwarf::DW_CFA_restore_extended:
      case dwarf::DW_CFA_undefined:
      case dwarf::DW_CFA_same_value:
      case dwarf::DW_CFA_register:
      case dwarf::DW_CFA_remember_state:
      case dwarf::DW_CFA_restore_state:
      case dwarf::DW_CFA_def_cfa:
      case dwarf::DW_CFA_def_cfa_register:
      case dwarf::DW_CFA_def_cfa_offset:
      case dwarf::DW_CFA_def_cfa_expression:
      case dwarf::DW_CFA_offset_extended_sf:
      case dwarf::DW_CFA_def_cfa_sf:
      case dwarf::DW_CFA_def_cfa_offset_sf:
      case dwarf::DW_CFA_val_offset_sf:
      case dwarf::DW_CFA_val_expression:
      case dwarf::DW_CFA_MIPS_advance_loc8:
      case dwarf::DW_CFA_AARCH64_negate_ra_state_with_pc:
      case dwarf::DW_CFA_AARCH64_negate_ra_state:
      case dwarf::DW_CFA_GNU_args_size:
      case dwarf::DW_CFA_LLVM_def_aspace_cfa:
      case dwarf::DW_CFA_LLVM_def_aspace_cfa_sf:
        Streamer.getContext().reportWarning(
            CFI.getLoc(), "skipping SFrame FDE; .cfi_escape "
                          "CFA expression with unknown side effects");
        return false;
      default:
        // Dwarf expression was only partially valid, and user could have
        // written anything.
        Streamer.getContext().reportWarning(
            CFI.getLoc(),
            "skipping SFrame FDE; .cfi_escape with unknown effects");
        return false;
      }
    }
    return true;
  }

  // Add the effects of CFI to the current FDE, creating a new FRE when
  // necessary.
  void HandleCFI(SFrameFDE &FDE, const MCCFIInstruction &CFI) {
    // Add a new FRE only when the instruction is both relevant to
    // SFrame unwinding and starts at new offset. We don't know both
    // until the end of the function, so work on a copy.
    SFrameFRE FRE = FDE.FREs.back();

    // Return on error or uninteresting CFI.
    switch (CFI.getOperation()) {
    case MCCFIInstruction::OpDefCfaRegister:
      if (!SetCfaRegister(FDE, FRE, CFI))
        return;
      break;
    case MCCFIInstruction::OpDefCfa:
    case MCCFIInstruction::OpLLVMDefAspaceCfa:
      if (!SetCfaRegister(FDE, FRE, CFI))
        return;
      FRE.CfaOffset = CFI.getOffset();
      break;
    case MCCFIInstruction::OpOffset:
      if (CFI.getRegister() == FPReg)
        FRE.FPOffset = CFI.getOffset();
      else if (CFI.getRegister() == RAReg)
        FRE.RAOffset = CFI.getOffset();
      else
        return; // uninteresting register.
      break;
    case MCCFIInstruction::OpRelOffset:
      if (CFI.getRegister() == FPReg)
        FRE.FPOffset += CFI.getOffset();
      else if (CFI.getRegister() == RAReg)
        FRE.RAOffset += CFI.getOffset();
      else
        return; // uninteresting register.
      break;
    case MCCFIInstruction::OpDefCfaOffset:
      if (!IsCfaRegisterSet(FDE, FRE, CFI))
        return;
      FRE.CfaOffset = CFI.getOffset();
      break;
    case MCCFIInstruction::OpAdjustCfaOffset:
      if (!IsCfaRegisterSet(FDE, FRE, CFI))
        return;
      FRE.CfaOffset += CFI.getOffset();
      break;
    case MCCFIInstruction::OpRememberState:
      if (FDE.FREs.size() == 1) {
        // Error for gas compatibility: If the initial FRE isn't complete,
        // then any state is incomplete.  FIXME: Dwarf doesn't error here.
        // Why should sframe?
        Streamer.getContext().reportWarning(
            CFI.getLoc(), "skipping SFrame FDE; .cfi_remember_state without "
                          "prior SFrame FRE state");
        FDE.Invalid = true;
        return;
      }
      llvm_unreachable("unimplemented");
      break;
    case MCCFIInstruction::OpEscape:
      // This is a string of bytes that contains an aribtrary dwarf-expression
      // that may or may not affect uwnind info.
      if (!IsCFIEscapeSafe(FDE, CFI)) {
        // Error already reported.
        FDE.Invalid = true;
        return;
      }
      break;
    default:
      // Instructions that don't affect the Cfa, RA, and SP can be safely
      // ignored.
      return;
    }

    uint32_t NewOffset = 0;
    if (auto *L = CFI.getLabel())
      NewOffset = L->getOffset() - FDE.DFrame.Begin->getOffset();

    if (NewOffset != FRE.FuncOffset) {
      FRE.FuncOffset = NewOffset;
      FDE.FREs.push_back(FRE);
    } else
      FDE.FREs.back() = FRE;
  }

    public:
      SFrameEmitterImpl(MCObjectStreamer & Streamer) : Streamer(Streamer) {
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
          // Untracked in this abi. Value chosen to match MCDwarfFrameInfo
          // constructor.
          RAReg = static_cast<unsigned>(INT_MAX);
          FPReg = 6;
          break;
        }
        FDESubSectionStart = Streamer.getContext().createTempSymbol();
        FRESubSectionStart = Streamer.getContext().createTempSymbol();
        FRESubSectionEnd = Streamer.getContext().createTempSymbol();
      }

      void BuildSFDE(const MCDwarfFrameInfo &DF) {
        // SFrames don't support certain kinds of functions.

        auto &FDE =
            FDEs.emplace_back(DF, Streamer.getContext().createTempSymbol());
        // This would have been set via ".cfi_return_column", but
        // MCObjectStreamer doesn't emit an MCCFIInstruction for that. It just
        // sets the DF.RAReg.
        // FIXME: This also prevents providing a proper location for the error.
        // LLVM doesn't change the return column itself, so this was
        // externally-generated assembly.
        if (DF.RAReg != RAReg) {
          Streamer.getContext().reportWarning(
              SMLoc(), "skipping SFrame FDE; non-default RA register " +
                           Twine(DF.RAReg));
          // Continue with the FDE to find any addtional errors. Discard it at
          // the end.
          FDE.Invalid = true;
        }
        const MCAsmInfo *AsmInfo = Streamer.getContext().getAsmInfo();
        if (!DF.IsSimple) {
          for (const auto &CFI : AsmInfo->getInitialFrameState())
            HandleCFI(FDE, CFI);
        }

        for (const auto &CFI : DF.Instructions) {
          // Instructions from InitialFrameState may not have a label, but if
          // these instructions don't, then they are in dead code or otherwise
          // unused.
          auto *L = CFI.getLabel();
          if (L && L->isDefined())
            HandleCFI(FDE, CFI);
        }
        // Building these even if some info is invalid reports every error.
        if (FDE.Invalid)
          FDEs.pop_back();
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
        uint32_t TotalFREs = 0;
        for (auto &FDE : FDEs)
          TotalFREs += FDE.FREs.size();
        Streamer.emitInt32(TotalFREs);

        // shf_fre_len
        Streamer.emitAbsoluteSymbolDiff(FRESubSectionEnd, FRESubSectionStart,
                                        sizeof(int32_t));
        // shf_fdeoff. With no sfh_auxhdr, these immediately follow this header.
        Streamer.emitInt32(0);
        // shf_freoff
        Streamer.emitAbsoluteSymbolDiff(FRESubSectionStart, FDESubSectionStart,
                                        sizeof(uint32_t));
      }

      void EmitFDEs() {
        Streamer.emitLabel(FDESubSectionStart);
        for (auto &FDE : FDEs) {
          if (!FDE.Invalid)
            FDE.Emit(Streamer, FDESubSectionStart);
        }
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

void MCSFrameEmitter::Emit(MCObjectStreamer &Streamer) {
  MCContext &Context = Streamer.getContext();
  SFrameEmitterImpl Emitter(Streamer);
  ArrayRef<MCDwarfFrameInfo> FrameArray = Streamer.getDwarfFrameInfos();

  // Both the header itself and the FDEs include the fre counts and certain
  // offsets. Therefore, all of this must be precomputed.
  for (const auto& DFrame : FrameArray)
    Emitter.BuildSFDE(DFrame);

  MCSection *Section = Context.getObjectFileInfo()->getSFrameSection();
  Streamer.switchSection(Section);
  MCSymbol *SectionStart = Context.createTempSymbol();
  Streamer.emitLabel(SectionStart);
  Emitter.EmitHeader();
  Emitter.EmitFDEs();
  Emitter.EmitFREs();
}
