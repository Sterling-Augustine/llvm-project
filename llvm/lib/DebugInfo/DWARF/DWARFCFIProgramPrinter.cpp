//===-- DWARFCFIProgramePrinter.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/DebugInfo/DWARF/DWARFCFIProgramPrinter.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFExpressionPrinter.h"
#include "llvm/DebugInfo/DWARF/DWARFUnit.h"
#include <cassert>
#include <cstdint>
#include <vector>

using namespace llvm;
using namespace dwarf;

static void printRegister(raw_ostream &OS, DIDumpOptions DumpOpts,
                          unsigned RegNum) {
  if (DumpOpts.GetNameForDWARFReg) {
    auto RegName = DumpOpts.GetNameForDWARFReg(RegNum, DumpOpts.IsEH);
    if (!RegName.empty()) {
      OS << RegName;
      return;
    }
  }
  OS << "reg" << RegNum;
}

/// Print \p Opcode's operand number \p OperandIdx which has value \p Operand.
void CFIProgramPrinter::printOperand(raw_ostream &OS, DIDumpOptions DumpOpts,
                                     const CFIProgram &Prog,
                                     const CFIProgram::Instruction &Instr,
                                     unsigned OperandIdx, uint64_t Operand,
                                     std::optional<uint64_t> &Address) {
  assert(OperandIdx < CFIProgram::MaxOperands);
  uint8_t Opcode = Instr.Opcode;
  CFIProgram::OperandType Type = Prog.getOperandTypes()[Opcode][OperandIdx];

  switch (Type) {
  case CFIProgram::OT_Unset: {
    OS << " Unsupported " << (OperandIdx ? "second" : "first") << " operand to";
    auto OpcodeName = Prog.callFrameString(Opcode);
    if (!OpcodeName.empty())
      OS << " " << OpcodeName;
    else
      OS << format(" Opcode %x", Opcode);
    break;
  }
  case CFIProgram::OT_None:
    break;
  case CFIProgram::OT_Address:
    OS << format(" %" PRIx64, Operand);
    Address = Operand;
    break;
  case CFIProgram::OT_Offset:
    // The offsets are all encoded in a unsigned form, but in practice
    // consumers use them signed. It's most certainly legacy due to
    // the lack of signed variants in the first Dwarf standards.
    OS << format(" %+" PRId64, int64_t(Operand));
    break;
  case CFIProgram::OT_FactoredCodeOffset: // Always Unsigned
    if (Prog.CodeAlignmentFactor)
      OS << format(" %" PRId64, Operand * Prog.CodeAlignmentFactor);
    else
      OS << format(" %" PRId64 "*code_alignment_factor", Operand);
    if (Address && Prog.CodeAlignmentFactor) {
      *Address += Operand * Prog.CodeAlignmentFactor;
      OS << format(" to 0x%" PRIx64, *Address);
    }
    break;
  case CFIProgram::OT_SignedFactDataOffset:
    if (Prog.DataAlignmentFactor)
      OS << format(" %" PRId64, int64_t(Operand) * Prog.DataAlignmentFactor);
    else
      OS << format(" %" PRId64 "*data_alignment_factor", int64_t(Operand));
    break;
  case CFIProgram::OT_UnsignedFactDataOffset:
    if (Prog.DataAlignmentFactor)
      OS << format(" %" PRId64, Operand * Prog.DataAlignmentFactor);
    else
      OS << format(" %" PRId64 "*data_alignment_factor", Operand);
    break;
  case CFIProgram::OT_Register:
    OS << ' ';
    printRegister(OS, DumpOpts, Operand);
    break;
  case CFIProgram::OT_AddressSpace:
    OS << format(" in addrspace%" PRId64, Operand);
    break;
  case CFIProgram::OT_Expression:
    assert(Instr.Expression && "missing DWARFExpression object");
    OS << " ";
    DWARFExpressionPrinter::print(&(*Instr.Expression), OS, DumpOpts, nullptr);
    break;
  }
}

void CFIProgramPrinter::print(raw_ostream &OS, DIDumpOptions DumpOpts,
                              const CFIProgram &Prog, unsigned IndentLevel,
                              std::optional<uint64_t> Address) {
  for (const auto &Instr : Prog.Instructions) {
    uint8_t Opcode = Instr.Opcode;
    OS.indent(2 * IndentLevel);
    OS << Prog.callFrameString(Opcode) << ":";
    for (unsigned i = 0; i < Instr.Ops.size(); ++i)
      printOperand(OS, DumpOpts, Prog, Instr, i, Instr.Ops[i], Address);
    OS << '\n';
  }
}
