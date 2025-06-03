//===-- DWARFExpressionPrinter.cpp ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/DebugInfo/DWARF/DWARFExpressionPrinter.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/DebugInfo/DWARF/DWARFUnit.h"
#include "llvm/DebugInfo/DWARF/LowLevel/DWARFExpression.h"
#include "llvm/Support/Format.h"
#include <cassert>
#include <cstdint>
#include <vector>

using namespace llvm;
using namespace dwarf;

namespace llvm {

void DWARFExpressionPrinter::prettyPrintBaseTypeRef(DWARFUnit *U,
                                                    raw_ostream &OS,
                                                    DIDumpOptions DumpOpts,
                                                    ArrayRef<uint64_t> Operands,
                                                    unsigned Operand) {
  assert(Operand < Operands.size() && "operand out of bounds");
  if (!U) {
    OS << format(" <base_type ref: 0x%" PRIx64 ">", Operands[Operand]);
    return;
  }
  auto Die = U->getDIEForOffset(U->getOffset() + Operands[Operand]);
  if (Die && Die.getTag() == dwarf::DW_TAG_base_type) {
    OS << " (";
    if (DumpOpts.Verbose)
      OS << format("0x%08" PRIx64 " -> ", Operands[Operand]);
    OS << format("0x%08" PRIx64 ")", U->getOffset() + Operands[Operand]);
    if (auto Name = dwarf::toString(Die.find(dwarf::DW_AT_name)))
      OS << " \"" << *Name << "\"";
  } else {
    OS << format(" <invalid base_type ref: 0x%" PRIx64 ">", Operands[Operand]);
  }
}

bool DWARFExpressionPrinter::prettyPrintRegisterOp(
    DWARFUnit *U, raw_ostream &OS, DIDumpOptions DumpOpts, uint8_t Opcode,
    ArrayRef<uint64_t> Operands) {
  if (!DumpOpts.GetNameForDWARFReg)
    return false;

  uint64_t DwarfRegNum;
  unsigned OpNum = 0;

  if (Opcode == DW_OP_bregx || Opcode == DW_OP_regx ||
      Opcode == DW_OP_regval_type)
    DwarfRegNum = Operands[OpNum++];
  else if (Opcode >= DW_OP_breg0 && Opcode < DW_OP_bregx)
    DwarfRegNum = Opcode - DW_OP_breg0;
  else
    DwarfRegNum = Opcode - DW_OP_reg0;

  auto RegName = DumpOpts.GetNameForDWARFReg(DwarfRegNum, DumpOpts.IsEH);
  if (!RegName.empty()) {
    if ((Opcode >= DW_OP_breg0 && Opcode <= DW_OP_breg31) ||
        Opcode == DW_OP_bregx)
      OS << ' ' << RegName << format("%+" PRId64, Operands[OpNum]);
    else
      OS << ' ' << RegName.data();

    if (Opcode == DW_OP_regval_type)
      prettyPrintBaseTypeRef(U, OS, DumpOpts, Operands, 1);
    return true;
  }

  return false;
}

bool DWARFExpressionPrinter::printOp(const DWARFExpression::Operation *Op,
                                     raw_ostream &OS, DIDumpOptions DumpOpts,
                                     const DWARFExpression *Expr,
                                     DWARFUnit *U) {
  if (Op->Error) {
    OS << "<decoding error>";
    return false;
  }

  StringRef Name = OperationEncodingString(Op->Opcode);
  assert(!Name.empty() && "DW_OP has no name!");
  OS << Name;

  if ((Op->Opcode >= DW_OP_breg0 && Op->Opcode <= DW_OP_breg31) ||
      (Op->Opcode >= DW_OP_reg0 && Op->Opcode <= DW_OP_reg31) ||
      Op->Opcode == DW_OP_bregx || Op->Opcode == DW_OP_regx ||
      Op->Opcode == DW_OP_regval_type)
    if (prettyPrintRegisterOp(U, OS, DumpOpts, Op->Opcode, Op->Operands))
      return true;

  for (unsigned Operand = 0; Operand < Op->Desc.Op.size(); ++Operand) {
    unsigned Size = Op->Desc.Op[Operand];
    unsigned Signed = Size & DWARFExpression::Operation::SignBit;

    if (Size == DWARFExpression::Operation::SizeSubOpLEB) {
      StringRef SubName =
          SubOperationEncodingString(Op->Opcode, Op->Operands[Operand]);
      assert(!SubName.empty() && "DW_OP SubOp has no name!");
      OS << " " << SubName;
    } else if (Size == DWARFExpression::Operation::BaseTypeRef && U) {
      // For DW_OP_convert the operand may be 0 to indicate that conversion to
      // the generic type should be done. The same holds for DW_OP_reinterpret,
      // which is currently not supported.
      if (Op->Opcode == DW_OP_convert && Op->Operands[Operand] == 0)
        OS << " 0x0";
      else
        prettyPrintBaseTypeRef(U, OS, DumpOpts, Op->Operands, Operand);
    } else if (Size == DWARFExpression::Operation::WasmLocationArg) {
      assert(Operand == 1);
      switch (Op->Operands[0]) {
      case 0:
      case 1:
      case 2:
      case 3: // global as uint32
      case 4:
        OS << format(" 0x%" PRIx64, Op->Operands[Operand]);
        break;
      default:
        assert(false);
      }
    } else if (Size == DWARFExpression::Operation::SizeBlock) {
      uint64_t Offset = Op->Operands[Operand];
      for (unsigned i = 0; i < Op->Operands[Operand - 1]; ++i)
        OS << format(" 0x%02x", Expr->Data.getU8(&Offset));
    } else {
      if (Signed)
        OS << format(" %+" PRId64, (int64_t)Op->Operands[Operand]);
      else if (Op->Opcode != DW_OP_entry_value &&
               Op->Opcode != DW_OP_GNU_entry_value)
        OS << format(" 0x%" PRIx64, Op->Operands[Operand]);
    }
  }
  return true;
}

void DWARFExpressionPrinter::print(const DWARFExpression *E, raw_ostream &OS,
                                   DIDumpOptions DumpOpts, DWARFUnit *U,
                                   bool IsEH) {
  uint32_t EntryValExprSize = 0;
  uint64_t EntryValStartOffset = 0;
  if (E->Data.getData().empty())
    OS << "<empty>";

  for (auto &Op : *E) {
    DumpOpts.IsEH = IsEH;
    if (!printOp(&Op, OS, DumpOpts, E, U)) {
      uint64_t FailOffset = Op.getEndOffset();
      while (FailOffset < E->Data.getData().size())
        OS << format(" %02x", E->Data.getU8(&FailOffset));
      return;
    }

    if (Op.getCode() == DW_OP_entry_value ||
        Op.getCode() == DW_OP_GNU_entry_value) {
      OS << "(";
      EntryValExprSize = Op.getRawOperand(0);
      EntryValStartOffset = Op.getEndOffset();
      continue;
    }

    if (EntryValExprSize) {
      EntryValExprSize -= Op.getEndOffset() - EntryValStartOffset;
      if (EntryValExprSize == 0)
        OS << ")";
    }

    if (Op.getEndOffset() < E->Data.getData().size())
      OS << ", ";
  }
}

/// A user-facing string representation of a DWARF expression. This might be an
/// Address expression, in which case it will be implicitly dereferenced, or a
/// Value expression.
struct PrintedExpr {
  enum ExprKind {
    Address,
    Value,
  };
  ExprKind Kind;
  SmallString<16> String;

  PrintedExpr(ExprKind K = Address) : Kind(K) {}
};

static bool printCompactDWARFExpr(
    raw_ostream &OS, DWARFExpression::iterator I,
    const DWARFExpression::iterator E,
    std::function<StringRef(uint64_t RegNum, bool IsEH)> GetNameForDWARFReg =
        nullptr) {
  SmallVector<PrintedExpr, 4> Stack;

  while (I != E) {
    const DWARFExpression::Operation &Op = *I;
    uint8_t Opcode = Op.getCode();
    switch (Opcode) {
    case dwarf::DW_OP_regx: {
      // DW_OP_regx: A register, with the register num given as an operand.
      // Printed as the plain register name.
      uint64_t DwarfRegNum = Op.getRawOperand(0);
      auto RegName = GetNameForDWARFReg(DwarfRegNum, false);
      if (RegName.empty())
        return false;
      raw_svector_ostream S(Stack.emplace_back(PrintedExpr::Value).String);
      S << RegName;
      break;
    }
    case dwarf::DW_OP_bregx: {
      int DwarfRegNum = Op.getRawOperand(0);
      int64_t Offset = Op.getRawOperand(1);
      auto RegName = GetNameForDWARFReg(DwarfRegNum, false);
      if (RegName.empty())
        return false;
      raw_svector_ostream S(Stack.emplace_back().String);
      S << RegName;
      if (Offset)
        S << format("%+" PRId64, Offset);
      break;
    }
    case dwarf::DW_OP_entry_value:
    case dwarf::DW_OP_GNU_entry_value: {
      // DW_OP_entry_value contains a sub-expression which must be rendered
      // separately.
      uint64_t SubExprLength = Op.getRawOperand(0);
      DWARFExpression::iterator SubExprEnd = I.skipBytes(SubExprLength);
      ++I;
      raw_svector_ostream S(Stack.emplace_back().String);
      S << "entry(";
      printCompactDWARFExpr(S, I, SubExprEnd, GetNameForDWARFReg);
      S << ")";
      I = SubExprEnd;
      continue;
    }
    case dwarf::DW_OP_stack_value: {
      // The top stack entry should be treated as the actual value of tne
      // variable, rather than the address of the variable in memory.
      assert(!Stack.empty());
      Stack.back().Kind = PrintedExpr::Value;
      break;
    }
    case dwarf::DW_OP_nop: {
      break;
    }
    case dwarf::DW_OP_LLVM_user: {
      assert(Op.getSubCode() && *Op.getSubCode() == dwarf::DW_OP_LLVM_nop);
      break;
    }
    default:
      if (Opcode >= dwarf::DW_OP_reg0 && Opcode <= dwarf::DW_OP_reg31) {
        // DW_OP_reg<N>: A register, with the register num implied by the
        // opcode. Printed as the plain register name.
        uint64_t DwarfRegNum = Opcode - dwarf::DW_OP_reg0;
        auto RegName = GetNameForDWARFReg(DwarfRegNum, false);
        if (RegName.empty())
          return false;
        raw_svector_ostream S(Stack.emplace_back(PrintedExpr::Value).String);
        S << RegName;
      } else if (Opcode >= dwarf::DW_OP_breg0 &&
                 Opcode <= dwarf::DW_OP_breg31) {
        int DwarfRegNum = Opcode - dwarf::DW_OP_breg0;
        int64_t Offset = Op.getRawOperand(0);
        auto RegName = GetNameForDWARFReg(DwarfRegNum, false);
        if (RegName.empty())
          return false;
        raw_svector_ostream S(Stack.emplace_back().String);
        S << RegName;
        if (Offset)
          S << format("%+" PRId64, Offset);
      } else {
        // If we hit an unknown operand, we don't know its effect on the stack,
        // so bail out on the whole expression.
        OS << "<unknown op " << dwarf::OperationEncodingString(Opcode) << " ("
           << (int)Opcode << ")>";
        return false;
      }
      break;
    }
    ++I;
  }

  if (Stack.size() != 1) {
    OS << "<stack of size " << Stack.size() << ", expected 1>";
    return false;
  }

  if (Stack.front().Kind == PrintedExpr::Address)
    OS << "[" << Stack.front().String << "]";
  else
    OS << Stack.front().String;

  return true;
}

bool DWARFExpressionPrinter::printCompact(
    const DWARFExpression *E, raw_ostream &OS,
    std::function<StringRef(uint64_t RegNum, bool IsEH)> GetNameForDWARFReg) {
  return printCompactDWARFExpr(OS, E->begin(), E->end(), GetNameForDWARFReg);
}

} // namespace llvm
