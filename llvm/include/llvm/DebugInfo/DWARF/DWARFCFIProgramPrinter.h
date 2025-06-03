//===--- DWARFCFIProgramPrinter.h - DWARF Expression printing ----*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// This functionality is separated from the main data structure so that nothing
// in DWARFCIFProgram.cpp needs build-time dependencies on DWARFUnit or other
// higher-level Dwarf structures. This approach creates better layering and
// allows DWARFCFIProgram to be used from code which can't have dependencies on
// those higher-level structures.

#ifndef LLVM_DEBUGINFO_DWARF_DWARFCFIPROGRAMPRINTER_H
#define LLVM_DEBUGINFO_DWARF_DWARFCFIPROGRAMPRINTER_H

#include "llvm/DebugInfo/DWARF/LowLevel/DWARFCFIProgram.h"

#include <cstdint>

namespace llvm {

struct DIDumpOptions;
class raw_ostream;

namespace dwarf {

class CFIProgramPrinter {
public:
  static void print(raw_ostream &OS, DIDumpOptions DumpOpts,
                    const CFIProgram &Prog, unsigned IndentLevel,
                    std::optional<uint64_t> Address);
  static void printOperand(raw_ostream &OS, DIDumpOptions DumpOpts,
                           const CFIProgram &Prog,
                           const dwarf::CFIProgram::Instruction &Instr,
                           unsigned OperandIdx, uint64_t Operand,
                           std::optional<uint64_t> &Address);
};

} // end namespace dwarf

} // end namespace llvm

#endif //  LLVM_DEBUGINFO_DWARF_DWARFCFIPROGRAMPRINTER_H
