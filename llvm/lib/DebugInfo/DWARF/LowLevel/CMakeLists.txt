add_llvm_component_library(LLVMDebugInfoDWARFLowLevel
  DWARFCFIProgram.cpp
  DWARFDataExtractorSimple.cpp
  DWARFExpression.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/DebugInfo/DWARF

  # This library is intended to have minimal dependencies so can be
  # used from MC without layering violations. Avoid adding new ones,
  # especially Object.

  LINK_COMPONENTS
  Support
  TargetParser
  )
