add_llvm_component_library(LLVMDebugInfoDWARFLowLevel
  DWARFExpression.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/DebugInfo/DWARF

  LINK_COMPONENTS
  Support
  TargetParser
  )
