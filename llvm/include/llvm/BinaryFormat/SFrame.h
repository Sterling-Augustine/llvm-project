//===-- llvm/BinaryFormat/SFrame.h ---SFrame Data Structures ----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file
/// This file contains data-structure definitions and constants to support
/// unwinding based on .sframe sections.  This only supports SFRAME_VERSION_2
/// as described at https://sourceware.org/binutils/docs/sframe-spec.html
///
/// Naming conventions follow the spec document. #defines converted to constants
/// and enums for better C++ compatibility.
//===----------------------------------------------------------------------===//

#ifndef LLVM_BINARYFORMAT_SFRAME_H
#define LLVM_BINARYFORMAT_SFRAME_H

#include <type_traits>

#include "llvm/Support/Compiler.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FormatVariadicDetails.h"
#include "llvm/TargetParser/Triple.h"

#include <limits>

namespace llvm {

namespace sframe {

//===----------------------------------------------------------------------===//

struct __attribute__((packed)) sframe_preamble {
  uint16_t sfp_magic;
  uint8_t sfp_version;
  uint8_t sfp_flags;
};

static_assert(std::is_trivial_v<sframe_preamble>);
static_assert(sizeof(sframe_preamble) == 4);

static constexpr uint16_t SFRAME_MAGIC = 0xDEE2;

enum : uint8_t {
  SFRAME_VERSION_1 = 1,
  SFRAME_VERSION_2 = 2,
};

enum : uint8_t {
  SFRAME_F_FDE_SORTED = 1,
  SFRAME_F_FRAME_POINTER = 2,
};

struct __attribute__((packed)) sframe_header {
  sframe_preamble sfh_preamble;
  uint8_t sfh_abi_arch;
  int8_t sfh_cfa_fixed_fp_offset;
  int8_t sfh_cfa_fixed_ra_offset;
  uint8_t sfh_auxhdr_len;
  uint32_t sfh_num_fdes;
  uint32_t sfh_num_fres;
  uint32_t sfh_fre_len;
  uint32_t sfh_fdeoff;
  uint32_t sfh_freoff;
};

static_assert(std::is_trivial_v<sframe_header>);
static_assert(sizeof(sframe_header) == 28);

enum : uint8_t {
  SFRAME_ABI_AARCH64_ENDIAN_BIG = 1,
  SFRAME_ABI_AARCH64_ENDIAN_LITTLE = 2,
  SFRAME_ABI_AMD64_ENDIAN_LITTLE = 3
};

struct __attribute__((packed)) func_desc_entry {
  int32_t sfde_func_start_address;
  uint32_t sfde_func_size;
  uint32_t sfde_func_start_fre_off;
  uint32_t sfde_func_num_fres;
  uint8_t sfde_func_info;
  uint8_t sfde_func_rep_size;
  uint16_t sfde_func_padding2;
};

static_assert(std::is_trivial_v<func_desc_entry>);
static_assert(sizeof(func_desc_entry) == 20);

enum sframe_fre_type_mask : uint8_t {
  fretype_mask = 0b00001111,
  fdetype_mask = 0b00010000,
  pauth_key_mask = 0b00100000,
  unused_mask = 0b11000000,
};

enum : uint8_t {
  SFRAME_FDE_TYPE_PCINC = 0,
  SFRAME_FDE_TYPE_PCMASK = 1,
};

enum : uint8_t {
  SFRAME_FRE_TYPE_ADDR1 = 0,
  SFRAME_FRE_TYPE_ADDR2 = 1,
  SFRAME_FRE_TYPE_ADDR4 = 2,
};

using sframe_fre_info = uint8_t;

struct __attribute__((packed)) sframe_frame_row_entry_addr1 {
  uint8_t sfre_start_address;
  sframe_fre_info sfre_info;
};

static_assert(std::is_trivial_v<sframe_frame_row_entry_addr1>);
static_assert(sizeof(sframe_frame_row_entry_addr1) == 2);

struct __attribute__((packed)) sframe_frame_row_entry_addr2 {
  uint16_t sfre_start_address;
  sframe_fre_info sfre_info;
};

static_assert(std::is_trivial_v<sframe_frame_row_entry_addr2>);
static_assert(sizeof(sframe_frame_row_entry_addr2) == 3);

struct __attribute__((packed)) sframe_frame_row_entry_addr4 {
  uint32_t sfre_start_address;
  sframe_fre_info sfre_info;
};

static_assert(std::is_trivial_v<sframe_frame_row_entry_addr4>);
static_assert(sizeof(sframe_frame_row_entry_addr4) == 5);

enum sframe_fre_info_mask : uint8_t {
  fre_cfa_base_reg_id_mask = 0b00000001,
  fre_offset_count_mask    = 0b00011110,
  fre_offset_size_mask     = 0b01100000,
  fre_mangled_ra_p_mask    = 0b10000000
};

} // End of namespace sframe
} // End of namespace llvm

#endif // LLVM_BINARYFORMAT_SFRAME_H
