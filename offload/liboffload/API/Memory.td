//===-- Memory.td - Memory definitions for Offload ---------*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains Offload API definitions related to memory allocations
//
//===----------------------------------------------------------------------===//

def : Enum {
  let name = "ol_alloc_type_t";
  let desc = "Represents the type of allocation made with olMemAlloc.";
  let etors = [
    Etor<"HOST", "Host allocation">,
    Etor<"DEVICE", "Device allocation">,
    Etor<"MANAGED", "Managed allocation">
  ];
}

def : Function {
  let name = "olMemAlloc";
  let desc = "Creates a memory allocation on the specified device.";
  let params = [
    Param<"ol_device_handle_t", "Device", "handle of the device to allocate on", PARAM_IN>,
    Param<"ol_alloc_type_t", "Type", "type of the allocation", PARAM_IN>,
    Param<"size_t", "Size", "size of the allocation in bytes", PARAM_IN>,
    Param<"void**", "AllocationOut", "output for the allocated pointer", PARAM_OUT>
  ];
  let returns = [
    Return<"OL_ERRC_INVALID_SIZE", [
      "`Size == 0`"
    ]>
  ];
}

def : Function {
  let name = "olMemFree";
  let desc = "Frees a memory allocation previously made by olMemAlloc.";
  let params = [
    Param<"void*", "Address", "address of the allocation to free", PARAM_IN>,
  ];
  let returns = [];
}

def : Function {
    let name = "olMemcpy";
    let desc = "Enqueue a memcpy operation.";
    let details = [
        "For host pointers, use the host device belonging to the OL_PLATFORM_BACKEND_HOST platform.",
        "If a queue is specified, at least one device must be a non-host device",
        "If a queue is not specified, the memcpy happens synchronously"
    ];
    let params = [
        Param<"ol_queue_handle_t", "Queue", "handle of the queue.", PARAM_IN_OPTIONAL>,
        Param<"void*", "DstPtr", "pointer to copy to", PARAM_IN>,
        Param<"ol_device_handle_t", "DstDevice", "device that DstPtr belongs to", PARAM_IN>,
        Param<"const void*", "SrcPtr", "pointer to copy from", PARAM_IN>,
        Param<"ol_device_handle_t", "SrcDevice", "device that SrcPtr belongs to", PARAM_IN>,
        Param<"size_t", "Size", "size in bytes of data to copy", PARAM_IN>,
    ];
    let returns = [];
}
