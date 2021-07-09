//
//   BSD LICENSE
//
//   Copyright(c) 2016 Mellanox Technologies, Ltd. All rights reserved.
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//     * Neither the name of Mellanox Technologies nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#ifndef __PKA_RING_H__
#define __PKA_RING_H__

///
/// @file
///
/// This file forms an interface to the BlueField Public Key Accelerator based
/// on EIP-154.
///
/// Rings are used as a communication mechanism between ARM cores (controller)
/// and the farm engines controlled by EIP-154 master firmware.
///
/// Note that the API defines data stuctures and functions to manage rings
/// within window RAM, and to enqueue/dequeue descriptors. Rings are considered
/// as a memory of descriptors (command/result descriptors) using finite size
/// circular queue and a couple of control status registers (count registers).
///


#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>           // for O_* constants
#include <unistd.h>
#include "pka_vectors.h"
#endif

#ifdef PKA_LIB_RING_DEBUG
// A structure that stores the ring statistics.
typedef struct
{
    uint64_t enq_success_cmd;  ///< Cmd descriptors successfully enqueued.
    uint64_t enq_fail_cmd;     ///< Cmd descriptors that failed to be enqueued.
    uint64_t deq_success_rslt; ///< Rslt descriptors successfully dequeued.
    uint64_t deq_fail_rslt;    ///< Rslt descriptors that failed to be dequeued.
} pka_ring_debug_stats __pka_cache_aligned;
#endif

#ifdef PKA_LIB_RING_DEBUG
#define __RING_STAT_ADD(r, name, n) ({ ##r##->stats.##name += 1; })
#else
#define __RING_STAT_ADD(r, name, n) do {} while(0)
#endif

/// Bluefield PKA command descriptor.
typedef struct  // 64 bytes long. 64 bytes aligned
{
    uint64_t pointer_a;
    uint64_t pointer_b;
    uint64_t pointer_c;
    uint64_t pointer_d;
    uint64_t tag;
    uint64_t pointer_e;

#ifdef __AARCH64EB__
    uint64_t linked         : 1;
    uint64_t driver_status  : 2;
    uint64_t odd_powers     : 5;    ///< shiftCnt for shift ops
    uint64_t kdk            : 2;    ///< Key Decryption Key number
    uint64_t encrypted_mask : 6;
    uint64_t rsvd_3         : 8;
    uint64_t command        : 8;
    uint64_t rsvd_2         : 5;
    uint64_t length_b       : 9;
    uint64_t output_attr    : 1;
    uint64_t input_attr     : 1;
    uint64_t rsvd_1         : 5;
    uint64_t length_a       : 9;
    uint64_t rsvd_0         : 2;
#else
    uint64_t rsvd_0         : 2;
    uint64_t length_a       : 9;
    uint64_t rsvd_1         : 5;
    uint64_t input_attr     : 1;
    uint64_t output_attr    : 1;
    uint64_t length_b       : 9;
    uint64_t rsvd_2         : 5;
    uint64_t command        : 8;
    uint64_t rsvd_3         : 8;
    uint64_t encrypted_mask : 6;
    uint64_t kdk            : 2;    ///< Key Decryption Key number
    uint64_t odd_powers     : 5;    ///< shiftCnt for shift ops
    uint64_t driver_status  : 2;
    uint64_t linked         : 1;
#endif

    uint64_t rsvd_4;
} pka_ring_hw_cmd_desc_t;

#define CMD_DESC_SIZE  sizeof(pka_ring_hw_cmd_desc_t)  // Must be 64

/// Bluefield PKA result descriptor.
typedef struct  // 64 bytes long. 64 bytes aligned
{
    uint64_t pointer_a;
    uint64_t pointer_b;
    uint64_t pointer_c;
    uint64_t pointer_d;
    uint64_t tag;

#ifdef __AARCH64EB__
    uint64_t rsvd_5                 : 13;
    uint64_t cmp_result             : 3;
    uint64_t modulo_is_0            : 1;
    uint64_t rsvd_4                 : 2;
    uint64_t modulo_msw_offset      : 11;
    uint64_t rsvd_3                 : 2;
    uint64_t rsvd_2                 : 11;
    uint64_t main_result_msb_offset : 5;
    uint64_t result_is_0            : 1;
    uint64_t rsvd_1                 : 2;
    uint64_t main_result_msw_offset : 11;
    uint64_t rsvd_0                 : 2;

    uint64_t linked         : 1;
    uint64_t driver_status  : 2;    ///< Always written to 0
    uint64_t odd_powers     : 5;    ///< shiftCnt for shift ops
    uint64_t kdk            : 2;    ///< Key Decryption Key number
    uint64_t encrypted_mask : 6;
    uint64_t result_code    : 8;
    uint64_t command        : 8;
    uint64_t rsvd_8         : 5;
    uint64_t length_b       : 9;
    uint64_t output_attr    : 1;
    uint64_t input_attr     : 1;
    uint64_t rsvd_7         : 5;
    uint64_t length_a       : 9;
    uint64_t rsvd_6         : 2;
#else
    uint64_t rsvd_0                 : 2;
    uint64_t main_result_msw_offset : 11;
    uint64_t rsvd_1                 : 2;
    uint64_t result_is_0            : 1;
    uint64_t main_result_msb_offset : 5;
    uint64_t rsvd_2                 : 11;
    uint64_t rsvd_3                 : 2;
    uint64_t modulo_msw_offset      : 11;
    uint64_t rsvd_4                 : 2;
    uint64_t modulo_is_0            : 1;
    uint64_t cmp_result             : 3;
    uint64_t rsvd_5                 : 13;

    uint64_t rsvd_6         : 2;
    uint64_t length_a       : 9;
    uint64_t rsvd_7         : 5;
    uint64_t input_attr     : 1;
    uint64_t output_attr    : 1;
    uint64_t length_b       : 9;
    uint64_t rsvd_8         : 5;
    uint64_t command        : 8;
    uint64_t result_code    : 8;
    uint64_t encrypted_mask : 6;
    uint64_t kdk            : 2;    ///< Key Decryption Key number
    uint64_t odd_powers     : 5;    ///< shiftCnt for shift ops
    uint64_t driver_status  : 2;    ///< Always written to 0
    uint64_t linked         : 1;
#endif

    uint64_t rsvd_9;
} pka_ring_hw_rslt_desc_t;

#define RESULT_DESC_SIZE  sizeof(pka_ring_hw_rslt_desc_t)  // Must be 64

/// Describes a PKA command/result ring as used by the hardware.  A pair of
/// command and result rings in PKA window memory, and the data memory used
/// by the commands.
typedef struct
{
  uint32_t num_descs;      ///< total number of descriptors in the ring.

  uint32_t cmd_ring_base;  ///< base address of the command ring.
  uint32_t cmd_idx;        ///< index of the command in a ring.

  uint32_t rslt_ring_base; ///< base address of the result ring.
  uint32_t rslt_idx;       ///< index of the result in a ring.

  uint32_t operands_base;  ///< operands memory base address.
  uint32_t operands_end;   ///< end address of operands memory.

  uint32_t desc_size;      ///< size of each element in the ring.

  uint64_t cmd_desc_mask;  ///< bitmask of free(0)/in_use(1) cmd descriptors.
  uint32_t cmd_desc_cnt;   ///< number of command descriptors currently in use.
  uint32_t rslt_desc_cnt;  ///< number of result descriptors currently ready.
} pka_ring_desc_t;

/// This structure declares ring parameters which can be used by user interface.
typedef struct
{
    int         fd;             ///< file descriptor.
    int         group;          ///< iommu group.
    int         container;      ///< vfio cointainer

    uint32_t    idx;            ///< ring index.
    uint32_t    ring_id;        ///< hardware ring identifier.

    uint64_t    mem_off;        ///< offset specific to window RAM region.
    uint64_t    mem_addr;       ///< window RAM region address.
    uint64_t    mem_size;       ///< window RAM region size.

    uint64_t    reg_off;        ///< offset specific to count registers region.
    uint64_t    reg_addr;       ///< count registers region address.
    uint64_t    reg_size;       ///< count registers region size.

    void       *mem_ptr;        ///< pointer to map-ped memory region.
    void       *reg_ptr;        ///< pointer to map-ped counters region.

    pka_ring_desc_t ring_desc;  ///< ring descriptor.

#ifdef PKA_LIB_RING_DEBUG
    struct pka_ring_debug_stats stats;
#endif

    uint8_t     big_endian;     ///< big endian byte order when enabled.
} pka_ring_info_t;

typedef struct
{
    uint32_t  dst_offset;        ///< operands desctination offset.
    uint32_t  max_dst_offset;    ///< operands end offset.

    pka_ring_info_t *ring;
} pka_ring_alloc_t;

// This sturcture encapsulates 'user data' information, it also includes
// additional information useful for command processing and statistics.
typedef struct
{
    uint64_t valid; ///< if set to 'PKA_UDATA_INFO_VALID' then info is valid
    uint64_t user_data;     ///< opaque user address.
    uint64_t cmd_num;       ///< command request number.
    uint8_t  cmd_desc_idx;  ///< index of the cmd descriptor in HW rings
    uint8_t  ring_num;      ///< command request number.
    uint8_t  queue_num;     ///< queue number.
} pka_udata_info_t;

#define PKA_UDATA_INFO_VALID    0xDEADBEEF

// This structure consists of a data base to store user data information.
// Note that a data base should be associated with a hardware ring.
typedef struct
{
    pka_udata_info_t entries[256]; // user data information entries.
    uint8_t          index;        // entry index. Wrapping is permitted.
} pka_udata_db_t;

#ifndef __KERNEL__
/// Lookup for 'req_rings_num' number of rings. This function search for a
/// set of free hardware rings which can be used. It returns 0 on success,
/// a negative error code on failure. Note that it also returns the number
/// of rings found (cnt - might be less that the requested number if no enough
/// rings available), the associated mask, and a table of rings matching
/// that number.
int pka_ring_lookup(pka_ring_info_t rings[],
                    uint32_t        req_rings_num,
                    uint8_t         byte_order,
                    uint8_t         mask[],
                    uint32_t        *cnt);

/// Free a set of assigned rings, referred by their number (cnt), their mask.
/// It returns 0 on success, a negative error code on failure.
int pka_ring_free(pka_ring_info_t rings[], uint8_t mask[], uint32_t *cnt);

/// Returns the number of available of rooms to append a command descriptors
/// within a given ring.
uint32_t pka_ring_has_available_room(pka_ring_info_t *ring);

/// Returns the number of available results (when result is ready). Note that
/// the returned value may reflect the number of processed commands.
uint32_t pka_ring_has_ready_rslt(pka_ring_info_t *ring);

/// Return whether the returned pointer to use data info is valid or not.
bool pka_ring_pop_tag(pka_ring_hw_rslt_desc_t *result_desc,
                      uint64_t                *user_data,
                      uint64_t                *cmd_num,
                      uint8_t                 *queue_num,
                      uint8_t                 *ring_num);

/// Set ring command descriptor tag which is used to hold a pointer to user
/// data info associated with a cmd.
void pka_ring_push_tag(pka_ring_hw_cmd_desc_t *cmd,
                       uint64_t                user_data,
                       uint64_t                cmd_num,
                       uint8_t                 queue_num,
                       uint8_t                 ring_num);

/// Write the command descriptor according to the PK command. This function
/// should be called before enqueuing the descriptor on a ring.
int pka_ring_set_cmd_desc(pka_ring_hw_cmd_desc_t *cmd,
                          pka_ring_alloc_t       *alloc,
                          pka_opcode_t            opcode,
                          uint32_t                operand_cnt,
                          uint32_t                shift_cnt,
                          pka_operand_t           operands[]);

/// Enqueue one command descriptor on a ring. This function verifies if there
/// is space in the queue for the command and append the descriptor. It returns
/// 0 on success, a negative error code on failure.
int pka_ring_enqueue_cmd_desc(pka_ring_info_t        *ring,
                              pka_ring_hw_cmd_desc_t *cmd_desc);

/// Dequeue one result descriptor from a ring. This function verifies if there
/// is a ready result in the queue for the command and read the descriptor. It
/// returns 0 on success, a negative error code on failure.
int pka_ring_dequeue_rslt_desc(pka_ring_info_t         *ring,
                               pka_ring_hw_rslt_desc_t *result_desc);

/// Get the output vector(s) associated with a result descriptor from ring
/// memory and copy it to a queue. It returns the queue head address.
uint32_t pka_ring_get_result(pka_ring_info_t         *ring,
                             pka_ring_hw_rslt_desc_t *result_desc,
                             uint8_t                 *queue_ptr,
                             uint32_t                 queue_size,
                             uint32_t                 result1_offset,
                             uint32_t                 result2_offset,
                             uint32_t                 result1_size,
                             uint32_t                 result2_size);

/// Set the size of result operands and return the number of results associated
/// with a given PK command.
uint32_t pka_ring_results_len(pka_ring_hw_rslt_desc_t *result_desc,
                              uint32_t                *result1_len,
                              uint32_t                *result2_len);

/// Dump the status of the ring on the console
void pka_ring_dump(pka_ring_info_t *r);

#endif // !__KERNEL__

#endif /// __PKA_RING_H__


