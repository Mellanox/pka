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

#ifndef __PKA_INTERNAL_H__
#define __PKA_INTERNAL_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include "pka_queue.h"
#include "pka_ring.h"

#define PKA_LIB_VERSION          "v1"

#define PKA_DEFAULT_NAME         "default"
#define PKA_DEFAULT_SIZE         (16 * MEGABYTE) // 16 MB

#define PKA_MAX_QUEUES_NUM        16

typedef struct
{
    pka_queue_t *cmd_queue;  ///< pointer to SW command queue.
    pka_queue_t *rslt_queue; ///< pointer to SW result queue.
} pka_worker_t;


// Shared structure - Should be visible to PK process and threads
typedef struct
{
    pid_t            main_pid;           ///< main process identifier

    uint32_t         requests_cnt;       ///< command request counter.
    uint32_t         queues_cnt;         ///< number of queues supported.
    uint32_t         cmd_queue_size;     ///< size of a command queue.
    uint32_t         rslt_queue_size;    ///< size of a result queue.

    pka_atomic32_t   workers_cnt;        ///< number of active workers.
    pka_worker_t     workers[PKA_MAX_QUEUES_NUM]; ///< table of initialized
                                                  ///  thread workers.

    uint32_t         rings_byte_order;   ///< byte order whether BE or LE.
    uint8_t          rings_mask[PKA_RING_NUM_BITMASK]; ///< bitmask of allocated HW rings.
    uint32_t         rings_cnt;          ///< number of allocated Rings.
    pka_ring_info_t  rings[PKA_MAX_NUM_RINGS];    ///< table of allocated rings
                                                  ///  to process PK commands.

    /// Lock-free implementations have higher performance and scale better
    /// than implementations using locks. User can decide whether to use
    /// lock-free implementation or its own locking mechanism by setting flags.
    /// these flags tend to optimize performance on platforms that implement
    /// a performance critical operation using locks.
    pka_atomic64_t   lock;               ///< protect shared resources.
    pka_flags_t      flags;              ///< flags supplied during creation.

    uint8_t         *mem_ptr;            ///< pointer to free memory space of
                                         ///  SW queues.

    uint8_t mem[0] __pka_cache_aligned;  ///< memory space of SW queues starts
                                         ///  here.
} pka_global_info_t;

typedef struct
{
    uint32_t            id;         ///< handle identifier - thread specific.
    uint32_t            req_num;    ///< number of outstanding requests.
    pka_global_info_t  *gbl_info;   ///< pointer to the instance information the
                                    ///  handle belongs to.
} pka_local_info_t;

static pka_global_info_t *pka_gbl_info; ///< PK global information.

// For Future use - currently used for statistics and might be extended
// and edited later.
typedef struct
{
    uint64_t    start_cycles;       ///< cycle count when cmd was submitted.
    uint64_t    overhead_cycles;    ///< overhead cycles count from submitting
                                    ///  a cmd until pushing it to the HW ring.
    uint64_t    processing_cycles;  ///< cmd processing cycles count.
    uint32_t    valid;              ///< if set to 'PKA_CMD_STATS_VALID'
                                    ///  then the stats entry is valid.
} pka_cmd_stats_t;

#define PKA_CMD_STATS_VALID     0xDEADBEEF

typedef struct
{
    pka_cmd_stats_t cmd_stats[4096]; ///< stats entry
    uint16_t        index:12;        ///< index in 0 .. 4095, wrapping is permitted.
} pka_cmd_stats_db_t;

static pka_cmd_stats_db_t pka_cmd_stats_db[PKA_MAX_QUEUES_NUM];

#endif // __PKA_INTERNAL_H__
