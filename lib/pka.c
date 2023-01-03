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

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>        // for mode constants
#include <fcntl.h>           // for O_* constants
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>

#include "pka_internal.h"
#include "pka_utils.h"
#include "pka_vectors.h"
#include "pka_mem.h"

#define PKA_INVALID_OPERANDS    0x0

uint64_t cpu_f_hz;

// Start statistics counters. Returns the command number associated with
// a statistic entry.
static __pka_inline uint32_t pka_stats_start_cycles_cnt(uint32_t queue_num)
{
    pka_cmd_stats_db_t *stats_db;
    pka_cmd_stats_t    *stats_entry;
    uint32_t            cmd_num;

    stats_db    = &pka_cmd_stats_db[queue_num];

    cmd_num     =  stats_db->index++;
    stats_entry = &stats_db->cmd_stats[cmd_num];

    stats_entry->start_cycles = pka_cpu_cycles();
    stats_entry->valid        = PKA_CMD_STATS_VALID;

    return cmd_num;
}

// Discard a given statistics entry from database.
static __pka_inline void pka_stats_discard(uint8_t queue_num, uint32_t cmd_num)
{
    pka_cmd_stats_db_t *stats_db;
    pka_cmd_stats_t    *stats_entry;

    stats_db         = &pka_cmd_stats_db[queue_num];

    stats_entry      = &stats_db->cmd_stats[cmd_num];
    memset(stats_entry, 0, sizeof(pka_cmd_stats_t));
}

void pka_stats_print(uint8_t queue_num, uint32_t cmd_num)
{
    pka_cmd_stats_db_t *stats_db;
    pka_cmd_stats_t    *stats_entry;

    stats_db    = &pka_cmd_stats_db[queue_num];
    stats_entry = &stats_db->cmd_stats[cmd_num];

    printf("[%u] command %u :\n", queue_num, cmd_num);
    printf("\t overhead cycles   =%lu\n", stats_entry->overhead_cycles);
    printf("\t processing cycles =%lu\n", stats_entry->processing_cycles);
}

// Capture overhead cycles -i.e. cycles needed to prepare a command for
// processing and enqueue in HW rings. It includes the waiting cyles in
// a SW command queue before the command get processed.
static __pka_inline void pka_stats_overhead_cycles_cnt(uint8_t queue_num,
                                                       uint32_t cmd_num)
{
    pka_cmd_stats_db_t *stats_db;
    pka_cmd_stats_t    *stats_entry;
    uint64_t            cycles_start, cycles_end, cycles_taken;

    stats_db    = &pka_cmd_stats_db[queue_num];
    stats_entry = &stats_db->cmd_stats[cmd_num];

    if (stats_entry->valid == PKA_CMD_STATS_VALID)
    {
        cycles_end    = pka_cpu_cycles();
        cycles_start  = stats_entry->start_cycles;
        cycles_taken  = pka_cpu_cycles_diff(cycles_end, cycles_start);
        stats_entry->overhead_cycles = cycles_taken;
    }
}

// Capture processing cylces -i.e. cycles needed to process commands starting
// from HW ring enqueue to result enqueue in SW queue.
static __pka_inline void pka_stats_processing_cycles_cnt(uint8_t queue_num,
                                                         uint32_t cmd_num)
{
    pka_cmd_stats_db_t *stats_db;
    pka_cmd_stats_t    *stats_entry;
    uint64_t            cycles_start, cycles_end, cycles_taken;

    stats_db    = &pka_cmd_stats_db[queue_num];
    stats_entry = &stats_db->cmd_stats[cmd_num];

    if (stats_entry->valid == PKA_CMD_STATS_VALID)
    {
        cycles_end    = pka_cpu_cycles();
        cycles_start  = stats_entry->overhead_cycles;
        cycles_taken  = pka_cpu_cycles_diff(cycles_end, cycles_start);
        stats_entry->processing_cycles = cycles_taken;
    }
}

// Return Rings byte order, whether BE(1) or LE(0).
uint8_t pka_get_rings_byte_order(pka_handle_t handle)
{
    pka_global_info_t *gbl_info;
    pka_local_info_t  *local_info;
    uint32_t           rings_byte_order;

    rings_byte_order = PKA_RING_BYTE_ORDER;

    local_info = (pka_local_info_t *) handle;
    if (local_info)
    {
        gbl_info         = local_info->gbl_info;
        rings_byte_order = gbl_info->rings_byte_order;
    }

    return rings_byte_order;
}

// Determine the size of memory shared object.
static uint32_t pka_get_memsize(uint8_t cnt, uint32_t cmd_queue_size,
                                    uint32_t result_queue_size)
{
    uint32_t mem_size;

    mem_size  = cmd_queue_size;
    mem_size += result_queue_size;
    mem_size *= cnt;
    mem_size += sizeof(pka_global_info_t);
    mem_size  = PKA_ALIGN(mem_size, PKA_CACHE_LINE_SIZE);

    return mem_size;
}

// Initialize worker.
static void pka_init_worker_queues(pka_global_info_t *info, uint32_t queues_cnt)
{
    pka_worker_t *worker;
    uint32_t      cmd_queue_size, rslt_queue_size;
    uint8_t       worker_idx;
    uint8_t      *mem_ptr;

    // Create FIFO queues to append command descriptors and get result
    // descriptors. These queues aims to handle hardware rings overflow.
    cmd_queue_size     = info->cmd_queue_size;
    rslt_queue_size    = info->rslt_queue_size;

    mem_ptr = info->mem_ptr;

    // Instead of allocating contiguous command and result queues, we opt
    // for a first pool with all command queues, and a second pool with the
    // result queues.

    // Create contiguous command queues.
    for (worker_idx = 0; worker_idx < queues_cnt; worker_idx++)
    {
        worker = &info->workers[worker_idx];

        // Create command SW queue.
        worker->cmd_queue  = pka_queue_create(cmd_queue_size,
                                                PKA_QUEUE_TYPE_CMD, mem_ptr);

        // increment memory pointer.
        mem_ptr      += cmd_queue_size;
    }

    // Create contiguous result queues.
    for (worker_idx = 0; worker_idx < queues_cnt; worker_idx++)
    {
        worker = &info->workers[worker_idx];

        // Create result SW queue.
        worker->rslt_queue = pka_queue_create(rslt_queue_size,
                                                PKA_QUEUE_TYPE_RSLT, mem_ptr);

        // increment memory pointer.
        mem_ptr      += rslt_queue_size;
    }
}

// Global PKA initialization.
pka_instance_t pka_init_global(const char *name,
                               uint8_t     flags,
                               uint32_t    ring_cnt,
                               uint32_t    queue_cnt,
                               uint32_t    cmd_queue_size,
                               uint32_t    result_queue_size)
{
    uint32_t  mem_size;
    int       ret;

    if ((!flags) || (cmd_queue_size > PKA_QUEUE_MASK_SIZE)  ||
            (result_queue_size > PKA_QUEUE_MASK_SIZE)  ||
            (ring_cnt          > PKA_MAX_NUM_RINGS)    ||
            (queue_cnt         > PKA_MAX_QUEUES_NUM))
    {
        PKA_DEBUG(PKA_USER, "invalid PK context arguments\n");
        errno = EINVAL;
        goto exit_error;
    }

    PKA_DEBUG(PKA_USER, "Instance name: %s\n", name);

    // Determine the size of the pair of queues.
    if (!pka_is_power_of_2(cmd_queue_size))
        cmd_queue_size  = pka_align32pow2(cmd_queue_size);

    if (!pka_is_power_of_2(result_queue_size))
        result_queue_size += pka_align32pow2(result_queue_size);

    cmd_queue_size    = pka_queue_get_memsize(cmd_queue_size);
    result_queue_size = pka_queue_get_memsize(result_queue_size);
    // Determine the memory required for PK context.
    mem_size = pka_get_memsize(queue_cnt, cmd_queue_size,
                               result_queue_size);

    pka_gbl_info = (pka_global_info_t *) calloc(1, mem_size);
    if (pka_gbl_info == NULL)
    {
        errno = ENOMEM;
        goto exit_error;
    }

    // Verify if rings are available to process PKA commands.
    pka_gbl_info->rings_byte_order =
                            pka_get_rings_byte_order(PKA_HANDLE_INVALID);
    ret = pka_ring_lookup(pka_gbl_info->rings, ring_cnt,
                          pka_gbl_info->rings_byte_order,
                          pka_gbl_info->rings_mask,
                          &pka_gbl_info->rings_cnt);
    if (ret)
    {
        PKA_DEBUG(PKA_USER, "failed to retrieve free rings\n");
        errno = EBUSY;
        goto exit_mem_free;
    }

    // Initialize PK context info
    pka_atomic64_init(&pka_gbl_info->lock, 0);
    pka_atomic32_init(&pka_gbl_info->workers_cnt, 0);
    pka_gbl_info->flags           = flags;
    pka_gbl_info->queues_cnt      = queue_cnt;
    pka_gbl_info->cmd_queue_size  = cmd_queue_size;
    pka_gbl_info->rslt_queue_size = result_queue_size;
    // Init memory pointer.
    pka_gbl_info->mem_ptr = (uint8_t *) pka_gbl_info->mem;

    // Create worker queues
    pka_init_worker_queues(pka_gbl_info, queue_cnt);

    // Get process identifier for the PK instance
    pka_gbl_info->main_pid     = getpid();
    pka_gbl_info->requests_cnt = 0;

    PKA_DEBUG(PKA_USER, "PKA instance %s created successfully\n", name);
    return (pka_instance_t) pka_gbl_info->main_pid;

exit_mem_free:
    PKA_DEBUG(PKA_USER, "munmap PKA shared memory object\n");
    free(pka_gbl_info);
    pka_gbl_info = NULL;
exit_error:
    return PKA_INSTANCE_INVALID;
}

// Global PKA termination.
void pka_term_global(pka_instance_t instance)
{
    if (instance == (pka_instance_t) pka_gbl_info->main_pid)
    {
        if (pka_atomic32_load(&pka_gbl_info->workers_cnt))
            PKA_DEBUG(PKA_USER, "warning: non-released PK handles are no "
                                        "longer usable\n");

        PKA_DEBUG(PKA_USER, "release PKA rings\n");
        pka_ring_free(pka_gbl_info->rings, pka_gbl_info->rings_mask,
                      &pka_gbl_info->rings_cnt);

        free(pka_gbl_info);
        pka_gbl_info = NULL;
    }
}

// Thread local PKA initialization.
pka_handle_t pka_init_local(pka_instance_t instance)
{
    pka_local_info_t *local_info;
    uint8_t           worker_id;

    if (instance != (pka_instance_t) pka_gbl_info->main_pid)
    {
        PKA_DEBUG(PKA_USER, "bad PK instance\n");
        errno = EINVAL;
        return PKA_HANDLE_INVALID;
    }

    // load and increment the number workers.
    worker_id = pka_atomic32_fetch_inc_relaxed(&pka_gbl_info->workers_cnt);
    if (worker_id > pka_gbl_info->queues_cnt - 1)
    {
        PKA_DEBUG(PKA_USER, "handle cnt exceeded\n");
        errno = EINVAL;
        return PKA_HANDLE_INVALID;
    }

    local_info = calloc(sizeof(*local_info), 1);
    if (!local_info)
    {
        pka_atomic32_dec(&pka_gbl_info->workers_cnt);
        errno = ENXIO;
        return PKA_HANDLE_INVALID;
    }
    // Init PK handle
    local_info->id       = worker_id;
    local_info->gbl_info = pka_gbl_info;
    local_info->req_num  = 0;

    PKA_DEBUG(PKA_USER, "PKA handle %d initialized successfully\n",
                    worker_id);

    return (pka_handle_t) local_info;
}

// Thread local PKA termination.
void pka_term_local(pka_handle_t handle)
{
    pka_local_info_t *local_info;

    local_info = (pka_local_info_t *) handle;
    if (local_info)
    {
        pka_atomic32_dec(&local_info->gbl_info->workers_cnt);
        free(local_info);
    }
}

uint32_t pka_get_rings_count(pka_instance_t instance)
{
    if (instance == (pka_instance_t) pka_gbl_info->main_pid)
        return pka_gbl_info->rings_cnt;

    return 0;
}

uint8_t* pka_get_rings_bitmask(pka_instance_t instance)
{
    if (instance == (pka_instance_t) pka_gbl_info->main_pid)
        return pka_gbl_info->rings_mask;

    return 0;
}

static pka_ring_info_t* pka_has_available_ring(pka_ring_info_t rings_info[],
                                               uint8_t         rings_cnt,
                                               uint32_t        vectors_size,
                                               uint32_t       *avail_descs_cnt)
{
    pka_ring_info_t *ring_info;
    bool             found;
    uint32_t         best_ring_idx, cnt;
    uint8_t          ring_idx;

    best_ring_idx    = 0;
    *avail_descs_cnt = 0;
    cnt              = 0;
    found            = false;

    for (ring_idx = 0; ring_idx < rings_cnt; ring_idx++)
    {
        ring_info = &rings_info[ring_idx];

        cnt = pka_ring_has_available_room(ring_info);
        if (!cnt)
            continue;

        if (pka_mem_is_full(ring_info->ring_id, vectors_size))
            continue;

        if (cnt > *avail_descs_cnt)
        {
            best_ring_idx    = ring_idx;
            *avail_descs_cnt = cnt;
            found            = true;
        }
    }

    return (found == true) ? &rings_info[best_ring_idx] : NULL;
}

// Check if there is an available descriptor across rings. This function should
// return as soon as possible.
static bool pka_has_avail_descs(pka_global_info_t *gbl_info)
{
    pka_ring_info_t *ring;
    bool             has_avail_desc;
    uint8_t          ring_idx, rings_cnt;

    rings_cnt       = gbl_info->rings_cnt;
    has_avail_desc  = false;

    for (ring_idx = 0; ring_idx < rings_cnt; ring_idx++)
    {
        ring = &gbl_info->rings[ring_idx];
        if (pka_ring_has_available_room(ring))
        {
            has_avail_desc = true;
            break;
        }
    }

    return has_avail_desc;
}

// Determine the number of available descriptors.
uint32_t pka_avail_desc_count(pka_global_info_t *gbl_info)
{
    pka_ring_info_t *ring;
    uint32_t         avail_descs_cnt;
    uint8_t          ring_idx, rings_cnt;

    rings_cnt       = gbl_info->rings_cnt;
    avail_descs_cnt = 0;

    for (ring_idx = 0; ring_idx < rings_cnt; ring_idx++)
    {
        ring             = &gbl_info->rings[ring_idx];
        avail_descs_cnt += pka_ring_has_available_room(ring);
    }

    return avail_descs_cnt;
}

// Set HW ring command descriptor to enqueue.
static int pka_set_cmd_desc(pka_global_info_t      *gbl_info,
                            uint8_t                 worker_id,
                            pka_queue_cmd_desc_t   *cmd_desc,
                            pka_ring_hw_cmd_desc_t *ring_desc,
                            pka_ring_alloc_t       *alloc,
                            pka_operand_t           operands[])
{
    pka_worker_t  *worker;
    pka_queue_t   *cmd_queue;
    int ret;

    worker    = &gbl_info->workers[worker_id];
    cmd_queue = worker->cmd_queue;

    // Check whether operands are valid
    if (operands != PKA_INVALID_OPERANDS)
        // Set command ring descriptor and copy operands to window RAM.
        ret = pka_ring_set_cmd_desc(ring_desc, alloc, cmd_desc->opcode,
                    cmd_desc->operand_cnt, cmd_desc->shift_cnt, operands);
    else
        // Dequeue command from SW queue, set command ring descriptor
        // and copy operands to window RAM.
        ret = pka_queue_cmd_dequeue(cmd_queue, ring_desc, alloc);

    return ret;
}

static int pka_rslt_dequeue(pka_local_info_t *local_info)
{
    pka_global_info_t       *gbl_info;
    pka_ring_info_t         *ring;
    pka_ring_hw_rslt_desc_t  ring_desc;
    pka_queue_rslt_desc_t    rslt_desc;
    pka_queue_t             *rslt_queue;
    uint64_t                 user_data, cmd_num;
    uint8_t                  queue_num, ring_num, ring_idx;

    int rc     = 0;
    int errors = 0;

    gbl_info = local_info->gbl_info;

    memset(&ring_desc, 0, sizeof(pka_ring_hw_rslt_desc_t));

    for (ring_idx = 0; ring_idx < gbl_info->rings_cnt; ring_idx++)
    {
        ring = &gbl_info->rings[ring_idx];
        while (pka_ring_has_ready_rslt(ring))
        {
            // optional check of return value. This call is no supposed to fail.
            if (rc != pka_ring_dequeue_rslt_desc(ring, &ring_desc))
            {
                PKA_DEBUG(PKA_USER, "failed to dequeue result from ring\n");
                errors += 1;
                continue;
            }

            // Check if the tag is valid, otherwise discard the result.
            if (!pka_ring_pop_tag(&ring_desc, &user_data, &cmd_num, &queue_num,
                                    &ring_num))
            {
                PKA_DEBUG(PKA_USER, "tag is invalid! result is dropped\n");
                errors += 1;
                continue;
            }

            // Get result queue
            rslt_queue = gbl_info->workers[queue_num].rslt_queue;

            memset(&rslt_desc, 0, sizeof(pka_queue_rslt_desc_t));
            if (!pka_queue_is_full(rslt_queue))
            {
                pka_queue_set_rslt_desc(&rslt_desc, &ring_desc, cmd_num,
                                            user_data, queue_num);

                if (rc != pka_queue_rslt_enqueue(rslt_queue, ring, &ring_desc,
                                                    &rslt_desc))
                {
                    PKA_DEBUG(PKA_USER, "failed to enqueue result in"
                                        "queue %d\n", queue_num);
                    errors += 1;
                }

                // Capture processing cycles cnt
                pka_stats_processing_cycles_cnt(queue_num, cmd_num);
            }
        }
    }

    return errors;
}

static int pka_cmd_enqueue(pka_global_info_t    *gbl_info,
                           uint8_t               worker_id,
                           pka_queue_cmd_desc_t *cmd_desc,
                           pka_operand_t         operands[])
{
    pka_ring_info_t        *ring_info;
    pka_ring_hw_cmd_desc_t  ring_desc;
    pka_ring_alloc_t        alloc;
    uint32_t                base_offset, max_offset;
    uint32_t                avail_descs_num;

    // Pick a specific ring to use. Currently this is done in a simple
    // round robin fashion, with only one command outstanding at a time.
    ring_info = pka_has_available_ring(gbl_info->rings, gbl_info->rings_cnt,
                                cmd_desc->operands_len, &avail_descs_num);
    if (!ring_info)
    {
        PKA_DEBUG(PKA_USER, "there are no rings available\n");
        return -ENOBUFS;
    }

    alloc.ring   = ring_info;
    // Allocate some window RAM for the total set vectors.
    base_offset  = pka_mem_alloc(ring_info->ring_id, cmd_desc->operands_len);
    max_offset   = base_offset + cmd_desc->operands_len;
    // Set operands offsets
    alloc.dst_offset       = base_offset;
    alloc.max_dst_offset   = max_offset;

    // Clear window RAM in order to write operands.
    pka_mem_reset(alloc.dst_offset, ring_info->mem_ptr,
                    cmd_desc->operands_len);

    // Create a command descriptor associated with the command.
    memset(&ring_desc, 0, sizeof(pka_ring_hw_cmd_desc_t));
    if (pka_set_cmd_desc(gbl_info, worker_id, cmd_desc, &ring_desc, &alloc,
                            operands))
    {
        PKA_DEBUG(PKA_USER, "failed to set ring command descriptor\n");
        return -EWOULDBLOCK;
    }

    // Set descriptor tag field.
    pka_ring_push_tag(&ring_desc, cmd_desc->user_data, cmd_desc->cmd_num,
                      worker_id, ring_info->ring_id);

    // Append descriptor to a ring. No need to check return value, this call
    // is not supposed to fail.
    pka_ring_enqueue_cmd_desc(ring_info, &ring_desc);

    // increment the request counter.
    gbl_info->requests_cnt += 1;

    // Capture overhead cycles cnt
    pka_stats_overhead_cycles_cnt(worker_id, cmd_desc->cmd_num);

    return 0;
}

static int pka_process_cmd_queues(pka_global_info_t *gbl_info,
                                  uint8_t            worker_id)
{
    pka_queue_cmd_desc_t  cmd_desc;
    pka_worker_t         *worker;
    pka_queue_t          *cmd_queue;

    int rc = 0;

    worker    = &gbl_info->workers[worker_id];
    cmd_queue = worker->cmd_queue;

    if (pka_queue_is_empty(cmd_queue))
        return 0;

    // Dequeue SW queue.
    memset(&cmd_desc, 0, sizeof(pka_queue_cmd_desc_t));
    if (rc == pka_queue_load_cmd_desc(&cmd_desc, cmd_queue))
    {
        // Enqueue cmd descriptor in HW rings.
        if(rc != pka_cmd_enqueue(gbl_info, worker_id, &cmd_desc,
                                    PKA_INVALID_OPERANDS))
        {
            PKA_DEBUG(PKA_USER, "failed to enqueue a command descriptor"
                                    " of worker %d on HW rings\n", worker_id);
            return 0;
        }

        return 1;
    }

    PKA_DEBUG(PKA_USER, "failed to dequeue a command descriptor from SW"
                            " queue of worker %d\n", worker_id);
    return 0;
}

static int pka_process_queues_sync(pka_local_info_t *local_info)
{
    pka_global_info_t *gbl_info;
    pka_lock_t         lock;
    uint32_t           cmds_num, workers_cnt;
    uint8_t            worker_idx;

    int ret;

    gbl_info    = local_info->gbl_info;
    workers_cnt = pka_atomic32_load(&gbl_info->workers_cnt);
    // We are now the owner of all of the PK context - including all
    // the HW rings.

    // First we do reply processing.
    ret = pka_rslt_dequeue(local_info);
    if (ret)
        PKA_DEBUG(PKA_USER, "failed to dequeue %d results\n", ret);

    // Next process all SW cmd queues at least once. Stop when a full sweep
    // of the SW cmd queues results in nothing.
    while (true)
    {
        cmds_num = 0;
        for (worker_idx = 0; worker_idx < workers_cnt; worker_idx++)
            cmds_num += pka_process_cmd_queues(gbl_info, worker_idx);

        if (cmds_num == 0)
            break;
    }

    // Now try to release the lock, but if we can't because of some other
    // thread's request bit is set, then re-process that SW cmd queue.
    while (true)
    {
        lock = pka_try_release_lock(&gbl_info->lock.v, local_info->id);
        if (lock == LOCK_RELEASED)
            break; // lock was released.

        worker_idx = lock;
        pka_process_cmd_queues(gbl_info, worker_idx);
    }

    return 0;
}

static int pka_process_queues_nosync(pka_local_info_t *local_info)
{
    uint32_t workers_cnt, cmds_num;
    uint8_t  worker_idx;

    int ret;

    // First we do reply processing.
    ret = pka_rslt_dequeue(local_info);
    if (ret)
        PKA_DEBUG(PKA_USER, "failed to dequeue %d results\n", ret);

    workers_cnt = pka_atomic32_load(&local_info->gbl_info->workers_cnt);
    // Next process all SW cmd queues at least once. Stop when a full sweep
    // of the SW cmd queues results in nothing.
    while (true)
    {
        cmds_num = 0;
        for (worker_idx = 0; worker_idx < workers_cnt; worker_idx++)
            cmds_num += pka_process_cmd_queues(local_info->gbl_info,
                                                    worker_idx);

        if (cmds_num == 0)
            break;
    }

    return 0;
}

// Submit PK command
static pka_status_t pka_submit_cmd(pka_handle_t    handle,
                                   void           *user_data,
                                   pka_opcode_t    opcode,
                                   pka_operands_t *operands)
{
    pka_global_info_t *gbl_info;
    pka_local_info_t  *local_info;
    pka_worker_t      *worker;
    pka_lock_t         lock;
    uint8_t            worker_id;

    pka_queue_cmd_desc_t  cmd_desc;
    uint32_t              cmd_num;

    int rc = 0;

    // Get context information.
    local_info = (pka_local_info_t *) handle;
    gbl_info   = local_info->gbl_info;
    worker_id  = local_info->id;
    worker     = &gbl_info->workers[worker_id];

    // Prepare statistics
    cmd_num = pka_stats_start_cycles_cnt(worker_id);

    // Set a command descriptor to enqueue.
    //cmd_num    = local_info->req_num;
    memset(&cmd_desc, 0, sizeof(pka_queue_cmd_desc_t));
    if (pka_queue_set_cmd_desc(&cmd_desc, cmd_num, user_data, opcode,
                                    operands))
    {
        PKA_DEBUG(PKA_USER, "failed to set command descriptor\n");
        pka_stats_discard(worker_id, cmd_num);
        return FAILURE;
    }

    //
    // Start processing PK command.
    //

    // Check the synchronization mode
    if (gbl_info->flags & PKA_F_SYNC_MODE_DISABLE)
    {
        // simple case where no synchronization need to be done
        if (!pka_has_avail_descs(gbl_info))
        {
            PKA_DEBUG(PKA_USER, "there are no available descs\n");

            if (rc != pka_queue_cmd_enqueue(worker->cmd_queue, &cmd_desc,
                                                operands))
            {
                PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a "
                                        "command descriptor on SW queue\n",
                                        worker_id);
                return FAILURE;
            }

        }
        else
        {
            if(rc != pka_cmd_enqueue(gbl_info, worker_id, &cmd_desc,
                                        operands->operands))
            {
                PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a "
                                        "command descriptor on HW ring\n",
                                         worker_id);
                return FAILURE;
            }
        }

        local_info->req_num++;
        pka_process_queues_nosync(local_info);
        return SUCCESS;
    }

    // Multi-threading/lock-free case:

    // BIG ASSUMPTION:  Assume that the pka_handle is locked/owned less than
    // 10% of the time worst case and often less than 1% of the time!

    // Based upon the assumption above, first just optimistically try to
    // acquire the lock.  Should succeed the vast majority of time.  Make sure
    // set_bit is FALSE here, since we have not yet copied the request
    // (cmd and operands) into the sw_request ring.
    lock = pka_try_acquire_lock(&gbl_info->lock.v, local_info->id, false);
    if (lock == LOCK_ACQUIRED)
    {
        // We are now the owner of all of the global state - including all
        // the HW rings.  Note that we do want to copy the request to the
        // end of the sw_req queue if we can instead directly append it to
        // the end of a HW cmd ring!  Hence the following code.
        if (!pka_has_avail_descs(gbl_info))
        {
            PKA_DEBUG(PKA_USER, "there are no available descs\n");

            if (rc != pka_queue_cmd_enqueue(worker->cmd_queue, &cmd_desc,
                                            operands))
                PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a "
                                        "command descriptor on SW queue\n",
                                         worker_id);
        }
        else
        {
            if (rc != pka_cmd_enqueue(gbl_info, worker_id, &cmd_desc,
                                        operands->operands))
            {
                PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a "
                                        "command descriptor on HW ring\n",
                                         worker_id);
                // If we cannot append command to HW ring we enqueue it in
                // our SW queue.
                if (rc != pka_queue_cmd_enqueue(worker->cmd_queue, &cmd_desc,
                                                    operands))
                    PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a "
                                            "command descriptor on SW queue\n",
                                             worker_id);
            }
        }

        pka_process_queues_sync(local_info);
        local_info->req_num++;
        return SUCCESS;
    }

    // We now need to append our request to the end of our SW cmd queue,
    // after making sure that there is room!
    if (rc != pka_queue_cmd_enqueue(worker->cmd_queue, &cmd_desc,
                                        operands))
    {
        PKA_DEBUG(PKA_USER, "worker %d - failed to enqueue a command"
                               " descriptor on SW queue\n", worker_id);
        return FAILURE; // There is not enough room in the SW cmd queue.
    }

    local_info->req_num++;

    // We failed on our first attempt to acquire the lock.  We will make a
    // second attempt, but first we need to register our request, in case
    // we fail a second time.  Note that this call first waits (if neccessary)
    // for any previous request bit of ours to be cleared, since if we set it
    // a second time there is no record of the fact that we made multiple
    // requests.  Thats because each bit setting corresponds to exactly one
    // pk request.  Note that "bit" is TRUE here.
    lock = pka_try_acquire_lock(&gbl_info->lock.v, local_info->id, true);
    if (lock == LOCK_ACQUIRED)
    {
        pka_process_queues_sync(local_info);
        return SUCCESS;
    }

    // This is the somewhat rare case of failing a second attempt to acquire
    // the global lock.  We assume/require that the current owner is guaranteed
    // to see our previously set request bit and act on it before it can
    // release the lock.  Hence we can just return.
    return SUCCESS;
}

static void pka_parse_result(pka_queue_rslt_desc_t *rslt_desc,
                             pka_results_t         *results)
{
    // Get command descriptor information.
    results->user_data      = (void *) rslt_desc->user_data;
    results->opcode         = rslt_desc->opcode;
    results->result_cnt     = rslt_desc->result_cnt;
    results->status         = rslt_desc->status;
    results->compare_result = rslt_desc->compare_result;
}

// Acknowledgement for returned result.
static void pka_result_ack(pka_local_info_t *local_info)
{
    if (local_info->req_num > 0)
        local_info->req_num -= 1;
}

// Return results pending in SW queue.
int pka_get_result(pka_handle_t handle, pka_results_t *results)
{
    pka_local_info_t      *local_info;
    pka_global_info_t     *gbl_info;
    pka_worker_t          *worker;
    pka_queue_rslt_desc_t  rslt_desc;
    pka_queue_t           *rslt_queue;
    pka_lock_t             lock;
    uint8_t                worker_id;

    int rc = 0;

    local_info = (pka_local_info_t *) handle;
    if (!local_info)
    {
        PKA_DEBUG(PKA_USER, "bad PK handle");
        return FAILURE;
    }

    gbl_info  = local_info->gbl_info;
    worker_id = local_info->id;
    worker    = &gbl_info->workers[worker_id];

    // Do queue processing -- if our result is not available i.e. our
    // SW queue is empty, we can process SW queues a second time. Calling
    // pka_process_queues_(no)sync() might help to dequeue our result and
    // push it to SW queue, if our result is ready in HW rings- Otherwise
    // our command might be pending in SW queue, so the call might cause
    // the enqueue of our cmd from SW queue to a HW ring and next time
    // when we will call again pka_get_rslt() (after tn > t0 + T), we
    // make sure that our result will be ready.
    if (gbl_info->flags & PKA_F_SYNC_MODE_DISABLE)
    {
        pka_process_queues_nosync(local_info);
    }
    else
    {
        lock = pka_try_acquire_lock(&gbl_info->lock.v, local_info->id, false);
        if (lock == LOCK_ACQUIRED)
            pka_process_queues_sync(local_info);
    }

    if (pka_queue_is_empty(worker->rslt_queue))
    {
        //PKA_DEBUG(PKA_USER, "worker %d's result queue is empty\n",
        //            local_info->id);
        // *TBD* make a second attempt to process queues (cost?)
        return FAILURE;
    }

    rslt_queue = worker->rslt_queue;
    memset(&rslt_desc, 0, sizeof(pka_queue_rslt_desc_t));
    if (rc == pka_queue_rslt_dequeue(rslt_queue, &rslt_desc, results))
    {
        pka_parse_result(&rslt_desc, results);
        pka_result_ack(local_info);
        return SUCCESS;
    }

    PKA_DEBUG(PKA_USER, "worker %d failed to dequeue result "
                                "descriptor from SW queue\n", worker_id);

    return FAILURE;
}

// Return if there is a avilable results.
bool pka_has_avail_result(pka_handle_t handle)
{
    pka_local_info_t  *local_info;
    pka_global_info_t *gbl_info;
    pka_ring_info_t   *ring;
    pka_queue_t       *rslt_queue;
    uint8_t            ring_idx, rings_cnt;

    local_info = (pka_local_info_t *) handle;
    if (local_info)
    {
        gbl_info   = local_info->gbl_info;
        rings_cnt  = gbl_info->rings_cnt;
        rslt_queue = gbl_info->workers[local_info->id].rslt_queue;

        if (!pka_queue_is_empty(rslt_queue))
            return true;

        for (ring_idx = 0; ring_idx < rings_cnt; ring_idx++)
        {
            ring = &gbl_info->rings[ring_idx];
            if (pka_ring_has_ready_rslt(ring) > 0)
                return true;
        }
    }

    return false;
}

// Return the number of outstanding command requets.
uint32_t pka_request_count(pka_handle_t handle)
{
    pka_local_info_t *local_info;

    local_info = (pka_local_info_t *) handle;
    if (local_info)
        return local_info->req_num;

    return 0;
}

static uint32_t pka_process_operand(pka_operand_t *value, uint8_t big_endian)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len          = value->actual_len;
    value->big_endian = big_endian;
    if (byte_len == 0)
        return 0;

    if (big_endian != 0)
    {
        byte_ptr = &value->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return byte_len;

        // Move forwards over all zero bytes.
        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr++;
            byte_len--;
        }

        value->buf_ptr    = byte_ptr;
        value->actual_len = byte_len;
        return byte_len;
    }
    else  // little-endian.
    {
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes, in order to skip leading
        // zeros and find the real byte_len.
        byte_ptr = &value->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len;

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr--;
            byte_len--;
        }

        value->actual_len = byte_len;
        return byte_len;
    }
}

int pka_add(pka_handle_t   handle,
            void          *user_data,
            pka_operand_t *value,
            pka_operand_t *addend)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          addend_len;
    uint8_t           big_endian;

    if (!value || !addend)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !addend->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt        = 2;
    operands.operands[0]        = *value;
    operands.operands[1]        = *addend;

    local_info = (pka_local_info_t *) handle;
    big_endian = local_info->gbl_info->rings_byte_order;
    value_len  = pka_process_operand(&operands.operands[0], big_endian);
    addend_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (addend_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < addend_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_ADD, &operands);
}

int pka_subtract(pka_handle_t   handle,
                 void          *user_data,
                 pka_operand_t *value,
                 pka_operand_t *subtrahend)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          subtrahend_len;
    uint8_t           big_endian;

    if (!value || !subtrahend)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !subtrahend->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt        = 2;
    operands.operands[0]        = *value;
    operands.operands[1]        = *subtrahend;

    local_info     = (pka_local_info_t *) handle;
    big_endian     = local_info->gbl_info->rings_byte_order;
    value_len      = pka_process_operand(&operands.operands[0], big_endian);
    subtrahend_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (subtrahend_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < subtrahend_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_SUBTRACT, &operands);
}

int pka_add_subtract(pka_handle_t   handle,
                     void          *user_data,
                     pka_operand_t *value,
                     pka_operand_t *addend,
                     pka_operand_t *subtrahend)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          addend_len;
    uint32_t          subtrahend_len;
    uint8_t           big_endian;

    if (!value || !addend || !subtrahend)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !addend->buf_ptr || !subtrahend->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt        = 3;
    operands.operands[0]        = *value;
    operands.operands[1]        = *addend;
    operands.operands[2]        = *subtrahend;

    local_info     = (pka_local_info_t *) handle;
    big_endian     = local_info->gbl_info->rings_byte_order;
    value_len      = pka_process_operand(&operands.operands[0], big_endian);
    addend_len     = pka_process_operand(&operands.operands[1], big_endian);
    subtrahend_len = pka_process_operand(&operands.operands[2], big_endian);

    if ((value_len == 0) || (addend_len == 0) || (subtrahend_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < addend_len) ||
                (MAX_BYTE_LEN < subtrahend_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_ADD_SUBTRACT, &operands);
}

int pka_multiply(pka_handle_t   handle,
                 void          *user_data,
                 pka_operand_t *value,
                 pka_operand_t *multiplier)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          multiplier_len;
    uint8_t           big_endian;

    if (!value || !multiplier)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !multiplier->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt        = 2;
    operands.operands[0]        = *value;
    operands.operands[1]        = *multiplier;

    local_info     = (pka_local_info_t *) handle;
    big_endian     = local_info->gbl_info->rings_byte_order;
    value_len      = pka_process_operand(&operands.operands[0], big_endian);
    multiplier_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (multiplier_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < multiplier_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_MULTIPLY, &operands);
}

int pka_divide(pka_handle_t   handle,
               void          *user_data,
               pka_operand_t *value,
               pka_operand_t *divisor)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          divisor_len;
    uint8_t           big_endian;

    if (!value || !divisor)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !divisor->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt        = 2;
    operands.operands[0]        = *value;
    operands.operands[1]        = *divisor;

    local_info  = (pka_local_info_t *) handle;
    big_endian  = local_info->gbl_info->rings_byte_order;
    value_len   = pka_process_operand(&operands.operands[0], big_endian);
    divisor_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (divisor_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if (value_len < divisor_len)
        return PKA_OPERAND_LEN_A_LT_LEN_B;

    // *TBD*
    //if ((value_len < 5) || (divisor_len < 5))
    //    return PKA_OPERAND_LEN_TOO_SHORT;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < divisor_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_DIVIDE, &operands);
}

int pka_modulo(pka_handle_t   handle,
               void          *user_data,
               pka_operand_t *value,
               pka_operand_t *modulus)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          modulus_len;
    //uint32_t          value_word_len;
    //uint32_t          modulus_word_len;
    uint8_t           big_endian;

    if ((value == NULL) || (modulus == NULL))
        return PKA_OPERAND_MISSING;

    if ((value->buf_ptr == NULL) || (modulus->buf_ptr == NULL))
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 2;
    operands.operands[0] = *value;
    operands.operands[1] = *modulus;

    local_info  = (pka_local_info_t *) handle;
    big_endian  = local_info->gbl_info->rings_byte_order;
    value_len   = pka_process_operand(&operands.operands[0], big_endian);
    modulus_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (modulus_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    // *TBD*
    //value_word_len   = (value_len   + 3) / 4;
    //modulus_word_len = (modulus_len + 3) / 4;
    //if (value_word_len < modulus_word_len)
    //    return PKA_OPERAND_LEN_A_LT_LEN_B;

    // *TBD*
    //if ((value_len < 5) || (modulus_len < 5))
    //    return PKA_OPERAND_LEN_TOO_SHORT;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < modulus_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    return pka_submit_cmd(handle, user_data, CC_MODULO, &operands);
}

int pka_shift_left(pka_handle_t   handle,
                   void          *user_data,
                   pka_operand_t *value,
                   uint32_t       shift_cnt)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint8_t           big_endian;

    if (!value)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt  = 1;
    operands.shift_amount = shift_cnt;
    operands.operands[0]  = *value;

    local_info = (pka_local_info_t *) handle;
    big_endian = local_info->gbl_info->rings_byte_order;
    value_len  = pka_process_operand(&operands.operands[0], big_endian);

    if (value_len == 0)
        return PKA_OPERAND_LEN_ZERO;

    if (MAX_BYTE_LEN < value_len)
        return PKA_OPERAND_LEN_TOO_LONG;

    // Check that shift_amount is <= 32?

    return pka_submit_cmd(handle, user_data, CC_SHIFT_LEFT, &operands);
}

int pka_shift_right(pka_handle_t   handle,
                    void          *user_data,
                    pka_operand_t *value,
                    uint32_t       shift_cnt)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint8_t           big_endian;

    if (!value)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt  = 1;
    operands.shift_amount = shift_cnt;
    operands.operands[0]  = *value;

    local_info = (pka_local_info_t *) handle;
    big_endian = local_info->gbl_info->rings_byte_order;
    value_len  = pka_process_operand(&operands.operands[0], big_endian);

    if (value_len == 0)
        return PKA_OPERAND_LEN_ZERO;

    if (MAX_BYTE_LEN < value_len)
        return PKA_OPERAND_LEN_TOO_LONG;

    // Check that shift_amount is <= 32?

    return pka_submit_cmd(handle, user_data, CC_SHIFT_RIGHT, &operands);
}

static pka_result_code_t pka_internal_subtract(pka_operand_t *value,
                                               pka_operand_t *subtrahend,
                                               pka_operand_t *result)
{
    uint32_t minuend_byte_len, subtrahend_byte_len, result_byte_len;
    uint32_t borrow, minuend_byte, subtrahend_byte, result_byte;
    uint32_t byte_cnt;
    uint8_t *minuend_ptr, *subtrahend_ptr, *result_ptr;

    minuend_byte_len    = value->actual_len;
    subtrahend_byte_len = subtrahend->actual_len;
    result_byte_len     = minuend_byte_len;
    result->actual_len  = result_byte_len;

    minuend_ptr    = &value->buf_ptr[0];
    subtrahend_ptr = &subtrahend->buf_ptr[0];
    result_ptr     = &result->buf_ptr[0];

    // Subtract subtrahend from minued by proceeding from the least significant
    // bytes to the most significant bytes.
    borrow = 0;
    for (byte_cnt = 0; byte_cnt < minuend_byte_len; byte_cnt++)
    {
        minuend_byte = *minuend_ptr;
        if (byte_cnt < subtrahend_byte_len)
            subtrahend_byte = (*subtrahend_ptr) + borrow;
        else
            subtrahend_byte = borrow;

        if (subtrahend_byte <= minuend_byte)
        {
            result_byte = minuend_byte - subtrahend_byte;
            borrow    = 0;
        }
        else
        {
            result_byte = (256 + minuend_byte) - subtrahend_byte;
            borrow    = 1;
        }

        *result_ptr = result_byte;
        minuend_ptr++;
        subtrahend_ptr++;
        result_ptr++;
    }

    // Finally adjust the actual length by skipping any leading zeros.
    result_byte_len = result->actual_len;
    result_ptr      = &result->buf_ptr[result_byte_len - 1];
    while ((*result_ptr == 0) && (1 <= result_byte_len))
    {
        result_ptr--;
        result_byte_len--;
    }

    result->actual_len = result_byte_len;
    return RC_NO_ERROR;
}

static pka_comparison_t pka_internal_compare(uint8_t *value_buf_ptr,
                                             uint8_t *comparend_buf_ptr,
                                             uint32_t operand_len,
                                             uint8_t  is_big_endian)
{
    uint32_t idx, value_len, comparend_len;

    if (is_big_endian)
    {
        // Start the comparison at the most significant end which is at the
        // lowest idx.  But first we need to skip any leading zeros!
        value_len = operand_len;
        while ((value_buf_ptr[0] == 0) && (2 <= value_len))
        {
            value_buf_ptr++;
            value_len--;
        }

        comparend_len = operand_len;
        while ((comparend_buf_ptr[0] == 0) && (2 <= comparend_len))
        {
            comparend_buf_ptr++;
            comparend_len--;
        }

        if (value_len < comparend_len)
            return PKA_LESS_THAN;
        else if (comparend_len < value_len)
            return PKA_GREATER_THAN;

        operand_len = value_len;
        for (idx = 1;  idx <= operand_len;  idx++)
        {
            if (value_buf_ptr[0] < comparend_buf_ptr[0])
                return PKA_LESS_THAN;
            else if (value_buf_ptr[0] > comparend_buf_ptr[0])
                return PKA_GREATER_THAN;

            value_buf_ptr++;
            comparend_buf_ptr++;
        }
    }
    else
    {
        // Start the comparison at the most significant end which is at the
        // highest idx.  But first we need to skip any leading zeros!
        value_buf_ptr = &value_buf_ptr[operand_len - 1];
        value_len     = operand_len;
        while ((value_buf_ptr[0] == 0) && (2 <= value_len))
        {
            value_buf_ptr--;
            value_len--;
        }

        comparend_buf_ptr = &comparend_buf_ptr[operand_len - 1];
        comparend_len     = operand_len;
        while ((comparend_buf_ptr[0] == 0) && (2 <= comparend_len))
        {
            comparend_buf_ptr--;
            comparend_len--;
        }

        if (value_len < comparend_len)
            return PKA_LESS_THAN;
        else if (comparend_len < value_len)
            return PKA_GREATER_THAN;

        operand_len = value_len;
        for (idx = 1;  idx <= operand_len;  idx++)
        {
            if (value_buf_ptr[0] < comparend_buf_ptr[0])
                return PKA_LESS_THAN;
            else if (value_buf_ptr[0] > comparend_buf_ptr[0])
                return PKA_GREATER_THAN;

            value_buf_ptr--;
            comparend_buf_ptr--;
        }
    }

    return PKA_EQUAL;
}

int pka_dh(pka_handle_t   handle,
           void          *user_data,
           pka_operand_t *private_key,
           pka_operand_t *modulus,
           pka_operand_t *value)
{
    return pka_modular_exp(handle, user_data, private_key, modulus, value);
}

int pka_modular_exp(pka_handle_t   handle,
                    void          *user_data,
                    pka_operand_t *exponent,
                    pka_operand_t *modulus,
                    pka_operand_t *value)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          exponent_len;
    uint32_t          modulus_len;
    uint32_t          value_len;
    uint8_t           big_endian;

    if (!exponent || !modulus || !value)
        return PKA_OPERAND_MISSING;

    if (!exponent->buf_ptr || !modulus->buf_ptr || !value->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 3;
    operands.operands[0] = *exponent;
    operands.operands[1] = *modulus;
    operands.operands[2] = *value;

    local_info   = (pka_local_info_t *) handle;
    big_endian   = local_info->gbl_info->rings_byte_order;
    exponent_len = pka_process_operand(&operands.operands[0], big_endian);
    modulus_len  = pka_process_operand(&operands.operands[1], big_endian);
    value_len    = pka_process_operand(&operands.operands[2], big_endian);

    if ((exponent_len == 0) || (modulus_len == 0) || (value_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < exponent_len) || (MAX_BYTE_LEN < modulus_len) ||
        (MAX_BYTE_LEN < value_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    // *TBD*
    //if (modulus_len < 5)
    //    return PKA_OPERAND_LEN_TOO_SHORT;

    // Make sure that value (aka msg) < modulus.
    if (modulus_len < value_len)
        return PKA_OPERAND_VAL_GE_MODULUS;
    else if (modulus_len == value_len)
    {
        if (pka_internal_compare(operands.operands[2].buf_ptr,
                             operands.operands[1].buf_ptr, value_len,
                             big_endian) != PKA_LESS_THAN)
            return PKA_OPERAND_VAL_GE_MODULUS;
    }

    // Check for odd modulus
    if (big_endian)
    {
        if ((operands.operands[1].buf_ptr[modulus_len - 1] & 0x01) == 0)
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }
    else
    {
        if ((operands.operands[1].buf_ptr[0] & 0x01) == 0)
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }

    return pka_submit_cmd(handle, user_data, CC_MODULAR_EXP, &operands);
}

int pka_modular_exp_crt(pka_handle_t   handle,
                        void          *user_data,
                        pka_operand_t *value,
                        pka_operand_t *p,
                        pka_operand_t *q,
                        pka_operand_t *d_p,
                        pka_operand_t *d_q,
                        pka_operand_t *qinv)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len;
    uint32_t          p_len, q_len, d_p_len, d_q_len, qinv_len;
    uint8_t           big_endian;

    if (!value || !p || !q || !d_p || !d_q || !qinv)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !p->buf_ptr || !q->buf_ptr || !d_p->buf_ptr ||
            !d_q->buf_ptr || !qinv->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 6;
    operands.operands[0] = *p;
    operands.operands[1] = *q;
    operands.operands[2] = *value;
    operands.operands[3] = *d_p;
    operands.operands[4] = *d_q;
    operands.operands[5] = *qinv;

    local_info = (pka_local_info_t *) handle;
    big_endian = local_info->gbl_info->rings_byte_order;
    p_len      = pka_process_operand(&operands.operands[0], big_endian);
    q_len      = pka_process_operand(&operands.operands[1], big_endian);
    value_len  = pka_process_operand(&operands.operands[2], big_endian);
    d_p_len    = pka_process_operand(&operands.operands[3], big_endian);
    d_q_len    = pka_process_operand(&operands.operands[4], big_endian);
    qinv_len   = pka_process_operand(&operands.operands[5], big_endian);

    if ((p_len == 0) || (q_len == 0) || (value_len == 0) || (d_p_len == 0) ||
            (d_q_len == 0) || (qinv_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((OTHER_MAX_BYTE_LEN < p_len) || (OTHER_MAX_BYTE_LEN < q_len) ||
            (MAX_BYTE_LEN < value_len) || (OTHER_MAX_BYTE_LEN < d_p_len) ||
            (OTHER_MAX_BYTE_LEN < d_q_len) || (OTHER_MAX_BYTE_LEN < qinv_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    // *TBD*
    // Check that p_len and q_len > 32 bits
    //if ((p_len < 5) || (q_len < 5))
    //    return PKA_OPERAND_LEN_TOO_SHORT;

    // *TBD*
    // Check that q < p (i.e. operands.operands[1] < operands.operands[0])
    //comparison = pka_compare(&operands.operands[1], &operands.operands[0]);
    //if (comparison != PKA_LESS_THAN)
    //    return PKA_OPERAND_Q_GE_OPERAND_P;

    // Check that c_len <= p_len + q_len? Probably not worth it, so don't
    // bother for now.

    // We could also check that d_p < p, d_q < q and qinv < p, but it is
    // probably not worth it, so don't bother for now.

    // Check for odd modulus (i.e. p and q must be odd, but in common usage
    // p and q will usually be a large prime number and hence odd).
    if (big_endian)
    {
        if (((operands.operands[0].buf_ptr[p_len - 1] & 0x01) == 0) ||
            ((operands.operands[1].buf_ptr[q_len - 1] & 0x01) == 0))
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }
    else
    {
        if (((operands.operands[0].buf_ptr[0] & 0x01) == 0) ||
            ((operands.operands[1].buf_ptr[0] & 0x01) == 0))
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }

    return pka_submit_cmd(handle, user_data, CC_MOD_EXP_CRT, &operands);
}

int pka_rsa(pka_handle_t   handle,
            void          *user_data,
            pka_operand_t *exponent,
            pka_operand_t *modulus,
            pka_operand_t *value)
{
    return pka_modular_exp(handle, user_data, exponent, modulus, value);
}

int pka_rsa_crt(pka_handle_t   handle,
                void          *user_data,
                pka_operand_t *p,
                pka_operand_t *q,
                pka_operand_t *c,
                pka_operand_t *d_p,
                pka_operand_t *d_q,
                pka_operand_t *qinv)
{
    return pka_modular_exp_crt(handle, user_data, c, p, q, d_p, d_q, qinv);
}

int pka_modular_inverse(pka_handle_t   handle,
                        void          *user_data,
                        pka_operand_t *value,
                        pka_operand_t *modulus)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          value_len, modulus_len;
    uint8_t           big_endian;

    if (!value || !modulus)
        return PKA_OPERAND_MISSING;

    if (!value->buf_ptr || !modulus->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 2;
    operands.operands[0] = *value;
    operands.operands[1] = *modulus;

    local_info  = (pka_local_info_t *) handle;
    big_endian  = local_info->gbl_info->rings_byte_order;
    value_len   = pka_process_operand(&operands.operands[0], big_endian);
    modulus_len = pka_process_operand(&operands.operands[1], big_endian);

    if ((value_len == 0) || (modulus_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    if ((MAX_BYTE_LEN < value_len) || (MAX_BYTE_LEN < modulus_len))
        return PKA_OPERAND_LEN_TOO_LONG;

    // Check for odd modulus.
    if (big_endian)
    {
        if ((operands.operands[1].buf_ptr[modulus_len - 1] & 0x01) == 0)
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }
    else
    {
        if ((operands.operands[1].buf_ptr[0] & 0x01) == 0)
            return PKA_OPERAND_MODULUS_IS_EVEN;
    }

    return pka_submit_cmd(handle, user_data, CC_MODULAR_INVERT, &operands);
}

/// This function, returns 1 if the given value is less than or equal to
/// the curve prime.  Specifically will return 0 for curve25519 iff the value
/// is between 2^255 - 19 and 2^255 - 1.  For curve448, it will return 0 iff
/// the value is between 2^448 - 2^224 - 1 and 2^448 - 1.  Note that it is
/// exceedingly rare for this function to return 0 on random inputs.
static int pka_is_mont_ecdh_canonical(ecc_mont_curve_t* curve,
                                      pka_operand_t*    point_x)
{
    pka_comparison_t rc;
    uint32_t         idx;
    uint8_t          big_endian, ls_byte, ms_byte;

    big_endian = point_x->big_endian;
    if (curve->type == PKA_CURVE_25519)
    {
        if (point_x->actual_len != 32)
            return 1;

        // We want to see if point_x (with a special adjustment of the
        // most significant byte) is < the curve prime.
        // First do a quick test
        ls_byte = point_x->buf_ptr[big_endian ? 31 : 0];
        if (ls_byte < 0xED) // 237 = 256 - 19
            return 1;

        // Loop over the bytes from least significant to most significant
        // looking for a byte != 0xFF.  The most signifcant byte is special.
        if (big_endian)
        {
            for (idx = 1; idx <= 30; idx++)
                if (point_x->buf_ptr[31 - idx] != 0xFF)
                    return 1;

            ms_byte = point_x->buf_ptr[0];
        }
        else
        {
            for (idx = 1; idx <= 30; idx++)
                if (point_x->buf_ptr[idx] != 0xFF)
                    return 1;

            ms_byte = point_x->buf_ptr[31];
        }

        ms_byte &= 0x7F;
        return ms_byte != 0x7F;
    }
    else if (curve->type == PKA_CURVE_448)
    {
        if (point_x->actual_len != 56)
            return 1;

        // Quick test *TBD*
        ms_byte = point_x->buf_ptr[big_endian ? 0 : 55];
        if (ms_byte != 0xFF)
            return 1;

        rc = pka_internal_compare(point_x->buf_ptr, curve->p.buf_ptr, 56,
                                  big_endian);
        if (rc == PKA_LESS_THAN)
            return 1;

        return 0;
    }
    else
        return 1;
}

/// This function will first check if the value is already canonical (by
/// calling pka_is_mont_ecdh_canonical), and if it is not canonical, it will
/// do a modular reduction of value by the curve prime.
static int pka_mont_ecdh_canonicalize(pka_handle_t      handle,
                                      ecc_mont_curve_t* curve,
                                      pka_operand_t*    point_x,
                                      pka_operand_t*    reduced_value)
{
    pka_result_code_t rc;
    pka_operand_t     temp;
    uint8_t           temp_buf[MAX_ECC_BUF];
    int               is_canonical;

    is_canonical = pka_is_mont_ecdh_canonical(curve, point_x);
    if (is_canonical)
        return -1;

    // Make a local copy of point_x first
    memcpy(&temp, point_x, sizeof(temp));
    temp.buf_ptr = &temp_buf[0];
    memcpy(temp.buf_ptr, point_x->buf_ptr, point_x->actual_len);
    if (curve->type == PKA_CURVE_25519)
        temp.buf_ptr[31] &= 0x7F;

    rc = pka_internal_subtract(&temp, &curve->p, reduced_value);
    if (rc == RC_NO_ERROR)
        return 0;
    else
        return -1;
}

int pka_mont_ecdh_mult(pka_handle_t      handle,
                       void*             user_data,
                       ecc_mont_curve_t* curve,
                       pka_operand_t*    point_x,
                       pka_operand_t*    multiplier)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    pka_operand_t     reduced_point_x;
    uint32_t          point_x_len, p_len, A_len, k_len;
    uint8_t           reduced_point_buf[MAX_ECC_BUF];
    uint8_t           big_endian;
    int               rc, is_canonical;

    if (!curve || !point_x || !multiplier)
        return PKA_OPERAND_MISSING;

    if (!curve->p.buf_ptr  || !curve->A.buf_ptr || !multiplier->buf_ptr ||
          !point_x->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    if ((curve->type != PKA_CURVE_25519) && (curve->type != PKA_CURVE_448))
        return PKA_CURVE_TYPE_INVALID;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 4;
    operands.operands[0] = *multiplier;
    operands.operands[1] = *point_x;
    operands.operands[2] = curve->p;
    operands.operands[3] = curve->A;

    local_info  = (pka_local_info_t *) handle;
    big_endian  = local_info->gbl_info->rings_byte_order;
    k_len       = pka_process_operand(&operands.operands[0], big_endian);
    point_x_len = pka_process_operand(&operands.operands[1], big_endian);
    p_len       = pka_process_operand(&operands.operands[2], big_endian);
    A_len       = pka_process_operand(&operands.operands[3], big_endian);

    if ((point_x_len == 0) || (p_len == 0) ||
          (A_len       == 0) || (k_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    is_canonical = pka_is_mont_ecdh_canonical(curve, point_x);
    if (!is_canonical)
    {
        memset(&reduced_point_x,      0, sizeof(pka_operand_t));
        memset(&reduced_point_buf[0], 0, MAX_ECC_BUF);
        reduced_point_x.buf_len      = MAX_ECC_BUF;
        reduced_point_x.actual_len   = 0;
        reduced_point_x.is_encrypted = 0;
        reduced_point_x.big_endian   = 0;
        reduced_point_x.buf_ptr      = &reduced_point_buf[0];

        rc = pka_mont_ecdh_canonicalize(handle, curve, point_x,
                                        &reduced_point_x);
        if (rc == 0)
            operands.operands[1] = reduced_point_x;
    }

    // We could check that point is "on" the given curve, but that is deemed
    // too expensive for now.

    return pka_submit_cmd(handle, user_data, CC_MONT_ECDH_MULTIPLY,
                          &operands);
}

int pka_ecc_pt_add(pka_handle_t   handle,
                   void          *user_data,
                   ecc_curve_t   *curve,
                   ecc_point_t   *pointA,
                   ecc_point_t   *pointB)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          pointA_x_len, pointA_y_len, pointB_x_len, pointB_y_len;
    uint32_t          p_len, a_len, b_len;
    uint8_t           big_endian;

    if (!curve || !pointA || !pointB)
        return PKA_OPERAND_MISSING;

    if (!curve->p.buf_ptr || !curve->a.buf_ptr || !curve->b.buf_ptr ||
           !pointA->x.buf_ptr || !pointA->y.buf_ptr || !pointB->x.buf_ptr ||
           !pointB->y.buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 7;
    operands.operands[0] = pointA->x;
    operands.operands[1] = pointA->y;
    operands.operands[2] = pointB->x;
    operands.operands[3] = pointB->y;
    operands.operands[4] = curve->p;
    operands.operands[5] = curve->a;
    operands.operands[6] = curve->b;

    local_info   = (pka_local_info_t *) handle;
    big_endian   = local_info->gbl_info->rings_byte_order;
    pointA_x_len = pka_process_operand(&operands.operands[0], big_endian);
    pointA_y_len = pka_process_operand(&operands.operands[1], big_endian);
    pointB_x_len = pka_process_operand(&operands.operands[2], big_endian);
    pointB_y_len = pka_process_operand(&operands.operands[3], big_endian);
    p_len        = pka_process_operand(&operands.operands[4], big_endian);
    a_len        = pka_process_operand(&operands.operands[5], big_endian);
    b_len        = pka_process_operand(&operands.operands[6], big_endian);

    if ((pointA_x_len == 0) || (pointA_y_len == 0) ||
        (pointB_x_len == 0) || (pointB_y_len == 0) ||
        (p_len        == 0) || (a_len        == 0) ||
        (b_len        == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that pointA and pointB are "on" the given curve, but
    // that is deemed too expensive for now.

    return pka_submit_cmd(handle, user_data, CC_ECC_PT_ADD, &operands);
}

int pka_ecc_pt_mult(pka_handle_t   handle,
                    void          *user_data,
                    ecc_curve_t   *curve,
                    ecc_point_t   *pointA,
                    pka_operand_t *multiplier)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          pointA_x_len, pointA_y_len, p_len, a_len, b_len, k_len;
    uint8_t           big_endian;

    if (!curve || !pointA || !multiplier)
        return PKA_OPERAND_MISSING;

    if (!curve->p.buf_ptr  || !curve->a.buf_ptr    ||
        !curve->b.buf_ptr  || !multiplier->buf_ptr ||
        !pointA->x.buf_ptr || !pointA->y.buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 6;
    operands.operands[0] = *multiplier;
    operands.operands[1] = pointA->x;
    operands.operands[2] = pointA->y;
    operands.operands[3] = curve->p;
    operands.operands[4] = curve->a;
    operands.operands[5] = curve->b;

    local_info   = (pka_local_info_t *) handle;
    big_endian   = local_info->gbl_info->rings_byte_order;
    k_len        = pka_process_operand(&operands.operands[0], big_endian);
    pointA_x_len = pka_process_operand(&operands.operands[1], big_endian);
    pointA_y_len = pka_process_operand(&operands.operands[2], big_endian);
    p_len        = pka_process_operand(&operands.operands[3], big_endian);
    a_len        = pka_process_operand(&operands.operands[4], big_endian);
    b_len        = pka_process_operand(&operands.operands[5], big_endian);

    if ((pointA_x_len == 0) || (pointA_y_len == 0) ||
        (p_len        == 0) || (a_len        == 0) ||
        (b_len        == 0) || (k_len        == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that pointA is "on" the given curve, but that is deemed
    // too expensive for now.

    return pka_submit_cmd(handle, user_data, CC_ECC_PT_MULTIPLY, &operands);
}

int pka_mont_ecdh(pka_handle_t      handle,
                  void*             user_data,
                  ecc_mont_curve_t* curve,
                  pka_operand_t*    point_x,
                  pka_operand_t*    private_key)
{
    return pka_mont_ecdh_mult(handle, user_data, curve, point_x, private_key);
}

int pka_ecdh(pka_handle_t   handle,
             void*          user_data,
             ecc_curve_t   *curve,
             ecc_point_t   *point,
             pka_operand_t *private_key)
{
    return pka_ecc_pt_mult(handle, user_data, curve, point, private_key);
}

int pka_ecdsa_signature_generate(pka_handle_t   handle,
                                 void          *user_data,
                                 ecc_curve_t   *curve,
                                 ecc_point_t   *base_pt,
                                 pka_operand_t *base_pt_order,
                                 pka_operand_t *private_key,
                                 pka_operand_t *hash,
                                 pka_operand_t *k)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          base_point_x_len, base_point_y_len, k_len, alpha_len;
    uint32_t          h_len, p_len, a_len, b_len, n_len;
    uint8_t        big_endian;

    if (!curve || !base_pt || !base_pt_order || !private_key || !hash || !k)
        return PKA_OPERAND_MISSING;

    if (!curve->p.buf_ptr     || !curve->a.buf_ptr       ||
        !curve->b.buf_ptr     || !base_pt_order->buf_ptr ||
        !base_pt->x.buf_ptr   || !base_pt->y.buf_ptr     ||
        !private_key->buf_ptr || !hash->buf_ptr          ||
        !k->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 9;
    operands.operands[0] = base_pt->x;
    operands.operands[1] = base_pt->y;
    operands.operands[2] = *k;
    operands.operands[3] = *private_key;
    operands.operands[4] = *hash;
    operands.operands[5] = curve->p;
    operands.operands[6] = curve->a;
    operands.operands[7] = curve->b;
    operands.operands[8] = *base_pt_order;

    local_info       = (pka_local_info_t *) handle;
    big_endian       = local_info->gbl_info->rings_byte_order;
    base_point_x_len = pka_process_operand(&operands.operands[0], big_endian);
    base_point_y_len = pka_process_operand(&operands.operands[1], big_endian);
    k_len            = pka_process_operand(&operands.operands[2], big_endian);
    alpha_len        = pka_process_operand(&operands.operands[3], big_endian);
    h_len            = pka_process_operand(&operands.operands[4], big_endian);
    p_len            = pka_process_operand(&operands.operands[5], big_endian);
    a_len            = pka_process_operand(&operands.operands[6], big_endian);
    b_len            = pka_process_operand(&operands.operands[7], big_endian);
    n_len            = pka_process_operand(&operands.operands[8], big_endian);

    if ((base_point_x_len == 0) || (base_point_y_len == 0) ||
        (k_len            == 0) || (alpha_len        == 0) ||
        (h_len            == 0) || (p_len            == 0) ||
        (a_len            == 0) || (b_len            == 0) ||
        (n_len            == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that base_point_x < p, base_point_y < p, a < p, b < p,
    // base_pt_order < p, k < base_pt_order, and hash < base_pt_order, but
    // these are all too expensive for now.

    return pka_submit_cmd(handle, user_data, CC_ECDSA_GENERATE, &operands);
}

int pka_ecdsa_signature_verify(pka_handle_t     handle,
                               void            *user_data,
                               ecc_curve_t     *curve,
                               ecc_point_t     *base_pt,
                               pka_operand_t   *base_pt_order,
                               ecc_point_t     *public_key,
                               pka_operand_t   *hash,
                               dsa_signature_t *rcvd_signature,
                               uint8_t          no_write)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          base_point_x_len, base_point_y_len;
    uint32_t          public_point_x_len, public_point_y_len, h_len, p_len;
    uint32_t          a_len, b_len, n_len, r_len, s_len;
    uint8_t           big_endian;

    if (!curve      || !base_pt || !base_pt_order ||
        !public_key || !hash    || !rcvd_signature)
        return PKA_OPERAND_MISSING;

    if (!curve->p.buf_ptr           || !curve->a.buf_ptr            ||
        !curve->b.buf_ptr           || !base_pt_order->buf_ptr      ||
        !base_pt->x.buf_ptr         || !base_pt->y.buf_ptr          ||
        !public_key->x.buf_ptr      || !public_key->y.buf_ptr       ||
        !rcvd_signature->r.buf_ptr  || !rcvd_signature->s.buf_ptr   ||
        !hash->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt  = 11;
    operands.operands[0]  = base_pt->x;
    operands.operands[1]  = base_pt->y;
    operands.operands[2]  = public_key->x;
    operands.operands[3]  = public_key->y;
    operands.operands[4]  = *hash;
    operands.operands[5]  = curve->p;
    operands.operands[6]  = curve->a;
    operands.operands[7]  = curve->b;
    operands.operands[8]  = *base_pt_order;
    operands.operands[9]  = rcvd_signature->r;
    operands.operands[10] = rcvd_signature->s;

    local_info         = (pka_local_info_t *) handle;
    big_endian         = local_info->gbl_info->rings_byte_order;
    base_point_x_len   = pka_process_operand(&operands.operands[0], big_endian);
    base_point_y_len   = pka_process_operand(&operands.operands[1], big_endian);
    public_point_x_len = pka_process_operand(&operands.operands[2], big_endian);
    public_point_y_len = pka_process_operand(&operands.operands[3], big_endian);
    h_len              = pka_process_operand(&operands.operands[4], big_endian);
    p_len              = pka_process_operand(&operands.operands[5], big_endian);
    a_len              = pka_process_operand(&operands.operands[6], big_endian);
    b_len              = pka_process_operand(&operands.operands[7], big_endian);
    n_len              = pka_process_operand(&operands.operands[8], big_endian);
    r_len              = pka_process_operand(&operands.operands[9], big_endian);
    s_len              = pka_process_operand(&operands.operands[10],big_endian);

    if ((base_point_x_len   == 0) || (base_point_y_len   == 0) ||
        (public_point_x_len == 0) || (public_point_y_len == 0) ||
        (h_len              == 0) || (p_len              == 0) ||
        (a_len              == 0) || (b_len              == 0) ||
        (n_len              == 0) || (r_len              == 0) ||
        (s_len              == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that base_point_x < p, base_point_y < p, a < p, b < p,
    // base_pt_order < p, public_point_x < p, public_point_y < p,
    // hash < base_pt_order, r < base_pt_order and s < base_pt_order but
    // these are all too expensive for now.

    if (no_write)
        return pka_submit_cmd(handle, user_data, CC_ECDSA_VERIFY_NO_WRITE,
                                    &operands);
    else
        return pka_submit_cmd(handle, user_data, CC_ECDSA_VERIFY, &operands);
}

int pka_dsa_signature_generate(pka_handle_t   handle,
                               void          *user_data,
                               pka_operand_t *p,
                               pka_operand_t *q,
                               pka_operand_t *g,
                               pka_operand_t *private_key,
                               pka_operand_t *hash,
                               pka_operand_t *k)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          p_len, g_len, q_len, hash_len, k_len, private_key_len;
    uint8_t           big_endian;

    if (!p || !q || !g || !private_key || !hash || !k)
        return PKA_OPERAND_MISSING;

    if (!p->buf_ptr           || !q->buf_ptr    || !g->buf_ptr ||
        !private_key->buf_ptr || !hash->buf_ptr || !k->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 6;
    operands.operands[0] = *p;
    operands.operands[1] = *g;
    operands.operands[2] = *q;
    operands.operands[3] = *hash;
    operands.operands[4] = *k;
    operands.operands[5] = *private_key;

    local_info      = (pka_local_info_t *) handle;
    big_endian      = local_info->gbl_info->rings_byte_order;
    p_len           = pka_process_operand(&operands.operands[0], big_endian);
    g_len           = pka_process_operand(&operands.operands[1], big_endian);
    q_len           = pka_process_operand(&operands.operands[2], big_endian);
    hash_len        = pka_process_operand(&operands.operands[3], big_endian);
    k_len           = pka_process_operand(&operands.operands[4], big_endian);
    private_key_len = pka_process_operand(&operands.operands[5], big_endian);

    if ((p_len == 0) || (g_len           == 0) ||
        (q_len == 0) || (hash_len        == 0) ||
        (k_len == 0) || (private_key_len == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that q < p, g < p, k < q, and hash < q, but
    // these are all too expensive for now.

    return pka_submit_cmd(handle, user_data, CC_DSA_GENERATE, &operands);
}

int pka_dsa_signature_verify(pka_handle_t     handle,
                             void            *user_data,
                             pka_operand_t   *p,
                             pka_operand_t   *q,
                             pka_operand_t   *g,
                             pka_operand_t   *public_key,
                             pka_operand_t   *hash,
                             dsa_signature_t *rcvd_signature,
                             uint8_t          no_write)
{
    pka_local_info_t *local_info;
    pka_operands_t    operands;
    uint32_t          p_len, g_len, q_len, hash_len, public_key_len;
    uint32_t          r_len, s_len;
    uint8_t           big_endian;

    if (!p || !q || !g || !public_key || !hash || !rcvd_signature)
        return PKA_OPERAND_MISSING;

    if (!p->buf_ptr                || !q->buf_ptr    || !g->buf_ptr ||
        !public_key->buf_ptr       || !rcvd_signature->r.buf_ptr    ||
        !rcvd_signature->s.buf_ptr || !hash->buf_ptr)
        return PKA_OPERAND_BUF_MISSING;

    memset(&operands, 0, sizeof(pka_operands_t));
    operands.operand_cnt = 7;
    operands.operands[0] = *p;
    operands.operands[1] = *g;
    operands.operands[2] = *q;
    operands.operands[3] = *hash;
    operands.operands[4] = *public_key;
    operands.operands[5] = rcvd_signature->r;
    operands.operands[6] = rcvd_signature->s;

    local_info     = (pka_local_info_t *) handle;
    big_endian     = local_info->gbl_info->rings_byte_order;
    p_len          = pka_process_operand(&operands.operands[0], big_endian);
    g_len          = pka_process_operand(&operands.operands[1], big_endian);
    q_len          = pka_process_operand(&operands.operands[2], big_endian);
    hash_len       = pka_process_operand(&operands.operands[3], big_endian);
    public_key_len = pka_process_operand(&operands.operands[4], big_endian);
    r_len          = pka_process_operand(&operands.operands[5], big_endian);
    s_len          = pka_process_operand(&operands.operands[6], big_endian);

    if ((p_len          == 0) || (g_len    == 0) ||
        (q_len          == 0) || (hash_len == 0) ||
        (public_key_len == 0) || (r_len    == 0) ||
        (s_len          == 0))
        return PKA_OPERAND_LEN_ZERO;

    // We could check that q < p, g < p, public_key < p, hash < q, r < q, and
    // s < q but these are all too expensive for now.

    if (no_write)
        return pka_submit_cmd(handle, user_data, CC_DSA_VERIFY_NO_WRITE,
                                    &operands);
    else
        return pka_submit_cmd(handle, user_data, CC_DSA_VERIFY, &operands);
}

int pka_get_rand_bytes(pka_handle_t  handle,
                       uint8_t      *buf,
                       uint32_t      buf_len)
{
    pka_global_info_t   *gbl_info;
    pka_local_info_t    *local_info;
    pka_ring_info_t     *ring_info;
    pka_dev_trng_info_t  trng_info;
    uint8_t              ring_idx;
    int                  ret;

    if (handle == NULL || buf == NULL || buf_len <= 0)
	return 0;

    local_info      = (pka_local_info_t *)handle;
    gbl_info        = local_info->gbl_info;
    trng_info.data  = buf;
    trng_info.count = buf_len;

    for (ring_idx = 0; ring_idx < gbl_info->rings_cnt; ring_idx++)
    {
        ring_info = &gbl_info->rings[ring_idx];

        if (!ring_info)
            continue;

        ret = ioctl(ring_info->fd, PKA_GET_RANDOM_BYTES, &trng_info);
        if (!ret)
            return buf_len;

        PKA_ERROR(PKA_USER, "Error(%d) getting random number.\n", ret);
    }

    return 0;
}
