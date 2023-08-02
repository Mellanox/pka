// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_QUEUE_H__
#define __PKA_QUEUE_H__

///
/// @file
///
/// API to manage software queues. It consists of an implementation of circular
/// queues on top of command/result descriptor rings. It allows multiple threads
/// to submit PK commands to the hardware without causing ring congestion.
/// Software-based queues are assigned to clients which may run over single or
/// multiple threads, a pair of queue per thread: one queue to append command
/// descriptors and an other one to append result descriptors. Each group of
/// queues is associated to a one or group of rings depending on client context.
/// The implementation of the software-based queues help to leverage the small
/// size of descriptor rings and avoid interrupts, so far (processes have to
/// wait until a given ring can accept new descriptors again).
/// Queues have the following properties :
///      - FIFO,
///      - Capacity is fixed,
///      - Lockless implementation,
/// However, having many circular queues with significant size may costs in
/// terms of memory (more than linked list queue).  An empty queue contains
/// at least N pointers.
///
/// Note that the current API implements an Enq/Deq a fixed number of items
/// from a queue and does not support multi producer/consumer.
///
/// Also note that the implementation includes a mechanism which exert a back
/// pressure to inform a given client to pause. It defines a threshold, once
/// an enqueue reaches the high threshold, the client is notified.
///

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include "pka_utils.h"
#include "pka_ring.h"

/// PK queue result descriptor structure. This structure characterize an
/// item in PK SW queue.  One can enqueue/dequeue descriptors similar to
/// those associated with HW rings (64 bytes item).  The purpose here is
/// to decrease the overhead added due to SW queue during  PK operations
/// processing. This structure holds the minimal information required to
/// retrieve a PK result.   It also aims to increase the number of items
/// -i.e. results in the result queue.
typedef struct // 32 bytes
{
    uint32_t  size;            // total size the result descriptor. This
                               // field is common to both result and cmd
                               // descriptors and MUST remain in the top
                               // 32 bits of the two structure since it
                               // is used for enqueuing and dequeuing objs
                               // to/from the queue.

    uint32_t  cmd_num;         // command request number.
    uint32_t  result1_len;     // length of the first result.
    uint32_t  result2_len;     // length of the second result.

    uint64_t  user_data;       // opaque user data information address.
    uint32_t  opcode;          // PK operation code
    uint8_t   result_cnt;      // might be 0, 1 or 2
    uint8_t   status;          // the raw result_code.
    uint8_t   compare_result;  // the raw compare_result.
    uint8_t   queue_num;       // queue number
} pka_queue_rslt_desc_t __pka_aligned(8);

#define QUEUE_RSLT_DESC_SIZE  sizeof(pka_queue_rslt_desc_t)


/// PK queue command descriptor structure.   This structure characterize
/// an item in PK SW command queue. One can enqueue/dequeue the HW rings
/// descriptors (64 bytes item). The purpose here is to have a structure
/// which holds the minimal information required  to process PK commands
/// and decrease the overhead added due to SW queue.  Note that it tends
/// to increase the number of items -i.e. results in the result queue.
typedef struct // 40 bytes.
{
    uint16_t  size;           // total size the command descriptor. This
                              // field is common to both result and cmd
                              // descriptors and MUST remain in the top
                              // 32 bits of the two structure since it
                              // is used for enqueuing and dequeuing objs
                              // to/from the queue.

    uint8_t   operand_cnt;    // number of operands.
    uint8_t   shift_cnt;      // shift value used by the PK command.

    uint64_t  user_data;      // opaque user data information address.
    uint32_t  opcode;         // code of the requested PK command.
    uint32_t  operands_len;   // aligned and padded data vectors size. It
                              // refers to size of both command and result
                              // operands.

    uint32_t  cmd_num;        // command request number.

} pka_queue_cmd_desc_t __pka_aligned(8);

#define QUEUE_CMD_DESC_SIZE  sizeof(pka_queue_cmd_desc_t)

#ifdef PKA_LIB_QUEUE_DEBUG
// A structure that stores the queue statistics.
struct pka_queue_debug_stats {
    uint64_t enq_success_objs; ///< Objects successfully enqueued.
    uint64_t enq_fail_objs;    ///< Objects that failed to be enqueued.
    uint64_t deq_success_objs; ///< Objects successfully dequeued.
    uint64_t deq_fail_objs;    ///< Objects that failed to be dequeued.
} __pka_cache_aligned;
#endif

/* structure to hold a pair of head/tail values */
typedef struct {
    volatile uint32_t head;  /**< Prod/consumer head. */
    volatile uint32_t tail;  /**< Prod/consumer tail. */
} pka_queue_headtail_t;

typedef struct
{
    uint32_t flags;            ///< Flags supplied at creation.
    uint32_t size;             ///< Size of the queue.
    uint32_t mask;             ///< Mask (size-1) of queue.
    uint32_t capacity;         ///< Usable size of queue.

    uint8_t  pad0 __pka_cache_aligned; ///< empty cache line.

    // Queue producer status.
    pka_queue_headtail_t prod __pka_cache_aligned;
    uint8_t  pad1 __pka_cache_aligned; ///< empty cache line.

    // Queue consumer status.
    pka_queue_headtail_t cons __pka_cache_aligned;
    uint8_t  pad2 __pka_cache_aligned; ///< empty cache line.

#ifdef PKA_LIB_QUEUE_DEBUG
    struct pka_queue_debug_stats stats;
#endif

    uint8_t mem[0] __pka_cache_aligned; ///< Memory space of queue starts here.
                                        /// not volatile so need to be careful
                                        /// about compiler re-ordering.
} pka_queue_t;

#define PKA_QUEUE_DESC_MAX_SIZE      (1 << 12) // 4K bytes.

#define PKA_QUEUE_TYPE_CMD  0x1 ///< the default type is command queue.
#define PKA_QUEUE_TYPE_RSLT 0x2 ///< The default type is result queue.

#define PKA_QUEUE_MASK_SIZE  (unsigned)(0x007fffff)  ///< Queue mask size (8MB)

#ifdef PKA_LIB_QUEUE_DEBUG
#define __QUEUE_STAT_ADD(q, name, n) ({ ##q##->stats.##name##_objs += n; })
#else
#define __QUEUE_STAT_ADD(q, name, n) do {} while(0)
#endif


/// Calculate the memory size needed for a queue. This function returns the
/// number of bytes needed for a queue, given the number of elements in it.
/// This value is the sum of the size of the structure pka_queue_t and the
/// size of the memory needed by the items. The value is aligned to a cache
/// line size.
ssize_t pka_queue_get_memsize(uint32_t size);

/// Create a new queue in memory then initialize a queue structure in memory
/// pointed by "queue".  The size of the memory area must be large enough to
/// store the queue header and data.
/// It is advised to use "pka_queue_get_memsize()" to get the appropriate size.
/// The queue size must be a power of two. Water marking is disabled by default.
/// The real usable queue size is 'size-1' instead of 'size' to differentiate a
/// free queue from an empty queue.
///
/// Indeed, current implementation supposes that the memory given by the caller
/// is shareable among PKA applications.
pka_queue_t *pka_queue_create(ssize_t size, uint32_t flags, void *mem);

/// Free the given queue.
void pka_queue_free(pka_queue_t **queue);

/// Change the high water mark. If 'count' is 0, water marking is disabled.
/// Otherwise, it is set to the 'count' value. The 'count' value must be
/// greater than 0 and less than the ring size. This function can be called
/// at any time (not necessarily at initialization).
int pka_queue_set_water_mark(pka_queue_t *queue, uint32_t size);

/// Enqueue a command on the queue (copy command from user context -> queue).
int pka_queue_cmd_enqueue(pka_queue_t          *queue,
                          pka_queue_cmd_desc_t *cmd_desc,
                          pka_operands_t       *operands);

/// Enqueue a result on the queue (copy result from ring -> queue).
int pka_queue_rslt_enqueue(pka_queue_t             *queue,
                           pka_ring_info_t         *ring,
                           pka_ring_hw_rslt_desc_t *ring_desc,
                           pka_queue_rslt_desc_t   *rslt_desc);

/// Dequeue a command from a queue (copy cmd from queue -> ring).
int pka_queue_cmd_dequeue(pka_queue_t            *queue,
                          pka_ring_hw_cmd_desc_t *ring_desc,
                          pka_ring_alloc_t       *alloc);

/// Dequeue a result from a queue (copy result from queue -> user context).
int pka_queue_rslt_dequeue(pka_queue_t            *queue,
                           pka_queue_rslt_desc_t  *rslt_desc,
                           pka_results_t          *results);

/// Set queue command descriptor.
int pka_queue_set_cmd_desc(pka_queue_cmd_desc_t *cmd_desc,
                           uint32_t              cmd_num,
                           void                 *user_data,
                           pka_opcode_t          opcode,
                           pka_operands_t       *operands);

/// Set queue result descriptor.
int pka_queue_set_rslt_desc(pka_queue_rslt_desc_t   *rslt_desc,
                            pka_ring_hw_rslt_desc_t *ring_desc,
                            uint32_t                 cmd_num,
                            uint64_t                 user_data,
                            uint8_t                  queue_num);

/// Load a command descriptor from a queue.
int pka_queue_load_cmd_desc(pka_queue_cmd_desc_t *cmd_desc, pka_queue_t *queue);

/// Return the number of entries in a queue (in bytes).
static inline uint32_t pka_queue_count(pka_queue_t *queue)
{
    uint32_t prod_tail = queue->prod.tail;
    uint32_t cons_tail = queue->cons.tail;
    uint32_t count = (prod_tail - cons_tail) & queue->mask;
    return (count > queue->capacity) ? queue->capacity : count;
}

/// Return the number of free entries in a queue (in bytes).
static inline uint32_t pka_queue_free_count(pka_queue_t *queue)
{
    return queue->capacity - pka_queue_count(queue);
}

/// Test if a ring is full. Returns 1 if a queue is full, 0 if not.
static inline int pka_queue_is_full(pka_queue_t *queue)
{
    return pka_queue_free_count(queue) == 0;
}

/// Test if a ring is empty. Returns 1 if a queue is empty, 0 if not.
static inline int pka_queue_is_empty(pka_queue_t *queue)
{
    return pka_queue_count(queue) == 0;
}

/// dump the status of the queue on the console
void pka_queue_dump(pka_queue_t *queue);

#endif /// __PKA_QUEUE_H__
