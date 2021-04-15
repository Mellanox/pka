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

#include "pka_queue.h"
#include "pka_mem.h"

// Note that the current API implements an Enq/Deq a fixed number of items
// from a queue and does not support multi producer/consumer.

// True if x is a power of 2
#define POWEROF2(x) ((((x)-1) & (x)) == 0)

// Calculate the memory size (in bytes) needed for a queue.
ssize_t pka_queue_get_memsize(uint32_t size)
{
    ssize_t q_size;

    // size must be a power of 2
    if ((!POWEROF2(size)) || (size > PKA_QUEUE_MASK_SIZE ))
    {
        PKA_DEBUG(PKA_QUEUE, "Requested size %u is invalid, must be "
                       "power of 2, and do not exceed the size limit %u\n",
                        size, PKA_QUEUE_MASK_SIZE);
        return -EINVAL;
    }

    q_size = sizeof(pka_queue_t) + size;
    q_size = PKA_ALIGN(q_size, PKA_CACHE_LINE_SIZE);

    return q_size;
}

// Create a new queue in memory.
pka_queue_t *pka_queue_create(ssize_t size, uint32_t flags, void *mem)
{
    pka_queue_t *q;
    uint32_t     q_size;

    // Initialize a queue structure in memory pointed by "queue".
    q = (pka_queue_t *) mem;
    memset(q, 0, sizeof(*q));

    // The current implemetation supports simple producer/consumer.
    // We set then the queue flags to a default value.
    q->flags     = flags;

    // Set queue head and tails.
    q->prod.head = q->cons.head = 0;
    q->prod.tail = q->cons.tail = 0;

    // Set the queue size. Size MUST not include the queue header.
    // Queue watermark is disabled by default.
    q_size       = size - sizeof(pka_queue_t);
    memset(q->mem, 0, q_size);
    q->size      = q_size;
    q->mask      = q_size - 1;
    q->capacity  = q->mask;

    return q;
}

// Free the given queue.
void pka_queue_free(pka_queue_t **queue)
{
    pka_queue_t *queue_ptr;

    if (*queue)
    {
        queue_ptr = *queue;

        memset(queue_ptr->mem, 0, queue_ptr->size);
        queue_ptr = NULL;
    }
}

// Return the length of an operand in words.
static uint8_t pka_operand_wlen(pka_operand_t *operand, uint32_t max_len)
{
    uint32_t byte_len;

    byte_len = operand->actual_len;
    return MIN((byte_len + 3)/4, max_len);
}

static uint16_t pka_concat_wlen(uint8_t  word_len,
                                uint32_t odd_skip,
                                uint32_t even_skip,
                                uint32_t pad_len)
{
    uint32_t skip_len, total_wlen;

    skip_len    = ((word_len & 0x1) == 1) ? odd_skip : even_skip;
    total_wlen  = word_len + skip_len;
    total_wlen += word_len + pad_len;

    return total_wlen;
}

static uint16_t pka_concat3_wlen(uint32_t word_len1,
                                 uint32_t word_len2,
                                 uint32_t word_len3,
                                 uint32_t odd_skip,
                                 uint32_t even_skip)
{
    uint32_t skip_len1, skip_len2, total_wlen;

    skip_len1   = ((word_len1 & 0x1) == 1) ? odd_skip : even_skip;
    skip_len2   = ((word_len2 & 0x1) == 1) ? odd_skip : even_skip;
    total_wlen  =  word_len1 + skip_len1;
    total_wlen +=  word_len2 + skip_len2;
    total_wlen +=  word_len3;
    return total_wlen;
}

static uint16_t pka_concat6_wlen(uint32_t word_len,
                                 uint32_t odd_skip,
                                 uint32_t even_skip)
{
    uint32_t skip_len, total_wlen;

    skip_len    = ((word_len & 0x1) == 1) ? odd_skip : even_skip;
    total_wlen  = 5 * (word_len + skip_len);
    total_wlen += word_len;

    return total_wlen;
}

// Adjusts the value present in the array pointed by buf_ptr.
// Adjustment is done by removing zero padding at the most significant bytes.
// Once this is done, align the new length around 8-byte boundary.
static void pka_rm_rslt_zero_pad(pka_operand_t *result)
{
    uint8_t  *byte_ptr;
    uint32_t  result_len;

    result_len  = result->actual_len;
    byte_ptr    = result->buf_ptr;

    if (result->big_endian)
    {
        byte_ptr = &byte_ptr[0];

        // Move forwards over all zero bytes.
        while ((byte_ptr[0] == 0) && (1 <= result_len))
        {
            byte_ptr++;
            result_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the len, and
        // then move backwards over all zero bytes.
        byte_ptr = &byte_ptr[result_len - 1];
        while ((byte_ptr[0] == 0) && (1 <= result_len))
        {
            byte_ptr--;
            result_len--;
        }
    }

    // Align around 8-byte/64-bit boundary
    result_len         = PKA_ALIGN(result_len, 8);
    result->actual_len = result_len;
}

// Determine total memory needed in the window ram for the command and the
// result operands. The lenght is computed in bytes.
static uint32_t pka_operands_len(pka_opcode_t  opcode,
                                 uint32_t      shift_cnt,
                                 pka_operand_t operands[])
{
    uint32_t lenA, lenB;
    uint32_t operands_wlen, operands_len;

    operands_wlen = 0;

    switch (opcode)
    {
    case CC_ADD:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(MAX(lenA, lenB) + 1, 8);

        break;

    case CC_SUBTRACT:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(MAX(lenA, lenB), 8);

        break;

    case CC_ADD_SUBTRACT:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        operands_wlen += 3 * PKA_ALIGN(lenA, 8);
        operands_wlen += PKA_ALIGN(lenA + 1, 8);

        break;

    case CC_MULTIPLY:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN((lenA + lenB + 6), 8); // ?? +6 words??

        break;

    case CC_DIVIDE:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(lenB + 1, 8) +    // ?? +1 word ??
                                    PKA_ALIGN((lenA - lenB) + 1, 8);

        break;

    case CC_MODULO:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN((lenB + 1), 8);    // ?? +1 word ??

        break;

    case CC_SHIFT_LEFT:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8);
        operands_wlen += (shift_cnt == 0) ?
                    PKA_ALIGN(lenA, 8) : PKA_ALIGN(lenA + 1, 8);

        break;

    case CC_SHIFT_RIGHT:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8);
        operands_wlen += PKA_ALIGN(lenA, 8);

        break;

    case CC_COMPARE:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        operands_wlen += 2 * PKA_ALIGN(lenA, 8);
        operands_wlen += 0;

        break;

    case CC_MODULAR_EXP:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + 2 * PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(lenB + 1, 8);

        break;

    case CC_MOD_EXP_CRT:
        lenA = MAX(pka_operand_wlen(&operands[3], MAX_MODEXP_CRT_VEC_SZ),
                   pka_operand_wlen(&operands[4], MAX_MODEXP_CRT_VEC_SZ));
        lenB = MAX(pka_operand_wlen(&operands[0], MAX_MODEXP_CRT_VEC_SZ),
                   pka_operand_wlen(&operands[1], MAX_MODEXP_CRT_VEC_SZ));

        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenA, 1, 0, 0), 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 1, 2, 1), 8);
        operands_wlen += PKA_ALIGN(lenB, 8) + PKA_ALIGN(2 * lenB, 8);
        operands_wlen += PKA_ALIGN(2 * lenB, 8);

        break;

    case CC_MODULAR_INVERT:
        lenA          = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB          = pka_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(lenB, 8);

        break;

    case CC_MONT_ECDH_MULTIPLY:
        lenA = pka_operand_wlen(&operands[0], MAX_ECC_VEC_SZ);
        lenB = pka_operand_wlen(&operands[2], MAX_ECC_VEC_SZ);

        operands_wlen += PKA_ALIGN(lenA, 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        operands_wlen += PKA_ALIGN(lenB + 3, 8);
        operands_wlen += PKA_ALIGN(lenB, 8);

        break;

    case CC_ECC_PT_ADD:
        lenB = MAX(pka_operand_wlen(&operands[0], MAX_ECC_VEC_SZ),
                   pka_operand_wlen(&operands[2], MAX_ECC_VEC_SZ));

        operands_wlen += 3 * PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        operands_wlen += PKA_ALIGN((2 * lenB) + 3, 8);

        break;

    case CC_ECC_PT_MULTIPLY:
        lenA = pka_operand_wlen(&operands[0], MAX_ECC_VEC_SZ);
        lenB = MAX(pka_operand_wlen(&operands[1], MAX_ECC_VEC_SZ),
                   pka_operand_wlen(&operands[2], MAX_ECC_VEC_SZ));

        operands_wlen += PKA_ALIGN(lenA, 8);
        operands_wlen += PKA_ALIGN(pka_concat3_wlen(lenB, lenB, lenB, 3, 2), 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        operands_wlen += PKA_ALIGN((2 * lenB) + 3, 8);

        break;

    case CC_ECDSA_GENERATE:
        lenB           = pka_operand_wlen(&operands[5], MAX_ECC_VEC_SZ);
        operands_wlen += 3 * PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(pka_concat6_wlen(lenB, 3, 2), 8);
        operands_wlen += PKA_ALIGN((2 * lenB) + 3, 8);

        break;

    case CC_ECDSA_VERIFY_NO_WRITE:
    case CC_ECDSA_VERIFY:
        lenB           = pka_operand_wlen(&operands[5], MAX_ECC_VEC_SZ);
        operands_wlen += PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        operands_wlen += PKA_ALIGN(pka_concat6_wlen(lenB, 3, 2), 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        if (opcode == CC_ECDSA_VERIFY_NO_WRITE)
            operands_wlen += 0;
        else
            operands_wlen += PKA_ALIGN(lenB, 8);

        break;

    case CC_DSA_GENERATE:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[2], lenA - 1);
        operands_wlen += PKA_ALIGN(pka_concat3_wlen(lenA, lenA, lenB, 3, 2), 8);
        operands_wlen += 3 * PKA_ALIGN(lenB, 8);
        operands_wlen += PKA_ALIGN((2 * lenB) + 3, 8);

        break;

    case CC_DSA_VERIFY_NO_WRITE:
    case CC_DSA_VERIFY:
        lenA           = pka_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_operand_wlen(&operands[2], lenA - 1);
        operands_wlen += PKA_ALIGN(pka_concat3_wlen(lenA, lenA, lenB, 3, 2), 8);
        operands_wlen += PKA_ALIGN(pka_concat_wlen(lenB, 3, 2, 0), 8);
        operands_wlen += PKA_ALIGN(lenA, 8) + PKA_ALIGN(lenB, 8);

        if (opcode == CC_DSA_VERIFY_NO_WRITE)
            operands_wlen += 0;
        else
            operands_wlen += PKA_ALIGN(lenB, 8);

        break;

    default:
        return 0;
    }

    operands_len  = operands_wlen << 2;
    // Include 3 extra words.
    operands_len  = PKA_ALIGN(operands_len, 8);
    operands_len += 3 * BYTES_PER_WORD; // or (3 << 2)

    // return length in bytes.
    return operands_len;
}

// Set queue command descriptor.
int pka_queue_set_cmd_desc(pka_queue_cmd_desc_t *cmd_desc,
                           uint32_t              cmd_num,
                           void                 *user_data,
                           pka_opcode_t          opcode,
                           pka_operands_t       *operands)
{
    pka_operand_t *operand;
    uint32_t       cmd_desc_size;
    uint8_t        operand_idx, operand_cnt, shift_amount;

    cmd_desc_size  = 0;
    operand_cnt    = operands->operand_cnt;
    shift_amount   = operands->shift_amount;

    cmd_desc->cmd_num     = cmd_num;
    cmd_desc->opcode      = opcode;
    cmd_desc->operand_cnt = operand_cnt;
    cmd_desc->shift_cnt   = shift_amount;
    cmd_desc->user_data   = (uint64_t) user_data;

    // Determine the length of the operands. This is used to check
    // the total size of the object to enqueue for safety purposes.
    // Indeed, this prevents enqueue errors when there are no rooms
    // available to copy the totality of the object.
    for (operand_idx = 0;  operand_idx < operand_cnt;  operand_idx++)
    {
        operand        = &operands->operands[operand_idx];
        // Note here that command operands data MUST be 8 byte aligned.
        // Indeed, only 8 byte aligned data are allowed for read and write
        // from/to window RAM. Thus to leverage the trade-off between the
        // memory space occupied by items in the queue and performance of
        // data copy, we propose to align operand data.
        cmd_desc_size += PKA_ALIGN(operand->actual_len, 8);
    }

    // Add the operand info. It consist of a header for each operand
    // that will be hold by this descriptor.
    cmd_desc_size  += sizeof(pka_operand_t) * operand_cnt;
    // Determine the size of the command descriptor to enqueue.
    cmd_desc->size  = sizeof(pka_queue_cmd_desc_t) + cmd_desc_size;
    PKA_ASSERT(cmd_desc->size < PKA_QUEUE_DESC_MAX_SIZE);

    // Here we estimate in bytes the total memory dedicated for operands
    // and results allocation in window RAM.  This is done here to avoid
    // going further and enqueuing a command which exceeds the tolerated
    // allocation size 'MAX_ALLOC_SIZE'.
    cmd_desc->operands_len =
            pka_operands_len(opcode, shift_amount, operands->operands);
    PKA_ASSERT(cmd_desc->operands_len < MAX_ALLOC_SIZE);

    return 0;
}

// Set queue result descriptor.
int pka_queue_set_rslt_desc(pka_queue_rslt_desc_t   *rslt_desc,
                            pka_ring_hw_rslt_desc_t *ring_desc,
                            uint32_t                 cmd_num,
                            uint64_t                 user_data,
                            uint8_t                  queue_num)
{
    // Initialize the queue result descriptor.
    rslt_desc->opcode         = ring_desc->command;
    rslt_desc->status         = ring_desc->result_code;
    rslt_desc->compare_result = ring_desc->cmp_result;
    rslt_desc->queue_num      = queue_num;
    rslt_desc->cmd_num        = cmd_num;
    rslt_desc->user_data      = user_data;

    // Get the result length and result count.
    rslt_desc->result_cnt = pka_ring_results_len(ring_desc,
                                                 &rslt_desc->result1_len,
                                                 &rslt_desc->result2_len);

    // Note here that result operands data MUST be 8 byte aligned.
    // Indeed, only 8 byte aligned data are allowed for read and write
    // from/to window RAM. Thus to leverage the trade-off between the
    // memory space occupied by items in the queue and performance of
    // data copy, we propose to align the result operand data.
    if (rslt_desc->result1_len)
        rslt_desc->result1_len = PKA_ALIGN(rslt_desc->result1_len, 8);

    if (rslt_desc->result2_len)
        rslt_desc->result2_len = PKA_ALIGN(rslt_desc->result2_len, 8);

    // Set the size of the queue result descriptor.
    rslt_desc->size  = sizeof(pka_queue_rslt_desc_t);
    rslt_desc->size += sizeof(pka_operand_t) * rslt_desc->result_cnt;
    rslt_desc->size += rslt_desc->result1_len + rslt_desc->result2_len;

    return 0;
}

// The actual enqueue of pointers on the queue. Placed here since identical
// code needed in both header and data enqueue.
static __pka_inline void pka_queue_do_enqueue(pka_queue_t *queue,
                                              uint32_t    *head,
                                              uint8_t     *obj_ptr,
                                              uint32_t     entries)
{
    uint32_t idx, size;
    uint32_t first_chunk, second_chunk;
    uint8_t  *q_mem;

    idx   = *head & queue->mask;
    q_mem = &queue->mem[idx];
    size  = queue->size;

    if (likely(idx + entries < size))
    {
        memcpy(q_mem, obj_ptr, entries);
    }
    else
    {
        first_chunk = size - idx;
        memcpy(q_mem, obj_ptr, first_chunk);

        q_mem = &queue->mem[0];
        second_chunk = entries - first_chunk;
        memcpy(q_mem, (obj_ptr + first_chunk), second_chunk);
    }

    *head = (*head + entries) & queue->mask;
}

// The actual dequeue of pointers on the queue. Placed here since identical
// code needed in both header and data dequeue.
static __pka_inline void pka_queue_do_dequeue(pka_queue_t *queue,
                                              uint32_t    *head,
                                              uint8_t     *obj_ptr,
                                              uint32_t     entries)
{
    uint32_t idx, size;
    uint32_t first_chunk, second_chunk;
    uint8_t  *q_mem;

    idx   = *head & queue->mask;
    q_mem = &queue->mem[idx];
    size  = queue->size;

    if (likely(idx + entries < size))
    {
        memcpy(obj_ptr, q_mem, entries);
    }
    else
    {
        first_chunk = size - idx;
        memcpy(obj_ptr, q_mem, first_chunk);

        q_mem = &queue->mem[0];
        second_chunk = entries - first_chunk;
        memcpy((obj_ptr + first_chunk), q_mem, second_chunk);
    }

    *head = (*head + entries) & queue->mask;
}

//This function updates the producer head for enqueue
static __pka_inline unsigned int
pka_queue_move_prod_head(pka_queue_t  *queue,
                         unsigned int  n,
                         uint32_t     *old_head,
                         uint32_t     *new_head,
                         uint32_t     *free_entries)
{
    const uint32_t capacity = queue->capacity;

    // move prod.head atomically
    *old_head = queue->prod.head;

    // add rmb barrier to avoid load/load reorder in weak memory model.
    pka_rmb();

    const uint32_t cons_tail = queue->cons.tail;
    //  The subtraction is done between two unsigned 32bits value
    // (the result is always modulo 32 bits even if we have
    // *old_head > cons_tail). So 'free_entries' is always between 0
    // and capacity (which is < size).
    *free_entries = (capacity + cons_tail - *old_head);

    // check that we have enough room in queue
    if (unlikely(n > *free_entries))
        n = 0;

    if (n == 0)
        return 0;

    *new_head        = (*old_head + n) & queue->mask;
    queue->prod.head = *new_head;

    return n;
}

static __pka_inline unsigned int
pka_queue_move_cons_head(pka_queue_t  *queue,
                         unsigned int  n,
                         uint32_t     *old_head,
                         uint32_t     *new_head,
                         uint32_t     *entries)
{
    // move cons.head atomically
    *old_head = queue->cons.head;

    // add rmb barrier to avoid load/load reorder in weak memory model.
    pka_rmb();

    const uint32_t prod_tail = queue->prod.tail;
    // The subtraction is done between two unsigned 32bits value
    // (the result is always modulo 32 bits even if we have
    // cons_head > prod_tail). So 'entries' is always between 0
    // and size(queue)-1.
    *entries = (prod_tail - *old_head);

    // Set the actual entries for dequeue
    if (n > *entries)
        n = 0;

    if (unlikely(n == 0))
        return 0;

    *new_head        = (*old_head + n) & queue->mask;
    queue->cons.head = *new_head;

    return n;
}

static __pka_inline void
pka_queue_update_tail(pka_queue_headtail_t *ht,
                      uint32_t  new_val,
                      uint32_t  enqueue)
{
    if (enqueue)
        pka_wmb();
    else
        pka_rmb();

    ht->tail = new_val;
}

// Enqueue a command on the queue (copy command from user context -> queue).
int pka_queue_cmd_enqueue(pka_queue_t          *queue,
                          pka_queue_cmd_desc_t *cmd_desc,
                          pka_operands_t       *operands)
{
    pka_operand_t *operand;
    uint32_t       total_size;
    uint32_t       prod_head, prod_next, free_entries;
    uint32_t       operand_idx, operand_cnt;
    uint64_t       operand_buf_addr;
    uint8_t       *operand_buf_ptr;

    if (queue->flags != PKA_QUEUE_TYPE_CMD)
        return -EPERM;

    total_size = pka_queue_move_prod_head(queue, cmd_desc->size, &prod_head,
                                            &prod_next, &free_entries);
    if (total_size == 0)
    {
        PKA_DEBUG(PKA_QUEUE, "not enough room in queue\n");
        __QUEUE_STAT_ADD(queue, enq_fail_objs, 1);
        return -ENOBUFS;
    }

    // write the command header.
    pka_queue_do_enqueue(queue, &prod_head, (uint8_t *) cmd_desc,
                            sizeof(pka_queue_cmd_desc_t));

    operand_cnt   = cmd_desc->operand_cnt;
    // write the operands information and data.
    for (operand_idx = 0;  operand_idx < operand_cnt;  operand_idx++)
    {
        operand = &operands->operands[operand_idx];

        // Save the operand buffer pointer and reset the operand buffer address.
        operand_buf_ptr  = operand->buf_ptr;
        operand_buf_addr = (prod_head + sizeof(pka_operand_t)) & queue->mask;
        operand->buf_ptr = (uint8_t *)(queue->mem + operand_buf_addr);

        // copy the operand information.
        pka_queue_do_enqueue(queue, &prod_head, (uint8_t *) operand,
                                        sizeof(pka_operand_t));

        // copy the operand buffer data.
        pka_queue_do_enqueue(queue, &prod_head, operand_buf_ptr,
                                PKA_ALIGN(operand->actual_len, 8));
    }

    pka_queue_update_tail(&queue->prod, prod_next, 1);

    __QUEUE_STAT_ADD(queue, enq_success, 1);
    return 0;
}

// Enqueue a result on a queue.
int pka_queue_rslt_enqueue(pka_queue_t             *queue,
                           pka_ring_info_t         *ring,
                           pka_ring_hw_rslt_desc_t *ring_desc,
                           pka_queue_rslt_desc_t   *rslt_desc)
{
    pka_operand_t *rslt1_ptr;
    pka_operand_t *rslt2_ptr;
    pka_operand_t  rslt_op_tmp;
    uint32_t       prod_head, prod_next, free_entries;
    uint32_t       total_size, queue_size, queue_mask, rslt_desc_size;
    uint32_t       result_cnt, result1_offset, result2_offset;
    uint32_t       size_left;

    if (queue->flags != PKA_QUEUE_TYPE_RSLT)
        return -EPERM;

    total_size = pka_queue_move_prod_head(queue, rslt_desc->size, &prod_head,
                                            &prod_next, &free_entries);
    if (total_size == 0)
    {
        PKA_DEBUG(PKA_QUEUE, "not enough room in queue\n");
        __QUEUE_STAT_ADD(queue, enq_fail_objs, 1);
        return -ENOBUFS;
    }

    rslt_desc_size  = sizeof(pka_queue_rslt_desc_t);

    // write the result header.
    pka_queue_do_enqueue(queue, &prod_head, (uint8_t *) rslt_desc,
                            rslt_desc_size);

    queue_mask      = queue->mask;
    queue_size      = queue->size;

    // Set result operands offset
    result1_offset  = prod_head;
    result1_offset &= queue_mask;

    result2_offset  = result1_offset + sizeof(pka_operand_t);
    result2_offset += rslt_desc->result1_len;
    result2_offset &= queue_mask;

    result_cnt      = rslt_desc->result_cnt;
    switch (result_cnt)
    {
    case 2:
        rslt2_ptr             = (pka_operand_t *) (queue->mem + result2_offset);
        memset(&rslt_op_tmp, 0, sizeof(pka_operand_t));
        rslt_op_tmp.big_endian = PKA_RING_BYTE_ORDER;
        rslt_op_tmp.actual_len = rslt_desc->result2_len;
        rslt_op_tmp.buf_len    = rslt_desc->result2_len;
        result2_offset         += sizeof(pka_operand_t);
        result2_offset         &= queue_mask;
        if (rslt_op_tmp.actual_len)
            rslt_op_tmp.buf_ptr = (uint8_t *) (queue->mem + result2_offset);

        // Copy pka operand info from temporary buffer to the queue memory.
        size_left = ((uint8_t *)queue->mem + queue->size) - (uint8_t *)rslt2_ptr;

        if (size_left >= sizeof(pka_operand_t))
        {
            // If there is enough space, Copy completely.
            memcpy(rslt2_ptr, &rslt_op_tmp, sizeof(pka_operand_t));
        }
        else
        {
            // Copy chunkwise and wrap around if we are crossing the queue boundary
            memcpy(rslt2_ptr, &rslt_op_tmp, size_left);
            memcpy(&queue->mem[0], (uint8_t *)&rslt_op_tmp + size_left,
                sizeof(pka_operand_t) - size_left);
        }
        // fall-through
    case 1:
        rslt1_ptr             = (pka_operand_t *) (queue->mem + result1_offset);
        memset(&rslt_op_tmp, 0, sizeof(pka_operand_t));
        rslt_op_tmp.big_endian = PKA_RING_BYTE_ORDER;
        rslt_op_tmp.actual_len = rslt_desc->result1_len;
        rslt_op_tmp.buf_len    = rslt_desc->result1_len;
        result1_offset         += sizeof(pka_operand_t);
        result1_offset         &= queue_mask;
        if (rslt_op_tmp.actual_len)
            rslt_op_tmp.buf_ptr = (uint8_t *) (queue->mem + result1_offset);

        // Copy pka operand info from temporary buffer to the queue memory.
        size_left = ((uint8_t *)queue->mem + queue->size) - (uint8_t *)rslt1_ptr;

        if (size_left >= sizeof(pka_operand_t))
        {
            // If there is enough space, Copy completely.
            memcpy(rslt1_ptr, &rslt_op_tmp, sizeof(pka_operand_t));
        }
        else
        {
            // Copy chunkwise and wrap around if we are crossing the queue boundary
            memcpy(rslt1_ptr, &rslt_op_tmp, size_left);
            memcpy(&queue->mem[0], (uint8_t *)&rslt_op_tmp + size_left,
                sizeof(pka_operand_t) - size_left);
        }
    }

    // Write the result operands information and data.
    // Note that we separate settings from data copy for performance
    // purposes -i.e. no matter compiler optimizations (re-ordering, etc.)
    prod_head = pka_ring_get_result(ring, ring_desc, queue->mem, queue_size,
                    result1_offset, result2_offset, rslt_desc->result1_len,
                                        rslt_desc->result2_len);

    pka_queue_update_tail(&queue->prod, prod_next, 1);

    __QUEUE_STAT_ADD(queue, enq_success, 1);

    return 0;
}

// Read command descriptor from queue. This function is not thread-safe.
int pka_queue_load_cmd_desc(pka_queue_cmd_desc_t *cmd_desc, pka_queue_t *queue)
{
    uint32_t cons_head, prod_tail, entries;
    uint32_t cmd_desc_size;

    if (queue->flags != PKA_QUEUE_TYPE_CMD)
        return -EPERM;

    cons_head = queue->cons.head;

    // add rmb barrier to avoid load/load reorder in weak memory model.
    pka_rmb();

    prod_tail = queue->prod.tail;
    // The subtraction is done between two unsigned 32bits value
    // (the result is always modulo 32 bits even if we have
    // cons_head > prod_tail). So 'entries' is always between 0
    // and size(queue)-1.
    entries = (prod_tail - cons_head);

    cmd_desc_size = sizeof(pka_queue_cmd_desc_t);

    // Set the actual entries for dequeue
    if (unlikely(cmd_desc_size > entries))
    {
        PKA_DEBUG(PKA_QUEUE, "no entries to read in queue\n");
        return -EPERM;
    }

    pka_queue_do_dequeue(queue, &cons_head, (uint8_t *) cmd_desc,
                            cmd_desc_size);

    return 0;
}

// Dequeue a command - copy cmd desc and operands from cmd queue to cmd ring.
int pka_queue_cmd_dequeue(pka_queue_t            *queue,
                          pka_ring_hw_cmd_desc_t *ring_desc,
                          pka_ring_alloc_t       *alloc)
{
    pka_queue_cmd_desc_t *cmd_desc;
    pka_queue_cmd_desc_t  cmd_desc_tmp;
    pka_operand_t         operands[MAX_OPERAND_CNT];
    pka_operand_t        *operand;
    uint32_t              cons_head, cons_next, entries;
    uint32_t              total_size;
    uint32_t              operand_idx, operand_cnt;
    uint16_t              buf_len;
    uint32_t              first_chunk;

    if (queue->flags != PKA_QUEUE_TYPE_CMD)
        return -EPERM;

    // Retrieve the size of the descriptor to dequeue. Note that the first
    // word corresponds to the size.
    // One might just read 32bits using a 'uint32_t *' but for calirity we
    // cast the addresse in the queue.
    cons_head     = queue->cons.head;
    // Read the queue memory carefully, adjust and wrap around if needed.
    if (cons_head + sizeof(pka_queue_cmd_desc_t) < queue->size)
    {
        cmd_desc = (pka_queue_cmd_desc_t *) &queue->mem[cons_head];
    }
    else
    {
        first_chunk = queue->size - cons_head;
        memcpy(&cmd_desc_tmp, &queue->mem[cons_head], first_chunk);
        memcpy((uint8_t *)&cmd_desc_tmp + first_chunk, &queue->mem[0],
            sizeof(pka_queue_cmd_desc_t) - first_chunk);
        cmd_desc = &cmd_desc_tmp;
    }

    total_size = pka_queue_move_cons_head(queue, cmd_desc->size,
                                        &cons_head, &cons_next, &entries);
    if (total_size == 0)
    {
        PKA_DEBUG(PKA_QUEUE, "no entries in queue\n");
        __QUEUE_STAT_ADD(queue, deq_fail, 1);
        return -EPERM;
    }

    cons_head  += sizeof(pka_queue_cmd_desc_t);

    operand_cnt = cmd_desc->operand_cnt;
    memset(&operands[0], 0, sizeof(pka_operand_t) * MAX_OPERAND_CNT);

    for (operand_idx = 0;  operand_idx < operand_cnt;  operand_idx++)
    {
        // write the operand info and data.
        operand = (pka_operand_t *) &queue->mem[cons_head & queue->mask];
        if ((cons_head & queue->mask) + sizeof(pka_operand_t) < queue->size)
        {
            memcpy(&operands[operand_idx], operand, sizeof(pka_operand_t));
        }
        else
        {
            first_chunk = queue->size - (cons_head & queue->mask);
            memcpy(&operands[operand_idx], operand, first_chunk);
            memcpy((uint8_t *)&operands[operand_idx] + first_chunk, &queue->mem[0],
                        sizeof(pka_operand_t) - first_chunk);
        }

        buf_len    = PKA_ALIGN(operands[operand_idx].actual_len, 8);
        cons_head += sizeof(pka_operand_t) + buf_len;
    }
    // Set ring descriptor and copy operands to window RAM.
    pka_ring_set_cmd_desc(ring_desc, alloc, cmd_desc->opcode,
                        cmd_desc->operand_cnt, cmd_desc->shift_cnt, operands);

    pka_queue_update_tail(&queue->cons, cons_next, 0);

    __QUEUE_STAT_ADD(queue, deq_success, 1);
    return 0;
}

int pka_queue_rslt_dequeue(pka_queue_t            *queue,
                           pka_queue_rslt_desc_t  *rslt_desc,
                           pka_results_t          *results)
{
    pka_queue_rslt_desc_t *dummy_rslt_desc; // used to avoid breaking strict
                                            // aliasing rule.
    pka_queue_rslt_desc_t  rslt_desc_tmp; // used to avoid breaking strict
    pka_operand_t         *result;
    uint32_t               cons_head, cons_next, entries, total_size;
    uint32_t               rslt_desc_size, result_idx, result_cnt;
    uint32_t               first_chunk;
    uint8_t               *buf_ptr;

    if (queue->flags != PKA_QUEUE_TYPE_RSLT)
        return -EPERM;

    // Retrieve the size of the descriptor to dequeue. Note that the first
    // word corresponds to the size.
    // One might just read 32bits using a 'uint32_t *' but for calirity we
    // cast the addresse in the queue.
    cons_head       = queue->cons.head;
    if (cons_head + sizeof(pka_queue_rslt_desc_t) < queue->size)
    {
        dummy_rslt_desc = (pka_queue_rslt_desc_t *) &queue->mem[cons_head];
    }
    else
    {
        first_chunk = queue->size - cons_head;
        memcpy(&rslt_desc_tmp, &queue->mem[cons_head], first_chunk);
        memcpy((uint8_t *)&rslt_desc_tmp + first_chunk, &queue->mem[0],
            sizeof(pka_queue_rslt_desc_t) - first_chunk);
        dummy_rslt_desc = &rslt_desc_tmp;
    }

    total_size = pka_queue_move_cons_head(queue, dummy_rslt_desc->size,
                                            &cons_head, &cons_next, &entries);
    if (total_size == 0)
    {
        PKA_DEBUG(PKA_QUEUE, "no entries in queue\n");
        __QUEUE_STAT_ADD(queue, deq_fail, 1);
        return -EPERM;
    }

    rslt_desc_size = sizeof(pka_queue_rslt_desc_t);

    // Read queue result descriptor.
    pka_queue_do_dequeue(queue, &cons_head, (uint8_t *) rslt_desc,
                            rslt_desc_size);

    result_cnt = rslt_desc->result_cnt;
    // Read the operand info and data.
    for (result_idx = 0;  result_idx < result_cnt;  result_idx++)
    {
        result  = &results->results[result_idx];
        buf_ptr = result->buf_ptr;

        // copy the result operand information.
        pka_queue_do_dequeue(queue, &cons_head, (uint8_t *) result,
                                sizeof(pka_operand_t));
        // copy the result operand buffer data.
        pka_queue_do_dequeue(queue, &cons_head, buf_ptr, result->actual_len);

        result->buf_ptr = buf_ptr;

        // Remove zero padding and adjust the actual length
        // of the second result for the following algos:
        // 1. ECC PT Addition
        // 2. ECC PT Multiplication
        // 3. ECDSA signature generation
        if ((rslt_desc->opcode == CC_ECC_PT_ADD
            || rslt_desc->opcode == CC_ECC_PT_MULTIPLY
            || rslt_desc->opcode == CC_ECDSA_GENERATE)
            && result_idx == 1)
        {
            pka_rm_rslt_zero_pad(result);
        }
    }

    pka_queue_update_tail(&queue->cons, cons_next, 0);

    __QUEUE_STAT_ADD(queue, deq_success, 1);
    return 0;
}

// dump the status of the queue on the console
void pka_queue_dump(pka_queue_t *queue)
{
#ifdef PKA_QUEUE_DEBUG
    struct pka_queue_debug_stats stats;
#endif

    printf("queue %p\n", queue);
    printf("  flags     =%x\n", queue->flags);
    printf("  size      =%"PRIu32"\n", queue->size);
    printf("  capacity  =%"PRIu32"\n", queue->capacity);
    printf("  ct        =%"PRIu32"\n", queue->cons.tail);
    printf("  ch        =%"PRIu32"\n", queue->cons.head);
    printf("  pt        =%"PRIu32"\n", queue->prod.tail);
    printf("  ph        =%"PRIu32"\n", queue->prod.head);
    printf("  used      =%u\n", pka_queue_count(queue));
    printf("  avail     =%u\n", pka_queue_free_count(queue));

    // dump statistics
#ifdef  PKA_QUEUE_DEBUG
    memset(&s, 0, sizeof(s));
    stats.enq_success_objs = queue->stats.enq_success_objs;
    stats.enq_fail_objs    = queue->stats.enq_fail_objs;
    stats.deq_success_objs = queue->stats.deq_success_objs;
    stats.deq_fail_objs    = queue->stats.deq_fail_objs;

    printf("  size             =%"PRIu32"\n", queue->prod.size);
    printf("  enq_success_objs =%"PRIu64"\n", stats.enq_success_objs);
    printf("  enq_fail_objs    =%"PRIu64"\n", stats.enq_fail_objs);
    printf("  deq_success_objs =%"PRIu64"\n", stats.deq_success_objs);
    printf("  deq_fail_objs    =%"PRIu64"\n", stats.deq_fail_objs);
#endif
}

