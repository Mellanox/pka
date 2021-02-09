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

//#ifndef __KERNEL__
//TODO Code should be used by both Kernel services and user space applications.

#include "pka_ring.h"
#include "pka_mem.h"
#include "pka_dev.h"

#include "pka_utils.h"

// This structure is used to hold "user_data" information associated
// with PK commands.
pka_udata_db_t pka_ring_udata_db[PKA_MAX_NUM_RINGS];

// Returns offset of the command count register.
static uint32_t pka_ring_cmd_cnt_offset(uint64_t base)
{
    size_t   page, page_mask;

    page      = (size_t)sysconf(_SC_PAGESIZE);
    page_mask = ~(page - 1);

    return (base + COMMAND_COUNT_0_ADDR) & ~page_mask;
    // should return 0x80
}

// Returns offset of the result count register.
static uint32_t pka_ring_rslt_cnt_offset(uint64_t base)
{
    size_t   page, page_mask;

    page      = (size_t)sysconf(_SC_PAGESIZE);
    page_mask = ~(page - 1);

    return (base + RESULT_COUNT_0_ADDR) & ~page_mask;
    // should return 0x88
}

// Increment ring command counter register.
static void pka_ring_inc_cmd_cnt(pka_ring_info_t *ring, uint64_t inc)
{
    uint32_t reg_offset;

    reg_offset = pka_ring_cmd_cnt_offset(ring->reg_addr);
    pka_mmio_write(ring->reg_ptr + reg_offset, inc);

}

// Decrement ring command counter register.
static void pka_ring_dec_rslt_cnt(pka_ring_info_t *ring, uint64_t dec)
{
    uint32_t reg_offset;

    reg_offset = pka_ring_rslt_cnt_offset(ring->reg_addr);
    pka_mmio_write(ring->reg_ptr + reg_offset, dec);
}

// The function checks to see if the PKA HW counters are properly initialized.
// Crashes and unstability may be caused by the fact that the counters are not
// zero, both SW and master firmware gets confused and crashes. This code tries
// to check (repair so far) this case - either directly or by returning a value
// which will cause the caller to try a reset.
static bool pka_ring_has_nonzero_counters(pka_ring_info_t *ring)
{
    uint64_t cmd_count, rslt_count;
    uint32_t reg_offset;

    reg_offset = pka_ring_cmd_cnt_offset(ring->reg_addr);
    cmd_count  = pka_mmio_read(ring->reg_ptr + reg_offset);
    PKA_DEBUG(PKA_RING, "CMMD_CTR_INC_%u=%lu\n", ring->ring_id, cmd_count);

    reg_offset = pka_ring_rslt_cnt_offset(ring->reg_addr);
    rslt_count = pka_mmio_read(ring->reg_ptr + reg_offset);
    PKA_DEBUG(PKA_RING, "RSLT_CTR_DEC_%u=%lu\n", ring->ring_id, rslt_count);

    if ((cmd_count != 0) || (rslt_count != 0))
    {
        PKA_DEBUG(PKA_RING, "non-zero HW counters - reinit PK block\n");

        // reset all command and result counters.
        if (ioctl(ring->fd, PKA_CLEAR_RING_COUNTERS))
            PKA_ERROR(PKA_RING,
                "failed to clear non-zero CMMD_CTR_INC_x and RSLT_CTR_DEC_x\n");

        return true;
    }

    return false;
}

static void pka_ring_reset_mem(pka_ring_info_t *ring)
{
    uint64_t *src64_ptr;
    uint32_t idx, src_offset = 0;
    uint32_t word_len = (ring->mem_size + 3) / 4;

    src64_ptr = (uint64_t *) (ring->mem_ptr + src_offset);
    for (idx = 0;  idx < (word_len + 1) / 2;  idx++)
    {
        pka_mmio_write(src64_ptr, 0);
        src64_ptr++;
    }
}

// Search for available rings. It returns a table of rings matching the request
// (or less than the request if no enough rings available), 0 if no rings found.
int pka_ring_lookup(pka_ring_info_t rings[],
                    uint32_t        req_rings_num,
                    uint8_t         byte_order,
                    uint8_t         mask[],
                    uint32_t       *cnt)
{
    pka_ring_info_t *ring;
    uint32_t         ring_idx;
    uint8_t          mask_idx, mask_bit;
    int              container;

    *cnt  = 0;

    if (!req_rings_num)
    {
        PKA_DEBUG(PKA_RING,
                    "warning: number of requested rings is zero\n");
        return 0;
    }

    // Create a new container
    container = open(PKA_VFIO_CONTAINER_PATH, O_RDWR);
    if (container < 0)
    {
        PKA_DEBUG(PKA_RING, "cannot create a new container\n");
        return -EBADF;
    }

    if (ioctl(container, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
    {
         PKA_DEBUG(PKA_RING, "unknown VFIO API version\n");
         close(container);
         return -EFAULT;
    }

    if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU))
    {
        PKA_DEBUG(PKA_RING, "does not support IOMMU TYPE 1 driver\n");
        close(container);
        return -EFAULT;
    }

    // Clear HW rings bitmask
    memset(mask, 0, PKA_RING_NUM_BITMASK * sizeof(*mask));

    // Lookup for available ring.
    for (ring_idx = 0; ring_idx < req_rings_num; ring_idx++)
    {
        ring = &rings[ring_idx];

        // Set handler container
        ring->container = container;

        // Check for an available ring.
        if (!pka_dev_has_avail_ring(ring, (req_rings_num - *cnt)))
        {
            PKA_DEBUG(PKA_RING, "failed to find available ring %d\n",
                            ring_idx);
            if (!(*cnt))
            {
                close(container);
                return -EBUSY;
            }
            break;
        }

        PKA_DEBUG(PKA_RING, "ring %u opened (hw ring %d)\n", ring_idx,
                            ring->ring_id);

        // Check counters for the ring
        // *TBD* Verify the return value of pka_ring_has_nonzero_counters(),
        //       and apply the right action (PK reinit or discard the ring).
        //       Note that SW controls one or multiple rings. Rings can belong
        //       to different PK shims. Careful, reinit should not affect other
        //       running SW. If ring X belongs to Shim Y, make sure that all
        //       the remaining rings of Y are not in-use before Y reinit.
        //       Otherwise, X MUST not be used (could crashe the SW and make
        //       the firmware instable).
        pka_ring_has_nonzero_counters(ring);

        // Initialize data memory for the ring.
        pka_mem_create(ring->ring_id);

        // Clear memory content.
        pka_ring_reset_mem(ring);

        ring->idx        = ring_idx;
        ring->big_endian = byte_order;

        // Set ring bit in mask
        mask_idx = ring->ring_id / 8;
        mask_bit = ring->ring_id % 8;
        mask[mask_idx] |= 1 << mask_bit;
        *cnt      += 1;
    }

    return 0;
}

// Free the given ring - ring becomes available.
static int pka_ring_put(pka_ring_info_t *ring, uint32_t cnt)
{
    if (ring)
    {
        // Unmap ring
        pka_dev_munmap_ring(ring);
        // Close ring
        pka_dev_close_ring(ring);

        if (!cnt) // check for last ring
            // close container
            close(ring->container);

        ring = NULL;
    }

    return 0;
}

// Free the set of assigned rings.
int pka_ring_free(pka_ring_info_t rings[], uint8_t mask[], uint32_t *cnt)
{
    pka_ring_info_t *ring;
    uint8_t          mask_idx, mask_bit;
    uint32_t         ring_idx = 0;

    if (!rings)
        return -EINVAL;

    while (*cnt > 0)
    {
        ring  = &rings[ring_idx];

        // Reset ring bit in mask (or toggle the bit i ^= (1 << bit))
        mask_idx = ring->ring_id / 8;
        mask_bit = ring->ring_id % 8;
        mask[mask_idx] &= ~(1 << mask_bit);
        *cnt  -= 1;

        // Clear memory content.
        pka_ring_reset_mem(ring);

        if(pka_ring_put(ring, *cnt))
            PKA_DEBUG(PKA_RING, "failed to put ring %d\n", ring_idx);
        ring_idx += 1;
    }

    return 0;
}


// Return the number of available rooms to append a command descriptors.
uint32_t pka_ring_has_available_room(pka_ring_info_t *ring)
{
    uint64_t used_desc_mask;
    uint32_t total_descs_num, used_descs_num, next_desc_idx;

    if (ring)
    {
        // When results are out of order, some command descriptors previously
        // enqueued may be pending in the ring, e.g: first command descriptor
        // is pending and the last result is associated with the last command
        // descriptor. In that case, we are no longer able to enqueue commands
        // even when there are available descriptors in the ring. Thus always
        // check for whether the descriptor at the next command index has been
        // processed, i.e., associated result dequeued.
        next_desc_idx  = ring->ring_desc.cmd_idx;
        used_desc_mask = ring->ring_desc.cmd_desc_mask;
        if ((1 << next_desc_idx) & used_desc_mask)
            return 0;

        total_descs_num = ring->ring_desc.num_descs;
        used_descs_num  = ring->ring_desc.cmd_desc_cnt;
        return total_descs_num - used_descs_num;
    }

    return 0;
}

// Returns the number of available results (when result is ready).
uint32_t pka_ring_has_ready_rslt(pka_ring_info_t *ring)
{
    uint32_t rslt_cnt_off;
    uint32_t rslt_cnt_val;

    size_t   page, page_mask;

    rslt_cnt_val = 0;

    if (ring)
    {
        page = (size_t)sysconf(_SC_PAGESIZE);
        page_mask = ~(page - 1);

        rslt_cnt_off = (ring->reg_addr + RESULT_COUNT_0_ADDR)
                                    & ~page_mask; // should be 0x88
        rslt_cnt_val = (uint32_t) pka_mmio_read(ring->reg_ptr + rslt_cnt_off);
    }

    return rslt_cnt_val;
}

// Return whether the returned values of 'user_data', 'cmd_num', 'queue_num'
// and 'ring_num' are valid.
bool pka_ring_pop_tag(pka_ring_hw_rslt_desc_t *result_desc,
                      uint64_t                *user_data,
                      uint64_t                *cmd_num,
                      uint8_t                 *queue_num,
                      uint8_t                 *ring_num)
{
    pka_udata_info_t *udata_info;

    udata_info = (pka_udata_info_t *) result_desc->tag;

    if (udata_info->valid == PKA_UDATA_INFO_VALID)
    {
        *cmd_num   = udata_info->cmd_num;
        *queue_num = udata_info->queue_num;
        *user_data = udata_info->user_data;
        *ring_num  = udata_info->ring_num; // future use - statistics

        // reset user data info
        udata_info->valid = 0;

        return true;
    }

    PKA_DEBUG(PKA_RING, "user data information invalid!\n");

    return false;
}

// Set tag value - the tag is supposed to hold the address (8 bytes) of user
// data entry that is reserved from the data base 'pka_ring_udata_db'.
void pka_ring_push_tag(pka_ring_hw_cmd_desc_t *cmd,
                       uint64_t                user_data,
                       uint64_t                cmd_num,
                       uint8_t                 queue_num,
                       uint8_t                 ring_num)
{
    pka_udata_db_t   *udata_db;
    pka_udata_info_t *udata_info;

    udata_db   = &pka_ring_udata_db[ring_num]; // Kind of memory allocation
    udata_info = &udata_db->entries[udata_db->index++];

    udata_info->user_data = user_data;
    udata_info->cmd_num   = cmd_num;
    udata_info->queue_num = queue_num;
    udata_info->ring_num  = ring_num;

    udata_info->valid     = PKA_UDATA_INFO_VALID;

    cmd->tag  = (uint64_t) udata_info;
}

static __pka_inline void
pka_ring_update_cmd_desc_mask(pka_ring_info_t *ring,
                              uint64_t         tag)
{
    pka_udata_info_t *udata_info;
    uint8_t           index;

    udata_info = (pka_udata_info_t *) tag;
    if (udata_info != NULL &&
            udata_info->valid == PKA_UDATA_INFO_VALID)
    {
        index = udata_info->cmd_desc_idx;
    }
    else
    {
        PKA_DEBUG(PKA_RING, "user data information invalid!");

        // Set command descriptor bit
        index = ring->ring_desc.cmd_idx;
    }
    ring->ring_desc.cmd_desc_mask &= ~(1 << index);
}

static __pka_inline void
pka_ring_store_cmd_desc_idx(pka_ring_desc_t *ring_desc,
                            uint64_t         tag,
                            uint8_t          cmd_idx)
{
    pka_udata_info_t *udata_info;
    uint8_t           cmd_desc_idx;

    cmd_desc_idx = (uint8_t) (cmd_idx & 0x3f); // max descs num is 64 (6 bits)
    // Set command descriptor bit.
    ring_desc->cmd_desc_mask |= 1 << cmd_desc_idx;

    // update user data information.
    udata_info = (pka_udata_info_t *) tag;
    if (udata_info != NULL &&
            udata_info->valid == PKA_UDATA_INFO_VALID)
        udata_info->cmd_desc_idx = cmd_desc_idx;
}

// Write data in window RAM.
static void __pka_inline pka_ring_write_mem(pka_ring_info_t *ring,
                                            uint16_t         dst_addr,
                                            void            *src,
                                            uint32_t         src_word_len,
                                            uint32_t         dst_word_len)
{
    uint64_t *src64_ptr, src_data;
    uint32_t idx;

    src64_ptr = src;
    for (idx = 0; idx < src_word_len / 2; idx++)
    {
        pka_mmio_write((uint8_t *) ring->mem_ptr + dst_addr, *src64_ptr);
        dst_addr += 8;
        src64_ptr++;
    }

    if ((src_word_len & 0x1) != 0)
    {
        // Special case when the src_word_len is odd.
        src_data = *src64_ptr;
        pka_mmio_write((uint8_t *) ring->mem_ptr + dst_addr,
                            src_data & 0xFFFFFFFFULL);
        dst_addr += 8;
        idx++;
    }

    // Now add any leading zero words required.
    for ( ; idx < (dst_word_len + 1) / 2; idx++)
    {
        pka_mmio_write((uint8_t *) ring->mem_ptr + dst_addr, 0);
        dst_addr += 8;
    }
}

// Read data from window RAM.
static __pka_inline void pka_ring_read_mem(pka_ring_info_t *ring,
                                           void            *dst,
                                           uint16_t         src_addr,
                                           uint32_t         word_len)
{
    uint64_t *dst64_ptr;
    uint32_t  idx;

    dst64_ptr = dst;
    for (idx = 0; idx < (word_len + 1) / 2; idx++)
    {
        *dst64_ptr = pka_mmio_read((uint8_t *)ring->mem_ptr + src_addr);
        dst64_ptr++;
        src_addr += 8;
    }
}

// Enqueue one command descriptor on a ring. This function verifies if there is
// space in the queue for the command and append the descriptor. The command
// descriptor number cmd_desc_num is written and might be used by the caller.
int pka_ring_enqueue_cmd_desc(pka_ring_info_t        *ring,
                              pka_ring_hw_cmd_desc_t *cmd_desc)
{
    pka_ring_desc_t *ring_desc;
    uint32_t         cmd_idx;
    uint32_t         odd_powers;
    uint32_t         cmd_tail_addr;
    uint32_t         cmd_desc_wlen;

    if (!ring)
        return -EINVAL;

    if (!pka_ring_has_available_room(ring))
    {
        __RING_STAT_ADD(r, enq_fail_cmd, 1);
        return -ENOBUFS;
    }

    ring_desc = &ring->ring_desc;

    switch (cmd_desc->command)
    {
    case CC_SHIFT_LEFT:
    case CC_SHIFT_RIGHT:
        odd_powers = cmd_desc->odd_powers;
        break;

    case CC_MODULAR_EXP:
        odd_powers = (cmd_desc->length_a <= 1) ? 1 : 4;
        break;

    case CC_MOD_EXP_CRT:
        odd_powers = 4;
        break;

    case CC_DSA_GENERATE:
    case CC_DSA_VERIFY:
        odd_powers = 4;  // *TBD* when should we use 4?  Depends on k length?
        break;

    default :
        odd_powers = 0;
    }

    cmd_desc->odd_powers = odd_powers;

    cmd_idx        = ring_desc->cmd_idx % ring_desc->num_descs;
    cmd_tail_addr  = ring_desc->cmd_ring_base & (ring->mem_size - 1);
    cmd_tail_addr += (cmd_idx * CMD_DESC_SIZE);
    cmd_desc_wlen  = (CMD_DESC_SIZE  + 3) / 4;

    // Update command descriptor counter.
    ring_desc->cmd_desc_cnt  += 1;

    // Write command descriptor.
    pka_ring_write_mem(ring, cmd_tail_addr, cmd_desc, cmd_desc_wlen,
                       cmd_desc_wlen);
    ring_desc->cmd_idx += 1;
    ring_desc->cmd_idx %= ring_desc->num_descs;

    // Increment command count.
    pka_ring_inc_cmd_cnt(ring, 1);

    // Store the command descriptor index.
    pka_ring_store_cmd_desc_idx(ring_desc, cmd_desc->tag, cmd_idx);

    __RING_STAT_ADD(ring, enq_success_cmd, n);

    return 0;
}

// Dequeue one result descriptor from a ring. This function verifies if there is
// a ready result in the queue for the command and read the descriptor.
int pka_ring_dequeue_rslt_desc(pka_ring_info_t         *ring,
                               pka_ring_hw_rslt_desc_t *result_desc)
{
    pka_ring_desc_t *ring_desc;
    uint32_t         rslt_idx;
    uint32_t         rslt_head_addr;
    uint32_t         rslt_desc_wlen;

    if (!ring)
        return -EINVAL;

    if (!pka_ring_has_ready_rslt(ring))
    {
        __RING_STAT_ADD(ring, deq_fail_rslt, 1);
        return -EPERM;
    }

    ring_desc = &ring->ring_desc;

    rslt_idx        = ring_desc->rslt_idx % ring_desc->num_descs;
    rslt_head_addr  = ring_desc->rslt_ring_base & (ring->mem_size - 1);
    rslt_head_addr += (rslt_idx * RESULT_DESC_SIZE);

    ring_desc->rslt_desc_cnt += 1;
    ring_desc->rslt_desc_cnt %= ring_desc->num_descs;
    rslt_desc_wlen = (RESULT_DESC_SIZE + 3) / 4;

    // Read result descriptor
    pka_ring_read_mem(ring, result_desc, rslt_head_addr, rslt_desc_wlen);
    ring_desc->rslt_idx += 1;
    ring_desc->rslt_idx %= ring_desc->num_descs;

    // Decrement result count
    pka_ring_dec_rslt_cnt(ring, 1);

    // update command descriptor counter
    pka_ring_update_cmd_desc_mask(ring, result_desc->tag);
    ring->ring_desc.cmd_desc_cnt -= 1;

    __RING_STAT_ADD(ring, deq_success_rslt, 1);

    return 0;
}

static __pka_inline uint16_t pka_ring_get_mem_ptr(pka_ring_info_t *ring,
                                                  uint16_t         offset)
{
    pka_ring_desc_t *ring_desc;

    ring_desc = &ring->ring_desc;
    return ring_desc->operands_base + offset;
}

// Returns operand word length.
static uint8_t pka_ring_operand_wlen(pka_operand_t *operand, uint32_t max_len)
{
    uint32_t byte_len;

    byte_len = operand->actual_len;
    return MIN((byte_len + 3)/4, max_len);
}

// Write the operand to ring memory.
static void pka_ring_write_operand(pka_ring_alloc_t *alloc,
                                   pka_operand_t    *src_operand,
                                   uint32_t          word_len,
                                   uint32_t          pad_len)
{
    uint32_t src_word_len;
    uint16_t dst_addr;
    uint8_t *src_ptr;

    // Now load the operand into the 64KB window ram.
    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    src_ptr      = src_operand->buf_ptr;
    dst_addr     = alloc->dst_offset;
    src_word_len = PKA_ALIGN(src_operand->actual_len, 8) / 4;
    pka_ring_write_mem(alloc->ring, dst_addr, src_ptr, src_word_len, word_len);
    alloc->dst_offset += 4 * (word_len + pad_len);
    if ((alloc->dst_offset & 0x7) != 0)
        alloc->dst_offset = PKA_ALIGN(alloc->dst_offset, 8);

    PKA_ASSERT(alloc->dst_offset <= alloc->max_dst_offset);
}

static int pka_adjust_mont_ecdh_multiplier(pka_operand_t *dst_operand,
                                           pka_operand_t *src_operand,
                                           pka_operand_t *curve_p)
{
    uint32_t prime_byte_len, src_byte_len, msb_byte_idx;

    // Two different cases: Curve25519 and Cureve448.  Distinguish these cases
    // by looking at the length of the curve prime
    prime_byte_len = curve_p->actual_len;
    src_byte_len   = src_operand->actual_len;
    memset(dst_operand->buf_ptr, 0, dst_operand->buf_len);
    memcpy(dst_operand->buf_ptr, src_operand->buf_ptr, src_byte_len);
    if (prime_byte_len == 32)
    {
        // For curve25519, clear the three least significant bit (bits 0, 1
        // and 2), clear the most significant bit (bit 255), and set the next
        // most significant bit (bit 254).
        PKA_ASSERT(32 <= dst_operand->buf_len);
        msb_byte_idx                        = 31;
        dst_operand->buf_ptr[0]            &= 0xF8;
        dst_operand->buf_ptr[msb_byte_idx] &= 0x7F;
        dst_operand->buf_ptr[msb_byte_idx] |= 0x40;
        dst_operand->actual_len             = 32;
    }
    else if (prime_byte_len == 56)
    {
        // For curve448, clear the two least significant bit (bits 0 and 1),
        // and set the most significant bit (bit 487) to 1.
        PKA_ASSERT(56 <= dst_operand->buf_len);
        msb_byte_idx                        = 55;
        dst_operand->buf_ptr[0]            &= 0xFC;
        dst_operand->buf_ptr[msb_byte_idx] |= 0x80;
        dst_operand->actual_len             = 56;
    }

    return 0;
}

// Copy the input vector associated with a command descriptor into ring memory.
static uint16_t pka_ring_copy_operand(pka_ring_alloc_t *alloc,
                                      pka_operand_t    *operand,
                                      uint8_t           word_len,
                                      uint8_t           pad_len)
{
    uint32_t start_dst_offset;

    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    start_dst_offset = alloc->dst_offset;

    pka_ring_write_operand(alloc, operand, word_len, pad_len);
    return pka_ring_get_mem_ptr(alloc->ring, start_dst_offset);
}

static uint16_t pka_ring_concat(pka_ring_alloc_t *alloc,
                                pka_operand_t    *operand1,
                                pka_operand_t    *operand2,
                                uint8_t           word_len,
                                uint32_t          odd_skip,
                                uint32_t          even_skip,
                                uint32_t          pad_len)
{
    uint32_t start_dst_offset, skip_len;

    // Either skip 0, 1, 2 or 3 words
    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    skip_len         = ((word_len & 0x1) == 1) ? odd_skip : even_skip;
    start_dst_offset = alloc->dst_offset;

    pka_ring_write_operand(alloc, operand1, word_len, skip_len);
    pka_ring_write_operand(alloc, operand2, word_len, pad_len);
    return pka_ring_get_mem_ptr(alloc->ring, start_dst_offset);
}

static uint16_t pka_ring_concat3(pka_ring_alloc_t *alloc,
                                 pka_operand_t    *operand1,
                                 pka_operand_t    *operand2,
                                 pka_operand_t    *operand3,
                                 uint8_t           word_len1,
                                 uint8_t           word_len2,
                                 uint8_t           word_len3,
                                 uint32_t          odd_skip,
                                 uint32_t          even_skip)
{
    uint32_t start_dst_offset, skip_len1, skip_len2;

    // Either skip 0, 1, 2 or 3 words
    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    skip_len1        = ((word_len1 & 0x1) == 1) ? odd_skip : even_skip;
    skip_len2        = ((word_len2 & 0x1) == 1) ? odd_skip : even_skip;
    start_dst_offset = alloc->dst_offset;

    pka_ring_write_operand(alloc, operand1, word_len1, skip_len1);
    pka_ring_write_operand(alloc, operand2, word_len2, skip_len2);
    pka_ring_write_operand(alloc, operand3, word_len3, 0);
    return pka_ring_get_mem_ptr(alloc->ring, start_dst_offset);
}

static uint16_t pka_ring_concat6(pka_ring_alloc_t *alloc,
                                 pka_operand_t    *operand1,
                                 pka_operand_t    *operand2,
                                 pka_operand_t    *operand3,
                                 pka_operand_t    *operand4,
                                 pka_operand_t    *operand5,
                                 pka_operand_t    *operand6,
                                 uint8_t           word_len,
                                 uint32_t          odd_skip,
                                 uint32_t          even_skip)
{
    uint32_t start_dst_offset, skip_len;

    // Either skip 0, 1, 2 or 3 words
    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    skip_len         = ((word_len & 0x1) == 1) ? odd_skip : even_skip;
    start_dst_offset = alloc->dst_offset;

    pka_ring_write_operand(alloc, operand1, word_len, skip_len);
    pka_ring_write_operand(alloc, operand2, word_len, skip_len);
    pka_ring_write_operand(alloc, operand3, word_len, skip_len);
    pka_ring_write_operand(alloc, operand4, word_len, skip_len);
    pka_ring_write_operand(alloc, operand5, word_len, skip_len);
    pka_ring_write_operand(alloc, operand6, word_len, 0);
    return pka_ring_get_mem_ptr(alloc->ring, start_dst_offset);
}

// Returns result pointer - i.e. result offset
static uint16_t pka_ring_result_ptr(pka_ring_alloc_t *alloc, uint8_t word_len)
{
    uint32_t start_dst_offset;

    PKA_ASSERT((alloc->dst_offset & 0x7) == 0);
    start_dst_offset  = alloc->dst_offset;
    alloc->dst_offset = PKA_ALIGN(start_dst_offset + (4 * word_len), 8);
    return pka_ring_get_mem_ptr(alloc->ring, start_dst_offset);
}

// Set the command descriptor according to the PK command, before appending
// it to a ring.
int pka_ring_set_cmd_desc(pka_ring_hw_cmd_desc_t *cmd,
                          pka_ring_alloc_t       *alloc,
                          pka_opcode_t            opcode,
                          uint32_t                operand_cnt,
                          uint32_t                shift_cnt,
                          pka_operand_t           operands[])
{
    pka_operand_t multiplier;
    uint32_t      lenA, lenB, pad_len, result_len;
    uint8_t       mult_buf[MAX_ECC_BUF];

    cmd->command    = opcode;
    cmd->odd_powers = shift_cnt;

    switch (opcode)
    {
    case CC_ADD:
        // operands[0] is value, operands[1] is addend.
        PKA_ASSERT(operand_cnt == 2);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, MAX(lenA, lenB) + 1);
        break;

    case CC_SUBTRACT:
        // operands[0] is value, operands[1] is subtrahend.
        PKA_ASSERT(operand_cnt == 2);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, MAX(lenA, lenB));
        break;

    case CC_ADD_SUBTRACT:
        // operands[0] is value, operands[1] is addend and operands[2] is
        // subtrahend.
        PKA_ASSERT(operand_cnt == 3);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[2], lenA, 0);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[1], lenA, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, lenA + 1);
        break;

    case CC_MULTIPLY:
        // operands[0] is value, operands[1] is multiplier.
        PKA_ASSERT(operand_cnt == 2);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, lenA + lenB + 6);  // ?? +6 ??
        break;

    case CC_DIVIDE:
        // operands[0] is value, operands[1] is divisor.
        PKA_ASSERT(operand_cnt == 2);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, lenB + 1);
        cmd->pointer_d = pka_ring_result_ptr(alloc, (lenA - lenB) + 1);
        break;

    case CC_MODULO:
        // operands[0] is value, operands[1] is modulus.
        PKA_ASSERT(operand_cnt == 2);
        PKA_ASSERT(5 <= operands[1].actual_len);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB           = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, lenB + 1);
        break;

    case CC_SHIFT_LEFT:
        // operands[0] is value to be shifted.
        PKA_ASSERT(operand_cnt == 1);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        result_len     = (shift_cnt == 0) ? lenA : (lenA + 1);
        cmd->length_a  = lenA;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, result_len);
        break;

    case CC_SHIFT_RIGHT:
        // operands[0] is value to be shifted.
        PKA_ASSERT(operand_cnt == 1);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_c = pka_ring_result_ptr(alloc, lenA);
        break;

    case CC_COMPARE:
        // operands[0] is value, operands[1] is comparend.
        PKA_ASSERT(operand_cnt == 2);
        lenA           = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        cmd->length_a  = lenA;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenA, 0);
        break;

    case CC_MODULAR_EXP:
        // operands[0] is exponent, operands[1] is modulus,
        // operands[2] is message value.
        PKA_ASSERT(operand_cnt == 3);
        lenA = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);
        PKA_ASSERT(operands[2].actual_len <= operands[1].actual_len);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0); // pad 1??
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[2], lenB, 0); // pad 1??
        cmd->pointer_d = pka_ring_result_ptr(alloc, lenB + 1);
        break;

    case CC_MOD_EXP_CRT:
        // operands[0] is prime p, operands[1] is prime q,
        // operands[2] is input c, operands[3] is d_p,
        // operands[4] is d_q,     operands[5] is qinv.
        // Note that d_p = d mod (p-1) and d_q = d mod (q-1), where d is the
        // decrypt exponent/secret key, and ((q * qinv) mod p) = 1.
        // Also note that q MUST be less than p, and so lenB is based only on
        // on the length of operands[0]=p.
        PKA_ASSERT(operand_cnt == 6);
        lenA = MAX(pka_ring_operand_wlen(&operands[3], MAX_MODEXP_CRT_VEC_SZ),
                   pka_ring_operand_wlen(&operands[4], MAX_MODEXP_CRT_VEC_SZ));
        lenB = MAX(pka_ring_operand_wlen(&operands[0], MAX_MODEXP_CRT_VEC_SZ),
                   pka_ring_operand_wlen(&operands[1], MAX_MODEXP_CRT_VEC_SZ));
        PKA_ASSERT(operands[1].actual_len <= operands[0].actual_len);
        PKA_ASSERT(operands[5].actual_len <= operands[0].actual_len);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_concat(alloc, &operands[3], &operands[4],
                                            lenA, 1, 0, 0);
        cmd->pointer_b = pka_ring_concat(alloc, &operands[0], &operands[1],
                                            lenB, 1, 2, 1);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[5], lenB, 0);
        cmd->pointer_e = pka_ring_copy_operand(alloc, &operands[2],
                                                                2 * lenB, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, 2 * lenB);
        break;

    case CC_MODULAR_INVERT:
        // operands[0] is value to be inverted, operands[1] is modulus.
        PKA_ASSERT(operand_cnt == 2);
        lenA = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB = pka_ring_operand_wlen(&operands[1], MAX_GEN_VEC_SZ);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_copy_operand(alloc, &operands[1], lenB, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, lenB);
        break;

    case CC_MONT_ECDH_MULTIPLY:
        // operands[0] is multiplier,    operands[1] is point x,
        // operands[2] is curve prime p, operands[3] is curve param A
        PKA_ASSERT(operand_cnt == 4);
        lenA    = pka_ring_operand_wlen(&operands[0], MAX_ECC_VEC_SZ);
        lenB    = pka_ring_operand_wlen(&operands[2], MAX_ECC_VEC_SZ);
        pad_len = (lenB & 0x1) ? 3: 2;

        memcpy(&multiplier, &operands[0], sizeof(multiplier));
        multiplier.buf_len = MAX_ECC_BUF;
        multiplier.buf_ptr = &mult_buf[0];
        pka_adjust_mont_ecdh_multiplier(&multiplier, &operands[0],
                                        &operands[2]);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &multiplier, lenA, 0);
        cmd->pointer_b = pka_ring_concat(alloc, &operands[2], &operands[3],
                                         lenB, 3, 2, 0);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[1], lenB,
                                               pad_len);
        cmd->pointer_d = pka_ring_result_ptr(alloc, lenB);
        break;

    case CC_ECC_PT_ADD:
        // operands[0] is pointA x,      operands[1] is pointA y,
        // operands[2] is pointB x,      operands[3] is pointB y,
        // operands[4] is curve prime p, operands[5] is curve param a,
        // operands[6] is curve param b.
        PKA_ASSERT(operand_cnt == 7);

        // Note that operand[6] == b is currently not used!?!
        lenB = MAX(pka_ring_operand_wlen(&operands[0], MAX_ECC_VEC_SZ),
                   pka_ring_operand_wlen(&operands[2], MAX_ECC_VEC_SZ));

        cmd->length_a  = 0;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_concat(alloc, &operands[0], &operands[1],
                                            lenB, 3, 2, 0);
        cmd->pointer_b = pka_ring_concat3(alloc, &operands[4], &operands[5],
                                        &operands[6], lenB, lenB, lenB, 3, 2);
        cmd->pointer_c = pka_ring_concat(alloc, &operands[2], &operands[3],
                                            lenB, 3, 2, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, (2 * lenB) + 3);
        break;

    case CC_ECC_PT_MULTIPLY:
        // operands[0] is multiplier,    operands[1] is pointA x,
        // operands[2] is pointA y,      operands[3] is curve prime p,
        // operands[4] is curve param a, operands[5] is curve param b.
        PKA_ASSERT(operand_cnt == 6);
        lenA       = pka_ring_operand_wlen(&operands[0], MAX_ECC_VEC_SZ);
        lenB       = MAX(pka_ring_operand_wlen(&operands[1], MAX_ECC_VEC_SZ),
                         pka_ring_operand_wlen(&operands[2], MAX_ECC_VEC_SZ));

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[0], lenA, 0);
        cmd->pointer_b = pka_ring_concat3(alloc, &operands[3], &operands[4],
                                 &operands[5], lenB, lenB, lenB, 3, 2);
        cmd->pointer_c = pka_ring_concat(alloc, &operands[1], &operands[2],
                                            lenB, 3, 2, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, (2 * lenB) + 3);
        break;

    case CC_ECDSA_GENERATE:
        // operands[0] is base point x,        operands[1] is base point y,
        // operands[2] is secret k,            operands[3] is private key,
        // operands[4] is message digest hash, operands[5] is curve prime p,
        // operands[6] is curve param a,       operands[7] is curve param b,
        // operands[8] is base point order.
        PKA_ASSERT(operand_cnt == 9);
        PKA_ASSERT(operands[0].actual_len <= operands[5].actual_len);
        PKA_ASSERT(operands[1].actual_len <= operands[5].actual_len);
        PKA_ASSERT(operands[2].actual_len <= operands[8].actual_len);
        PKA_ASSERT(operands[3].actual_len <= operands[8].actual_len);
        PKA_ASSERT(operands[4].actual_len <= operands[8].actual_len);
        PKA_ASSERT(operands[6].actual_len <= operands[5].actual_len);
        PKA_ASSERT(operands[7].actual_len <= operands[5].actual_len);
        PKA_ASSERT(operands[8].actual_len <= operands[5].actual_len);
        lenB = pka_ring_operand_wlen(&operands[5], MAX_ECC_VEC_SZ);

        cmd->length_a  = 0;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[3], lenB, 0);
        cmd->pointer_b = pka_ring_concat6(alloc, &operands[5], &operands[6],
                                 &operands[7], &operands[8], &operands[0],
                                 &operands[1], lenB, 3, 2);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[4], lenB, 0);
        cmd->pointer_e = pka_ring_copy_operand(alloc, &operands[2], lenB, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, (2 * lenB) + 3);
        break;

    case CC_ECDSA_VERIFY:
    case CC_ECDSA_VERIFY_NO_WRITE:
        // operands[0]  is base point x,        operands[1] is base point y,
        // operands[2]  is public key x,        operands[3] is public key y,
        // operands[4]  is message digest hash, operands[5] is curve prime p,
        // operands[6]  is curve param a,       operands[7] is curve param b,
        // operands[8]  is base point order,    operands[9] is signature r,
        // operands[10] is signature s.
        PKA_ASSERT(operand_cnt == 11);
        PKA_ASSERT(operands[0].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[1].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[2].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[3].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[4].actual_len  <= operands[8].actual_len);
        PKA_ASSERT(operands[6].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[7].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[8].actual_len  <= operands[5].actual_len);
        PKA_ASSERT(operands[9].actual_len  <= operands[8].actual_len);
        PKA_ASSERT(operands[10].actual_len <= operands[8].actual_len);
        lenB = pka_ring_operand_wlen(&operands[5], MAX_ECC_VEC_SZ);

        cmd->length_a  = 0;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_concat(alloc, &operands[2], &operands[3],
                                            lenB, 3, 2, 0);
        cmd->pointer_b = pka_ring_concat6(alloc, &operands[5], &operands[6],
                                 &operands[7], &operands[8], &operands[0],
                                 &operands[1], lenB, 3, 2);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[4], lenB, 0);
        cmd->pointer_e = pka_ring_concat(alloc, &operands[9], &operands[10],
                                            lenB, 3, 2, 0);
        if (opcode == CC_ECDSA_VERIFY)
            cmd->pointer_d = pka_ring_result_ptr(alloc, (2 * lenB));

        break;

    case CC_DSA_GENERATE:
        // operands[0] is prime p,     operands[1] is generator g,
        // operands[2] is sub-prime q, operands[3] is message digest hash,
        // operands[4] is secret k,    operands[5] is private key.
        PKA_ASSERT(operand_cnt == 6);
        PKA_ASSERT(operands[1].actual_len <= operands[0].actual_len);
        PKA_ASSERT(operands[3].actual_len <= operands[2].actual_len);
        PKA_ASSERT(operands[4].actual_len <= operands[2].actual_len);
        PKA_ASSERT(operands[5].actual_len <= operands[2].actual_len);
        lenA = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB = pka_ring_operand_wlen(&operands[2], lenA - 1);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[5], lenB, 0);
        cmd->pointer_b = pka_ring_concat3(alloc, &operands[0], &operands[1],
                                 &operands[2], lenA, lenA, lenB, 3, 2);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[3], lenB, 0);
        cmd->pointer_e = pka_ring_copy_operand(alloc, &operands[4], lenB, 0);
        cmd->pointer_d = pka_ring_result_ptr(alloc, (2 * lenB) + 3);
        break;

    case CC_DSA_VERIFY:
    case CC_DSA_VERIFY_NO_WRITE:
        // operands[0] is prime p,     operands[1] is generator g,
        // operands[2] is sub-prime q, operands[3] is message digest hash,
        // operands[4] is public key,  operands[5] is signature r,
        // operands[6] is signature s.
        PKA_ASSERT(operand_cnt == 7);
        PKA_ASSERT(operands[1].actual_len <= operands[0].actual_len);
        PKA_ASSERT(operands[4].actual_len <= operands[0].actual_len);
        PKA_ASSERT(operands[3].actual_len <= operands[2].actual_len);
        PKA_ASSERT(operands[5].actual_len <= operands[2].actual_len);
        PKA_ASSERT(operands[6].actual_len <= operands[2].actual_len);
        lenA = pka_ring_operand_wlen(&operands[0], MAX_GEN_VEC_SZ);
        lenB = pka_ring_operand_wlen(&operands[2], lenA - 1);

        cmd->length_a  = lenA;
        cmd->length_b  = lenB;
        cmd->pointer_a = pka_ring_copy_operand(alloc, &operands[4], lenA, 0);
        cmd->pointer_b = pka_ring_concat3(alloc, &operands[0], &operands[1],
                                 &operands[2], lenA, lenA, lenB, 3, 2);
        cmd->pointer_c = pka_ring_copy_operand(alloc, &operands[3], lenB, 0);
        cmd->pointer_e = pka_ring_concat(alloc, &operands[5], &operands[6],
                                            lenB, 3, 2, 0);
        if(opcode == CC_DSA_VERIFY)
            cmd->pointer_d = pka_ring_result_ptr(alloc, lenB);

        break;

    default:
        PKA_ASSERT(0);
    }

    return 0;
}

// The actual copy of operands from the ring to
// buffers -e.g. queue. Defined here as a macro
// since identical code needed in both copy with
// and without buffer wrapping.
#define COPY_PTRS(addr, len) \
({ \
    uint8_t   *dst8_ptr  = (uint8_t  *) dst;                \
    uint64_t  *dst64_ptr = (uint64_t *)(dst8_ptr + idx);    \
    uint64_t   src_data64;                                  \
    uint32_t   i;                                           \
    for (i=0; i < (len & (~(uint32_t)0x7)); i+=8, idx+=8)                   \
    {                                                                       \
        PKA_ASSERT((uint64_t) dst64_ptr < (uint64_t)(dst + dst_size)); \
        *dst64_ptr = pka_mmio_read((uint8_t *)ring->mem_ptr + addr + i);    \
        dst64_ptr++;                                                        \
    }                                                                       \
    src_data64 = pka_mmio_read((uint8_t *)ring->mem_ptr + addr + i);        \
    for (i = 0; i < (len & ((uint32_t) 0x7)); i++, idx++) {                   \
        PKA_ASSERT((uint64_t) (dst8_ptr + idx) < (uint64_t)(dst + dst_size)); \
        *(dst8_ptr + idx) = src_data64 >> (i * 8); }                         \
})

// Copy one result from window RAM.
static __pka_inline uint32_t
pka_ring_copy_result(pka_ring_info_t *ring,
                     void            *dst,
                     uint32_t         dst_idx,
                     uint32_t         src_addr,
                     uint32_t         src_len,
                     uint32_t         dst_size)
{
    uint32_t  operands_base;
    uint32_t  idx, src_remain_len;

    idx = dst_idx;

    // Determine the result operand offset.
    operands_base = ring->ring_desc.operands_base;
    src_addr      = src_addr & ~operands_base;

    if (likely(dst_idx + src_len < dst_size))
    {
        // Copy data
        COPY_PTRS(src_addr, src_len);
    }
    else
    {
        // Copy first chunk of data, before reaching the end of buffer
        // refered by 'dst_size'.
        src_remain_len = (dst_idx + src_len) & (dst_size - 1);
        src_len        = dst_size - dst_idx;
        COPY_PTRS(src_addr, src_len);

        // Copy remaining data.
        idx            = 0; // destination buffer wrapping.
        src_addr      += src_len;
        COPY_PTRS(src_addr, src_remain_len);
    }

    return idx;
}

// Copy output vector(s) associated with a result descriptor from ring memory.
uint32_t pka_ring_get_result(pka_ring_info_t         *ring,
                             pka_ring_hw_rslt_desc_t *result_desc,
                             uint8_t                 *queue_ptr,
                             uint32_t                 queue_size,
                             uint32_t                 result1_offset,
                             uint32_t                 result2_offset,
                             uint32_t                 result1_size,
                             uint32_t                 result2_size)
{
    uint32_t       lengthB;
    uint32_t       skip_bytes;
    uint32_t       y_offset;
    uint32_t       s_offset;
    uint32_t       index;
    uint32_t       operands_base;
    uint32_t       operands_off;

    index = 0;

    switch (result_desc->command)
    {
    case CC_ADD :
    case CC_SUBTRACT:
    case CC_MULTIPLY:
    case CC_SHIFT_LEFT:
    case CC_SHIFT_RIGHT:
        // All of these opcodes return a single result using pointer_c.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_c, result1_size, queue_size);

        break;

    case CC_ADD_SUBTRACT:
        // Returns a single result using pointer_d.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_d, result1_size, queue_size);

        break;

    case CC_DIVIDE:
        // Returns two results using pointer_c (remainder) and pointer_d
        // (quotient).
        index  = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_c, result1_size, queue_size);

        index  = pka_ring_copy_result(ring, queue_ptr, result2_offset,
                        result_desc->pointer_d, result2_size, queue_size);
        break;

    case CC_MODULO:
        // Returns a single result using pointer_c.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_c, result1_size, queue_size);

        break;

    case CC_COMPARE:
        // Returns zero results.
        break;

    case CC_MODULAR_EXP:
    case CC_MOD_EXP_CRT:
    case CC_MODULAR_INVERT:
    case CC_MONT_ECDH_MULTIPLY:
        // Returns a single result using pointer_d.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_d, result1_size, queue_size);
        break;

    case CC_ECC_PT_ADD:
    case CC_ECC_PT_MULTIPLY:
        // Returns two results (x and y values of an ECC point) using pointer_d.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_d, result1_size, queue_size);

        lengthB    = result_desc->length_b;
        skip_bytes = 4 * (((lengthB & 1) == 0) ? 2 : 3);
        y_offset   = result_desc->pointer_d + (4 * lengthB) + skip_bytes;
        index = pka_ring_copy_result(ring, queue_ptr, result2_offset, y_offset,
                                        result2_size, queue_size);
        break;

    case CC_ECDSA_GENERATE:
    case CC_DSA_GENERATE:
        // Returns two results (r and s values of an signature) using pointer_d.
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_d, result1_size, queue_size);
        lengthB    = result_desc->length_b;
        skip_bytes = 4 * (((lengthB & 1) == 0) ? 2 : 3);
        s_offset   = result_desc->pointer_d + (4 * lengthB) + skip_bytes;
        index      = pka_ring_copy_result(ring, queue_ptr, result2_offset,
                                            s_offset, result2_size, queue_size);
        break;

    case CC_ECDSA_VERIFY:
    case CC_DSA_VERIFY:
        index = pka_ring_copy_result(ring, queue_ptr, result1_offset,
                    result_desc->pointer_d, result1_size, queue_size);
        break;

    case CC_ECDSA_VERIFY_NO_WRITE:
    case CC_DSA_VERIFY_NO_WRITE:
        // Returns zero operands.
        break;

    default:
        PKA_ASSERT(0);
        break;
    }

    // Free up operands and results from memory.
    operands_base = ring->ring_desc.operands_base;
    operands_off  = result_desc->pointer_a & ~operands_base;
    pka_mem_free(ring->ring_id, operands_off);

    return index;
}

// Set the size of result operands and return the number of results associated
// with a given PK command.
uint32_t pka_ring_results_len(pka_ring_hw_rslt_desc_t *result_desc,
                              uint32_t                *result1_len,
                              uint32_t                *result2_len)
{
    uint32_t rslt_bit_len, rslt_byte_len;
    uint32_t rslt_byte_lenB;

    *result1_len = 0;
    *result2_len = 0;

    rslt_bit_len   = (result_desc->main_result_msw_offset * 32) +
                     result_desc->main_result_msb_offset + 1;
    rslt_byte_len  = (rslt_bit_len + 7) / 8;

    rslt_byte_lenB = result_desc->length_b * 4;

    switch (result_desc->command)
    {
    case CC_ADD:
    case CC_SUBTRACT:
    case CC_MULTIPLY:
    case CC_SHIFT_LEFT:
    case CC_SHIFT_RIGHT:
    case CC_ADD_SUBTRACT:
        *result1_len = rslt_byte_len;
        return 1;

    case CC_DIVIDE:
        // Returns two results. Note that the remainder length's are returned
        // in different fields.

        // Note the "31" added to the result_bit_len (when the result is not
        // zero).  This is because there is no modulo_msb_offset (i.e. bit
        // offset) and so we must assume the largest so that at least all of
        // the valid bytes are copied - and perhaps a few more.
        if (result_desc->modulo_is_0 != 0)
            rslt_bit_len = 0;
        else
            rslt_bit_len = (result_desc->modulo_msw_offset * 32) + 31;

        *result1_len = (rslt_bit_len + 7) / 8;

        if (result_desc->result_is_0 != 0)
            rslt_bit_len = 0;
        else
            rslt_bit_len = (result_desc->main_result_msw_offset * 32) + 31;

        *result2_len = (rslt_bit_len + 7) / 8;

        return 2;

    case CC_MODULO:
        // Returns a single result, except that the result length's are
        // returned in different fields.

        // Note the "31" added to the result_bit_len (when the result is not
        // zero).  This is because there is no modulo_msb_offset (i.e. bit
        // offset) and so we must assume the largest so that at least all of
        // the valid bytes are copied - and perhaps a few more.
        if (result_desc->modulo_is_0 != 0)
            rslt_bit_len = 0;
        else
            rslt_bit_len = (result_desc->modulo_msw_offset * 32) + 31;

        *result1_len = (rslt_bit_len + 7) / 8;

        return 1;

    case CC_COMPARE:
        // Returns zero results.
        return 0;

    case CC_MODULAR_EXP:
    case CC_MOD_EXP_CRT:
    case CC_MODULAR_INVERT:
    case CC_MONT_ECDH_MULTIPLY:
        // Returns a single result.
        *result1_len = rslt_byte_len;

        return 1;

    case CC_ECC_PT_ADD:
    case CC_ECC_PT_MULTIPLY:
        // Returns two results (x and y values of an ECC point).
        *result1_len = rslt_byte_len;
        *result2_len = rslt_byte_lenB;

        return 2;

    case CC_ECDSA_GENERATE:
    case CC_DSA_GENERATE:
        // Returns two results (r and s values of an signature).
        *result1_len = rslt_byte_lenB;
        *result2_len = rslt_byte_lenB;

        return 2;

    case CC_ECDSA_VERIFY:
    case CC_DSA_VERIFY:
        *result1_len = rslt_byte_lenB;

        return 1;

    case CC_ECDSA_VERIFY_NO_WRITE:
    case CC_DSA_VERIFY_NO_WRITE:
        // Returns zero operands.
        return 0;

    default:
        PKA_ASSERT(0);
        return 0;
    }
}

// Dump the status of the queue on the console
void pka_ring_dump(pka_ring_info_t *r)
{
#ifdef PKA_RING_DEBUG
    pka_ring_debug_stats s;
#endif

    printf("ring handle %p id %d:\n", r, r->ring_id);
    printf("  descs num        =%"PRIu32"\n", r->ring_desc.num_descs);
    printf("  desc size        =%"PRIu32"\n", r->ring_desc.desc_size);
    printf("  cmd base         =%"PRIu32"\n", r->ring_desc.cmd_ring_base);
    printf("  rslt base        =%"PRIu32"\n", r->ring_desc.rslt_ring_base);
    printf("  operands base    =%"PRIu32"\n", r->ring_desc.operands_base);
    printf("  operands end     =%"PRIu32"\n", r->ring_desc.operands_end);
    printf("  cmd cnt          =%"PRIu32"\n", r->ring_desc.cmd_desc_cnt);
    printf("  rslt cnt         =%"PRIu32"\n", r->ring_desc.rslt_desc_cnt);
    printf("  cmd idx          =%"PRIu32"\n", r->ring_desc.cmd_idx);
    printf("  rslt idx         =%"PRIu32"\n", r->ring_desc.rslt_idx);
    printf("  avail cmd descs  =%"PRIu32"\n", pka_ring_has_available_room(r));
    printf("  ready rslt descs =%"PRIu32"\n", pka_ring_has_ready_rslt(r));

    // dump statistics
#ifdef  PKA_LIB_RING_DEBUG
    memset(&s, 0, sizeof(s));
    s.enq_success_cmd  = r->stats.enq_success_cmd;
    s.enq_fail_cmd     = r->stats.enq_fail_cmd;
    s.deq_success_rslt = r->stats.deq_success_rslt;
    s.deq_fail_rslt    = r->stats.deq_fail_rslt;

    printf("  enq_success_cmd  =%"PRIu64"\n", s.enq_success_cmd);
    printf("  enq_fail_cmd     =%"PRIu64"\n", s.enq_fail_cmd);
    printf("  deq_success_rslt =%"PRIu64"\n", s.deq_success_rslt);
    printf("  deq_fail_rslt    =%"PRIu64"\n", s.deq_fail_rslt);
#endif
}


//#endif
