// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#include "pka_mem.h"

static pka_mem_desc_t *pka_data_mem_tbl[PKA_MAX_NUM_RINGS];

// Note that the most likely request sizes for RSA are 9, 10 (1024 bit keys),
// 17, 19 (2048 bit keys) and maybe 33, 37 (4096 bit keys) cache lines.

// Currently support lists are:
// List Idx   List Size Range in Cache Lines     List Size In Bytes
//    1         3                                 196 - 255
//    2         4                                 256 - 319
//    3         5                                 320 - 383
//    4         6                                 384 - 447
//    5         7                                 448
//    6         8                                 512
//    7         9*                                576
//    8        10*                                640
//    9        11                                 704
//   10        12                                 768
//   11        13                                 832
//   12        14                                 896
//   13        15                                 960
//   14        16,  17*, 18, 19*                  1024 - 1279,
//   15        20,  21,  22, 23                   1280 - 1535
//   16        24,  25,  26, 27                   1536
//   17        28,  29,  30, 31
//   18        32,  33*, 34, 35
//   19        36,  37*, 38, 39
//   20        40,  41,  42, 43
//   21        44,  45,  46, 47
//   22        48,  49,  50, 51
//   23        52,  53,  54, 55
//   24        56,  57,  58, 59
//   25        60,  61,  62, 63
//   26        64 - 79
//   27        80 - 95
//   28        96 - 111
//   29       112 - 127
//   30       128 - 143
//   31       144 - 159
//   32       160 - 175
//   33       176 - 183
//   34       184

/// Return the list index associated with the given size (in bytes).
static uint32_t pka_mem_get_list_index(uint32_t size)
{
    uint32_t cache_lines_num = MAX((size + 63) / 64, 3);

    if (256 <= cache_lines_num)              // i.e. 16384 <= size
        return 39;
    else if (64 <= cache_lines_num)          // i.e. 4096 <= size
        return 22 + (cache_lines_num / 16);  // 22 + 4 .. 15
    else if (16 <= cache_lines_num)          // i.e. 1024 <= size
        return 10 + (cache_lines_num / 4);   // 10 + 4 .. 15
    else
        return -2 + cache_lines_num;         // -2 + 3 .. 15
}

/// Set memory mapping entries into used. Mark a location starting from the
/// given offset with the given size in data memory as used.
static __pka_inline void pka_mem_set_map_entries_in_use(pka_mem_desc_t *data_mem,
                                                  uint16_t        offset,
                                                  uint16_t        size)
{
    uint32_t map_idx, end_map_idx;

    map_idx     = offset >> ALIGN_SHIFT;
    end_map_idx = map_idx + (size >> ALIGN_SHIFT) - 1;
    PKA_ASSERT(size != 0);

    // First check that the previous values are zero.
    PKA_ASSERT(data_mem->mem_map_tbl[map_idx]     == 0);
    PKA_ASSERT(data_mem->mem_map_tbl[end_map_idx] == 0);

    // Set the start and end mem Map entries.
    data_mem->mem_map_tbl[map_idx]     = (USED_MEM << 12) | size;
    data_mem->mem_map_tbl[end_map_idx] = (USED_MEM << 12) | size;
}

/// Set memory mapping entries into available. Mark a location starting from
/// the given offset with the given size in data memory as available.
static __pka_inline void pka_mem_set_map_entries_avail(pka_mem_desc_t *data_mem,
                                                 uint16_t        offset,
                                                 uint16_t        size,
                                                 pka_mem_idx_t   chunk_idx)
{
    uint32_t map_idx;
    uint32_t end_map_idx;

    map_idx     = offset >> ALIGN_SHIFT;
    end_map_idx = map_idx + (size >> ALIGN_SHIFT) - 1;
    PKA_ASSERT(size != 0);

    // First check that the previous values are zero.
    PKA_ASSERT(data_mem->mem_map_tbl[map_idx]     == 0);
    PKA_ASSERT(data_mem->mem_map_tbl[end_map_idx] == 0);

    // Set the start and end memory Map entries.
    data_mem->mem_map_tbl[map_idx]     = (AVAIL_MEM << 12) |
                                                (uint16_t) chunk_idx;
    data_mem->mem_map_tbl[end_map_idx] = (AVAIL_MEM << 12) |
                                                (uint16_t) chunk_idx;
}

/// Clear memory mapping entries.
static __pka_inline void pka_mem_clear_map_entries(pka_mem_desc_t *data_mem,
                                             uint32_t        map_idx,
                                             uint32_t        end_map_idx)
{
    // First check that the previous values are non-zero and the same.
    PKA_ASSERT(data_mem->mem_map_tbl[map_idx] != 0);
    PKA_ASSERT(data_mem->mem_map_tbl[map_idx] ==
                    data_mem->mem_map_tbl[end_map_idx]);

    // Zero out the old memMap entries.
    data_mem->mem_map_tbl[map_idx]     = 0;
    data_mem->mem_map_tbl[end_map_idx] = 0;
}

/// Add a given memory chunk to the available list. Link chunk and create
/// corresponding memory mapping entries.
static void pka_mem_add_chunk_to_avail(pka_mem_desc_t *data_mem,
                                       pka_mem_idx_t   chunk_idx)
{
    pka_mem_chunk_list_t *list_ptr;
    pka_mem_idx_t         this_chunk_idx;
    pka_mem_idx_t         prev_chunk_idx;
    pka_mem_idx_t         tail_idx;
    pka_mem_chunk_t      *chunk;
    uint16_t              offset;
    uint16_t              size;
    uint8_t               list_idx;

    chunk  = &data_mem->chunk_tbl[chunk_idx];
    offset = chunk->offset;
    size   = chunk->size;

    PKA_ASSERT((offset & ALIGN_MASK) == 0);

    // Set the start and end MemMap entries.
    pka_mem_set_map_entries_avail(data_mem, offset, size, chunk_idx);

    // Loop over the list until we find a larger element, and insert this
    // chunk just before it. Optimize the case where this list is empty.
    list_idx =  pka_mem_get_list_index(size);
    list_ptr = &data_mem->avail_lists[list_idx];

    PKA_ASSERT(chunk->list_idx == 0);

    if (list_ptr->size == 0)
    {
        list_ptr->head = chunk_idx;
        list_ptr->tail = chunk_idx;
        list_ptr->size = 1;

        data_mem->chunk_tbl[chunk_idx].list_idx       = list_idx;
        data_mem->chunk_tbl[chunk_idx].prev_chunk_idx = 0;
        data_mem->chunk_tbl[chunk_idx].next_chunk_idx = 0;
        return;
    }

    this_chunk_idx = list_ptr->head;
    prev_chunk_idx = 0;

    while (this_chunk_idx != 0)
    {
        chunk = &data_mem->chunk_tbl[this_chunk_idx];
        if (size < chunk->size)
        {
            list_ptr->size++;
            data_mem->chunk_tbl[chunk_idx].list_idx            = list_idx;
            data_mem->chunk_tbl[chunk_idx].next_chunk_idx      = this_chunk_idx;
            data_mem->chunk_tbl[chunk_idx].prev_chunk_idx      = prev_chunk_idx;
            data_mem->chunk_tbl[prev_chunk_idx].next_chunk_idx = chunk_idx;
            data_mem->chunk_tbl[this_chunk_idx].prev_chunk_idx = chunk_idx;
            if (prev_chunk_idx != 0)
                data_mem->chunk_tbl[prev_chunk_idx].next_chunk_idx = chunk_idx;
            else
                list_ptr->head = chunk_idx;

            return;
        }

        prev_chunk_idx = this_chunk_idx;
        this_chunk_idx = chunk->next_chunk_idx;
    }

    // If we reach here, then this new mem chunk is larger than all others in
    // this list, so just append it to the tail. Note that we know that there
    // has to be at least one prior element.
    list_ptr->size++;
    tail_idx                                      = list_ptr->tail;
    data_mem->chunk_tbl[chunk_idx].list_idx       = list_idx;
    data_mem->chunk_tbl[tail_idx].next_chunk_idx  = chunk_idx;
    data_mem->chunk_tbl[chunk_idx].prev_chunk_idx = tail_idx;
    data_mem->chunk_tbl[chunk_idx].next_chunk_idx = 0;
    list_ptr->tail                                = chunk_idx;
}

/// Remove a given memory chunk from the available list. Unlink chunk and clear
/// corresponding memory mapping entries.
static void pka_mem_remove_chunk_from_avail(pka_mem_desc_t *data_mem,
                                            pka_mem_idx_t   chunk_idx)
{
    pka_mem_chunk_list_t *list_ptr;
    pka_mem_idx_t         next_chunk_idx;
    pka_mem_idx_t         prev_chunk_idx;
    pka_mem_chunk_t      *chunk;
    uint32_t              map_idx;
    uint32_t              end_map_idx;
    uint16_t              offset;
    uint16_t              size;
    uint8_t               list_idx;

    chunk  = &data_mem->chunk_tbl[chunk_idx];
    offset = chunk->offset;
    PKA_ASSERT((offset & ALIGN_MASK) == 0);

    size         = chunk->size;
    map_idx      = offset >> ALIGN_SHIFT;
    end_map_idx  = map_idx + (size >> ALIGN_SHIFT) - 1;
    PKA_ASSERT(size != 0);

    // Zero out the old MemMap entries.
    pka_mem_clear_map_entries(data_mem, map_idx, end_map_idx);

    list_idx = chunk->list_idx;
    PKA_ASSERT(list_idx == pka_mem_get_list_index(size));
    list_ptr = &data_mem->avail_lists[list_idx];

    next_chunk_idx = chunk->next_chunk_idx;
    prev_chunk_idx = chunk->prev_chunk_idx;

    // Remove from the linked list.
    list_ptr->size--;
    if (prev_chunk_idx != 0)
        data_mem->chunk_tbl[prev_chunk_idx].next_chunk_idx = next_chunk_idx;
    else
        list_ptr->head = next_chunk_idx;

    if (next_chunk_idx != 0)
        data_mem->chunk_tbl[next_chunk_idx].prev_chunk_idx = prev_chunk_idx;
    else
        list_ptr->tail = prev_chunk_idx;

    chunk->list_idx       = 0;
    chunk->next_chunk_idx = 0;
    chunk->prev_chunk_idx = 0;
}

/// Allocate memory chunk for vectors in the data memory. Remove chunk from
/// the Free List and make it avialable.
static pka_mem_idx_t pka_mem_alloc_chunk(pka_mem_desc_t *data_mem)
{
    pka_mem_idx_t    chunk_idx;
    pka_mem_chunk_t *chunk;

    if (data_mem->free_list.size <= 2)
        return 0;

    chunk_idx =  data_mem->free_list.head;
    chunk     = &data_mem->chunk_tbl[chunk_idx];

    PKA_ASSERT(chunk_idx != 0);

    data_mem->free_list.head = chunk->next_chunk_idx;
    data_mem->free_list.size--;

    PKA_ASSERT(chunk->kind     == ON_FREE_LIST);
    PKA_ASSERT(chunk->list_idx == 0);
    PKA_ASSERT(chunk->offset   == 0);
    PKA_ASSERT(chunk->size     == 0);

    chunk->kind           = AVAIL_MEM;
    chunk->next_chunk_idx = 0;
    chunk->prev_chunk_idx = 0;

    return chunk_idx;
}

/// Free memory chunk. Put chunk back in the Free List.
static void pka_mem_free_chunk(pka_mem_desc_t *data_mem,
                               pka_mem_idx_t   chunk_idx)
{
    pka_mem_chunk_t *chunk;

    chunk = &data_mem->chunk_tbl[chunk_idx];

    PKA_ASSERT((1 <= chunk_idx) && (chunk_idx <= MAX_CHUNK_IDX));
    PKA_ASSERT(chunk->kind == AVAIL_MEM);

    chunk->kind   = ON_FREE_LIST;
    chunk->offset = 0;
    chunk->size   = 0;
    chunk->next_chunk_idx = 0;
    chunk->prev_chunk_idx = 0;

    if (data_mem->free_list.size == 0)
    {
        data_mem->free_list.head = chunk_idx;
        data_mem->free_list.tail = chunk_idx;
        data_mem->free_list.size = 1;
        return;
    }

    data_mem->chunk_tbl[data_mem->free_list.tail].next_chunk_idx = chunk_idx;
    data_mem->free_list.tail = chunk_idx;
    data_mem->free_list.size++;
}

static __pka_inline void pka_mem_no_coalesce(pka_mem_desc_t *data_mem,
                                               uint16_t        offset,
                                               uint16_t        size)
{
    pka_mem_idx_t    chunk_idx;
    pka_mem_chunk_t *chunk;

    chunk_idx = pka_mem_alloc_chunk(data_mem);
    chunk     = &data_mem->chunk_tbl[chunk_idx];
    PKA_ASSERT(chunk_idx != 0);

    chunk->offset = offset;
    chunk->size   = size;
    PKA_ASSERT((offset & ALIGN_MASK) == 0);
    pka_mem_add_chunk_to_avail(data_mem, chunk_idx);
}

static __pka_inline void pka_mem_coalesce_preceding (pka_mem_desc_t *data_mem,
                                          pka_mem_idx_t preceding_chunk_idx,
                                          uint16_t      used_offset,
                                          uint16_t      used_size)
{
    pka_mem_chunk_t *chunk;

    chunk = &data_mem->chunk_tbl[preceding_chunk_idx];
    pka_mem_remove_chunk_from_avail(data_mem, preceding_chunk_idx);

    PKA_ASSERT(chunk->offset + chunk->size == used_offset);
    PKA_ASSERT((chunk->offset & ALIGN_MASK) == 0);

    chunk->size += used_size;
    pka_mem_add_chunk_to_avail(data_mem, preceding_chunk_idx);
}

static __pka_inline void pka_mem_coalesce_following (pka_mem_desc_t *data_mem,
                                          pka_mem_idx_t following_chunk_idx,
                                          uint16_t      used_offset,
                                          uint16_t      used_size)
{
    pka_mem_chunk_t *chunk;

    chunk = &data_mem->chunk_tbl[following_chunk_idx];
    pka_mem_remove_chunk_from_avail(data_mem, following_chunk_idx);

    PKA_ASSERT(used_offset + used_size == chunk->offset);
    PKA_ASSERT((used_offset & ALIGN_MASK) == 0);

    chunk->offset = used_offset;
    chunk->size  += used_size;
    pka_mem_add_chunk_to_avail(data_mem, following_chunk_idx);
}

static __pka_inline void pka_mem_coalesce_both (pka_mem_desc_t *data_mem,
                                             pka_mem_idx_t preceding_chunk_idx,
                                             pka_mem_idx_t following_chunk_idx,
                                             uint16_t      used_offset,
                                             uint16_t      used_size)
{
    pka_mem_chunk_t *chunk;
    pka_mem_chunk_t *following_chunk;

    chunk           = &data_mem->chunk_tbl[preceding_chunk_idx];
    following_chunk = &data_mem->chunk_tbl[following_chunk_idx];
    pka_mem_remove_chunk_from_avail(data_mem, preceding_chunk_idx);
    pka_mem_remove_chunk_from_avail(data_mem, following_chunk_idx);

    PKA_ASSERT((used_offset & ALIGN_MASK) == 0);

    chunk->size += used_size + following_chunk->size;
    pka_mem_free_chunk(data_mem, following_chunk_idx);
    pka_mem_add_chunk_to_avail(data_mem, preceding_chunk_idx);
}

/// Best-Fit search algorithm to look for the "Best" chunk fitting the given
/// size. It returns TRUE if a chunk is found, FALSE if not. If non-zero the
/// chunk index pointer holds the index of the best chunk found.
static __pka_noinline bool pka_mem_BestFit_search(pka_mem_desc_t *data_mem,
                                                  uint32_t        size,
                                                  uint32_t        multiples,
                                                  uint32_t        slop,
                                                  pka_mem_idx_t  *chunk_idx_ptr)
{
    pka_mem_chunk_list_t *list_ptr;
    pka_mem_idx_t         chunk_idx;
    pka_mem_idx_t         best_chunk_idx;
    pka_mem_chunk_t      *chunk;
    uint32_t              total_size;
    uint32_t              first_list_idx;
    uint32_t              last_list_idx;
    uint32_t              list_idx;
    uint32_t              best_size;

    total_size      = size * multiples;
    first_list_idx  = pka_mem_get_list_index(total_size);
    last_list_idx   = pka_mem_get_list_index(total_size + slop);
    best_size       = total_size + 100;
    best_chunk_idx  = 0;

    for (list_idx = first_list_idx;  list_idx <= last_list_idx;  list_idx++)
    {
        list_ptr = &data_mem->avail_lists[list_idx];
        if (list_ptr->size != 0)
        {
            chunk_idx = list_ptr->head;
            while (chunk_idx != 0)
            {
                chunk = &data_mem->chunk_tbl[chunk_idx];
                if ((total_size <= chunk->size) &&
                        ((chunk->size - total_size) <= slop))
                {
                    // Two cases. In the event of an exact match, just return
                    // otherwise record the best match so far and continue
                    // searching;
                    if (chunk->size == total_size)
                    {
                        *chunk_idx_ptr = chunk_idx;
                        return true;
                    }
                    else if (chunk->size < best_size)
                    {
                        best_size      = chunk->size;
                        best_chunk_idx = chunk_idx;
                    }
                }

                chunk_idx = chunk->next_chunk_idx;
            }

            if (best_chunk_idx != 0)
            {
                *chunk_idx_ptr = best_chunk_idx;
                return true;
            }
        }
    }

    return false;
}

/// Search an avialable list matching the size. It calls a Best-Fit search
/// algorithm first, if an available non-emptty list is not found, loop over
/// lists from largest to smallest. This function returns the index of the
/// available chunk.
static __pka_inline pka_mem_idx_t pka_mem_lookup_avail(pka_mem_desc_t *data_mem,
                                                       uint32_t        size)
{
    pka_mem_chunk_list_t *list_ptr;
    pka_mem_idx_t         chunk_idx;
    uint32_t              slop, idx;

    slop = 3 * ALIGNMENT;
    if (pka_mem_BestFit_search(data_mem, size, 1, slop, &chunk_idx))
        return chunk_idx;
    else if (pka_mem_BestFit_search(data_mem, size, 2, slop, &chunk_idx))
        return chunk_idx;

    // Loop over lists from largest to smallest, find the first nonempty list.
    for (idx = NUM_OF_AVAIL_SIZES - 1;  0 < idx;  idx--)
    {
        list_ptr = &data_mem->avail_lists[idx];
        if (list_ptr->size != 0)
        {
            // Now find the largest mem_desc on this list, which should always
            // be at the tail!
            if (size <= data_mem->chunk_tbl[list_ptr->tail].size)
                return list_ptr->tail;
        }
    }

    return 0;
}


/// Return the size (in bytes) of the largest memory chunk available.
uint32_t pka_mem_largest_chunk_size(uint32_t ring_id)
{
    pka_mem_chunk_list_t *list_ptr;
    pka_mem_desc_t       *data_mem;
    uint32_t              idx;

    data_mem = pka_data_mem_tbl[ring_id];
    PKA_ASSERT(data_mem != NULL);

    // Loop over lists from largest to smallest, find the first nonempty list.
    for (idx = NUM_OF_AVAIL_SIZES - 1;  0 < idx;  idx--)
    {
        list_ptr = &data_mem->avail_lists[idx];
        if (list_ptr->size != 0)
            // Now find the largest chunk on this list, which should always
            // be at the tail!
            return data_mem->chunk_tbl[list_ptr->tail].size;
    }

    return 0;
}

/// Return the size (in bytes) of the used memory starting at the given offset.
uint32_t pka_mem_in_use_size(uint32_t ring_id, uint16_t offset)
{
    pka_mem_desc_t *data_mem;
    uint32_t        map_idx;
    uint16_t        map;
    uint16_t        used_size;
    uint16_t        used_offset;

    data_mem = pka_data_mem_tbl[ring_id];
    PKA_ASSERT(data_mem != NULL);

    used_offset = offset;
    map_idx     = used_offset >> ALIGN_SHIFT;
    PKA_ASSERT(used_offset < DATA_MEM_SIZE);

    map = data_mem->mem_map_tbl[map_idx];
    PKA_ASSERT(IS_USED_MEM(map));

    used_size = USED_SIZE(map);

    return used_size;
}

/// Check whether data memory is full or not.
bool pka_mem_is_full(uint32_t ring_id, uint32_t data_size)
{
    pka_mem_desc_t *data_mem;

    data_mem = pka_data_mem_tbl[ring_id];
    if (data_mem == NULL)
    {
        PKA_DEBUG(PKA_MEM, "bad data memory\n");
        return true;
    }

    // Round data size up to next 64 byte multiple.
    data_size = PKA_ALIGN(data_size, ALIGNMENT);

    // First check if there is even a possibility of a match.
    if ((MAX_ALLOCS <= data_mem->alloc_cnt) ||
          (data_mem->free_list.size <= 2) ||
          (DATA_MEM_SIZE <= (data_mem->alloc_bytes + data_size)))
        return true;

    data_size = MAX(MIN_ALLOC_SIZE, data_size);
    if (MAX_ALLOC_SIZE < data_size)
    {
        PKA_DEBUG(PKA_MEM, "bad data size=%u\n", data_size);
        return true;
    }

    // If allocBytes is less than 50% then there must be room
    if (data_mem->alloc_bytes < (DATA_MEM_SIZE / 2))
        return false;

    // General purpose, but expensive check
    if (data_size <= pka_mem_largest_chunk_size(ring_id))
        return false;

    return true;
}

/// Allocate data memory.
uint16_t pka_mem_alloc(uint32_t ring_id, uint32_t size)
{
    pka_mem_idx_t    chunk_idx;
    pka_mem_chunk_t *chunk;
    pka_mem_desc_t  *data_mem;
    uint16_t         offset;

    data_mem = pka_data_mem_tbl[ring_id];
    PKA_ASSERT(data_mem != NULL);

    // Round size (in bytes) up to next 64 byte multiple.
    size = PKA_ALIGN(size, ALIGNMENT);
    size = MAX(MIN_ALLOC_SIZE, size);
    PKA_ASSERT(size <= MAX_ALLOC_SIZE);

    // First check if there is even a possibility of a match.
    if ((MAX_ALLOCS <= data_mem->alloc_cnt) ||
        (data_mem->free_list.size <= 2) ||
        (DATA_MEM_SIZE <= (data_mem->alloc_bytes + size)))
        return 0;

    // Want to do a specific type of best fit match.
    chunk_idx = pka_mem_lookup_avail(data_mem, size);
    if (chunk_idx == 0)
        return 0;

    chunk  = &data_mem->chunk_tbl[chunk_idx];
    offset = chunk->offset;
    PKA_ASSERT((offset & ALIGN_MASK) == 0);

    PKA_ASSERT(size <= chunk->size);
    if ((chunk->size - size) <= MAX_PADDING)
    {
        // If this chunk is a "good" fit, then we increase the requested
        // size to consume the entire chunk, and then we need to free the
        // chunk, since it has been completely consumed by the allocation.
        size = chunk->size;
        pka_mem_remove_chunk_from_avail(data_mem, chunk_idx);
        pka_mem_free_chunk(data_mem, chunk_idx);
    }
    else
    {
        // If this chunk isn't a perfect fit, then we need to split the
        // chunk.
        pka_mem_remove_chunk_from_avail(data_mem, chunk_idx);
        chunk->offset += size;
        chunk->size   -= size;
        PKA_ASSERT((offset & ALIGN_MASK) == 0);
        pka_mem_add_chunk_to_avail(data_mem, chunk_idx);
    }

    // Set the start and end mem Map entries for the newly allocated used space.
    pka_mem_set_map_entries_in_use(data_mem, offset, size);

    data_mem->alloc_cnt++;
    data_mem->alloc_bytes += size;

    //PKA_DEBUG(PKA_MEM, "Ring %d, allocate memory start offset=%u, "
    //                            "size=%u\n", ring_id, offset, size);

    return offset;
}

/// Free data memory.
void pka_mem_free(uint32_t ring_id, uint16_t offset)
{
    pka_mem_desc_t *data_mem;
    uint32_t        map_idx;
    uint32_t        end_map_idx;
    uint16_t        map;
    uint16_t        prev_map;
    uint16_t        next_map;
    uint16_t        used_size;
    uint16_t        used_offset;

    //PKA_DEBUG(PKA_MEM, "Ring %d, free memory at offset=%u\n",
    //            ring_id, offset);

    if (offset == 0)
        return;

    data_mem = pka_data_mem_tbl[ring_id];
    PKA_ASSERT(data_mem != NULL);

    used_offset = offset;
    map_idx     = used_offset >> ALIGN_SHIFT;
    PKA_ASSERT((used_offset & ALIGN_MASK) == 0);
    PKA_ASSERT(used_offset < DATA_MEM_SIZE);

    map = data_mem->mem_map_tbl[map_idx];
    PKA_ASSERT(IS_USED_MEM(map));

    used_size   = USED_SIZE(map);
    end_map_idx = map_idx + (used_size >> ALIGN_SHIFT) - 1;

    // Make sure end map index value matchs MemMap.
    PKA_ASSERT(map == data_mem->mem_map_tbl[end_map_idx]);
    PKA_ASSERT((ALIGNMENT <= used_size) && (used_size <= MAX_ALLOC_SIZE));
    PKA_ASSERT((used_size & ALIGN_MASK) == 0);

    pka_mem_clear_map_entries(data_mem, map_idx, end_map_idx);
    data_mem->alloc_cnt--;
    data_mem->alloc_bytes -= used_size;

    // If preceding block is free space, coalesce with it.
    if (map_idx != 0)
    {
        prev_map = data_mem->mem_map_tbl[map_idx - 1];
        if (IS_AVAIL_MEM(prev_map))
        {
            // See if we are coalescing both preceding and following blocks.
            if (end_map_idx != MAX_MEM_MAP_IDX)
            {
                next_map = data_mem->mem_map_tbl[end_map_idx + 1];
                if (IS_AVAIL_MEM(next_map))
                {
                    pka_mem_coalesce_both(data_mem, MEM_DESC_IDX(prev_map),
                                 MEM_DESC_IDX(next_map), used_offset,
                                 used_size);
                    return;
                }
            }

            pka_mem_coalesce_preceding(data_mem, MEM_DESC_IDX(prev_map),
                              used_offset, used_size);
            return;
        }
    }

    // If following block is free space, coalesce with it.
    if (end_map_idx != MAX_MEM_MAP_IDX)
    {
        next_map = data_mem->mem_map_tbl[end_map_idx + 1];
        if (IS_AVAIL_MEM(next_map))
        {
            pka_mem_coalesce_following(data_mem, MEM_DESC_IDX(next_map),
                              used_offset, used_size);
            return;
        }
    }

    // If we cannot coalesce this newly freed memory with adjacent free space,
    // then just turn this into an avail chunk and add to the appropriate list.
    pka_mem_no_coalesce(data_mem, used_offset, used_size);
}

/// Create a new data memory in PKA Window RAM.
void pka_mem_create(uint32_t ring_id)
{
    pka_mem_idx_t    chunk_idx;
    pka_mem_chunk_t *chunk;
    pka_mem_desc_t  *data_mem;
    uint32_t         list_idx;

    if (pka_data_mem_tbl[ring_id] != NULL)
        return;

    data_mem = malloc(sizeof(pka_mem_desc_t));
    memset(data_mem, 0, sizeof(pka_mem_desc_t));

    pka_data_mem_tbl[ring_id] = data_mem;
    for (list_idx = 1; list_idx < NUM_OF_AVAIL_SIZES; list_idx++)
        data_mem->avail_lists[list_idx].list_idx = list_idx;

    // Initialize the mem descriptors free list.
    data_mem->free_list.head  = 1;
    data_mem->free_list.tail  = MAX_CHUNK_IDX;
    data_mem->free_list.size  = MAX_CHUNK_IDX;
    for (chunk_idx = 1;  chunk_idx < MAX_CHUNK_IDX;  chunk_idx++)
        data_mem->chunk_tbl[chunk_idx].next_chunk_idx = chunk_idx + 1;

    data_mem->alloc_cnt = 0;
    data_mem->alloc_bytes = 0;

    // Now allocate one memory descriptor to cover all of the available space.
    chunk_idx     = pka_mem_alloc_chunk(data_mem);
    chunk         = &data_mem->chunk_tbl[chunk_idx];
    chunk->offset = ALIGNMENT;
    chunk->size   = DATA_MEM_SIZE - ALIGNMENT;
    chunk->kind   = AVAIL_MEM;
    pka_mem_add_chunk_to_avail(data_mem, chunk_idx);
}

/// Clear allocated memory. Should be called before copying input vectors and
/// submitting commands.
void pka_mem_reset(uint32_t dst_offset, void* mem_ptr, uint32_t operands_size)
{
    uint64_t *dst64_ptr;
    uint32_t  offset, word_len, idx;

    word_len  = (operands_size + 3) / 4;
    offset    = (dst_offset + 7) & ~0x7;
    dst64_ptr = (uint64_t *) (mem_ptr + offset);
    for (idx = 0;  idx < (word_len + 1) / 2;  idx++)
        pka_mmio_write(dst64_ptr++, 0);
}


