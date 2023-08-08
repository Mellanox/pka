// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_MEM_H__
#define __PKA_MEM_H__

///
/// @file
///
/// This file describes a memory management interface used by rings to allocate
/// free memory needed by PK commands.
///
/// PKA memory allocator's job is primarily to manage the data memory - i.e.
/// efficiently allocate and free memory space to hold the input/output vectors.
/// One could use this code to do individual allocations and frees for each
/// vector, but instead it is expected that a single contiguous allocation/free
/// will be done for all the vectors - i.e. operands and results, belonging to
/// a single command. It is possible to also support a mode of operation,
/// whereby individual operand allocation can be used when a single command
/// allocation fails for lack of memory (i.e. this can deal efficiently with
/// the occasional data memory fragmentation where there is enough contiguous
/// memory pieces to hold the individual operand, but not single piece large
/// enough to hold all of the operands).
///
/// This code assumes that Data Memory is in the bottom 14KB of the "PKA window
/// RAM" and so the addresses for the rings start at offset 0x3800.  Also, note
/// that just because the rings hold 16 descriptors, does not mean that 16
/// commands can be outstanding - since it is expected that often the Data
/// Memory will run out before any or all of the rings are full themselves.
/// Of course the opposite can also happen (though less likely) - that is the
/// rings are full, when the Data Memory is not!
///
/// Note also that ALL allocations handled by this code start at least on
/// 64-byte boundaries and ALL allocations have sizes that are a multiple of
/// 64 bytes. The algorithm here always maximally coalesces contiguous free
/// space. In other words, there is never a case where two free space descri-
/// -ptors point to adjacent memory. Of course the converse is not true. Used
/// space blocks can be adjacent to either other used space blocks to free space
/// blocks.
///
/// Valid free space descriptors (i.e. those whose size is not zero) are kept on
/// various lists based upon their size.  Non-valid free space descriptors (so
/// called "free" avail space descriptors) are linked on a single free list.

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "pka_utils.h"

#define ALIGN_SHIFT  6
#define ALIGNMENT    (1 << ALIGN_SHIFT)
#define ALIGN_MASK   (ALIGNMENT - 1)
#define MAX_PADDING  (3 * ALIGNMENT)

#ifdef PKA_WINDOW_RAM_DATA_MEM_SIZE
#define DATA_MEM_SIZE    PKA_WINDOW_RAM_DATA_MEM_SIZE
#else
#define DATA_MEM_SIZE    0x3800  // 14 KB
#endif

#define MIN_ALLOC_SIZE      192
#define MAX_ALLOC_SIZE      2560

#define MAX_ALLOCS          248
#define MAX_CHUNK_IDX       250
#define NUM_OF_AVAIL_SIZES  40
#define MAX_MEM_MAP_IDX     ((DATA_MEM_SIZE >> ALIGN_SHIFT) - 1)

#define ON_FREE_LIST        0
#define AVAIL_MEM           1
#define USED_MEM            2

#define IS_AVAIL_MEM(map_value)  ((map_value >> 12) == AVAIL_MEM)
#define IS_USED_MEM(map_value)   ((map_value >> 12) == USED_MEM)
#define MEM_DESC_IDX(map_value)  (map_value & 0x00FF)
#define USED_SIZE(map_value)     (map_value & 0x0FFF)

typedef uint8_t pka_mem_idx_t;

/// This structure declares a "view" into memory allowing access to necessary
/// fields at known offsets from a given base. The size field holds bytes
/// representing a multiple of 64, and can range in size from 64 bytes to
/// 14K bytes (i.e. all of Data Memory can be described by a single free space
/// descriptor and will be when there are no allocations). A value of zero
/// indicates that this is NOT a currently valid descriptor i.e. it must be
/// on the free list.
typedef struct // 8 bytes long.
{
    uint16_t offset;                    ///< chunk offset in bytes.
    uint16_t size;                      ///< chunk size in bytes, including
                                        ///  overhead.

    pka_mem_idx_t next_chunk_idx;       ///< next chunk index in list.
    pka_mem_idx_t prev_chunk_idx;       ///< previous chunk index in list.

    uint8_t kind;                       ///< whether chunk is free or available.
    uint8_t list_idx;                   ///< chunk index in list.
} pka_mem_chunk_t;

/// This structure declares linked lists used by memory descriptor below.
typedef struct // 4 bytes long
{
    pka_mem_idx_t head;
    pka_mem_idx_t tail;
    uint8_t       size;
    uint8_t       list_idx;
} pka_mem_chunk_list_t;

/// This structure declares a "memory descriptor" which holds lists of the
/// available/free memory chunks, and a mapping of memory into chunks.
typedef struct
{
    // The following table is used to map a location in Data Memory into a
    // chunk OR a used size.  The input to the mapping is the offset from the
    // start of "PKA window RAM" divided by the ALIGNMENT.  The result of this
    // mapping fcn is a 16 bit integer - called the MemMap - which is used to
    // mark the memory as used or available and either give the used size or
    // give the index of the avail chunk table. Only the start and end locations
    // of the covered used/avail memory have non-zero values in this table.
    // Note in the (rare) case of the used/avail memory being ALIGNMENT bytes
    // in size, then the start location is the same as the end location,
    // but this still works out OK.
    uint16_t mem_map_tbl[MAX_MEM_MAP_IDX + 1];

    pka_mem_chunk_list_t avail_lists[NUM_OF_AVAIL_SIZES];
    pka_mem_chunk_t      chunk_tbl[MAX_CHUNK_IDX + 1];

    // Note that the freeList is only singly-linked, even though these same
    // descriptors are doubly-linked when on the avail_lists!
    pka_mem_chunk_list_t free_list;

    uint32_t alloc_cnt;
    uint32_t alloc_bytes;
} pka_mem_desc_t;

/// Return the size (in bytes) of the largest memory chunk available.
uint32_t pka_mem_largest_chunk_size(uint32_t ring_id);

/// Return the size (in bytes) of the used memory starting at the given offset.
uint32_t pka_mem_in_use_size(uint32_t ring_id, uint16_t offset);

/// Check whether data memory is full or not. This function is used to
/// tell whether or not pka_mem_alloc will succeed or not. Returns FALSE
/// if pka_mem_alloc will succeed and TRUE if it will fail.
bool pka_mem_is_full(uint32_t ring_id, uint32_t data_size);

/// Allocate data memory. Add a contiguous memory chunk where vectors can be
/// instantiated. It returns the offset of the allocated memory.
uint16_t pka_mem_alloc(uint32_t ring_id, uint32_t size);

/// Free data memory. Clear the memory entries from mapping list, free the
/// memory chunks, and coalesce free continuous memory chunks. The chunks must
/// not be used as they will be freed.
void pka_mem_free(uint32_t ring_id, uint16_t offset);

/// Create a new data memory in PKA Window RAM. This function allocate memory
/// and make it available. All elements of the memory are allocated, in one
/// continuous chunk of memory.
void pka_mem_create(uint32_t ring_id);

/// Reset allocated PKA window RAM region.
void pka_mem_reset(uint32_t dst_offset, void* mem_ptr, uint32_t operands_size);

#endif // __PKA_MEM_H__
