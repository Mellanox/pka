// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_COMMON_H__
#define __PKA_COMMON_H__

/// Common byte definitions

#define MEGABYTE    (1024 * 1024)

#define BYTES_PER_WORD          4
#define BYTES_PER_DOUBLE_WORD   8

#ifndef __KERNEL__

#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/// Generic, commonly-used macro and inline function definitions for PKA lib.

#ifndef typeof
#define typeof __typeof__
#endif

#ifndef asm
#define asm __asm__
#endif

#define PKA_CACHE_LINE_SIZE     64  ///< Cache line size.
//Force alignment to cache line.
#define __pka_aligned(a)        __attribute__((__aligned__(a)))
#define __pka_cache_aligned     __pka_aligned(PKA_CACHE_LINE_SIZE)

// Macro to mark functions for inlining.
#define __pka_noinline          __attribute__((noinline))
#define __pka_inline            inline __attribute__((always_inline))
// Macro to mark functions and fields scheduled for removal.
#define __pka_deprecated        __attribute__((__deprecated__))
// Force a structure to be packed.
#define __pka_packed            __attribute__((__packed__))

// Macro to define a function that does not return
#define __pka_noreturn          __attribute__((__noreturn__))

/// Macros for bit manipulation

#define BIT_MASK(bits)          ((1U << (bits)) - 1)

#define BIT_IS_SET(var, pos)    (((var) >> (pos)) & 1)

/// Macros for pointer arithmetic

// Add a byte-value offset from a pointer
#define PKA_PTR_ADD(ptr, x) ((void*)((uintptr_t)(ptr) + (x)))

/// Macros/static functions for doing alignment

// Macro to align a value to a given power-of-two. The resultant value
// will be of the same type as the first parameter, and will be no
// bigger than the first parameter. Second parameter must be a
// power-of-two value.
#define PKA_ALIGN_FLOOR(val, align) \
    (typeof(val))((val) & (~((typeof(val))((align) - 1))))

// Macro to align a pointer to a given power-of-two. The resultant
// pointer will be a pointer of the same type as the first parameter, and
// point to an address no higher than the first parameter. Second parameter
// must be a power-of-two value.
#define PKA_PTR_ALIGN_FLOOR(ptr, align) \
    ((typeof(ptr))PKA_ALIGN_FLOOR((uintptr_t)ptr, align))

// Macro to align a pointer to a given power-of-two. The resultant
// pointer will be a pointer of the same type as the first parameter, and
// point to an address no lower than the first parameter. Second parameter
// must be a power-of-two value.
#define PKA_PTR_ALIGN_CEIL(ptr, align) \
    PKA_PTR_ALIGN_FLOOR((typeof(ptr))PKA_PTR_ADD(ptr, (align) - 1), align)

// Macro to align a value to a given power-of-two. The resultant value
// will be of the same type as the first parameter, and will be no lower
// than the first parameter. Second parameter must be a power-of-two
// value.
#define PKA_ALIGN_CEIL(val, align) \
    PKA_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

// Macro to align a pointer to a given power-of-two. The resultant
// pointer will be a pointer of the same type as the first parameter, and
// point to an address no lower than the first parameter. Second parameter
// must be a power-of-two value.
// This function is the same as PKA_PTR_ALIGN_CEIL
#define PKA_PTR_ALIGN(ptr, align) PKA_PTR_ALIGN_CEIL(ptr, align)

// Macro to align a value to a given power-of-two. The resultant
// value will be of the same type as the first parameter, and
// will be no lower than the first parameter. Second parameter
// must be a power-of-two value.
// This function is the same as PKA_ALIGN_CEIL
#define PKA_ALIGN(val, align) PKA_ALIGN_CEIL(val, align)

// Checks if a pointer is aligned to a given power-of-two value. It returns
// true (1) where the pointer is correctly aligned, false (0) otherwise.
static inline int pka_is_aligned(void *ptr, unsigned align)
{
    return PKA_PTR_ALIGN(ptr, align) == ptr;
}


/// Macro for calculating the number of elements in the array.
#define	PKA_DIM(a)	(sizeof (a) / sizeof ((a)[0]))

/// Macros for calculating min and max

// Macro to return the maximum of two numbers.
#define MAX(a, b)  (((a) <= (b)) ? (b) : (a))
// Macro to return the minimum of two numbers.
#define MIN(a, b)  (((a) <= (b)) ? (a) : (b))

/// Macros for branch prediction

// Check if a branch is likely to be taken.  This compiler builtin allows the
// developer to indicate if a branch is likely to be taken.
#define likely(x)       __builtin_expect((x),1)

// Check if a branch is unlikely to be taken. This compiler builtin allows the
// developer to indicate if a branch is unlikely to be taken.
#define unlikely(x)     __builtin_expect((x),0)

/// __builtin_prefetch (const void *addr, rw, locality)
///
/// rw 0..1       (0: read, 1: write)
/// locality 0..3 (0: dont leave to cache, 3: leave on all cache levels)

// Cache prefetch address
#define prefetch(x)         __builtin_prefetch((x), 0, 3)

// Cache prefetch address for storing
#define prefetch_store(x)   __builtin_prefetch((x), 1, 3)

/// Macros to work with powers of 2

// Returns true if n is a power of 2
static inline int pka_is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}

// Aligns input parameter to the next power of 2
static inline uint32_t pka_align32pow2(uint32_t x)
{
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return x + 1;
}

// Aligns 64b input parameter to the next power of 2
static inline uint64_t pka_align64pow2(uint64_t v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;

    return v + 1;
}

#endif // __KERNEL__

#endif // __PKA_COMMON_H__
