// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_MMIO_H__
#define __PKA_MMIO_H__


/// Macros for standard MMIO functions.

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/io.h>

#define pka_mmio_read64(addr)       readq_relaxed(addr)
#define pka_mmio_write64(addr, val) writeq_relaxed((val), (addr))
#define pka_mmio_read(addr)         pka_mmio_read64(addr)
#define pka_mmio_write(addr, val)   pka_mmio_write64((addr), (val))

#else

#include <stdbool.h>
#include <features.h>
#include <stdint.h>

#ifndef __BIG_ENDIAN__

static inline __attribute__((always_inline)) uint64_t
__pka_mmio_read64(void* addr)
{
  return *((volatile uint64_t*)addr);
}

static inline __attribute__((always_inline)) void
__pka_mmio_write64(void* addr, uint64_t val)
{
  *((volatile uint64_t*)addr) = val;
}

#else

static inline __attribute__((always_inline)) uint64_t
__pka_mmio_read64(void* addr)
{
  return __builtin_bswap64(*((volatile uint64_t*)addr));
}

static inline __attribute__((always_inline)) void
__pka_mmio_write64(void* addr, uint64_t val)
{
  *((volatile uint64_t*)addr) = __builtin_bswap64(val);
}

#endif //__BIG_ENDIAN__

/* Default size is 64-bit. */
#define pka_mmio_read(addr)       __pka_mmio_read64(addr)
#define pka_mmio_write(addr, val) __pka_mmio_write64(addr, val)

#endif // __KERNEL__

#endif // __PKA_MMIO_H__
