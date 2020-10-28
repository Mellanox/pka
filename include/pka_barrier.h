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

#ifndef __PKA_BARRIER_H__
#define __PKA_BARRIER_H__

#include "pka_atomic.h"

// ARMv8 Assembler code to implement memory barrier:

#define dmb(opt)  ({ asm volatile("dmb " #opt : : : "memory"); })
#define dsb(opt)  ({ asm volatile("dsb " #opt : : : "memory"); })

// General memory barrier. Guarantees that the LOAD and STORE operations
// generated before the barrier occur before the LOAD and STORE operations
// generated after. This function is architecture dependent.
static inline void pka_mb(void)
{
    dmb(ish);
}

// Write memory barrier. Guarantees that the STORE operations generated before
// the barrier occur before the STORE operations generated after. This function
// is architecture dependent.
static inline void pka_wmb(void)
{
    dmb(ishst);
}

// Read memory barrier. Guarantees that the LOAD operations generated before
// the barrier occur before the LOAD operations generated after. This function
// is architecture dependent.
static inline void pka_rmb(void)
{
    dmb(ishld);
}

static inline void pka_mb_full(void)
{
    dsb(sy);
}

// CPU pause -i.e. wait for few CPU cycles. This function is implemented in the
// assembler file (pka_lock.S)
void pka_wait();

// PKA thread synchronization barrier
typedef struct
{
    uint32_t         count;  ///< Thread count
    pka_atomic32_t   bar;    ///< Barrier counter
} pka_barrier_t;

static inline void pka_barrier_init(pka_barrier_t *barrier, uint32_t count)
{
    barrier->count = (uint32_t)count;
    pka_atomic32_init(&barrier->bar, 0);
}

// Efficient barrier_sync -
//
//   Barriers are initialized with a count of the number of callers
//   that must sync on the barrier before any may proceed.
//
//   To avoid race conditions and to permit the barrier to be fully
//   reusable, the barrier value cycles between 0..2*count-1. When
//   synchronizing the wasless variable simply tracks which half of
//   the cycle the barrier was in upon entry.  Exit is when the
//   barrier crosses to the other half of the cycle.
static inline void pka_barrier_wait(pka_barrier_t *barrier)
{
    uint32_t count;
    int wasless;

    pka_mb_full();

    count   = pka_atomic32_fetch_inc_relaxed(&barrier->bar);
    wasless = count < barrier->count;

    if (count == (2 * barrier->count - 1))
    {
        // Wrap around *atomically*
        pka_atomic32_sub(&barrier->bar, 2 * barrier->count);
    }
    else
    {
        while ((pka_atomic32_load(&barrier->bar) < barrier->count)
                == wasless)
            pka_wait();
    }

    pka_mb_full();
}

#endif // __PKA_BARRIER_H__
