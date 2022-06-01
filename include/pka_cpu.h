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

#ifndef __PKA_CPU_H__
#define __PKA_CPU_H__

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/timex.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#include "pka_common.h"

#define MAX_CPU_NUMBER 16      // BlueField specific

#define MEGA 1000000
#define GIGA 1000000000

#define MS_PER_S 1000
#define US_PER_S 1000000
#define NS_PER_S 1000000000

// Initial guess at our CPU speed.  We set this to be larger than any
// possible real speed, so that any calculated delays will be too long,
// rather than too short.
//
//*Warning: use dummy value for frequency
#define CPU_HZ_MAX      (2 * GIGA) // Cortex A72 : 2 GHz max -> 2.5 GHz max
//#define CPU_HZ_MAX        (1255 * MEGA) // CPU Freq for High/Bin Chip

// YIELD hints the CPU to switch to another thread if possible
// and executes as a NOP otherwise.
#define pka_cpu_yield() ({ asm volatile("yield" : : : "memory"); })
// ISB flushes the pipeline, then restarts. This is guaranteed to
// stall the CPU a number of cycles.
#define pka_cpu_relax() ({ asm volatile("isb" : : : "memory"); })

#ifdef __KERNEL__
// Processor speed in hertz; used in routines which might be called very
// early in boot.
static inline uint64_t pka_early_cpu_speed(void)
{
  return CPU_HZ_MAX;
}
#else

#ifdef __BIG_ENDIAN__
#define WORD(x) (u16)((x)[0] + ((x)[1] << 8))
#define DWORD(x) (u32)((x)[0] + ((x)[1] << 8) + ((x)[2] << 16) + ((x)[3] << 24))
#define QWORD(x) (U64(DWORD(x), DWORD(x + 4)))
#else
#define WORD(x) (uint16_t)(*(const uint16_t *)(x))
#define DWORD(x) (uint32_t)(*(const uint32_t *)(x))
#define QWORD(x) (*(const uint64_t *)(x))
#endif
#define MAX_CLOCK_CYCLES     UINT64_MAX

/// Global variable holding the cpu frequency.
extern uint64_t cpu_f_hz;

static __pka_inline uint64_t pka_get_hz_ticks(void)
{
    uint64_t freq_64;

    // Read counter
    asm volatile("mrs %0, cntfrq_el0" : "=r" (freq_64));
    return freq_64;
}

/// Returns maximum frequency of specified CPU (in Hz) on success, and 0
/// on failure
static inline uint64_t pka_cpu_hz_max_id(int id)
{
    if (id < 0 || id >= MAX_CPU_NUMBER)
        return 0;

    /// Below check is to avoid multiple read.
    if (cpu_f_hz)
        return cpu_f_hz;

    cpu_f_hz = pka_get_hz_ticks();

    /// if frequency reading is zero, return max value.
    if (!cpu_f_hz)
        cpu_f_hz = CPU_HZ_MAX;

    return cpu_f_hz;
}

/// Returns maximum frequency of this CPU (in Hz) on success, and 0 on failure.
static inline uint64_t pka_cpu_hz_max(void)
{
    return pka_cpu_hz_max_id(0);
}

/// Read the system counter frequency
static inline uint64_t pka_cpu_rdfrq(void)
{
    uint64_t frq;

    asm volatile("mrs %0, cntfrq_el0" : "=r" (frq));
    return frq;
}

/// Read the time base register.
static inline uint64_t pka_cpu_rdvct(void)
{
    uint64_t vct;

    asm volatile("mrs %0, cntvct_el0" : "=r" (vct));
    return vct;
}

/// Return current CPU cycle count. Cycle count may not be reset at PKA init
/// and thus may wrap back to zero between two calls. Use pka_cpu_cycles_max()
/// to read the maximum count value after which it wraps. Cycle count frequency
/// follows the CPU frequency and thus may change at any time. The count may
/// advance in steps larger than one. Use pka_cpu_cycles_resolution() to read
/// the step size.
///
/// @note Do not use CPU count for time measurements since the frequency may
/// vary.
///
/// @note This call is easily portable to any ARM architecture, however,
/// it may be damn slow and inprecise for some tasks.
static inline uint64_t pka_cpu_cycles(void)
{
#ifdef PKA_AARCH_64
    return pka_cpu_rdvct();
#else
    struct timespec time;
    uint64_t sec, ns, hz, cycles;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

    if (ret != 0)
        abort();

    hz  = pka_cpu_hz_max();
    sec = (uint64_t)time.tv_sec;
    ns  = (uint64_t)time.tv_nsec;

    cycles  = sec * hz;
    cycles += (ns * hz) / GIGA;

    return cycles;
#endif
}

/// Return maximum CPU cycle count value before it wraps back to zero.
static inline uint64_t pka_cpu_cycles_max(void)
{
    return MAX_CLOCK_CYCLES;
}

/// CPU cycle count may advance in steps larger than one. This function returns
/// resolution of pka_cpu_cycles() in CPU cycles.
static inline uint64_t pka_cpu_cycles_resolution(void)
{
    return 1;
}

/// Format CPU cycles. If PKA_AARCH_64 is defined, this function deduce the
/// the number of cycles from raw counters (generic timers count).
static inline uint64_t pka_cpu_cycles_format(uint64_t cycles_cnt)
{
#ifdef PKA_AARCH_64
    uint64_t ns, hz, hz_max, cycles;

    hz  = pka_cpu_rdfrq();
    ns  = cycles_cnt * NS_PER_S;
    ns /= hz;

    hz_max  = pka_cpu_hz_max();
    cycles = (ns * hz_max) / GIGA;

    return cycles;
#else
    return cycles_cnt;
#endif
}

/// Calculate difference between cycle counts c1 and c2. Parameter c1 must
/// be the first cycle count sample and c2 the second. The function handles
/// correctly single cycle count wrap between c1 and c2.
static inline uint64_t pka_cpu_cycles_diff(uint64_t c2, uint64_t c1)
{
    uint64_t cycles;

    if (likely(c2 >= c1))
        cycles = c2 - c1;
    else
        cycles = c2 + (pka_cpu_cycles_max() - c1) + 1;

    return pka_cpu_cycles_format(cycles);
}

/// Pause CPU execution for a short while. This call is intended for tight
/// loops which poll a shared resource. A short pause within the loop may
/// save energy and improve system performance as CPU polling frequency is
/// reduced.
static inline void pka_cpu_pause(void)
{
    __asm__ __volatile__ ("nop");
    __asm__ __volatile__ ("nop");
    __asm__ __volatile__ ("nop");
    __asm__ __volatile__ ("nop");
}

#endif // __KERNEL__

#endif // __PKA_CPU_H__
