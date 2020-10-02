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

#define PKA_AARCH_64
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
#define PKA_DMI_TYPE_END 127

#define PKA_DMI_TABLE_LEN 4
#define PKA_DMI_TABLE_OFFSET 0x0C

#define PKA_DMI_PROC_TYPE 4
#define PKA_DMI_PROC_TABLE_LEN 0x1A
#define PKA_DMI_PROC_FREQ_OFFSET 0x16

#define PKA_DMI_HEADER_LEN_OFFSET 1
#define PKA_DMI_HEADER_TYPE_OFFSET 0
#define PKA_DMI_HEADER_HANDLE_OFFSET 2

#define PKA_SYS_DMI_TABLE "/sys/firmware/dmi/tables/DMI"
#define PKA_SYS_SMBIOS_ENTRY_POINT "/sys/firmware/dmi/tables/smbios_entry_point"

#define PKA_SMBIOS_LEN_OFFSET 0x06
#define PKA_SMBIOS_EXPECTED_LEN 0x20

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

typedef struct {
    uint16_t handle;
    uint8_t  type;
    uint8_t  length;
    uint8_t *data;
} pka_cpu_dmi_hdr_t;

/// Global variable holding the cpu frequency.
uint64_t cpu_f_hz;

static void *pka_cpu_read_sysfs(size_t *file_len, const char *filename)
{
    struct stat sbuf;
    size_t      read_count;
    ssize_t     read_status;
    uint8_t    *file_mem;
    int         fd;

    read_count  = 0;
    read_status = 1;

    fd = open(filename, O_RDONLY);
    if (fd == -EPERM)
    {
        PKA_ERROR(PKA_CPU, "\nOpening file failed with error:%d.\n", errno);
        return NULL;
    }

    if (!fstat(fd, &sbuf))
    {
        *file_len = sbuf.st_size;
    }

    file_mem = malloc(*file_len);
    if (file_mem == NULL)
    {
        PKA_ERROR(PKA_CPU, "\nMemory alloc failed when reading file.\n");
        goto out;
    }

    while (read_count != *file_len && read_status != 0)
    {
        read_status = read(fd, file_mem + read_count, *file_len - read_count);
        if (read_status == -1)
        {
            PKA_ERROR(PKA_CPU, "\nReading file failed.\n");
            goto err;
        }
        else
            read_count += read_status;
    }

    if (read_count != *file_len)
    {
        PKA_ERROR(PKA_CPU, "\n EOF reached before expected length.\n");
        goto err;
    }
    else
        goto out;

err:
    free(file_mem);
    file_mem = NULL;
out:
    if (close(fd) == -EPERM)
        PKA_ERROR(PKA_CPU, "\nClosing the file failed with error=%d.\n", errno);

    return file_mem;
}

static int pka_cpu_checksum(const uint8_t *buf, size_t len)
{
    uint8_t sum;
    size_t  d;

    sum = 0;

    for (d = 0; d < len; d++)
         sum += buf[d];

    return sum == 0;
}

static uint16_t pka_cpu_read_dmi_table(const char *sysfs)
{
    uint8_t          *buf, *data, *next;
    pka_cpu_dmi_hdr_t dmi_hdr;
    uint32_t          file_len;
    size_t            file_size;

    buf = pka_cpu_read_sysfs(&file_size, sysfs);
    if (buf == NULL)
        return 0;

    file_len = file_size;
    data     = buf;

    while (data + PKA_DMI_TABLE_LEN <= buf + file_len)
    {

        /// Copy the header information
        dmi_hdr.type   = data[PKA_DMI_HEADER_TYPE_OFFSET];
        dmi_hdr.length = data[PKA_DMI_HEADER_LEN_OFFSET];
        dmi_hdr.handle = WORD(data + PKA_DMI_HEADER_HANDLE_OFFSET);
        dmi_hdr.data   = data;

        if (dmi_hdr.length < PKA_DMI_TABLE_LEN)
        {
            PKA_ERROR(PKA_CPU, "\nInvalid entry length, DMI table is broken.\n");
            break;
        }

        if (dmi_hdr.type == PKA_DMI_TYPE_END)
            break;

        next = data + dmi_hdr.length;
        while ((unsigned long)(next - buf + 1) < file_len
            && (next[0] != 0 || next[1] != 0))
                next++;

        next += 2;

        if ((unsigned long)(next - buf) > file_len)
        {
            PKA_ERROR(PKA_CPU, "\nDMI structure is truncated.\n");
            break;
        }

        /// Processor information
        if (dmi_hdr.type == PKA_DMI_PROC_TYPE)
        {
            if (dmi_hdr.length < PKA_DMI_PROC_TABLE_LEN)
            {
                PKA_ERROR(PKA_CPU, "\nIncomplete processor information.\n");
                return 0;
            }
            /// Read frequency from offset
            return WORD(dmi_hdr.data + PKA_DMI_PROC_FREQ_OFFSET);
        }

        data = next;
    }
    return 0;
}

/// Returns current frequency (in Hz) on successful read from SMBIOS table,
/// and 0 in case of any errors while reading.
static uint64_t pka_cpu_get_freq_from_smbios(void)
{
    uint16_t freq;
    uint8_t *buf;
    size_t   file_size;

    freq = 0;

    buf = pka_cpu_read_sysfs(&file_size, PKA_SYS_SMBIOS_ENTRY_POINT);
    if (buf != NULL)
    {
        if (buf[PKA_SMBIOS_LEN_OFFSET] > PKA_SMBIOS_EXPECTED_LEN)
        {
            PKA_ERROR(PKA_CPU, "\n Entry point length exceeds the expected limit.\n");
            return 0;
        }

        if (!pka_cpu_checksum(buf, buf[PKA_SMBIOS_LEN_OFFSET]))
        {
            PKA_ERROR(PKA_CPU, "\nChecksum mismatch.\n");
            return 0;
        }

        freq = pka_cpu_read_dmi_table(PKA_SYS_DMI_TABLE);

        return freq * MEGA;
    }

    return freq;
}

/// Returns maximum frequency of specified CPU (in Hz) on success, and 0
/// on failure
static inline uint64_t pka_cpu_hz_max_id(int id)
{
    if (id < 0 || id >= MAX_CPU_NUMBER)
        return 0;

    /// Below check is to avoid multiple smbios read.
    if (cpu_f_hz)
        return cpu_f_hz;

    cpu_f_hz = pka_cpu_get_freq_from_smbios();

    /// Frequency will be zero if reading from smbios fails.
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
