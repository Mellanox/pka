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

#ifndef __PKA_IOCTL_H__
#define __PKA_IOCTL_H__

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define PKA_IOC_TYPE 0xB7

/// PKA_RING_GET_REGION_INFO - _IORW(PKA_IOC_TYPE, 0x0, pka_dev_region_info_t)
///
/// Retrieve information about a device region. This is intended to describe
/// MMIO, I/O port, as well as bus specific regions (ex. PCI config space).
/// Zero sized regions may be used to describe unimplemented regions.
/// Return: 0 on success, -errno on failure.
typedef struct
{
    uint32_t reg_index;    ///< Registers region index.
    uint64_t reg_size;     ///< Registers region size (bytes).
    uint64_t reg_offset;   ///< Registers region offset from start of device fd.

    uint32_t mem_index;    ///< Memory region index.
    uint64_t mem_size;     ///< Memory region size (bytes).
    uint64_t mem_offset;   ///< Memeory region offset from start of device fd.
} pka_dev_region_info_t;
#define PKA_RING_GET_REGION_INFO _IOWR(PKA_IOC_TYPE, 0x0, pka_dev_region_info_t)

/// PKA_GET_RING_INFO - _IORW(PKA_IOC_TYPE, 0x1, pka_dev_ring_info_t)
///
/// Retrieve information about a ring. This is intended to describe ring
/// information words located in PKA_BUFFER_RAM. Ring information includes
/// base addresses, size and statistics.
/// Return: 0 on success, -errno on failure.
typedef struct // Bluefield specific ring information
{
    /// Base address of the command descriptor ring.
    uint64_t cmmd_base;

    /// Base address of the result descriptor ring.
    uint64_t rslt_base;

    /// Size of a command ring in number of descriptors, minus 1.
    /// Minimum value is 0 (for 1 descriptor); maximum value is
    /// 65535 (for 64K descriptors).
    uint16_t size;

    /// This field specifies the size (in 32-bit words) of the
    /// space that PKI command and result descriptor occupies on
    /// the Host.
    uint16_t host_desc_size : 10;

    /// Indicates whether the result ring delivers results strictly
    /// in-order ('1') or that result descriptors are written to the
    /// result ring as soon as they become available, so out-of-order
    /// ('0').
    uint8_t  in_order       : 1;

    /// Read pointer of the command descriptor ring.
    uint16_t cmmd_rd_ptr;

    /// Write pointer of the result descriptor ring.
    uint16_t rslt_wr_ptr;

    /// Read statistics of the command descriptor ring.
    uint16_t cmmd_rd_stats;

    /// Write statistics of the result descriptor ring.
    uint16_t rslt_wr_stats;

} pka_dev_hw_ring_info_t;
#define PKA_GET_RING_INFO   _IOWR(PKA_IOC_TYPE, 0x1, pka_dev_hw_ring_info_t)

/// PKA_CLEAR_RING_COUNTERS - _IO(PKA_IOC_TYPE, 0x2)
///
/// Clear counters. This is intended to reset all command and result counters.
/// Return: 0 on success, -errno on failure.
#define PKA_CLEAR_RING_COUNTERS  _IO(PKA_IOC_TYPE, 0x2)

/// PKA_GET_RANDOM_BYTES - _IOWR(PKA_IOC_TYPE, 0x3, pka_dev_trng_info_t)
///
/// Get random bytes from True Random Number Generator(TRNG).
/// Return: 0 on success, -errno on failure.
typedef struct // True Random Number Generator information
{
    /// Number of random bytes in the buffer; Length of the buffer.
    uint32_t count;

    /// Data buffer to hold the random bytes.
    uint8_t *data;

} pka_dev_trng_info_t;
#define PKA_GET_RANDOM_BYTES  _IOWR(PKA_IOC_TYPE, 0x3, pka_dev_trng_info_t)

#endif // __PKA_IOCTL_H__
