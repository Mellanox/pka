// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_IOCTL_H__
#define __PKA_IOCTL_H__

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#endif

#define PKA_IOC_TYPE 0xBF
#define PKA_IOC_TYPE_ALT 0xB7

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
    uint64_t mem_offset;   ///< Memory region offset from start of device fd.
} pka_dev_region_info_t;
#define PKA_RING_GET_REGION_INFO _IOWR(PKA_IOC_TYPE, 0x0, pka_dev_region_info_t)
#define PKA_RING_GET_REGION_INFO_ALT _IOWR(PKA_IOC_TYPE_ALT, 0x0, pka_dev_region_info_t)

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
#define PKA_GET_RING_INFO_ALT   _IOWR(PKA_IOC_TYPE_ALT, 0x1, pka_dev_hw_ring_info_t)

/// Clear counters. This is intended to reset all command and result counters.
/// Return: 0 on success, -errno on failure.
#define PKA_CLEAR_RING_COUNTERS  _IO(PKA_IOC_TYPE, 0x2)
#define PKA_CLEAR_RING_COUNTERS_ALT  _IO(PKA_IOC_TYPE_ALT, 0x2)

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
#define PKA_GET_RANDOM_BYTES_ALT  _IOWR(PKA_IOC_TYPE_ALT, 0x3, pka_dev_trng_info_t)

#ifndef __KERNEL__
// ioctl wrapper that tries both PKA ioctl numbers
// This allows the library to work with drivers using either 0xB7 or 0xBF
static inline int pka_ioctl_compat(int fd,
				   unsigned long primary_cmd,
				   unsigned long alt_cmd,
				   void *arg)
{
    int ret;

    // Try primary ioctl number first (0xB7 based)
    ret = ioctl(fd, primary_cmd, arg);
    if (ret == -1 && errno == ENOTTY) {
        // If not supported, try alternate ioctl number (0xBF based)
        ret = ioctl(fd, alt_cmd, arg);
    }

    return ret;
}

// Convenience macros for each PKA ioctl command
#define PKA_IOCTL_GET_REGION_INFO(fd, arg) \
    pka_ioctl_compat(fd, PKA_RING_GET_REGION_INFO, PKA_RING_GET_REGION_INFO_ALT, arg)

#define PKA_IOCTL_GET_RING_INFO(fd, arg) \
    pka_ioctl_compat(fd, PKA_GET_RING_INFO, PKA_GET_RING_INFO_ALT, arg)

#define PKA_IOCTL_CLEAR_RING_COUNTERS(fd) \
    pka_ioctl_compat(fd, PKA_CLEAR_RING_COUNTERS, PKA_CLEAR_RING_COUNTERS_ALT, NULL)

#define PKA_IOCTL_GET_RANDOM_BYTES(fd, arg) \
    pka_ioctl_compat(fd, PKA_GET_RANDOM_BYTES, PKA_GET_RANDOM_BYTES_ALT, arg)
#endif

#endif // __PKA_IOCTL_H__
