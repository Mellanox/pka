// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_DEV_H__
#define __PKA_DEV_H__

///
/// @file
///
/// API to handle the PKA EIP-154 I/O block (shim).  It provides functions
/// and data structures to initialize and configure the PKA shim. It's the
/// "southband interface" for communication with PKA hardware resources.
///

#ifdef __KERNEL__
#include <linux/mutex.h>
#include <linux/types.h>
#include "pka_firmware.h"
#else
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#endif

#include <linux/vfio.h>


#include "pka_ring.h"
#include "pka_utils.h"

#define PKA_SYSFS_RING_DEVICES      "/sys/bus/platform/devices"
#define PKA_VFIO_DIR                "/dev/vfio"
#define PKA_VFIO_CONTAINER_PATH     "/dev/vfio/vfio"
#define PKA_VFIO_GROUP_FMT          "/dev/vfio/%d"

#define PKA_DEVFS_RING_DEVICES      "/dev/pka/%d"

// Defines specific to device-tree and Linux operating system.
// Careful, all constants MUST be conform with both devicetree
// (DTS) and ACPI tables (SSDT).
// *TBD* Better to be detected automatically (or passed as arg
//       so far).
#define PKA_DEV_RING_DT_PREFIX_0        "45000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_1        "47000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_2        "4d000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_3        "4f000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_4        "44000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_5        "46000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_6        "4c000000.eip154:ring@%d"
#define PKA_DEV_RING_DT_PREFIX_7        "4e000000.eip154:ring@%d"

#define PKA_DEV_RING_ACPI_PREFIX        "MLNXBF11:%02x"

/// Device resource structure
typedef struct
{
    void    *ioaddr;         ///< (iore)mapped version of addr, for
                             ///  driver internal use.

    uint64_t base;           ///< base address of the device's
                             ///  resource

    uint64_t size;           ///< size of IO

    uint8_t  type;           ///< type of resource addr points to
    int8_t   status;         ///< status of the resource

    char    *name;           ///< name of the resource
} pka_dev_res_t;

/// defines for pka_dev_res->type
#define PKA_DEV_RES_TYPE_MEM            1   // resource type is memory
#define PKA_DEV_RES_TYPE_REG            2   // resource type is register

/// defines for pka_dev_res->status
#define PKA_DEV_RES_STATUS_MAPPED       1   // the resource is (iore)-mapped
#define PKA_DEV_RES_STATUS_UNMAPPED    -1   // the resource is unmapped

/// PKA Ring resources structure
typedef struct
{
    pka_dev_res_t   info_words;     // ring information words
    pka_dev_res_t   counters;       // ring counters
    pka_dev_res_t   window_ram;     // window RAM
} pka_dev_ring_res_t;

typedef struct pka_dev_shim_s pka_dev_shim_t;

/// PKA Ring structure
typedef struct
{
    uint32_t                ring_id;        ///< ring identifier.

    pka_dev_shim_t         *shim;           ///< pointer to the shim associated
                                            ///  to the ring.

    uint32_t                resources_num;  ///< number of ring resources.
    pka_dev_ring_res_t      resources;      ///< ring resources.

    pka_dev_hw_ring_info_t *ring_info;      ///< ring information.
    uint32_t                num_cmd_desc;   ///< number of command descriptors.

    int8_t                  status;         ///< status of the ring.

#ifdef __KERNEL__
    struct mutex            mutex;          ///< mutex lock for sharing ring device
#endif
} pka_dev_ring_t;

/// defines for pka_dev_ring->status
#define PKA_DEV_RING_STATUS_UNDEFINED   -1
#define PKA_DEV_RING_STATUS_INITIALIZED  1
#define PKA_DEV_RING_STATUS_READY        2
#define PKA_DEV_RING_STATUS_BUSY         3
#define PKA_DEV_RING_STATUS_FINALIZED    4

/// PKA Shim resources structure
typedef struct
{
    pka_dev_res_t    buffer_ram;        // buffer RAM
    pka_dev_res_t    master_prog_ram;   // master controller program RAM
    pka_dev_res_t    master_seq_ctrl;   // master sequencer controller CSR
    pka_dev_res_t    aic_csr;           // interrupt controller CSRs
    pka_dev_res_t    trng_csr;          // TRNG module CSRs
    pka_dev_res_t    ext_csr;           // MiCA specific CSRs (glue logic)
} pka_dev_shim_res_t;

#define PKA_DEV_SHIM_RES_CNT         6  // Number of PKA device resources

/// Platform global shim resource information
typedef struct
{
    pka_dev_res_t *res_tbl[PKA_DEV_SHIM_RES_CNT];
    uint8_t        res_cnt;
} pka_dev_gbl_shim_res_info_t;

struct pka_dev_mem_res
{
    uint64_t eip154_base;         ///< base address for eip154 mmio registers
    uint64_t eip154_size;         ///< eip154 mmio register region size

    uint64_t wndw_ram_off_mask;   ///< common offset mask for alt window ram and window ram
    uint64_t wndw_ram_base;       ///< base address for window ram
    uint64_t wndw_ram_size;       ///< window ram region size

    uint64_t alt_wndw_ram_0_base; ///< base address for alternate window ram 0
    uint64_t alt_wndw_ram_1_base; ///< base address for alternate window ram 1
    uint64_t alt_wndw_ram_2_base; ///< base address for alternate window ram 2
    uint64_t alt_wndw_ram_3_base; ///< base address for alternate window ram 3
    uint64_t alt_wndw_ram_size;   ///< alternate window ram regions size

    uint64_t csr_base;            ///< base address for csr registers
    uint64_t csr_size;            ///< csr area size
};

/// PKA Shim structure
struct pka_dev_shim_s
{
    struct pka_dev_mem_res mem_res;

    uint64_t               trng_err_cycle;    ///< TRNG error cycle

    uint32_t               shim_id;           ///< shim identifier

    uint32_t               rings_num;         ///< Number of supported rings (hw
                                              ///  specific)

    pka_dev_ring_t       **rings;             ///< pointer to rings which belong to
                                              ///  the shim.

    uint8_t                ring_priority;     ///< specify the priority in which
                                              ///  rings are handled.

    uint8_t                ring_type;         ///< indicates whether the result
                                              ///  ring delivers results strictly
                                              ///  in-order.

    pka_dev_shim_res_t     resources;         ///< shim resources

    uint8_t                window_ram_split;  ///< Window RAM mode. if non-zero,
                                              ///  the splitted window RAM scheme
                                              ///  is used.

    uint32_t               busy_ring_num;     ///< Number of active rings (rings in
                                              ///  busy state)

    uint8_t                trng_enabled;      ///< Whether the TRNG engine is
                                              ///  enabled.

    int8_t                 status;            ///< status of the shim

#ifdef __KERNEL__
    struct mutex           mutex;             ///< mutex lock for sharing shim
#endif
};

/// defines for pka_dev_shim->status
#define PKA_SHIM_STATUS_UNDEFINED          -1
#define PKA_SHIM_STATUS_CREATED             1
#define PKA_SHIM_STATUS_INITIALIZED         2
#define PKA_SHIM_STATUS_RUNNING             3
#define PKA_SHIM_STATUS_STOPPED             4
#define PKA_SHIM_STATUS_FINALIZED           5

/// defines for pka_dev_shim->window_ram_split
#define PKA_SHIM_WINDOW_RAM_SPLIT_ENABLED   1   // window RAM is splitted into
                                                // 4 * 16KB blocks

#define PKA_SHIM_WINDOW_RAM_SPLIT_DISABLED  2   // window RAM is not splitted
                                                // and occupies 64KB

/// defines for pka_dev_shim->trng_enabled
#define PKA_SHIM_TRNG_ENABLED               1
#define PKA_SHIM_TRNG_DISABLED              0

/// Platform global configuration structure
typedef struct
{
    uint32_t         dev_shims_cnt;     ///< number of registered PKA shims.
    uint32_t         dev_rings_cnt;     ///< number of registered Rings.

    pka_dev_shim_t  *dev_shims[PKA_MAX_NUM_IO_BLOCKS]; ///< table of registered
                                                       ///  PKA shims.

    pka_dev_ring_t  *dev_rings[PKA_MAX_NUM_RINGS];     ///< table of registered
                                                       ///  Rings.
} pka_dev_gbl_config_t;

extern pka_dev_gbl_config_t pka_gbl_config;

#ifndef __KERNEL__
/// Return ring information and initialize ring descriptors.
int pka_dev_get_ring_info(pka_ring_info_t *ring_info);

/// Return true if there is an available ring, false if not. This function
/// verifies if there is a free ring which can be used. It returns true if
/// true, otherwise it returns false. The input parameter rings_num refers
/// to the number of rings to look for.
bool pka_dev_has_avail_ring(pka_ring_info_t *ring_info,
                            uint32_t         rings_num);
#endif

#ifdef __KERNEL__

/// Ring getter for pka_dev_gbl_config_t structure which holds all system
/// global configuration. This configuration is shared and common to kernel
/// device driver associated with PKA hardware.
pka_dev_ring_t *pka_dev_get_ring(uint32_t ring_id);

/// Shim getter for pka_dev_gbl_config_t structure which holds all system
/// global configuration. This configuration is shared and common to kernel
/// device driver associated with PKA hardware.
pka_dev_shim_t *pka_dev_get_shim(uint32_t shim_id);

/// Register a Ring. This function initializes a Ring and configures its
/// related resources, and returns a pointer to that ring.
pka_dev_ring_t *pka_dev_register_ring(uint32_t ring_id, uint32_t shim_id);

/// Unregister a Ring
int pka_dev_unregister_ring(pka_dev_ring_t *ring);

/// Register PKA IO block. This function initializes a shim and configures its
/// related resources, and returns a pointer to that ring.
pka_dev_shim_t *pka_dev_register_shim(uint32_t shim_id, uint8_t shim_fw_id,
                                      struct pka_dev_mem_res *mem_res);

/// Unregister PKA IO block
int pka_dev_unregister_shim(pka_dev_shim_t *shim);

/// Reset a Ring.
int pka_dev_reset_ring(pka_dev_ring_t *ring);

/// Clear ring counters. This function resets the master sequencer controller
/// to clear the command and result counters.
int pka_dev_clear_ring_counters(pka_dev_ring_t *ring);

/// Read data from the TRNG. Drivers can fill up to 'cnt' bytes of data into
/// the buffer 'data'. The buffer 'data' is aligned for any type and 'cnt' is
/// a multiple of 4.
int pka_dev_trng_read(pka_dev_shim_t *shim, uint32_t *data, uint32_t cnt);

/// Return true if the TRNG engine is enabled, false if not.
bool pka_dev_has_trng(pka_dev_shim_t *shim);

#endif // __KERNEL__

/// Open the file descriptor associated with ring. It returns an integer value,
/// which is used to refer to the file. If unsuccessful, it returns a negative
/// error.
int pka_dev_open_ring(pka_ring_info_t *ring_info);

/// Close the file descriptor associated with ring. The function returns 0 if
/// successful, negative value to indicate an error.
int pka_dev_close_ring(pka_ring_info_t *ring_info);

/// Map ring resources.
int pka_dev_mmap_ring(pka_ring_info_t *ring_info);

/// Unmap ring resources.
int pka_dev_munmap_ring(pka_ring_info_t *ring_info);

#endif /// __PKA_DEV_H__
