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

#ifndef __PKA_ADDRS_H__
#define __PKA_ADDRS_H__

// Define memory size in bytes
#define MEM_SIZE_4KB        0x1000
#define MEM_SIZE_8KB        0x2000
#define MEM_SIZE_16KB       0x4000
#define MEM_SIZE_32KB       0x8000
#define MEM_SIZE_64KB       0x10000

//
// COMMON SPACE
//
#define CRYPTO_COMMON_BASE  0x0

// Common IO CSR addresses/offsets: These are all addressed as 8-byte registers.
#define DEV_INFO_ADDR       (0x00 | CRYPTO_COMMON_BASE)
#define DEV_CTL_ADDR        (0x08 | CRYPTO_COMMON_BASE)
#define MMIO_INFO_ADDR      (0x10 | CRYPTO_COMMON_BASE)
#define SCRATCHPAD_ADDR     (0x20 | CRYPTO_COMMON_BASE)
#define SEMAPHORE0_ADDR     (0x28 | CRYPTO_COMMON_BASE)
#define SEMAPHORE1_ADDR     (0x30 | CRYPTO_COMMON_BASE)
#define CLOCK_COUNT_ADDR    (0x38 | CRYPTO_COMMON_BASE)
#define INT_SETUP_ADDR      (0x40 | CRYPTO_COMMON_BASE)
#define CRED_CTL_ADDR       (0x50 | CRYPTO_COMMON_BASE)
#define SAM_CTL_ADDR        (0x58 | CRYPTO_COMMON_BASE)

//
// CRYPTO SPACE
//

// All addresses/offsets herein are BYTE addresses.

// EIP154 CSRS:

// Global Control Space CSR addresses/offsets. These are accessed from the
// ARM as 8 byte reads/writes however only the bottom 32 bits are implemented.
#define PKA_CLOCK_SWITCH_ADDR   0x11C68
#define PKA_CLK_FORCE_ADDR      0x11C80
#define MODE_SELECTION_ADDR     0x11C88
#define PKA_PROT_STATUS_ADDR    0x11C90
#define PKA_OPTIONS_ADDR        0x11DF0
#define PKA_VERSION_ADDR        0x11DF8

// Advanced Interrupt Controller CSR addresses/offsets. These are accessed
// from the ARM as 8 byte reads/writes however only the bottom 32 bits are
// implemented.
#define AIC_POL_CTRL_ADDR       0x11E00
#define AIC_TYPE_CTRL_ADDR      0x11E08
#define AIC_ENABLE_CTRL_ADDR    0x11E10
#define AIC_RAW_STAT_ADDR       0x11E18
#define AIC_ENABLE_SET_ADDR     0x11E18
#define AIC_ENABLED_STAT_ADDR   0x11E20
#define AIC_ACK_ADDR            0x11E20
#define AIC_ENABLE_CLR_ADDR     0x11E28
#define AIC_OPTIONS_ADDR        0x11E30
#define AIC_VERSION_ADDR        0x11E38

// The True Random Number Generator CSR addresses/offsets. These are accessed
// from the ARM as 8 byte reads/writes however only the bottom 32 bits are
// implemented.
#define TRNG_OUTPUT_0_ADDR      0x12000
#define TRNG_OUTPUT_1_ADDR      0x12008
#define TRNG_OUTPUT_2_ADDR      0x12010
#define TRNG_OUTPUT_3_ADDR      0x12018
#define TRNG_STATUS_ADDR        0x12020
#define TRNG_INTACK_ADDR        0x12020
#define TRNG_CONTROL_ADDR       0x12028
#define TRNG_CONFIG_ADDR        0x12030
#define TRNG_ALARMCNT_ADDR      0x12038
#define TRNG_FROENABLE_ADDR     0x12040
#define TRNG_FRODETUNE_ADDR     0x12048
#define TRNG_ALARMMASK_ADDR     0x12050
#define TRNG_ALARMSTOP_ADDR     0x12058
#define TRNG_TEST_ADDR          0x120E0
#define TRNG_BLOCKCNT_ADDR      0x120E8
#define TRNG_OPTIONS_ADDR       0x120F0
#define TRNG_TEST_ADDR          0x120E0
#define TRNG_RAW_L_ADDR         0x12060
#define TRNG_RAW_H_ADDR         0x12068
#define TRNG_RUN_CNT_ADDR       0x12080
#define TRNG_MONOBITCNT_ADDR    0x120B8
#define TRNG_POKER_3_0_ADDR     0x120C0
#define TRNG_POKER_7_4          0x120C8
#define TRNG_POKER_B_8          0x120D0
#define TRNG_POKER_F_C          0x120D8

#define TRNG_PS_AI_0_ADDR       0x12080
#define TRNG_PS_AI_1_ADDR       0x12088
#define TRNG_PS_AI_2_ADDR       0x12090
#define TRNG_PS_AI_3_ADDR       0x12098
#define TRNG_PS_AI_4_ADDR       0x120A0
#define TRNG_PS_AI_5_ADDR       0x120A8
#define TRNG_PS_AI_6_ADDR       0x120B0
#define TRNG_PS_AI_7_ADDR       0x120B8
#define TRNG_PS_AI_8_ADDR       0x120C0
#define TRNG_PS_AI_9_ADDR       0x120C8
#define TRNG_PS_AI_10_ADDR      0x120D0
#define TRNG_PS_AI_11_ADDR      0x120D8

// Control register address/offset. This is accessed from the ARM using 8
// byte reads/writes however only the bottom 32 bits are implemented.
#define PKA_MASTER_SEQ_CTRL_ADDR    0x27F90

// Ring CSRs:  These are all accessed from the ARM using 8 byte reads/writes
// however only the bottom 32 bits are implemented.

// Ring 0 CSRS
#define COMMAND_COUNT_0_ADDR    0x80080
#define RESULT_COUNT_0_ADDR     0x80088
#define IRQ_THRESH_0_ADDR       0x80090

// Ring 1 CSRS:
#define COMMAND_COUNT_1_ADDR    0x90080
#define RESULT_COUNT_1_ADDR     0x90088
#define IRQ_THRESH_1_ADDR       0x90090

// Ring 2 CSRS:
#define COMMAND_COUNT_2_ADDR    0xA0080
#define RESULT_COUNT_2_ADDR     0xA0088
#define IRQ_THRESH_2_ADDR       0xA0090

// Ring 3 CSRS:
#define COMMAND_COUNT_3_ADDR    0xB0080
#define RESULT_COUNT_3_ADDR     0xB0088
#define IRQ_THRESH_3_ADDR       0xB0090

// EIP154 RAM regions: Note that the FARM_PROG_RAM_X address range overlaps
// with the FARM_DATA_RAM_X and FARM_DATA_RAM_X_EXT address ranges.  This
// conflict is resolved by using the FARM_PROG_RAM_X only when the
// Sequencer is in SW reset, and the DATA_RAMs are picked only when the
// engine is operation.
//
//  Note:
//      The FARM_DATA_RAM_X_EXT RAMs may also be
//      called the LNME FIFO RAMs in some of the documentation.
//
//          PKA_BUFFER_RAM        : 1024 x 64  -  8K bytes
//          PKA_SECURE_RAM        : 1536 x 64  - 12K bytes
//          PKA_MASTER_PROG_RAM   : 8192 x 32  - 32K bytes
//          FARM_DATA_RAM_X       : 1024 x 64  -  8K bytes
//          FARM_DATA_RAM_X_EXT   :  256 x 32  -  1K bytes
//          FARM_PROG_RAM_X       : 2048 x 32  -  8K bytes
//
//  Note:
//      *TBD* Since hardware guys multiplied the address per 2, the size of
//      each memory/registers group increased and become two times larger.
//      Memory size should be adjusted accordingly:
//          PKA Buffer RAM size :                8KB  --> 16KB
//          PKA Secure RAM size :                8KB  --> 16KB
//          PKA Master Program RAM size :       32KB  --> 64KB
//          PKA Farm Data RAM size :             4KB  -->  8KB
//          PKA Farm Data RAM extension size :   4KB  -->  8KB
//          PKA Farm Program RAM size :          8KB  --> 16KB
//
#define PKA_BUFFER_RAM_BASE         0x00000
#define PKA_BUFFER_RAM_SIZE         MEM_SIZE_16KB   // 0x00000...0x03FFF

#define PKA_SECURE_RAM_BASE         0x20000
#define PKA_SECURE_RAM_SIZE         MEM_SIZE_16KB   // 0x20000...0x23FFF

#define PKA_MASTER_PROG_RAM_BASE    0x30000
#define PKA_MASTER_PROG_RAM_SIZE    MEM_SIZE_64KB   // 0x30000...0x3FFFF

#define FARM_DATA_RAM_0_BASE        0x40000
#define FARM_DATA_RAM_0_SIZE        MEM_SIZE_8KB    // 0x40000...0x41FFF
#define FARM_DATA_RAM_0_EXT_BASE    0x42000
#define FARM_DATA_RAM_0_EXT_SIZE    MEM_SIZE_8KB    // 0x42000...0x43FFF
#define FARM_PROG_RAM_0_BASE        0x40000
#define FARM_PROG_RAM_0_SIZE        MEM_SIZE_16KB   // 0x40000...0x43FFF
#define FARM_DATA_RAM_1_BASE        0x44000
#define FARM_DATA_RAM_1_SIZE        MEM_SIZE_8KB    // 0x44000...0x45FFF
#define FARM_DATA_RAM_1_EXT_BASE    0x46000
#define FARM_DATA_RAM_1_EXT_SIZE    MEM_SIZE_8KB    // 0x46000...0x47FFF
#define FARM_PROG_RAM_1_BASE        0x44000
#define FARM_PROG_RAM_1_SIZE        MEM_SIZE_16KB   // 0x44000...0x47FFF
#define FARM_DATA_RAM_2_BASE        0x48000
#define FARM_DATA_RAM_2_SIZE        MEM_SIZE_8KB    // 0x48000...0x49FFF
#define FARM_DATA_RAM_2_EXT_BASE    0x4A000
#define FARM_DATA_RAM_2_EXT_SIZE    MEM_SIZE_8KB    // 0x4A000...0x4BFFF
#define FARM_PROG_RAM_2_BASE        0x48000
#define FARM_PROG_RAM_2_SIZE        MEM_SIZE_16KB   // 0x48000...0x4BFFF
#define FARM_DATA_RAM_3_BASE        0x4C000
#define FARM_DATA_RAM_3_SIZE        MEM_SIZE_8KB    // 0x4C000...0x4DFFF
#define FARM_DATA_RAM_3_EXT_BASE    0x4E000
#define FARM_DATA_RAM_3_EXT_SIZE    MEM_SIZE_8KB    // 0x4E000...0x4FFFF
#define FARM_PROG_RAM_3_BASE        0x4C000
#define FARM_PROG_RAM_3_SIZE        MEM_SIZE_16KB   // 0x4C000...0x4FFFF
#define FARM_DATA_RAM_4_BASE        0x50000
#define FARM_DATA_RAM_4_SIZE        MEM_SIZE_8KB    // 0x50000...0x51FFF
#define FARM_DATA_RAM_4_EXT_BASE    0x52000
#define FARM_DATA_RAM_4_EXT_SIZE    MEM_SIZE_8KB    // 0x52000...0x53FFF
#define FARM_PROG_RAM_4_BASE        0x50000
#define FARM_PROG_RAM_4_SIZE        MEM_SIZE_16KB   // 0x50000...0x53FFF
#define FARM_DATA_RAM_5_BASE        0x54000
#define FARM_DATA_RAM_5_SIZE        MEM_SIZE_8KB    // 0x54000...0x55FFF
#define FARM_DATA_RAM_5_EXT_BASE    0x56000
#define FARM_DATA_RAM_5_EXT_SIZE    MEM_SIZE_8KB    // 0x56000...0x57FFF
#define FARM_PROG_RAM_5_BASE        0x54000
#define FARM_PROG_RAM_5_SIZE        MEM_SIZE_16KB   // 0x54000...0x57FFF

// PKA Buffer RAM offsets. These are NOT real CSR's but instead are
// specific offset/addresses within the EIP154 PKA_BUFFER_RAM.

// Ring 0:
#define RING_CMMD_BASE_0_ADDR   0x00000
#define RING_RSLT_BASE_0_ADDR   0x00010
#define RING_SIZE_TYPE_0_ADDR   0x00020
#define RING_RW_PTRS_0_ADDR     0x00028
#define RING_RW_STAT_0_ADDR     0x00030

// Ring 1
#define RING_CMMD_BASE_1_ADDR   0x00040
#define RING_RSLT_BASE_1_ADDR   0x00050
#define RING_SIZE_TYPE_1_ADDR   0x00060
#define RING_RW_PTRS_1_ADDR     0x00068
#define RING_RW_STAT_1_ADDR     0x00070

// Ring 2
#define RING_CMMD_BASE_2_ADDR   0x00080
#define RING_RSLT_BASE_2_ADDR   0x00090
#define RING_SIZE_TYPE_2_ADDR   0x000A0
#define RING_RW_PTRS_2_ADDR     0x000A8
#define RING_RW_STAT_2_ADDR     0x000B0

// Ring 3
#define RING_CMMD_BASE_3_ADDR   0x000C0
#define RING_RSLT_BASE_3_ADDR   0x000D0
#define RING_SIZE_TYPE_3_ADDR   0x000E0
#define RING_RW_PTRS_3_ADDR     0x000E8
#define RING_RW_STAT_3_ADDR     0x000F0

// Ring Options
#define PKA_RING_OPTIONS_ADDR   0x07FF8

// Alternate Window RAM size
#define PKA_WINDOW_RAM_REGION_SIZE  MEM_SIZE_16KB

// Currently, we do not use these MiCA specific CSRs.
// The PKI (not EIP154) CSR address/offsets: These are all addressed as
// 8-byte registers.
#define PKA_INT_MASK_ADDR           0x00
#define PKA_INT_MASK_SET_ADDR       0x08
#define PKA_INT_MASK_RESET_ADDR     0x10
#define PKA_ZEROIZE_ADDR            0x40
#define TST_FRO_ADDR                0x50
#define FRO_COUNT_ADDR              0x58
#define PKA_PARITY_CTL_ADDR         0x60
#define PKA_PARITY_STAT_ADDR        0x68

#endif // __PKA_ADDRS_H__
