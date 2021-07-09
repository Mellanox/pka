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

#ifndef __PKA_CONFIG_H__
#define __PKA_CONFIG_H__

#include "pka_addrs.h"

// The maximum number of PKA shims refered to as IO blocks.
#define PKA_MAX_NUM_IO_BLOCKS           24
// The maximum number of Rings supported by IO block (shim).
#define PKA_MAX_NUM_IO_BLOCK_RINGS      4

#define PKA_MAX_NUM_RINGS \
    (PKA_MAX_NUM_IO_BLOCK_RINGS * PKA_MAX_NUM_IO_BLOCKS)

// Bitmask to represent rings, grouped into 8 bit (uint8_t) blocks.
#define PKA_RING_NUM_BITMASK \
    ((PKA_MAX_NUM_RINGS / 8) + 1)

// Resources are regions which include info control/status words,
// count registers and host window ram.
#define PKA_MAX_NUM_RING_RESOURCES      3

// PKA Ring resources.
// Define Ring resources parameters including base address, size (in bytes)
// and ring spacing.
#define PKA_RING_WORDS_ADDR         PKA_BUFFER_RAM_BASE
#define PKA_RING_CNTRS_ADDR         COMMAND_COUNT_0_ADDR

#define PKA_RING_WORDS_SIZE         0x40        // 64 bytes
#define PKA_RING_CNTRS_SIZE         0x20        // 32 bytes (3 count registers)
#define PKA_RING_MEM_SIZE           0x4000      // 16K bytes

#define PKA_RING_WORDS_SPACING      0x40        // 64  bytes
#define PKA_RING_CNTRS_SPACING      0x10000     // 64K bytes
#define PKA_RING_MEM_0_SPACING      0x4000      // 16K bytes
#define PKA_RING_MEM_1_SPACING      0x10000     // 64K bytes

// PKA Window RAM parameters.
// Define whether to split or not Window RAM during PKA device creation phase.
#define SPLIT_WINDOW_RAM_MODE_ENABLED        1
#define SPLIT_WINDOW_RAM_MODE_DISABLED       0
#define PKA_SPLIT_WINDOW_RAM_MODE            SPLIT_WINDOW_RAM_MODE_DISABLED
// Defines for Window RAM partition. It is valid for 16K memory.
#define PKA_WINDOW_RAM_RING_MEM_SIZE         0x0800 //  2KB
#define PKA_WINDOW_RAM_DATA_MEM_SIZE         0x3800 // 14KB

// Window RAM/Alternate Window RAM  offset mask for BF1 and BF2
#define PKA_WINDOW_RAM_OFFSET_MASK1       0x730000

// Window RAM/Alternate Window RAM offset mask for BF3
#define PKA_WINDOW_RAM_OFFSET_MASK2       0x70000

// Macro for mapping PKA Ring address into Window RAM address. It converts the
// ring address, either physical address or virtual address, to valid address
// into the Window RAM. This is done assuming the Window RAM base, size and
// mask. Here, base is the actual physical address of the Window RAM, with the
// help of mask it is reduced to Window RAM offset within that PKA block.
// Further, with the help of addr and size, we arrive at the Window RAM
// offset address for a PKA Ring within the given Window RAM.
#define PKA_RING_MEM_ADDR(base, mask, addr, size) \
    ((base & mask) | (((addr) & 0xffff) | \
        ((((addr) & ~((size) - 1)) & 0xf0000) >> 2)))

// PKA Master Sequencer Control/Status Register
//  Write '1' to bit [31] puts the Master controller Sequencer in a reset
//  reset state. Resetting the Sequencer (in order to load other firmware)
//  should only be done when the EIP-154 is not performing any operations.
#define PKA_MASTER_SEQ_CTRL_RESET_VAL           0x80000000
//  Write '1' to bit [30] will reset all Command and Result counters. This
//  bit is write-only and self clearing and can only be set if the ‘Reset’
//  bit [31] is ‘1’.
#define PKA_MASTER_SEQ_CTRL_CLEAR_COUNTERS_VAL  0x40000000
//  Bit [8] in the PKA Master Sequencer Control/Status Register is tied to
//  the 'pka_master_irq interrupt' on the EIP-154 interrupt controller.
#define PKA_MASTER_SEQ_CTRL_MASTER_IRQ_BIT      8
//  Sequencer status bits are used by the Master controller Sequencer to
//  reflect status. Bit [0] is tied to the 'pka_master_irq' interrupt on
//  the EIP-154 interrupt controller.
#define PKA_MASTER_SEQ_CTRL_STATUS_BYTE         0x01
// 'pka_master_irq' mask for the Master controller Sequencer Status Register.
#define PKA_MASTER_SEQ_CTRL_MASTER_IRQ_MASK     0x100

// Advanced Interrupt Controller (AIC) configuration
//  AIC Polarity Control Register is used to set each individual interrupt
//  signal (High Level / Rising Edge) during the initialization phase.
//   '0' = Low level or falling edge.
//   '1' = High level or rising edge.
#define PKA_AIC_POL_CTRL_REG_VAL                0x000FFFFF
//  AIC Type Control Register is used to set each interrupt to level or edge.
//   '0' = Level.
//   '1' = Edge.
#define PKA_AIC_TYPE_CTRL_REG_VAL               0x000FFFFF
//  AIC Enable Control Register is used to enable interrupt inputs.
//   '0' = Disabled.
//   '1' = Enabled.
#define PKA_AIC_ENABLE_CTRL_REG_VAL             0x000F030F
//  AIC Enabled Status Register bits reflect the status of the interrupts
//  gated with the enable bits of the AIC_ENABLE_CTRL Register.
//   '0' = Inactive.
//   '1' = Pending.
#define PKA_AIC_ENABLE_STAT_REG_VAL             0x000F030F

// 'pka_master_irq' mask for the AIC Enabled Status Register.
#define PKA_AIC_ENABLED_STAT_MASTER_IRQ_MASK    0x100

// PKA_RING_OPTIONS field to specify the priority in which rings are handled:
//  '00' = full rotating priority,
//  '01' = fixed priority (ring 0 lowest),
//  '10' = ring 0 has the highest priority and the remaining rings have
//         rotating priority,
//  '11' = reserved, do not use.
#define PKA_FULL_ROTATING_PRIORITY              0x0
#define PKA_FIXED_PRIORITY                      0x1
#define PKA_RING_0_HAS_THE_HIGHEST_PRIORITY     0x2
#define PKA_RESERVED                            0x3
#define PKA_RING_OPTIONS_PRIORITY               PKA_FULL_ROTATING_PRIORITY

// 'Signature' byte used because the ring options are transferred through RAM
// which does not have a defined reset value.  The EIP-154  master controller
// keeps reading the  PKA_RING_OPTIONS word at start-up until the ‘Signature’
// byte contains 0x46 and the ‘Reserved’ field contains zero.
#define PKA_RING_OPTIONS_SIGNATURE_BYTE         0x46

// Order of the result reporting: Two schemas are available:
//  InOrder    - This means that the results will be reported in the same order
//               as the commands were provided.
//  OutOfOrder - This means that the results are reported as soon as they are
//               available
#define PKA_RING_TYPE_IN_ORDER_BIT          1
#define PKA_RING_TYPE_OUT_OF_ORDER_BIT      0
#define PKA_RING_TYPE_IN_ORDER              PKA_RING_TYPE_OUT_OF_ORDER_BIT

// Byte order of the data written/read to/from Rings.
//  Little Endian (LE) - The least significant bytes have the lowest address.
//  Big    Endian (BE) - The most significant bytes come first.
#define PKA_RING_BYTE_ORDER_LE              0
#define PKA_RING_BYTE_ORDER_BE              1
#define PKA_RING_BYTE_ORDER                 PKA_RING_BYTE_ORDER_LE

// 'trng_clk_on' mask for PKA Clock Switch Forcing Register. Turn on the
// TRNG clock. When the TRNG is controlled via the Host slave interface,
// this engine needs to be turned on by setting bit 11.
#define PKA_CLK_FORCE_TRNG_ON               0x800

// Number of TRNG Output registers
#define PKA_TRNG_OUTPUT_CNT                 4

// TRNG Configuration
#define PKA_TRNG_CONFIG_REG_VAL             0x00020008
// TRNG Alarm Counter Register Value
#define PKA_TRNG_ALARMCNT_REG_VAL           0x000200FF
// TRNG FRO Enable Register Value
#define PKA_TRNG_FROENABLE_REG_VAL          0x00FFFFFF
// TRNG Control Register Value; Set bit 10 to start the EIP-76 a.k.a TRNG
// engine, gathering entropy from the FROs.
#define PKA_TRNG_CONTROL_REG_VAL            0x00000400

// TRNG Control bit
#define PKA_TRNG_CONTROL_TEST_MODE          0x100

// TRNG Control Register Value; Set bit 10 and 12 to start the EIP-76 a.k.a TRNG
// engine with DRBG enabled, gathering entropy from the FROs.
#define PKA_TRNG_CONTROL_DRBG_REG_VAL       0x00001400

// DRBG enabled TRNG 'request_data' value. REQ_DATA_VAL (in accordance with
// DATA_BLOCK_MASK) requests 256 blocks of 128-bit random output.
// 4095 blocks is the max number that can be requested for the TRNG(with DRBG)
// configuration on Bluefield platforms.
#define PKA_TRNG_CONTROL_REQ_DATA_VAL       0x10010000

// Mask for 'Data Block' in TRNG Control Register.
#define PKA_TRNG_DRBG_DATA_BLOCK_MASK       0xfff00000

// Set bit 12 of TRNG Control Register to enable DRBG functionality.
#define PKA_TRNG_CONTROL_DRBG_ENABLE_VAL    0x00001000

// Set bit 8 a.ka 'test_sp_800_90 DRBG' bit in the TRNG Test Register.
#define PKA_TRNG_TEST_DRBG_VAL              0x00000080

// Number of Personalization String/Additional Input Registers
#define PKA_TRNG_PS_AI_REG_COUNT            12

// DRBG Reseed enable
#define PKA_TRNG_CONTROL_DRBG_RESEED        0x00008000

// TRNG Status bits
#define PKA_TRNG_STATUS_READY               0x1
#define PKA_TRNG_STATUS_SHUTDOWN_OFLO       0x2
#define PKA_TRNG_STATUS_TEST_READY          0x100
#define PKA_TRNG_STATUS_MONOBIT_FAIL        0x80
#define PKA_TRNG_STATUS_RUN_FAIL            0x10
#define PKA_TRNG_STATUS_POKER_FAIL          0x40

// TRNG Alarm Counter bits
#define PKA_TRNG_ALARMCNT_STALL_RUN_POKER   0x8000

// TRNG Test bits
#define PKA_TRNG_TEST_KNOWN_NOISE           0x20
#define PKA_TRNG_TEST_NOISE                 0x2000

#endif // __PKA_CONFIG_H__
