// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef __PKA_VECTORS_H__
#define __PKA_VECTORS_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include "pka.h"
#include "pka_types.h"

// EIP-154 maximum operand lengths in bytes:
#define MAX_GEN_VEC_SZ         (258 * 4)
#define MAX_MODEXP_CRT_VEC_SZ  (130 * 4)
#define MAX_ECC_VEC_SZ         ( 24 * 4)

// The following maximum lengths are deliberately a little larger than the
// actual HW limits above so as to allow for algorithms that might have
// intermediate
#define MAX_BUF     (260 * 4)  // EIP154 max byte length is actually 258 * 4
#define MAX_ECC_BUF (25  * 4)  // EIP154 max ECC  length is actually  24 * 4

/// The pka_operands_t record type is used to package the entire set of
/// input operands (big integers) of a single crypto operation.
typedef struct  // 4 + (16 * 11) = 180 bytes long
{
    uint8_t       operand_cnt;                ///< Number of valid operands.
    uint8_t       shift_amount;               ///< Holds the shift amount arg.
    uint8_t       encrypt_results[2];         ///< Reserved for future use.
    pka_operand_t operands[MAX_OPERAND_CNT];  ///< Actual operand descriptors.
} pka_operands_t;

typedef struct
{
    pka_operand_t p;
    pka_operand_t q;
    pka_operand_t g;
} dsa_domain_params_t;

typedef struct
{
    pka_operand_t *modulus;
    pka_operand_t *private;
    pka_operand_t *public;

    pka_operand_t *p;
    pka_operand_t *q;
    pka_operand_t *dp;
    pka_operand_t *dq;
    pka_operand_t *qInv;
} rsa_system_t;

#endif // __PKA_VECTORS_H__
