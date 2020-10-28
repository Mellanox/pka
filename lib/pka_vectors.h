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

#ifndef __PKA_VECTORS_H__
#define __PKA_VECTORS_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include "pka.h"
#include "pka_types.h"

// EIP-154 maximum operand lengths in 4-byte words:
#define MAX_GEN_VEC_SZ         258
#define MAX_MODEXP_CRT_VEC_SZ  130
#define MAX_ECC_VEC_SZ          24

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
