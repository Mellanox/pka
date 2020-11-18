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

#ifndef PKA_HELPER_H
#define PKA_HELPER_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "pka.h"
#include "pka_utils.h"
#include "pka_vectors.h"

// 64-bit processor
#ifdef BN_ULONG
#define PKA_ULONG   BN_ULONG
#else
#define PKA_ULONG   uint64_t
#endif

#ifdef BN_BYTES
#define PKA_BYTES   BN_BYTES
#else
#define PKA_BYTES   8
#endif

#define PKA_BITS    (PKA_BYTES * 8)

#define PKA_ENGINE_QUEUE_CNT        4
#define PKA_ENGINE_RING_CNT         8

#define PKA_ENGINE_INSTANCE_NAME    "SSL engine"

#define PKA_MAX_OBJS                 32       // 32  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14) // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12) //  4K bytes.

// This encapsulates big number information. This structure enables
// compatibility to OpenSSL
typedef struct {
    PKA_ULONG *d;   // Pointer to an array of 'PKA_BITS' bit chunks.
    int top;        // Index of last used d +1.
    int dmax;       // Size of the d array.
    int neg;        // one if the number is negative.
    int flags;
} pka_bignum_t;

// This encapsulates the engine information. As of now, the PKA library
// does not support mult-processes, a single engine is created. This engine
// allows multiple handlers to share the PKA instance.
typedef struct {
    pka_instance_t instance;
    bool           valid;
} pka_engine_info_t;

// This function implement all the needed PKA initialization, in order to
// enable hardware acceleration. This function is not thread-safe.
int pka_init(void);

// This function releases all the PKA resources previously initialized. This
// function is not thread-safe.
int pka_finish(void);

// This function implements the modular exponentiation using BlueField
// PKA hardware.
int pka_bn_mod_exp(pka_bignum_t *bn_value,
                   pka_bignum_t *bn_exponent,
                   pka_bignum_t *bn_modulus,
                   pka_bignum_t *bn_result);

// This function implements the modular exponentiation with CRT using
// BlueField PKA hardware.
int pka_rsa_mod_exp_crt(pka_bignum_t *bn_value,
                        pka_bignum_t *bn_p,
                        pka_bignum_t *bn_q,
                        pka_bignum_t *bn_d_p,
                        pka_bignum_t *bn_d_q,
                        pka_bignum_t *bn_qinv,
                        pka_bignum_t *bn_result);

// This function implements the elliptic curve point addition using
// Bluefield PKA hardware.
int pka_bn_ecc_pt_add(pka_bignum_t *bn_p,
                      pka_bignum_t *bn_a,
                      pka_bignum_t *bn_b,
                      pka_bignum_t *bn_x1,
                      pka_bignum_t *bn_y1,
                      pka_bignum_t *bn_x2,
                      pka_bignum_t *bn_y2,
                      pka_bignum_t *bn_result_x,
                      pka_bignum_t *bn_result_y);

// This function implements the elliptic curve point multiplication using
// Bluefield PKA hardware.
int pka_bn_ecc_pt_mult(pka_bignum_t *bn_p,
                       pka_bignum_t *bn_a,
                       pka_bignum_t *bn_b,
                       pka_bignum_t *bn_x,
                       pka_bignum_t *bn_y,
                       pka_bignum_t *bn_multiplier,
                       pka_bignum_t *bn_result_x,
                       pka_bignum_t *bn_result_y);

// This function implements the modular inverse using BlueField
// PKA hardware.
int pka_bn_mod_inv(pka_bignum_t *bn_value,
                   pka_bignum_t *bn_modulus,
                   pka_bignum_t *bn_result);

// This function implements the random number generation using BlueField
// PKA hardware.
int pka_get_random_bytes(uint8_t *buf,
                         int      len);

#ifdef  __cplusplus
}
#endif

#endif // PKA_HELPER_H
