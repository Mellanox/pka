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

#ifndef __PKA_TYPES_H__
#define __PKA_TYPES_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

typedef enum { SUCCESS, FAILURE }    pka_status_t;

/// PKA error codes.
/// This enumeration lists the error codes returned by the main API functions.
typedef enum
{
    PKA_NO_ERROR                =     0,  ///< Successful return code.
    PKA_OPERAND_MISSING         = -1500,  ///< operand missing
    PKA_OPERAND_BUF_MISSING     = -1501,  ///< operand buf is NULL
    PKA_OPERAND_LEN_ZERO        = -1502,  ///< operand len is 0
    PKA_OPERAND_LEN_TOO_SHORT   = -1503,  ///< operand len is too short for op
    PKA_OPERAND_LEN_TOO_LONG    = -1504,  ///< operand len is too long for op
    PKA_OPERAND_LEN_A_LT_LEN_B  = -1505,  ///< operand ordering error
    PKA_OPERAND_VAL_GE_MODULUS  = -1506,  ///< value operand is >= modulus
    PKA_OPERAND_Q_GE_OPERAND_P  = -1507,  ///< q operand is >= p operand
    PKA_OPERAND_MODULUS_IS_EVEN = -1508,  ///< modulus must be odd for this op
    PKA_RESULT_MUST_BE_POSITIVE = -1509,  ///< all result big integers >= 0
    PKA_OPERAND_FIFO_FULL       = -1510,  ///< operand request fifo full
    PKA_CMD_RING_FULL           = -1511,  ///< cmd request fifo full
    PKA_DRIVER_TOO_BUSY         = -1512,  ///< PKA driver backlog too large
    PKA_BAD_OPERAND_CNT         = -1513,  ///< wrong operand_cnt for cmd
    PKA_TRY_GET_RESULTS_FAILED  = -1514,  ///< try found result fifo empty
    PKA_TRY_GET_RANDOM_FAILED   = -1515,  ///< random number fifo empty
    PKA_RESULT_BUF_NULL         = -1516,  ///< result buf ptr is NULL
    PKA_RESULT_BUF_TOO_SMALL    = -1517,  ///< result buf_len too small
    PKA_BAD_RESULT_IDX          = -1518,  ///< bad rsult_idx
    PKA_RESULT_FIFO_EMPTY       = -1519,  ///< result fifo empty
    PKA_CURVE_TYPE_INVALID      = -1520   ///< Invalid curve type
} pka_ret_code_t;

/// The pka_comparison_t enumeration is the result type for internal comparison.
typedef enum
{
    PKA_NO_COMPARE,
    PKA_LESS_THAN,
    PKA_EQUAL,
    PKA_GREATER_THAN
} pka_comparison_t;

#endif // __PKA_TYPES_H__
