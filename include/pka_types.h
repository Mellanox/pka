// SPDX-FileCopyrightText: © 2023 NVIDIA Corporation & affiliates.
// SPDX-License-Identifier: BSD-3-Clause

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
