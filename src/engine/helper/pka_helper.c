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

#include <stdio.h>
#include <string.h>

#include "pka_helper.h"

#define return_if_instance_invalid(inst)                    \
({                                                          \
    if ((inst) == PKA_INSTANCE_INVALID || (inst) ==0)       \
    {                                                       \
        DEBUG(PKA_D_ERROR, "PKA instance is invalid\n");    \
        return 0;                                           \
    }                                                       \
})

#define return_if_handle_invalid(hdl)                       \
({                                                          \
    if ((hdl) == PKA_HANDLE_INVALID || (hdl) == 0)          \
    {                                                       \
        DEBUG(PKA_D_ERROR, "PKA handle is invalid\n");      \
        return 0;                                           \
    }                                                       \
})

#define set_pka_instance(eng, inst) \
    ({ ((pka_engine_info_t *) (eng))->instance = (inst); })

#define reset_pka_instance(inst) \
    ({ (inst) = PKA_INSTANCE_INVALID; })

#define reset_pka_handle(hdl) \
    ({ (hdl) = PKA_HANDLE_INVALID; })

#define handle_is_valid(hdl) \
    ((hdl) != PKA_HANDLE_INVALID && (hdl) != 0)

// The actual engine that provides PKA support. For now, a single process
// is allowed.
static pka_engine_info_t gbl_engine;

// When running over multiple threads, a handle must be assigned per thread.
static __thread pka_handle_t tls_handle;

static uint32_t gbl_engine_init;
static uint32_t gbl_engine_finish;

#define DEBUG_MODE    0xf
#define PKA_D_ERROR   0x1
#define PKA_D_INFO    0x8

#define DEBUG(level, fmt_and_args...)           \
({                                              \
    if (level & DEBUG_MODE)                     \
        PKA_PRINT(PKA_ENGINE, fmt_and_args);    \
})

static void copy_operand(pka_operand_t *src, pka_operand_t *dst)
{
    PKA_ASSERT(src != NULL);
    PKA_ASSERT(dst != NULL);

    dst->actual_len = src->actual_len;
    dst->big_endian = src->big_endian;
    memcpy(dst->buf_ptr, src->buf_ptr, src->actual_len);
}

static void operand_byte_copy(pka_operand_t *operand,
                              uint8_t       *buf_ptr,
                              uint32_t       buf_len)
{
    PKA_ASSERT(operand != NULL);
    PKA_ASSERT(buf_ptr != NULL);
    PKA_ASSERT(buf_len <= operand->buf_len);
    operand->actual_len = buf_len;

    // BIG ASSUMPTION: OpenSSL treats all series of bytes (unsigned char
    //                 arrays) depending on the underlying architecture.
    //                 Since we are running in Little endian, no need to
    //                 swap bytes while copying buffers.
    memcpy(operand->buf_ptr, buf_ptr, buf_len);
}

static pka_operand_t *make_operand(PKA_ULONG *bn_buf_ptr,
                                   uint32_t   buf_len,
                                   uint32_t   buf_max_len,
                                   uint8_t    big_endian)
{
    pka_operand_t *operand;

    if (!bn_buf_ptr || (buf_max_len == 0))
        return NULL;

    operand = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->big_endian = big_endian;

    // Now init the operand buffer
    operand->buf_ptr    = malloc(buf_max_len);
    operand->buf_len    = buf_max_len;
    memset(operand->buf_ptr, 0, buf_max_len);

    // Now fill the operand buf.
    operand_byte_copy(operand, (uint8_t *) bn_buf_ptr, buf_len);

    return operand;
}

static pka_operand_t *bignum_to_operand(pka_bignum_t *bignum)
{
    uint32_t byte_len, byte_max_len;

    if (bignum)
    {
        byte_len     = bignum->top  * PKA_BYTES;
        byte_max_len = bignum->dmax * PKA_BYTES;

        return make_operand(bignum->d, byte_len, byte_max_len, 0);
    }

    return NULL;
}

static pka_operand_t *malloc_operand(uint32_t buf_len)
{
    pka_operand_t *operand;

    operand             = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->buf_ptr    = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = 0;

    return operand;
}

static void free_operand(pka_operand_t *operand)
{
    uint8_t *buf_ptr;

    if (operand == NULL)
        return;

    buf_ptr = operand->buf_ptr;

    if (buf_ptr != NULL)
        free(buf_ptr);

    free(operand);
}

#ifdef VERBOSE_MODE
static uint32_t operand_byte_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;

    byte_len = operand->actual_len;
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return byte_len;

        // Move forwards over all zero bytes.
        while ((1 <= byte_len) && (byte_ptr[0] == 0))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len;

        while ((1 <= byte_len) && (byte_ptr[0] == 0))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    return byte_len;
}

static void print_operand(char *prefix, pka_operand_t *operand, char *suffix)
{
    uint32_t byte_len, byte_cnt, byte_idx;
    uint8_t *byte_ptr;

    if (prefix != NULL)
        printf("%s", prefix);

    byte_len = operand_byte_len(operand);
    printf("0x");
    if ((byte_len == 0) || ((byte_len == 1) && (operand->buf_ptr[0] == 0)))
        printf("0");
    else
    {
        byte_idx = (operand->big_endian) ? 0 : byte_len - 1;
        byte_ptr = &operand->buf_ptr[byte_idx];
        for (byte_cnt = 0; byte_cnt < byte_len; byte_cnt++)
            printf("%02X", (operand->big_endian) ?
                    *byte_ptr++ : *byte_ptr--);
    }

    if (suffix != NULL)
        printf("%s", suffix);
}
#endif

static void pka_wait_for_results(pka_handle_t handle, pka_results_t *results)
{
    // *TBD*
    // This is weak! We should define a timer here, so that we don't
    // get stuck indefinitely when the test fails to retrieve a result.
    while (true)
    {
        if (!pka_get_result(handle, results))
            break;

        // Wait for a short while (~50 cycles) between attempts to get
        // the result
        pka_wait();
    }
}

static void init_results_operand(pka_results_t *results,
                                 uint32_t       result_cnt,
                                 uint8_t       *res1_buf,
                                 uint32_t       res1_len,
                                 uint8_t       *res2_buf,
                                 uint32_t       res2_len)
{
    pka_operand_t *result_ptr;

    PKA_ASSERT(result_cnt <= MAX_RESULT_CNT);
    results->result_cnt = result_cnt;

    switch (result_cnt) {
    case 2:
        PKA_ASSERT(res2_buf   != NULL);
        result_ptr             = &results->results[1];
        result_ptr->buf_ptr    = res2_buf;
        memset(result_ptr->buf_ptr, 0, res2_len);
        result_ptr->buf_len    = res2_len;
        result_ptr->actual_len = 0;
        // fall-through
    case 1:
        PKA_ASSERT(res1_buf   != NULL);
        result_ptr             = &results->results[0];
        result_ptr->buf_ptr    = res1_buf;
        memset(result_ptr->buf_ptr, 0, res1_len);
        result_ptr->buf_len    = res1_len;
        result_ptr->actual_len = 0;
    default:
        return;
    }
}

static pka_operand_t *results_to_operand(pka_handle_t handle)
{
    pka_results_t  results;
    pka_operand_t *result_ptr;
    uint32_t       result_len;
    uint8_t        res1[MAX_BYTE_LEN];

    memset(&results, 0, sizeof(pka_results_t));
    init_results_operand(&results, 1, res1, MAX_BYTE_LEN, NULL, 0);

    pka_wait_for_results(handle, &results);
    if (results.status != RC_NO_ERROR)
    {
        PKA_ERROR(PKA_TESTS, "pka_get_result status=0x%x\n", results.status);
        return NULL;
    }

    result_len = results.results[0].actual_len;
    result_ptr = malloc_operand(result_len);
    copy_operand(&results.results[0], result_ptr);
    return result_ptr;
}

static void set_bignum(pka_bignum_t *bn, pka_operand_t *operand)
{
    uint32_t word_len;
    uint16_t len;

    if (!operand || !bn)
        return;

    len      = operand->actual_len;
    word_len = (len + (PKA_BYTES - 1)) / PKA_BYTES;
    PKA_ASSERT(bn->dmax >= word_len);
    bn->top = word_len;
    bn->neg = 0;

    // BIG ASSUMPTION: OpenSSL treats all series of bytes (unsigned char
    //                 arrays) depending on the underlying architecture.
    //                 Since we are running in Little endian, no need to
    //                 swap bytes while copying buffers.
    memcpy(bn->d, operand->buf_ptr, len);
}

//
// Synchronous PKA implementation
//

static pka_operand_t *pka_do_mod_exp(pka_handle_t   handle,
                                     pka_operand_t *value,
                                     pka_operand_t *exponent,
                                     pka_operand_t *modulus)
{
    int rc;

    PKA_ASSERT(value    != NULL);
    PKA_ASSERT(exponent != NULL);
    PKA_ASSERT(modulus  != NULL);

    rc = pka_modular_exp(handle, NULL, exponent, modulus, value);

    if (SUCCESS != rc)
    {
        DEBUG(PKA_D_ERROR, "pka_modular_exp failed, rc=%d\n", rc);
#ifdef VERBOSE_MODE
        print_operand("  value   =", value,    "\n");
        print_operand("  exponent=", exponent, "\n");
        print_operand("  modulus =", modulus,  "\n");
#endif
        return NULL;
    }

    return results_to_operand(handle);
}

static pka_operand_t *pka_do_mod_exp_crt(pka_handle_t   handle,
                                         pka_operand_t *value,
                                         pka_operand_t *p,
                                         pka_operand_t *q,
                                         pka_operand_t *d_p,
                                         pka_operand_t *d_q,
                                         pka_operand_t *qinv)
{
    int rc;

    rc = pka_modular_exp_crt(handle, NULL, value, p, q, d_p, d_q, qinv);

    if (SUCCESS != rc)
    {
        DEBUG(PKA_D_ERROR, "pka_modular_exp_crt failed, rc=%d\n", rc);
#ifdef VERBOSE_MODE
        print_operand("  value   =", value, "\n");
        print_operand("  p       =", p,     "\n");
        print_operand("  q       =", q,     "\n");
        print_operand("  d_p     =", d_p,   "\n");
        print_operand("  d_q     =", d_q,   "\n");
        print_operand("  qinv    =", qinv,  "\n");
#endif
        return NULL;
    }

    return results_to_operand(handle);
}

//
// Engine helper functions
//

// This functions creates a PKA handle to be used by the engine. Retruns 1
// on success, 0 on failure.
static int pka_engine_get_handle(pka_engine_info_t *engine)
{
    pka_handle_t *handle = &tls_handle;

    PKA_ASSERT(engine != NULL);

    return_if_instance_invalid(engine->instance);

    if (handle_is_valid(*handle))
        return 1;

    reset_pka_handle(*handle);

    // Init PK local execution context.
    *handle = pka_init_local(engine->instance);
    return_if_handle_invalid(*handle);

    return 1;
}

// This functions releases the PKA handle associated with the engine.
static void pka_engine_put_handle(pka_engine_info_t *engine)
{
    pka_handle_t *handle = &tls_handle;

    PKA_ASSERT(engine != NULL);

    if (handle_is_valid(*handle))
        pka_term_local(*handle);

    reset_pka_handle(*handle);
}

// This functions creates a PKA instance to be used by the engine. Retruns 1
// on success, 0 on failure.
static int pka_engine_get_instance(pka_engine_info_t *engine)
{
    pka_instance_t  instance;
    uint32_t        cmd_queue_sz, rslt_queue_sz;
    uint8_t         queue_cnt, ring_cnt, flags;

    PKA_ASSERT(engine   != NULL);

    if (!engine->valid)
    {
        // Init the PKA instance before calling anything else
        flags         = PKA_F_PROCESS_MODE_MULTI | PKA_F_SYNC_MODE_ENABLE;
        ring_cnt      = PKA_ENGINE_RING_CNT;
        queue_cnt     = PKA_ENGINE_QUEUE_CNT;
        cmd_queue_sz  = PKA_MAX_OBJS * PKA_CMD_DESC_MAX_DATA_SIZE;
        rslt_queue_sz = PKA_MAX_OBJS * PKA_RSLT_DESC_MAX_DATA_SIZE;
        instance      = pka_init_global(PKA_ENGINE_INSTANCE_NAME,
                                        flags,
                                        ring_cnt,
                                        queue_cnt,
                                        cmd_queue_sz,
                                        rslt_queue_sz);
        set_pka_instance(engine, instance);
        return_if_instance_invalid(engine->instance);
    }

    return 1;
}

// This functions releases the PKA instance associated with the engine.
static void pka_engine_put_instance(pka_engine_info_t *engine)
{
    PKA_ASSERT(engine != NULL);

    pka_term_global(engine->instance);
    reset_pka_instance(engine->instance);
}

// This function resets a crypto engine.
static void pka_reset_engine(pka_engine_info_t *engine)
{
    memset(engine, 0, sizeof(pka_engine_info_t));
    reset_pka_instance(engine->instance);
}

// This function returns a valid crypto engine. Otherwise, NULL pointer, if
// there is no valid engine. During the first call, the function retrives
// valid instance and handles to be used by the engine. This function is not
// thread-safe.
static pka_engine_info_t* pka_get_engine(void)
{
    pka_engine_info_t *engine = &gbl_engine;

    if (!engine->valid)
    {
        pka_reset_engine(engine);

        if (!pka_engine_get_instance(engine))
        {
            DEBUG(PKA_D_ERROR, "failed to retrieve valid instance\n");
            return NULL;
        }

        // Mark the PKA engine as valid and return
        engine->valid = true;
    }

    if (!pka_engine_get_handle(engine))
        DEBUG(PKA_D_ERROR, "failed to retrieve valid handle\n");

    return engine;
}

// This function removes a crypto engine and releases its associated instance
// and handles. This function is not thread-safe.
static void pka_put_engine(void)
{
    pka_engine_info_t *engine = &gbl_engine;

    if (!engine->valid)
        return;

    pka_engine_put_handle(engine);
    pka_engine_put_instance(engine);
    engine->valid = false;
}

// This function initializes a crypto engine. Retruns 1 on success, 0 on
// failure.
static int pka_init_engine(void)
{
    pka_engine_info_t *engine;

    engine = pka_get_engine();
    return (engine) ? 1 : 0;
}

// This releases a crypto engine.
static void pka_release_engine(void)
{
    return pka_put_engine();
}

//
// API
//

int pka_rsa_mod_exp(pka_bignum_t *bn_value,
                    pka_bignum_t *bn_exponent,
                    pka_bignum_t *bn_modulus,
                    pka_bignum_t *bn_result)
{
    pka_operand_t     *value, *exponent, *modulus, *result;
    int                rc;

    PKA_ASSERT(bn_value    != NULL);
    PKA_ASSERT(bn_exponent != NULL);
    PKA_ASSERT(bn_modulus  != NULL);
    PKA_ASSERT(bn_result   != NULL);

    return_if_handle_invalid(tls_handle);

    value    = bignum_to_operand(bn_value);
    exponent = bignum_to_operand(bn_exponent);
    modulus  = bignum_to_operand(bn_modulus);

    result = pka_do_mod_exp(tls_handle, value, exponent, modulus);
    if (result) {
        set_bignum(bn_result, result);
        rc = 1;
    } else
        rc = 0;

    free_operand(value);
    free_operand(exponent);
    free_operand(modulus);
    free_operand(result);

    return rc;
}

int pka_rsa_mod_exp_crt(pka_bignum_t  *bn_value,
                        pka_bignum_t  *bn_p,
                        pka_bignum_t  *bn_q,
                        pka_bignum_t  *bn_d_p,
                        pka_bignum_t  *bn_d_q,
                        pka_bignum_t  *bn_qinv,
                        pka_bignum_t  *bn_result)
{
    pka_operand_t     *value, *p, *q, *d_q, *d_p, *qinv, *result;
    int                rc;

    PKA_ASSERT(bn_value  != NULL);
    PKA_ASSERT(bn_p      != NULL);
    PKA_ASSERT(bn_q      != NULL);
    PKA_ASSERT(bn_d_p    != NULL);
    PKA_ASSERT(bn_d_q    != NULL);
    PKA_ASSERT(bn_qinv   != NULL);
    PKA_ASSERT(bn_result != NULL);

    return_if_handle_invalid(tls_handle);

    value = bignum_to_operand(bn_value);
    p     = bignum_to_operand(bn_p);
    q     = bignum_to_operand(bn_q);
    d_p   = bignum_to_operand(bn_d_p);
    d_q   = bignum_to_operand(bn_d_q);
    qinv  = bignum_to_operand(bn_qinv);

    result = pka_do_mod_exp_crt(tls_handle, value, p, q, d_p, d_q, qinv);
    if (result) {
        set_bignum(bn_result, result);
        rc = 1;
    } else
        rc = 0;

    free_operand(value);
    free_operand(p);
    free_operand(q);
    free_operand(d_p);
    free_operand(d_q);
    free_operand(qinv);
    free_operand(result);

    return rc;
}

int pka_init(void)
{
    int ret;

    if (__sync_bool_compare_and_swap(&gbl_engine_init, 1, 1))
        return 1; // Engine already exist.

    ret = pka_init_engine();
    if (ret != 0)
        __sync_fetch_and_add(&gbl_engine_init, 1);

    return ret;
}

int pka_finish(void)
{
    if (__sync_bool_compare_and_swap(&gbl_engine_finish, 0, 0))
    {
        pka_release_engine();
        __sync_fetch_and_add(&gbl_engine_finish, 1);
    }

    return 1;
}
