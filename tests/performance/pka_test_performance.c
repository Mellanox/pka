#define _GNU_SOURCE

#include <sched.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include "pka_test_utils.h"

#define MAX_NUM_TESTS   1000
#define MAX_THREADS     (MAX_CPU_NUMBER - 1)

#define MAX_RINGS       PKA_MAX_NUM_RINGS

typedef struct
{
    uint32_t thread_idx;
    uint32_t cpu_number;
} thread_arg_t;

typedef struct
{
    pka_handle_t    handle;
    uint16_t       *randomize_tests;
    test_stats_t   *test_desc_stats;

    test_stats_t    thread_stats;
    uint64_t        thread_cycles;
    uint64_t        create_cycles;
    uint64_t        init_cycles;
    uint64_t        start_cycles;
    uint64_t        end_cycles;
    uint64_t        final_cycles;
} thread_state_t;

typedef struct
{
    uint32_t      user_data_idx;
    uint32_t      thread_idx;

    test_desc_t  *test_desc;
    test_stats_t *test_desc_stats;
    uint64_t      start_time;  // time is measured in current clock cycles
    uint32_t      test_idx;
    bool          multi_submit;
    bool          first_submit;
} user_data_t;

static const uint32_t DEFAULT_BIT_LEN[] =
{
    [TEST_NOP] = 0,

    // Basic_pka_tests.  These use NO associated PKA key_system_t object.
    [TEST_ADD ... TEST_MOD_INVERT] = 1024,

    // Modular exponentiation tests.  These use the mod_exp_key_system_t.
    [TEST_MOD_EXP] = 1024,

    // RSA tests.  These use the rsa_key_system_t.
    [TEST_RSA_MOD_EXP ... TEST_RSA_MOD_EXP_WITH_CRT] = 1024,

    // Montgomery ECDH tests.  These use the mont_ecdh_keys_t.
    [TEST_MONT_ECDH_MULTIPLY] = 255,

    // Ecc tests.  These use the ecc_key_system_t.
    [TEST_ECC_ADD ... TEST_ECC_MULTIPLY] = 256,

    // Montgomery Ecdh tests.  These use the mont_ecdh_keys_t.
    [TEST_MONT_ECDH ... TEST_MONT_ECDHE] = 255,

    // Ecdh tests.  These use the ecdh_key_system_t.
    [TEST_ECDH ... TEST_ECDHE] = 256,

    // Ecdsa tests.  These use the ecdsa_key_system_t.
    [TEST_ECDSA_GEN ... TEST_ECDSA_GEN_VERIFY] = 256,

    // Dsa tests.  These use the dsa_key_system_t.
    [TEST_DSA_GEN ... TEST_DSA_GEN_VERIFY] = 1024
};

static pka_instance_t pka_test_instance;

static uint32_t        num_of_threads;
static uint32_t        cmds_outstanding;
static uint32_t        submits_per_test;
static uint8_t         num_of_rings;
static bool            check_results;
static bool            report_thread_stats;
static bool            big_endian;
static bool            help;
static pka_test_kind_t test_kind;

static test_desc_t *test_descs[MAX_NUM_TESTS];
static uint32_t     num_tests;

static thread_state_t thread_states[MAX_THREADS];
static pthread_t      threads[MAX_THREADS];
static thread_arg_t   thread_args[MAX_THREADS];

static uint32_t overall_cmds_done   = 0;
static uint32_t overall_bad_results = 0;
static uint64_t overall_start_time;
static uint64_t overall_end_time;
static uint64_t main_init1_cycles;
static uint64_t  main_pre_barrier;
static uint64_t cpu_freq;   // cycles per second.

static test_stats_t overall_test_stats;

static uint32_t verbosity = 0;

static pka_barrier_t thread_start_barrier;
static pka_barrier_t thread_end_barrier;

static __pka_inline uint64_t pka_get_ticks(void)
{
    uint64_t tick_cnt64;

    // Read counter
    asm volatile("mrs %0, cntvct_el0" : "=r" (tick_cnt64));
    return tick_cnt64;
}

#define pm_enable() do {} while(0)
#define pm_disable() do {} while(0)
#define pka_get_cycle_cnt() pka_get_ticks()
#define pka_get_cpu_freq()  pka_get_hz_ticks()

#define PKA_MAX_OBJS                16          // 16  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14)   // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12)   //  4K bytes.

// Get rid of path in filename
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
                strrchr((file_name), '/') + 1 : (file_name))

// *TBD*
// DMB - Data Memory Barrier acts as a memory barrier. It ensures that all
// explicit memory accesses that appear in program order before the DMB
// instruction are observed before any explicit memory accesses that appear
// in program order after the DMB instruction. It does not affect the ordering
// of any other instructions executing on the processor.
//
// Permitted values of option are:
//
// SY       Full system DMB operation. This is the default and can be omitted.
// ST       DMB operation that waits only for stores to complete.
// ISH      DMB operation only to the inner shareable domain.
// ISHST    DMB operation that waits only for stores to complete, and only to
//          the inner shareable domain.
// NSH      DMB operation only out to the point of unification.
// NSHST    DMB operation that waits only for stores to complete and only out
//          to the point of unification.
// OSH      DMB operation only to the outer shareable domain.
// OSHST    DMB operation that waits only for stores to complete, and only to
//          the outer shareable domain.
//
// ISB - Instruction Synchronization Barrier flushes the pipeline in the
// processor, so that all instructions following the ISB are fetched from
// cache or memory, after the instruction has been completed. It ensures that
// the effects of context altering operations, such as changing the ASID, or
// completed TLB maintenance operations, or branch predictor maintenance
// operations, as well as all changes to the CP15 registers, executed before
// the ISB instruction are visible to the instructions fetched after the ISB.
// In addition, the ISB instruction ensures that any branches that appear in
// program order after it are always written into the branch prediction logic
// with the context that is visible after the ISB instruction. This is
// required to ensure correct execution of the instruction stream.
//
// Permitted values of option are:
//
// SY       Full system ISB operation. This is the default, and can be omitted.
//
#define isb(opt)     ({ asm volatile("isb " #opt : : : "memory"); })
static __pka_inline void pka_mf(void)
{
    isb(sy);
}

uint64_t isqrt(uint64_t num)
{
    uint64_t result, bit;
    uint32_t bitNum;

    bitNum = 63 - __builtin_clz(num);
    if (num < 4)
        return 1;

    // "bit" starts at the highest power of four <= the argument.
    bit = 1UL << (bitNum & 0x3E);
    result = 0;

    while (bit != 0)
    {
        if (num >= (result + bit))
        {
            num   -= result + bit;
            result = (result >> 1) + bit;
        }
        else
            result >>= 1;

        bit >>= 2;
    }

    return result;
}

static __pka_noinline void busy_delay(void)
{
    uint32_t cnt;

    // Wait for ~300 cycles.
    for (cnt = 1;  cnt < 50;  cnt++)
        pka_cpu_relax();
}

static pka_status_t submit_basic_test(pka_handle_t  handle,
                                      user_data_t  *user_data_ptr,
                                      test_desc_t  *test_desc,
                                      uint32_t      test_idx)
{
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_result_code_t  rc;
    test_basic_t      *basic;

    test_kind = (pka_test_kind_t *) test_desc->test_kind;
    basic     = (test_basic_t    *) test_desc->test_operands;
    test_name = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s\n", test_idx,
               test_name_to_string(test_name));
        if ((test_name == TEST_SHIFT_LEFT) ||
            (test_name == TEST_SHIFT_RIGHT))
        {
            print_operand("first  = ", basic->first,  "\n");
            printf       ("shift  = %u\n", basic->shift_cnt);
        }
        else
        {
            print_operand("first  = ", basic->first,  "\n");
            print_operand("second = ", basic->second, "\n");
        }
    }

    switch (test_name)
    {
    case TEST_ADD:
        rc = pka_add(handle, user_data_ptr, basic->first, basic->second);
        break;

    case TEST_SUBTRACT:
        rc = pka_subtract(handle, user_data_ptr, basic->first,
                            basic->second);
        break;

    case TEST_MULTIPLY:
        rc = pka_multiply(handle, user_data_ptr, basic->first,
                            basic->second);
        break;

    case TEST_DIVIDE:
    case TEST_DIV_MOD:
        rc = pka_divide(handle, user_data_ptr, basic->first,
                            basic->second);
        break;

    case TEST_MODULO:
        rc = pka_modulo(handle, user_data_ptr, basic->first,
                            basic->second);
        break;

    case TEST_MOD_INVERT:
        rc = pka_modular_inverse(handle, user_data_ptr, basic->first,
                                    basic->second);
        break;

    case TEST_SHIFT_LEFT:
        rc = pka_shift_left(handle, user_data_ptr, basic->first,
                                basic->shift_cnt);
        break;

    case TEST_SHIFT_RIGHT:
        rc = pka_shift_right(handle, user_data_ptr, basic->first,
                                basic->shift_cnt);
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_mod_exp_test(pka_handle_t  handle,
                                        user_data_t  *user_data_ptr,
                                        test_desc_t  *test_desc,
                                        uint32_t      test_idx)
{
    mod_exp_key_system_t *mod_exp_keys;
    pka_test_kind_t      *test_kind;
    pka_test_name_t       test_name;
    test_mod_exp_t       *test_mod_exp;
    pka_result_code_t     rc;

    test_kind     = (pka_test_kind_t      *) test_desc->test_kind;
    mod_exp_keys  = (mod_exp_key_system_t *) test_desc->key_system;
    test_mod_exp  = (test_mod_exp_t       *) test_desc->test_operands;
    test_name     = test_kind->test_name;
    PKA_ASSERT (test_name == TEST_MOD_EXP);

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s\n", test_idx,
                test_name_to_string(test_name));
        print_operand("base     = ", test_mod_exp->base,     "\n");
        print_operand("exponent = ", test_mod_exp->exponent, "\n");
        print_operand("modulus  = ", mod_exp_keys->modulus,  "\n");
    }

    // Modular exponentiation tests.  These use the mod_exp_key_system_t.
    rc = pka_modular_exp(handle, user_data_ptr, test_mod_exp->exponent,
                          mod_exp_keys->modulus, test_mod_exp->base);
    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
                test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_rsa_test(pka_handle_t  handle,
                                    user_data_t  *user_data_ptr,
                                    test_desc_t  *test_desc,
                                    uint32_t      test_idx)
{
    rsa_key_system_t  *rsa_keys;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_result_code_t  rc;
    test_rsa_t        *test_rsa;

    test_kind = (pka_test_kind_t  *) test_desc->test_kind;
    rsa_keys  = (rsa_key_system_t *) test_desc->key_system;
    test_rsa  = (test_rsa_t       *) test_desc->test_operands;
    test_name = test_kind->test_name;

    if (3 <= verbosity)
        printf("\nRunning test_idx=%u test_name=%s\n", test_idx,
                test_name_to_string(test_name));

    switch (test_name)
    {
    case TEST_RSA_MOD_EXP:
        if (3 <= verbosity)
        {
            print_operand("base     = ", test_rsa->msg,         "\n");
            print_operand("exponent = ", rsa_keys->private_key, "\n");
            print_operand("modulus  = ", rsa_keys->n,           "\n");
        }

        rc = pka_rsa(handle, user_data_ptr, rsa_keys->private_key,
                        rsa_keys->n, test_rsa->msg);
        break;

    case TEST_RSA_VERIFY:
        if (3 <= verbosity)
        {
            print_operand("base     = ", test_rsa->msg,        "\n");
            print_operand("exponent = ", rsa_keys->public_key, "\n");
            print_operand("modulus  = ", rsa_keys->n,          "\n");
        }

        rc = pka_rsa(handle, user_data_ptr, rsa_keys->public_key,
                        rsa_keys->n, test_rsa->msg);
        break;

    case TEST_RSA_MOD_EXP_WITH_CRT:
        if (3 <= verbosity)
        {
            print_operand("msg      = ", test_rsa->msg,  "\n");
            print_operand("d_p      = ", rsa_keys->d_p,  "\n");
            print_operand("d_q      = ", rsa_keys->d_q,  "\n");
            print_operand("p        = ", rsa_keys->p,    "\n");
            print_operand("q        = ", rsa_keys->q,    "\n");
            print_operand("qinv     = ", rsa_keys->qinv, "\n");
            print_operand("p * q    = ", rsa_keys->n,    "\n");
        }

        rc = pka_rsa_crt(handle, user_data_ptr, rsa_keys->p, rsa_keys->q,
                            test_rsa->msg, rsa_keys->d_p, rsa_keys->d_q,
                                    rsa_keys->qinv);
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_mont_ecc_test(pka_handle_t  handle,
                                         user_data_t  *user_data_ptr,
                                         test_desc_t  *test_desc,
                                         uint32_t      test_idx)
{
    pka_result_code_t  rc;
    mont_ecdh_keys_t  *ecdh_keys;
    ecc_mont_curve_t  *curve;
    test_mont_ecdh_t  *ecdh_test;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_operand_t     *point_x, *multiplier;

    test_kind  = (pka_test_kind_t  *) test_desc->test_kind;
    ecdh_keys  = (mont_ecdh_keys_t *) test_desc->key_system;
    ecdh_test  = (test_mont_ecdh_t *) test_desc->test_operands;
    curve      = ecdh_keys->curve;
    point_x    = ecdh_test->point_x;
    multiplier = ecdh_test->multiplier;
    test_name  = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s\n", test_idx,
               test_name_to_string(test_name));
        print_operand("curve->p     = ", &curve->p,  "\n");
        print_operand("curve->A     = ", &curve->A,  "\n");
        print_operand("point_x      = ", point_x,    "\n");
        print_operand("multiplier   = ", multiplier, "\n");
    }

    PKA_ASSERT(test_name == TEST_MONT_ECDH_MULTIPLY);
    rc = pka_mont_ecdh_mult(handle, user_data_ptr, curve, point_x, multiplier);
    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_ecc_test(pka_handle_t  handle,
                                    user_data_t  *user_data_ptr,
                                    test_desc_t  *test_desc,
                                    uint32_t      test_idx)
{
    ecc_key_system_t  *ecc_keys;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_result_code_t  rc;
    ecc_curve_t       *curve;
    ecc_point_t       *pointA;
    test_ecc_t        *ecc_test;

    test_kind = (pka_test_kind_t  *) test_desc->test_kind;
    ecc_keys  = (ecc_key_system_t *) test_desc->key_system;
    ecc_test  = (test_ecc_t       *) test_desc->test_operands;
    curve     = ecc_keys->curve;
    pointA    = ecc_test->pointA;
    test_name = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s\n", test_idx,
                test_name_to_string(test_name));
        print_operand("curve->p     = ", &curve->p,  "\n");
        print_operand("curve->a     = ", &curve->a,  "\n");
        print_operand("curve->b     = ", &curve->b,  "\n");
        print_operand("pointA->x    = ", &pointA->x, "\n");
        print_operand("pointA->y    = ", &pointA->y, "\n");
    }

    switch (test_name)
    {
    case TEST_ECC_ADD:
        if (3 <= verbosity)
        {
            print_operand("pointB->x    = ", &ecc_test->pointB->x, "\n");
            print_operand("pointB->y    = ", &ecc_test->pointB->y, "\n");
        }

        rc = pka_ecc_pt_add(handle, user_data_ptr, curve, pointA,
                              ecc_test->pointB);
        break;

    case TEST_ECC_DOUBLE:
        rc = pka_ecc_pt_add(handle, user_data_ptr, curve, pointA, pointA);
        break;

    case TEST_ECC_MULTIPLY:
        if (3 <= verbosity)
            print_operand("multiplier   = ", ecc_test->multiplier, "\n");

        rc = pka_ecc_pt_mult(handle, user_data_ptr, curve, pointA,
                                ecc_test->multiplier);
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
                test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_mont_ecdh_test(pka_handle_t  handle,
                                          user_data_t  *user_data_ptr,
                                          test_desc_t  *test_desc,
                                          uint32_t      test_idx,
                                          bool          first_submit)
{
    pka_result_code_t  rc;
    mont_ecdh_keys_t  *keys;
    ecc_mont_curve_t  *curve;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_operand_t     *base_pt_order, *local_private_key;
    test_mont_ecdh_t  *ecdh_test;
    pka_operand_t     *base_pt_x, *remote_public_key, *local_public_key;

    test_kind         = (pka_test_kind_t  *) test_desc->test_kind;
    keys              = (mont_ecdh_keys_t *) test_desc->key_system;
    ecdh_test         = (test_mont_ecdh_t *) test_desc->test_operands;
    curve             = keys->curve;
    base_pt_x         = keys->base_pt_x;
    base_pt_order     = keys->base_pt_order;
    remote_public_key = ecdh_test->remote_public_key;
    test_name         = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s first_submit=%s\n", test_idx,
               test_name_to_string(test_name), first_submit ? "true" : "false");
        print_operand("curve->p             = ", &curve->p,         "\n");
        print_operand("curve->A             = ", &curve->A,         "\n");
        print_operand("base_pt->x           = ", base_pt_x,         "\n");
        print_operand("base_pt_order        = ", base_pt_order,     "\n");
        print_operand("remote_public_key->x = ", remote_public_key, "\n");
    }

    switch (test_name)
    {
    case TEST_MONT_ECDH:
        local_private_key = ecdh_test->remote_private_key;
        local_public_key  = ecdh_test->remote_public_key;

        if (3 <= verbosity)
        {
            print_operand("local_private_key->x = ", local_private_key, "\n");
            print_operand("local_public_key->x  = ", local_public_key,  "\n");
        }

        rc = pka_mont_ecdh(handle, user_data_ptr, curve, remote_public_key,
                           local_private_key);
        break;

    case TEST_MONT_ECDHE:
        if (first_submit)
        {
            // Need to create a new "ephemeral" local private key and use that
            // to calculate and send the corresponding local public key to the
            // other side.
            local_private_key = rand_non_zero_integer(handle, base_pt_order);
            ecdh_test->local_private_key = local_private_key;

            rc = pka_mont_ecdh(handle, user_data_ptr, curve, base_pt_x,
                               local_private_key);
        }
        else
        {
            local_private_key = ecdh_test->local_private_key;
            local_public_key  = ecdh_test->local_public_key;

            if (3 <= verbosity)
            {
                print_operand("local_private_key    = ", local_private_key,
                              "\n");
                print_operand("local_public_key->x  = ", local_public_key,
                              "\n");
            }

            // Now determine the shared secret by multiplying the remote public
            // key by our newly created local private key.
            rc = pka_mont_ecdh(handle, user_data_ptr, curve, remote_public_key,
                               local_private_key);
        }
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_ecdh_test(pka_handle_t  handle,
                                     user_data_t  *user_data_ptr,
                                     test_desc_t  *test_desc,
                                     uint32_t      test_idx,
                                     bool          first_submit)
{
    ecdh_key_system_t *keys;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_result_code_t  rc;
    pka_operand_t     *base_pt_order, *local_private_key;
    test_ecdh_t       *ecdh_test;
    ecc_curve_t       *curve;
    ecc_point_t       *base_pt, *remote_public_key, *local_public_key;

    test_kind         = (pka_test_kind_t   *) test_desc->test_kind;
    keys              = (ecdh_key_system_t *) test_desc->key_system;
    ecdh_test         = (test_ecdh_t       *) test_desc->test_operands;
    curve             = keys->curve;
    base_pt           = keys->base_pt;
    base_pt_order     = keys->base_pt_order;
    remote_public_key = ecdh_test->remote_public_key;
    test_name         = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s first_submit=%s\n", test_idx,
               test_name_to_string(test_name), first_submit ? "true" : "false");
        print_operand("curve->p             = ", &curve->p,             "\n");
        print_operand("curve->a             = ", &curve->a,             "\n");
        print_operand("curve->b             = ", &curve->b,             "\n");
        print_operand("base_pt->x           = ", &base_pt->x,           "\n");
        print_operand("base_pt->y           = ", &base_pt->y,           "\n");
        print_operand("base_pt_order        = ", base_pt_order,         "\n");
        print_operand("remote_public_key->x = ", &remote_public_key->x, "\n");
        print_operand("remote_public_key->y = ", &remote_public_key->y, "\n");
    }

    switch (test_name)
    {
    case TEST_ECDH:
        local_private_key = keys->private_key;
        local_public_key  = keys->public_key;

        if (3 <= verbosity)
        {
            print_operand("local_private_key    = ", local_private_key,   "\n");
            print_operand("local_public_key->x  = ", &local_public_key->x, "\n");
            print_operand("local_public_key->y  = ", &local_public_key->y, "\n");
        }

        rc = pka_ecdh(handle, user_data_ptr, curve, remote_public_key,
                      local_private_key);
        break;

    case TEST_ECDHE:
        if (first_submit)
        {
            // Need to create a new "ephemeral" local private key and use that
            // to calculate and send the corresponding local public key to the
            // other side.
            local_private_key = rand_non_zero_integer(handle, base_pt_order);
            ecdh_test->local_private_key = local_private_key;

            rc = pka_ecdh(handle, user_data_ptr, curve, base_pt,
                          local_private_key);
        }
        else
        {
            local_private_key = ecdh_test->local_private_key;
            local_public_key  = ecdh_test->local_public_key;

            if (3 <= verbosity)
            {
                print_operand("local_private_key    = ", local_private_key,
                                "\n");
                print_operand("local_public_key->x  = ", &local_public_key->x,
                                "\n");
                print_operand("local_public_key->y  = ", &local_public_key->y,
                                "\n");
            }

            // Now determine the shared secret by multiplying the remote public
            // key by our newly created local private key.
            rc = pka_ecdh(handle, user_data_ptr, curve,
                          remote_public_key, local_private_key);
        }
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_ecdsa_test(pka_handle_t  handle,
                                      user_data_t  *user_data_ptr,
                                      test_desc_t  *test_desc,
                                      uint32_t      test_idx,
                                      bool          first_submit)
{
    ecdsa_key_system_t *keys;
    dsa_signature_t    *signature;
    pka_test_kind_t    *test_kind;
    pka_test_name_t     test_name;
    pka_result_code_t   rc;
    pka_operand_t      *base_pt_order, *hash;
    test_ecdsa_t       *ecdsa_test;
    ecc_curve_t        *curve;
    ecc_point_t        *base_pt;

    test_kind     = (pka_test_kind_t    *) test_desc->test_kind;
    keys          = (ecdsa_key_system_t *) test_desc->key_system;
    ecdsa_test    = (test_ecdsa_t       *) test_desc->test_operands;
    curve         = keys->curve;
    base_pt       = keys->base_pt;
    base_pt_order = keys->base_pt_order;
    hash          = ecdsa_test->hash;
    test_name     = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s first_submit=%s\n", test_idx,
               test_name_to_string(test_name), first_submit ? "true" : "false");
        print_operand("curve->p      = ", &curve->p,      "\n");
        print_operand("curve->a      = ", &curve->a,      "\n");
        print_operand("curve->b      = ", &curve->b,      "\n");
        print_operand("base_pt->x    = ", &base_pt->x,    "\n");
        print_operand("base_pt->y    = ", &base_pt->y,    "\n");
        print_operand("base_pt_order = ", base_pt_order, "\n");
        print_operand("hash          = ", hash,          "\n");
    }

    switch (test_name)
    {
    case TEST_ECDSA_GEN:
        if (3 <= verbosity)
        {
            print_operand("private_key   = ", keys->private_key, "\n");
            print_operand("k             = ", ecdsa_test->k,     "\n");
        }

        rc = pka_ecdsa_signature_generate(handle, user_data_ptr,
                                          curve, base_pt, base_pt_order,
                                          keys->private_key, ecdsa_test->hash,
                                          ecdsa_test->k);
        break;

    case TEST_ECDSA_VERIFY:
        signature = ecdsa_test->answer;
        if (3 <= verbosity)
        {
            print_operand("public_key->x = ", &keys->public_key->x, "\n");
            print_operand("public_key->y = ", &keys->public_key->y, "\n");
            print_operand("signature->r  = ", &signature->r,        "\n");
            print_operand("signature->s  = ", &signature->s,        "\n");
        }

        rc = pka_ecdsa_signature_verify(handle, user_data_ptr, curve,
                                            base_pt, base_pt_order,
                                            keys->public_key, hash,
                                            signature, 0); // write-back
        break;

    case TEST_ECDSA_GEN_VERIFY:
        if (first_submit)
        {
            if (3 <= verbosity)
            {
                print_operand("private_key   = ", keys->private_key, "\n");
                print_operand("k             = ", ecdsa_test->k,     "\n");
            }

            rc = pka_ecdsa_signature_generate(handle, user_data_ptr,
                                              curve, base_pt, base_pt_order,
                                              keys->private_key,
                                              ecdsa_test->hash,
                                              ecdsa_test->k);
        }
        else
        {
            signature = ecdsa_test->signature;
            if (3 <= verbosity)
            {
                print_operand("public_key->x = ", &keys->public_key->x, "\n");
                print_operand("public_key->y = ", &keys->public_key->y, "\n");
                print_operand("signature->r  = ", &signature->r,        "\n");
                print_operand("signature->s  = ", &signature->s,        "\n");
            }

            rc = pka_ecdsa_signature_verify(handle, user_data_ptr, curve,
                                            base_pt, base_pt_order,
                                            keys->public_key, hash,
                                            signature, 0); // write-back
        }
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static pka_status_t submit_dsa_test(pka_handle_t  handle,
                                user_data_t      *user_data_ptr,
                                test_desc_t      *test_desc,
                                uint32_t          test_idx,
                                bool              first_submit)
{
    dsa_key_system_t  *keys;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    dsa_signature_t   *signature;
    pka_result_code_t  rc;
    test_dsa_t        *dsa_test;

    test_kind = (pka_test_kind_t  *) test_desc->test_kind;
    keys      = (dsa_key_system_t *) test_desc->key_system;
    dsa_test  = (test_dsa_t       *) test_desc->test_operands;
    test_name = test_kind->test_name;

    if (3 <= verbosity)
    {
        printf("\nRunning test_idx=%u test_name=%s first_submit=%s\n", test_idx,
               test_name_to_string(test_name), first_submit ? "true" : "false");
        print_operand("p            = ", keys->p,        "\n");
        print_operand("q            = ", keys->q,        "\n");
        print_operand("g            = ", keys->g,        "\n");
        print_operand("hash         = ", dsa_test->hash, "\n");
    }

    switch (test_name)
    {
    case TEST_DSA_GEN:
        if (3 <= verbosity)
        {
            print_operand("private_key  = ", keys->private_key, "\n");
            print_operand("k            = ", dsa_test->k,       "\n");
        }

        rc = pka_dsa_signature_generate(handle, user_data_ptr,
                            keys->p, keys->q, keys->g,
                            keys->private_key, dsa_test->hash, dsa_test->k);
        break;

    case TEST_DSA_VERIFY:
        signature = dsa_test->answer;
        if (3 <= verbosity)
        {
            print_operand("public_key   = ", keys->private_key, "\n");
            print_operand("signature->r = ", &signature->r,     "\n");
            print_operand("signature->s = ", &signature->s,     "\n");
        }

        rc = pka_dsa_signature_verify(handle, user_data_ptr, keys->p, keys->q,
                                 keys->g, keys->public_key, dsa_test->hash,
                                 signature, 0);
        break;

    case TEST_DSA_GEN_VERIFY:
        if (first_submit)
        {
            if (3 <= verbosity)
            {
                print_operand("private_key   = ", keys->private_key, "\n");
                print_operand("k             = ", dsa_test->k,     "\n");
            }

            rc = pka_dsa_signature_generate(handle, user_data_ptr,
                                            keys->p, keys->q, keys->g,
                                            keys->private_key, dsa_test->hash,
                                            dsa_test->k);
        }
        else
        {
            signature = dsa_test->signature;
            if (3 <= verbosity)
            {
                print_operand("signature->r  = ", &signature->r,        "\n");
                print_operand("signature->s  = ", &signature->s,        "\n");
            }

            rc = pka_dsa_signature_verify(handle, user_data_ptr, keys->p,
                                          keys->q, keys->g, keys->public_key,
                                          dsa_test->hash, signature, 0);
        }
        break;

    default:
        PKA_ASSERT(false);
    }

    if (rc != RC_NO_ERROR)
    {
        printf("Bad submit test_name=%s rc=%d\n",
               test_name_to_string(test_name), rc);
        return FAILURE;
    }

    return SUCCESS;
}

static __pka_noinline pka_status_t submit_pka_test(pka_handle_t  handle,
                                                   user_data_t  *user_data_ptr,
                                                   bool          first_submit)
{
    pka_test_name_t  test_name;
    pka_test_kind_t *test_kind;
    test_stats_t    *test_stats;
    test_desc_t     *test_desc;
    uint32_t         test_idx;
    pka_status_t     status;

    test_idx   = user_data_ptr->test_idx;
    test_desc  = user_data_ptr->test_desc;
    test_kind  = (pka_test_kind_t *) test_desc->test_kind;
    test_stats = user_data_ptr->test_desc_stats;
    test_name  = test_kind->test_name;
    PKA_ASSERT(test_desc->test_category == PKA_TEST);

    if (first_submit)
        user_data_ptr->start_time = pka_get_cycle_cnt();

    switch (test_name)
    {
    case TEST_ADD:
    case TEST_SUBTRACT:
    case TEST_MULTIPLY:
    case TEST_DIVIDE:
    case TEST_DIV_MOD:
    case TEST_MODULO:
    case TEST_SHIFT_LEFT:
    case TEST_SHIFT_RIGHT:
    case TEST_MOD_INVERT:
        status = submit_basic_test(handle, user_data_ptr, test_desc, test_idx);
        break;

    case TEST_MOD_EXP:
        status = submit_mod_exp_test(handle, user_data_ptr, test_desc,
                                     test_idx);
        break;

    case TEST_RSA_MOD_EXP:
    case TEST_RSA_VERIFY:
    case TEST_RSA_MOD_EXP_WITH_CRT:
        status = submit_rsa_test(handle, user_data_ptr, test_desc, test_idx);
        break;

    case TEST_MONT_ECDH_MULTIPLY:
        status = submit_mont_ecc_test(handle, user_data_ptr, test_desc,
                                      test_idx);
        break;

    case TEST_ECC_ADD:
    case TEST_ECC_DOUBLE:
    case TEST_ECC_MULTIPLY:
        status = submit_ecc_test(handle, user_data_ptr, test_desc, test_idx);
        break;

    case TEST_MONT_ECDH:
    case TEST_MONT_ECDHE:
        if (test_name == TEST_MONT_ECDHE)
            user_data_ptr->multi_submit = true;

        status = submit_mont_ecdh_test(handle, user_data_ptr, test_desc,
                                       test_idx, first_submit);
        break;

    case TEST_ECDH:
    case TEST_ECDHE:
        if (test_name == TEST_ECDHE)
            user_data_ptr->multi_submit = true;

        status = submit_ecdh_test(handle, user_data_ptr, test_desc, test_idx,
                                    first_submit);
        break;

    case TEST_ECDSA_GEN:
    case TEST_ECDSA_VERIFY:
    case TEST_ECDSA_GEN_VERIFY:
        if (test_name  == TEST_ECDSA_GEN_VERIFY)
            user_data_ptr->multi_submit = true;

        status = submit_ecdsa_test(handle, user_data_ptr, test_desc, test_idx,
                                   first_submit);
        break;

    case TEST_DSA_GEN:
    case TEST_DSA_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        if (test_name  == TEST_DSA_GEN_VERIFY)
            user_data_ptr->multi_submit = true;

        status = submit_dsa_test(handle, user_data_ptr, test_desc, test_idx,
                                 first_submit);
        break;

    default:
        PKA_ASSERT(false);
        status = FAILURE;
    }

    if (first_submit)
        test_stats->num_cmd_submits++;

    test_stats->num_total_submits++;
    if (status == SUCCESS)
        test_stats->num_good_replies++;
    else
    {
        test_stats->num_bad_replies++;
        test_stats->errors++;
    }

    return status;
}

static pka_status_t chk_basic_test_results(test_desc_t   *test_desc,
                                           pka_results_t *results)
{
    pka_test_kind_t *test_kind;
    pka_operand_t   *result, *result2, *answer, *answer2;
    test_basic_t    *basic;

    // TEST_DIV_MOD needs two answers.  Also for TEST_DIVIDE
    // the quotient is in result2!
    test_kind = (pka_test_kind_t *) test_desc->test_kind;
    result    = &results->results[0];
    result2   = &results->results[1];
    if (test_kind->test_name == TEST_DIVIDE)
        result = result2;

    basic   = (test_basic_t *) test_desc->test_operands;
    answer  = basic->answer;
    answer2 = basic->answer2;

    if (3 <= verbosity)
    {
        // printf("%s test_name=%s result_cnt=%u\n", __func__,
        //        test_name_to_string(test_kind->test_name),
        //        results->result_cnt);
        print_operand("result = ", result, "\n");
        print_operand("answer = ", answer, "\n");
        if ((results->result_cnt > 1) && (answer2 != NULL))
        {
            print_operand("result2 = ", result2, "\n");
            print_operand("answer2 = ", answer2, "\n");
        }
    }

    // Compare result and answer to make sure they agree.
    if (pki_compare(result, answer) != RC_COMPARE_EQUAL)
        return FAILURE;
    else if (test_kind->test_name != TEST_DIV_MOD)
        return SUCCESS;
    else if (answer2 == NULL)
        return FAILURE;
    else if (pki_compare(result2, answer2) != RC_COMPARE_EQUAL)
        return FAILURE;
    else
        return SUCCESS;;
}

static pka_status_t chk_mod_exp_test_results(test_desc_t   *test_desc,
                                             pka_results_t *results)
{
    test_mod_exp_t *test_mod_exp;
    pka_operand_t  *result, *answer;

    result       = &results->results[0];
    test_mod_exp = (test_mod_exp_t *) test_desc->test_operands;
    answer       = test_mod_exp->answer;

    if (3 <= verbosity)
    {
        print_operand("result   = ", result, "\n");
        print_operand("answer   = ", answer, "\n");
    }

    // Compare result and answer to make sure they agree.
    if (pki_compare(result, answer) == RC_COMPARE_EQUAL)
        return SUCCESS;
    else
        return FAILURE;
}

static pka_status_t chk_rsa_test_results(test_desc_t   *test_desc,
                                         pka_results_t *results)
{
    pka_operand_t *result, *answer;
    test_rsa_t    *test_rsa;

    result   = &results->results[0];
    test_rsa = (test_rsa_t *) test_desc->test_operands;
    answer   = test_rsa->answer;

    if (3 <= verbosity)
    {
        print_operand("result   = ", result, "\n");
        print_operand("answer   = ", answer, "\n");
    }

    // Compare result and answer to make sure they agree.
    if (pki_compare(result, answer) == RC_COMPARE_EQUAL)
        return SUCCESS;
    else
        return FAILURE;
}

static pka_status_t chk_mont_ecc_test_results(pka_handle_t   handle,
                                              test_desc_t   *test_desc,
                                              pka_results_t *results)
{
    test_mont_ecdh_t *ecdh_test;
    pka_operand_t    *answer_pt_x, *result_pt_x;

    PKA_ASSERT(results->result_cnt == 1);
    result_pt_x  = &results->results[0];
    ecdh_test    = (test_mont_ecdh_t *) test_desc->test_operands;
    answer_pt_x  = ecdh_test->answer;

    if (3 <= verbosity)
    {
        print_operand("result_pt_x = ", result_pt_x, "\n");
        print_operand("answer_pt_x = ", answer_pt_x, "\n");
    }

    if (pki_compare(result_pt_x, answer_pt_x) == RC_COMPARE_EQUAL)
        return SUCCESS;
    else
        return FAILURE;
}

static pka_status_t chk_ecc_test_results(pka_handle_t   handle,
                                         test_desc_t   *test_desc,
                                         pka_results_t *results)
{
    ecc_point_t   *answer_pt, *result_pt;
    pka_operand_t *x_ptr, *y_ptr;
    test_ecc_t    *ecc_test;

    PKA_ASSERT(results->result_cnt == 2);
    result_pt    = calloc(1, sizeof(ecc_point_t));
    x_ptr        = dup_operand(&results->results[0]);
    y_ptr        = dup_operand(&results->results[1]);
    result_pt->x = *x_ptr;
    result_pt->y = *y_ptr;
    ecc_test     = (test_ecc_t *) test_desc->test_operands;
    answer_pt    = ecc_test->answer;

    if (3 <= verbosity)
    {
        print_operand("result_pt->x = ", &result_pt->x, "\n");
        print_operand("result_pt->y = ", &result_pt->y, "\n");
        print_operand("answer_pt->x = ", &answer_pt->x, "\n");
        print_operand("answer_pt->y = ", &answer_pt->y, "\n");
    }

    if (ecc_points_are_equal(result_pt, answer_pt))
        return SUCCESS;
    else
        return FAILURE;
}

static pka_status_t chk_mont_ecdh_test_results(pka_handle_t   handle,
                                               test_desc_t   *test_desc,
                                               pka_results_t *results)
{
    mont_ecdh_keys_t *ecdh_keys;
    test_mont_ecdh_t *ecdh_test;
    pka_test_kind_t  *test_kind;
    pka_test_name_t   test_name;
    pka_operand_t    *answer_pt_x, *result_pt_x;
    pka_status_t      status;

    test_kind  = (pka_test_kind_t   *) test_desc->test_kind;
    ecdh_keys  = (mont_ecdh_keys_t  *) test_desc->key_system;
    ecdh_test  = (test_mont_ecdh_t  *) test_desc->test_operands;
    test_name  = test_kind->test_name;

    PKA_ASSERT((test_name == TEST_MONT_ECDH) || (test_name == TEST_MONT_ECDHE));
    PKA_ASSERT(results->result_cnt == 1);

    result_pt_x  = &results->results[0];
    if (test_name == TEST_MONT_ECDH)
        answer_pt_x = ecdh_test->answer;
    else
        answer_pt_x = sw_mont_ecdh_multiply(handle, ecdh_keys->curve,
                                            ecdh_test->local_public_key,
                                            ecdh_test->remote_private_key);

    PKA_ASSERT(answer_pt_x != NULL);
    if (3 <= verbosity)
    {
        print_operand("result_pt_x = ", result_pt_x, "\n");
        print_operand("answer_pt_x = ", answer_pt_x, "\n");
    }

    if (pki_compare(result_pt_x, answer_pt_x) == RC_COMPARE_EQUAL)
        status = SUCCESS;
    else
        status = FAILURE;

    if (3 <= verbosity)
    {
        if (status == SUCCESS)
            printf("run_mont_ecdh_test SUCCESS\n");
        else
            printf("run_ecdh_test FAILURE\n");
    }

    return status;
}

static pka_status_t chk_ecdh_test_results(pka_handle_t   handle,
                                          test_desc_t   *test_desc,
                                          pka_results_t *results)
{
    ecdh_key_system_t *ecdh_keys;
    pka_test_kind_t   *test_kind;
    pka_test_name_t    test_name;
    pka_operand_t     *x_ptr, *y_ptr;
    test_ecdh_t       *ecdh_test;
    ecc_point_t       *answer_pt, *result_pt;
    pka_status_t       status;

    test_kind  = (pka_test_kind_t   *) test_desc->test_kind;
    ecdh_keys  = (ecdh_key_system_t *) test_desc->key_system;
    ecdh_test  = (test_ecdh_t       *) test_desc->test_operands;
    test_name  = test_kind->test_name;
    PKA_ASSERT((test_name == TEST_ECDH) || (test_name == TEST_ECDHE));
    PKA_ASSERT(results->result_cnt == 2);

    result_pt    = calloc(1, sizeof(ecc_point_t));
    x_ptr        = dup_operand(&results->results[0]);
    y_ptr        = dup_operand(&results->results[1]);
    result_pt->x = *x_ptr;
    result_pt->y = *y_ptr;
    if (test_name == TEST_ECDH)
        answer_pt = ecdh_test->answer;
    else
        answer_pt = sw_ecc_multiply(handle, ecdh_keys->curve,
                                    ecdh_test->local_public_key,
                                    ecdh_test->remote_private_key);

    PKA_ASSERT(answer_pt != NULL);
    if (3 <= verbosity)
    {
        print_operand("result_pt->x = ", &result_pt->x, "\n");
        print_operand("result_pt->y = ", &result_pt->y, "\n");
        print_operand("answer_pt->x = ", &answer_pt->x, "\n");
        print_operand("answer_pt->y = ", &answer_pt->y, "\n");
    }

    if (ecc_points_are_equal(result_pt, answer_pt))
        status = SUCCESS;
    else
        status = FAILURE;

    if (3 <= verbosity)
    {
        if (status == SUCCESS)
            printf("run_ecdh_test SUCCESS\n");
        else
            printf("run_ecdh_test FAILURE\n");
    }

    return status;
}

static pka_status_t chk_ecdsa_test_results(test_desc_t   *test_desc,
                                           pka_results_t *results)
{
    pka_test_kind_t  *test_kind;
    pka_test_name_t   test_name;
    dsa_signature_t  *answer, *signature;
    test_ecdsa_t     *ecdsa_test;
    pka_status_t      status;
    pka_operand_t    *r, *s;
    uint32_t          r_buf_len, s_buf_len;
    uint8_t          *r_buf_ptr, *s_buf_ptr;

    test_kind  = (pka_test_kind_t *) test_desc->test_kind;
    ecdsa_test = (test_ecdsa_t    *) test_desc->test_operands;
    answer     = ecdsa_test->answer;
    signature  = NULL;
    test_name  = test_kind->test_name;

    if ((results != NULL) && (results->result_cnt == 2))
    {
        r = &results->results[0];
        s = &results->results[1];
        r_buf_ptr = r->buf_ptr;
        r_buf_len = r->buf_len;
        s_buf_ptr = s->buf_ptr;
        s_buf_len = s->buf_len;
        signature = make_dsa_signature(r_buf_ptr, r_buf_len,
                                       s_buf_ptr, s_buf_len, true);
    }

    switch (test_name)
    {
    case TEST_ECDSA_GEN:
        if (3 <= verbosity)
        {
            print_operand("signature->r = ", &signature->r, "\n");
            print_operand("signature->s = ", &signature->s, "\n");
            print_operand("answer->r    = ", &answer->r, "\n");
            print_operand("answer->s    = ", &answer->s, "\n");
        }

        if (signatures_are_equal(signature, answer))
            status = SUCCESS;
        else
            status = FAILURE;

        break;

    case TEST_ECDSA_VERIFY:
    case TEST_ECDSA_GEN_VERIFY:
        status = (results->compare_result == RC_COMPARE_EQUAL) ?
                    SUCCESS : FAILURE;
        break;

    default:
        PKA_ASSERT(false);
    }

    if (3 <= verbosity)
    {
        if (status == SUCCESS)
            printf("run_ecdsa_test SUCCESS\n");
        else
            printf("run_ecdsa_test FAILURE\n");
    }

    return status;
}

static pka_status_t chk_dsa_test_results(test_desc_t   *test_desc,
                                         pka_results_t *results)
{
    pka_test_kind_t  *test_kind;
    pka_test_name_t   test_name;
    dsa_signature_t  *signature;
    test_dsa_t       *dsa_test;
    pka_status_t      status;

    test_kind = (pka_test_kind_t *) test_desc->test_kind;
    dsa_test  = (test_dsa_t      *) test_desc->test_operands;
    signature = dsa_test->signature;
    test_name = test_kind->test_name;

    switch (test_kind->test_name)
    {
    case TEST_DSA_GEN:
        if (3 <= verbosity)
        {
            print_operand("signature->r  = ", &signature->r, "\n");
            print_operand("signature->s  = ", &signature->s, "\n");
        }

        if (signatures_are_equal(signature, dsa_test->signature))
            status = SUCCESS;
        else
            status = FAILURE;

        break;

    case TEST_DSA_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        status = (results->compare_result == RC_COMPARE_EQUAL) ?
                    SUCCESS : FAILURE;
        break;

    default:
        PKA_ASSERT(false);
    }

    if (3 <= verbosity)
    {
        if (status == SUCCESS)
            printf("run_dsa_test SUCCESS\n");
        else
            printf("run_dsa_test FAILURE\n");
    }

    return status;
}

static __pka_noinline pka_status_t
chk_test_results(pka_handle_t     handle,
                 pka_test_name_t  test_name,
                 test_desc_t     *test_desc,
                 pka_results_t   *results)
{
    // check the results fields
    if (results->results[0].big_endian > 1)
        printf("%s: test_name=%s result[0].big_endian=%u\n", __func__,
               test_name_to_string(test_name), results->results[0].big_endian);

    switch (test_name)
    {
    case TEST_ADD:
    case TEST_SUBTRACT:
    case TEST_MULTIPLY:
    case TEST_DIVIDE:
    case TEST_DIV_MOD:
    case TEST_MODULO:
    case TEST_SHIFT_LEFT:
    case TEST_SHIFT_RIGHT:
    case TEST_MOD_INVERT:
        return chk_basic_test_results(test_desc, results);

    case TEST_MOD_EXP:
        return chk_mod_exp_test_results(test_desc, results);

    case TEST_RSA_MOD_EXP:
    case TEST_RSA_VERIFY:
    case TEST_RSA_MOD_EXP_WITH_CRT:
        return chk_rsa_test_results(test_desc, results);

    case TEST_MONT_ECDH_MULTIPLY:
        return chk_mont_ecc_test_results(handle, test_desc, results);

    case TEST_ECC_ADD:
    case TEST_ECC_DOUBLE:
    case TEST_ECC_MULTIPLY:
        return chk_ecc_test_results(handle, test_desc, results);

    case TEST_MONT_ECDH:
    case TEST_MONT_ECDHE:
        return chk_mont_ecdh_test_results(handle, test_desc, results);

    case TEST_ECDH:
    case TEST_ECDHE:
        return chk_ecdh_test_results(handle, test_desc, results);

    case TEST_ECDSA_GEN:
    case TEST_ECDSA_VERIFY:
    case TEST_ECDSA_GEN_VERIFY:
        return chk_ecdsa_test_results(test_desc, results);

    case TEST_DSA_GEN:
    case TEST_DSA_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        return chk_dsa_test_results(test_desc, results);

    default:
        PKA_ASSERT(false);
        return FAILURE;
    }
}

static void store_first_submit_results(test_desc_t    *test_desc,
                                       pka_test_name_t test_name,
                                       pka_results_t  *results)
{
    dsa_signature_t  *signature;
    pka_operand_t    *x_ptr, *y_ptr, *r, *s;
    test_ecdsa_t     *ecdsa_test;
    ecc_point_t      *result_pt;
    test_ecdh_t      *ecdh_test;
    test_mont_ecdh_t *mont_ecdh_test;
    test_dsa_t       *dsa_test;
    uint32_t          r_buf_len, s_buf_len;
    uint8_t          *r_buf_ptr, *s_buf_ptr;

    switch (test_name)
    {
    case TEST_MONT_ECDHE:
        x_ptr = dup_operand(&results->results[0]);

        mont_ecdh_test = (test_mont_ecdh_t *) test_desc->test_operands;
        mont_ecdh_test->local_public_key = x_ptr;
        break;

    case TEST_ECDHE:
        result_pt    = calloc(1, sizeof(ecc_point_t));
        x_ptr        = dup_operand(&results->results[0]);
        y_ptr        = dup_operand(&results->results[1]);
        result_pt->x = *x_ptr;
        result_pt->y = *y_ptr;

        ecdh_test                   = (test_ecdh_t *) test_desc->test_operands;
        ecdh_test->local_public_key = result_pt;
        break;

    case TEST_ECDSA_GEN_VERIFY:
    case TEST_DSA_GEN_VERIFY:
        r         = &results->results[0];
        s         = &results->results[1];
        r_buf_ptr = r->buf_ptr;
        r_buf_len = r->buf_len;
        s_buf_ptr = s->buf_ptr;
        s_buf_len = s->buf_len;
        signature = make_dsa_signature(r_buf_ptr, r_buf_len,
                                       s_buf_ptr, s_buf_len, true);

        if (test_name == TEST_ECDSA_GEN_VERIFY)
        {
            ecdsa_test            = (test_ecdsa_t *) test_desc->test_operands;
            ecdsa_test->signature = signature;
        }
        else
        {
            dsa_test            = (test_dsa_t *) test_desc->test_operands;
            dsa_test->signature = signature;
        }

        break;

    default:
        PKA_ASSERT(false);
    }
}

static bool process_pka_test_results(pka_handle_t   handle,
                                     pka_results_t *results,
                                     uint64_t       test_end_time)
{
    pka_test_kind_t *test_kind;
    pka_operand_t   *x_ptr, *y_ptr;
    test_stats_t    *test_stats;
    test_desc_t     *test_desc;
    user_data_t     *user_data_ptr;
    test_ecdh_t     *ecdh_test;
    uint64_t         latency;
    ecc_point_t     *result_pt;
    pka_status_t     status;

    user_data_ptr = (user_data_t     *) results->user_data;
    test_desc     = (test_desc_t     *) user_data_ptr->test_desc;
    test_kind     = (pka_test_kind_t *) test_desc->test_kind;
    test_stats    = user_data_ptr->test_desc_stats;

    if ((user_data_ptr->multi_submit) && (user_data_ptr->first_submit))
    {
        store_first_submit_results(test_desc, test_kind->test_name, results);

        if (false) // test_kind->test_name == TEST_ECDHE)
        {
            ecdh_test    = (test_ecdh_t *) test_desc->test_operands;
            result_pt    = calloc(1, sizeof(ecc_point_t));
            x_ptr        = dup_operand(&results->results[0]);
            y_ptr        = dup_operand(&results->results[1]);
            result_pt->x = *x_ptr;
            result_pt->y = *y_ptr;
            ecdh_test->local_public_key = result_pt;
        }

        if (4  <= verbosity)
            printf("%s: Do second submit_pka_test for test_name=%s\n", __func__,
                   test_name_to_string(test_kind->test_name));

        user_data_ptr->first_submit = false;
        submit_pka_test(handle, user_data_ptr, false);
        return false;
    }

    if (check_results)
        status = chk_test_results(handle, test_kind->test_name, test_desc,
                                  results);
    else
        status = SUCCESS;

    if (status != SUCCESS)
    {
        printf("%s: Wrong answer\n", __func__);
        test_stats->num_wrong_answers++;
        test_stats->errors++;
        return true;
    }

    test_stats->num_correct_answers++;
    latency = (test_end_time - user_data_ptr->start_time) / 256;
    test_stats->total_latency   += latency;
    test_stats->latency_squared += latency * latency;
    test_stats->min_latency      = MIN(test_stats->min_latency, latency);
    test_stats->max_latency      = MAX(test_stats->max_latency, latency);
    return true;
}

static void join_threads(uint32_t num_threads)
{
    uint32_t thread_idx;
    int      rc;

    for (thread_idx = 0; thread_idx < num_threads; thread_idx++)
    {
        rc = pthread_join(threads[thread_idx], NULL);
        if (rc != 0)
            printf("%s join failed with rc=%d\n", __func__, rc);
    }
}

static void execute_tests_by_thread(uint32_t        thread_idx,
                                    thread_state_t *thread_state)
{
    pka_handle_t   handle;
    pka_results_t *results;
    user_data_t   *user_data_ptr, user_data[256];
    uint64_t       thread_start_time, thread_end_time, test_end_time;
    uint64_t       current_time, duration;
    uint32_t       outstanding_cmds, failure_cnt;
    uint32_t       total_cmds_done, num_cmds, test_idx, test_desc_idx;
    uint32_t       total_cmds_submitted, user_data_idx, cmds_left_to_submit;

    handle = pka_init_local(pka_test_instance);
    if (handle == PKA_HANDLE_INVALID)
    {
        printf("Failed to init local on thread_idx=%u\n",
               thread_idx);
        return;
    }

    // Wait here for all threads to be ready.
    pka_barrier_wait(&thread_start_barrier);
    memset(user_data, 0, sizeof (user_data));
    for (user_data_idx = 0;  user_data_idx < 256;  user_data_idx++)
    {
        user_data[user_data_idx].user_data_idx = user_data_idx;
        user_data[user_data_idx].thread_idx    = thread_idx;
    }

    outstanding_cmds     = 0;
    total_cmds_submitted = 0;
    total_cmds_done      = 0;
    failure_cnt          = 0;
    thread_start_time    = pka_get_cycle_cnt();
    test_desc_idx        = 0;
    num_cmds             = num_tests * submits_per_test;
    user_data_idx        = 0;
    results              = malloc_results(2, MAX_BYTE_LEN + 8);

    //printf("[%d] num_cmds=%u - cmds_outstanding=%u\n",
    //       thread_idx, num_cmds, cmds_outstanding);
    test_end_time = pka_get_cycle_cnt();

    while(true)
    {
        cmds_left_to_submit = num_cmds - total_cmds_submitted;
        while ((cmds_left_to_submit != 0) && (outstanding_cmds < cmds_outstanding))
        {
            // Need to get the next user_data structure to use and the next
            // test_desc idx to run.
            user_data_ptr = &user_data[user_data_idx++];
            if (256 <= user_data_idx)
                user_data_idx = 0;

            test_idx = thread_state->randomize_tests[test_desc_idx++];
            if (num_tests <= test_desc_idx)
                test_desc_idx = 0;

            user_data_ptr->test_idx        = test_idx;
            user_data_ptr->test_desc       = test_descs[test_idx];
            user_data_ptr->test_desc_stats =
                                    &thread_state->test_desc_stats[test_idx];
            user_data_ptr->first_submit    = true;
            if (SUCCESS == submit_pka_test(handle, user_data_ptr, true))
            {
                outstanding_cmds++;
                total_cmds_submitted++;
                cmds_left_to_submit = num_cmds - total_cmds_submitted;
            }
            else if (failure_cnt++ > 10)
                break;
        }

        if (SUCCESS == pka_get_result(handle, results))
        {
            test_end_time = pka_get_cycle_cnt();
            if (process_pka_test_results(handle, results, test_end_time))
            {
                outstanding_cmds--;
                total_cmds_done++;
                //printf("[%d] outstanding_cmds:%u - total_cmds_done=%u\n",
                //       thread_idx, outstanding_cmds, total_cmds_done);
                if (num_cmds <= total_cmds_done)
                    break;
            }
            else
                busy_delay();
        }

        else
        {
            current_time = pka_get_cycle_cnt();
            duration     = current_time - test_end_time;
            // Break out if no result is received for a long time.
            if (duration > CPU_HZ_MAX)
            {
                printf("%s: No results for a LONG time\n", __func__);
                thread_state->thread_stats.errors++;
                break;
            }
        }
        //printf("[%d] total_cmds_done=%u - failure_cnt=%u\n",
        //      thread_idx, total_cmds_done, failure_cnt);

        if ((cmds_left_to_submit == 0) && (num_cmds == total_cmds_done))
            break;
    }

    thread_end_time             = pka_get_cycle_cnt();
    thread_state->thread_cycles = thread_end_time - thread_start_time;
    pka_barrier_wait(&thread_end_barrier);
    pka_term_local(handle);
}

static void *pka_test_thread(void *arg)
{
    thread_arg_t *thread_arg_ptr;
    uint32_t      thread_idx;

    thread_arg_ptr = (thread_arg_t *) arg;
    thread_idx     = thread_arg_ptr->thread_idx;

    pm_enable();
    thread_states[thread_idx].init_cycles = pka_get_cycle_cnt();

    if (1 <= verbosity)
        printf("%s worker_cpu=%u currently running on cpu=%u\n",
               __func__, thread_arg_ptr->cpu_number, sched_getcpu());

    thread_states[thread_idx].start_cycles = pka_get_cycle_cnt();
    execute_tests_by_thread(thread_idx, &thread_states[thread_idx]);
    thread_states[thread_idx].end_cycles = pka_get_cycle_cnt();

    pm_disable();

    pka_mf();
    thread_states[thread_idx].final_cycles = pka_get_cycle_cnt();
    return NULL;
}

static pka_status_t create_tests (pka_handle_t handle)
{
    thread_state_t *thread_state;
    test_stats_t   *test_desc_stats;
    uint32_t        thread_idx, test_idx;
    uint16_t       *randomize_tests;
    pka_status_t    status;

    free_pka_test_descs(test_descs);
    if (SUCCESS != chk_bit_lens(&test_kind))
        return FAILURE;

    num_tests = test_kind.num_key_systems * test_kind.tests_per_key_system;
    status    = create_pka_test_descs(handle, &test_kind, test_descs,
                                      check_results, verbosity);
    if (status != SUCCESS)
        return FAILURE;

    // Now create the per thread test structures.
    // randomize array.
    for (thread_idx = 0;  thread_idx < num_of_threads;  thread_idx++)
    {
        thread_state = &thread_states[thread_idx];
        if (thread_state->randomize_tests != NULL)
            free(thread_state->randomize_tests);

        if (thread_state->test_desc_stats != NULL)
            free(thread_state->test_desc_stats);

        randomize_tests = malloc(num_tests * sizeof(uint16_t));
        test_desc_stats = malloc(num_tests * sizeof(test_stats_t));

        memset(randomize_tests, 0, num_tests * sizeof(uint16_t));
        memset(test_desc_stats, 0, num_tests * sizeof(test_stats_t));

        thread_state->randomize_tests = randomize_tests;
        thread_state->test_desc_stats = test_desc_stats;

        // For now just use identity map.
        for (test_idx = 0;  test_idx < num_tests;  test_idx++)
            randomize_tests[test_idx] = test_idx;

        // Init the min_latency field to a big number.
        for (test_idx = 0;  test_idx < num_tests;  test_idx++)
            test_desc_stats[test_idx].min_latency = 0xFFFFFFFF;
    }

    return SUCCESS;
}

pthread_t main_thread;
uint32_t  main_thread_cpu;

static int run_test(pka_handle_t handle)
{
    pthread_attr_t attr;
    cpu_set_t cpu_set;
    uint32_t  thread_idx;
    int64_t   worker_cpu;
    int       rc;

    // Next create the common test cases and distribute amongst the various
    // worker tiles.
    if (SUCCESS != create_tests(handle))
    {
        printf("create_tests failure\n");
        pka_term_local(handle);
        return -3;
    }

    pka_term_local(handle);

    if (MAX_THREADS < num_of_threads)
        return -3;

    pm_enable();

    main_thread = pthread_self();
    main_thread_cpu = sched_getcpu();
    CPU_ZERO(&cpu_set);
    CPU_SET(main_thread_cpu, &cpu_set);
    rc = pthread_setaffinity_np(main_thread, sizeof(cpu_set_t), &cpu_set);

    if (1 <= verbosity)
        printf("%s main_thread_cpu=%u\n", __func__, main_thread_cpu);

    main_init1_cycles = pka_get_cycle_cnt();
    main_pre_barrier  = pka_get_cycle_cnt();

    worker_cpu = 0;
    for (thread_idx = 0; thread_idx < num_of_threads; thread_idx++)
    {
        if (worker_cpu == main_thread_cpu)
            worker_cpu++;

        // worker_cpu = thread_idx % num_of_threads;
        CPU_ZERO(&cpu_set);
        CPU_SET(worker_cpu, &cpu_set);
        pthread_attr_init(&attr);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpu_set);

        thread_states[thread_idx].create_cycles = pka_get_cycle_cnt();
        thread_args[thread_idx].thread_idx = thread_idx;
        thread_args[thread_idx].cpu_number = worker_cpu;
        rc = pthread_create(&threads[thread_idx], &attr, pka_test_thread,
                            &thread_args[thread_idx]);
        if (rc != 0)
        {
            printf("Error creating the server threads\n");
            break;
        }

        if (1 <= verbosity)
            printf("%s created worker thread affinitized to cpu=%lu\n", __func__,
                   worker_cpu);
        worker_cpu++;
    }

    // Next start the threads.
    main_pre_barrier = pka_get_cycle_cnt();
    pka_barrier_wait(&thread_start_barrier);
    overall_start_time = pka_get_cycle_cnt();

    // Wait for each thread to complete their running of the test.
    pka_barrier_wait(&thread_end_barrier);

    join_threads(num_of_threads);
    overall_end_time = pka_get_cycle_cnt();

    pm_disable();
    return 0;
}

static uint64_t to_usecs(uint64_t cycles_div_256)
{
    return (1000000 * 256 * cycles_div_256) / cpu_freq;
}

static void update_test_stats(test_stats_t *test_stats, uint32_t num)
{
    uint64_t avg, var, std_dev;

    avg     = test_stats->total_latency / num;
    var     = (test_stats->latency_squared / num) - (avg * avg);
    std_dev = isqrt(var);

    test_stats->min_latency     = to_usecs(test_stats->min_latency);
    test_stats->max_latency     = to_usecs(test_stats->max_latency);
    test_stats->avg_latency     = to_usecs(avg);
    test_stats->latency_std_dev = to_usecs(std_dev);
}

static void analyze_results (void)
{
    thread_state_t *thread_state;
    test_stats_t   *thread_stats, *test_stats;
    uint32_t        thread_idx, test_idx, num, bad_results;

    memset(&overall_test_stats, 0, sizeof(overall_test_stats));
    overall_cmds_done              = 0;
    overall_bad_results            = 0;
    overall_test_stats.min_latency = 0xFFFFFFFF;

    for (thread_idx = 0; thread_idx < num_of_threads; thread_idx++)
    {
        thread_state = &thread_states[thread_idx];
        thread_stats = &thread_state->thread_stats;
        thread_stats->min_latency = 0xFFFFFFFF;

        for (test_idx = 0; test_idx < num_tests; test_idx++)
        {
            test_stats  = &thread_state->test_desc_stats[test_idx];
            num         = test_stats->num_cmd_submits;
            bad_results = test_stats->errors;

            thread_stats->num_cmd_submits     += num;
            thread_stats->errors              += bad_results;
            thread_stats->num_correct_answers += test_stats->num_correct_answers;
            thread_stats->total_latency       += test_stats->total_latency;
            thread_stats->latency_squared     += test_stats->latency_squared;
            thread_stats->min_latency          = MIN(thread_stats->min_latency,
                                                     test_stats->min_latency);
            thread_stats->max_latency          = MAX(thread_stats->max_latency,
                                                     test_stats->max_latency);

            if (num != 0)
                update_test_stats(test_stats, num);
        }

        num = thread_stats->num_correct_answers;

        overall_cmds_done                  += num;
        overall_bad_results                += thread_stats->errors;
        overall_test_stats.total_latency   += thread_stats->total_latency;
        overall_test_stats.latency_squared += thread_stats->latency_squared;
        overall_test_stats.min_latency = MIN(overall_test_stats.min_latency,
                                             thread_stats->min_latency);
        overall_test_stats.max_latency = MAX(overall_test_stats.max_latency,
                                             thread_stats->max_latency);

        if (num != 0)
            update_test_stats(thread_stats, num);
    }

    if (overall_cmds_done != 0)
        update_test_stats(&overall_test_stats, overall_cmds_done);
}

static void report_per_thread_results(void)
{
    thread_state_t *thread_state;
    test_stats_t   *thread_stats, *test_stats;
    uint64_t        microsecs64, millisecs64;
    uint32_t        thread_idx, test_idx, bad_results, num_cmds;
    uint32_t        usecs_rem, cmds_per_sec;

    for (thread_idx = 0; thread_idx < num_of_threads; thread_idx++)
    {
        thread_state = &thread_states[thread_idx];
        thread_stats = &thread_state->thread_stats;

        if (1 <= verbosity)
        {
            printf("idx=%u create_cycles=%lu init=%lu start=%lu end=%lu final=%lu\n",
                   thread_idx, thread_state->create_cycles, thread_state->init_cycles,
                   thread_state->start_cycles, thread_state->end_cycles,
                   thread_state->final_cycles);
            printf("        init_rel=%lu start_rel=%lu end_rel=%lu final_rel=%lu\n",
                   thread_state->init_cycles  - thread_state->create_cycles,
                   thread_state->start_cycles - thread_state->init_cycles,
                   thread_state->end_cycles   - thread_state->start_cycles,
                   thread_state->final_cycles - thread_state->end_cycles);
        }

        // Only report per thread per test stats if the num_tests is > 1.
        if (1 < num_tests)
        {
            for (test_idx = 0; test_idx < num_tests; test_idx++)
            {
                test_stats   = &thread_state->test_desc_stats[test_idx];
                bad_results  = test_stats->errors;
                num_cmds     = test_stats->num_cmd_submits;

                printf("    thread_idx=%u test_idx=%u num=%u errors=%u min=%u "
                       "avg=%u max=%u std_dev=%u (usecs)\n",
                       thread_idx, test_idx, num_cmds, bad_results,
                       (uint32_t) test_stats->min_latency,
                       (uint32_t) test_stats->avg_latency,
                       (uint32_t) test_stats->max_latency,
                       (uint32_t) test_stats->latency_std_dev);
            }
        }

        microsecs64  = (1000000 * thread_state->thread_cycles) / cpu_freq;
        millisecs64  = microsecs64 / 1000;
        usecs_rem    = (uint32_t) (microsecs64 - (millisecs64 * 1000));
        num_cmds     = thread_stats->num_correct_answers;
        cmds_per_sec = (uint32_t) ((1000000 * (uint64_t) num_cmds) /
                                   microsecs64);

        printf("  thread_idx=%u millisecs=%u.%03u num cmds=%u errors=%u "
               "cmdsPerSec=%u\n", thread_idx, (uint32_t) millisecs64,
               usecs_rem, num_cmds, thread_stats->errors, cmds_per_sec);

        printf("  thread_idx=%u min=%u avg=%u max=%u std_dev=%u (usecs)\n\n",
               thread_idx, (uint32_t) thread_stats->min_latency,
               (uint32_t) thread_stats->avg_latency,
               (uint32_t) thread_stats->max_latency,
               (uint32_t) thread_stats->latency_std_dev);
    }
}

static void report_results(uint64_t total_time_cycles, uint32_t num_threads)
{
    uint64_t microsecs64, millisecs64;
    uint32_t usecs_rem, num_cmds, cmds_per_sec;

    microsecs64  = (1000000 * total_time_cycles) / cpu_freq;
    millisecs64  = microsecs64 / 1000;
    usecs_rem    = (uint32_t) (microsecs64 - (millisecs64 * 1000));
    num_cmds     = overall_cmds_done;
    cmds_per_sec = (uint32_t) ((1000000 * (uint64_t) num_cmds) /
                               microsecs64);

    printf("\n");
    printf("total time millisecs=%u.%03u total cmds=%u errors=%u cmdsPerSec=%u "
           "(bit_len=%u",
           (uint32_t) millisecs64, usecs_rem, num_cmds, overall_bad_results,
           cmds_per_sec, test_kind.bit_len);

    if (test_kind.second_bit_len != 0)
        printf(" second_bit_len=%u", test_kind.second_bit_len);

    printf(")\n");

    if (overall_cmds_done != 0)
        printf("latency num_threads=%u min=%u avg=%u max=%u std_dev=%u "
               "(usecs)\n",
               num_threads, (uint32_t) overall_test_stats.min_latency,
               (uint32_t) overall_test_stats.avg_latency,
               (uint32_t) overall_test_stats.max_latency,
               (uint32_t) overall_test_stats.latency_std_dev);

    if (1 <= verbosity)
        printf("  main_init1=%lu main_pre_barrier=%lu overall_start=%lu overall_end=%lu\n",
               main_init1_cycles, main_pre_barrier, overall_start_time, overall_end_time);

    if (report_thread_stats)
    {
        printf("\nPer Thread Per Test results:\n");
        report_per_thread_results();
    }
}

static void print_usage(char *progname)
{
    printf("'%s <options>' - where options can be:\n", progname);
    printf("  -b <bit_len>         primary bit_len to use\n");
    printf("  -e ( big | little )  endianness of the interface\n");
    printf("  -h                   print this message and exit\n");
    printf("  -k <num_keys>        num of different key subsystems to make\n");
    printf("  -m <runs_per_test>   num of runs of each test per thread\n");
    printf("  -n <num_tests>       num of tests (per key subsystem) to make\n");
    printf("  -q <cmds_outstanding>number of cmds each thread keeps in play\n");
    printf("  -r                   report the per thread stats/results\n");
    printf("  -s <second_bit_len>  secondary bit_len for some cryptosystems\n");
    printf("  -t <num_threads>     number of threads/tiles to use\n");
    printf("  -o <num_rings>       number of PKA rings to use\n");
    printf("  -v <verbosity>       verbosity level - in range 0-3\n");
    printf("  -y ( yes | no )      check_results if set to yes\n");
    printf("  -c <test_kind>       name of the test kind.  One of:\n");
    printf("     ADD, SUBTRACT, MULTIPLY, DIVIDE, DIV_MOD, MODULO\n");
    printf("     SHIFT_LEFT, SHIFT_RIGHT, MOD_INVERT\n");
    printf("     MOD_EXP, RSA_MOD_EXP, RSA_VERIFY, RSA_MOD_EXP_WITH_CRT\n");
    printf("     MONT_ECDH_MULTIPLY, ECC_ADD, ECC_DOUBLE, ECC_MULTIPLY\n");
    printf("     MONT_ECDH, MONT_ECDHE, ECDH, ECDHE,\n");
    printf("     ECDSA_GEN, ECDSA_VERIFY, ECDSA_GEN_VERIFY\n");
    printf("     DSA_GEN, DSA_VERIFY, DSA_GEN_VERIFY\n\n");
    printf("The default command line options (except for -b and -s) are:\n");
    printf("'-c MOD_EXP -e little -k 1 -m 100 -n 4 -q 10 -t 1 -o 1 -v 0 -y no'\n");
    printf("The defaults for '-b' and '-s' depend upon the test name (as \n");
    printf("given by '-c') as follows:\n");
    printf("a) the default for '-b' is 1024 for all tests except\n");
    printf("   for the ECC_* tests, ECDH* and ECDSA_* tests when it is 256,\n");
    printf("   and for the MONT_* tests when it is 255.\n");
    printf("b) the default for -s is 17 for RSA_VERIFY, 'bit_len - 1'\n");
    printf("   for DIVIDE, DIV_MOD, MODULO, and DSA_* tests\n");
    printf("   and unused for for all other tests.\n\n");
}

static pka_status_t process_options(int argc, char *argv[])
{
    pka_test_name_t test_name;
    uint32_t        num_tests, thread_cnt, ring_cnt;
    uint32_t        num_outstanding, bit_len, test_runs, key_systems;
    int             optionChar;

    while ((optionChar = getopt(argc, argv, "b:c:e:hk:m:n:q:rs:t:o:v:y:")) != -1)
    {
        switch (optionChar)
        {
        case 'b':
            bit_len = atoi(optarg);
            if (bit_len <= 32)
            {
                printf("primary key bit_len must be >= 33 bits\n");
                return FAILURE;
            }
            else if (4096 < bit_len)
            {
                printf("primary key bit_len must be <= 4096 bits\n");
                return FAILURE;
            }
            else
                test_kind.bit_len = bit_len;
            break;

        case 'c':
            test_name = lookup_test_name(optarg);
            if (test_name == TEST_NOP)
            {
                printf("Option -c needs to be followed by legal test_name\n");
                return FAILURE;
            }
            else
                test_kind.test_name = test_name;

            break;

        case 'e':
            if (strcasecmp(optarg, "big") == 0)
                big_endian = true;
            else if (strcasecmp(optarg, "little") == 0)
                big_endian = false;
            else
            {
                printf("Option -e needs to be followed by either"
                       " 'big' or 'little'\n");
                return FAILURE;
            }
            break;

        case 'h':
            help = true;
            break;

        case 'k':
            key_systems = atoi(optarg);
            if (key_systems != 1)
            {
                printf("currenly the num of key systems can only be 1\n");
                return FAILURE;
            }
            else
                test_kind.num_key_systems = key_systems;
            break;

        case 'm':
            test_runs = atoi(optarg);
            if (test_runs == 0)
            {
                printf("num of times to run each test cannot be 0\n");
                return FAILURE;
            }
            else if (1000000 < test_runs)
            {
                printf("num of times to run each test) (per thread) must be "
                       "<= 1000000\n");
                return FAILURE;
            }
            else
                submits_per_test = test_runs;
            break;

        case 'n':
            num_tests = atoi(optarg);
            if (num_tests == 0)
            {
                printf("num of tests per key subsystem cannot be 0\n");
                return FAILURE;
            }
            else if (MAX_NUM_TESTS < num_tests)
            {
                printf("num of tests per key subsystem must be <= %u\n",
                       MAX_NUM_TESTS);
                return FAILURE;
            }
            else
                test_kind.tests_per_key_system = num_tests;
            break;

        case 'q':
            num_outstanding = atoi(optarg);
            if (num_outstanding == 0)
            {
                printf("num of oustanding cmds cannot be 0\n");
                return FAILURE;
            }
            else if (128 < num_outstanding)
            {
                printf("num of oustanding cmds must be <= 128\n");
                return FAILURE;
            }
            else
                cmds_outstanding = num_outstanding;
            break;

        case 'r':
            report_thread_stats = true;
            break;

        case 's':
            bit_len = atoi(optarg);
            if (bit_len <= 8)
            {
                printf("secondary key bit_len must be >= 9 bits\n");
                return FAILURE;
            }
            else if (4095 < bit_len)
            {
                printf("secondary key bit_len must be <= 4095 bits\n");
                return FAILURE;
            }
            else
                test_kind.second_bit_len = bit_len;
            break;

        case 't':
            thread_cnt = atoi(optarg);
            if (thread_cnt == 0)
            {
                printf("number of threads/tiles cannot be 0\n");
                return FAILURE;
            }
            else if (MAX_THREADS < thread_cnt)
            {
                printf("number of threads/tiles must be <= %u\n",
                       MAX_THREADS);
                return FAILURE;
            }
            else
                num_of_threads = atoi(optarg);
            break;

        case 'o':
            ring_cnt = atoi(optarg);
            if (ring_cnt == 0)
            {
                printf("number of PK rings cannot be 0\n");
                return FAILURE;
            }
            else if (MAX_RINGS < ring_cnt)
            {
                printf("number of threads/tiles must be <= %u\n",
                       MAX_RINGS);
                return FAILURE;
            }
            else
                num_of_rings = atoi(optarg);
            break;

        case 'v':
            verbosity = atoi(optarg);
            break;

        case 'y':
            if (strcasecmp(optarg, "yes") == 0)
                check_results = true;
            else if (strcasecmp(optarg, "no") == 0)
                check_results = false;
            else
            {
                printf("Option -y needs to be followed by either"
                       " 'yes' or 'no'\n");
                return FAILURE;
            }
            break;
        }
    }

    return SUCCESS;
}

int main (int argc, char *argv[])
{
    pka_handle_t  handle;
    uint32_t      cmd_queue_sz, rslt_queue_sz;
    uint8_t       flags;
    int           return_code = 0;

    // Set argument defaults:
    num_of_threads      = 1;
    num_of_rings        = 1;
    cmds_outstanding    = 10;
    submits_per_test    = 100;
    check_results       = false;
    report_thread_stats = false;
    big_endian          = false;
    help                = false;
    verbosity           = 0;

    test_kind.bit_len              = 0;
    test_kind.second_bit_len       = 0;
    test_kind.num_key_systems      = 1;
    test_kind.tests_per_key_system = 4;
    test_kind.test_name            = TEST_MOD_EXP;

    if (2 <= argc)
    {
        if (SUCCESS != process_options(argc, argv))
            return -1;
    }
    else
        help = true;

    if (help)
    {
        print_usage(NO_PATH(argv[0]));
        return 0;
    }

    // Set the default bit_len (i.e. when not explicitly set on the command
    // line) depending on the kind of test.
    if (test_kind.bit_len == 0)
        test_kind.bit_len = DEFAULT_BIT_LEN[test_kind.test_name];

    if (test_kind.second_bit_len == 0)
    {
        switch (test_kind.test_name)
        {
        case TEST_DIVIDE:
        case TEST_DIV_MOD:
        case TEST_MODULO:
            test_kind.second_bit_len = test_kind.bit_len - 1;
            break;

        case TEST_DSA_GEN:
        case TEST_DSA_VERIFY:
        case TEST_DSA_GEN_VERIFY:
            if (test_kind.bit_len == 1024)
                test_kind.second_bit_len = 160;
            else if (test_kind.bit_len == 2048)
                test_kind.second_bit_len = 224;
            else if (test_kind.bit_len == 3072)
                test_kind.second_bit_len = 256;
            else if (test_kind.bit_len >= 1024)
                test_kind.second_bit_len = 256;
            else
                test_kind.second_bit_len = test_kind.bit_len / 4;
            break;

        case TEST_RSA_VERIFY:
            test_kind.second_bit_len = 17;
            break;

        default:
            test_kind.second_bit_len = 0;
            break;
        }
    }

    cpu_freq = pka_get_cpu_freq();
    printf("cpu_freq=%ld\n", cpu_freq);
    printf("Creating %u %s tests of test kind %s using bit_lens %u and %u\n",
           test_kind.tests_per_key_system,
           big_endian ? "BIG_ENDIAN" : "LITTLE_ENDIAN",
           test_name_to_string(test_kind.test_name), test_kind.bit_len,
           test_kind.second_bit_len);
    printf("Running each test %u times with %u cmds outstanding on %u "
           "threads\n", submits_per_test, cmds_outstanding, num_of_threads);
    printf("Tests %s be checked and thread stats %s be reported. "
           "Verbosity=%u\n", check_results ? "will" : " will not",
           report_thread_stats ? "will" : "will not", verbosity);

    // Init PKA before calling anything else
    flags         = PKA_F_PROCESS_MODE_SINGLE;
    flags        |= (num_of_threads > 1) ?
                        PKA_F_SYNC_MODE_ENABLE : PKA_F_SYNC_MODE_DISABLE;
    cmd_queue_sz  = PKA_MAX_OBJS * PKA_CMD_DESC_MAX_DATA_SIZE;
    rslt_queue_sz = PKA_MAX_OBJS * PKA_RSLT_DESC_MAX_DATA_SIZE;
    pka_test_instance = pka_init_global(NO_PATH(argv[0]), flags, num_of_rings,
                            num_of_threads, cmd_queue_sz,
                            rslt_queue_sz);
    if (pka_test_instance == PKA_INSTANCE_INVALID)
    {
        printf("Failed to init global\n");
        return -11;
    }

    handle = pka_init_local(pka_test_instance);
    if (handle == PKA_HANDLE_INVALID)
    {
        printf("Failed to open mica pka handle on the main thread\n");
        return -11;
    }

    init_test_utils(handle);
    pka_barrier_init(&thread_start_barrier, num_of_threads + 1);
    pka_barrier_init(&thread_end_barrier,   num_of_threads + 1);

    return_code = run_test(handle);
    analyze_results();
    report_results(overall_end_time - overall_start_time, num_of_threads);

    return return_code;
}
