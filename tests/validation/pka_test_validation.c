#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <ctype.h>
#include <sched.h>
#include <pthread.h>
#include <stdbool.h>

#include "pka.h"
#include "pka_utils.h"

#include "pka_test_utils.h"
#include "pka_test_vectors.h"

#define PKA_MAX_OBJS                 32       // 32  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14) // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12) //  4K bytes.

// Macro to print the current application mode
#define PRINT_APPL_MODE(x) printf("%s(bit %i)\n", #x, (x))

// Get rid of path in filename
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
                strrchr((file_name), '/') + 1 : (file_name))

// Parsed command line application arguments
typedef struct
{
    pka_instance_t instance;       ///< PKA instance
    uint8_t        cpu_count;      ///< Number of CPUs to use
    uint8_t        ring_count;     ///< Number of Rings to use
    uint8_t        mode;           ///< Application mode
    uint8_t        sync;           ///< Synchronization mode
    uint8_t        time;           ///< Time to run app
} app_args_t;

// Thread specific arguments
typedef struct
{
    uint32_t       id;
    uint32_t       cpu_num;
    uint32_t       ticks;
    uint32_t       seed;
    uint32_t       tests_failed;
    uint32_t       tests_passed;
    pka_instance_t instance;
    pka_handle_t   handle;
    void          *user_data;
} thread_args_t;

#define MAX_THREADS        15

// Grouping of both parsed CLI args and thread specific args - alloc together
typedef struct
{
    app_args_t      app;                  ///< application arguments
    thread_args_t   thread[MAX_THREADS];  ///< Thread specific arguments
    uint8_t         exit_threads;         ///< Flag to exit worker threads
} args_t;

/// Global pointer to args
static args_t *gbl_args;

volatile bool global_quit;

volatile uint32_t print_thread_idx;

static pka_barrier_t startup_barrier;
static pka_barrier_t ending_barrier;

static uint32_t validation_tests_passed;
static uint32_t validation_tests_failed;
static uint32_t validation_tests_total;

typedef pka_result_code_t (* basic_fcn_t) (pka_handle_t   hdl,
                                           void          *user_data,
                                           pka_operand_t *left,
                                           pka_operand_t *right);

typedef pka_result_code_t (* shift_fcn_t) (pka_handle_t   hdl,
                                           void          *user_data,
                                           pka_operand_t *operand,
                                           uint32_t       shift_cnt);

#define PKA_ADD            (basic_fcn_t) pka_add
#define PKA_SUBTRACT       (basic_fcn_t) pka_subtract
#define PKA_MULTIPLY       (basic_fcn_t) pka_multiply
#define PKA_MODULO         (basic_fcn_t) pka_modulo
#define PKA_MOD_INVERSE    (basic_fcn_t) pka_modular_inverse
#define PKA_SHIFT_LEFT     (shift_fcn_t) pka_shift_left
#define PKA_SHIFT_RIGHT    (shift_fcn_t) pka_shift_right
#define MOD_EXP                          pka_modular_exp
#define MOD_EXP_WITH_CRT                 pka_modular_exp_crt
#define ECC_ADD                          pka_ecc_pt_add
#define ECC_MULTIPLY                     pka_ecc_pt_mult
#define ECDSA_GENERATE                   pka_ecdsa_signature_generate
#define ECDSA_VERIFY                     pka_ecdsa_signature_verify
#define DSA_GENERATE                     pka_dsa_signature_generate
#define DSA_VERIFY                       pka_dsa_signature_verify
#define ECDH                             pka_ecdh
#define DH                               pka_dh

static pka_operand_t   *test_operands[200];
static ecc_point_t     *test_ecc_points[100];
static dsa_signature_t *test_signatures[100];

static rsa_system_t *RSA1024;

static ecc_curve_t *P256;
static ecc_curve_t *P384;
static ecc_curve_t *P521;

static ecc_point_t *P256_base_pt;
static ecc_point_t *P384_base_pt;
static ecc_point_t *P521_base_pt;

static pka_operand_t *P256_base_pt_order;
static pka_operand_t *P384_base_pt_order;
static pka_operand_t *P521_base_pt_order;

static dsa_domain_params_t *DSS_1024_160;
static dsa_domain_params_t *DSS_2048_224;
static dsa_domain_params_t *DSS_3072_256;

// helper funcs
static void ParseArgs(int argc, char *argv[], app_args_t *app_args);
static void PrintInfo(char *progname, app_args_t *app_args);
static void Usage(char *progname);

uint32_t Randomize(thread_args_t *args, uint32_t ticks)
{
    uint32_t rand_byte;

    rand_byte = rand_r(&args->seed) & 0xFF;

    // Randomize so that over the random byte range (0-255) the incoming
    // ticks value can go up by a factor of 2 or go down by a factor of 1/2.
    return (ticks * (85 + rand_byte)) / 170;
}

void BusyWait(uint32_t ticks)
{
    uint32_t cnt;

    for (cnt = 1; cnt <= ticks; cnt++)
        pka_wait();
}

static pka_operand_t *MakeOperand(uint8_t *big_endian_buf_ptr, uint32_t buf_len)
{
    return make_operand(big_endian_buf_ptr, buf_len, 0);
}

static void SetTestOperand(uint32_t operand_idx, pka_operand_t *operand)
{
    test_operands[operand_idx] = operand;
}

static void CreateTestOperand(uint32_t operand_idx,
                              uint64_t msb_bytes,
                              uint64_t middle_bytes,
                              uint32_t middle_repeat,
                              uint64_t lsb_bytes)
{
    pka_operand_t *test_operand;
    uint32_t       msb_bytes_len, middle_bytes_len, lsb_bytes_len, total_len;
    uint32_t       buf_len, cnt;
    uint8_t       *buf_ptr;

    msb_bytes_len    = byte_len(msb_bytes);
    middle_bytes_len = byte_len(middle_bytes);
    lsb_bytes_len    = byte_len(lsb_bytes);
    total_len        = msb_bytes_len + (middle_bytes_len * middle_repeat) +
                       lsb_bytes_len;

    buf_len = ((total_len + 7) / 8) * 8;
    test_operand = malloc(sizeof(pka_operand_t));
    memset(test_operand, 0, sizeof(pka_operand_t));
    test_operand->buf_ptr = malloc(buf_len);
    memset(test_operand->buf_ptr, 0, buf_len);
    test_operand->buf_len    = buf_len;
    test_operand->actual_len = total_len;

    // Now fill the test_operand buf.
    buf_ptr = test_operand->buf_ptr;
    if (lsb_bytes_len != 0)
        buf_ptr = append_bytes(buf_ptr, lsb_bytes, lsb_bytes_len);

    if ((middle_bytes_len != 0) && (middle_repeat != 0))
    {
        for (cnt = 1; cnt <= middle_repeat; cnt++)
            buf_ptr = append_bytes(buf_ptr, middle_bytes, middle_bytes_len);
    }

    if (msb_bytes_len != 0)
        buf_ptr = append_bytes(buf_ptr, msb_bytes, msb_bytes_len);

    SetTestOperand(operand_idx, test_operand);
}

static void InitTestOperands(void)
{
    CreateTestOperand(0,  0,              0, 0, 0);  // Value 0
    CreateTestOperand(1,  1,              0, 0, 0);  // Value 1
    CreateTestOperand(2,  2,              0, 0, 0);  // Value 2
    CreateTestOperand(3,  0xFE,           0, 0, 0);  // Value 254
    CreateTestOperand(4,  0xFF,           0, 0, 0);  // Value 255
    CreateTestOperand(5,  0x100,          0, 0, 0);  // Value 256
    CreateTestOperand(6,  0x101,          0, 0, 0);  // Value 257
    CreateTestOperand(7,  0xFFFE,         0, 0, 0);
    CreateTestOperand(8,  0xFFFF,         0, 0, 0);
    CreateTestOperand(9,  0x10000,        0, 0, 0);
    CreateTestOperand(10, 0x10001,        0, 0, 0);
    CreateTestOperand(11, 0xFFFFFFFE,     0, 0, 0);
    CreateTestOperand(12, 0xFFFFFFFF,     0, 0, 0);
    CreateTestOperand(13, 0x100000000ULL, 0, 0, 0);
    CreateTestOperand(14, 0x100000001ULL, 0, 0, 0);

    CreateTestOperand(15, 0xFFFFFFFE,     0xFFFE, 100, 0);
    CreateTestOperand(16, 0xFFFFFFFF,     0xFFFF, 100, 0);
    CreateTestOperand(17, 0x100000000ULL, 0x0001, 100, 0);
    CreateTestOperand(18, 0x100000001ULL, 0x0001, 100, 0);
    CreateTestOperand(19, 0x100000001ULL, 0xF001, 100, 0);

    CreateTestOperand(20, 0xAAAAAAAB, 0, 0, 0);
    CreateTestOperand(21, 0xCCCC999A, 0, 0, 0);
    CreateTestOperand(22, 0xC0000001, 0, 0, 0);

    SetTestOperand(30, MakeOperand(RESULT0, sizeof(RESULT0)));
    SetTestOperand(31, MakeOperand(RESULT1, sizeof(RESULT1)));
    SetTestOperand(32, MakeOperand(RESULT2, sizeof(RESULT2)));
    SetTestOperand(33, MakeOperand(RESULT3, sizeof(RESULT3)));
    SetTestOperand(34, MakeOperand(RESULT4, sizeof(RESULT4)));

    SetTestOperand(97, MakeOperand(VALUE,      sizeof(VALUE)));
    SetTestOperand(98, MakeOperand(SUBTRAHEND, sizeof(SUBTRAHEND)));
    SetTestOperand(99, MakeOperand(SUB_RESULT, sizeof(SUB_RESULT)));

    SetTestOperand(35, MakeOperand(VAL_TO_INVERT,  sizeof(VAL_TO_INVERT)));
    SetTestOperand(36, MakeOperand(INVERT_MODULUS, sizeof(INVERT_MODULUS)));
    SetTestOperand(37, MakeOperand(INVERT_RESULT,  sizeof(INVERT_RESULT)));

    SetTestOperand(194, MakeOperand(ADD_VALUE,        sizeof(ADD_VALUE)));
    SetTestOperand(195, MakeOperand(ADD_ADDEND,       sizeof(ADD_ADDEND)));
    SetTestOperand(196, MakeOperand(ADD_EXPECTED_RES, sizeof(ADD_EXPECTED_RES)));

    SetTestOperand(191, MakeOperand(SUB_VALUE,        sizeof(SUB_VALUE)));
    SetTestOperand(192, MakeOperand(SUB_SUBTRAHEND,   sizeof(SUB_SUBTRAHEND)));
    SetTestOperand(193, MakeOperand(SUB_EXPECTED_RES, sizeof(SUB_EXPECTED_RES)));

    SetTestOperand(188, MakeOperand(MUL_VALUE,        sizeof(MUL_VALUE)));
    SetTestOperand(189, MakeOperand(MUL_MULTIPLIER,   sizeof(MUL_MULTIPLIER)));
    SetTestOperand(190, MakeOperand(MUL_EXPECTED_RES, sizeof(MUL_EXPECTED_RES)));

    SetTestOperand(185, MakeOperand(MOD_VALUE,        sizeof(MOD_VALUE)));
    SetTestOperand(186, MakeOperand(MOD_MODULUS,      sizeof(MOD_MODULUS)));
    SetTestOperand(187, MakeOperand(MOD_EXPECTED_RES, sizeof(MOD_EXPECTED_RES)));

    SetTestOperand(182, MakeOperand(MOD_INV_VALUE,    sizeof(MOD_INV_VALUE)));
    SetTestOperand(183, MakeOperand(MOD_INV_MODULUS,  sizeof(MOD_INV_MODULUS)));
    SetTestOperand(184,
            MakeOperand(MOD_INV_EXPECTED_RES, sizeof(MOD_INV_EXPECTED_RES)));

    SetTestOperand(178, MakeOperand(MOD_EXP_VALUE,    sizeof(MOD_EXP_VALUE)));
    SetTestOperand(179, MakeOperand(MOD_EXP_EXPONENT, sizeof(MOD_EXP_EXPONENT)));
    SetTestOperand(180, MakeOperand(MOD_EXP_MODULUS,  sizeof(MOD_EXP_MODULUS)));
    SetTestOperand(181,
            MakeOperand(MOD_EXP_EXPECTED_RES, sizeof(MOD_EXP_EXPECTED_RES)));

    SetTestOperand(171, MakeOperand(SHIFT_VALUE,    sizeof(SHIFT_VALUE)));
    SetTestOperand(172, MakeOperand(SHIFT_VALUE_R1, sizeof(SHIFT_VALUE_R1)));
    SetTestOperand(173, MakeOperand(SHIFT_VALUE_R2, sizeof(SHIFT_VALUE_R2)));
    SetTestOperand(174, MakeOperand(SHIFT_VALUE_R3, sizeof(SHIFT_VALUE_R3)));
    SetTestOperand(175, MakeOperand(SHIFT_VALUE_L1, sizeof(SHIFT_VALUE_L1)));
    SetTestOperand(176, MakeOperand(SHIFT_VALUE_L2, sizeof(SHIFT_VALUE_L2)));
    SetTestOperand(177, MakeOperand(SHIFT_VALUE_L3, sizeof(SHIFT_VALUE_L3)));
}

static void InitRsaOperands(void)
{
    pka_operand_t *msg, *correct;

    RSA1024 = malloc(sizeof(rsa_system_t));
    memset(RSA1024, 0, sizeof(rsa_system_t));

    RSA1024->modulus = MakeOperand(RSA1024_modulus, sizeof(RSA1024_modulus));
    RSA1024->private = MakeOperand(RSA1024_private, sizeof(RSA1024_private));
    RSA1024->public  = MakeOperand(RSA1024_public,  sizeof(RSA1024_public));
    RSA1024->p       = MakeOperand(RSA1024_p,       sizeof(RSA1024_p));
    RSA1024->q       = MakeOperand(RSA1024_q,       sizeof(RSA1024_q));
    RSA1024->dp      = MakeOperand(RSA1024_dp,      sizeof(RSA1024_dp));
    RSA1024->dq      = MakeOperand(RSA1024_dq,      sizeof(RSA1024_dq));
    RSA1024->qInv    = MakeOperand(RSA1024_qInv,    sizeof(RSA1024_qInv));

    msg     = MakeOperand(RSA1024_msg,    sizeof(RSA1024_msg));
    correct = MakeOperand(RSA1024_result, sizeof(RSA1024_result));

    SetTestOperand(25, msg);
    SetTestOperand(26, correct);
}

static void SetEccTestPoint(uint32_t ecc_point_idx, ecc_point_t *ecc_point)
{
    test_ecc_points[ecc_point_idx] = ecc_point;
}


static ecc_curve_t *MakeEccCurve(uint8_t *p_bytes,
                                 uint32_t p_len,
                                 uint8_t *a_bytes,
                                 uint32_t a_len,
                                 uint8_t *b_bytes,
                                 uint32_t b_len)
{
    return make_ecc_curve(p_bytes, p_len, a_bytes, a_len, b_bytes, b_len, 0);
}

static ecc_point_t *MakeEccPoint(ecc_curve_t *curve,
                                 uint8_t     *x_bytes,
                                 uint32_t     x_len,
                                 uint8_t     *y_bytes,
                                 uint32_t     y_len)
{
    return make_ecc_point(curve, x_bytes, x_len, y_bytes, y_len, 0);
}

static bool CreateEccPoint(uint32_t     ecc_point_idx,
                           ecc_curve_t *curve,
                           uint8_t     *x_bytes,
                           uint32_t     x_len)
{
    ecc_point_t  *ecc_point;
    bool          point_is_valid;

    point_is_valid = false;

    ecc_point = create_ecc_point(curve, x_bytes, x_len, 0);
    if (ecc_point != NULL)
        point_is_valid = true;

    SetEccTestPoint(ecc_point_idx, ecc_point);
    return point_is_valid;
}

static void InitEccOperands(void)
{
    ecc_point_t *ecc_pt10,  *ecc_pt11, *ecc_pt12,  *ecc_pt13;
    ecc_point_t *ecc_pt20,  *ecc_pt21;

    P256 = MakeEccCurve(P256_p, sizeof(P256_p), P256_a, sizeof(P256_a),
                        P256_b, sizeof(P256_b));
    P384 = MakeEccCurve(P384_p, sizeof(P384_p), P384_a, sizeof(P384_a),
                        P384_b, sizeof(P384_b));
    P521 = MakeEccCurve(P521_p, sizeof(P521_p), P521_a, sizeof(P521_a),
                        P521_b, sizeof(P521_b));

    P256_base_pt = MakeEccPoint(P256, P256_xg, sizeof(P256_xg),
                                P256_yg, sizeof(P256_yg));
    P384_base_pt = MakeEccPoint(P384, P384_xg, sizeof(P384_xg),
                                P384_yg, sizeof(P384_yg));
    P521_base_pt = MakeEccPoint(P521, P521_xg, sizeof(P521_xg),
                                P521_yg, sizeof(P521_yg));

    P256_base_pt_order = MakeOperand(P256_n, sizeof(P256_n));
    P384_base_pt_order = MakeOperand(P384_n, sizeof(P384_n));
    P521_base_pt_order = MakeOperand(P521_n, sizeof(P521_n));

    SetEccTestPoint(1, P256_base_pt);
    SetEccTestPoint(2, P384_base_pt);
    SetEccTestPoint(3, P521_base_pt);

    CreateEccPoint(4, P256, P256_x1, sizeof(P256_x1));
    CreateEccPoint(5, P256, P256_x2, sizeof(P256_x2));
    CreateEccPoint(6, P256, P256_x3, sizeof(P256_x3));

    ecc_pt10 = MakeEccPoint(P256, ECC_RESULT10_x, sizeof(ECC_RESULT10_x),
                            ECC_RESULT10_y, sizeof(ECC_RESULT10_y));
    ecc_pt11 = MakeEccPoint(P256, ECC_RESULT11_x, sizeof(ECC_RESULT11_x),
                            ECC_RESULT11_y, sizeof(ECC_RESULT11_y));
    ecc_pt12 = MakeEccPoint(P256, ECC_RESULT12_x, sizeof(ECC_RESULT12_x),
                            ECC_RESULT12_y, sizeof(ECC_RESULT12_y));
    ecc_pt13 = MakeEccPoint(P256, ECC_RESULT13_x, sizeof(ECC_RESULT13_x),
                            ECC_RESULT13_y, sizeof(ECC_RESULT13_y));

    ecc_pt20 = MakeEccPoint(P256, ECC_RESULT20_x, sizeof(ECC_RESULT20_x),
                            ECC_RESULT20_y, sizeof(ECC_RESULT20_y));
    ecc_pt21 = MakeEccPoint(P256, ECC_RESULT21_x, sizeof(ECC_RESULT21_x),
                            ECC_RESULT21_y, sizeof(ECC_RESULT21_y));

    SetEccTestPoint(10, ecc_pt10);
    SetEccTestPoint(11, ecc_pt11);
    SetEccTestPoint(12, ecc_pt12);
    SetEccTestPoint(13, ecc_pt13);
    SetEccTestPoint(20, ecc_pt20);
    SetEccTestPoint(21, ecc_pt21);
}

static void SetTestSignature(uint32_t sig_idx, dsa_signature_t *signature)
{
    test_signatures[sig_idx] = signature;
}

static dsa_signature_t *MakeDsaSignature(uint8_t *r_bytes,
                                         uint32_t r_len,
                                         uint8_t *s_bytes,
                                         uint32_t s_len)
{
    return make_dsa_signature(r_bytes, r_len, s_bytes, s_len, 0);
}

static void InitEcdaOperands(void)
{
    dsa_signature_t *sig_40,     *sig_50,     *sig_60;
    pka_operand_t   *operand_40, *operand_41, *operand_42;
    pka_operand_t   *operand_50, *operand_51, *operand_52;
    pka_operand_t   *operand_60, *operand_61, *operand_62;
    ecc_point_t     *ecc_pt40,   *ecc_pt50,   *ecc_pt60;

    operand_40 = MakeOperand(P256_private_key, sizeof(P256_private_key));
    operand_41 = MakeOperand(P256_hash,        sizeof(P256_hash));
    operand_42 = MakeOperand(P256_k,           sizeof(P256_k));

    operand_50 = MakeOperand(P384_private_key, sizeof(P384_private_key));
    operand_51 = MakeOperand(P384_hash,        sizeof(P384_hash));
    operand_52 = MakeOperand(P384_k,           sizeof(P384_k));

    operand_60 = MakeOperand(P521_private_key, sizeof(P521_private_key));
    operand_61 = MakeOperand(P521_hash,        sizeof(P521_hash));
    operand_62 = MakeOperand(P521_k,           sizeof(P521_k));

    SetTestOperand(40, operand_40);
    SetTestOperand(41, operand_41);
    SetTestOperand(42, operand_42);
    SetTestOperand(50, operand_50);
    SetTestOperand(51, operand_51);
    SetTestOperand(52, operand_52);
    SetTestOperand(60, operand_60);
    SetTestOperand(61, operand_61);
    SetTestOperand(62, operand_62);

    ecc_pt40 = MakeEccPoint(P256, P256_public_key_x, sizeof(P256_public_key_x),
                                  P256_public_key_y, sizeof(P256_public_key_y));
    ecc_pt50 = MakeEccPoint(P384, P384_public_key_x, sizeof(P384_public_key_x),
                                  P384_public_key_y, sizeof(P384_public_key_y));
    ecc_pt60 = MakeEccPoint(P521, P521_public_key_x, sizeof(P521_public_key_x),
                                  P521_public_key_y, sizeof(P521_public_key_y));

    SetEccTestPoint(40, ecc_pt40);
    SetEccTestPoint(50, ecc_pt50);
    SetEccTestPoint(60, ecc_pt60);

    sig_40 = MakeDsaSignature(P256_r, sizeof(P256_r), P256_s, sizeof(P256_s));
    sig_50 = MakeDsaSignature(P384_r, sizeof(P384_r), P384_s, sizeof(P384_s));
    sig_60 = MakeDsaSignature(P521_r, sizeof(P521_r), P521_s, sizeof(P521_s));

    SetTestSignature(40, sig_40);
    SetTestSignature(50, sig_50);
    SetTestSignature(60, sig_60);
}

static dsa_domain_params_t *MakeDsaParams(uint8_t *p_bytes,
                                          uint32_t p_len,
                                          uint8_t *q_bytes,
                                          uint32_t q_len,
                                          uint8_t *g_bytes,
                                          uint32_t g_len)
{
    return make_dsa_domain_params(p_bytes, p_len,
                                  q_bytes, q_len,
                                  g_bytes, g_len,
                                  0);
}

static void InitDsaOperands(void)
{
    dsa_signature_t *sig_70,     *sig_80,     *sig_90;
    pka_operand_t   *operand_70, *operand_71, *operand_72, *operand_73;
    pka_operand_t   *operand_80, *operand_81, *operand_82, *operand_83;
    pka_operand_t   *operand_90, *operand_91, *operand_92, *operand_93;

    DSS_1024_160 = MakeDsaParams(DSS_1024_160_p, sizeof(DSS_1024_160_p),
                                 DSS_1024_160_q, sizeof(DSS_1024_160_q),
                                 DSS_1024_160_g, sizeof(DSS_1024_160_g));
    DSS_2048_224 = MakeDsaParams(DSS_2048_224_p, sizeof(DSS_2048_224_p),
                                 DSS_2048_224_q, sizeof(DSS_2048_224_q),
                                 DSS_2048_224_g, sizeof(DSS_2048_224_g));
    DSS_3072_256 = MakeDsaParams(DSS_3072_256_p, sizeof(DSS_3072_256_p),
                                 DSS_3072_256_q, sizeof(DSS_3072_256_q),
                                 DSS_3072_256_g, sizeof(DSS_3072_256_g));

    operand_70 = MakeOperand(DSS_1024_160_private_key,
                             sizeof(DSS_1024_160_private_key));
    operand_71 = MakeOperand(DSS_1024_160_public_key,
                             sizeof(DSS_1024_160_public_key));
    operand_72 = MakeOperand(DSS_1024_160_hash, sizeof(DSS_1024_160_hash));
    operand_73 = MakeOperand(DSS_1024_160_k, sizeof(DSS_1024_160_k));

    operand_80 = MakeOperand(DSS_2048_224_private_key,
                             sizeof(DSS_2048_224_private_key));
    operand_81 = MakeOperand(DSS_2048_224_public_key,
                             sizeof(DSS_2048_224_public_key));
    operand_82 = MakeOperand(DSS_2048_224_hash, sizeof(DSS_2048_224_hash));
    operand_83 = MakeOperand(DSS_2048_224_k, sizeof(DSS_2048_224_k));

    operand_90 = MakeOperand(DSS_3072_256_private_key,
                             sizeof(DSS_3072_256_private_key));
    operand_91 = MakeOperand(DSS_3072_256_public_key,
                             sizeof(DSS_3072_256_public_key));
    operand_92 = MakeOperand(DSS_3072_256_hash, sizeof(DSS_3072_256_hash));
    operand_93 = MakeOperand(DSS_3072_256_k, sizeof(DSS_3072_256_k));

    SetTestOperand(70, operand_70);
    SetTestOperand(71, operand_71);
    SetTestOperand(72, operand_72);
    SetTestOperand(73, operand_73);
    SetTestOperand(80, operand_80);
    SetTestOperand(81, operand_81);
    SetTestOperand(82, operand_82);
    SetTestOperand(83, operand_83);
    SetTestOperand(90, operand_90);
    SetTestOperand(91, operand_91);
    SetTestOperand(92, operand_92);
    SetTestOperand(93, operand_93);

    sig_70 = MakeDsaSignature(DSS_1024_160_r, sizeof(DSS_1024_160_r),
                              DSS_1024_160_s, sizeof(DSS_1024_160_s));
    sig_80 = MakeDsaSignature(DSS_2048_224_r, sizeof(DSS_2048_224_r),
                              DSS_2048_224_s, sizeof(DSS_2048_224_s));
    sig_90 = MakeDsaSignature(DSS_3072_256_r, sizeof(DSS_3072_256_r),
                              DSS_3072_256_s, sizeof(DSS_3072_256_s));

    SetTestSignature(70, sig_70);
    SetTestSignature(80, sig_80);
    SetTestSignature(90, sig_90);
}

static void TestInit()
{
    InitTestOperands();
    InitRsaOperands();
    InitEccOperands();
    InitEcdaOperands();
    InitDsaOperands();
}

static char *ResultCodeName(pka_result_code_t result_code)
{
    if (result_code == RC_NO_ERROR)
        return "NO_ERROR";

    switch (result_code)
    {
    case RC_EVEN_MODULUS:          return "EVEN_MODULUS";
    case RC_ZERO_EXPONENT:         return "ZERO_EXPONENT";
    case RC_SHORT_MODULUS:         return "SHORT_MODULUS";
    case RC_ONE_EXPONENT:          return "ONE_EXPONENT";
    case RC_BAD_ODD_POWERS:        return "BAD_ODD_POWERS";
    case RC_RESULT_IS_PAI:         return "RESULT_IS_POINT_AT_INFINITY";
    case RC_UNKNOWN_COMMAND:       return "UNKNOWN_COMMAND";
    case RC_INTERMEDIATE_PAI:      return "INTERMEDIATE_IS_POINT_AT_INFINITY";
    case RC_NO_MODULAR_INVERSE:    return "NO_MODULAR_INVERSE";
    case RC_ECC_RESULT_OFF_CURVE:  return "ECC_RESULT_OFF_CURVE";
    case RC_OPERAND_LENGTH_ERR:    return "OPERAND_LENGTH_ERR";
    case RC_UNDEFINED_TRIGGER:     return "UNDEFINED_TRIGGER";
    case RC_INVALID_ARGUMENT:      return "INVALID_ARGUMENT";
    case RC_OPERAND_VALUE_ERR:     return "OPERAND_VALUE_ERR";
    case RC_CALCULATION_ERR:       return "CALCULATION_ERR";
    case RC_INVALID_ADDRESS:       return "INVALID_ADDRESS";
    case RC_ENCRYPTED_PARAM_ERR:   return "ENCRYPTED_PARAM_ERR";
    case RC_TOO_LITTLE_MEMORY:     return "TOO_LITTLE_MEMORY";
    case RC_MEMORY_DEADLOCK:       return "MEMORY_DEADLOCK";
    default:                       return "UNKNOWN ERROR CODE";
    }
}

void PrintTestOperands(const char    *test_fcn_name,
                       char          *pki_fcn_name,
                       pka_operand_t *inputs[],
                       uint32_t       num_inputs,
                       pka_operand_t *result)
{
    uint32_t idx;

    printf("%s: %s\n", test_fcn_name, pki_fcn_name);

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
}

void ShiftTestFailed(thread_args_t     *args,
                     const char        *test_fcn_name,
                     char              *pki_fcn_name,
                     pka_operand_t     *inputs[],
                     uint32_t           num_inputs,
                     pka_result_code_t  result_code,
                     pka_operand_t     *result)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
    args->tests_failed++;
}

static void CmdFailed(thread_args_t     *args,
                      const char        *test_fcn_name,
                      char              *pki_fcn_name,
                      pka_operand_t     *inputs[],
                      uint32_t           num_inputs,
                      pka_result_code_t  result_code)
{
    uint32_t idx;

    printf("%s: %s cmd failed %s rc='%s'\n", __func__, test_fcn_name,
            pki_fcn_name, ResultCodeName(result_code));

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    args->tests_failed++;
}

static void TestFailed(thread_args_t     *args,
                       const char        *test_fcn_name,
                       char              *pki_fcn_name,
                       pka_operand_t     *inputs[],
                       uint32_t           num_inputs,
                       pka_result_code_t  result_code,
                       pka_operand_t     *result,
                       pka_operand_t     *correct)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
    print_operand("    correct  = ", correct, "\n\n");
    args->tests_failed++;
}

static void ModExpWithCrtTestFailed(thread_args_t     *args,
                                    const char        *test_fcn_name,
                                    rsa_system_t      *rsa,
                                    pka_operand_t     *inputs[],
                                    uint32_t           num_inputs,
                                    pka_result_code_t  result_code,
                                    pka_operand_t     *result,
                                    pka_operand_t     *correct)
{
    uint32_t idx;

    printf("%s error with pki_mod_exp_with_crt rc='%s'\n", test_fcn_name,
           ResultCodeName(result_code));
    print_operand("    modulus  = ", rsa->modulus, "\n");
    print_operand("    private  = ", rsa->private, "\n");
    print_operand("    public   = ", rsa->public,  "\n");
    print_operand("    p        = ", rsa->p,       "\n");
    print_operand("    q        = ", rsa->q,       "\n");
    print_operand("    dp       = ", rsa->dp,      "\n");
    print_operand("    dq       = ", rsa->dq,      "\n");
    print_operand("    qInv     = ", rsa->qInv,    "\n");

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
    print_operand("    correct  = ", correct, "\n\n");
    args->tests_failed++;
}

static void EccTestFailed(thread_args_t     *args,
                          const char        *test_fcn_name,
                          char              *pki_fcn_name,
                          ecc_curve_t       *curve,
                          pka_operand_t     *inputs[],
                          uint32_t           num_inputs,
                          pka_result_code_t  result_code,
                          ecc_point_t       *result,
                          ecc_point_t       *correct)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));

    print_operand("    p         = ", &curve->p, "\n");
    print_operand("    a         = ", &curve->a, "\n");
    print_operand("    b         = ", &curve->b, "\n");

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u  = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result.x  = ", &result->x,  "\n");
    print_operand("    result.y  = ", &result->y,  "\n");
    print_operand("    correct.x = ", &correct->x, "\n");
    print_operand("    correct.y = ", &correct->y, "\n\n");
    args->tests_failed++;
}

static void EcdsaTestFailed(thread_args_t       *args,
                            const char          *test_fcn_name,
                            char                *pki_fcn_name,
                            ecc_curve_t         *curve,
                            ecc_point_t         *base_pt,
                            pka_operand_t       *base_pt_order,
                            pka_operand_t       *inputs[],
                            uint32_t             num_inputs,
                            pka_result_code_t    result_code,
                            dsa_signature_t     *result_sig,
                            dsa_signature_t     *correct_sig)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));
    print_operand("    p             = ", &curve->p,     "\n");
    print_operand("    a             = ", &curve->a,     "\n");
    print_operand("    b             = ", &curve->b,     "\n");
    print_operand("    base_pt.x     = ", &base_pt->x,   "\n");
    print_operand("    base_pt.y     = ", &base_pt->y,   "\n");
    print_operand("    base_pt_order = ", base_pt_order, "\n");

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u      = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result_sig.r  = ", &result_sig->r,  "\n");
    print_operand("    result_sig.s  = ", &result_sig->s,  "\n");
    print_operand("    correct_sig.r = ", &correct_sig->r, "\n");
    print_operand("    correct_sig.s = ", &correct_sig->s, "\n\n");
    args->tests_failed++;
}

static void DsaTestFailed(thread_args_t       *args,
                          const char          *test_fcn_name,
                          char                *pki_fcn_name,
                          dsa_domain_params_t *dsa_params,
                          pka_operand_t       *inputs[],
                          uint32_t             num_inputs,
                          pka_result_code_t    result_code,
                          dsa_signature_t     *result_sig,
                          dsa_signature_t     *correct_sig)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));

    print_operand("    p             = ", &dsa_params->p, "\n");
    print_operand("    q             = ", &dsa_params->q, "\n");
    print_operand("    g             = ", &dsa_params->g, "\n");

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u      = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result_sig.r  = ", &result_sig->r,  "\n");
    print_operand("    result_sig.s  = ", &result_sig->s,  "\n");
    print_operand("    correct_sig.r = ", &correct_sig->r, "\n");
    print_operand("    correct_sig.s = ", &correct_sig->s, "\n\n");
    args->tests_failed++;
}

static void BasicTest(thread_args_t *args,
                      char          *pki_fcn_name,
                      basic_fcn_t    fcn,
                      uint32_t       left_idx,
                      uint32_t       right_idx,
                      uint32_t       correct_idx)
{
    pka_operand_t     *left, *right, *correct, *inputs[2], *result;
    pka_results_t      results;
    pka_result_code_t  rc;
    pka_cmp_code_t     cmp;
    uint8_t            res_buf[MAX_BUF];

    left    = test_operands[left_idx];
    right   = test_operands[right_idx];
    correct = test_operands[correct_idx];

    rc = fcn(args->handle, args->user_data, left, right);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = left;
        inputs[1] = right;
        CmdFailed(args, __func__, pki_fcn_name, inputs, 2, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
    result = &results.results[0];

    if (pka_request_count(args->handle))
    {
        while (FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        if (rc == RC_NO_ERROR)
        {
            cmp = pki_compare(result, correct);
            if (cmp == RC_COMPARE_EQUAL)
            {
                args->tests_passed++;
                return;
            }
        }
    }


    inputs[0] = left;
    inputs[1] = right;
    TestFailed(args, __func__, pki_fcn_name, inputs, 2, rc, result, correct);
}

static void ShiftTest(thread_args_t *args,
                      char          *pki_fcn_name,
                      shift_fcn_t    fcn,
                      uint32_t       operand_idx,
                      uint32_t       shift_cnt,
                      uint32_t       correct_idx)
{
    pka_operand_t       *operand, *correct, *result;
    pka_results_t       results;
    pka_result_code_t   rc;
    pka_cmp_code_t      cmp;
    uint8_t             res_buf[MAX_BUF];

    operand = test_operands[operand_idx];
    correct = test_operands[correct_idx];

    rc = fcn(args->handle, args->user_data, operand, shift_cnt);
    if (rc != RC_NO_ERROR)
    {
        CmdFailed(args, __func__, pki_fcn_name, &operand, 2, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
    result = &results.results[0];

    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        if (rc == RC_NO_ERROR)
        {
            cmp = pki_compare(result, correct);
            if (cmp == RC_COMPARE_EQUAL)
            {
                args->tests_passed++;
                return;
            }
        }
    }

    TestFailed(args, __func__, pki_fcn_name, &operand, 1, rc, result, correct);
}

static void DhTest(thread_args_t *args,
                   uint32_t       value_idx,
                   uint32_t       exponent_idx,
                   uint32_t       modulus_idx,
                   uint32_t       correct_idx)
{
    pka_operand_t      *value, *exponent, *modulus, *correct, *result, *inputs[3];
    pka_results_t       results;
    pka_result_code_t   rc;
    pka_cmp_code_t      cmp;
    uint8_t             res_buf[MAX_BUF];

    value    = test_operands[value_idx];
    exponent = test_operands[exponent_idx];
    modulus  = test_operands[modulus_idx];
    correct  = test_operands[correct_idx];

    rc = DH(args->handle, args->user_data, exponent, modulus, value);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = value;
        inputs[1] = exponent;
        inputs[2] = modulus;
        CmdFailed(args, __func__, "pka_dh", inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
    result = &results.results[0];

    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        if (rc == RC_NO_ERROR)
        {
            cmp = pki_compare(result, correct);
            if (cmp == RC_COMPARE_EQUAL)
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = value;
    inputs[1] = exponent;
    inputs[2] = modulus;
    TestFailed(args, __func__, "pka_dh", inputs, 3, rc, result, correct);
}
static void ModExpTest(thread_args_t *args,
                       char          *pki_fcn_name,
                       uint32_t       value_idx,
                       uint32_t       exponent_idx,
                       uint32_t       modulus_idx,
                       uint32_t       correct_idx)
{
    pka_operand_t *value, *exponent, *modulus, *correct, *result, *inputs[3];
    pka_results_t       results;
    pka_result_code_t   rc;
    pka_cmp_code_t      cmp;
    uint8_t             res_buf[MAX_BUF];

    value    = test_operands[value_idx];
    exponent = test_operands[exponent_idx];
    modulus  = test_operands[modulus_idx];
    correct  = test_operands[correct_idx];

    rc = MOD_EXP(args->handle, args->user_data, exponent, modulus, value);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = value;
        inputs[1] = exponent;
        inputs[2] = modulus;
        CmdFailed(args, __func__, pki_fcn_name, inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
    result = &results.results[0];

    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        if (rc == RC_NO_ERROR)
        {
            cmp = pki_compare(result, correct);
            if (cmp == RC_COMPARE_EQUAL)
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = value;
    inputs[1] = exponent;
    inputs[2] = modulus;
    TestFailed(args, __func__, pki_fcn_name, inputs, 3, rc, result, correct);
}

static void ModExpWithCrtTest(thread_args_t *args,
                              rsa_system_t  *rsa,
                              uint32_t       msg_idx,
                              uint32_t       correct_idx)
{
    pka_operand_t       *msg, *correct, *result, *inputs[3];
    pka_results_t       results;
    pka_result_code_t   rc;
    pka_cmp_code_t      cmp;
    uint8_t             res_buf[MAX_BUF];

    msg     = test_operands[msg_idx];
    correct = test_operands[correct_idx];

    rc = MOD_EXP_WITH_CRT(args->handle, args->user_data,
                            msg, rsa->p, rsa->q, rsa->dp, rsa->dq, rsa->qInv);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = msg;
        CmdFailed(args, __func__, "pka_rsa", inputs, 1, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
    result = &results.results[0];

    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        if (rc == RC_NO_ERROR)
        {
            cmp = pki_compare(result, correct);
            if (cmp == RC_COMPARE_EQUAL)
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = msg;
    ModExpWithCrtTestFailed(args, __func__, rsa, inputs, 1, rc, result,
                                correct);
}

static void EccAddTest(thread_args_t *args,
                       ecc_curve_t   *curve,
                       uint32_t       pointA_idx,
                       uint32_t       pointB_idx,
                       uint32_t       correct_idx)
{
    pka_operand_t      *inputs[4];
    pka_result_code_t   rc;
    ecc_point_t        *pointA, *pointB, *correct, result;
    pka_results_t       results;
    uint8_t             x_buf[MAX_BUF], y_buf[MAX_BUF];

    pointA  = test_ecc_points[pointA_idx];
    pointB  = test_ecc_points[pointB_idx];
    correct = test_ecc_points[correct_idx];

    rc = ECC_ADD(args->handle, args->user_data, curve, pointA, pointB);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = &pointA->x;
        inputs[1] = &pointA->y;
        inputs[2] = &pointB->x;
        inputs[3] = &pointB->y;
        CmdFailed(args, __func__, "pka_ecc_add", inputs, 4, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &x_buf[0], MAX_BUF, 0);
    init_operand(&results.results[1], &y_buf[0], MAX_BUF, 0);
    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        result.x = results.results[0];
        result.y = results.results[1];
        if (rc == RC_NO_ERROR)
        {
            if (ecc_points_are_equal(&result, correct))
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = &pointA->x;
    inputs[1] = &pointA->y;
    inputs[2] = &pointB->x;
    inputs[3] = &pointB->y;
    EccTestFailed(args, __func__, "pka_ecc_add", curve, inputs, 4,
                  rc, &result, correct);
}

static void EccMultiplyTest(thread_args_t *args,
                            ecc_curve_t   *curve,
                            uint32_t       pointA_idx,
                            uint32_t       multiplier_idx,
                            uint32_t       correct_idx)
{
    pka_operand_t       *multiplier, *inputs[3];
    pka_result_code_t    rc;
    ecc_point_t         *pointA, *correct, result;
    pka_results_t        results;
    uint8_t              x_buf[MAX_BUF], y_buf[MAX_BUF];

    pointA     = test_ecc_points[pointA_idx];
    multiplier = test_operands[multiplier_idx];
    correct    = test_ecc_points[correct_idx];

    rc = ECC_MULTIPLY(args->handle, args->user_data, curve, pointA, multiplier);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = &pointA->x;
        inputs[1] = &pointA->y;
        inputs[2] = multiplier;
        CmdFailed(args, __func__, "pka_ecc_multiply", inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &x_buf[0], MAX_BUF, 0);
    init_operand(&results.results[1], &y_buf[0], MAX_BUF, 0);
    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        result.x = results.results[0];
        result.y = results.results[1];
        if (rc == RC_NO_ERROR)
        {
            if (ecc_points_are_equal(&result, correct))
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = &pointA->x;
    inputs[1] = &pointA->y;
    inputs[2] = multiplier;
    EccTestFailed(args, __func__, "pka_ecc_multiply", curve, inputs, 3,
                  rc, &result, correct);
}

static void EcdhTest(thread_args_t *args,
                     ecc_curve_t   *curve,
                     uint32_t       point_idx,
                     uint32_t       private_key_idx,
                     uint32_t       correct_idx)
{
    pka_operand_t       *private_key, *inputs[3];
    pka_result_code_t    rc;
    ecc_point_t         *point, *correct, result;
    pka_results_t        results;
    uint8_t              x_buf[MAX_BUF], y_buf[MAX_BUF];

    point       = test_ecc_points[point_idx];
    private_key = test_operands[private_key_idx];
    correct     = test_ecc_points[correct_idx];

    rc = ECDH(args->handle, args->user_data, curve, point, private_key);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = &point->x;
        inputs[1] = &point->y;
        inputs[2] = private_key;
        CmdFailed(args, __func__, "pka_ecdh", inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &x_buf[0], MAX_BUF, 0);
    init_operand(&results.results[1], &y_buf[0], MAX_BUF, 0);
    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.
        result.x = results.results[0];
        result.y = results.results[1];
        if (rc == RC_NO_ERROR)
        {
            if (ecc_points_are_equal(&result, correct))
            {
                args->tests_passed++;
                return;
            }
        }
    }

    inputs[0] = &point->x;
    inputs[1] = &point->y;
    inputs[2] = private_key;
    EccTestFailed(args, __func__, "pka_ecdh", curve, inputs, 3,
                  rc, &result, correct);
}

static void EcdsaTest(thread_args_t *args,
                      ecc_curve_t   *curve,
                      ecc_point_t   *base_pt,
                      pka_operand_t *base_pt_order,
                      uint32_t       private_key_idx,
                      uint32_t       public_key_idx,
                      uint32_t       hash_idx,
                      uint32_t       k_idx,
                      uint32_t       correct_sig_idx)
{
    dsa_signature_t      generate_sig, verify_sig, *correct_sig;
    pka_operand_t       *private_key, *hash, *k, *inputs[5];
    pka_result_code_t    rc;
    pka_cmp_code_t       cmp;
    ecc_point_t         *public_key;
    pka_results_t        results;
    uint8_t              r_buf[MAX_BUF], s_buf[MAX_BUF];

    private_key = test_operands[private_key_idx];
    public_key  = test_ecc_points[public_key_idx];
    hash        = test_operands[hash_idx];
    k           = test_operands[k_idx];
    correct_sig = test_signatures[correct_sig_idx];

    rc = ECDSA_GENERATE(args->handle, args->user_data, curve, base_pt,
                        base_pt_order, private_key, hash, k);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = private_key;
        inputs[1] = hash;
        inputs[2] = k;
        CmdFailed(args, __func__, "pka_ecdsa_generate", inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &r_buf[0], MAX_BUF, 0);
    init_operand(&results.results[1], &s_buf[0], MAX_BUF, 0);
    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        generate_sig.r = results.results[0];
        generate_sig.s = results.results[1];
        if ((rc == RC_NO_ERROR) &&
            (signatures_are_equal(&generate_sig, correct_sig)))
        {
            rc = ECDSA_VERIFY(args->handle, args->user_data, curve, base_pt,
                              base_pt_order, public_key, hash,
                              &generate_sig, 0);
            if (rc != RC_NO_ERROR)
            {
                inputs[0] = &public_key->x;
                inputs[1] = &public_key->y;
                inputs[2] = hash;
                inputs[3] = private_key;
                inputs[4] = k;
                CmdFailed(args, __func__, "pka_ecdsa_verify", inputs, 5, rc);
                return;
            }

            memset(&results, 0, sizeof(pka_results_t));
            init_operand(&results.results[0], &r_buf[0], MAX_BUF, 0);
            init_operand(&results.results[1], &s_buf[0], MAX_BUF, 0);
            if (pka_request_count(args->handle))
            {
                while(FAILURE == pka_get_result(args->handle, &results));
                verify_sig.r = results.results[0];
                verify_sig.s = results.results[1];
                cmp          = results.compare_result;
                if ((rc == RC_NO_ERROR) && (cmp == RC_COMPARE_EQUAL))
                {
                    args->tests_passed += 2;
                    return;
                }

                inputs[0] = &public_key->x;
                inputs[1] = &public_key->y;
                inputs[2] = hash;
                EcdsaTestFailed(args, __func__, "pka_ecdsa_verify", curve,
                                base_pt, base_pt_order, inputs, 3, rc,
                                &verify_sig, correct_sig);
            }

            args->tests_passed += 1;
            return;
        }
    }

    inputs[0] = private_key;
    inputs[1] = hash;
    inputs[2] = k;
    EcdsaTestFailed(args, __func__, "pka_ecdsa_generate", curve, base_pt,
                    base_pt_order, inputs, 3, rc, &generate_sig, correct_sig);
}

static void DsaTest(thread_args_t       *args,
                    dsa_domain_params_t *dsa_params,
                    uint32_t             private_key_idx,
                    uint32_t             public_key_idx,
                    uint32_t             hash_idx,
                    uint32_t             k_idx,
                    uint32_t             correct_sig_idx)
{
    dsa_signature_t      generate_sig, verify_sig, *correct_sig;
    pka_operand_t       *private_key, *public_key, *hash, *k, *inputs[4];
    pka_result_code_t    rc;
    pka_cmp_code_t       cmp;
    pka_results_t        results;
    uint8_t              r_buf[MAX_BUF], s_buf[MAX_BUF];

    private_key = test_operands[private_key_idx];
    public_key  = test_operands[public_key_idx];
    hash        = test_operands[hash_idx];
    k           = test_operands[k_idx];
    correct_sig = test_signatures[correct_sig_idx];

    rc = DSA_GENERATE(args->handle, args->user_data, &dsa_params->p,
                      &dsa_params->q, &dsa_params->g, private_key, hash, k);
    if (rc != RC_NO_ERROR)
    {
        inputs[0] = private_key;
        inputs[1] = hash;
        inputs[2] = k;
        CmdFailed(args, __func__, "pka_dsa_generate", inputs, 3, rc);
        return;
    }

    memset(&results, 0, sizeof(pka_results_t));
    init_operand(&results.results[0], &r_buf[0], MAX_BUF, 0);
    init_operand(&results.results[1], &s_buf[0], MAX_BUF, 0);
    if (pka_request_count(args->handle))
    {
        while(FAILURE == pka_get_result(args->handle, &results));
        generate_sig.r = results.results[0];
        generate_sig.s = results.results[1];
        if ((rc == RC_NO_ERROR) &&
            (signatures_are_equal(&generate_sig, correct_sig)))
        {
            rc = DSA_VERIFY(args->handle, args->user_data, &dsa_params->p,
                            &dsa_params->q, &dsa_params->g, public_key, hash,
                            &generate_sig, 0);
            if (rc != RC_NO_ERROR)
            {
                inputs[0] = public_key;
                inputs[1] = hash;
                CmdFailed(args, __func__, "pka_dsa_verify", inputs, 2, rc);
                return;
            }

            memset(&results, 0, sizeof(pka_results_t));
            init_operand(&results.results[0], &r_buf[0], MAX_BUF, 0);
            init_operand(&results.results[1], &s_buf[0], MAX_BUF, 0);
            if (pka_request_count(args->handle))
            {
                while(FAILURE == pka_get_result(args->handle, &results));
                verify_sig.r = results.results[0];
                verify_sig.s = results.results[1];
                cmp          = results.compare_result;
                if ((rc == RC_NO_ERROR) && (cmp == RC_COMPARE_EQUAL))
                {
                    args->tests_passed += 2;
                    return;
                }

                inputs[0] = public_key;
                inputs[1] = hash;
                inputs[2] = private_key;
                inputs[3] = k;
                DsaTestFailed(args, __func__, "pka_dsa_verify", dsa_params,
                              inputs, 4, rc, &verify_sig, correct_sig);
            }

            args->tests_passed += 1;
            return;
        }
    }

    inputs[0] = private_key;
    inputs[1] = hash;
    inputs[2] = k;
    DsaTestFailed(args, __func__, "pka_dsa_generate", dsa_params, inputs, 3,
                  rc, &generate_sig, correct_sig);
}

void TestPkaAdd(thread_args_t *args)
{
    //BasicTest(args, "pka_add", PKA_ADD, 1,  0, 1);
    BasicTest(args, "pka_add", PKA_ADD, 1,  1, 2);
    BasicTest(args, "pka_add", PKA_ADD, 3,  1, 4);
    BasicTest(args, "pka_add", PKA_ADD, 4,  1, 5);
    BasicTest(args, "pka_add", PKA_ADD, 2,  4, 6);
    BasicTest(args, "pka_add", PKA_ADD, 5,  1, 6);
    BasicTest(args, "pka_add", PKA_ADD, 7,  1, 8);
    BasicTest(args, "pka_add", PKA_ADD, 16, 1, 30);

    BasicTest(args, "pka_add", PKA_ADD, 194, 195, 196);
}

void TestPkaSubtract(thread_args_t *args)
{
    //BasicTest(args, "pka_subtract", PKA_SUBTRACT, 1,  0,  1);
    BasicTest(args, "pka_subtract", PKA_SUBTRACT, 2,  1,  1);
    BasicTest(args, "pka_subtract", PKA_SUBTRACT, 6,  2,  4);
    BasicTest(args, "pka_subtract", PKA_SUBTRACT, 13, 1,  12);
    BasicTest(args, "pka_subtract", PKA_SUBTRACT, 11, 11, 0);
    BasicTest(args, "pki_subtract", PKA_SUBTRACT, 97, 98, 99);

    BasicTest(args, "pki_subtract", PKA_SUBTRACT, 191, 192, 193);
}

void TestPkaMultiply(thread_args_t *args)
{
    //BasicTest(args, "pka_multiply", PKA_MULTIPLY, 1,  0,   0);
    BasicTest(args, "pka_multiply", PKA_MULTIPLY, 9,  9,   13);
    BasicTest(args, "pka_multiply", PKA_MULTIPLY, 16, 17,  31);

    BasicTest(args, "pka_multiply", PKA_MULTIPLY, 188, 189,  190);
}

void TestPkaModulo(thread_args_t *args)
{
    //BasicTest(args, "pka_modulo", PKA_MODULO, 10, 8,  2);
    //BasicTest(args, "pka_modulo", PKA_MODULO, 13, 9,  0);
    BasicTest(args, "pka_modulo", PKA_MODULO, 31, 17, 0);
    //BasicTest(args, "pka_modulo", PKA_MODULO, 18, 17, 33);
    //BasicTest(args, "pka_modulo", PKA_MODULO, 9,  6,  1);

    BasicTest(args, "pka_modulo", PKA_MODULO, 185, 186, 187);
}

void TestPkaModInverse(thread_args_t *args)
{
    BasicTest(args, "pka_mod_inverse", PKA_MOD_INVERSE, 11, 14, 20);
    BasicTest(args, "pka_mod_inverse", PKA_MOD_INVERSE, 7,  14, 21);
    BasicTest(args, "pki_mod_inverse", PKA_MOD_INVERSE, 35, 36, 37);

    BasicTest(args, "pki_mod_inverse", PKA_MOD_INVERSE, 182, 183, 184);
}

void TestPkaShift(thread_args_t *args)
{
    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  1,  16,  9);
    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  5,  8,   9);
    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  5,  24,  13);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 9,  16,  1);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 9,  8,   5);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 13, 24,  5);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 14, 24,  5);

    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  171, 8,  175);
    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  171, 16, 176);
    ShiftTest(args, "pka_shift_left",  PKA_SHIFT_LEFT,  171, 24, 177);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 171, 8,  172);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 171, 16, 173);
    ShiftTest(args, "pka_shift_right", PKA_SHIFT_RIGHT, 171, 24, 174);
}

void TestPkaModExp(thread_args_t *args)
{
    //ModExpTest(args, "pka_mod_exp", 5,  2,  11, 9);     // Odd modulus
    //ModExpTest(args, "pka_mod_exp", 5,  2,  6,  1);     // RC_OPERAND_LENGTH_ERR (length_a)
    //ModExpTest(args, "pka_mod_exp", 12, 11, 14, 22);    // RC_OPERAND_LENGTH_ERR (length_a)
    ModExpTest(args, "pka_mod_exp", 16, 15, 19, 34);

    ModExpTest(args, "pka_mod_exp", 178, 179, 180, 181);

    ModExpWithCrtTest(args, RSA1024, 26, 25);
}

void TestPkaDh(thread_args_t *args)
{
    // Note here that the test operand and result idx are same as that for
    // one of the ModExp test above. This is because Dh is based on 
    // Modular Exponentiation without CRT.
    DhTest(args, 178, 179, 180, 181);
}

void TestPkaEccAdd(thread_args_t *args)
{
    EccAddTest(args, P256, 1, 4, 10);
    EccAddTest(args, P256, 4, 5, 11);
    EccAddTest(args, P256, 5, 6, 12);
    EccAddTest(args, P256, 4, 4, 13);
}

void TestPkaEccMultiply(thread_args_t *args)
{
    // EccMultiplyTest(P256, 1, 2,  3);
    EccMultiplyTest(args, P256, 4, 2,  13);
    EccMultiplyTest(args, P256, 4, 5,  20);
    EccMultiplyTest(args, P256, 5, 6,  21);
    // EccMultiplyTest(P256, 6, 10, 3);
}

void TestPkaEcdh(thread_args_t *args)
{
    // Note here that the test operand and result idx are same as that for
    // Ecc multiply test above. This is because Ecdh is based on 
    // Ecc point multiplication.
    EcdhTest(args, P256, 4, 2, 13);
}

void TestEcdsa(thread_args_t *args)
{
    // The following test comes from RFC4754 Section 8.1.  The indicies are
    // the private_key_idx, the public_key_idx, the hash_idx, the k_idx
    // and finally the correct signature.
    EcdsaTest(args, P256, P256_base_pt, P256_base_pt_order, 40, 40, 41, 42, 40);
    EcdsaTest(args, P384, P384_base_pt, P384_base_pt_order, 50, 50, 51, 52, 50);
    EcdsaTest(args, P521, P521_base_pt, P521_base_pt_order, 60, 60, 61, 62, 60);
}

void TestDsa(thread_args_t *args)
{
    DsaTest(args, DSS_1024_160, 70, 71, 72, 73, 70);
    DsaTest(args, DSS_2048_224, 80, 81, 82, 83, 80);
    DsaTest(args, DSS_3072_256, 90, 91, 92, 93, 90);
}

// When application run multiple threads, this test will fail if it is called
// by every thread. Issues regarding queueing and re-ordering should be fixed.
void SingleThreadTestAll(thread_args_t *args)
{
    // Basic tests:
    TestPkaAdd(args);
    TestPkaSubtract(args);
    TestPkaMultiply(args);
    TestPkaModulo(args);
    TestPkaModInverse(args);

    // Shift tests:
    TestPkaShift(args);

    // Modular exponentiation tests:
    TestPkaModExp(args); //Need new operands (assert!)

    // Diffie-Hellman tests:
    TestPkaDh(args);

    // Basic ECC tests:
    TestPkaEccAdd(args);
    TestPkaEccMultiply(args);

    // ECDSA tests:
    TestEcdsa(args);

    // DSA tests:
    TestDsa(args);

    // ECDH tests:
    TestPkaEcdh(args);
}

static void *thread_start_routine(void *arg)
{
    pka_handle_t   pka_hdl;
    thread_args_t *thread_args;
    uint32_t       thread_idx, cpu_num;

    thread_args = (thread_args_t *) arg;
    thread_idx  =  thread_args->id;
    cpu_num     =  thread_args->cpu_num;

    thread_args->user_data = arg;

    thread_args->ticks = 50;
    thread_args->seed  = 1000 * thread_idx + 10 * cpu_num + 1;

    thread_args->tests_failed = 0;
    thread_args->tests_passed = 0;

    printf("Starting thread_idx=%u on cpu_num=%u\n", thread_idx, cpu_num);
    fflush(NULL);

    pka_barrier_wait(&startup_barrier);

    // Init PK local execution context.
    pka_hdl = pka_init_local(thread_args->instance);
    if (pka_hdl == PKA_HANDLE_INVALID)
    {
        printf("failed to init local\n");
        return NULL;
    }

    // Set thread handle
    thread_args->handle = pka_hdl;

    // Do some stuff here
    //while (gbl_args->exit_threads)
        SingleThreadTestAll(thread_args);

    pka_barrier_wait(&ending_barrier);

    pka_term_local(thread_args->handle);
    //printf("thread %d - term local\n", thread_idx);

    // wait for print_thread_idx to be equal to my thread_idx + 1.
    while (print_thread_idx != (thread_idx + 1))
            pka_wait();

    // Summary;
    printf("%s thread_idx=%u cpu_num=%u done\n\t", __func__,
               thread_idx, cpu_num);
    printf("tests_passed=%u \n\t"
           "tests_failed=%u \n\t"
           "total_tests=%u  \n",
           thread_args->tests_passed,
           thread_args->tests_failed,
           thread_args->tests_passed + thread_args->tests_failed);
    fflush(NULL);

    validation_tests_passed = thread_args->tests_passed;
    validation_tests_failed = thread_args->tests_failed;
    validation_tests_total  =
            validation_tests_passed + validation_tests_failed;

    // Signal the next thread to print its counters.
    print_thread_idx += 1;
    pka_mb_full();

    return NULL;
}

int main(int argc, char *argv[])
{
    app_args_t      *app_args;
    static pthread_t thread_tbl[MAX_THREADS];
    thread_args_t   *thread_args;
    pthread_attr_t   attr;
    cpu_set_t        cpu_set;
    pka_instance_t   pka_instance;
    uint32_t         cpu_num, worker_idx, cmd_queue_sz, rslt_queue_sz;
    uint8_t          flags, rings_num, workers_num;

    int ret = 0;

    gbl_args = calloc(1, sizeof(args_t));
    if (gbl_args == NULL) {
        printf("gbl_args mem alloc failed.\n");
        exit(EXIT_FAILURE);
    }

    // Parse and store the instance arguments
    ParseArgs(argc, argv, &gbl_args->app);

    // Default to system CPU count unless user specified
    workers_num = MAX_THREADS;
    if (gbl_args->app.cpu_count <= MAX_THREADS)
        workers_num = gbl_args->app.cpu_count;

    // Init PKA before calling anything else
    app_args      = &gbl_args->app;
    flags         = app_args->mode | app_args->sync;
    rings_num     = app_args->ring_count;
    cmd_queue_sz  = PKA_MAX_OBJS * PKA_CMD_DESC_MAX_DATA_SIZE;
    rslt_queue_sz = PKA_MAX_OBJS * PKA_RSLT_DESC_MAX_DATA_SIZE;
    pka_instance = pka_init_global(NO_PATH(argv[0]), flags, rings_num,
                            workers_num, cmd_queue_sz,
                            rslt_queue_sz);
    if (pka_instance == PKA_INSTANCE_INVALID)
    {
        printf("failed to init global\n");
        return ret;
    }

    gbl_args->app.instance = pka_instance;

    // Print both system and instance information
    PrintInfo(NO_PATH(argv[0]), &gbl_args->app);

    // Init test parameters
    TestInit();

    printf("num worker threads: %i\n", workers_num);

    // Create and init worker threads
    pka_barrier_init(&startup_barrier, workers_num);
    memset(thread_tbl, 0, sizeof(thread_tbl));
    for (worker_idx = 0; worker_idx < workers_num; worker_idx++)
    {
        thread_args  = &gbl_args->thread[worker_idx];
        cpu_num      = worker_idx % app_args->cpu_count;
        CPU_ZERO(&cpu_set);
        CPU_SET(cpu_num, &cpu_set);
        pthread_attr_init(&attr);
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpu_set);

        // Create threads one-by-one instead of all-at-once,
        // because each thread might get different arguments.
        // Calls pthread_create() for each thread
        thread_args->cpu_num  = cpu_num;
        thread_args->id       = worker_idx;
        thread_args->instance = pka_instance;
        pthread_create(&thread_tbl[worker_idx], &attr,
                               thread_start_routine, (void *) thread_args);
    }

    // Sleep during test and then signal threads to quit.
    pka_barrier_init(&ending_barrier, workers_num);
    //sleep(inst->time);
    //global_quit = TRUE;

    // Now command each thread in turn to dump its stats.
    print_thread_idx = 1;
    pka_mb_full();

    for (worker_idx = 0; worker_idx < workers_num; worker_idx++)
        pthread_join(thread_tbl[worker_idx], NULL);

    sleep(1);

    if (validation_tests_total &&
            (validation_tests_total == validation_tests_passed))
        printf("validation tests passed!\n");
    else
        printf("validation tests failed!\n"
               " tests failed = %u\n"
               " tests passed = %u\n"
               " tests total  = %u\n",
               validation_tests_failed,
               validation_tests_passed,
               validation_tests_total);

    // Remove PK global
    pka_term_global(app_args->instance);

    return 0;
}

// Parse and store the command line arguments
static void ParseArgs(int argc, char *argv[], app_args_t *app_args)
{
    int opt;
    int long_index;
    int i;
    static const struct option longopts[] = {
        {"cpu",   required_argument, NULL, 'c'},
        {"ring",  required_argument, NULL, 'r'},
        {"time",  required_argument, NULL, 't'},
        {"mode",  required_argument, NULL, 'm'},  // return 'm'
        {"sync", required_argument, NULL, 's'},   // return 's'
        {"help",  no_argument,       NULL, 'h'},  // return 'h'
        {NULL, 0, NULL, 0}
    };

    static const char *shortopts = "c:r:t:m:s:h";

    app_args->mode = PKA_F_PROCESS_MODE_SINGLE;
    app_args->sync = PKA_F_SYNC_MODE_ENABLE;
    app_args->time = 5; ///< 0: loop forever

    opterr = 0; // do not issue errors on helper options

    while (1)
    {
        opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

        if (opt == -1)
            break; // No more options

        switch (opt)
        {
        case 'c':
            app_args->cpu_count = atoi(optarg);
            break;
        case 'r':
            app_args->ring_count = atoi(optarg);
            break;
        case 't':
            app_args->time = atoi(optarg);
            break;
        case 'm':
            i = atoi(optarg);
            switch (i)
            {
            case 0:
                app_args->mode = PKA_F_PROCESS_MODE_SINGLE;
                break;
            case 1:
                app_args->mode = PKA_F_PROCESS_MODE_MULTI;
                break;
            default:
                Usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            i = atoi(optarg);
            switch (i)
            {
            case 0:
                app_args->sync = PKA_F_SYNC_MODE_DISABLE;
                break;
            case 1:
                app_args->sync = PKA_F_SYNC_MODE_ENABLE;
                break;
            default:
                Usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            Usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;

        default:
            break;
        }
    }

    if (app_args->cpu_count == 0 || app_args->ring_count == 0)
    {
        Usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    optind = 1; // reset 'extern optind' from the getopt lib
}

static void PrintInfo(char *progname, app_args_t *app_args)
{
    int8_t   mask_idx;
    uint8_t *mask;
    printf("\n"
           "PKA system info\n"
           "---------------\n"
           "PKA API version: %s\n"
           "Cache line size: %d\n"
           "CPU count:       %d\n"
           "Ring count:      %d\n"
           "\n",
           PKA_LIB_VERSION,
           PKA_CACHE_LINE_SIZE,
           app_args->cpu_count,
           app_args->ring_count);

    printf("Running PKA inst: %s\n"
           "-----------------\n"
           "Avail rings:      %d\n",
           progname,
           pka_get_rings_count(app_args->instance));

    mask = pka_get_rings_bitmask(app_args->instance);
    printf("HW rings in use      :  ");
    for (mask_idx = PKA_RING_NUM_BITMASK - 1; mask_idx >= 0; mask_idx--)
        printf("%x", mask[mask_idx]);
    printf("\n\n");
    printf("Mode:            ");
    switch (app_args->mode)
    {
    case PKA_F_PROCESS_MODE_SINGLE:
        PRINT_APPL_MODE(PKA_F_PROCESS_MODE_SINGLE);
        break;
    case PKA_F_PROCESS_MODE_MULTI:
        PRINT_APPL_MODE(PKA_F_PROCESS_MODE_MULTI);
        break;
    }
    printf("Sync:            ");
    switch (app_args->sync)
    {
    case PKA_F_SYNC_MODE_DISABLE:
        PRINT_APPL_MODE(PKA_F_SYNC_MODE_DISABLE);
        break;
    case PKA_F_SYNC_MODE_ENABLE:
        PRINT_APPL_MODE(PKA_F_SYNC_MODE_ENABLE);
        break;
    }
    printf("\n\n");
    fflush(NULL);
}

// Print usage information
static void Usage(char *progname)
{
    printf("\n"
           "Usage: %s OPTIONS\n"
           "  E.g. %s -c 8 -r 4 -s 1\n"
           "\n"
           "PKA example application.\n"
           "\n"
           "Mandatory OPTIONS:\n"
           "  -c, --cpu  <number>  CPU count.\n"
           "  -r, --ring <number>  Ring count.\n"
           "\n"
           "Optional OPTIONS\n"
           "  -t, --time <seconds> Number of seconds to run.\n"
           "  -m, --mode <digit>   Application mode\n"
           "                        0: single process mode (default)\n"
           "                        1: multi process mode\n"
           "  -s, --sync <digit>   Synchronization mode for multithread "
                                   "operations\n"
           "                        0: none of operations are lock-free\n"
           "                        1: all operations are lock-free (default)\n"
           "  -h, --help           Display help and exit.\n"
           "\n", NO_PATH(progname), NO_PATH(progname)
        );
}
