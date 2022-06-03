#ifndef PKA_TEST_UTILS_H
#define PKA_TEST_UTILS_H

#include <stdint.h>
#include <stdbool.h>

#include "pka.h"
#include "pka_utils.h"
#include "pka_vectors.h"

#define PKA_LIB_VERSION     "v1"

#define LOG(min_verbosity, fmt_and_args...)    \
    ({                                         \
        if (min_verbosity <= verbosity)        \
            PKA_PRINT(PKA_TEST, fmt_and_args); \
    })

typedef struct
{
    pka_operand_t *quotient;
    pka_operand_t *remainder;
} quot_and_remain_t;

//
// Types and Fcns to help with test creation
//

// Definition of PKA key "systems"
typedef struct
{
    pka_operand_t *modulus;
} mod_exp_key_system_t;

typedef struct
{
    // Note that the modulus, n,  MUST equal p * q.  The bit_len of the system
    // is the bit_len of n.  p and q are prime numbers where p is always
    // larger than q, and have similar bit_len's.  (private_key * public_key)
    // mod (p-1)*(q-1) must equal 1.  Note that in an RSA "verify" key
    // system, public_key, e, has a secondary len < 33 bits long and has
    // exactly 2 bits set (the MSB and the LSB).
    pka_operand_t *p;
    pka_operand_t *q;
    pka_operand_t *private_key;  // aka d.
    pka_operand_t *public_key;   // aka e.

    // Derived values:
    pka_operand_t *n;            // I.e. modulus = product of p * q.
    pka_operand_t *d_p;          // d mod (p-1)
    pka_operand_t *d_q;          // d mod (q-1)
    pka_operand_t *qinv;         // q * qinv mod p = 1
} rsa_key_system_t;

typedef struct
{
    ecc_mont_curve_t *curve;
    pka_operand_t    *base_pt_x;      // aka x-coordinate of point G
    pka_operand_t    *base_pt_order;  // aka n - order of point G
} mont_ecdh_keys_t;

typedef struct
{
    ecc_curve_t *curve;
    ecc_point_t *base_pt;
} ecc_key_system_t;

typedef struct
{
    ecc_curve_t   *curve;
    ecc_point_t   *base_pt;        // aka point G
    pka_operand_t *base_pt_order;  // aka n - order of point G
    pka_operand_t *private_key;    // aka local d.
    ecc_point_t   *public_key;     // aka point local Q
} ec_key_system_t;

typedef ec_key_system_t  ecdh_key_system_t;
typedef ec_key_system_t  ecdsa_key_system_t;

typedef struct
{
    pka_operand_t *p;            // Must be prime.
    pka_operand_t *q;            // aka n, must be prime. Must divide p-1.
    pka_operand_t *g;            // g^q mod prime = 1?.  1 < g < p.
    pka_operand_t *private_key;  // aka x.  0 < private_key < q
    pka_operand_t *public_key;   // aka y.  y= g^private_key mod prime
} dsa_key_system_t;

// Definition of the "test_*_t types which point to all of the operands
// and answers of a test_desc_t.
typedef struct
{
    pka_operand_t *first;
    pka_operand_t *second;
    uint32_t       shift_cnt;
    pka_operand_t *answer;
    pka_operand_t *answer2;  // Modulus result for TEST_DIV_MOD
} test_basic_t;

typedef struct
{
    pka_operand_t *base;
    pka_operand_t *exponent;
    pka_operand_t *answer;
} test_mod_exp_t;

typedef struct
{
    pka_operand_t *msg;
    pka_operand_t *answer;
} test_rsa_t;

typedef struct
{
    pka_operand_t *base;    // aka msg, c, or plaintext.
    pka_operand_t *answer;
} test_crt_t;

typedef struct
{
    pka_operand_t *point_x;
    pka_operand_t *multiplier;
    pka_operand_t *local_private_key;    // aka local d.
    pka_operand_t *local_public_key;     // aka point local Q
    pka_operand_t *remote_private_key;   // aka remote d.
    pka_operand_t *remote_public_key;    // aka point remote Q
    pka_operand_t *answer;
} test_mont_ecdh_t;


typedef struct
{
    ecc_point_t   *pointA;
    ecc_point_t   *pointB;
    pka_operand_t *multiplier;
    ecc_point_t   *answer;
} test_ecc_t;

typedef struct
{
    pka_operand_t *local_private_key;    // aka local d.
    ecc_point_t   *local_public_key;     // aka point local Q
    pka_operand_t *remote_private_key;   // aka remote d.
    ecc_point_t   *remote_public_key;    // aka point remote Q
    ecc_point_t   *answer;
} test_ecdh_t;

typedef struct
{
    pka_operand_t   *k;          // Secret num unique to each msg.  0 < k < q.
    pka_operand_t   *hash;       // Message hash
    dsa_signature_t *signature;
    dsa_signature_t *answer;
} test_ecdsa_t;

typedef struct
{
    pka_operand_t   *k;          // Secret num unique to each msg.  0 < k < q.
    pka_operand_t   *hash;       // Message hash
    dsa_signature_t *signature;
    dsa_signature_t *answer;
} test_dsa_t;

typedef enum
{
    PKA_TEST, BULK_CRYPTO_TEST   // *TBD* Others?
} test_category_t;

typedef enum
{
    TEST_NOP,  // Represents no valid test.

    // Basic_pka_tests.  These use NO associated PKA key_system_t object.
    TEST_ADD, TEST_SUBTRACT, TEST_MULTIPLY, TEST_DIVIDE, TEST_DIV_MOD,
    TEST_MODULO, TEST_SHIFT_LEFT, TEST_SHIFT_RIGHT, TEST_MOD_INVERT,

    // Modular exponentiation tests.  These use the mod_exp_key_system_t.
    TEST_MOD_EXP,

    // RSA tests.  These use the rsa_key_system_t.
    TEST_RSA_MOD_EXP, TEST_RSA_VERIFY, TEST_RSA_MOD_EXP_WITH_CRT,

    // Montgomery ECC tests.  These use the mont_ecdh_key_system_t.
    TEST_MONT_ECDH_MULTIPLY,

    // Ecc tests.  These use the ecc_key_system_t.
    TEST_ECC_ADD, TEST_ECC_DOUBLE, TEST_ECC_MULTIPLY,

    // Montgomery Ecdh tests.  These use the mont_ecdh_key_system_t.
    TEST_MONT_ECDH, TEST_MONT_ECDHE,

    // Ecdh tests.  These use the ecdh_key_system_t.
    TEST_ECDH, TEST_ECDHE,

    // Ecdsa tests.  These use the ecdsa_key_system_t.
    TEST_ECDSA_GEN, TEST_ECDSA_VERIFY, TEST_ECDSA_GEN_VERIFY,

    // Dsa tests.  These use the dsa_key_system_t.
    TEST_DSA_GEN, TEST_DSA_VERIFY, TEST_DSA_GEN_VERIFY
} pka_test_name_t;

pka_test_name_t lookup_test_name(char *string);
char *test_name_to_string(pka_test_name_t test_name);

typedef struct
{
  //    uint32_t num_requested;
    uint32_t num_cmd_submits;
    uint32_t num_total_submits;
    uint32_t num_good_replies;
    uint32_t num_bad_replies;
    uint32_t num_correct_answers;
    uint32_t num_wrong_answers;
    uint32_t errors;
    uint64_t total_latency;          // units = some multiple of clock cycles.
    uint64_t latency_squared;        // needed to calculate std deviation.

    uint64_t min_latency;            // units of microsecs.
    uint64_t avg_latency;
    uint64_t max_latency;
    uint32_t latency_std_dev;
} test_stats_t;

// There is one *_test_kind_t for kind of test currently being run.  Typically
// there is only one pka_test_kind_t object, but this system allows the
// capability of having mixed tests running siumultaneously (subject to
// certain constraints) using multiple test_kind_t objects.
typedef struct
{
    pka_test_name_t test_name;
    uint32_t        bit_len;          // primary bit_len
    uint32_t        second_bit_len;   // secondary bit_len
    uint32_t        num_key_systems;
    uint32_t        tests_per_key_system;
    bool            create_key_verbosity;
    bool            create_test_verbosity;
    test_stats_t   *test_kind_stats;
} pka_test_kind_t;

// There is a test_desc_t for each unique set of test_operands.
// There can be many test_desc_t objects for each test_kind.  The test_category
// determines the type of the test_kind.  The test_kind, in turn determines
// the numthe type of the test_operands and answer.
typedef struct
{
    test_category_t test_category;  // Determines the test_kind type.
    void           *test_kind;      // points to a *_test_kind_t object above.
    void           *key_system;     // points to a *_key_system_t object above.
    void           *test_operands;  // points to a test_*_t object above
    uint32_t        test_idx;

    // If per test_desc_t stats are not required, then this field is NULL.
    // In all cases however, test_kind_stats are defined and counted.
    test_stats_t *test_desc_stats;
} test_desc_t;

// NIST prime curves:
extern ec_key_system_t P256_ec;
extern ec_key_system_t P384_ec;
extern ec_key_system_t P521_ec;

// Bernstein curves:
// extern ec_mont_key_system_t B255_ec;
// extern ec_mont_key_system_t B488_ec;

//
// helper functions
//

uint32_t byte_len(uint64_t num);

uint8_t *append_bytes(uint8_t *buf_ptr, uint64_t num, uint32_t num_len);

void byte_swap_copy(uint8_t *dest, uint8_t *src, uint32_t len);

void copy_operand(pka_operand_t *original, pka_operand_t *copy);

void print_operand(char *prefix, pka_operand_t *operand, char *suffix);

uint32_t operand_bit_len(pka_operand_t *operand);

uint32_t operand_byte_len(pka_operand_t *operand);

uint8_t is_zero(pka_operand_t *operand);

uint8_t is_one(pka_operand_t *operand);

uint8_t is_even(pka_operand_t *operand);

uint8_t is_odd(pka_operand_t *operand);

pka_operand_t *malloc_operand(uint32_t buf_len);

void free_operand(pka_operand_t *operand);

void init_operand(pka_operand_t *operand,
                  uint8_t       *buf,
                  uint32_t       buf_len,
                  uint8_t        big_endian);

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                            uint32_t  buf_len,
                            uint8_t   big_endian);

pka_operand_t *dup_operand(pka_operand_t *src_operand);

pka_operand_t *rand_operand(pka_handle_t  handle,
                            uint32_t      bit_len,
                            bool          make_odd);

pka_operand_t *rand_non_zero_integer(pka_handle_t   handle,
                                     pka_operand_t *max_plus_1);

bool is_prime(pka_handle_t   handle,
              pka_operand_t *prime,    // aka possible_prime
              uint32_t       iterations,
              bool           should_be_prime);

pka_operand_t *rand_prime_operand(pka_handle_t handle, uint32_t bit_len);

pka_operand_t *hex_string_to_operand(char *string, uint8_t big_endian);

void print_operand(char *prefix, pka_operand_t *operand, char *suffix);

ecc_point_t *malloc_ecc_point(uint32_t x_buf_len,
                              uint32_t y_buf_len,
                              uint8_t  big_endian);

void free_ecc_point(ecc_point_t *ecc_point);

ecc_point_t *make_ecc_point(ecc_curve_t *curve,
                            uint8_t     *big_endian_buf_x_ptr,
                            uint32_t     buf_x_len,
                            uint8_t     *big_endian_buf_y_ptr,
                            uint32_t     buf_y_len,
                            uint8_t      big_endian);

ecc_point_t *create_ecc_point(ecc_curve_t *curve,
                              uint8_t     *big_endian_buf_x_ptr,
                              uint32_t     buf_x_len,
                              uint8_t      big_endian);

void init_ecc_point(ecc_point_t *ecc_pt,
                    uint8_t     *buf_x,
                    uint8_t     *buf_y,
                    uint32_t     buf_len,
                    uint8_t      big_endian);

ecc_curve_t *make_ecc_curve(uint8_t *big_endian_buf_p_ptr,
                            uint32_t p_len,
                            uint8_t *big_endian_buf_a_ptr,
                            uint32_t a_len,
                            uint8_t *big_endian_buf_b_ptr,
                            uint32_t b_len,
                            uint8_t  big_endian);

ecc_curve_t *create_ecc_curve(pka_operand_t     *prime,
                              pka_operand_t     *a,
                              pka_operand_t     *b);

void init_ecc_curve(ecc_curve_t *ecc_curve,
                    uint8_t     *buf_p,
                    uint8_t     *buf_a,
                    uint8_t     *buf_b,
                    uint32_t     buf_len,
                    uint8_t      big_endian);

dsa_signature_t *malloc_dsa_signature(uint32_t r_buf_len,
                                      uint32_t s_buf_len,
                                      uint8_t  big_endian);

void free_dsa_signature(dsa_signature_t *signature);

void init_dsa_signature(dsa_signature_t *signature,
                        uint8_t         *buf_r,
                        uint8_t         *buf_s,
                        uint32_t         buf_len,
                        uint8_t          big_endian);

dsa_signature_t *make_dsa_signature(uint8_t *big_endian_buf_r_ptr,
                                    uint32_t r_len,
                                    uint8_t *big_endian_buf_s_ptr,
                                    uint32_t s_len,
                                    uint8_t  big_endian);

dsa_domain_params_t *make_dsa_domain_params(uint8_t *big_endian_buf_p_ptr,
                                            uint32_t p_len,
                                            uint8_t *big_endian_buf_q_ptr,
                                            uint32_t q_len,
                                            uint8_t *big_endian_buf_g_ptr,
                                            uint32_t g_len,
                                            uint8_t  big_endian);

pka_results_t *malloc_results(uint32_t result_cnt, uint32_t buf_len);

void free_results(pka_results_t *results);

//
// PKI software operations.
//

pka_result_code_t pki_copy(pka_operand_t *value, pka_operand_t *result_ptr);

pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right);

pka_result_code_t pki_add(pka_operand_t *value,
                          pka_operand_t *addend,
                          pka_operand_t *result);

pka_result_code_t pki_subtract(pka_operand_t *value,
                               pka_operand_t *subtrahend,
                               pka_operand_t *result);

pka_result_code_t pki_add_subtract(pka_operand_t *value,
                                   pka_operand_t *addend,
                                   pka_operand_t *subtrahend,
                                   pka_operand_t *result_ptr);

pka_result_code_t pki_multiply(pka_operand_t *value,
                               pka_operand_t *multiplier,
                               pka_operand_t *result);

pka_result_code_t pki_shift_left(pka_operand_t *value,
                                 uint32_t       shift_cnt,
                                 pka_operand_t *result);

pka_result_code_t pki_shift_right(pka_operand_t *value,
                                  uint32_t       shift_cnt,
                                  pka_operand_t *result);

// Note that quotient and remainder are output parameters - all other
// parameters are input.
pka_result_code_t pki_divide(pka_operand_t *value,
                             pka_operand_t *divisor,
                             pka_operand_t *quotient_ptr,
                             pka_operand_t *remainder_ptr);

pka_result_code_t pki_modulo(pka_operand_t *value,
                             pka_operand_t *modulus,
                             pka_operand_t *result_ptr);

pka_result_code_t pki_mod_multiply(pka_operand_t *value,
                                   pka_operand_t *multiplier,
                                   pka_operand_t *modulus,
                                   pka_operand_t *result);

pka_result_code_t pki_mod_exp(pka_operand_t *value,
                              pka_operand_t *exponent,
                              pka_operand_t *modulus,
                              pka_operand_t *result);

pka_result_code_t pki_mod_exp_with_crt(pka_operand_t *value,
                                       pka_operand_t *p,
                                       pka_operand_t *q,
                                       pka_operand_t *d_p,
                                       pka_operand_t *d_q,
                                       pka_operand_t *qinv,
                                       pka_operand_t *result_ptr);

pka_result_code_t pki_mod_inverse(pka_operand_t *value,
                                  pka_operand_t *modulus,
                                  pka_operand_t *result_ptr);

pka_result_code_t pki_mod_square_root(pka_operand_t *value,
                                      pka_operand_t *modulus,
                                      pka_operand_t *result);

pka_result_code_t pki_mod_add(pka_operand_t *value,
                              pka_operand_t *addend,
                              pka_operand_t *modulus,
                              pka_operand_t *result);

pka_result_code_t pki_mod_subtract(pka_operand_t *value,
                                   pka_operand_t *subtrahend,
                                   pka_operand_t *modulus,
                                   pka_operand_t *result);

pka_result_code_t pki_ecc_add(ecc_curve_t *curve,
                              ecc_point_t *pointA,
                              ecc_point_t *pointB,
                              ecc_point_t *result_pt);

pka_result_code_t pki_ecc_multiply(ecc_curve_t   *curve,
                                   ecc_point_t   *pointA,
                                   pka_operand_t *multiplier,
                                   ecc_point_t   *result_point);

// Note that signature_result is an output parameter - all other parameters
// are input.
pka_result_code_t pki_ecdsa_generate(ecc_curve_t     *curve,
                                     ecc_point_t     *base_pt,
                                     pka_operand_t   *base_pt_order,
                                     pka_operand_t   *private_key,
                                     pka_operand_t   *hash,
                                     pka_operand_t   *k,
                                     dsa_signature_t *signature_result);

// Note that the outputs are the optional calc_signature and the
// cmp_code_result -  all other parameters are input.
pka_result_code_t pki_ecdsa_verify(ecc_curve_t     *curve,
                                   ecc_point_t     *base_pt,
                                   pka_operand_t   *base_pt_order,
                                   ecc_point_t     *public_key,
                                   pka_operand_t   *hash,
                                   dsa_signature_t *rcvd_signature,
                                   dsa_signature_t *calc_signature_ptr,
                                   pka_cmp_code_t  *cmp_code_result_ptr);

// Note that signature_result is an output parameter - all other parameters
// are input.
pka_result_code_t pki_dsa_generate(pka_operand_t   *p,
                                   pka_operand_t   *q,
                                   pka_operand_t   *g,
                                   pka_operand_t   *private_key,
                                   pka_operand_t   *hash,
                                   pka_operand_t   *k,
                                   dsa_signature_t *signature_result_ptr);

// Note that the outputs are the optional calc_signature and the
// cmp_code_result -  all other parameters are input.
pka_result_code_t pki_dsa_verify(pka_operand_t   *p,
                                 pka_operand_t   *q,
                                 pka_operand_t   *g,
                                 pka_operand_t   *public_key,
                                 pka_operand_t   *hash,
                                 dsa_signature_t *rcvd_signature,
                                 dsa_signature_t *calc_signature_ptr,
                                 pka_cmp_code_t  *cmp_code_result_ptr);

pka_result_code_t modular_square_root(pka_operand_t *value,
                                      pka_operand_t *modulus,
                                      pka_operand_t *result);

bool ecc_points_are_equal(ecc_point_t *pointA, ecc_point_t *pointB);

bool signatures_are_equal(dsa_signature_t *left_sig,
                          dsa_signature_t *right_sig);

bool is_valid_curve(pka_handle_t handle, ecc_curve_t *curve);

uint8_t is_point_on_mont_curve(ecc_mont_curve_t *curve, ecc_point_t *point);
uint8_t is_point_on_curve(ecc_curve_t *curve, ecc_point_t *point);

//
// Software PKA calls
//

pka_operand_t *sw_add(pka_handle_t   handle,
                      pka_operand_t *value,
                      pka_operand_t *addend);

pka_operand_t *sw_subtract(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *subtrahend);

pka_operand_t *sw_multiply(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *multiplier);

pka_operand_t *sw_divide(pka_handle_t   handle,
                         pka_operand_t *dividend,
                         pka_operand_t *divisor);

pka_operand_t *sw_modulo(pka_handle_t   handle,
                         pka_operand_t *value,
                         pka_operand_t *modulus);

pka_operand_t *sw_shift_left(pka_handle_t   handle,
                             pka_operand_t *value,
                             uint32_t       shift_cnt);

pka_operand_t *sw_shift_right(pka_handle_t   handle,
                              pka_operand_t *value,
                              uint32_t       shift_cnt);

pka_operand_t *sw_mod_inverse(pka_handle_t   handle,
                              pka_operand_t *value,
                              pka_operand_t *modulus);

pka_operand_t *sw_mod_add(pka_handle_t   handle,
                          pka_operand_t *value,
                          pka_operand_t *addend,
                          pka_operand_t *modulus);

pka_operand_t *sw_mod_subtract(pka_handle_t   handle,
                               pka_operand_t *value,
                               pka_operand_t *subtrahend,
                               pka_operand_t *modulus);

pka_operand_t *sw_mod_multiply(pka_handle_t   handle,
                               pka_operand_t *value,
                               pka_operand_t *multiplier,
                               pka_operand_t *modulus);

pka_operand_t *sw_mod_exp(pka_handle_t   handle,
                          pka_operand_t *exponent,
                          pka_operand_t *modulus,
                          pka_operand_t *msg);

pka_operand_t *sw_mod_exp_with_crt(pka_handle_t   handle,
                                   pka_operand_t *p,
                                   pka_operand_t *q,
                                   pka_operand_t *msg,
                                   pka_operand_t *d_p,
                                   pka_operand_t *d_q,
                                   pka_operand_t *qinv);

pka_operand_t *sw_mont_ecdh_multiply(pka_handle_t      handle,
                                     ecc_mont_curve_t *curve,
                                     pka_operand_t    *point_x,
                                     pka_operand_t    *multiplier);

ecc_point_t *sw_ecc_add(pka_handle_t  handle,
                        ecc_curve_t  *curve,
                        ecc_point_t  *pointA,
                        ecc_point_t  *pointB);

ecc_point_t *sw_ecc_multiply(pka_handle_t   handle,
                             ecc_curve_t   *curve,
                             ecc_point_t   *pointA,
                             pka_operand_t *multiplier);

dsa_signature_t *sw_ecdsa_gen(pka_handle_t   handle,
                              ecc_curve_t   *curve,
                              ecc_point_t   *base_pt,
                              pka_operand_t *base_pt_order,
                              pka_operand_t *private_key,
                              pka_operand_t *hash,
                              pka_operand_t *k);

pka_status_t sw_ecdsa_verify(pka_handle_t       handle,
                             ecc_curve_t       *curve,
                             ecc_point_t       *base_pt,
                             pka_operand_t     *base_pt_order,
                             ecc_point_t       *public_key,
                             pka_operand_t     *hash,
                             dsa_signature_t   *signature);

dsa_signature_t *sw_dsa_gen(pka_handle_t       handle,
                            pka_operand_t     *p,
                            pka_operand_t     *q,
                            pka_operand_t     *g,
                            pka_operand_t     *private_key,
                            pka_operand_t     *hash,
                            pka_operand_t     *k);

pka_status_t sw_dsa_verify(pka_handle_t       handle,
                           pka_operand_t     *p,
                           pka_operand_t     *q,
                           pka_operand_t     *g,
                           pka_operand_t     *public_key,
                           pka_operand_t     *hash,
                           dsa_signature_t   *signature);

//
// Synchronous PKA calls
//

pka_operand_t *sync_add(pka_handle_t   handle,
                        pka_operand_t *value,
                        pka_operand_t *addend);

pka_operand_t *sync_subtract(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *subtrahend);

pka_operand_t *sync_multiply(pka_handle_t   handle,
                             pka_operand_t *value,
                             pka_operand_t *multipler);

pka_operand_t *sync_divide(pka_handle_t   handle,
                           pka_operand_t *dividend,
                           pka_operand_t *divisor);

pka_operand_t *sync_modulo(pka_handle_t   handle,
                           pka_operand_t *value,
                           pka_operand_t *modulus);

pka_operand_t *sync_shift_left(pka_handle_t   handle,
                               pka_operand_t *value,
                               uint32_t       shift_cnt);

pka_operand_t *sync_shift_right(pka_handle_t   handle,
                                pka_operand_t *value,
                                uint32_t       shift_cnt);

pka_operand_t *sync_mod_inverse(pka_handle_t   handle,
                                pka_operand_t *value,
                                pka_operand_t *modulus);

pka_operand_t *sync_mod_add(pka_handle_t   handle,
                            pka_operand_t *value,
                            pka_operand_t *addend,
                            pka_operand_t *modulus);

pka_operand_t *sync_mod_subtract(pka_handle_t   handle,
                                 pka_operand_t *value,
                                 pka_operand_t *subtrahend,
                                 pka_operand_t *modulus);

pka_operand_t *sync_mod_multiply(pka_handle_t   handle,
                                 pka_operand_t *value,
                                 pka_operand_t *multiplier,
                                 pka_operand_t *modulus);

pka_operand_t *sync_mod_exp(pka_handle_t   handle,
                            pka_operand_t *exponent,
                            pka_operand_t *modulus,
                            pka_operand_t *msg);

pka_operand_t *sync_mod_exp_with_crt(pka_handle_t   handle,
                                     pka_operand_t *p,
                                     pka_operand_t *q,
                                     pka_operand_t *msg,
                                     pka_operand_t *d_p,
                                     pka_operand_t *d_q,
                                     pka_operand_t *qinv);

pka_operand_t *sync_mont_ecdh_multiply(pka_handle_t      handle,
                                       ecc_mont_curve_t *curve,
                                       pka_operand_t    *pointA_x,
                                       pka_operand_t    *multiplier);

ecc_point_t *sync_ecc_add(pka_handle_t  handle,
                          ecc_curve_t  *curve,
                          ecc_point_t  *pointA,
                          ecc_point_t  *pointB);

ecc_point_t *sync_ecc_multiply(pka_handle_t   handle,
                               ecc_curve_t   *curve,
                               ecc_point_t   *pointA,
                               pka_operand_t *multiplier);

ecc_point_t *sync_mont_ecdh(pka_handle_t      handle,
                            ecc_mont_curve_t *curve,
                            ecc_point_t      *point,
                            pka_operand_t    *private_key);

pka_status_t chk_bit_lens(pka_test_kind_t *test_kind);


pka_status_t create_pka_test_descs(pka_handle_t     handle,
                                   pka_test_kind_t *test_kind,
                                   test_desc_t     *test_descs[],
                                   bool             make_answers,
                                   uint32_t         verbosity);

dsa_signature_t *sync_ecdsa_gen(pka_handle_t   handle,
                                ecc_curve_t   *curve,
                                ecc_point_t   *base_pt,
                                pka_operand_t *base_pt_order,
                                pka_operand_t *private_key,
                                pka_operand_t *hash,
                                pka_operand_t *k);

pka_status_t sync_ecdsa_verify(pka_handle_t       handle,
                               ecc_curve_t       *curve,
                               ecc_point_t       *base_pt,
                               pka_operand_t     *base_pt_order,
                               ecc_point_t       *public_key,
                               pka_operand_t     *hash,
                               dsa_signature_t   *signature);

dsa_signature_t *sync_dsa_gen(pka_handle_t       handle,
                              pka_operand_t     *p,
                              pka_operand_t     *q,
                              pka_operand_t     *g,
                              pka_operand_t     *private_key,
                              pka_operand_t     *hash,
                              pka_operand_t     *k);

pka_status_t sync_dsa_verify(pka_handle_t       handle,
                             pka_operand_t     *p,
                             pka_operand_t     *q,
                             pka_operand_t     *g,
                             pka_operand_t     *public_key,
                             pka_operand_t     *hash,
                             dsa_signature_t   *signature);

//
// Test helper functions
//

pka_status_t create_pka_test_descs(pka_handle_t     handle,
                                   pka_test_kind_t *test_kind,
                                   test_desc_t     *test_descs[],
                                   bool             make_answers,
                                   uint32_t         verbosity);

void free_pka_test_descs(test_desc_t *test_descs[]);

pka_status_t chk_bit_lens(pka_test_kind_t *test_kind);

void init_test_utils(pka_handle_t handle);

pka_status_t get_rand_bytes(pka_handle_t  handle,
                            uint8_t      *buf,
                            uint32_t      buf_len);

#endif // PKA_TEST_UTILS_H
