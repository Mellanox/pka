/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>
#include <openssl/ossl_typ.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#include "ec_local.h"
#endif

#include "pka_helper.h"

/* Attempt to have a single source for both 1.0 and 1.1 */
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#  define BLUEFIELD_DYNAMIC_ENGINE
#else
# error "Only OpenSSL >= 1.0 is supported"
#endif

#ifdef BLUEFIELD_DYNAMIC_ENGINE
/* Engine id and name */
static const char *engine_pka_id = "pka";
static const char *engine_pka_name = "BlueField PKA engine support";

/* Engine lifetime functions */
static int engine_pka_destroy(ENGINE *e);
static int engine_pka_init(ENGINE *e);
static int engine_pka_finish(ENGINE *e);
void engine_load_pka_int(void);

/* BN mod_exp */
static int engine_pka_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* DSA stuff */
#ifndef NO_DSA
static int engine_pka_dsa_init(DSA *dsa);
static int engine_pka_dsa_finish(DSA *dsa);
#endif

/* RSA stuff */
#ifndef NO_RSA
static int engine_pka_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                    BN_CTX *ctx);

static int engine_pka_rsa_init(RSA *rsa);
static int engine_pka_rsa_finish(RSA *rsa);
#endif

/* DH stuff */
#ifndef NO_DH
static int engine_pka_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
                                    const BIGNUM *p, const BIGNUM *m,
                                    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int engine_pka_dh_init(DH *dh);
static int engine_pka_dh_finish(DH *dh);
#endif

/* RAND stuff */
#ifndef NO_RAND
static int engine_pka_get_random_bytes(unsigned char *buf, int num);
static int engine_pka_random_status(void);
static RAND_METHOD pka_rand_meth = {
    NULL,
    engine_pka_get_random_bytes,
    NULL,
    NULL,
    engine_pka_get_random_bytes,
    engine_pka_random_status
};
#endif

# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
/* BN mod_inv */
static int
engine_pka_bn_mod_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *x,
                      BN_CTX *ctx);
/* RSA stuff */
#ifndef NO_RSA
static RSA_METHOD *pka_rsa_meth = NULL;
#endif

/* DSA stuff */
#ifndef NO_DSA
static int engine_pka_dsa_mod_exp(DSA *dsa, BIGNUM *rr, const BIGNUM *a1,
                                  const BIGNUM *p1, const BIGNUM *a2,
                                  const BIGNUM *p2, const BIGNUM *m,
                                  BN_CTX *ctx, BN_MONT_CTX *in_mont);
static int engine_pka_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a,
                                     const BIGNUM *p, const BIGNUM *m,
                                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static DSA_METHOD *pka_dsa_meth = NULL;
#endif

/* DH stuff */
#ifndef NO_DH
static DH_METHOD *pka_dh_meth = NULL;
#endif

/* EC stuff */
#ifndef NO_EC
/* ECC POINT ADD */
static int
engine_pka_ecc_pt_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                      const EC_POINT *b, BN_CTX *ctx);

/* ECC POINT MULT */
static int
engine_pka_ecc_pt_mult(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                       size_t num, const EC_POINT *points[],
                       const BIGNUM *scalars[], BN_CTX *ctx);

static int
override_pka_methods(const EC_KEY *eckey, EC_GROUP **dup_group_ptr,
                     EC_KEY **dup_key_ptr);
/* ECDH stuff */
#ifndef NO_ECDH
static int
engine_pka_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key,
                            const EC_KEY *ecdh);

/* OpenSSL ECDH placeholder */
int (*ossl_ecdh_compute_key)(unsigned char **pout, size_t *poutlen,
                             const EC_POINT *pub_key, const EC_KEY *ecdh);
#endif /* ECDH */

/* ECDSA stuff */
#ifndef NO_ECDSA
static int
engine_pka_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp);

static int
engine_pka_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                      unsigned char *sig, unsigned int *siglen,
                      const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

static ECDSA_SIG*
engine_pka_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                          const BIGNUM *in_kinv, const BIGNUM *in_r,
                          EC_KEY *eckey);

static int
engine_pka_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

static int
engine_pka_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                            const ECDSA_SIG *sig, EC_KEY *eckey);

/* OpennSSL ECDSA placeholders */
int (*ossl_sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                 *sig, unsigned int *siglen, const BIGNUM *kinv,
                 const BIGNUM *r, EC_KEY *eckey);

int (*ossl_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                       BIGNUM **rp);

ECDSA_SIG *(*ossl_sign_sig)(const unsigned char *dgst, int dgst_len,
                            const BIGNUM *in_kinv, const BIGNUM *in_r,
                            EC_KEY *eckey);

int (*ossl_verify)(int type, const unsigned char *dgst, int dgst_len,
                   const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

int (*ossl_verify_sig)(const unsigned char *dgst, int dgst_len,
                       const ECDSA_SIG *sig, EC_KEY *eckey);

#endif /* ECDSA */

static EC_KEY_METHOD        *pka_ec_key_meth = NULL;
static const EC_KEY_METHOD  *ec_key_meth     = NULL;
#endif /* EC */

# else // OpenSSL >=1.0.0 && < 1.0.1
/* RSA stuff */
#ifndef NO_RSA
static RSA_METHOD pka_rsa_meth = {
    "BlueField RSA method",
    NULL,
    NULL,
    NULL,
    NULL,
    engine_pka_rsa_mod_exp,
    engine_pka_bn_mod_exp,
    engine_pka_rsa_init,
    engine_pka_rsa_finish,
    0,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif

/* DSA stuff */
#ifndef NO_DSA
static int engine_pka_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                                  BIGNUM *p1, BIGNUM *a2,
                                  BIGNUM *p2, BIGNUM *m,
                                  BN_CTX *ctx, BN_MONT_CTX *in_mont);
static int engine_pka_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a,
                                     const BIGNUM *p, const BIGNUM *m,
                                     BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static DSA_METHOD pka_dsa_meth = {
    "BlueField DSA method",
    NULL,
    NULL,
    NULL,
    engine_pka_dsa_mod_exp,
    engine_pka_dsa_bn_mod_exp,
    engine_pka_dsa_init,
    engine_pka_dsa_finish,
    0,
    NULL,
    NULL,
    NULL
};
#endif

/* DH stuff */
#ifndef NO_DH
static DH_METHOD pka_dh_meth = {
    "BlueField DH method",
    NULL,
    NULL,
    engine_pka_dh_bn_mod_exp,
    engine_pka_dh_init,
    engine_pka_dh_finish,
    0,
    NULL,
    NULL
};
#endif
/* EC stuff */
/* rand stuff */
# endif

static int bind_pka(ENGINE *e)
{
    int rc = 1;

# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#ifndef NO_RSA
    /* Setup our RSA_METHOD that we provide pointers to */
    if ((pka_rsa_meth = RSA_meth_new("BlueField RSA method", 0)) == NULL
        || rc != RSA_meth_set_mod_exp(pka_rsa_meth, engine_pka_rsa_mod_exp)
        || rc != RSA_meth_set_bn_mod_exp(pka_rsa_meth, engine_pka_bn_mod_exp)
        || rc != RSA_meth_set_init(pka_rsa_meth, engine_pka_rsa_init)
        || rc != RSA_meth_set_finish(pka_rsa_meth, engine_pka_rsa_finish))
    {
        printf("ERROR: failed to setup BlueField RSA method\n");
        return 0;
    }

    /*
     * We know that the "RSA_PKCS1_OpenSSL()" functions hook properly
     * to the bluefield-specific engine_pka_rsa_mod_exp so we use
     * those functions.
     */
    const RSA_METHOD *meth  = RSA_PKCS1_OpenSSL();
    rc   &= RSA_meth_set_pub_enc(pka_rsa_meth, RSA_meth_get_pub_enc(meth));
    rc   &= RSA_meth_set_pub_dec(pka_rsa_meth, RSA_meth_get_pub_dec(meth));
    rc   &= RSA_meth_set_priv_enc(pka_rsa_meth, RSA_meth_get_priv_enc(meth));
    rc   &= RSA_meth_set_priv_dec(pka_rsa_meth, RSA_meth_get_priv_dec(meth));
    if (!rc)
    {
        printf("ERROR: failed to hook PKCS1_SSLeay() functions\n");
        return 0;
    }
#endif

#ifndef NO_DSA
    /* Setup our DSA_METHOD that we provide pointers to */
    if ((pka_dsa_meth = DSA_meth_new("BlueField DSA method", 0)) == NULL
        || rc != DSA_meth_set_mod_exp(pka_dsa_meth, engine_pka_dsa_mod_exp)
        || rc != DSA_meth_set_bn_mod_exp(pka_dsa_meth, engine_pka_dsa_bn_mod_exp)
        || rc != DSA_meth_set_init(pka_dsa_meth, engine_pka_dsa_init)
        || rc != DSA_meth_set_finish(pka_dsa_meth, engine_pka_dsa_finish))
    {
        printf("ERROR: failed to setup BlueField DSA method\n");
        return 0;
    }

    const DSA_METHOD *dsa_meth = DSA_OpenSSL();
    rc &= DSA_meth_set_sign(pka_dsa_meth, DSA_meth_get_sign(dsa_meth));
    rc &= DSA_meth_set_sign_setup(pka_dsa_meth, DSA_meth_get_sign_setup(dsa_meth));
    rc &= DSA_meth_set_verify(pka_dsa_meth, DSA_meth_get_verify(dsa_meth));
    if (!rc)
    {
        printf("ERROR: failed to hook DSA_OpenSSL() functions\n");
        return 0;
    }
#endif

#ifndef NO_DH
    /* Setup our DH_METHOD that we provide pointers to */
    if ((pka_dh_meth = DH_meth_new("BlueField DH method", 0)) == NULL
        || rc != DH_meth_set_bn_mod_exp(pka_dh_meth, engine_pka_dh_bn_mod_exp)
        || rc != DH_meth_set_init(pka_dh_meth, engine_pka_dh_init)
        || rc != DH_meth_set_finish(pka_dh_meth, engine_pka_dh_finish))
    {
        printf("ERROR: failed to setup BlueField DH method\n");
        return 0;
    }

    /*
     * We know that the "DH_OpenSSL()" functions hook properly
     * to the bluefield-specific engine_pka_rsa_mod_exp so we use
     * those functions.
     */
    const DH_METHOD *dh_meth  = DH_OpenSSL();
    rc   &= DH_meth_set_generate_key(pka_dh_meth, DH_meth_get_generate_key(dh_meth));
    rc   &= DH_meth_set_compute_key(pka_dh_meth, DH_meth_get_compute_key(dh_meth));
    if (!rc)
    {
        printf("ERROR: failed to hook DH_OpenSSL() functions\n");
        return 0;
    }
#endif

#ifndef NO_EC
    /* Setup our EC_KEY_METHOD that we provide pointers to */
    ec_key_meth     = EC_KEY_OpenSSL();
    pka_ec_key_meth = EC_KEY_METHOD_new(ec_key_meth);

#ifndef NO_ECDH
    EC_KEY_METHOD_set_compute_key(pka_ec_key_meth,
                                  engine_pka_ecdh_compute_key);

    /* Get OpenSSL ECDH compute */
    EC_KEY_METHOD_get_compute_key(ec_key_meth, &ossl_ecdh_compute_key);
#endif /* ECDH */

#ifndef NO_ECDSA
    EC_KEY_METHOD_set_sign(pka_ec_key_meth, engine_pka_ecdsa_sign,
                           engine_pka_ecdsa_sign_setup,
                           engine_pka_ecdsa_sign_sig);

    EC_KEY_METHOD_set_verify(pka_ec_key_meth, engine_pka_ecdsa_verify,
                             engine_pka_ecdsa_verify_sig);

    /* Get OpenSSL methods */
    EC_KEY_METHOD_get_sign(ec_key_meth, &ossl_sign, &ossl_sign_setup, &ossl_sign_sig);

    EC_KEY_METHOD_get_verify(ec_key_meth, &ossl_verify, &ossl_verify_sig);

#endif /* ECDSA */

#endif /* EC */

#ifndef NO_RAND
    const RAND_METHOD *rand_meth = RAND_OpenSSL();
    pka_rand_meth.seed = rand_meth->seed;
    pka_rand_meth.cleanup = rand_meth->cleanup;
    pka_rand_meth.add = rand_meth->add;
#endif

# else // OpenSSL >=1.0.0 && < 1.0.1
#ifndef NO_RSA
    /*
     * We know that the "RSA_PKCS1_SSLeay()" functions hook properly
     * to the bluefield-specific engine_pka_rsa_mod_exp so we use
     * those functions.
     */
    const RSA_METHOD *meth  = RSA_PKCS1_SSLeay();
    pka_rsa_meth.rsa_pub_enc = meth->rsa_pub_enc;
    pka_rsa_meth.rsa_pub_dec = meth->rsa_pub_dec;
    pka_rsa_meth.rsa_priv_enc = meth->rsa_priv_enc;
    pka_rsa_meth.rsa_priv_dec = meth->rsa_priv_dec;
#endif

    /* Setup our DSA_METHOD that we provide pointers to */
#ifndef NO_DSA
    /*
     * We know that the "DSA_OpenSSL()" functions hook properly
     * to the bluefield-specific engine_pka_dsa_mod_exp and
     * engine_pka_dsa_bn_mod_exp, so we use those functions.
     */
    const DSA_METHOD *dsa_meth  = DSA_OpenSSL();
    pka_dsa_meth.dsa_do_sign    = dsa_meth->dsa_do_sign;
    pka_dsa_meth.dsa_sign_setup = dsa_meth->dsa_sign_setup;
    pka_dsa_meth.dsa_do_verify  = dsa_meth->dsa_do_verify;
#endif

    /* Setup our DH_METHOD that we provide pointers to */
#ifndef NO_DH
    /*
     * We know that the "DH_OpenSSL()" functions hook properly
     * to the bluefield-specific engine_pka_dh_bn_mod_exp so we use
     * those functions.
     */
    const DH_METHOD *dh_meth = DH_OpenSSL();
    pka_dh_meth.generate_key = dh_meth->generate_key;
    pka_dh_meth.compute_key  = dh_meth->compute_key;
#endif
    /* Setup our RAND_METHOD that we provide pointers to */
#ifndef NO_RAND
    const RAND_METHOD *rand_meth = RAND_SSLeay();
    pka_rand_meth.seed = rand_meth->seed;
    pka_rand_meth.cleanup = rand_meth->cleanup;
    pka_rand_meth.add = rand_meth->add;
#endif
# endif

    if (rc != ENGINE_set_id(e, engine_pka_id)
        || rc != ENGINE_set_name(e, engine_pka_name)
#ifndef NO_RAND
        || rc != ENGINE_set_RAND(e, &pka_rand_meth)
#endif
# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#ifndef NO_RSA
        || rc != ENGINE_set_RSA(e, pka_rsa_meth)
#endif
#ifndef NO_DSA
        || rc != ENGINE_set_DSA(e, pka_dsa_meth)
#endif
#ifndef NO_DH
        || rc != ENGINE_set_DH(e, pka_dh_meth)
#endif
#ifndef NO_EC
        || rc != ENGINE_set_EC(e, pka_ec_key_meth)
#endif
# else // OpenSSL >=1.0.0 && < 1.0.1
#ifndef NO_RSA
        || rc != ENGINE_set_RSA(e, &pka_rsa_meth)
#endif
#ifndef NO_DSA
        || rc != ENGINE_set_DSA(e, &pka_dsa_meth)
#endif
#ifndef NO_DH
        || rc != ENGINE_set_DH(e, &pka_dh_meth)
#endif
# endif
        || rc != ENGINE_set_destroy_function(e, engine_pka_destroy)
        || rc != ENGINE_set_init_function(e, engine_pka_init)
        || rc != ENGINE_set_finish_function(e, engine_pka_finish))
    {
        printf("ERROR: failed to setup ENGINE [%s] %s\n",
               engine_pka_id, engine_pka_name);
        return 0;
    }

    return 1;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_pka_id) != 0))
        return 0;
    if (!bind_pka(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

static ENGINE *engine_pka(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_pka(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_pka_int(void)
{
    ENGINE *toadd = engine_pka();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
}

static int engine_pka_init(ENGINE *e)
{
    return pka_init();
}

static int engine_pka_finish(ENGINE *e)
{
    return pka_finish();
}

static int engine_pka_destroy(ENGINE *e)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#ifndef NO_RSA
    RSA_meth_free(pka_rsa_meth);
#endif
#ifndef NO_DSA
    DSA_meth_free(pka_dsa_meth);
#endif
#ifndef NO_DH
    DH_meth_free(pka_dh_meth);
#ifndef NO_EC
    EC_KEY_METHOD_free(pka_ec_key_meth);
#endif
#endif
#endif
    return 1;
}

/* BN operations */

/* BN_mod_exp */
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int
engine_pka_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    BIGNUM *result;
    int     rc, result_bit_len;

    rc = 0;

    result         = BN_new();
    result_bit_len = BN_num_bits(m);

    /* Expand the result bn so that it can hold our big num */
    if (!BN_lshift(result, result, result_bit_len))
    {
        printf("ERROR: bn_mod_exp failed to expand RSA result component\n");
        goto end;
    }

    rc = pka_bn_mod_exp((pka_bignum_t *) a,
                        (pka_bignum_t *) p,
                        (pka_bignum_t *) m,
                        (pka_bignum_t *) result);

    if (!rc || BN_copy(r, result) == NULL)
        rc = 0;

end:
    BN_free(result);
    return rc;
}

#ifndef NO_RAND
static int
engine_pka_get_random_bytes(unsigned char *buf, int num)
{
    unsigned char *pka_buf;
    int            ret;

    if (buf == NULL || num <= 0)
        return 0;

    pka_buf = calloc(num, sizeof(unsigned char));
    if (pka_buf == NULL)
    {
        printf("ERROR: Buffer memory allocation failed.\n");
        return 0;
    }

    ret = pka_get_random_bytes(pka_buf, num);
    memcpy(buf, pka_buf, num);

    free(pka_buf);
    return (num == ret) ? 1 : 0;
}

static int
engine_pka_random_status(void)
{
    return 1;
}
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
/* BN_mod_inv */
static int
engine_pka_bn_mod_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *x,
                      BN_CTX *ctx)
{
    if(group == NULL || r == NULL || x == NULL)
        return 0;

    int     rc, result_bit_len;
    BIGNUM *order  = BN_new();
    BIGNUM *result = BN_new();
    rc             = 0;

    EC_GROUP_get_order(group, order, ctx);

    result_bit_len = BN_num_bits(order);

    /* Expand the result bn so that it can hold our big num */
    if (!BN_set_bit(result, result_bit_len))
    {
        printf("ERROR: bn_mod_inv failed to expand Inverse result component\n");
        goto end;
    }

    rc = pka_bn_mod_inv((pka_bignum_t *) x,
                        (pka_bignum_t *) order,
                        (pka_bignum_t *) result);

    if (!rc || BN_copy(r, result) == NULL)
        rc = 0;

end:
    BN_free(result);
    return rc;

}
#endif

#ifndef NO_RSA
/* RSA implementation */
static int
engine_pka_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    int           rc = 0, result_bit_len;
    BIGNUM       *result;
# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    const BIGNUM *n, *e, *d;
    const BIGNUM *p, *q, *dmp1, *dmq1, *iqmp;

    /* Do not check input parameters - ignore errors; we carry on anyway */
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    RSA_get0_key(rsa, &n, &e, &d);

    if (n != NULL)
    {
        result         = BN_new();
        result_bit_len = BN_num_bits(n);
        /* Expand the result bn so that it can hold our big num */
        if (!BN_lshift(result, result, result_bit_len))
        {
            printf("ERROR: failed to expand RSA result component\n");
            goto end;
        }

        /* *TBD* Perform in software if modulus is too large for hardware. */

        /* See if we have all the necessary bits for a crt */
        if (p && q && dmp1 && dmq1 && iqmp) {
            rc = pka_rsa_mod_exp_crt((pka_bignum_t *) I,
                                     (pka_bignum_t *) p,
                                     (pka_bignum_t *) q,
                                     (pka_bignum_t *) dmp1,
                                     (pka_bignum_t *) dmq1,
                                     (pka_bignum_t *) iqmp,
                                     (pka_bignum_t *) result);
        }
        else if (d)
        {
            rc = pka_bn_mod_exp((pka_bignum_t *) I,
                                (pka_bignum_t *) d,
                                (pka_bignum_t *) n,
                                (pka_bignum_t *) result);
        }
# else
    if (rsa->n != NULL)
    {
        result         = BN_new();
        result_bit_len = BN_num_bits(rsa->n);
        /* Expand the result bn so that it can hold our big num */
        if (!BN_lshift(result, result, result_bit_len))
        {
            printf("ERROR: failed to expand RSA result component\n");
            goto end;
        }

        /* *TBD* Perform in software if modulus is too large for hardware. */

        /* See if we have all the necessary bits for a crt */
        if (rsa->p && rsa->q && rsa->dmp1 && rsa->dmq1 && rsa->iqmp) {
            rc = pka_rsa_mod_exp_crt((pka_bignum_t *) I,
                                     (pka_bignum_t *) rsa->p,
                                     (pka_bignum_t *) rsa->q,
                                     (pka_bignum_t *) rsa->dmp1,
                                     (pka_bignum_t *) rsa->dmq1,
                                     (pka_bignum_t *) rsa->iqmp,
                                     (pka_bignum_t *) result);
        }
        else if (rsa->d)
        {
            rc = pka_bn_mod_exp((pka_bignum_t *) I,
                                (pka_bignum_t *) rsa->d,
                                (pka_bignum_t *) rsa->n,
                                (pka_bignum_t *) result);
        }
# endif
        else
        {
            printf("ERROR: RSA missing key components\n");
            goto end;
        }

        if (rc && BN_copy(r0, result) != NULL)
            goto end;
    }
    else
    {
        printf("ERROR: RSA missing modulus component\n");
        return 0;
    }

end:
    BN_free(result);
    return rc;
}

static int engine_pka_rsa_init(RSA *rsa)
{
    return pka_init();
}

static int engine_pka_rsa_finish(RSA *rsa)
{
    return pka_finish();
}
#endif

#ifndef NO_DSA
/* DSA implementation */
static int
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
engine_pka_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                          const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
#else
engine_pka_dsa_bn_mod_exp(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                          const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
#endif
{
    return engine_pka_bn_mod_exp(r, a, p, m, ctx, m_ctx);
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
static int engine_pka_dsa_mod_exp(DSA *dsa, BIGNUM *rr, const BIGNUM *a1,
                                  const BIGNUM *p1, const BIGNUM *a2,
                                  const BIGNUM *p2, const BIGNUM *m,
                                  BN_CTX *ctx, BN_MONT_CTX *in_mont)
#else
static int engine_pka_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                                  BIGNUM *p1, BIGNUM *a2,
                                  BIGNUM *p2, BIGNUM *m,
                                  BN_CTX *ctx, BN_MONT_CTX *in_mont)
#endif
{
    // Algorithm: rr = a1^p1 * a2^p2 mod m
    BIGNUM *t;
    int rc;

    rc = 1;
    t  = BN_new();

    // t = a1^p1 mod m*/
    // rr = a2^p2 mod m */
    // rr = rr * t mod m */
    // TBD: BN_mod_mul() below can be replaced with pka library functions,
    //      it has to be checked whether this will improve the performance
    //      or the overhead of converting BN to pka_operand_t and vice versa
    //      will be detrimental to the performance. Also, it has to be
    //      investigated if the conversion BN <-> pka_operand_t can be skipped
    //      for intermediate results.
    //
    if(!engine_pka_bn_mod_exp(t, a1, p1, m, ctx, in_mont)
    || !engine_pka_bn_mod_exp(rr, a2, p2, m, ctx, in_mont)
    || !BN_mod_mul(rr,rr,t,m,ctx))
        rc = 0;

    BN_free(t);
    return rc;
}

static int engine_pka_dsa_init(DSA *dsa)
{
    return pka_init();
}

static int engine_pka_dsa_finish(DSA *dsa)
{
    return pka_finish();
}
#endif

#ifndef NO_DH
/* DH implementation */
static int
engine_pka_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return engine_pka_bn_mod_exp(r, a, p, m, ctx, m_ctx);
}

static int engine_pka_dh_init(DH *dh)
{
    return pka_init();
}

static int engine_pka_dh_finish(DH *dh)
{
    return pka_finish();
}
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)

#ifndef NO_EC
/* EC implementation */
static int
engine_pka_ecc_pt_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                      const EC_POINT *b, BN_CTX *ctx)
{
    if (r == NULL || a == NULL || b == NULL)
        return 0;

    int     rc, result_bit_len;
    BIGNUM *P  = BN_new();
    BIGNUM *A  = BN_new();
    BIGNUM *B  = BN_new();
    BIGNUM *X1 = BN_new();
    BIGNUM *Y1 = BN_new();
    BIGNUM *X2 = BN_new();
    BIGNUM *Y2 = BN_new();
    BIGNUM *XR = BN_new();
    BIGNUM *YR = BN_new();
    rc         = 1;

    if (!EC_GROUP_get_curve(group, P, A, B, ctx))
    {
        printf("\n ERROR: pka_ecc_pt_add failed to get curve params.\n");
        rc = 0;
        goto end;
    }

    result_bit_len = BN_num_bits(P);

    // Preallocate result bn's so that it can hold our big num.
    if (!BN_set_bit(XR, result_bit_len)
        || !BN_set_bit(YR, result_bit_len))
    {
        printf("ERROR: pka_ecc_pt_add failed to expand result component.\n");
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates(group, a, X1, Y1, ctx)
        || !EC_POINT_get_affine_coordinates(group, b, X2, Y2, ctx))
    {
        printf("\n ERROR: pka_ecc_pt_add failed to get point co-ordinates.\n");
        rc = 0;
        goto end;
    }

    if (!pka_bn_ecc_pt_add((pka_bignum_t *) P,
                           (pka_bignum_t *) A,
                           (pka_bignum_t *) B,
                           (pka_bignum_t *) X1,
                           (pka_bignum_t *) Y1,
                           (pka_bignum_t *) X2,
                           (pka_bignum_t *) Y2,
                           (pka_bignum_t *) XR,
                           (pka_bignum_t *) YR))
    {
        printf("\n ERROR: pka_ecc_pt_add operation failed.\n");
        rc = 0;
        goto end;
    }

    if (!EC_POINT_set_affine_coordinates(group, r, XR, YR, ctx))
    {
        printf("\n ERROR: pka_ecc_pt_add failed to set result point co-ordinates.\n");
        rc = 0;
        goto end;
    }

end:
    BN_free(P);
    BN_free(A);
    BN_free(B);
    BN_free(X1);
    BN_free(Y1);
    BN_free(X2);
    BN_free(Y2);
    BN_free(XR);
    BN_free(YR);
    return rc;
}

/* 
 * NOTE: OpenSSL library recommends that the engine_pka_ecc_pt_mult(),
 *       meet the below requirements:
 *
 *   r := generator * scalar
 *        + points[0] * scalars[0]
 *        + ...
 *        + points[num-1] * scalars[num-1].
 *
 * For a fixed point multiplication (scalar != NULL, num == 0)
 * or a variable point multiplication (scalar == NULL, num == 1),
 * mul() must use a constant time algorithm: in both cases callers
 * should provide an input scalar (either scalar or scalars[0])
 * in the range [0, ec_group_order); for robustness, implementers
 * should handle the case when the scalar has not been reduced, but
 * may treat it as an unusual input, without any constant-timeness
 * guarantee.
 */
static int
engine_pka_ecc_pt_mult(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                       size_t num, const EC_POINT *points[],
                       const BIGNUM *scalars[], BN_CTX *ctx)
{
    int             rc, result_bit_len;
    EC_POINT       *result;
    const EC_POINT *g;
    BIGNUM         *P  = BN_new();
    BIGNUM         *A  = BN_new();
    BIGNUM         *B  = BN_new();
    BIGNUM         *X  = BN_new();
    BIGNUM         *Y  = BN_new();
    BIGNUM         *XR = BN_new();
    BIGNUM         *YR = BN_new();
    BIGNUM         *XD = NULL;
    BIGNUM         *YD = NULL;

    rc                 = 1;
    result             = EC_POINT_new(group);
    g                  = EC_GROUP_get0_generator(group);

    if (result == NULL || XR == NULL || YR == NULL)
        goto end;

    // Retrieve p,a,b parameters pertaining to the curve.
    if (!EC_GROUP_get_curve(group, P, A, B, ctx))
    {
        printf("\n ERROR: pka_ecc_pt_mult failed to get curve params.\n");
        rc = 0;
        goto end;
    }

    result_bit_len = BN_num_bits(P);

    // Preallocate result bn's so that it can hold our big num.
    if (!BN_set_bit(XR, result_bit_len)
        || !BN_set_bit(YR, result_bit_len))
    {
        printf("ERROR: pka_ecc_pt_mult failed to expand result component.\n");
        goto end;
    }

    // Generator point present.
    if (scalar != NULL && g != NULL)
    {
        if (!EC_POINT_get_affine_coordinates(group, g, X, Y, ctx))
        {
            printf("\n ERROR: pka_ecc_pt_mult:"
                              "failed to get generator point co-ordinates.\n");
            rc = 0;
            goto end;
        }

        rc &= pka_bn_ecc_pt_mult((pka_bignum_t *) P,
                                 (pka_bignum_t *) A,
                                 (pka_bignum_t *) B,
                                 (pka_bignum_t *) X,
                                 (pka_bignum_t *) Y,
                                 (pka_bignum_t *) scalar,
                                 (pka_bignum_t *) XR,
                                 (pka_bignum_t *) YR);

        // Exit if operation failed.
        if (!rc)
        {
            printf("\n ERROR: pka_ecc_pt_mult:"
                              "Operation failed.\n");
            goto end;
        }

        // Duplicate the result for future use.
        if (num >= 1)
        {
            XD = BN_dup(XR);
            YD = BN_dup(YR);
            if (XD == NULL || YD == NULL)
            {
                printf("\n ERROR: pka_ecc_pt_mult:"
                                  "failed to duplicate point co-ordinates.\n");
                rc = 0;
                goto end;
            }
        }
    }

    // Input points passed via points[] and scalar via scalars[].
    if (num >= 1 && points != NULL && scalars != NULL)
    {
        uint64_t  i;
        BIGNUM   *XP = NULL;
        BIGNUM   *YP = NULL;

        for (i = 0; i < num; i++)
        {
            // Input check.
            if (points[i] == NULL || scalars[i] == NULL)
            {
                printf("\n ERROR: pka_ecc_pt_mult:"
                                  "Input can't be NULL.\n");
                rc = 0;
                goto end;
            }

            if (!EC_POINT_get_affine_coordinates(group, points[i], X, Y, ctx))
            {
                printf("\n ERROR: pka_ecc_pt_mult:"
                                  "failed to get point co-ordinates.\n");
                rc = 0;
                goto end;
            }

            rc &= pka_bn_ecc_pt_mult((pka_bignum_t *) P,
                                     (pka_bignum_t *) A,
                                     (pka_bignum_t *) B,
                                     (pka_bignum_t *) X,
                                     (pka_bignum_t *) Y,
                                     (pka_bignum_t *) scalars[i],
                                     (pka_bignum_t *) XR,
                                     (pka_bignum_t *) YR);

            // Skip addition for the first iteration.
            if (rc && i != 0)
            {
                rc &= pka_bn_ecc_pt_add((pka_bignum_t *) P,
                                        (pka_bignum_t *) A,
                                        (pka_bignum_t *) B,
                                        (pka_bignum_t *) XR,
                                        (pka_bignum_t *) YR,
                                        (pka_bignum_t *) XP,
                                        (pka_bignum_t *) YP,
                                        (pka_bignum_t *) XR,
                                        (pka_bignum_t *) YR);
                BN_free(XP);
                BN_free(YP);
            }
            // Add the (generator*scalar) point if present, during the
            // first iteration.
            else if (rc && scalar != NULL && g != NULL)
            {
                rc &= pka_bn_ecc_pt_add((pka_bignum_t *) P,
                                        (pka_bignum_t *) A,
                                        (pka_bignum_t *) B,
                                        (pka_bignum_t *) XR,
                                        (pka_bignum_t *) YR,
                                        (pka_bignum_t *) XD,
                                        (pka_bignum_t *) YD,
                                        (pka_bignum_t *) XR,
                                        (pka_bignum_t *) YR);
                BN_free(XD);
                BN_free(YD);
            }

            // Exit if any of the above operations failed.
            if (!rc)
            {
                printf("\n ERROR: pka_ecc_pt_mult:"
                                  "Operation failed.\n");
                goto end;
            }

            // Store the results for addition during next iteration.
            // Not required to store result for last iteration.
            if (i < num-1)
            {
                XP = BN_dup(XR);
                YP = BN_dup(YR);
                if (XP == NULL || YP == NULL)
                {
                    printf("\n ERROR: pka_ecc_pt_mult:"
                                      "failed to duplicate point.\n");
                    rc = 0;
                    goto end;
                }
            }
        }
    }

    if (!EC_POINT_set_affine_coordinates(group, r, XR, YR, ctx))
    {
        printf("\n ERROR: pka_ecc_pt_mult:"
                          "failed to set result point co-ordinates.\n");
        rc = 0;
        goto end;
    }

end:
    BN_free(P);
    BN_free(A);
    BN_free(B);
    BN_free(X);
    BN_free(Y);
    BN_free(XR);
    BN_free(YR);
    if (result)
        EC_POINT_free(result);
    return rc;
}

static int
override_pka_methods(const EC_KEY *eckey, EC_GROUP **dup_group_ptr,
                     EC_KEY **dup_key_ptr)
{
    int             rc;
    const EC_GROUP *group;
    EC_GROUP       *dup_group;
    EC_KEY         *dup_key;

    rc        = 1;
    group     = EC_KEY_get0_group(eckey);

    // Duplicate group and eckey in order to override methods.
    dup_group = EC_GROUP_dup(group);
    dup_key   = EC_KEY_dup(eckey);

    if (!dup_group || !dup_key)
    {
        printf("\n ERROR: Group, Key duplication failed.\n");
        rc = 0;
        goto end;
    }

    dup_group->meth = malloc(sizeof(EC_METHOD));

    memcpy(dup_group->meth, EC_GROUP_method_of(group), sizeof(EC_METHOD));

    // Override the mul, add and inverse functions with pka engine functions.
    dup_group->meth->mul                   = engine_pka_ecc_pt_mult;
    dup_group->meth->add                   = engine_pka_ecc_pt_add;
    dup_group->meth->field_inverse_mod_ord = engine_pka_bn_mod_inv;

    // EC_METHOD should be same in EC_GROUP and (generator point)EC_POINT.
    dup_group->generator->meth             = dup_group->meth;

    if (!EC_KEY_set_group(dup_key, dup_group))
    {
        printf("\n ERROR: Failed to set group.\n");
        rc = 0;
        // Free memory allocations.
        free(dup_group->meth);
        EC_GROUP_free(dup_group);
        EC_KEY_free(dup_key);
        goto end;
    }

    // EC_METHOD should be same in EC_GROUP and (pub_key)EC_POINT.
    dup_key->pub_key->meth = dup_group->meth;

    // Set the output
    *dup_group_ptr         = dup_group;
    *dup_key_ptr           = dup_key;

end:
    return rc;
}

#ifndef NO_ECDH
static int
engine_pka_ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    int       rc;
    EC_GROUP *dup_group = NULL;
    EC_KEY   *dup_key   = NULL;
    EC_POINT *ecdh_pkey = NULL;


    if (!override_pka_methods(ecdh, &dup_group, &dup_key))
    {
        rc = 0;
        goto end;
    }

    ecdh_pkey       = malloc(sizeof(EC_POINT));
    memcpy(ecdh_pkey, pub_key, sizeof(EC_POINT));
    ecdh_pkey->meth = dup_group->meth;

    rc = ossl_ecdh_compute_key(pout, poutlen, ecdh_pkey, dup_key);

    free(dup_group->meth);
    free(ecdh_pkey);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return rc;
}
#endif /* ECDH */

#ifndef NO_ECDSA

static int
engine_pka_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                      unsigned char *sig, unsigned int *siglen,
                      const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    int       rc;
    EC_GROUP *dup_group = NULL;
    EC_KEY   *dup_key   = NULL;

    if (!override_pka_methods(eckey, &dup_group, &dup_key))
    {
        rc = 0;
        goto end;
    }

    rc = ossl_sign(type, dgst, dlen, sig, siglen, kinv, r, dup_key);

    free(dup_group->meth);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return rc;
}

static int
engine_pka_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp)
{
    int       rc;
    EC_GROUP *dup_group = NULL;
    EC_KEY   *dup_key   = NULL;

    if (!override_pka_methods(eckey, &dup_group, &dup_key))
    {
        rc = 0;
        goto end;
    }

    rc = ossl_sign_setup(dup_key, ctx_in, kinvp, rp);

    free(dup_group->meth);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return rc;
}

static ECDSA_SIG*
engine_pka_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len,
                          const BIGNUM *in_kinv, const BIGNUM *in_r,
                          EC_KEY *eckey)
{
    EC_GROUP  *dup_group = NULL;
    EC_KEY    *dup_key   = NULL;
    ECDSA_SIG *ret       = NULL;


    if (!override_pka_methods(eckey, &dup_group, &dup_key))
    {
        goto end;
    }

    ret = ossl_sign_sig(dgst, dgst_len, in_kinv, in_r, dup_key);

    free(dup_group->meth);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return ret;
}

static int
engine_pka_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    int       rc;
    EC_GROUP *dup_group = NULL;
    EC_KEY   *dup_key   = NULL;

    if (!override_pka_methods(eckey, &dup_group, &dup_key))
    {
        rc = 0;
        goto end;
    }

    rc = ossl_verify(type, dgst, dgst_len, sigbuf, sig_len, dup_key);

    free(dup_group->meth);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return rc;
}

static int
engine_pka_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                            const ECDSA_SIG *sig, EC_KEY *eckey)
{
    int       rc;
    EC_GROUP *dup_group = NULL;
    EC_KEY   *dup_key   = NULL;

    if (!override_pka_methods(eckey, &dup_group, &dup_key))
    {
        rc = 0;
        goto end;
    }

    rc = ossl_verify_sig(dgst, dgst_len, sig, dup_key);

    free(dup_group->meth);
    EC_GROUP_free(dup_group);
    EC_KEY_free(dup_key);
end:
    return rc;
}

#endif /* ECDSA */
#endif /* EC */
#endif /* >= OpenSSL 1.1.0 */
#endif /* BLUEFIELD_DYNAMIC_ENGINE */
