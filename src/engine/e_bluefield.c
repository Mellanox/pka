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
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>

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

/* RSA stuff */
#ifndef NO_RSA
static int engine_pka_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                                    BN_CTX *ctx);
static int engine_pka_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

static int engine_pka_rsa_init(RSA *rsa);
static int engine_pka_rsa_finish(RSA *rsa);

# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
static RSA_METHOD *pka_rsa_meth = NULL;
# else
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
# endif
#endif

/* DSA stuff */
/* DH stuff */
/* EC stuff */
/* rand stuff */

static int bind_pka(ENGINE *e)
{
    int rc = 1;

#ifndef NO_RSA
# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
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
# else
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
# endif
#endif

    /* Setup our DSA_METHOD that we provide pointers to */
    /* Setup our DH_METHOD that we provide pointers to */
    /* Setup our EC_KEY_METHOD that we provide pointers to */
    /* Setup our RAND_METHOD that we provide pointers to */

    if (rc != ENGINE_set_id(e, engine_pka_id)
        || rc != ENGINE_set_name(e, engine_pka_name)
#ifndef NO_RSA
# if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        || rc != ENGINE_set_RSA(e, pka_rsa_meth)
# else
        || rc != ENGINE_set_RSA(e, &pka_rsa_meth)
# endif
#endif
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
    RSA_meth_free(pka_rsa_meth);
#endif
    return 1;
}

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
            rc = pka_rsa_mod_exp((pka_bignum_t *) I,
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
            rc = pka_rsa_mod_exp((pka_bignum_t *) I,
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

    rc = pka_rsa_mod_exp((pka_bignum_t *) a,
                         (pka_bignum_t *) p,
                         (pka_bignum_t *) m,
                         (pka_bignum_t *) result);

    if (!rc || BN_copy(r, result) == NULL)
        rc = 0;

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
#endif /* BLUEFIELD_DYNAMIC_ENGINE */
