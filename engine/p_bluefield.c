#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "pka_helper.h"

typedef struct {
    unsigned char private_key[PKA_448_PRIKEY_SIZE];
    unsigned char public_key[PKA_448_PUBKEY_SIZE];
    size_t private_key_len;
    size_t public_key_len;
    int has_private;
    int has_public;
    int key_type;
} PKA_PROVIDER_KEY;

typedef struct {
    int key_type;
    int selection;
} PKA_PROVIDER_GEN_CTX;

typedef struct {
    int key_type;
    PKA_PROVIDER_KEY *self;
    PKA_PROVIDER_KEY *peer;
} PKA_PROVIDER_KEX_CTX;

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
} PKA_PROVIDER_RSA_KEY;

typedef struct {
    PKA_PROVIDER_RSA_KEY *key;
} PKA_PROVIDER_RSA_CTX;

typedef struct {
    char group_name[64];
    unsigned char public_key[256];
    size_t public_key_len;
    unsigned char private_key[80];
    size_t private_key_len;
    int has_group;
    int has_public;
    int has_private;
} PKA_PROVIDER_EC_KEY;

typedef struct {
    PKA_PROVIDER_EC_KEY *key;
} PKA_PROVIDER_ECDSA_CTX;

enum {
    PKA_KEYTYPE_X25519 = 1,
    PKA_KEYTYPE_X448 = 2,
};

static size_t pka_priv_len_for_type(int key_type)
{
    return (key_type == PKA_KEYTYPE_X25519) ? PKA_25519_PRIKEY_SIZE : PKA_448_PRIKEY_SIZE;
}

static size_t pka_pub_len_for_type(int key_type)
{
    return (key_type == PKA_KEYTYPE_X25519) ? PKA_25519_PUBKEY_SIZE : PKA_448_PUBKEY_SIZE;
}

static int pka_generate_public(int key_type, unsigned char *pub, const unsigned char *priv)
{
    pka_operand_t priv_op = {0};
    size_t priv_len = pka_priv_len_for_type(key_type);

    priv_op.buf_ptr = (uint8_t *)priv;
    priv_op.buf_len = (uint32_t)priv_len;
    priv_op.actual_len = (uint32_t)priv_len;
    priv_op.big_endian = 0;

    if (key_type == PKA_KEYTYPE_X25519)
        return pka_mont_25519_derive_pubkey(pub, &priv_op);

    return pka_mont_448_derive_pubkey(pub, &priv_op);
}

static int pka_derive_secret(int key_type, unsigned char *out, const unsigned char *peer_pub,
                             const unsigned char *priv)
{
    pka_operand_t pub_op = {0};
    pka_operand_t priv_op = {0};
    size_t pub_len = pka_pub_len_for_type(key_type);
    size_t priv_len = pka_priv_len_for_type(key_type);

    pub_op.buf_ptr = (uint8_t *)peer_pub;
    pub_op.buf_len = (uint32_t)pub_len;
    pub_op.actual_len = (uint32_t)pub_len;
    pub_op.big_endian = 0;

    priv_op.buf_ptr = (uint8_t *)priv;
    priv_op.buf_len = (uint32_t)priv_len;
    priv_op.actual_len = (uint32_t)priv_len;
    priv_op.big_endian = 0;

    if (key_type == PKA_KEYTYPE_X25519)
        return pka_mont_25519_mult(out, &pub_op, &priv_op);

    return pka_mont_448_mult(out, &pub_op, &priv_op);
}

static void *pka_key_new(int key_type)
{
    PKA_PROVIDER_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    key->key_type = key_type;
    return key;
}

static void pka_key_free(void *keydata)
{
    OPENSSL_clear_free(keydata, sizeof(PKA_PROVIDER_KEY));
}

static int pka_key_has(const void *keydata, int selection)
{
    const PKA_PROVIDER_KEY *key = (const PKA_PROVIDER_KEY *)keydata;
    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_private)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_public)
        return 0;
    return 1;
}

static int pka_key_match(const void *keydata1, const void *keydata2, int selection)
{
    const PKA_PROVIDER_KEY *key1 = (const PKA_PROVIDER_KEY *)keydata1;
    const PKA_PROVIDER_KEY *key2 = (const PKA_PROVIDER_KEY *)keydata2;
    size_t pub_len;

    if (key1 == NULL || key2 == NULL || key1->key_type != key2->key_type)
        return 0;

    pub_len = pka_pub_len_for_type(key1->key_type);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!key1->has_public || !key2->has_public)
            return 0;
        if (CRYPTO_memcmp(key1->public_key, key2->public_key, pub_len) != 0)
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!key1->has_private || !key2->has_private)
            return 0;
        if (CRYPTO_memcmp(key1->private_key, key2->private_key, pka_priv_len_for_type(key1->key_type)) != 0)
            return 0;
    }

    return 1;
}

static int pka_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    PKA_PROVIDER_KEY *key = (PKA_PROVIDER_KEY *)keydata;
    const OSSL_PARAM *p;
    size_t pub_len;
    size_t priv_len;

    if (key == NULL)
        return 0;

    pub_len = pka_pub_len_for_type(key->key_type);
    priv_len = pka_priv_len_for_type(key->key_type);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size != pub_len)
            return 0;
        memcpy(key->public_key, p->data, pub_len);
        key->public_key_len = pub_len;
        key->has_public = 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size != priv_len)
            return 0;
        memcpy(key->private_key, p->data, priv_len);
        key->private_key_len = priv_len;
        key->has_private = 1;
        if (!pka_generate_public(key->key_type, key->public_key, key->private_key))
            return 0;
        key->public_key_len = pub_len;
        key->has_public = 1;
    }

    return 1;
}

static int pka_key_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    PKA_PROVIDER_KEY *key = (PKA_PROVIDER_KEY *)keydata;
    OSSL_PARAM params[3];
    size_t idx = 0;
    size_t pub_len;
    size_t priv_len;

    if (key == NULL || param_cb == NULL)
        return 0;

    pub_len = pka_pub_len_for_type(key->key_type);
    priv_len = pka_priv_len_for_type(key->key_type);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                           key->public_key, pub_len);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                           key->private_key, priv_len);
    }
    params[idx] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

static const OSSL_PARAM *pka_key_impexp_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)selection;
    return types;
}

static int pka_key_get_params(void *keydata, OSSL_PARAM params[])
{
    PKA_PROVIDER_KEY *key = (PKA_PROVIDER_KEY *)keydata;
    OSSL_PARAM *p;
    size_t bits;
    size_t secbits;
    size_t max_size;

    if (key == NULL)
        return 0;

    if (key->key_type == PKA_KEYTYPE_X25519) {
        bits = PKA_CURVE25519_BITS;
        secbits = PKA_CURVE25519_SECURITY_BITS;
        max_size = PKA_25519_PUBKEY_SIZE;
    } else {
        bits = PKA_CURVE448_BITS;
        secbits = PKA_CURVE448_SECURITY_BITS;
        max_size = PKA_448_PUBKEY_SIZE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, bits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, secbits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, max_size))
        return 0;
    return 1;
}

static const OSSL_PARAM *pka_key_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return gettables;
}

static void *pka_key_gen_init(void *provctx, int selection, const OSSL_PARAM params[], int key_type)
{
    PKA_PROVIDER_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    (void)provctx;
    (void)params;
    if (gctx == NULL)
        return NULL;
    gctx->selection = selection;
    gctx->key_type = key_type;
    return gctx;
}

static void pka_key_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static void *pka_key_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    PKA_PROVIDER_GEN_CTX *gctx = (PKA_PROVIDER_GEN_CTX *)genctx;
    PKA_PROVIDER_KEY *key;
    size_t priv_len;
    size_t pub_len;
    (void)osslcb;
    (void)cbarg;

    if (gctx == NULL)
        return NULL;

    key = pka_key_new(gctx->key_type);
    if (key == NULL)
        return NULL;

    priv_len = pka_priv_len_for_type(gctx->key_type);
    pub_len = pka_pub_len_for_type(gctx->key_type);

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!pka_get_random_bytes(key->private_key, (int)priv_len)) {
            pka_key_free(key);
            return NULL;
        }
        key->private_key_len = priv_len;
        key->has_private = 1;
        if (!pka_generate_public(gctx->key_type, key->public_key, key->private_key)) {
            pka_key_free(key);
            return NULL;
        }
        key->public_key_len = pub_len;
        key->has_public = 1;
    }
    return key;
}

static void *pka_x25519_key_new(void *provctx) { (void)provctx; return pka_key_new(PKA_KEYTYPE_X25519); }
static void *pka_x448_key_new(void *provctx) { (void)provctx; return pka_key_new(PKA_KEYTYPE_X448); }
static void *pka_x25519_key_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) { return pka_key_gen_init(provctx, selection, params, PKA_KEYTYPE_X25519); }
static void *pka_x448_key_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) { return pka_key_gen_init(provctx, selection, params, PKA_KEYTYPE_X448); }

static void *pka_kex_newctx(void *provctx, int key_type)
{
    PKA_PROVIDER_KEX_CTX *kctx = OPENSSL_zalloc(sizeof(*kctx));
    (void)provctx;
    if (kctx == NULL)
        return NULL;
    kctx->key_type = key_type;
    return kctx;
}

static void pka_kex_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int pka_kex_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PKA_PROVIDER_KEX_CTX *kctx = (PKA_PROVIDER_KEX_CTX *)vctx;
    PKA_PROVIDER_KEY *key = (PKA_PROVIDER_KEY *)vkey;
    (void)params;
    if (kctx == NULL || key == NULL || key->key_type != kctx->key_type || !key->has_private)
        return 0;
    kctx->self = key;
    return 1;
}

static int pka_kex_set_peer(void *vctx, void *vkey)
{
    PKA_PROVIDER_KEX_CTX *kctx = (PKA_PROVIDER_KEX_CTX *)vctx;
    PKA_PROVIDER_KEY *key = (PKA_PROVIDER_KEY *)vkey;
    if (kctx == NULL || key == NULL || key->key_type != kctx->key_type || !key->has_public)
        return 0;
    kctx->peer = key;
    return 1;
}

static int pka_kex_derive(void *vctx, unsigned char *secret, size_t *secretlen, size_t outlen)
{
    PKA_PROVIDER_KEX_CTX *kctx = (PKA_PROVIDER_KEX_CTX *)vctx;
    size_t keylen;

    if (kctx == NULL || kctx->self == NULL || kctx->peer == NULL || secretlen == NULL)
        return 0;

    keylen = pka_pub_len_for_type(kctx->key_type);
    if (secret == NULL) {
        *secretlen = keylen;
        return 1;
    }
    if (outlen < keylen)
        return 0;

    if (!pka_derive_secret(kctx->key_type, secret, kctx->peer->public_key, kctx->self->private_key))
        return 0;

    *secretlen = keylen;
    return 1;
}

static void *pka_x25519_kex_newctx(void *provctx) { return pka_kex_newctx(provctx, PKA_KEYTYPE_X25519); }
static void *pka_x448_kex_newctx(void *provctx) { return pka_kex_newctx(provctx, PKA_KEYTYPE_X448); }

static void *pka_ec_key_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(PKA_PROVIDER_EC_KEY));
}

static void pka_ec_key_free(void *keydata)
{
    OPENSSL_clear_free(keydata, sizeof(PKA_PROVIDER_EC_KEY));
}

static int pka_ec_key_has(const void *keydata, int selection)
{
    const PKA_PROVIDER_EC_KEY *key = (const PKA_PROVIDER_EC_KEY *)keydata;
    if (key == NULL)
        return 0;
    if (!key->has_group)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && !key->has_public)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !key->has_private)
        return 0;
    return 1;
}

static int pka_ec_key_match(const void *keydata1, const void *keydata2, int selection)
{
    const PKA_PROVIDER_EC_KEY *a = (const PKA_PROVIDER_EC_KEY *)keydata1;
    const PKA_PROVIDER_EC_KEY *b = (const PKA_PROVIDER_EC_KEY *)keydata2;
    if (a == NULL || b == NULL)
        return 0;
    if (!a->has_group || !b->has_group || strcmp(a->group_name, b->group_name) != 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!a->has_public || !b->has_public || a->public_key_len != b->public_key_len)
            return 0;
        if (CRYPTO_memcmp(a->public_key, b->public_key, a->public_key_len) != 0)
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!a->has_private || !b->has_private || a->private_key_len != b->private_key_len)
            return 0;
        if (CRYPTO_memcmp(a->private_key, b->private_key, a->private_key_len) != 0)
            return 0;
    }
    return 1;
}

static int pka_ec_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    PKA_PROVIDER_EC_KEY *key = (PKA_PROVIDER_EC_KEY *)keydata;
    const OSSL_PARAM *p;
    BIGNUM *bn = NULL;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char *group_name = NULL;
        size_t group_name_len = 0;
        if (p->data_type != OSSL_PARAM_UTF8_STRING && p->data_type != OSSL_PARAM_UTF8_PTR)
            return 0;
        if (p->data_type == OSSL_PARAM_UTF8_PTR) {
            group_name = *((const char **)p->data);
            if (group_name == NULL)
                return 0;
            group_name_len = strlen(group_name);
        } else {
            group_name = (const char *)p->data;
            group_name_len = p->data_size;
            if (group_name_len > 0 && group_name[group_name_len - 1] == '\0')
                group_name_len--;
        }
        if (group_name_len == 0 || group_name_len >= sizeof(key->group_name))
            return 0;
        memset(key->group_name, 0, sizeof(key->group_name));
        memcpy(key->group_name, group_name, group_name_len);
        key->has_group = 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING ||
            p->data_size == 0 || p->data_size > sizeof(key->public_key))
            return 0;
        memcpy(key->public_key, p->data, p->data_size);
        key->public_key_len = p->data_size;
        key->has_public = 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p == NULL)
            return 0;
        if (p->data_type == OSSL_PARAM_OCTET_STRING) {
            if (p->data_size == 0 || p->data_size > sizeof(key->private_key))
                return 0;
            memcpy(key->private_key, p->data, p->data_size);
            key->private_key_len = p->data_size;
        } else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            if (!OSSL_PARAM_get_BN(p, &bn))
                return 0;
            key->private_key_len = (size_t)BN_num_bytes(bn);
            if (key->private_key_len == 0 || key->private_key_len > sizeof(key->private_key)) {
                BN_free(bn);
                return 0;
            }
            if (BN_bn2binpad(bn, key->private_key, (int)key->private_key_len) != (int)key->private_key_len) {
                BN_free(bn);
                return 0;
            }
            BN_free(bn);
            bn = NULL;
        } else {
            return 0;
        }
        key->has_private = 1;
    }

    return key->has_group;
}

static int pka_ec_key_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    PKA_PROVIDER_EC_KEY *key = (PKA_PROVIDER_EC_KEY *)keydata;
    OSSL_PARAM params[4];
    unsigned char priv_bn[80];
    size_t idx = 0;

    if (key == NULL || !key->has_group || param_cb == NULL)
        return 0;

    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, key->group_name, 0);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->public_key, key->public_key_len);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        memcpy(priv_bn, key->private_key, key->private_key_len);
        params[idx++] = OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv_bn, key->private_key_len);
    }
    params[idx] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM *pka_ec_key_impexp_types(int selection)
{
    static const OSSL_PARAM ec_types[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)selection;
    return ec_types;
}

static int pka_ec_key_get_params(void *keydata, OSSL_PARAM params[])
{
    PKA_PROVIDER_EC_KEY *key = (PKA_PROVIDER_EC_KEY *)keydata;
    OSSL_PARAM *p;
    size_t bits = 0;
    size_t secbits = 0;

    if (key == NULL || !key->has_group)
        return 0;

    if (strcmp(key->group_name, "prime256v1") == 0 || strcmp(key->group_name, "secp256r1") == 0) {
        bits = 256; secbits = 128;
    } else if (strcmp(key->group_name, "secp384r1") == 0) {
        bits = 384; secbits = 192;
    } else if (strcmp(key->group_name, "secp521r1") == 0) {
        bits = 521; secbits = 256;
    } else {
        bits = key->public_key_len * 8;
        secbits = bits / 2;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, bits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, secbits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, key->public_key_len ? key->public_key_len : (bits + 7) / 8))
        return 0;
    return 1;
}

static const OSSL_PARAM *pka_ec_key_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return gettables;
}

static EVP_PKEY *pka_make_default_ec_pkey(const PKA_PROVIDER_EC_KEY *key)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[4];
    unsigned char priv_bn[80];
    size_t idx = 0;
    int selection;

    if (key == NULL || !key->has_group)
        return NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto end;

    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)key->group_name, 0);
    if (key->has_public) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                           (void *)key->public_key, key->public_key_len);
    }
    if (key->has_private) {
        memcpy(priv_bn, key->private_key, key->private_key_len);
        params[idx++] = OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv_bn, key->private_key_len);
    }
    params[idx] = OSSL_PARAM_construct_end();

    selection = key->has_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    if (EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) {
        pkey = NULL;
        goto end;
    }

end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void *pka_ecdsa_newctx(void *provctx, const char *propq)
{
    (void)provctx;
    (void)propq;
    return OPENSSL_zalloc(sizeof(PKA_PROVIDER_ECDSA_CTX));
}

static void pka_ecdsa_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int pka_ecdsa_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PKA_PROVIDER_ECDSA_CTX *ctx = (PKA_PROVIDER_ECDSA_CTX *)vctx;
    PKA_PROVIDER_EC_KEY *key = (PKA_PROVIDER_EC_KEY *)vkey;
    (void)params;
    if (ctx == NULL || key == NULL || !key->has_group || !key->has_private)
        return 0;
    ctx->key = key;
    return 1;
}

static int pka_ecdsa_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PKA_PROVIDER_ECDSA_CTX *ctx = (PKA_PROVIDER_ECDSA_CTX *)vctx;
    PKA_PROVIDER_EC_KEY *key = (PKA_PROVIDER_EC_KEY *)vkey;
    (void)params;
    if (ctx == NULL || key == NULL || !key->has_group || !key->has_public)
        return 0;
    ctx->key = key;
    return 1;
}

static int pka_ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
                          const unsigned char *tbs, size_t tbslen)
{
    PKA_PROVIDER_ECDSA_CTX *ctx = (PKA_PROVIDER_ECDSA_CTX *)vctx;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t outlen = 0;
    int ok = 0;

    if (ctx == NULL || ctx->key == NULL || siglen == NULL || tbs == NULL)
        return 0;

    pkey = pka_make_default_ec_pkey(ctx->key);
    if (pkey == NULL)
        goto end;
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=default");
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_sign_init(pctx) <= 0)
        goto end;
    if (EVP_PKEY_sign(pctx, NULL, &outlen, tbs, tbslen) <= 0)
        goto end;
    if (sig == NULL) {
        *siglen = outlen;
        ok = 1;
        goto end;
    }
    if (sigsize < outlen)
        goto end;
    if (EVP_PKEY_sign(pctx, sig, &outlen, tbs, tbslen) <= 0)
        goto end;
    *siglen = outlen;
    ok = 1;

end:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static int pka_ecdsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen)
{
    PKA_PROVIDER_ECDSA_CTX *ctx = (PKA_PROVIDER_ECDSA_CTX *)vctx;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (ctx == NULL || ctx->key == NULL || sig == NULL || tbs == NULL)
        return 0;

    pkey = pka_make_default_ec_pkey(ctx->key);
    if (pkey == NULL)
        goto end;
    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=default");
    if (pctx == NULL)
        goto end;
    if (EVP_PKEY_verify_init(pctx) <= 0)
        goto end;
    ret = EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen);
    if (ret == 1)
        ret = 1;
    else
        ret = 0;

end:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static void pka_rsa_clear(PKA_PROVIDER_RSA_KEY *key)
{
    if (key == NULL)
        return;
    BN_free(key->n);
    BN_free(key->e);
    BN_free(key->d);
    BN_free(key->p);
    BN_free(key->q);
    BN_free(key->dmp1);
    BN_free(key->dmq1);
    BN_free(key->iqmp);
    memset(key, 0, sizeof(*key));
}

static void *pka_rsa_key_new(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(PKA_PROVIDER_RSA_KEY));
}

static void pka_rsa_key_free(void *keydata)
{
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)keydata;
    if (key == NULL)
        return;
    pka_rsa_clear(key);
    OPENSSL_free(key);
}

static int pka_rsa_key_has(const void *keydata, int selection)
{
    const PKA_PROVIDER_RSA_KEY *key = (const PKA_PROVIDER_RSA_KEY *)keydata;
    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
        (key->n == NULL || key->e == NULL))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->d == NULL)
        return 0;
    return 1;
}

static int pka_rsa_key_match(const void *keydata1, const void *keydata2, int selection)
{
    const PKA_PROVIDER_RSA_KEY *a = (const PKA_PROVIDER_RSA_KEY *)keydata1;
    const PKA_PROVIDER_RSA_KEY *b = (const PKA_PROVIDER_RSA_KEY *)keydata2;
    if (a == NULL || b == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (a->n == NULL || b->n == NULL || a->e == NULL || b->e == NULL)
            return 0;
        if (BN_cmp(a->n, b->n) != 0 || BN_cmp(a->e, b->e) != 0)
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (a->d == NULL || b->d == NULL || BN_cmp(a->d, b->d) != 0)
            return 0;
    }
    return 1;
}

static int pka_rsa_import_bn(const OSSL_PARAM params[], const char *name, BIGNUM **out)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);
    if (p == NULL)
        return 1;
    BN_free(*out);
    *out = NULL;
    return OSSL_PARAM_get_BN(p, out);
}

static int pka_rsa_key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)keydata;
    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_N, &key->n) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_E, &key->e))
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_D, &key->d) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_FACTOR1, &key->p) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_FACTOR2, &key->q) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_EXPONENT1, &key->dmp1) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_EXPONENT2, &key->dmq1) ||
            !pka_rsa_import_bn(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &key->iqmp))
            return 0;
    }

    return (key->n != NULL && key->e != NULL);
}

static int pka_rsa_add_bn_param(OSSL_PARAM params[], size_t *idx, const char *name, const BIGNUM *bn,
                                unsigned char *tmp, size_t tmp_size)
{
    int len;
    if (bn == NULL)
        return 1;
    len = BN_num_bytes(bn);
    if (len <= 0 || (size_t)len > tmp_size)
        return 0;
    if (BN_bn2binpad(bn, tmp, len) != len)
        return 0;
    params[(*idx)++] = OSSL_PARAM_BN(name, tmp, len);
    return 1;
}

static int pka_rsa_key_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)
{
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)keydata;
    OSSL_PARAM params[9];
    unsigned char b1[1024], b2[1024], b3[1024], b4[1024], b5[1024], b6[1024], b7[1024], b8[1024];
    size_t idx = 0;

    if (key == NULL || param_cb == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_N, key->n, b1, sizeof(b1)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_E, key->e, b2, sizeof(b2)))
            return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_D, key->d, b3, sizeof(b3)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_FACTOR1, key->p, b4, sizeof(b4)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_FACTOR2, key->q, b5, sizeof(b5)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_EXPONENT1, key->dmp1, b6, sizeof(b6)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_EXPONENT2, key->dmq1, b7, sizeof(b7)) ||
            !pka_rsa_add_bn_param(params, &idx, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, key->iqmp, b8, sizeof(b8)))
            return 0;
    }
    params[idx] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM *pka_rsa_key_impexp_types(int selection)
{
    static const OSSL_PARAM rsa_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0),
        OSSL_PARAM_END
    };
    (void)selection;
    return rsa_types;
}

static int pka_rsa_key_get_params(void *keydata, OSSL_PARAM params[])
{
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)keydata;
    OSSL_PARAM *p;
    size_t bits = 0;
    if (key == NULL || key->n == NULL)
        return 0;
    bits = (size_t)BN_num_bits(key->n);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, bits))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, (bits + 7) / 8))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, bits / 2))
        return 0;
    return 1;
}

static const OSSL_PARAM *pka_rsa_key_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return gettables;
}

static void *pka_rsa_asym_newctx(void *provctx)
{
    (void)provctx;
    return OPENSSL_zalloc(sizeof(PKA_PROVIDER_RSA_CTX));
}

static void pka_rsa_asym_freectx(void *ctx)
{
    OPENSSL_free(ctx);
}

static int pka_rsa_asym_encrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    PKA_PROVIDER_RSA_CTX *rctx = (PKA_PROVIDER_RSA_CTX *)ctx;
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)provkey;
    (void)params;
    if (rctx == NULL || key == NULL || key->n == NULL || key->e == NULL)
        return 0;
    rctx->key = key;
    return 1;
}

static int pka_rsa_asym_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    PKA_PROVIDER_RSA_CTX *rctx = (PKA_PROVIDER_RSA_CTX *)ctx;
    PKA_PROVIDER_RSA_KEY *key = (PKA_PROVIDER_RSA_KEY *)provkey;
    (void)params;
    if (rctx == NULL || key == NULL || key->n == NULL || key->d == NULL)
        return 0;
    rctx->key = key;
    return 1;
}

static int pka_rsa_modexp_public(const PKA_PROVIDER_RSA_KEY *key, BIGNUM *out, const BIGNUM *in)
{
    return pka_bn_mod_exp((pka_bignum_t *)in, (pka_bignum_t *)key->e, (pka_bignum_t *)key->n, (pka_bignum_t *)out);
}

static int pka_rsa_modexp_private(const PKA_PROVIDER_RSA_KEY *key, BIGNUM *out, const BIGNUM *in)
{
    if (key->p != NULL && key->q != NULL && key->dmp1 != NULL && key->dmq1 != NULL && key->iqmp != NULL) {
        return pka_rsa_mod_exp_crt((pka_bignum_t *)in, (pka_bignum_t *)key->p, (pka_bignum_t *)key->q,
                                   (pka_bignum_t *)key->dmp1, (pka_bignum_t *)key->dmq1,
                                   (pka_bignum_t *)key->iqmp, (pka_bignum_t *)out);
    }
    return pka_bn_mod_exp((pka_bignum_t *)in, (pka_bignum_t *)key->d, (pka_bignum_t *)key->n, (pka_bignum_t *)out);
}

static int pka_rsa_asym_encrypt(void *ctx, unsigned char *out, size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    PKA_PROVIDER_RSA_CTX *rctx = (PKA_PROVIDER_RSA_CTX *)ctx;
    BIGNUM *bn_in = NULL, *bn_out = NULL;
    size_t mod_len;
    int ok = 0;

    if (rctx == NULL || rctx->key == NULL || outlen == NULL || in == NULL)
        return 0;
    mod_len = (size_t)BN_num_bytes(rctx->key->n);
    if (out == NULL) {
        *outlen = mod_len;
        return 1;
    }
    if (outsize < mod_len || inlen > mod_len)
        return 0;

    bn_in = BN_bin2bn(in, (int)inlen, NULL);
    bn_out = BN_new();
    if (bn_in == NULL || bn_out == NULL)
        goto end;
    if (!BN_set_bit(bn_out, BN_num_bits(rctx->key->n)))
        goto end;
    if (BN_cmp(bn_in, rctx->key->n) >= 0)
        goto end;
    if (!pka_rsa_modexp_public(rctx->key, bn_out, bn_in))
        goto end;
    if (BN_bn2binpad(bn_out, out, (int)mod_len) != (int)mod_len)
        goto end;
    *outlen = mod_len;
    ok = 1;
end:
    BN_free(bn_in);
    BN_free(bn_out);
    return ok;
}

static int pka_rsa_asym_decrypt(void *ctx, unsigned char *out, size_t *outlen, size_t outsize,
                                const unsigned char *in, size_t inlen)
{
    PKA_PROVIDER_RSA_CTX *rctx = (PKA_PROVIDER_RSA_CTX *)ctx;
    BIGNUM *bn_in = NULL, *bn_out = NULL;
    size_t mod_len;
    int ok = 0;

    if (rctx == NULL || rctx->key == NULL || outlen == NULL || in == NULL)
        return 0;
    mod_len = (size_t)BN_num_bytes(rctx->key->n);
    if (out == NULL) {
        *outlen = mod_len;
        return 1;
    }
    if (outsize < mod_len || inlen > mod_len)
        return 0;

    bn_in = BN_bin2bn(in, (int)inlen, NULL);
    bn_out = BN_new();
    if (bn_in == NULL || bn_out == NULL)
        goto end;
    if (!BN_set_bit(bn_out, BN_num_bits(rctx->key->n)))
        goto end;
    if (BN_cmp(bn_in, rctx->key->n) >= 0)
        goto end;
    if (!pka_rsa_modexp_private(rctx->key, bn_out, bn_in))
        goto end;
    if (BN_bn2binpad(bn_out, out, (int)mod_len) != (int)mod_len)
        goto end;
    *outlen = mod_len;
    ok = 1;
end:
    BN_free(bn_in);
    BN_free(bn_out);
    return ok;
}

static const OSSL_DISPATCH pka_x25519_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pka_x25519_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pka_key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pka_key_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pka_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pka_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pka_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pka_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pka_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pka_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pka_key_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pka_x25519_key_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pka_key_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pka_key_gen_cleanup },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_x448_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pka_x448_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pka_key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pka_key_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pka_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pka_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pka_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pka_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pka_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pka_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pka_key_gettable_params },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))pka_x448_key_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pka_key_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pka_key_gen_cleanup },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pka_rsa_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pka_rsa_key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pka_rsa_key_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pka_rsa_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pka_rsa_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pka_rsa_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pka_rsa_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pka_rsa_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pka_rsa_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pka_rsa_key_gettable_params },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_x25519_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))pka_x25519_kex_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))pka_kex_freectx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))pka_kex_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))pka_kex_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))pka_kex_derive },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_x448_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))pka_x448_kex_newctx },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))pka_kex_freectx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))pka_kex_init },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))pka_kex_set_peer },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))pka_kex_derive },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))pka_rsa_asym_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))pka_rsa_asym_encrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))pka_rsa_asym_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))pka_rsa_asym_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))pka_rsa_asym_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))pka_rsa_asym_freectx },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))pka_ec_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pka_ec_key_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pka_ec_key_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pka_ec_key_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pka_ec_key_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pka_ec_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pka_ec_key_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pka_ec_key_impexp_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pka_ec_key_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pka_ec_key_gettable_params },
    { 0, NULL }
};

static const OSSL_DISPATCH pka_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))pka_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))pka_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))pka_ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))pka_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))pka_ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))pka_ecdsa_verify },
    { 0, NULL }
};

static const OSSL_ALGORITHM pka_keymgmt[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=bluefield-pka", pka_rsa_keymgmt_functions, "BlueField PKA RSA" },
    { "EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=bluefield-pka", pka_ec_keymgmt_functions, "BlueField PKA EC" },
    { "X25519:1.3.101.110", "provider=bluefield-pka", pka_x25519_keymgmt_functions, "BlueField PKA X25519" },
    { "X448:1.3.101.111", "provider=bluefield-pka", pka_x448_keymgmt_functions, "BlueField PKA X448" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pka_keyexch[] = {
    { "X25519:1.3.101.110", "provider=bluefield-pka", pka_x25519_keyexch_functions, "BlueField PKA X25519 key exchange" },
    { "X448:1.3.101.111", "provider=bluefield-pka", pka_x448_keyexch_functions, "BlueField PKA X448 key exchange" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pka_asym_cipher[] = {
    { "RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=bluefield-pka", pka_rsa_asym_cipher_functions, "BlueField PKA RSA asym cipher" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pka_signature[] = {
    { "ECDSA:1.2.840.10045.4", "provider=bluefield-pka", pka_ecdsa_signature_functions, "BlueField PKA ECDSA signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *pka_query_operation(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    if (operation_id == OSSL_OP_KEYMGMT)
        return pka_keymgmt;
    if (operation_id == OSSL_OP_KEYEXCH)
        return pka_keyexch;
    if (operation_id == OSSL_OP_ASYM_CIPHER)
        return pka_asym_cipher;
    if (operation_id == OSSL_OP_SIGNATURE)
        return pka_signature;
    return NULL;
}

static void pka_provider_teardown(void *provctx)
{
    (void)provctx;
    pka_finish();
}

static const OSSL_PARAM *pka_provider_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return params;
}

static int pka_provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "BlueField PKA Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "BlueField PKA OpenSSL Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_DISPATCH pka_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pka_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pka_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pka_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pka_query_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *provctx = NULL;
    if (!pka_init())
        return 0;
    *out = pka_provider_dispatch_table;
    return 1;
}
