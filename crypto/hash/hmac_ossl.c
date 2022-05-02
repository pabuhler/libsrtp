/*
 * hmac_ossl.c
 *
 * Implementation of hmac srtp_auth_type_t that leverages OpenSSL
 *
 * John A. Foley
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright(c) 2013-2017, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "auth.h"
#include "alloc.h"
#include "err.h" /* for srtp_debug */
#include "auth_test_cases.h"
#include <openssl/evp.h>

#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
#define SRTP_OSSL_USE_EVP_MAC
#endif

#ifndef SRTP_OSSL_USE_EVP_MAC
#include <openssl/hmac.h>
#endif

#define SHA1_DIGEST_SIZE 20

/* the debug module for authentiation */

srtp_debug_module_t srtp_mod_hmac = {
    0,                   /* debugging is off by default */
    "hmac sha-1 openssl" /* printable name for module   */
};

typedef struct {
#ifdef SRTP_OSSL_USE_EVP_MAC
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
#else
    HMAC_CTX *ctx;
#endif
} srtp_hmac_ossl_ctx_t;

static srtp_err_status_t srtp_hmac_alloc(srtp_auth_t **a,
                                         int key_len,
                                         int out_len)
{
    extern const srtp_auth_type_t srtp_hmac;
    srtp_hmac_ossl_ctx_t *hmac;

    debug_print(srtp_mod_hmac, "allocating auth func with key length %d",
                key_len);
    debug_print(srtp_mod_hmac, "                          tag length %d",
                out_len);

    /* check output length - should be less than 20 bytes */
    if (out_len > SHA1_DIGEST_SIZE) {
        return srtp_err_status_bad_param;
    }

    *a = (srtp_auth_t *)srtp_crypto_alloc(sizeof(srtp_auth_t));
    if (*a == NULL) {
        return srtp_err_status_alloc_fail;
    }

    hmac =
        (srtp_hmac_ossl_ctx_t *)srtp_crypto_alloc(sizeof(srtp_hmac_ossl_ctx_t));
    if (hmac == NULL) {
        srtp_crypto_free(*a);
        *a = NULL;
        return srtp_err_status_alloc_fail;
    }

#ifdef SRTP_OSSL_USE_EVP_MAC
    hmac->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (hmac->mac == NULL) {
        srtp_crypto_free(hmac);
        srtp_crypto_free(*a);
        *a = NULL;
        return srtp_err_status_alloc_fail;
    }

    hmac->ctx = EVP_MAC_CTX_new(hmac->mac);
#else
    hmac->ctx = HMAC_CTX_new();
#endif
    if (hmac->ctx == NULL) {
#ifdef SRTP_OSSL_USE_EVP_MAC
        EVP_MAC_free(hmac->mac);
#endif
        srtp_crypto_free(hmac);
        srtp_crypto_free(*a);
        *a = NULL;
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    (*a)->state = hmac;
    (*a)->type = &srtp_hmac;
    (*a)->out_len = out_len;
    (*a)->key_len = key_len;
    (*a)->prefix_len = 0;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_dealloc(srtp_auth_t *a)
{
    srtp_hmac_ossl_ctx_t *hmac = (srtp_hmac_ossl_ctx_t *)a->state;

    if (hmac) {
#ifdef SRTP_OSSL_USE_EVP_MAC
        EVP_MAC_CTX_free(hmac->ctx);
        EVP_MAC_free(hmac->mac);
#else
        HMAC_CTX_free(hmac->ctx);
#endif
        /* zeroize entire state*/
        octet_string_set_to_zero(hmac, sizeof(srtp_hmac_ossl_ctx_t));

        srtp_crypto_free(hmac);
    }

    /* zeroize entire state*/
    octet_string_set_to_zero(a, sizeof(srtp_auth_t));

    /* free memory */
    srtp_crypto_free(a);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_start(void *statev)
{
    srtp_hmac_ossl_ctx_t *hmac = (srtp_hmac_ossl_ctx_t *)statev;

#ifdef SRTP_OSSL_USE_EVP_MAC
    if (EVP_MAC_init(hmac->ctx, NULL, 0, NULL) == 0)
        return srtp_err_status_auth_fail;
#else
    if (HMAC_Init_ex(hmac->ctx, NULL, 0, NULL, NULL) == 0)
        return srtp_err_status_auth_fail;
#endif
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_init(void *statev,
                                        const uint8_t *key,
                                        int key_len)
{
    srtp_hmac_ossl_ctx_t *hmac = (srtp_hmac_ossl_ctx_t *)statev;

#ifdef SRTP_OSSL_USE_EVP_MAC
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hmac->ctx, key, key_len, params) == 0)
        return srtp_err_status_auth_fail;
#else
    if (HMAC_Init_ex(hmac->ctx, key, key_len, EVP_sha1(), NULL) == 0)
        return srtp_err_status_auth_fail;
#endif
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_update(void *statev,
                                          const uint8_t *message,
                                          int msg_octets)
{
    srtp_hmac_ossl_ctx_t *hmac = (srtp_hmac_ossl_ctx_t *)statev;

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

#ifdef SRTP_OSSL_USE_EVP_MAC
    if (EVP_MAC_update(hmac->ctx, message, msg_octets) == 0)
        return srtp_err_status_auth_fail;
#else
    if (HMAC_Update(hmac->ctx, message, msg_octets) == 0)
        return srtp_err_status_auth_fail;
#endif
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_compute(void *statev,
                                           const uint8_t *message,
                                           int msg_octets,
                                           int tag_len,
                                           uint8_t *result)
{
    srtp_hmac_ossl_ctx_t *hmac = (srtp_hmac_ossl_ctx_t *)statev;
    uint8_t hash_value[SHA1_DIGEST_SIZE];
    int i;
#ifdef SRTP_OSSL_USE_EVP_MAC
    size_t len;
#else
    unsigned int len;
#endif

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    /* check tag length, return error if we can't provide the value expected */
    if (tag_len > SHA1_DIGEST_SIZE) {
        return srtp_err_status_bad_param;
    }

    /* hash message, copy output into H */
#ifdef SRTP_OSSL_USE_EVP_MAC
    if (EVP_MAC_update(hmac->ctx, message, msg_octets) == 0)
        return srtp_err_status_auth_fail;

    if (EVP_MAC_final(hmac->ctx, hash_value, &len, sizeof hash_value) == 0)
        return srtp_err_status_auth_fail;
#else
    if (HMAC_Update(hmac->ctx, message, msg_octets) == 0)
        return srtp_err_status_auth_fail;

    if (HMAC_Final(hmac->ctx, hash_value, &len) == 0)
        return srtp_err_status_auth_fail;
#endif
    if (len < tag_len)
        return srtp_err_status_auth_fail;

    /* copy hash_value to *result */
    for (i = 0; i < tag_len; i++) {
        result[i] = hash_value[i];
    }

    debug_print(srtp_mod_hmac, "output: %s",
                srtp_octet_string_hex_string(hash_value, tag_len));

    return srtp_err_status_ok;
}

static const char srtp_hmac_description[] =
    "hmac sha-1 authentication function";

/*
 * srtp_auth_type_t hmac is the hmac metaobject
 */

const srtp_auth_type_t srtp_hmac = {
    srtp_hmac_alloc,        /* */
    srtp_hmac_dealloc,      /* */
    srtp_hmac_init,         /* */
    srtp_hmac_compute,      /* */
    srtp_hmac_update,       /* */
    srtp_hmac_start,        /* */
    srtp_hmac_description,  /* */
    &srtp_hmac_test_case_0, /* */
    SRTP_HMAC_SHA1          /* */
};
