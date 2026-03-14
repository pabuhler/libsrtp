/*
 * crypto_kernel.c
 *
 * header for the cryptographic kernel
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright(c) 2001-2017 Cisco Systems, Inc.
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

#include "crypto_kernel.h"
#include "cipher_types.h"
#include "alloc.h"
#include "srtp_priv.h"

#include <stdlib.h>

/* the debug module for the crypto_kernel */

srtp_debug_module_t srtp_mod_crypto_kernel = {
    false,          /* debugging is off by default */
    "crypto kernel" /* printable name for module   */
};

#define MAX_RNG_TRIALS 25

static srtp_crypto_kernel_t *srtp_get_crypto_kernel(srtp_runtime_t runtime)
{
    return &runtime->crypto_kernel;
}

srtp_err_status_t srtp_crypto_kernel_init(srtp_runtime_t runtime)
{
    srtp_err_status_t status;
    srtp_crypto_kernel_t *crypto_kernel;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* check the security state */
    if (crypto_kernel->state == srtp_crypto_kernel_state_secure) {
        /*
         * we're already in the secure state, but we've been asked to
         * re-initialize, so we just re-run the self-tests and then return
         */
        return srtp_crypto_kernel_status(runtime);
    }

    /* initialize error reporting system */
    status = srtp_err_reporting_init(runtime);
    if (status) {
        return status;
    }

    /* load debug modules */
    status =
        srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_crypto_kernel);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_auth);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_cipher);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_alloc);
    if (status) {
        return status;
    }

    /* load cipher types */
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_null_cipher,
                                                 SRTP_NULL_CIPHER);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_aes_icm_128,
                                                 SRTP_AES_ICM_128);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_aes_icm_256,
                                                 SRTP_AES_ICM_256);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_aes_icm);
    if (status) {
        return status;
    }
#ifdef GCM
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_aes_icm_192,
                                                 SRTP_AES_ICM_192);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_aes_gcm_128,
                                                 SRTP_AES_GCM_128);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(runtime, &srtp_aes_gcm_256,
                                                 SRTP_AES_GCM_256);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_aes_gcm);
    if (status) {
        return status;
    }
#endif

    /* load auth func types */
    status = srtp_crypto_kernel_load_auth_type(runtime, &srtp_null_auth,
                                               SRTP_NULL_AUTH);
    if (status) {
        return status;
    }
    status =
        srtp_crypto_kernel_load_auth_type(runtime, &srtp_hmac, SRTP_HMAC_SHA1);
    if (status) {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(runtime, &srtp_mod_hmac);
    if (status) {
        return status;
    }

    /* change state to secure */
    crypto_kernel->state = srtp_crypto_kernel_state_secure;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_status(srtp_runtime_t runtime)
{
    srtp_err_status_t status;
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_cipher_type_t *ctype;
    srtp_kernel_auth_type_t *atype;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);
    ctype = crypto_kernel->cipher_type_list;
    atype = crypto_kernel->auth_type_list;

    /* for each cipher type, describe and test */
    while (ctype != NULL) {
        srtp_runtime_err_report(runtime, srtp_err_level_info, "cipher: %s\n",
                                ctype->cipher_type->description);
        srtp_runtime_err_report(runtime, srtp_err_level_info, "  self-test: ");
        status = srtp_cipher_type_self_test(runtime, ctype->cipher_type);
        if (status) {
            srtp_runtime_err_report(runtime, srtp_err_level_error,
                                    "failed with error code %d\n", status);
            exit(status);
        }
        srtp_runtime_err_report(runtime, srtp_err_level_info, "passed\n");
        ctype = ctype->next;
    }

    /* for each auth type, describe and test */
    while (atype != NULL) {
        srtp_runtime_err_report(runtime, srtp_err_level_info,
                                "auth func: %s\n",
                                atype->auth_type->description);
        srtp_runtime_err_report(runtime, srtp_err_level_info, "  self-test: ");
        status = srtp_auth_type_self_test(runtime, atype->auth_type);
        if (status) {
            srtp_runtime_err_report(runtime, srtp_err_level_error,
                                    "failed with error code %d\n", status);
            exit(status);
        }
        srtp_runtime_err_report(runtime, srtp_err_level_info, "passed\n");
        atype = atype->next;
    }

    srtp_crypto_kernel_list_debug_modules(runtime);

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_list_debug_modules(srtp_runtime_t runtime)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_debug_module_t *dm;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);
    dm = crypto_kernel->debug_module_list;

    /* describe each debug module */
    srtp_runtime_err_report(runtime, srtp_err_level_info,
                            "debug modules loaded:\n");
    while (dm != NULL) {
        srtp_runtime_err_report(runtime, srtp_err_level_info, "  %s ",
                                dm->mod->name);
        if (dm->mod->on) {
            srtp_runtime_err_report(runtime, srtp_err_level_info, "(on)\n");
        } else {
            srtp_runtime_err_report(runtime, srtp_err_level_info, "(off)\n");
        }
        dm = dm->next;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_shutdown(srtp_runtime_t runtime)
{
    srtp_crypto_kernel_t *crypto_kernel;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /*
     * free dynamic memory used in crypto_kernel at present
     */

    /* walk down cipher type list, freeing memory */
    while (crypto_kernel->cipher_type_list != NULL) {
        srtp_kernel_cipher_type_t *ctype = crypto_kernel->cipher_type_list;
        crypto_kernel->cipher_type_list = ctype->next;
        debug_print(runtime, srtp_mod_crypto_kernel, "freeing memory for cipher %s",
                    ctype->cipher_type->description);
        srtp_crypto_free(ctype);
    }

    /* walk down authetication module list, freeing memory */
    while (crypto_kernel->auth_type_list != NULL) {
        srtp_kernel_auth_type_t *atype = crypto_kernel->auth_type_list;
        crypto_kernel->auth_type_list = atype->next;
        debug_print(runtime, srtp_mod_crypto_kernel,
                    "freeing memory for authentication %s",
                    atype->auth_type->description);
        srtp_crypto_free(atype);
    }

    /* walk down debug module list, freeing memory */
    while (crypto_kernel->debug_module_list != NULL) {
        srtp_kernel_debug_module_t *kdm = crypto_kernel->debug_module_list;
        crypto_kernel->debug_module_list = kdm->next;
        debug_print(runtime, srtp_mod_crypto_kernel,
                    "freeing memory for debug module %s", kdm->mod->name);
        srtp_crypto_free(kdm);
    }

    /* return to insecure state */
    crypto_kernel->state = srtp_crypto_kernel_state_insecure;

    return srtp_err_status_ok;
}

static inline srtp_err_status_t srtp_crypto_kernel_do_load_cipher_type(
    srtp_runtime_t runtime,
    const srtp_cipher_type_t *new_ct,
    srtp_cipher_type_id_t id,
    bool replace)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_cipher_type_t *ctype;
    srtp_kernel_cipher_type_t *new_ctype = NULL;
    srtp_err_status_t status;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* defensive coding */
    if (new_ct == NULL) {
        return srtp_err_status_bad_param;
    }

    if (new_ct->id != id) {
        return srtp_err_status_bad_param;
    }

    /* check cipher type by running self-test */
    status = srtp_cipher_type_self_test(runtime, new_ct);
    if (status) {
        return status;
    }

    /* walk down list, checking if this type is in the list already  */
    ctype = crypto_kernel->cipher_type_list;
    while (ctype != NULL) {
        if (id == ctype->id) {
            if (!replace) {
                return srtp_err_status_bad_param;
            }
            status = srtp_cipher_type_test(runtime, new_ct,
                                           ctype->cipher_type->test_data);
            if (status) {
                return status;
            }
            new_ctype = ctype;
            break;
        } else if (new_ct == ctype->cipher_type) {
            return srtp_err_status_bad_param;
        }
        ctype = ctype->next;
    }

    /* if not found, put new_ct at the head of the list */
    if (ctype == NULL) {
        /* allocate memory */
        new_ctype = (srtp_kernel_cipher_type_t *)srtp_crypto_alloc(
            sizeof(srtp_kernel_cipher_type_t));
        if (new_ctype == NULL) {
            return srtp_err_status_alloc_fail;
        }
        new_ctype->next = crypto_kernel->cipher_type_list;

        /* set head of list to new cipher type */
        crypto_kernel->cipher_type_list = new_ctype;
    }

    /* set fields */
    new_ctype->cipher_type = new_ct;
    new_ctype->id = id;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_load_cipher_type(
    srtp_runtime_t runtime,
    const srtp_cipher_type_t *new_ct,
    srtp_cipher_type_id_t id)
{
    return srtp_crypto_kernel_do_load_cipher_type(runtime, new_ct, id, false);
}

srtp_err_status_t srtp_replace_cipher_type(srtp_runtime_t runtime,
                                           const srtp_cipher_type_t *new_ct,
                                           srtp_cipher_type_id_t id)
{
    return srtp_crypto_kernel_do_load_cipher_type(runtime, new_ct, id, true);
}

srtp_err_status_t srtp_crypto_kernel_do_load_auth_type(
    srtp_runtime_t runtime,
    const srtp_auth_type_t *new_at,
    srtp_auth_type_id_t id,
    bool replace)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_auth_type_t *atype;
    srtp_kernel_auth_type_t *new_atype = NULL;
    srtp_err_status_t status;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* defensive coding */
    if (new_at == NULL) {
        return srtp_err_status_bad_param;
    }

    if (new_at->id != id) {
        return srtp_err_status_bad_param;
    }

    /* check auth type by running self-test */
    status = srtp_auth_type_self_test(runtime, new_at);
    if (status) {
        return status;
    }

    /* walk down list, checking if this type is in the list already  */
    atype = crypto_kernel->auth_type_list;
    while (atype != NULL) {
        if (id == atype->id) {
            if (!replace) {
                return srtp_err_status_bad_param;
            }
            status = srtp_auth_type_test(runtime, new_at,
                                         atype->auth_type->test_data);
            if (status) {
                return status;
            }
            new_atype = atype;
            break;
        } else if (new_at == atype->auth_type) {
            return srtp_err_status_bad_param;
        }
        atype = atype->next;
    }

    /* if not found, put new_at at the head of the list */
    if (atype == NULL) {
        /* allocate memory */
        new_atype = (srtp_kernel_auth_type_t *)srtp_crypto_alloc(
            sizeof(srtp_kernel_auth_type_t));
        if (new_atype == NULL) {
            return srtp_err_status_alloc_fail;
        }

        new_atype->next = crypto_kernel->auth_type_list;
        /* set head of list to new auth type */
        crypto_kernel->auth_type_list = new_atype;
    }

    /* set fields */
    new_atype->auth_type = new_at;
    new_atype->id = id;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_load_auth_type(
    srtp_runtime_t runtime,
    const srtp_auth_type_t *new_at,
    srtp_auth_type_id_t id)
{
    return srtp_crypto_kernel_do_load_auth_type(runtime, new_at, id, false);
}

srtp_err_status_t srtp_replace_auth_type(srtp_runtime_t runtime,
                                         const srtp_auth_type_t *new_at,
                                         srtp_auth_type_id_t id)
{
    return srtp_crypto_kernel_do_load_auth_type(runtime, new_at, id, true);
}

const srtp_cipher_type_t *srtp_crypto_kernel_get_cipher_type(
    srtp_runtime_t runtime,
    srtp_cipher_type_id_t id)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_cipher_type_t *ctype;

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* walk down list, looking for id  */
    ctype = crypto_kernel->cipher_type_list;
    while (ctype != NULL) {
        if (id == ctype->id) {
            return ctype->cipher_type;
        }
        ctype = ctype->next;
    }

    /* haven't found the right one, indicate failure by returning NULL */
    return NULL;
}

srtp_err_status_t srtp_crypto_kernel_alloc_cipher(srtp_runtime_t runtime,
                                                  srtp_cipher_type_id_t id,
                                                  srtp_cipher_pointer_t *cp,
                                                  size_t key_len,
                                                  size_t tag_len)
{
    srtp_crypto_kernel_t *crypto_kernel;
    const srtp_cipher_type_t *ct;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /*
     * if the crypto_kernel is not yet initialized, we refuse to allocate
     * any ciphers - this is a bit extra-paranoid
     */
    if (crypto_kernel->state != srtp_crypto_kernel_state_secure) {
        return srtp_err_status_init_fail;
    }

    ct = srtp_crypto_kernel_get_cipher_type(runtime, id);
    if (!ct) {
        return srtp_err_status_fail;
    }

    return ((ct)->alloc(runtime, cp, key_len, tag_len));
}

const srtp_auth_type_t *srtp_crypto_kernel_get_auth_type(srtp_runtime_t runtime,
                                                         srtp_auth_type_id_t id)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_auth_type_t *atype;

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* walk down list, looking for id  */
    atype = crypto_kernel->auth_type_list;
    while (atype != NULL) {
        if (id == atype->id) {
            return atype->auth_type;
        }
        atype = atype->next;
    }

    /* haven't found the right one, indicate failure by returning NULL */
    return NULL;
}

srtp_err_status_t srtp_crypto_kernel_alloc_auth(srtp_runtime_t runtime,
                                                srtp_auth_type_id_t id,
                                                srtp_auth_pointer_t *ap,
                                                size_t key_len,
                                                size_t tag_len)
{
    srtp_crypto_kernel_t *crypto_kernel;
    const srtp_auth_type_t *at;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /*
     * if the crypto_kernel is not yet initialized, we refuse to allocate
     * any auth functions - this is a bit extra-paranoid
     */
    if (crypto_kernel->state != srtp_crypto_kernel_state_secure) {
        return srtp_err_status_init_fail;
    }

    at = srtp_crypto_kernel_get_auth_type(runtime, id);
    if (!at) {
        return srtp_err_status_fail;
    }

    return ((at)->alloc(runtime, ap, key_len, tag_len));
}

srtp_err_status_t srtp_crypto_kernel_load_debug_module(
    srtp_runtime_t runtime,
    srtp_debug_module_t *new_dm)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_debug_module_t *kdm, *new;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* defensive coding */
    if (new_dm == NULL || new_dm->name == NULL) {
        return srtp_err_status_bad_param;
    }

    /* walk down list, checking if this type is in the list already  */
    kdm = crypto_kernel->debug_module_list;
    while (kdm != NULL) {
        if (strncmp(new_dm->name, kdm->mod->name, 64) == 0) {
            return srtp_err_status_bad_param;
        }
        kdm = kdm->next;
    }

    /* put new_dm at the head of the list */
    /* allocate memory */
    new = (srtp_kernel_debug_module_t *)srtp_crypto_alloc(
        sizeof(srtp_kernel_debug_module_t));
    if (new == NULL) {
        return srtp_err_status_alloc_fail;
    }

    /* set fields */
    new->mod = new_dm;
    new->next = crypto_kernel->debug_module_list;

    /* set head of list to new cipher type */
    crypto_kernel->debug_module_list = new;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_kernel_set_debug_module(srtp_runtime_t runtime,
                                                      const char *name,
                                                      bool on)
{
    srtp_crypto_kernel_t *crypto_kernel;
    srtp_kernel_debug_module_t *kdm;

    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    crypto_kernel = srtp_get_crypto_kernel(runtime);

    /* walk down list, checking if this type is in the list already  */
    kdm = crypto_kernel->debug_module_list;
    while (kdm != NULL) {
        if (strncmp(name, kdm->mod->name, 64) == 0) {
            kdm->mod->on = on;
            return srtp_err_status_ok;
        }
        kdm = kdm->next;
    }

    return srtp_err_status_fail;
}
