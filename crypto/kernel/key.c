/*
 * key.c
 *
 * key usage limits enforcement
 *
 * David A. Mcgrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017 Cisco Systems, Inc.
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

#include "key.h"

/*
 * the soft limit warns once the remaining budget drops below a tenth of the
 * configured lifetime, so that the warning is proportional to the lifetime
 * rather than a fixed count that is meaningless for short lifetimes
 */
static srtp_xtd_seq_num_t srtp_key_soft_limit(const srtp_xtd_seq_num_t s)
{
    srtp_xtd_seq_num_t limit = s / 10;
    if (limit == 0) {
        limit = 1;
    }
    return limit;
}

srtp_err_status_t srtp_key_limit_set(srtp_key_limit_t key,
                                     const srtp_xtd_seq_num_t s)
{
    if (key == NULL || s == 0) {
        return srtp_err_status_bad_param;
    }
    key->limit = s;
    key->num_left = s;
    key->soft_limit = srtp_key_soft_limit(s);
    key->state = srtp_key_state_normal;
    return srtp_err_status_ok;
}

bool srtp_key_limit_is_expired(srtp_key_limit_t key)
{
    return key == NULL || key->num_left == 0 ||
           key->state == srtp_key_state_expired;
}

/*
 * callers reject an expired key before encrypting, so num_left is above zero
 * here; the check only guards against wrapping the counter. When the soft
 * limit and expiry fall on the same packet only the hard limit is reported.
 */
srtp_key_event_t srtp_key_limit_update(srtp_key_limit_t key)
{
    if (key->num_left == 0) {
        key->state = srtp_key_state_expired;
        return srtp_key_event_normal;
    }

    key->num_left--;
    if (key->num_left == 0) {
        key->state = srtp_key_state_expired;
        return srtp_key_event_hard_limit;
    }
    if (key->num_left < key->soft_limit &&
        key->state == srtp_key_state_normal) {
        key->state = srtp_key_state_past_soft_limit;
        return srtp_key_event_soft_limit;
    }
    return srtp_key_event_normal;
}

void srtp_key_limit_carry_over(srtp_key_limit_t to,
                               const struct srtp_key_limit_ctx_t *from)
{
    srtp_xtd_seq_num_t used;

    if (to == NULL || from == NULL) {
        return;
    }

    used = from->limit - from->num_left;
    if (used >= to->num_left) {
        to->num_left = 0;
        to->state = srtp_key_state_expired;
        return;
    }

    to->num_left -= used;

    /*
     * the state is deliberately left alone, so that a budget that lands below
     * the soft limit is still reported by the next update
     */
}
