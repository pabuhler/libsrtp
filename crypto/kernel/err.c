/*
 * err.c
 *
 * error status reporting functions
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

#include "err.h"
#include "datatypes.h"
#include "srtp_priv.h"

#include <string.h>

static void srtp_err_report_to_default_sink(const char *format, va_list args)
{
#ifdef ERR_REPORTING_STDOUT
    vfprintf(stdout, format, args);
#elif defined(ERR_REPORTING_FILE)
    FILE *err_file = fopen(ERR_REPORTING_FILE, "a");
    if (err_file != NULL) {
        vfprintf(err_file, format, args);
        fclose(err_file);
    }
#else
    (void)format;
    (void)args;
#endif
}

srtp_err_status_t srtp_err_reporting_init(srtp_runtime_t runtime)
{
    (void)runtime;
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_runtime_install_err_report_handler(
    srtp_runtime_t runtime,
    srtp_err_report_handler_func_t func,
    void *data)
{
    if (runtime == NULL) {
        return srtp_err_status_bad_param;
    }

    runtime->err_report_handler = func;
    runtime->err_report_handler_data = data;
    return srtp_err_status_ok;
}

void srtp_err_report(srtp_err_reporting_level_t level, const char *format, ...)
{
    va_list args;

    (void)level;
    va_start(args, format);
    srtp_err_report_to_default_sink(format, args);
    va_end(args);
}

void srtp_runtime_err_report(srtp_runtime_t runtime,
                             srtp_err_reporting_level_t level,
                             const char *format,
                             ...)
{
    char msg[512];
    va_list args;
    va_list sink_args;

    va_start(args, format);
    va_copy(sink_args, args);
    srtp_err_report_to_default_sink(format, sink_args);
    va_end(sink_args);

    if (runtime != NULL) {
        if (vsnprintf(msg, sizeof(msg), format, args) > 0) {
            size_t l = strlen(msg);
            if (l && msg[l - 1] == '\n') {
                msg[l - 1] = '\0';
            }

            if (runtime->err_report_handler != NULL) {
                runtime->err_report_handler(level, msg,
                                            runtime->err_report_handler_data);
            }

            if (runtime->log_handler != NULL) {
                srtp_log_level_t log_level = srtp_log_level_error;

                switch (level) {
                case srtp_err_level_error:
                    log_level = srtp_log_level_error;
                    break;
                case srtp_err_level_warning:
                    log_level = srtp_log_level_warning;
                    break;
                case srtp_err_level_info:
                    log_level = srtp_log_level_info;
                    break;
                case srtp_err_level_debug:
                    log_level = srtp_log_level_debug;
                    break;
                }

                runtime->log_handler(log_level, msg, runtime->log_handler_data);
            }

            octet_string_set_to_zero(msg, sizeof(msg));
        }
    }

    va_end(args);
}
