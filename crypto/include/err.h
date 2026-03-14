/*
 * err.h
 *
 * error status codes
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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

#ifndef ERR_H
#define ERR_H

#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "srtp.h"

#if defined(__clang__) || (defined(__GNUC__) && defined(__has_attribute))
#if __has_attribute(format)
#define LIBSRTP_FORMAT_PRINTF(fmt, args)                                       \
    __attribute__((format(__printf__, fmt, args)))
#else
#define LIBSRTP_FORMAT_PRINTF(fmt, args)
#endif
#else
#define LIBSRTP_FORMAT_PRINTF(fmt, args)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Error Error Codes
 *
 * Error status codes are represented by the enumeration srtp_err_status_t.
 *
 * @{
 */

/**
 * @}
 */

srtp_err_status_t srtp_err_reporting_init(srtp_runtime_t runtime);

srtp_err_status_t srtp_runtime_install_err_report_handler(
    srtp_runtime_t runtime,
    srtp_err_report_handler_func_t func,
    void *data);

void srtp_runtime_err_report(srtp_runtime_t runtime,
                             srtp_err_reporting_level_t level,
                             const char *format,
                             ...) LIBSRTP_FORMAT_PRINTF(3, 4);

/*
 * srtp_err_report reports a 'printf' formatted error
 * string, followed by a an arg list.  The level argument
 * is one of srtp_err_reporting_level_t.
 *
 * Errors will be reported to stdout, if ERR_REPORTING_STDOUT
 * is defined.
 *
 */

void srtp_err_report(srtp_err_reporting_level_t level, const char *format, ...)
    LIBSRTP_FORMAT_PRINTF(2, 3);

/*
 * debug_module_t defines a debug module
 */

typedef struct {
    bool on;          /* true if debugging is on, false if it is off */
    const char *name; /* printable name for debug module      */
} srtp_debug_module_t;

#define SRTP_DEBUG_PRINT0_SELECT(_1, _2, _3, NAME, ...) NAME
#define SRTP_DEBUG_PRINT1_SELECT(_1, _2, _3, _4, NAME, ...) NAME
#define SRTP_DEBUG_PRINT2_SELECT(_1, _2, _3, _4, _5, NAME, ...) NAME

#ifdef ENABLE_DEBUG_LOGGING

#ifndef debug_print0
#define debug_print0_with_runtime(runtime, mod, format)                        \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name)
#define debug_print0_without_runtime(mod, format)                              \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name)
#define debug_print0(...)                                                      \
    SRTP_DEBUG_PRINT0_SELECT(__VA_ARGS__, debug_print0_with_runtime,           \
                             debug_print0_without_runtime)(__VA_ARGS__)
#endif

#ifndef debug_print
#define debug_print_with_runtime(runtime, mod, format, arg)                    \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name, (arg))
#define debug_print_without_runtime(mod, format, arg)                          \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name, (arg))
#define debug_print(...)                                                       \
    SRTP_DEBUG_PRINT1_SELECT(__VA_ARGS__, debug_print_with_runtime,            \
                             debug_print_without_runtime)(__VA_ARGS__)
#endif

#ifndef debug_print2
#define debug_print2_with_runtime(runtime, mod, format, arg1, arg2)            \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name, (arg1), (arg2))
#define debug_print2_without_runtime(mod, format, arg1, arg2)                  \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name, (arg1), (arg2))
#define debug_print2(...)                                                      \
    SRTP_DEBUG_PRINT2_SELECT(__VA_ARGS__, debug_print2_with_runtime,           \
                             debug_print2_without_runtime)(__VA_ARGS__)
#endif

#else

#ifndef debug_print0
#define debug_print0_with_runtime(runtime, mod, format)                        \
    if ((mod).on)                                                              \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name)
#define debug_print0_without_runtime(mod, format)                              \
    if ((mod).on)                                                              \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name)
#define debug_print0(...)                                                      \
    SRTP_DEBUG_PRINT0_SELECT(__VA_ARGS__, debug_print0_with_runtime,           \
                             debug_print0_without_runtime)(__VA_ARGS__)
#endif

#ifndef debug_print
#define debug_print_with_runtime(runtime, mod, format, arg)                    \
    if ((mod).on)                                                              \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name, (arg))
#define debug_print_without_runtime(mod, format, arg)                          \
    if ((mod).on)                                                              \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name, (arg))
#define debug_print(...)                                                       \
    SRTP_DEBUG_PRINT1_SELECT(__VA_ARGS__, debug_print_with_runtime,            \
                             debug_print_without_runtime)(__VA_ARGS__)
#endif

#ifndef debug_print2
#define debug_print2_with_runtime(runtime, mod, format, arg1, arg2)            \
    if ((mod).on)                                                              \
    srtp_runtime_err_report((runtime), srtp_err_level_debug,                   \
                            ("%s: " format "\n"), (mod).name, (arg1), (arg2))
#define debug_print2_without_runtime(mod, format, arg1, arg2)                  \
    if ((mod).on)                                                              \
    srtp_runtime_err_report(NULL, srtp_err_level_debug,                        \
                            ("%s: " format "\n"), (mod).name, (arg1), (arg2))
#define debug_print2(...)                                                      \
    SRTP_DEBUG_PRINT2_SELECT(__VA_ARGS__, debug_print2_with_runtime,           \
                             debug_print2_without_runtime)(__VA_ARGS__)
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif /* ERR_H */
