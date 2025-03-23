/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Compiler sanitizer debugging
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2024-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <sanitizer/common_interface_defs.h>
#ifdef ASAN_LOG
#include <sanitizer/asan_interface.h>
#include <string.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include "sanitizer.h"
#include "logger.h"

static const char *sanitizer_log = "/tmp/keepalived-sanitizer";

#ifdef _ASAN_DEFAULT_OPTIONS_
const char *
__asan_default_options(void)
{
	return _ASAN_DEFAULT_OPTIONS_;
}
#endif

#ifdef _HWASAN_DEFAULT_OPTIONS_
const char *
__hwasan_default_options(void)
{
	return _HWASAN_DEFAULT_OPTIONS_;
}
#endif

#ifdef _LSAN_DEFAULT_OPTIONS_
const char *
__lsan_default_options(void)
{
	return _LSAN_DEFAULT_OPTIONS_;
}
#endif

#ifdef _MSAN_DEFAULT_OPTIONS_
const char *
__msan_default_options(void)
{
	return _MSAN_DEFAULT_OPTIONS_;
}
#endif

#ifdef _SCUDO_DEFAULT_OPTIONS_
const char *
__scudo_default_options(void)
{
	return _SCUDO_DEFAULT_OPTIONS_;
}
#endif

#ifdef _UBSAN_DEFAULT_OPTIONS_
const char *
__ubsan_default_options(void)
{
	return _UBSAN_DEFAULT_OPTIONS_;
}
#endif

#ifdef ASAN_LOG
/* Writing sanitizer output to the log is a good idea, but it is only implemented
 * for ASAN and not the other sanitizers. The default is therefore to be consistent
 * and write sanitizer output to a log file.
 */
static void
err_call(const char *str)
{
	const char *l_start, *l_end;

	for (l_start = str; l_start; l_start = l_end ? l_end + 1 : NULL) {
		l_end = strchr(l_start, '\n');
		log_message(LOG_INFO, "%.*s", l_end ? (int)(l_end - l_start) : (int)strlen(l_start), l_start);
	}
}
#endif

void
__sanitizer_report_error_summary(const char *error_summary)
{
	log_message(LOG_INFO, "sanitizer error %s: report written to %s.%d", error_summary, sanitizer_log, getpid());
}

void
sanitizer_init(void)
{
#ifdef ASAN_LOG
	__asan_set_error_report_callback(err_call);
#endif

	__sanitizer_set_report_path(sanitizer_log);
}
