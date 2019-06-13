/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        logging facility.
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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <memory.h>
#ifndef HAVE_SIGNALFD
#include <signal.h>
#endif

#include "logger.h"
#include "bitops.h"
#include "utils.h"

/* Boolean flag - send messages to console as well as syslog */
static bool log_console = false;

#ifdef ENABLE_LOG_TO_FILE
/* File to write log messages to */
const char *log_file_name;
static FILE *log_file;
bool always_flush_log_file;
#endif

void
enable_console_log(void)
{
	log_console = true;
}

#ifdef ENABLE_LOG_TO_FILE
void
set_flush_log_file(void)
{
	always_flush_log_file = true;
}

void
close_log_file(void)
{
	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}
}

void
open_log_file(const char *name, const char *prog, const char *namespace, const char *instance)
{
	const char *file_name;

	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}

	if (!name)
		return;

	file_name = make_file_name(name, prog, namespace, instance);

	log_file = fopen_safe(file_name, "a");
	if (log_file) {
		int n = fileno(log_file);
		if (fcntl(n, F_SETFD, FD_CLOEXEC | fcntl(n, F_GETFD)) == -1)
			log_message(LOG_INFO, "Failed to set CLOEXEC on log file %s", file_name);
		if (fcntl(n, F_SETFL, O_NONBLOCK | fcntl(n, F_GETFL)) == -1)
			log_message(LOG_INFO, "Failed to set NONBLOCK on log file %s", file_name);
	}

	FREE_CONST(file_name);
}

void
flush_log_file(void)
{
	if (log_file)
		fflush(log_file);
}

void
update_log_file_perms(mode_t umask_bits)
{
        if (log_file)
                fchmod(fileno(log_file), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) & ~umask_bits);
}
#endif

#ifndef HAVE_SIGNALFD
static inline bool
block_signals(sigset_t *cur_set)
{
	sigset_t block_set;

	sigfillset(&block_set);
	if (!sigprocmask(SIG_BLOCK, &block_set, cur_set))
		return false;

	/* Yes, we are logging without disabling signals,
	 * but it would be useful to know that sigprocmask has
	 * failed. The only error that could occur according
	 * to sigprocmask(2) is EFAULT, which would be very
	 * strange since the sigsets are on the stack. */
	syslog(LOG_ERR, "%s", "sigprocmask failed in block_signals()");

	return true;
}
#endif

void
vlog_message(const int facility, const char* format, va_list args)
{
#ifndef HAVE_SIGNALFD
	sigset_t cur_set;
	bool restore_signals = false;
#endif
#if !HAVE_VSYSLOG
	char buf[MAX_LOG_MSG+1];
#endif

	/* Don't write syslog if testing configuration */
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		return;

#if !HAVE_VSYSLOG
	vsnprintf(buf, sizeof(buf), format, args);
#endif

	if (
#ifdef ENABLE_LOG_TO_FILE
	    log_file ||
#endif
			(__test_bit(DONT_FORK_BIT, &debug) && log_console)) {
#if HAVE_VSYSLOG
		va_list args1;
		char buf[2 * MAX_LOG_MSG + 1];

		va_copy(args1, args);
		vsnprintf(buf, sizeof(buf), format, args1);
		va_end(args1);
#endif

		/* timestamp setup */
		time_t t = time(NULL);
		struct tm tm;
		localtime_r(&t, &tm);
		char timestamp[64];
		strftime(timestamp, sizeof(timestamp), "%c", &tm);

		if (log_console && __test_bit(DONT_FORK_BIT, &debug)) {
#ifndef HAVE_SIGNALFD
			if (!block_signals(&cur_set))
				restore_signals = true;
#endif

			fprintf(stderr, "%s: %s\n", timestamp, buf);
		}
#ifdef ENABLE_LOG_TO_FILE
		if (log_file) {
#ifndef HAVE_SIGNALFD
			if (!restore_signals && !block_signals(&cur_set))
				restore_signals = true;
#endif
			fprintf(log_file, "%s: %s\n", timestamp, buf);
			if (always_flush_log_file)
				fflush(log_file);
		}
#endif
	}

	if (!__test_bit(NO_SYSLOG_BIT, &debug)) {
#ifndef HAVE_SIGNALFD
		if (!restore_signals && !block_signals(&cur_set))
			restore_signals = true;
#endif

#if HAVE_VSYSLOG
		vsyslog(facility, format, args);
#else
		syslog(facility, "%s", buf);
#endif
	}

#ifndef HAVE_SIGNALFD
	if (restore_signals)
		sigprocmask(SIG_SETMASK, &cur_set, NULL);
#endif
}

void
log_message(const int facility, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vlog_message(facility, format, args);
	va_end(args);
}

void
conf_write(FILE *fp, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (fp) {
		vfprintf(fp, format, args);
		fprintf(fp, "\n");
	}
	else
		vlog_message(LOG_INFO, format, args);

	va_end(args);
}
