/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
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

#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <stdbool.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#include <sys/epoll.h>
#endif
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/version.h>
#include <ctype.h>
#include <stdlib.h>

#include "main.h"
#include "global_data.h"
#include "daemon.h"
#include "config.h"
#include "git-commit.h"
#include "utils.h"
#include "signals.h"
#include "pidfile.h"
#include "bitops.h"
#include "logger.h"
#include "parser.h"
#include "notify.h"
#include "utils.h"
#ifdef _WITH_LVS_
#include "check_parser.h"
#include "check_daemon.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_daemon.h"
#include "vrrp_parser.h"
#include "vrrp_if.h"
#ifdef _WITH_CN_PROC_
#include "track_process.h"
#endif
#ifdef _WITH_JSON_
#include "vrrp_json.h"
#endif
#ifdef _WITH_NFTABLES_
#include "vrrp_nftables.h"
#endif
#endif
#ifdef _WITH_BFD_
#include "bfd_daemon.h"
#include "bfd_parser.h"
#endif
#include "global_parser.h"
#if HAVE_DECL_CLONE_NEWNET
#include "namespaces.h"
#endif
#include "scheduler.h"
#include "keepalived_netlink.h"
#include "git-commit.h"
#if defined THREAD_DUMP || defined _EPOLL_DEBUG_ || defined _EPOLL_THREAD_DUMP_
#include "scheduler.h"
#endif
#include "process.h"
#ifdef _TIMER_CHECK_
#include "timer.h"
#endif
#ifdef _SMTP_ALERT_DEBUG_
#include "smtp.h"
#endif
#if defined _REGEX_DEBUG_ || defined _WITH_REGEX_TIMERS_
#include "check_http.h"
#endif
#ifdef _TSM_DEBUG_
#include "vrrp_scheduler.h"
#endif
#if defined _PARSER_DEBUG_ || defined _DUMP_KEYWORDS_
#include "parser.h"
#endif
#include "warnings.h"

/* musl libc doesn't define the following */
#ifndef	W_EXITCODE
#define	W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#endif
#ifndef	WCOREFLAG
#define	WCOREFLAG		((int32_t)WCOREDUMP(0xffffffff))
#endif

#define CHILD_WAIT_SECS	5

/* global var */
const char *version_string = VERSION_STRING;		/* keepalived version */
const char *conf_file = KEEPALIVED_CONFIG_FILE;		/* Configuration file */
int log_facility = LOG_DAEMON;				/* Optional logging facilities */
bool reload;						/* Set during a reload */
const char *main_pidfile;				/* overrule default pidfile */
static bool free_main_pidfile;
#ifdef _WITH_LVS_
pid_t checkers_child;					/* Healthcheckers child process ID */
const char *checkers_pidfile;				/* overrule default pidfile */
static bool free_checkers_pidfile;
#endif
#ifdef _WITH_VRRP_
pid_t vrrp_child;					/* VRRP child process ID */
const char *vrrp_pidfile;				/* overrule default pidfile */
static bool free_vrrp_pidfile;
#endif
#ifdef _WITH_BFD_
pid_t bfd_child;					/* BFD child process ID */
const char *bfd_pidfile;				/* overrule default pidfile */
static bool free_bfd_pidfile;
#endif
unsigned long daemon_mode;				/* VRRP/CHECK/BFD subsystem selection */
#ifdef _WITH_SNMP_
bool snmp_option;					/* Enable SNMP support */
const char *snmp_socket;				/* Socket to use for SNMP agent */
#endif
static const char *syslog_ident;			/* syslog ident if not default */
bool use_pid_dir;					/* Put pid files in /var/run/keepalived or @localstatedir@/run/keepalived */

unsigned os_major;					/* Kernel version */
unsigned os_minor;
unsigned os_release;
char *hostname;						/* Initial part of hostname */

#if HAVE_DECL_CLONE_NEWNET
static char *override_namespace;			/* If namespace specified on command line */
#endif

unsigned child_wait_time = CHILD_WAIT_SECS;		/* Time to wait for children to exit */

/* Log facility table */
static struct {
	int facility;
} LOG_FACILITY[] = {
	{LOG_LOCAL0}, {LOG_LOCAL1}, {LOG_LOCAL2}, {LOG_LOCAL3},
	{LOG_LOCAL4}, {LOG_LOCAL5}, {LOG_LOCAL6}, {LOG_LOCAL7}
};
#define	LOG_FACILITY_MAX	((sizeof(LOG_FACILITY) / sizeof(LOG_FACILITY[0])) - 1)

/* umask settings */
bool umask_cmdline;

/* Control producing core dumps */
static bool set_core_dump_pattern = false;
static bool create_core_dump = false;
static const char *core_dump_pattern = "core";
static char *orig_core_dump_pattern = NULL;

/* debug flags */
#if defined _TIMER_CHECK_ || defined _SMTP_ALERT_DEBUG_ || defined _EPOLL_DEBUG_ || defined _EPOLL_THREAD_DUMP_ || defined _REGEX_DEBUG_ || defined _WITH_REGEX_TIMERS_ || defined _TSM_DEBUG_ || defined _VRRP_FD_DEBUG_ || defined _NETLINK_TIMERS_ || defined _NETWORK_TIMESTAMP_ || defined _TRACK_PROCESS_DEBUG_ || defined _PARSER_DEBUG_ || defined _DUMP_KEYWORDS_
#define WITH_DEBUG_OPTIONS 1
#endif

#ifdef _TIMER_CHECK_
static char timer_debug;
#endif
#ifdef _SMTP_ALERT_DEBUG_
static char smtp_debug;
#endif
#ifdef _EPOLL_DEBUG_
static char epoll_debug;
#endif
#ifdef _EPOLL_THREAD_DUMP_
static char epoll_thread_debug;
#endif
#ifdef _REGEX_DEBUG_
static char regex_debug;
#endif
#ifdef _WITH_REGEX_TIMERS_
static char regex_timers;
#endif
#ifdef _TSM_DEBUG_
static char tsm_debug;
#endif
#ifdef _VRRP_FD_DEBUG_
static char vrrp_fd_debug;
#endif
#ifdef _NETLINK_TIMERS_
static char netlink_timer_debug;
#endif
#ifdef _NETWORK_TIMESTAMP_
static char network_timestamp_debug;
#endif
#ifdef _TRACK_PROCESS_DEBUG_
static char track_process_debug;
static char track_process_debug_detail;
#endif
#ifdef _PARSER_DEBUG_
static char parser_debug;
#endif
#ifdef _DUMP_KEYWORDS_
static char dump_keywords;
#endif

void
free_parent_mallocs_startup(bool am_child)
{
	if (am_child) {
#if HAVE_DECL_CLONE_NEWNET
		free_dirname();
#endif
#ifndef _MEM_CHECK_LOG_
		FREE_CONST_PTR(syslog_ident);
#else
		free(no_const_char_p(syslog_ident));
#endif
		syslog_ident = NULL;

		FREE_PTR(orig_core_dump_pattern);
	}

	if (free_main_pidfile) {
		FREE_CONST_PTR(main_pidfile);
		free_main_pidfile = false;
	}
}

void
free_parent_mallocs_exit(void)
{
#ifdef _WITH_VRRP_
	if (free_vrrp_pidfile)
		FREE_CONST_PTR(vrrp_pidfile);
#endif
#ifdef _WITH_LVS_
	if (free_checkers_pidfile)
		FREE_CONST_PTR(checkers_pidfile);
#endif
#ifdef _WITH_BFD_
	if (free_bfd_pidfile)
		FREE_CONST_PTR(bfd_pidfile);
#endif

	FREE_CONST_PTR(config_id);
}

const char *
make_syslog_ident(const char* name)
{
	size_t ident_len = strlen(name) + 1;
	char *ident;

#if HAVE_DECL_CLONE_NEWNET
	if (global_data->network_namespace)
		ident_len += strlen(global_data->network_namespace) + 1;
#endif
	if (global_data->instance_name)
		ident_len += strlen(global_data->instance_name) + 1;

	/* If we are writing MALLOC/FREE info to the log, we have
	 * trouble FREEing the syslog_ident */
#ifndef _MEM_CHECK_LOG_
	ident = MALLOC(ident_len);
#else
	ident = malloc(ident_len);
#endif

	if (!ident)
		return NULL;

	strcpy(ident, name);
#if HAVE_DECL_CLONE_NEWNET
	if (global_data->network_namespace) {
		strcat(ident, "_");
		strcat(ident, global_data->network_namespace);
	}
#endif
	if (global_data->instance_name) {
		strcat(ident, "_");
		strcat(ident, global_data->instance_name);
	}

	return ident;
}

static char *
make_pidfile_name(const char* start, const char* instance, const char* extn)
{
	size_t len;
	char *name;

	len = strlen(start) + 1;
	if (instance)
		len += strlen(instance) + 1;
	if (extn)
		len += strlen(extn);

	name = MALLOC(len);
	if (!name) {
		log_message(LOG_INFO, "Unable to make pidfile name for %s", start);
		return NULL;
	}

	strcpy(name, start);
	if (instance) {
		strcat(name, "_");
		strcat(name, instance);
	}
	if (extn)
		strcat(name, extn);

	return name;
}

#ifdef _WITH_VRRP_
bool __attribute__ ((pure))
running_vrrp(void)
{
	return (__test_bit(DAEMON_VRRP, &daemon_mode) &&
	    (global_data->have_vrrp_config ||
	     __test_bit(RUN_ALL_CHILDREN, &daemon_mode)));
}
#endif

#ifdef _WITH_LVS_
bool __attribute__ ((pure))
running_checker(void)
{
	return (__test_bit(DAEMON_CHECKERS, &daemon_mode) &&
	    (global_data->have_checker_config ||
	     __test_bit(RUN_ALL_CHILDREN, &daemon_mode)));
}
#endif

#ifdef _WITH_BFD_
static bool __attribute__ ((pure))
running_bfd(void)
{
	return (__test_bit(DAEMON_BFD, &daemon_mode) &&
	    (global_data->have_bfd_config ||
	     __test_bit(RUN_ALL_CHILDREN, &daemon_mode)));
}
#endif

static char const *
find_keepalived_child_name(pid_t pid)
{
#ifdef _WITH_LVS_
	if (pid == checkers_child)
		return PROG_CHECK;
#endif
#ifdef _WITH_VRRP_
	if (pid == vrrp_child)
		return PROG_VRRP;
#endif
#ifdef _WITH_BFD_
	if (pid == bfd_child)
		return PROG_BFD;
#endif

	return NULL;
}

static const vector_t *
global_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(true);

#ifdef _WITH_VRRP_
	init_vrrp_keywords(false);
#endif
#ifdef _WITH_LVS_
	init_check_keywords(false);
#endif
#ifdef _WITH_BFD_
	init_bfd_keywords(false);
#endif

	return keywords;
}

static void
read_config_file(void)
{
	init_data(conf_file, global_init_keywords);
}

/* Daemon stop sequence */
void
stop_keepalived(void)
{
#ifndef _DEBUG_
	/* Just cleanup memory & exit */
	thread_destroy_master(master);

#ifdef _WITH_VRRP_
	if (__test_bit(DAEMON_VRRP, &daemon_mode))
		pidfile_rm(vrrp_pidfile);
#endif

#ifdef _WITH_LVS_
	if (__test_bit(DAEMON_CHECKERS, &daemon_mode))
		pidfile_rm(checkers_pidfile);
#endif

#ifdef _WITH_BFD_
	if (__test_bit(DAEMON_BFD, &daemon_mode))
		pidfile_rm(bfd_pidfile);
#endif

	pidfile_rm(main_pidfile);
#endif
}

/* Daemon init sequence */
static int
start_keepalived(void)
{
	bool have_child = false;

#ifdef _WITH_BFD_
	/* must be opened before vrrp and bfd start */
	open_bfd_pipes();
#endif

#ifdef _WITH_LVS_
	/* start healthchecker child */
	if (running_checker()) {
		start_check_child();
		have_child = true;
	}
#endif
#ifdef _WITH_VRRP_
	/* start vrrp child */
	if (running_vrrp()) {
		start_vrrp_child();
		have_child = true;
	}
#endif
#ifdef _WITH_BFD_
	/* start bfd child */
	if (running_bfd()) {
		start_bfd_child();
		have_child = true;
	}
#endif

	return have_child;
}

static void
validate_config(void)
{
#ifdef _WITH_VRRP_
	kernel_netlink_read_interfaces();
#endif

#ifdef _WITH_LVS_
	/* validate healthchecker config */
#ifndef _DEBUG_
	prog_type = PROG_TYPE_CHECKER;
#endif
	check_validate_config();
#endif
#ifdef _WITH_VRRP_
	/* validate vrrp config */
#ifndef _DEBUG_
	prog_type = PROG_TYPE_VRRP;
#endif
	vrrp_validate_config();
#endif
#ifdef _WITH_BFD_
	/* validate bfd config */
#ifndef _DEBUG_
	prog_type = PROG_TYPE_BFD;
#endif
	bfd_validate_config();
#endif
}

static void
config_test_exit(void)
{
	config_err_t config_err = get_config_status();

	switch (config_err) {
	case CONFIG_OK:
		exit(KEEPALIVED_EXIT_OK);
	case CONFIG_FILE_NOT_FOUND:
	case CONFIG_BAD_IF:
	case CONFIG_FATAL:
		exit(KEEPALIVED_EXIT_CONFIG);
	case CONFIG_SECURITY_ERROR:
		exit(KEEPALIVED_EXIT_CONFIG_TEST_SECURITY);
	default:
		exit(KEEPALIVED_EXIT_CONFIG_TEST);
	}
}

#ifndef _DEBUG_
static bool reload_config(void)
{
	bool unsupported_change = false;

	log_message(LOG_INFO, "Reloading ...");

	/* Make sure there isn't an attempt to change the network namespace or instance name */
	old_global_data = global_data;
	global_data = NULL;
	global_data = alloc_global_data();

	read_config_file();

	init_global_data(global_data, old_global_data, false);

	/* Update process name if necessary */
	if (!global_data->process_name != !old_global_data->process_name ||
	    (global_data->process_name && strcmp(global_data->process_name, old_global_data->process_name)))
		set_process_name(global_data->process_name);

#if HAVE_DECL_CLONE_NEWNET
	if (override_namespace) {
		FREE_CONST_PTR(global_data->network_namespace);
		global_data->network_namespace = STRDUP(override_namespace);
	}

	if (!!old_global_data->network_namespace != !!global_data->network_namespace ||
	    (global_data->network_namespace && strcmp(old_global_data->network_namespace, global_data->network_namespace))) {
		log_message(LOG_INFO, "Cannot change network namespace at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
	FREE_CONST_PTR(global_data->network_namespace);
	global_data->network_namespace = old_global_data->network_namespace;
	old_global_data->network_namespace = NULL;
#endif

	if (!!old_global_data->instance_name != !!global_data->instance_name ||
	    (global_data->instance_name && strcmp(old_global_data->instance_name, global_data->instance_name))) {
		log_message(LOG_INFO, "Cannot change instance name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
	FREE_CONST_PTR(global_data->instance_name);
	global_data->instance_name = old_global_data->instance_name;
	old_global_data->instance_name = NULL;

#ifdef _WITH_NFTABLES_
	if (!!old_global_data->vrrp_nf_table_name != !!global_data->vrrp_nf_table_name ||
	    (global_data->vrrp_nf_table_name && strcmp(old_global_data->vrrp_nf_table_name, global_data->vrrp_nf_table_name))) {
		log_message(LOG_INFO, "Cannot change nftables table name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
	FREE_CONST_PTR(global_data->vrrp_nf_table_name);
	global_data->vrrp_nf_table_name = old_global_data->vrrp_nf_table_name;
	old_global_data->vrrp_nf_table_name = NULL;
#endif

	if (unsupported_change) {
		/* We cannot reload the configuration, so continue with the old config */
		free_global_data (global_data);
		global_data = old_global_data;
	}
	else
		free_global_data (old_global_data);


	return !unsupported_change;
}

/* SIGHUP/USR1/USR2 handler */
static void
propagate_signal(__attribute__((unused)) void *v, int sig)
{
	if (sig == SIGHUP) {
		if (!reload_config())
			return;
	}

	/* Signal child processes */
#ifdef _WITH_VRRP_
	if (vrrp_child > 0)
		kill(vrrp_child, sig);
	else if (sig == SIGHUP && running_vrrp())
		start_vrrp_child();
#endif
#ifdef _WITH_LVS_
	if (sig == SIGHUP || sig == SIGUSR1) {
		if (checkers_child > 0)
			kill(checkers_child, sig);
		else if (running_checker())
			start_check_child();
	}
#endif
#ifdef _WITH_BFD_
	if (sig == SIGHUP) {
		if (bfd_child > 0)
			kill(bfd_child, sig);
		else if (running_bfd())
			start_bfd_child();
	}
#endif
}

/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	int status;
	int ret;
	int wait_count = 0;
	struct timeval start_time, now;
#ifdef HAVE_SIGNALFD
	int timeout = child_wait_time * 1000;
	int signal_fd = master->signal_fd;
	struct signalfd_siginfo siginfo;
	sigset_t sigmask;
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = master->signal_fd };
	int efd;
	int wstatus;
#else
	sigset_t old_set, child_wait;
	struct timespec timeout = {
		.tv_sec = child_wait_time,
		.tv_nsec = 0
	};
#endif

	/* register the terminate thread */
	thread_add_terminate_event(master);

	log_message(LOG_INFO, "Stopping");

#ifdef HAVE_SIGNALFD
	/* We only want to receive SIGCHLD now */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	signalfd(signal_fd, &sigmask, 0);
#else
	sigmask_func(0, NULL, &old_set);
	if (!sigismember(&old_set, SIGCHLD)) {
		sigemptyset(&child_wait);
		sigaddset(&child_wait, SIGCHLD);
		sigmask_func(SIG_BLOCK, &child_wait, NULL);
	}
#endif

#ifdef _WITH_VRRP_
	if (vrrp_child > 0) {
		if (kill(vrrp_child, SIGTERM)) {
			/* ESRCH means no such process */
			if (errno == ESRCH)
				vrrp_child = 0;
		}
		else
			wait_count++;
	}
#endif
#ifdef _WITH_LVS_
	if (checkers_child > 0) {
		if (kill(checkers_child, SIGTERM)) {
			if (errno == ESRCH)
				checkers_child = 0;
		}
		else
			wait_count++;
	}
#endif
#ifdef _WITH_BFD_
	if (bfd_child > 0) {
		if (kill(bfd_child, SIGTERM)) {
			if (errno == ESRCH)
				bfd_child = 0;
		}
		else
			wait_count++;
	}
#endif

#ifdef HAVE_SIGNALFD
	efd = epoll_create(1);
	epoll_ctl(efd, EPOLL_CTL_ADD, signal_fd, &ev);
#endif

	gettimeofday(&start_time, NULL);
	while (wait_count) {
#ifdef HAVE_SIGNALFD
		ret = epoll_wait(efd, &ev, 1, timeout);
		if (ret == 0)
			break;
		if (ret == -1) {
			if (check_EINTR(errno))
				continue;

			log_message(LOG_INFO, "Terminating epoll_wait returned errno %d", errno);
			break;
		}

		if (ev.data.fd != signal_fd) {
			log_message(LOG_INFO, "Terminating epoll_wait did not return signal_fd");
			continue;
		}

		if (read(signal_fd, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
			log_message(LOG_INFO, "Terminating signal read did not read entire siginfo");
			break;
		}

		status = siginfo.ssi_code == CLD_EXITED ? W_EXITCODE(siginfo.ssi_status, 0) :
			 siginfo.ssi_code == CLD_KILLED ? W_EXITCODE(0, siginfo.ssi_status) :
							   WCOREFLAG;

#ifdef _WITH_VRRP_
		if (vrrp_child > 0 && vrrp_child == (pid_t)siginfo.ssi_pid) {
			report_child_status(status, vrrp_child, PROG_VRRP);
			ret = waitpid(vrrp_child, &wstatus, WNOHANG);
			if (ret == 0)
				continue;
			if (ret == -1) {
				if (check_EINTR(errno))
					continue;
				log_message(LOG_INFO, "Wait for vrrp child return errno %d", errno);
			}

			/* We could check ret == vrrp_child, but it seems unneccessary */

			vrrp_child = 0;
			wait_count--;
		}
#endif

#ifdef _WITH_LVS_
		if (checkers_child > 0 && checkers_child == (pid_t)siginfo.ssi_pid) {
			report_child_status(status, checkers_child, PROG_CHECK);
			ret = waitpid(checkers_child, &wstatus, WNOHANG);
			if (ret == 0)
				continue;
			if (ret == -1) {
				if (check_EINTR(errno))
					continue;
				log_message(LOG_INFO, "Wait for checker child return errno %d", errno);
			}
			checkers_child = 0;
			wait_count--;
		}
#endif
#ifdef _WITH_BFD_
		if (bfd_child > 0 && bfd_child == (pid_t)siginfo.ssi_pid) {
			report_child_status(status, bfd_child, PROG_BFD);
			ret = waitpid(bfd_child, &wstatus, WNOHANG);
			if (ret == 0)
				continue;
			if (ret == -1) {
				if (check_EINTR(errno))
					continue;
				log_message(LOG_INFO, "Wait for bfd child return errno %d", errno);
			}
			bfd_child = 0;
			wait_count--;
		}
#endif

#else
		ret = sigtimedwait(&child_wait, NULL, &timeout);
		if (ret == -1) {
			if (check_EINTR(errno))
				continue;
			if (check_EAGAIN(errno))
				break;
		}

#ifdef _WITH_VRRP_
		if (vrrp_child > 0 && vrrp_child == waitpid(vrrp_child, &status, WNOHANG)) {
			report_child_status(status, vrrp_child, PROG_VRRP);
			vrrp_child = 0;
			wait_count--;
		}
#endif

#ifdef _WITH_LVS_
		if (checkers_child > 0 && checkers_child == waitpid(checkers_child, &status, WNOHANG)) {
			report_child_status(status, checkers_child, PROG_CHECK);
			checkers_child = 0;
			wait_count--;
		}
#endif
#ifdef _WITH_BFD_
		if (bfd_child > 0 && bfd_child == waitpid(bfd_child, &status, WNOHANG)) {
			report_child_status(status, bfd_child, PROG_BFD);
			bfd_child = 0;
			wait_count--;
		}
#endif
#endif

		if (wait_count) {
			gettimeofday(&now, NULL);
#ifdef HAVE_SIGNALFD
			timeout = (child_wait_time - (now.tv_sec - start_time.tv_sec)) * 1000 + (start_time.tv_usec - now.tv_usec) / 1000;
			if (timeout < 0)
				break;
#else
			timeout.tv_sec = child_wait_time - (now.tv_sec - start_time.tv_sec);
			timeout.tv_nsec = (start_time.tv_usec - now.tv_usec) * 1000;
			if (timeout.tv_nsec < 0) {
				timeout.tv_nsec += 1000000000L;
				timeout.tv_sec--;
			}
			if (timeout.tv_sec < 0)
				break;
#endif
		}
	}
#ifdef HAVE_SIGNALFD
	close(efd);
#endif

	/* A child may not have terminated, so force its termination */
#ifdef _WITH_VRRP_
	if (vrrp_child) {
		log_message(LOG_INFO, "vrrp process failed to die - forcing termination");
		kill(vrrp_child, SIGKILL);
	}
#endif
#ifdef _WITH_LVS_
	if (checkers_child) {
		log_message(LOG_INFO, "checker process failed to die - forcing termination");
		kill(checkers_child, SIGKILL);
	}
#endif
#ifdef _WITH_BFD_
	if (bfd_child) {
		log_message(LOG_INFO, "bfd process failed to die - forcing termination");
		kill(bfd_child, SIGKILL);
	}
#endif

#ifndef HAVE_SIGNALFD
	if (!sigismember(&old_set, SIGCHLD))
		sigmask_func(SIG_UNBLOCK, &child_wait, NULL);
#endif
}
#endif

/* Initialize signal handler */
static void
signal_init(void)
{
#ifndef _DEBUG_
	signal_set(SIGHUP, propagate_signal, NULL);
	signal_set(SIGUSR1, propagate_signal, NULL);
	signal_set(SIGUSR2, propagate_signal, NULL);
#ifdef _WITH_JSON_
	signal_set(SIGJSON, propagate_signal, NULL);
#endif
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
#endif
	signal_ignore(SIGPIPE);
}

static void
signals_ignore(void) {
#ifndef _DEBUG_
	signal_ignore(SIGHUP);
	signal_ignore(SIGUSR1);
	signal_ignore(SIGUSR2);
#ifdef _WITH_JSON_
	signal_ignore(SIGJSON);
#endif
#endif
}

/* To create a core file when abrt is running (a RedHat distribution),
 * and keepalived isn't installed from an RPM package, edit the file
 * “/etc/abrt/abrt.conf”, and change the value of the field
 * “ProcessUnpackaged” to “yes”.
 *
 * Alternatively, use the -M command line option. */
static void
update_core_dump_pattern(const char *pattern_str)
{
	int fd;
	bool initialising = (orig_core_dump_pattern == NULL);

	/* CORENAME_MAX_SIZE in kernel source include/linux/binfmts.h defines
	 * the maximum string length, * see core_pattern[CORENAME_MAX_SIZE] in
	 * fs/coredump.c. Currently (Linux 4.10) defines it to be 128, but the
	 * definition is not exposed to user-space. */
#define	CORENAME_MAX_SIZE	128

	if (initialising)
		orig_core_dump_pattern = MALLOC(CORENAME_MAX_SIZE);

	fd = open ("/proc/sys/kernel/core_pattern", O_RDWR);

	if (fd == -1 ||
	    (initialising && read(fd, orig_core_dump_pattern, CORENAME_MAX_SIZE - 1) == -1) ||
	    write(fd, pattern_str, strlen(pattern_str)) == -1) {
		log_message(LOG_INFO, "Unable to read/write core_pattern");

		if (fd != -1)
			close(fd);

		FREE(orig_core_dump_pattern);

		return;
	}

	close(fd);

	if (!initialising)
		FREE_PTR(orig_core_dump_pattern);
}

static void
core_dump_init(void)
{
	struct rlimit orig_rlim, rlim;

	if (set_core_dump_pattern) {
		/* If we set the core_pattern here, we will attempt to restore it when we
		 * exit. This will be fine if it is a child of ours that core dumps,
		 * but if we ourself core dump, then the core_pattern will not be restored */
		update_core_dump_pattern(core_dump_pattern);
	}

	if (create_core_dump) {
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;

		if (getrlimit(RLIMIT_CORE, &orig_rlim) == -1)
			log_message(LOG_INFO, "Failed to get core file size");
		else if (setrlimit(RLIMIT_CORE, &rlim) == -1)
			log_message(LOG_INFO, "Failed to set core file size");
		else
			set_child_rlimit(RLIMIT_CORE, &orig_rlim);
	}
}

static mode_t
set_umask(const char *optarg)
{
	long umask_long;
	mode_t umask_bits;
	char *endptr;

	umask_long = strtoll(optarg, &endptr, 0);

	if (*endptr || umask_long < 0 || umask_long & ~(S_IRWXU | S_IRWXG | S_IRWXO)) {
		fprintf(stderr, "Invalid --umask option %s", optarg);
		return 0;
	}

	umask_bits = umask_long & (S_IRWXU | S_IRWXG | S_IRWXO);
	umask(umask_bits);

	umask_cmdline = true;

#ifdef _MEM_CHECK_
	update_mem_check_log_perms(umask_bits);
#endif
#ifdef ENABLE_LOG_TO_FILE
	update_log_file_perms(umask_bits);
#endif

	return umask_bits;
}

RELAX_SUGGEST_ATTRIBUTE_CONST_START
void
initialise_debug_options(void)
{
#if defined WITH_DEBUG_OPTIONS && !defined _DEBUG_
	char mask = 0;

	if (prog_type == PROG_TYPE_PARENT)
		mask = 1 << PROG_TYPE_PARENT;
#ifdef _WITH_BFD_
	else if (prog_type == PROG_TYPE_BFD)
		mask = 1 << PROG_TYPE_BFD;
#endif
#ifdef _WITH_LVS_
	else if (prog_type == PROG_TYPE_CHECKER)
		mask = 1 << PROG_TYPE_CHECKER;
#endif
#ifdef _WITH_VRRP_
	else if (prog_type == PROG_TYPE_VRRP)
		mask = 1 << PROG_TYPE_VRRP;
#endif

#ifdef _TIMER_CHECK_
	do_timer_check = !!(timer_debug & mask);
#endif
#ifdef _SMTP_ALERT_DEBUG_
	do_smtp_alert_debug = !!(smtp_debug & mask);
#endif
#ifdef _EPOLL_DEBUG_
	do_epoll_debug = !!(epoll_debug & mask);
#endif
#ifdef _EPOLL_THREAD_DUMP_
	do_epoll_thread_dump = !!(epoll_thread_debug & mask);
#endif
#ifdef _REGEX_DEBUG_
	do_regex_debug = !!(regex_debug & mask);
#endif
#ifdef _WITH_REGEX_TIMERS_
	do_regex_timers = !!(regex_timers & mask);
#endif
#ifdef _TSM_DEBUG_
	do_tsm_debug = !!(tsm_debug & mask);
#endif
#ifdef _VRRP_FD_DEBUG_
	do_vrrp_fd_debug = !!(vrrp_fd_debug & mask);
#endif
#ifdef _NETLINK_TIMERS_
	do_netlink_timers = !!(netlink_timer_debug & mask);
#endif
#ifdef _NETWORK_TIMESTAMP_
	do_network_timestamp = !!(network_timestamp_debug & mask);
#endif
#ifdef _WITH_CN_PROC_
#ifdef _TRACK_PROCESS_DEBUG_
	do_track_process_debug_detail = !!(track_process_debug_detail & mask);
	do_track_process_debug = !!(track_process_debug & mask) | do_track_process_debug_detail;
#endif
#endif
#ifdef _PARSER_DEBUG_
	do_parser_debug = !!(parser_debug & mask);
#endif
#ifdef _DUMP_KEYWORDS_
	do_dump_keywords = !!(dump_keywords & mask);
#endif
#endif
}
RELAX_SUGGEST_ATTRIBUTE_CONST_END

#ifdef  WITH_DEBUG_OPTIONS
static void
set_debug_options(const char *options)
{
	char all_processes, processes;
	char opt;
	const char *opt_p = options;

#ifdef _DEBUG_
	all_processes = 1;
#else
	all_processes = (1 << PROG_TYPE_PARENT);
#ifdef _WITH_BFD_
	all_processes |= (1 << PROG_TYPE_BFD);
#endif
#ifdef _WITH_LVS_
	all_processes |= (1 << PROG_TYPE_CHECKER);
#endif
#ifdef _WITH_VRRP_
	all_processes |= (1 << PROG_TYPE_VRRP);
#endif
#endif

	if (!options) {
#ifdef _TIMER_CHECK_
		timer_debug = all_processes;
#endif
#ifdef _SMTP_ALERT_DEBUG_
		smtp_debug = all_processes;
#endif
#ifdef _EPOLL_DEBUG_
		epoll_debug = all_processes;
#endif
#ifdef _EPOLL_THREAD_DUMP_
		epoll_thread_debug = all_processes;
#endif
#ifdef _REGEX_DEBUG_
		regex_debug = all_processes;
#endif
#ifdef _WITH_REGEX_TIMERS_
		regex_timers = all_processes;
#endif
#ifdef _TSM_DEBUG_
		tsm_debug = all_processes;
#endif
#ifdef _VRRP_FD_DEBUG_
		vrrp_fd_debug = all_processes;
#endif
#ifdef _NETLINK_TIMERS_
		netlink_timer_debug = all_processes;
#endif
#ifdef _NETWORK_TIMESTAMP_
		network_timestamp_debug = all_processes;
#endif
#ifdef _TRACK_PROCESS_DEBUG_
		track_process_debug = all_processes;
		track_process_debug_detail = all_processes;
#endif
#ifdef _PARSER_DEBUG_
		parser_debug = all_processes;
#endif
#ifdef _DUMP_KEYWORDS_
		dump_keywords = all_processes;
#endif

		return;
	}

	opt_p = options;
	while (*opt_p) {
		if (!isupper(*opt_p)) {
			fprintf(stderr, "Unknown debug option'%c' in '%s'\n", *opt_p, options);
			return;
		}
		opt = *opt_p++;

#ifdef _DEBUG_
		processes = all_processes;
#else
		if (!*opt_p || isupper(*opt_p))
			processes = all_processes;
		else {
			processes = 0;
			while (*opt_p && !isupper(*opt_p)) {
				switch (*opt_p) {
				case 'p':
					processes |= (1 << PROG_TYPE_PARENT);
					break;
#ifdef _WITH_BFD_
				case 'b':
					processes |= (1 << PROG_TYPE_BFD);
					break;
#endif
#ifdef _WITH_LVS_
				case 'c':
					processes |= (1 << PROG_TYPE_CHECKER);
					break;
#endif
#ifdef _WITH_VRRP_
				case 'v':
					processes |= (1 << PROG_TYPE_VRRP);
					break;
#endif
				default:
					fprintf(stderr, "Unknown debug process '%c' in '%s'\n", *opt_p, options);
					return;
				}
				opt_p++;
			}
		}
#endif

		switch (opt) {
#ifdef _TIMER_CHECK_
		case 'T':
			timer_debug = processes;
			break;
#endif
#ifdef _SMTP_ALERT_DEBUG_
		case 'M':
			smtp_debug = processes;
			break;
#endif
#ifdef _EPOLL_DEBUG_
		case 'E':
			epoll_debug = processes;
			break;
#endif
#ifdef _EPOLL_THREAD_DUMP_
		case 'D':
			epoll_thread_debug = processes;
			break;
#endif
#ifdef _REGEX_DEBUG_
		case 'R':
			regex_debug = processes;
			break;
#endif
#ifdef _WITH_REGEX_TIMERS_
		case 'X':
			regex_timers = processes;
			break;
#endif
#ifdef _TSM_DEBUG_
		case 'S':
			tsm_debug = processes;
			break;
#endif
#ifdef _VRRP_FD_DEBUG_
		case 'F':
			vrrp_fd_debug = processes;
			break;
#endif
#ifdef _NETLINK_TIMERS_
		case 'N':
			netlink_timer_debug = processes;
			break;
#endif
#ifdef _NETWORK_TIMESTAMP_
		case 'P':
			network_timestamp_debug = processes;
			break;
#endif
#ifdef _TRACK_PROCESS_DEBUG_
		case 'O':
			track_process_debug = processes;
			break;
		case 'A':
			track_process_debug_detail = processes;
			break;
#endif
#ifdef _PARSER_DEBUG_
		case 'C':
			parser_debug = processes;
			break;
#endif
#ifdef _DUMP_KEYWORDS_
		case 'K':
			dump_keywords = processes;
			break;
#endif
		default:
			fprintf(stderr, "Unknown debug type '%c' in '%s'\n", opt, options);
			return;
		}
	}
}
#endif

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -f, --use-file=FILE          Use the specified configuration file\n");
#if defined _WITH_VRRP_ && defined _WITH_LVS_
	fprintf(stderr, "  -P, --vrrp                   Only run with VRRP subsystem\n");
	fprintf(stderr, "  -C, --check                  Only run with Health-checker subsystem\n");
#endif
#ifdef _WITH_BFD_
	fprintf(stderr, "  -B, --no_bfd                 Don't run BFD subsystem\n");
#endif
	fprintf(stderr, "      --all                    Force all child processes to run, even if have no configuration\n");
	fprintf(stderr, "  -l, --log-console            Log messages to local console\n");
	fprintf(stderr, "  -D, --log-detail             Detailed log messages\n");
	fprintf(stderr, "  -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]\n");
#ifdef ENABLE_LOG_TO_FILE
	fprintf(stderr, "  -g, --log-file=FILE          Also log to FILE (default /tmp/keepalived.log)\n");
	fprintf(stderr, "      --flush-log-file         Flush log file on write\n");
#endif
	fprintf(stderr, "  -G, --no-syslog              Don't log via syslog\n");
	fprintf(stderr, "  -u, --umask=MASK             umask for file creation (in numeric form)\n");
#ifdef _WITH_VRRP_
	fprintf(stderr, "  -X, --release-vips           Drop VIP on transition from signal.\n");
	fprintf(stderr, "  -V, --dont-release-vrrp      Don't remove VRRP VIPs and VROUTEs on daemon stop\n");
#endif
#ifdef _WITH_LVS_
	fprintf(stderr, "  -I, --dont-release-ipvs      Don't remove IPVS topology on daemon stop\n");
#endif
	fprintf(stderr, "  -R, --dont-respawn           Don't respawn child processes\n");
	fprintf(stderr, "  -n, --dont-fork              Don't fork the daemon process\n");
	fprintf(stderr, "  -d, --dump-conf              Dump the configuration data\n");
	fprintf(stderr, "  -p, --pid=FILE               Use specified pidfile for parent process\n");
#ifdef _WITH_VRRP_
	fprintf(stderr, "  -r, --vrrp_pid=FILE          Use specified pidfile for VRRP child process\n");
#endif
#ifdef _WITH_LVS_
	fprintf(stderr, "  -c, --checkers_pid=FILE      Use specified pidfile for checkers child process\n");
	fprintf(stderr, "  -a, --address-monitoring     Report all address additions/deletions notified via netlink\n");
#endif
#ifdef _WITH_BFD_
	fprintf(stderr, "  -b, --bfd_pid=FILE           Use specified pidfile for BFD child process\n");
#endif
#ifdef _WITH_SNMP_
	fprintf(stderr, "  -x, --snmp                   Enable SNMP subsystem\n");
	fprintf(stderr, "  -A, --snmp-agent-socket=FILE Use the specified socket for master agent\n");
#endif
#if HAVE_DECL_CLONE_NEWNET
	fprintf(stderr, "  -s, --namespace=NAME         Run in network namespace NAME (overrides config)\n");
#endif
	fprintf(stderr, "  -m, --core-dump              Produce core dump if terminate abnormally\n");
	fprintf(stderr, "  -M, --core-dump-pattern=PATN Also set /proc/sys/kernel/core_pattern to PATN (default 'core')\n");
#ifdef _MEM_CHECK_LOG_
	fprintf(stderr, "  -L, --mem-check-log          Log malloc/frees to syslog\n");
#endif
	fprintf(stderr, "  -i, --config-id id           Skip any configuration lines beginning '@' that don't match id\n"
			"                                or any lines beginning @^ that do match.\n"
			"                                The config-id defaults to the node name if option not used\n");
	fprintf(stderr, "      --signum=SIGFUNC         Return signal number for STOP, RELOAD, DATA, STATS"
#ifdef _WITH_JSON_
								", JSON"
#endif
								"\n");
	fprintf(stderr, "  -t, --config-test[=LOG_FILE] Check the configuration for obvious errors, output to\n"
			"                                stderr by default\n");
#ifdef _WITH_PERF_
	fprintf(stderr, "      --perf[=PERF_TYPE]       Collect perf data, PERF_TYPE=all, run(default) or end\n");
#endif
#ifdef WITH_DEBUG_OPTIONS
	fprintf(stderr, "      --debug[=...]            Enable debug options. p, b, c, v specify parent, bfd, checker and vrrp processes\n");
#ifdef _TIMER_CHECK_
	fprintf(stderr, "                                   T - timer debug\n");
#endif
#ifdef _SMTP_ALERT_DEBUG_
	fprintf(stderr, "                                   M - email alert debug\n");
#endif
#ifdef _EPOLL_DEBUG_
	fprintf(stderr, "                                   E - epoll debug\n");
#endif
#ifdef _EPOLL_THREAD_DUMP_
	fprintf(stderr, "                                   D - epoll thread dump debug\n");
#endif
#ifdef _VRRP_FD_DEBUG_
	fprintf(stderr, "                                   F - vrrp fd dump debug\n");
#endif
#ifdef _REGEX_DEBUG_
	fprintf(stderr, "                                   R - regex debug\n");
#endif
#ifdef _WITH_REGEX_TIMERS_
	fprintf(stderr, "                                   X - regex timers\n");
#endif
#ifdef _TSM_DEBUG_
	fprintf(stderr, "                                   S - TSM debug\n");
#endif
#ifdef _NETLINK_TIMERS_
	fprintf(stderr, "                                   N - netlink timer debug\n");
#endif
#ifdef _NETWORK_TIMESTAMP_
	fprintf(stderr, "                                   P - network timestamp debug\n");
#endif
#ifdef _TRACK_PROCESS_DEBUG_
	fprintf(stderr, "                                   O - track process debug\n");
	fprintf(stderr, "                                   A - track process debug with extra detail\n");
#endif
#ifdef _PARSER_DEBUG_
	fprintf(stderr, "                                   C - parser (config) debug\n");
#endif
#ifdef _DUMP_KEYWORDS_
	fprintf(stderr, "                                   K - dump keywords\n");
#endif
	fprintf(stderr, "                                 Example --debug=TpMEvcp\n");
#endif
	fprintf(stderr, "  -v, --version                Display the version number\n");
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}

/* Command line parser */
static bool
parse_cmdline(int argc, char **argv)
{
	int c;
	bool reopen_log = false;
	int signum;
	struct utsname uname_buf;
	int longindex;
	int curind;
	bool bad_option = false;
	unsigned facility;
	mode_t new_umask_val;

	struct option long_options[] = {
		{"use-file",		required_argument,	NULL, 'f'},
#if defined _WITH_VRRP_ && defined _WITH_LVS_
		{"vrrp",		no_argument,		NULL, 'P'},
		{"check",		no_argument,		NULL, 'C'},
#endif
#ifdef _WITH_BFD_
		{"no_bfd",		no_argument,		NULL, 'B'},
#endif
		{"all",			no_argument,		NULL,  3 },
		{"log-console",		no_argument,		NULL, 'l'},
		{"log-detail",		no_argument,		NULL, 'D'},
		{"log-facility",	required_argument,	NULL, 'S'},
		{"log-file",		optional_argument,	NULL, 'g'},
#ifdef ENABLE_LOG_TO_FILE
		{"flush-log-file",	no_argument,		NULL,  2 },
#endif
		{"no-syslog",		no_argument,		NULL, 'G'},
		{"umask",		required_argument,	NULL, 'u'},
#ifdef _WITH_VRRP_
		{"release-vips",	no_argument,		NULL, 'X'},
		{"dont-release-vrrp",	no_argument,		NULL, 'V'},
#endif
#ifdef _WITH_LVS_
		{"dont-release-ipvs",	no_argument,		NULL, 'I'},
#endif
		{"dont-respawn",	no_argument,		NULL, 'R'},
		{"dont-fork",		no_argument,		NULL, 'n'},
		{"dump-conf",		no_argument,		NULL, 'd'},
		{"pid",			required_argument,	NULL, 'p'},
#ifdef _WITH_VRRP_
		{"vrrp_pid",		required_argument,	NULL, 'r'},
#endif
#ifdef _WITH_LVS_
		{"checkers_pid",	required_argument,	NULL, 'c'},
		{"address-monitoring",	no_argument,		NULL, 'a'},
#endif
#ifdef _WITH_BFD_
		{"bfd_pid",		required_argument,	NULL, 'b'},
#endif
#ifdef _WITH_SNMP_
		{"snmp",		no_argument,		NULL, 'x'},
		{"snmp-agent-socket",	required_argument,	NULL, 'A'},
#endif
		{"core-dump",		no_argument,		NULL, 'm'},
		{"core-dump-pattern",	optional_argument,	NULL, 'M'},
#ifdef _MEM_CHECK_LOG_
		{"mem-check-log",	no_argument,		NULL, 'L'},
#endif
#if HAVE_DECL_CLONE_NEWNET
		{"namespace",		required_argument,	NULL, 's'},
#endif
		{"config-id",		required_argument,	NULL, 'i'},
		{"signum",		required_argument,	NULL,  4 },
		{"config-test",		optional_argument,	NULL, 't'},
#ifdef _WITH_PERF_
		{"perf",		optional_argument,	NULL,  5 },
#endif
#ifdef WITH_DEBUG_OPTIONS
		{"debug",		optional_argument,	NULL,  6 },
#endif
		{"version",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},

		{NULL,			0,			NULL,  0 }
	};

	/* Unfortunately, if a short option is used, getopt_long() doesn't change the value
	 * of longindex, so we need to ensure that before calling getopt_long(), longindex
	 * is set to a known invalid value */
	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":vhlndu:DRS:f:p:i:mM::g::Gt::"
#if defined _WITH_VRRP_ && defined _WITH_LVS_
					    "PC"
#endif
#ifdef _WITH_VRRP_
					    "r:VX"
#endif
#ifdef _WITH_LVS_
					    "ac:I"
#endif
#ifdef _WITH_BFD_
					    "Bb:"
#endif
#ifdef _WITH_SNMP_
					    "xA:"
#endif
#ifdef _MEM_CHECK_LOG_
					    "L"
#endif
#if HAVE_DECL_CLONE_NEWNET
					    "s:"
#endif
				, long_options, &longindex)) != -1) {

		/* Check for an empty option argument. For example --use-file= returns
		 * a 0 length option, which we don't want */
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument && optarg && !optarg[0])
			c = ':';

		switch (c) {
		case 'v':
			fprintf(stderr, "%s", version_string);
#ifdef GIT_COMMIT
			fprintf(stderr, ", git commit %s", GIT_COMMIT);
#endif
			fprintf(stderr, "\n\n%s\n\n", COPYRIGHT_STRING);
			fprintf(stderr, "Built with kernel headers for Linux %d.%d.%d\n",
						(LINUX_VERSION_CODE >> 16) & 0xff,
						(LINUX_VERSION_CODE >>  8) & 0xff,
						(LINUX_VERSION_CODE      ) & 0xff);
			uname(&uname_buf);
			fprintf(stderr, "Running on %s %s %s\n\n", uname_buf.sysname, uname_buf.release, uname_buf.version);
			fprintf(stderr, "configure options: %s\n\n", KEEPALIVED_CONFIGURE_OPTIONS);
			fprintf(stderr, "Config options: %s\n\n", CONFIGURATION_OPTIONS);
			fprintf(stderr, "System options: %s\n", SYSTEM_OPTIONS);
			exit(0);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'l':
			__set_bit(LOG_CONSOLE_BIT, &debug);
			reopen_log = true;
			break;
		case 'n':
			__set_bit(DONT_FORK_BIT, &debug);
			break;
		case 'd':
			__set_bit(DUMP_CONF_BIT, &debug);
			break;
#ifdef _WITH_VRRP_
		case 'V':
			__set_bit(DONT_RELEASE_VRRP_BIT, &debug);
			break;
#endif
#ifdef _WITH_LVS_
		case 'I':
			__set_bit(DONT_RELEASE_IPVS_BIT, &debug);
			break;
#endif
		case 'D':
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				__set_bit(LOG_EXTRA_DETAIL_BIT, &debug);
			else
				__set_bit(LOG_DETAIL_BIT, &debug);
			break;
		case 'R':
			__set_bit(DONT_RESPAWN_BIT, &debug);
			break;
#ifdef _WITH_VRRP_
		case 'X':
			__set_bit(RELEASE_VIPS_BIT, &debug);
			break;
#endif
		case 'S':
			if (!read_unsigned(optarg, &facility, 0, LOG_FACILITY_MAX, false))
				fprintf(stderr, "Invalid log facility '%s'\n", optarg);
			else {
				log_facility = LOG_FACILITY[facility].facility;
				reopen_log = true;
			}
			break;
		case 'g':
#ifdef ENABLE_LOG_TO_FILE
			if (optarg && optarg[0])
				log_file_name = optarg;
			else
				log_file_name = "/tmp/keepalived.log";
			open_log_file(log_file_name, NULL, NULL, NULL);
#else
			fprintf(stderr, "-g requires configure option --enable-log-file\n");
			bad_option = true;
#endif
			break;
#ifdef ENABLE_LOG_TO_FILE
		case 2:		/* --flush-log-file */
			set_flush_log_file();
			break;
#endif
		case 'G':
			__set_bit(NO_SYSLOG_BIT, &debug);
			reopen_log = true;
			break;
		case 'u':
			new_umask_val = set_umask(optarg);
			if (umask_cmdline)
				umask_val = new_umask_val;
			break;
		case 't':
			__set_bit(CONFIG_TEST_BIT, &debug);
			__set_bit(DONT_RESPAWN_BIT, &debug);
			__set_bit(DONT_FORK_BIT, &debug);
			__set_bit(NO_SYSLOG_BIT, &debug);
			if (optarg && optarg[0]) {
				int fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if (fd == -1) {
					fprintf(stderr, "Unable to open config-test log file %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
			break;
		case 'f':
			conf_file = optarg;
			break;
#if defined _WITH_VRRP_ && defined _WITH_LVS_
		case 'P':
			__clear_bit(DAEMON_CHECKERS, &daemon_mode);
			break;
		case 'C':
			__clear_bit(DAEMON_VRRP, &daemon_mode);
			break;
#endif
#ifdef _WITH_BFD_
		case 'B':
			__clear_bit(DAEMON_BFD, &daemon_mode);
			break;
#endif
		case 'p':
			main_pidfile = optarg;
			break;
#ifdef _WITH_LVS_
		case 'c':
			checkers_pidfile = optarg;
			break;
		case 'a':
			__set_bit(LOG_ADDRESS_CHANGES, &debug);
			break;
#endif
#ifdef _WITH_VRRP_
		case 'r':
			vrrp_pidfile = optarg;
			break;
#endif
#ifdef _WITH_BFD_
		case 'b':
			bfd_pidfile = optarg;
			break;
#endif
#ifdef _WITH_SNMP_
		case 'x':
			snmp_option = true;
			break;
		case 'A':
			snmp_socket = optarg;
			break;
#endif
		case 'M':
			set_core_dump_pattern = true;
			if (optarg && optarg[0])
				core_dump_pattern = optarg;
			/* ... falls through ... */
		case 'm':
			create_core_dump = true;
			break;
#ifdef _MEM_CHECK_LOG_
		case 'L':
			__set_bit(MEM_CHECK_LOG_BIT, &debug);
			break;
#endif
#if HAVE_DECL_CLONE_NEWNET
		case 's':
			override_namespace = optarg;
			break;
#endif
		case 'i':
			FREE_CONST_PTR(config_id);
			config_id = STRDUP(optarg);
			break;
		case 4:			/* --signum */
			signum = get_signum(optarg);
			if (signum == -1) {
				fprintf(stderr, "Unknown sigfunc %s\n", optarg);
				exit(1);
			}

			printf("%d\n", signum);
			exit(0);
			break;
		case 3:			/* --all */
			__set_bit(RUN_ALL_CHILDREN, &daemon_mode);
#ifdef _WITH_VRRP_
			__set_bit(DAEMON_VRRP, &daemon_mode);
#endif
#ifdef _WITH_LVS_
			__set_bit(DAEMON_CHECKERS, &daemon_mode);
#endif
#ifdef _WITH_BFD_
			__set_bit(DAEMON_BFD, &daemon_mode);
#endif
			break;
#ifdef _WITH_PERF_
		case 5:
			if (optarg && optarg[0]) {
				if (!strcmp(optarg, "run"))
					perf_run = PERF_RUN;
				else if (!strcmp(optarg, "all"))
					perf_run = PERF_ALL;
				else if (!strcmp(optarg, "end"))
					perf_run = PERF_END;
				else
					log_message(LOG_INFO, "Unknown perf start point %s", optarg);
			}
			else
				perf_run = PERF_RUN;

			break;
#endif
#ifdef WITH_DEBUG_OPTIONS
		case 6:
			set_debug_options(optarg && optarg[0] ? optarg : NULL);
			break;
#endif
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option %s\n", argv[curind]);
			bad_option = true;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = true;
			break;
		default:
			exit(1);
			break;
		}
		curind = optind;
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (bad_option)
		exit(1);

	return reopen_log;
}

#ifdef THREAD_DUMP
static void
register_parent_thread_addresses(void)
{
	register_scheduler_addresses();
	register_signal_thread_addresses();

#ifdef _WITH_LVS_
	register_check_parent_addresses();
#endif
#ifdef _WITH_VRRP_
	register_vrrp_parent_addresses();
#endif
#ifdef _WITH_BFD_
	register_bfd_parent_addresses();
#endif

#ifndef _DEBUG_
	register_signal_handler_address("propagate_signal", propagate_signal);
	register_signal_handler_address("sigend", sigend);
#endif
	register_signal_handler_address("thread_child_handler", thread_child_handler);
}
#endif

/* Entry point */
int
keepalived_main(int argc, char **argv)
{
	bool report_stopped = true;
	struct utsname uname_buf;
	char *end;
	int exit_code = KEEPALIVED_EXIT_OK;
#ifdef _WITH_NFTABLES_
	FILE *fp;
	char nft_ver_buf[128];
	char *p;
	unsigned nft_major = 0, nft_minor = 0, nft_release = 0;
#endif

	/* Ignore reloading signals till signal_init call */
	signals_ignore();

	/* Ensure time_now is set. We then don't have to check anywhere
	 * else if it is set. */
	set_time_now();

	/* Save command line options in case need to log them later */
	save_cmd_line_options(argc, argv);

	/* Init debugging level */
	debug = 0;

	/* We are the parent process */
#ifndef _DEBUG_
	prog_type = PROG_TYPE_PARENT;
#endif

	/* Initialise daemon_mode */
#ifdef _WITH_VRRP_
	__set_bit(DAEMON_VRRP, &daemon_mode);
#endif
#ifdef _WITH_LVS_
	__set_bit(DAEMON_CHECKERS, &daemon_mode);
#endif
#ifdef _WITH_BFD_
	__set_bit(DAEMON_BFD, &daemon_mode);
#endif

	/* Set default file creation mask */
	umask(umask_val);

	/* Open log with default settings so we can log initially */
	openlog(PACKAGE_NAME, LOG_PID, log_facility);

#ifdef _MEM_CHECK_
	mem_log_init(PACKAGE_NAME, "Parent process");
#endif

	/* Some functionality depends on kernel version, so get the version here */
	if (uname(&uname_buf))
		log_message(LOG_INFO, "Unable to get uname() information - error %d", errno);
	else {
		os_major = (unsigned)strtoul(uname_buf.release, &end, 10);
		if (*end != '.')
			os_major = 0;
		else {
			os_minor = (unsigned)strtoul(end + 1, &end, 10);
			if (*end != '.')
				os_major = 0;
			else {
				if (!isdigit(end[1]))
					os_major = 0;
				else
					os_release = (unsigned)strtoul(end + 1, &end, 10);
			}
		}
		if (!os_major)
			log_message(LOG_INFO, "Unable to parse kernel version %s", uname_buf.release);

		/* config_id defaults to hostname */
		if (!config_id) {
			end = strchrnul(uname_buf.nodename, '.');
			config_id = STRNDUP(uname_buf.nodename, (size_t)(end - uname_buf.nodename));
		}
	}

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	if (parse_cmdline(argc, argv)) {
		closelog();
		if (!__test_bit(NO_SYSLOG_BIT, &debug))
			openlog(PACKAGE_NAME, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0) , log_facility);
	}

	if (__test_bit(LOG_CONSOLE_BIT, &debug))
		enable_console_log();

#ifdef GIT_COMMIT
	log_message(LOG_INFO, "Starting %s, git commit %s", version_string, GIT_COMMIT);
#else
	log_message(LOG_INFO, "Starting %s", version_string);
#endif

	/* Handle any core file requirements */
	core_dump_init();

	if (os_major) {
		if (KERNEL_VERSION(os_major, os_minor, os_release) < LINUX_VERSION_CODE) {
			/* keepalived was build for a later kernel version */
			log_message(LOG_INFO, "WARNING - keepalived was build for newer Linux %d.%d.%d, running on %s %s %s",
					(LINUX_VERSION_CODE >> 16) & 0xff,
					(LINUX_VERSION_CODE >>  8) & 0xff,
					(LINUX_VERSION_CODE      ) & 0xff,
					uname_buf.sysname, uname_buf.release, uname_buf.version);
		} else {
			/* keepalived was build for a later kernel version */
			log_message(LOG_INFO, "Running on %s %s %s (built for Linux %d.%d.%d)",
					uname_buf.sysname, uname_buf.release, uname_buf.version,
					(LINUX_VERSION_CODE >> 16) & 0xff,
					(LINUX_VERSION_CODE >>  8) & 0xff,
					(LINUX_VERSION_CODE      ) & 0xff);
		}
	}

#ifndef _DEBUG_
	log_command_line(0);
#endif

	/* Check we can read the configuration file(s).
	   NOTE: the working directory will be / if we
	   forked, but will be the current working directory
	   when keepalived was run if we haven't forked.
	   This means that if any config file names are not
	   absolute file names, the behaviour will be different
	   depending on whether we forked or not. */
	if (!check_conf_file(conf_file)) {
		if (__test_bit(CONFIG_TEST_BIT, &debug))
			config_test_exit();

		exit_code = KEEPALIVED_EXIT_NO_CONFIG;
		goto end;
	}

	global_data = alloc_global_data();

	read_config_file();

	init_global_data(global_data, NULL, false);

#ifdef _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name) {
		/* We are using nftables. Find the version of nft. */
		fp = popen("nft -v 2>/dev/null", "r");
		if (fgets(nft_ver_buf, sizeof(nft_ver_buf) - 1, fp)) {
			p = strchr(nft_ver_buf, ' ');
			while (*p == ' ')
				p++;
			if (*p == 'v')
				p++;

			if (sscanf(p, "%u.%u.%u", &nft_major, &nft_minor, &nft_release) >= 2)
				global_data->nft_version = (nft_major * 0x100 + nft_minor) * 0x100 + nft_release;
		}
		pclose(fp);

		set_nf_ifname_type();
	}
#endif

	/* Update process name if necessary */
	if (global_data->process_name)
		set_process_name(global_data->process_name);

#if HAVE_DECL_CLONE_NEWNET
	if (override_namespace) {
		if (global_data->network_namespace) {
			log_message(LOG_INFO, "Overriding config net_namespace '%s' with command line namespace '%s'", global_data->network_namespace, override_namespace);
			FREE_CONST(global_data->network_namespace);
		}
		global_data->network_namespace = STRDUP(override_namespace);
	}
#endif

	if (!__test_bit(CONFIG_TEST_BIT, &debug) &&
	    (global_data->instance_name
#if HAVE_DECL_CLONE_NEWNET
	     || global_data->network_namespace
#endif
					      )) {
		if ((syslog_ident = make_syslog_ident(PACKAGE_NAME))) {
			log_message(LOG_INFO, "Changing syslog ident to %s", syslog_ident);
			closelog();
			openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0), log_facility);
		}
		else
			log_message(LOG_INFO, "Unable to change syslog ident");

		use_pid_dir = true;

#ifdef ENABLE_LOG_TO_FILE
		open_log_file(log_file_name,
				NULL,
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);
#endif
	}

	/* Initialise pointer to child finding function */
	set_child_finder_name(find_keepalived_child_name);

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		if (use_pid_dir) {
			/* Create the directory for pid files */
			create_pid_dir();
		}
	}

	/* If we want to monitor processes, we have to do it before calling
	 * setns() */
#ifdef _WITH_CN_PROC_
	open_track_processes();
#endif

#if HAVE_DECL_CLONE_NEWNET
	if (global_data->network_namespace) {
		if (global_data->network_namespace && !set_namespaces(global_data->network_namespace)) {
			log_message(LOG_ERR, "Unable to set network namespace %s - exiting", global_data->network_namespace);
			goto end;
		}
	}
#endif

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		if (global_data->instance_name) {
			if (!main_pidfile && (main_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR KEEPALIVED_PID_FILE, global_data->instance_name, PID_EXTENSION)))
				free_main_pidfile = true;
#ifdef _WITH_LVS_
			if (!checkers_pidfile && (checkers_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR CHECKERS_PID_FILE, global_data->instance_name, PID_EXTENSION)))
				free_checkers_pidfile = true;
#endif
#ifdef _WITH_VRRP_
			if (!vrrp_pidfile && (vrrp_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR VRRP_PID_FILE, global_data->instance_name, PID_EXTENSION)))
				free_vrrp_pidfile = true;
#endif
#ifdef _WITH_BFD_
			if (!bfd_pidfile && (bfd_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR VRRP_PID_FILE, global_data->instance_name, PID_EXTENSION)))
				free_bfd_pidfile = true;
#endif
		}

		if (use_pid_dir) {
			if (!main_pidfile)
				main_pidfile = KEEPALIVED_PID_DIR KEEPALIVED_PID_FILE PID_EXTENSION;
#ifdef _WITH_LVS_
			if (!checkers_pidfile)
				checkers_pidfile = KEEPALIVED_PID_DIR CHECKERS_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_VRRP_
			if (!vrrp_pidfile)
				vrrp_pidfile = KEEPALIVED_PID_DIR VRRP_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_BFD_
			if (!bfd_pidfile)
				bfd_pidfile = KEEPALIVED_PID_DIR BFD_PID_FILE PID_EXTENSION;
#endif
		}
		else
		{
			if (!main_pidfile)
				main_pidfile = PID_DIR KEEPALIVED_PID_FILE PID_EXTENSION;
#ifdef _WITH_LVS_
			if (!checkers_pidfile)
				checkers_pidfile = PID_DIR CHECKERS_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_VRRP_
			if (!vrrp_pidfile)
				vrrp_pidfile = PID_DIR VRRP_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_BFD_
			if (!bfd_pidfile)
				bfd_pidfile = PID_DIR BFD_PID_FILE PID_EXTENSION;
#endif
		}

		/* Check if keepalived is already running */
		if (keepalived_running(daemon_mode)) {
			log_message(LOG_INFO, "daemon is already running");
			report_stopped = false;
			goto end;
		}
	}

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug) &&
	    xdaemon(false, false, true) > 0) {
		closelog();
		FREE_CONST_PTR(config_id);
		FREE_PTR(orig_core_dump_pattern);
		close_std_fd();
		exit(0);
	}

#ifdef _MEM_CHECK_
	enable_mem_log_termination();
#endif

	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		validate_config();

		config_test_exit();
	}

	/* write the father's pidfile */
	if (!pidfile_write(main_pidfile, getpid()))
		goto end;

	/* Create the master thread */
	master = thread_make_master();

	/* Signal handling initialization  */
	signal_init();

	/* Init daemon */
	if (!start_keepalived())
		log_message(LOG_INFO, "Warning - keepalived has no configuration to run");

	initialise_debug_options();

#ifdef THREAD_DUMP
	register_parent_thread_addresses();
#endif

	/* Launch the scheduling I/O multiplexer */
	launch_thread_scheduler(master);

	/* Finish daemon process */
	stop_keepalived();

#ifdef THREAD_DUMP
	deregister_thread_addresses();
#endif

	/*
	 * Reached when terminate signal catched.
	 * finally return from system
	 */
end:
	if (report_stopped) {
#ifdef GIT_COMMIT
		log_message(LOG_INFO, "Stopped %s, git commit %s", version_string, GIT_COMMIT);
#else
		log_message(LOG_INFO, "Stopped %s", version_string);
#endif
	}

#if HAVE_DECL_CLONE_NEWNET
	if (global_data && global_data->network_namespace)
		clear_namespaces();
#endif

	if (use_pid_dir)
		remove_pid_dir();

	/* Restore original core_pattern if necessary */
	if (orig_core_dump_pattern)
		update_core_dump_pattern(orig_core_dump_pattern);

	free_parent_mallocs_startup(false);
	free_parent_mallocs_exit();
	free_global_data(global_data);

	closelog();

#ifndef _MEM_CHECK_LOG_
	FREE_CONST_PTR(syslog_ident);
#else
	if (syslog_ident)
		free(no_const_char_p(syslog_ident));
#endif
	close_std_fd();

	return exit_code;
}
