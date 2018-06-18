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

#include "git-commit.h"

#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <stdbool.h>
#ifdef HAVE_SIGNALFD
#include <sys/signalfd.h>
#endif
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/version.h>
#include <ctype.h>

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
#ifdef _WITH_JSON_
#include "vrrp_json.h"
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

/* musl libc doesn't define the following */
#ifndef	W_EXITCODE
#define	W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
#endif
#ifndef	WCOREFLAG
#define	WCOREFLAG		((int32_t)WCOREDUMP(0xffffffff))
#endif

#define	LOG_FACILITY_MAX	7
#define	VERSION_STRING		PACKAGE_NAME " v" PACKAGE_VERSION " (" GIT_DATE ")"
#define COPYRIGHT_STRING	"Copyright(C) 2001-" GIT_YEAR " Alexandre Cassen, <acassen@gmail.com>"

#define CHILD_WAIT_SECS	5

/* global var */
const char *version_string = VERSION_STRING;		/* keepalived version */
char *conf_file = KEEPALIVED_CONFIG_FILE;		/* Configuration file */
int log_facility = LOG_DAEMON;				/* Optional logging facilities */
bool reload;						/* Set during a reload */
char *main_pidfile;					/* overrule default pidfile */
static bool free_main_pidfile;
#ifdef _WITH_LVS_
pid_t checkers_child;					/* Healthcheckers child process ID */
char *checkers_pidfile;					/* overrule default pidfile */
static bool free_checkers_pidfile;
#endif
#ifdef _WITH_VRRP_
pid_t vrrp_child;					/* VRRP child process ID */
char *vrrp_pidfile;					/* overrule default pidfile */
static bool free_vrrp_pidfile;
#endif
#ifdef _WITH_BFD_
pid_t bfd_child;					/* BFD child process ID */
char *bfd_pidfile;					/* overrule default pidfile */
static bool free_bfd_pidfile;
#endif
unsigned long daemon_mode;				/* VRRP/CHECK/BFD subsystem selection */
#ifdef _WITH_SNMP_
bool snmp;						/* Enable SNMP support */
const char *snmp_socket;				/* Socket to use for SNMP agent */
#endif
static char *syslog_ident;				/* syslog ident if not default */
bool use_pid_dir;					/* Put pid files in /var/run/keepalived or @localstatedir@/run/keepalived */

unsigned os_major;					/* Kernel version */
unsigned os_minor;
unsigned os_release;
char *hostname;						/* Initial part of hostname */

#if HAVE_DECL_CLONE_NEWNET
static char *override_namespace;			/* If namespace specified on command line */
#endif

unsigned child_wait_time = CHILD_WAIT_SECS;		/* Time to wait for children to exit */

int test_exit_status = EXIT_SUCCESS;			/* Set to EXIT_FAILURE if the configuration has a problem */

/* Log facility table */
static struct {
	int facility;
} LOG_FACILITY[LOG_FACILITY_MAX + 1] = {
	{LOG_LOCAL0}, {LOG_LOCAL1}, {LOG_LOCAL2}, {LOG_LOCAL3},
	{LOG_LOCAL4}, {LOG_LOCAL5}, {LOG_LOCAL6}, {LOG_LOCAL7}
};

/* Control producing core dumps */
static bool set_core_dump_pattern = false;
static bool create_core_dump = false;
static const char *core_dump_pattern = "core";
static char *orig_core_dump_pattern = NULL;

#ifdef _TIMER_DEBUG_
extern void print_smtp_addresses(void);
extern void print_check_daemon_addresses(void);
extern void print_check_dns_addresses(void);
extern void print_check_http_addresses(void);
extern void print_check_misc_addresses(void);
extern void print_check_smtp_addresses(void);
extern void print_check_tcp_addresses(void);
#ifdef _WITH_DBUS_
extern void print_vrrp_dbus_addresses(void);
#endif
extern void print_vrrp_if_addresses(void);
extern void print_vrrp_netlink_addresses(void);
extern void print_vrrp_daemon_addresses(void);
extern void print_check_ssl_addresses(void);
extern void print_vrrp_scheduler_addresses(void);

void global_print(void)
{
	print_smtp_addresses();
#ifdef _WITH_LVS_
	print_check_daemon_addresses();
	print_check_dns_addresses();
	print_check_http_addresses();
	print_check_misc_addresses();
	print_check_smtp_addresses();
	print_check_ssl_addresses();
	print_check_tcp_addresses();
#ifdef _WITH_BFD_
	print_check_bfd_addresses();
#endif
#endif
#ifdef _WITH_VRRP_
#ifdef _WITH_DBUS_
	print_vrrp_dbus_addresses();
#endif
	print_vrrp_if_addresses();
	print_vrrp_netlink_addresses();
	print_vrrp_daemon_addresses();
	print_vrrp_scheduler_addresses();
#endif
}
#endif

void
free_parent_mallocs_startup(bool am_child)
{
	if (am_child) {
#if HAVE_DECL_CLONE_NEWNET
		free_dirname();
#endif
#ifndef _MEM_CHECK_LOG_
		FREE_PTR(syslog_ident);
#else
		free(syslog_ident);
#endif
		syslog_ident = NULL;

		if (orig_core_dump_pattern) {
			FREE_PTR(orig_core_dump_pattern);
			orig_core_dump_pattern = NULL;
		}
	}

	if (free_main_pidfile) {
		FREE_PTR(main_pidfile);
		main_pidfile = NULL;
		free_main_pidfile = false;
	}
}

void
free_parent_mallocs_exit(void)
{
#ifdef _WITH_VRRP_
	if (free_vrrp_pidfile)
		FREE_PTR(vrrp_pidfile);
#endif
#ifdef _WITH_LVS_
	if (free_checkers_pidfile)
		FREE_PTR(checkers_pidfile);
#endif
#ifdef _WITH_BFD_
	if (free_bfd_pidfile)
		FREE_PTR(bfd_pidfile);
#endif

	FREE_PTR(config_id);
}

char *
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

#ifndef _DEBUG_
static void
parent_child_remover(thread_t *thread)
{
	int exit_status;

	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		exit_status = WIFEXITED(thread->u.c.status) ? WEXITSTATUS(thread->u.c.status) : 0;

		if (exit_status && exit_status != KEEPALIVED_EXIT_OK)
		       test_exit_status = EXIT_FAILURE;
	}

        if (prog_type == PROG_TYPE_PARENT) {
#ifdef _WITH_VRRP_
                if (thread->u.c.pid == vrrp_child)
                        vrrp_child = 0;
#endif
#ifdef _WITH_LVS_
                if (thread->u.c.pid == checkers_child)
                        checkers_child = 0;
#endif
#ifdef _WITH_BFD_
                if (thread->u.c.pid == bfd_child)
                        bfd_child = 0;
#endif

		if (__test_bit(CONFIG_TEST_BIT, &debug)) {
#ifdef _WITH_VRRP_
			if (vrrp_child == 0)
#endif
#ifdef _WITH_LVS_
			if (checkers_child == 0)
#endif
#ifdef _WITH_BFD_
			if (bfd_child == 0)
#endif
				raise(SIGTERM);
		}
	}
}
#endif

#ifdef _WITH_VRRP_
bool
running_vrrp(void)
{
	return (__test_bit(DAEMON_VRRP, &daemon_mode) &&
	    (global_data->have_vrrp_config ||
	     __test_bit(RUN_ALL_CHILDREN, &daemon_mode)));
}
#endif

#ifdef _WITH_LVS_
bool
running_checker(void)
{
	return (__test_bit(DAEMON_CHECKERS, &daemon_mode) &&
	    (global_data->have_checker_config ||
	     __test_bit(RUN_ALL_CHILDREN, &daemon_mode)));
}
#endif

#ifdef _WITH_BFD_
bool
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

static vector_t *
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
	signal_handler_destroy();
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
static void
start_keepalived(void)
{
#ifdef _WITH_BFD_
	/* must be opened before vrrp and bfd start */
	open_bfd_pipes();
#endif

#ifdef _WITH_LVS_
	/* start healthchecker child */
	if (running_checker())
		start_check_child();
#endif
#ifdef _WITH_VRRP_
	/* start vrrp child */
	if (running_vrrp())
		start_vrrp_child();
#endif
#ifdef _WITH_BFD_
	/* start bfd child */
	if (running_bfd())
		start_bfd_child();
#endif
}

static bool reload_config(void)
{
	bool unsupported_change = false;

	/* Make sure there isn't an attempt to change the network namespace or instance name */
	old_global_data = global_data;
	global_data = NULL;
	global_data = alloc_global_data();

	read_config_file();

	init_global_data(global_data);

#if HAVE_DECL_CLONE_NEWNET
	if (!!old_global_data->network_namespace != !!global_data->network_namespace ||
	    (global_data->network_namespace && strcmp(old_global_data->network_namespace, global_data->network_namespace))) {
		log_message(LOG_INFO, "Cannot change network namespace at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
	FREE_PTR(global_data->network_namespace);
	global_data->network_namespace = old_global_data->network_namespace;
	old_global_data->network_namespace = NULL;
#endif

	if (!!old_global_data->instance_name != !!global_data->instance_name ||
	    (global_data->instance_name && strcmp(old_global_data->instance_name, global_data->instance_name))) {
		log_message(LOG_INFO, "Cannot change instance name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
	FREE_PTR(global_data->instance_name);
	global_data->instance_name = old_global_data->instance_name;
	old_global_data->instance_name = NULL;

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
#ifndef _DEBUG_
static void
propogate_signal(__attribute__((unused)) void *v, int sig)
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
	if (sig == SIGHUP) {
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
	struct timeval timeout = {
		.tv_sec = child_wait_time,
		.tv_usec = 0
	};
	int signal_fd = signal_rfd();
	fd_set read_set;
	struct signalfd_siginfo siginfo;
	sigset_t sigmask;
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
	FD_ZERO(&read_set);
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
		if (!__test_bit(CONFIG_TEST_BIT, &debug) && kill(vrrp_child, SIGTERM)) {
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
		if (!__test_bit(CONFIG_TEST_BIT, &debug) && kill(checkers_child, SIGTERM)) {
			if (errno == ESRCH)
				checkers_child = 0;
		}
		else
			wait_count++;
	}
#endif
#ifdef _WITH_BFD_
	if (bfd_child > 0) {
		if (!__test_bit(CONFIG_TEST_BIT, &debug) && kill(bfd_child, SIGTERM)) {
			if (errno == ESRCH)
				bfd_child = 0;
		}
		else
			wait_count++;
	}
#endif

	gettimeofday(&start_time, NULL);
	while (wait_count) {
#ifdef HAVE_SIGNALFD
		FD_SET(signal_fd, &read_set);
		ret = select(signal_fd + 1, &read_set, NULL, NULL, &timeout);
		if (ret == 0)
			break;
		if (ret == -1) {
			if (errno == EINTR)
				continue;

			log_message(LOG_INFO, "Terminating select returned errno %d", errno);
			break;
		}

		if (!FD_ISSET(signal_fd, &read_set)) {
			log_message(LOG_INFO, "Terminating select did not return select_fd");
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
			vrrp_child = 0;
			wait_count--;
		}
#endif

#ifdef _WITH_LVS_
		if (checkers_child > 0 && checkers_child == (pid_t)siginfo.ssi_pid) {
			report_child_status(status, checkers_child, PROG_CHECK);
			checkers_child = 0;
			wait_count--;
		}
#endif
#ifdef _WITH_BFD_
		if (bfd_child > 0 && bfd_child == (pid_t)siginfo.ssi_pid) {
			report_child_status(status, bfd_child, PROG_BFD);
			bfd_child = 0;
			wait_count--;
		}
#endif

#else
		ret = sigtimedwait(&child_wait, NULL, &timeout);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
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
			timeout.tv_sec = child_wait_time - (now.tv_sec - start_time.tv_sec);
#ifdef HAVE_SIGNALFD
			timeout.tv_usec = (start_time.tv_usec - now.tv_usec);
			if (timeout.tv_usec < 0) {
				timeout.tv_usec += 1000000L;
				timeout.tv_sec--;
			}
#else
			timeout.tv_nsec = (start_time.tv_usec - now.tv_usec) * 1000;
			if (timeout.tv_nsec < 0) {
				timeout.tv_nsec += 1000000000L;
				timeout.tv_sec--;
			}
#endif
			if (timeout.tv_sec < 0)
				break;
		}
	}

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
	signal_handler_init();
#ifndef _DEBUG_
	signal_set(SIGHUP, propogate_signal, NULL);
	signal_set(SIGUSR1, propogate_signal, NULL);
	signal_set(SIGUSR2, propogate_signal, NULL);
#ifdef _WITH_JSON_
	signal_set(SIGJSON, propogate_signal, NULL);
#endif
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
#endif
	signal_ignore(SIGPIPE);
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
	    ( initialising && read(fd, orig_core_dump_pattern, CORENAME_MAX_SIZE - 1) == -1) ||
	    write(fd, pattern_str, strlen(pattern_str)) == -1) {
		log_message(LOG_INFO, "Unable to read/write core_pattern");

		if (fd != -1)
			close(fd);

		FREE(orig_core_dump_pattern);
		orig_core_dump_pattern = NULL;

		return;
	}

	close(fd);

	if (!initialising) {
		FREE(orig_core_dump_pattern);
		orig_core_dump_pattern = NULL;
	}
}

static void
core_dump_init(void)
{
	struct rlimit rlim;

	if (set_core_dump_pattern) {
		/* If we set the core_pattern here, we will attempt to restore it when we
		 * exit. This will be fine if it is a child of ours that core dumps,
		 * but if we ourself core dump, then the core_pattern will not be restored */
		update_core_dump_pattern(core_dump_pattern);
	}

	if (create_core_dump) {
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;

		if (setrlimit(RLIMIT_CORE, &rlim) == -1)
			log_message(LOG_INFO, "Failed to set core file size");
	}
}

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
	fprintf(stderr, "  -g, --log-file=FILE          Also log to FILE (default /tmp/keepalived.log)\n");
	fprintf(stderr, "      --flush-log-file         Flush log file on write\n");
	fprintf(stderr, "  -G, --no-syslog              Don't log via syslog\n");
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
	fprintf(stderr, "  -t, --config-test [LOG_FILE] Check the configuration for obvious errors, default log file\n"
			"                                /tmp/keepalived.config-check\n");
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
		{"flush-log-file",	no_argument,		NULL,  2 },
		{"no-syslog",		no_argument,		NULL, 'G'},
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
		{"version",		no_argument,		NULL, 'v'},
		{"help",		no_argument,		NULL, 'h'},

		{NULL,			0,			NULL,  0 }
	};

	/* Unfortunately, if a short option is used, getopt_long() doesn't change the value
	 * of longindex, so we need to ensure that before calling getopt_long(), longindex
	 * is set to a know invalid value */
	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":vhlndDRS:f:p:i:mM::g::Gt::"
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
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument && optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

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
			log_facility = LOG_FACILITY[atoi(optarg)].facility;
			reopen_log = true;
			break;
		case 'g':
			if (optarg && optarg[0])
				log_file_name = optarg;
			else
				log_file_name = "/tmp/keepalived.log";
			open_log_file(log_file_name, NULL, NULL, NULL);
			break;
		case 'G':
			__set_bit(NO_SYSLOG_BIT, &debug);
			reopen_log = true;
			break;
		case 't':
			__set_bit(CONFIG_TEST_BIT, &debug);
			__set_bit(DONT_RESPAWN_BIT, &debug);
			__set_bit(DONT_FORK_BIT, &debug);
			__set_bit(NO_SYSLOG_BIT, &debug);
			if (optarg && optarg[0])
				log_file_name = optarg;
			else
				log_file_name = "/tmp/keepalived.config-check";
			open_log_file(log_file_name, NULL, NULL, NULL);
			reopen_log = true;
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 2:		/* --flush-log-file */
			set_flush_log_file();
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
			snmp = 1;
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
			override_namespace = MALLOC(strlen(optarg) + 1);
			strcpy(override_namespace, optarg);
			break;
#endif
		case 'i':
			FREE_PTR(config_id);
			config_id = MALLOC(strlen(optarg) + 1);
			strcpy(config_id, optarg);
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
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
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

/* Entry point */
int
keepalived_main(int argc, char **argv)
{
	bool report_stopped = true;
	struct utsname uname_buf;
	char *end;

	/* Init debugging level */
	debug = 0;

	/* We are the parent process */
#ifndef _DEBUG_
	prog_type = PROG_TYPE_PARENT;
#endif

	/* Initialise pointer to child finding function */
	set_child_finder_name(find_keepalived_child_name);

	/* If one of our children terminates, we want to clear it out */
	set_child_remover(parent_child_remover);

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
			config_id = MALLOC((size_t)(end - uname_buf.nodename) + 1);
			strncpy(config_id, uname_buf.nodename, (size_t)(end - uname_buf.nodename));
			config_id[end - uname_buf.nodename] = '\0';
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

	netlink_set_recv_buf_size();

	/* Check we can read the configuration file(s).
	   NOTE: the working directory will be / if we
	   forked, but will be the current working directory
	   when keepalived was run if we haven't forked.
	   This means that if any config file names are not
	   absolute file names, the behaviour will be different
	   depending on whether we forked or not. */
	if (!check_conf_file(conf_file))
		goto end;

	global_data = alloc_global_data();

	read_config_file();

	init_global_data(global_data);

#if HAVE_DECL_CLONE_NEWNET
	if (override_namespace) {
		if (global_data->network_namespace) {
			log_message(LOG_INFO, "Overriding config net_namespace '%s' with command line namespace '%s'", global_data->network_namespace, override_namespace);
			FREE(global_data->network_namespace);
		}
		global_data->network_namespace = override_namespace;
		override_namespace = NULL;
	}
#endif

	if (global_data->instance_name
#if HAVE_DECL_CLONE_NEWNET
			  || global_data->network_namespace
#endif
					      ) {
		if ((syslog_ident = make_syslog_ident(PACKAGE_NAME))) {
			log_message(LOG_INFO, "Changing syslog ident to %s", syslog_ident);
			closelog();
			openlog(syslog_ident, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0), log_facility);
		}
		else
			log_message(LOG_INFO, "Unable to change syslog ident");

		use_pid_dir = true;

		open_log_file(log_file_name,
				NULL,
#if HAVE_DECL_CLONE_NEWNET
				global_data->network_namespace,
#else
				NULL,
#endif
				global_data->instance_name);
	}

#ifdef _TIMER_DEBUG_
	global_print();
#endif

	if (use_pid_dir) {
		/* Create the directory for pid files */
		create_pid_dir();
	}

#if HAVE_DECL_CLONE_NEWNET
	if (global_data->network_namespace) {
		if (global_data->network_namespace && !set_namespaces(global_data->network_namespace)) {
			log_message(LOG_ERR, "Unable to set network namespace %s - exiting", global_data->network_namespace);
			goto end;
		}
	}
#endif

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

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug) &&
	    xdaemon(false, false, true) > 0) {
		closelog();
		FREE(config_id);
		FREE(orig_core_dump_pattern);
		close_std_fd();
		exit(0);
	}

	/* Set file creation mask */
	umask(0);

#ifdef _MEM_CHECK_
	enable_mem_log_termination();
#endif

	/* write the father's pidfile */
	if (!pidfile_write(main_pidfile, getpid()))
		goto end;

	/* Signal handling initialization  */
	signal_init();

	/* Create the master thread */
	master = thread_make_master();

	add_signal_read_thread();

	/* Init daemon */
	signal_set(SIGCHLD, thread_child_handler, master);	/* Set this before creating children */
	start_keepalived();

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish daemon process */
	stop_keepalived();

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
	FREE_PTR(syslog_ident);
#else
	if (syslog_ident)
		free(syslog_ident);
#endif
	close_std_fd();

	exit(test_exit_status);
}
