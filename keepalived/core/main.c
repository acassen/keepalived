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
#include <sys/signalfd.h>
#include <sys/epoll.h>
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
#include <sys/prctl.h>

#include "main.h"
#include "global_data.h"
#include "daemon.h"
#include "config.h"
#ifndef _ONE_PROCESS_DEBUG_
#include "config_notify.h"
#endif
#include "git-commit.h"
#include "utils.h"
#include "signals.h"
#include "pidfile.h"
#include "bitops.h"
#include "logger.h"
#include "parser.h"
#include "notify.h"
#include "track_file.h"
#ifdef _WITH_LVS_
#include "check_genhash.h"
#include "check_parser.h"
#include "check_daemon.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_daemon.h"
#include "vrrp_parser.h"
#include "vrrp_if.h"
#ifdef _WITH_TRACK_PROCESS_
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
#include "namespaces.h"
#include "scheduler.h"
#include "keepalived_netlink.h"
#include "git-commit.h"
#if defined THREAD_DUMP || defined _EPOLL_DEBUG_ || defined _EPOLL_THREAD_DUMP_ || defined _SCRIPT_DEBUG_
#include "scheduler.h"
#endif
#include "process.h"
#ifdef _TIMER_CHECK_
#include "timer.h"
#endif
#if defined _SMTP_ALERT_DEBUG_ || defined _SMTP_CONNECT_DEBUG_
#include "smtp.h"
#endif
#if defined _REGEX_DEBUG_ || defined _WITH_REGEX_TIMERS_
#include "check_http.h"
#endif
#if defined _NETWORK_TIMESTAMP_ || defined _CHECKSUM_DEBUG_
#include "vrrp.h"
#endif
#if defined _TSM_DEBUG_ || defined _RECVMSG_DEBUG_
#include "vrrp_scheduler.h"
#endif
#if defined _PARSER_DEBUG_ || defined _DUMP_KEYWORDS_
#include "parser.h"
#endif
#ifdef _CHECKER_DEBUG_
#include "check_api.h"
#endif
#ifdef _MEM_ERR_DEBUG_
#include "memory.h"
#endif
#ifndef _ONE_PROCESS_DEBUG_
#include "reload_monitor.h"
#endif
#ifdef _USE_SYSTEMD_NOTIFY_
#include "systemd.h"
#endif
#include "warnings.h"

#define CHILD_WAIT_SECS	5

/* Structure used for handling termination of children */
struct child_term {
	pid_t * const pid_p;
	const char * const name;
	const char * const short_name;
};

#ifndef _ONE_PROCESS_DEBUG_
static const struct child_term children_term[] = {
#ifdef _WITH_VRRP_
	{ &vrrp_child, PROG_VRRP, "vrrp" },
#endif
#ifdef _WITH_LVS_
	{ &checkers_child, PROG_CHECK, "checker" },
#endif
#ifdef _WITH_BFD_
	{ &bfd_child, PROG_BFD, "bfd" },
#endif
};
#define NUM_CHILD_TERM	(sizeof children_term / sizeof children_term[0])
#endif

/* global var */
const char *version_string = VERSION_STRING;		/* keepalived version */
const char *conf_file = KEEPALIVED_CONFIG_FILE;		/* Configuration file */
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
bool use_pid_dir;					/* Put pid files in /run/keepalived or @localstatedir@/run/keepalived */

unsigned os_major;					/* Kernel version */
unsigned os_minor;
unsigned os_release;
char *hostname;						/* Initial part of hostname */

static char *override_namespace;			/* If namespace specified on command line */

unsigned child_wait_time = CHILD_WAIT_SECS;		/* Time to wait for children to exit */

/* Log facility table */
static struct {
	int facility;
} LOG_FACILITY[] = {
	{LOG_LOCAL0}, {LOG_LOCAL1}, {LOG_LOCAL2}, {LOG_LOCAL3},
	{LOG_LOCAL4}, {LOG_LOCAL5}, {LOG_LOCAL6}, {LOG_LOCAL7}
};
#define	LOG_FACILITY_MAX	((sizeof(LOG_FACILITY) / sizeof(LOG_FACILITY[0])) - 1)

static struct {
	const char *name;
	int facility;
} facility_names[] = {
	{ "daemon", LOG_DAEMON },
	{ "user", LOG_USER }
};

/* umask settings */
bool umask_cmdline;

/* Reload control */
unsigned num_reloading;

/* Control producing core dumps */
static bool set_core_dump_pattern = false;
static bool create_core_dump = false;
static const char *core_dump_pattern = "core";
static char *orig_core_dump_pattern = NULL;

#ifndef _ONE_PROCESS_DEBUG_
static const char *dump_file = KA_TMP_DIR "/keepalived_parent.data";
#endif

/* debug flags */
#if defined _TIMER_CHECK_ || \
    defined _SMTP_ALERT_DEBUG_ || \
    defined _SMTP_CONNECT_DEBUG_ || \
    defined _EPOLL_DEBUG_ || \
    defined _EPOLL_THREAD_DUMP_ || \
    defined _REGEX_DEBUG_ || \
    defined _WITH_REGEX_TIMERS_ || \
    defined _TSM_DEBUG_ || \
    defined _VRRP_FD_DEBUG_ || \
    defined _NETLINK_TIMERS_ || \
    defined _NETWORK_TIMESTAMP_ || \
    defined _CHECKSUM_DEBUG_ || \
    defined _TRACK_PROCESS_DEBUG_ || \
    defined _PARSER_DEBUG_ || \
    defined _DUMP_KEYWORDS_ || \
    defined _CHECKER_DEBUG_ || \
    defined _MEM_ERR_DEBUG_ || \
    defined _RECVMSG_DEBUG_ || \
    defined _EINTR_DEBUG_ || \
    defined _SCRIPT_DEBUG_
#define WITH_DEBUG_OPTIONS 1
#endif

#ifdef _TIMER_CHECK_
static char timer_debug;
#endif
#ifdef _SMTP_ALERT_DEBUG_
static char smtp_debug;
#endif
#ifdef _SMTP_CONNECT_DEBUG_
static char smtp_connect_debug;
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
#ifdef _CHECKSUM_DEBUG_
static char checksum_debug;
#endif
#ifdef _TRACK_PROCESS_DEBUG_
static char track_process_debug;
static char track_process_debug_detail;
#endif
#ifdef _PARSER_DEBUG_
static char parser_debug;
#endif
#ifdef _CHECKER_DEBUG_
static char checker_debug;
#endif
#ifdef _MEM_ERR_DEBUG_
static char mem_err_debug;
#endif
#ifdef _RECVMSG_DEBUG_
static char recvmsg_debug;
static char recvmsg_debug_dump;
#endif
#ifdef _EINTR_DEBUG_
static char eintr_debug;
#endif
#ifdef _SCRIPT_DEBUG_
static char script_debug;
#endif
#ifdef _DUMP_KEYWORDS_
static char dump_keywords;
#endif

void
free_parent_mallocs_startup(bool am_child)
{
	if (am_child) {
		free_dirname();
#ifdef _MEM_CHECK_LOG_
		free(no_const_char_p(syslog_ident));	/* malloc'd in make_syslog_ident */
#else
		FREE_CONST_PTR(syslog_ident);
#endif
		syslog_ident = NULL;

		FREE_PTR(orig_core_dump_pattern);

		free_notify_script(&global_data->startup_script);
		free_notify_script(&global_data->shutdown_script);
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

	if (global_data->network_namespace)
		ident_len += strlen(global_data->network_namespace) + 1;
	if (global_data->instance_name)
		ident_len += strlen(global_data->instance_name) + 1;

	/* If we are writing MALLOC/FREE info to the log, we have
	 * trouble FREEing the syslog_ident */
#ifdef _MEM_CHECK_LOG_
	ident = malloc(ident_len);	/* Required to stop loop */
#else
	ident = MALLOC(ident_len);
#endif

	if (!ident)
		return NULL;

	strcpy(ident, name);
	if (global_data->network_namespace) {
		strcat(ident, "_");
		strcat(ident, global_data->network_namespace);
	}
	if (global_data->instance_name) {
		strcat(ident, "_");
		strcat(ident, global_data->instance_name);
	}

	return ident;
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
#if defined _WITH_VRRP_ || defined _WITH_LVS_
	add_track_file_keywords(false);
#endif

	return keywords;
}

#ifndef _ONE_PROCESS_DEBUG_
static void
create_reload_file(void)
{
	int fd;

	if (!global_data->reload_file || __test_bit(CONFIG_TEST_BIT, &debug))
		return;

	/* We want to create the reloading file with permissions rw-r--r-- */
	if (umask_val & (S_IRGRP | S_IROTH))
		umask(umask_val & ~(S_IRGRP | S_IROTH));

	if ((fd = creat(global_data->reload_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1)
		close(fd);
	else
		log_message(LOG_INFO, "Failed to create reload file (%s) %d - %m", global_data->reload_file, errno);

	/* Restore the default umask */
	if (umask_val & (S_IRGRP | S_IROTH))
		umask(umask_val);
}

static void
remove_reload_file(void)
{
	if (global_data->reload_file && !__test_bit(CONFIG_TEST_BIT, &debug))
		unlink(global_data->reload_file);
}
#endif

static void
read_config_file(bool write_config_copy)
{
#ifndef _ONE_PROCESS_DEBUG_
	if (write_config_copy)
		create_reload_file();
#else
	write_config_copy = false;
#endif

	init_data(conf_file, global_init_keywords, write_config_copy);

#ifndef _ONE_PROCESS_DEBUG_
	if (write_config_copy)
		remove_reload_file();
#endif
}

/* Daemon stop sequence */
static void
stop_keepalived(void)
{
#ifndef _ONE_PROCESS_DEBUG_
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
static void
start_keepalived(__attribute__((unused)) thread_ref_t thread)
{
	bool have_child = false;

#ifdef _WITH_BFD_
	/* must be opened before vrrp and bfd start */
	if (!open_bfd_pipes()) {
		thread_add_terminate_event(thread->master);
		return;
	}
#endif

#ifdef _WITH_LVS_
	/* start healthchecker child */
	if (running_checker()) {
		start_check_child();
		have_child = true;
		num_reloading++;
	}
#endif
#ifdef _WITH_VRRP_
	/* start vrrp child */
	if (running_vrrp()) {
		start_vrrp_child();
		have_child = true;
		num_reloading++;
	}
#endif
#ifdef _WITH_BFD_
	/* start bfd child */
	if (running_bfd()) {
		start_bfd_child();
		have_child = true;
		num_reloading++;
	}
#endif

#ifndef _ONE_PROCESS_DEBUG_
	/* Do we have a reload file to monitor */
	if (global_data->reload_time_file)
		start_reload_monitor();
#endif

	if (!have_child)
		log_message(LOG_INFO, "Warning - keepalived has no configuration to run");
}

static bool
handle_child_timeout(thread_ref_t thread, const char *type)
{
	pid_t pid;
	int sig_num;
	void *next_arg;
	unsigned timeout = 0;

	pid = THREAD_CHILD_PID(thread);

	if (thread->arg == (void *)0) {
		next_arg = (void *)1;
		sig_num = SIGTERM;
		timeout = 2;
		log_message(LOG_INFO, "%s timed out", type);
	} else if (thread->arg == (void *)1) {
		next_arg = (void *)2;
		sig_num = SIGKILL;
		timeout = 2;
	} else if (thread->arg == (void *)2) {
		log_message(LOG_INFO, "%s (PID %d) failed to terminate after kill", type, pid);
		next_arg = (void *)3;
		sig_num = SIGKILL;
		timeout = 10;	/* Give it longer to terminate */
	} else if (thread->arg == (void *)3) {
		/* We give up trying to kill the script */
		return true;
	}

	if (timeout) {
		/* If kill returns an error, we can't kill the process since either the process has terminated,
		 * or we don't have permission. If we can't kill it, there is no point trying again. */
		if (kill(-pid, sig_num)) {
			if (errno == ESRCH) {
				/* The process does not exist, and we should
				 * have reaped its exit status, otherwise it
				 * would exist as a zombie process. */
				log_message(LOG_INFO, "%s (PID %d) lost", type, pid);
				timeout = 0;
			} else {
				log_message(LOG_INFO, "kill -%d of %s (%d) with new state %p failed with errno %d", sig_num, type, pid, next_arg, errno);
				timeout = 1000;
			}
		}
	} else {
		log_message(LOG_INFO, "%s %d timeout with unknown script state %p", type, pid, thread->arg);
		next_arg = thread->arg;
		timeout = 10;	/* We need some timeout */
	}

	if (timeout)
		thread_add_child(thread->master, thread->func, next_arg, pid, timeout * TIMER_HZ);

	return false;
}

static bool
startup_shutdown_script_completed(thread_ref_t thread, bool startup)
{
	const char *type = startup ? "startup script" : "shutdown script";
	int wait_status;
	pid_t pid;

	if (thread->type == THREAD_CHILD_TIMEOUT)
		return handle_child_timeout(thread, type);

	wait_status = THREAD_CHILD_STATUS(thread);

	if (WIFEXITED(wait_status)) {
		unsigned status = WEXITSTATUS(wait_status);

		if (status)
			log_message(LOG_INFO, "%s script failed, status %u", type, status);
		else if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "%s script succeeded", type);
	}
	else if (WIFSIGNALED(wait_status)) {
		if (thread->arg == (void *)1 && WTERMSIG(wait_status) == SIGTERM) {
			/* The script terminated due to a SIGTERM, and we sent it a SIGTERM to
			 * terminate the process. Now make sure any children it created have
			 * died too. */
			pid = THREAD_CHILD_PID(thread);
			kill(-pid, SIGKILL);
		}
	}

	return true;
}

static void
startup_script_completed(thread_ref_t thread)
{
	if (startup_shutdown_script_completed(thread, true))
		thread_add_event(thread->master, start_keepalived, NULL, 0);
}

static void
shutdown_script_completed(thread_ref_t thread)
{
	if (startup_shutdown_script_completed(thread, false))
		thread_add_terminate_event(thread->master);
}

static void
run_startup_script(thread_ref_t thread)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Running startup script %s", global_data->startup_script->args[0]);

	if (system_call_script(thread->master, startup_script_completed, NULL, global_data->startup_script_timeout * TIMER_HZ, global_data->startup_script) == -1)
		log_message(LOG_INFO, "Call of startup script %s failed", global_data->startup_script->args[0]);
}

static void
validate_config(void)
{
#ifdef _WITH_VRRP_
	kernel_netlink_read_interfaces();
#endif

#ifdef _WITH_LVS_
	/* validate healthchecker config */
#ifndef _ONE_PROCESS_DEBUG_
	prog_type = PROG_TYPE_CHECKER;
#endif
	check_validate_config();
#endif
#ifdef _WITH_VRRP_
	/* validate vrrp config */
#ifndef _ONE_PROCESS_DEBUG_
	prog_type = PROG_TYPE_VRRP;
#endif
	vrrp_validate_config();
#endif
#ifdef _WITH_BFD_
	/* validate bfd config */
#ifndef _ONE_PROCESS_DEBUG_
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

static unsigned
check_start_stop_script_secure(notify_script_t **script, magic_t magic)
{
	unsigned flags;

	flags = check_script_secure(*script, magic);

	/* Mark not to run if needs inhibiting */
	if (flags & (SC_INHIBIT | SC_NOTFOUND) ||
	    !(flags & (SC_EXECUTABLE | SC_SYSTEM)))
		free_notify_script(script);

	return flags;
}

#ifndef _ONE_PROCESS_DEBUG_
static bool reload_config(void)
{
	bool unsupported_change = false;

	log_message(LOG_INFO, "Reloading ...");

	if (global_data->reload_time_file)
		stop_reload_monitor();

	/* Clear any config errors from previous loads */
	clear_config_status();

	/* Make sure there isn't an attempt to change the network namespace or instance name */
	old_global_data = global_data;
	global_data = NULL;
	global_data = alloc_global_data();

	/* If reload_check_config the process checking the config will read the config files,
	 * otherwise this process needs to. */
	read_config_file(!old_global_data->reload_check_config);

	init_global_data(global_data, old_global_data, false);

	if (override_namespace) {
		FREE_CONST_PTR(global_data->network_namespace);
		global_data->network_namespace = STRDUP(override_namespace);
	}

	if (!!old_global_data->network_namespace != !!global_data->network_namespace ||
	    (global_data->network_namespace && strcmp(old_global_data->network_namespace, global_data->network_namespace))) {
		log_message(LOG_INFO, "Cannot change network namespace at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}

	if (!!old_global_data->instance_name != !!global_data->instance_name ||
	    (global_data->instance_name && strcmp(old_global_data->instance_name, global_data->instance_name))) {
		log_message(LOG_INFO, "Cannot change instance name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}

#ifdef _WITH_NFTABLES_
#ifdef _WITH_VRRP_
	if (!!old_global_data->vrrp_nf_table_name != !!global_data->vrrp_nf_table_name ||
	    (global_data->vrrp_nf_table_name && strcmp(old_global_data->vrrp_nf_table_name, global_data->vrrp_nf_table_name))) {
		log_message(LOG_INFO, "Cannot change nftables table name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
#endif
#ifdef _WITH_LVS_
	if (!!old_global_data->ipvs_nf_table_name != !!global_data->ipvs_nf_table_name ||
	    (global_data->ipvs_nf_table_name && strcmp(old_global_data->ipvs_nf_table_name, global_data->ipvs_nf_table_name))) {
		log_message(LOG_INFO, "Cannot change IPVS nftables table name at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
#endif
#endif

	if (!!old_global_data->config_directory != !!global_data->config_directory ||
	    (global_data->config_directory && strcmp(old_global_data->config_directory, global_data->config_directory))) {
		log_message(LOG_INFO, "Cannot change config_directory at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}

#ifdef _WITH_VRRP_
	if (old_global_data->disable_local_igmp != global_data->disable_local_igmp) {
		log_message(LOG_INFO, "Cannot change disable_local_igmp at a reload - please restart %s", PACKAGE);
		unsupported_change = true;
	}
#endif

	if (unsupported_change) {
		/* We cannot reload the configuration, so continue with the old config */
		free_global_data (global_data);
		global_data = old_global_data;
	}
	else {
		/* Update process name if necessary */
		if (!global_data->process_name != !old_global_data->process_name ||
		    (global_data->process_name && strcmp(global_data->process_name, old_global_data->process_name)))
			set_process_name(global_data->process_name);

		free_global_data (old_global_data);
	}

	/* There is no point checking the script security of the
	 * startup script, since we won't run it after a reload.
	 */
	if (global_data->shutdown_script) {
		magic_t magic;
		unsigned script_flags;

		magic = ka_magic_open();

		script_flags = check_start_stop_script_secure(&global_data->shutdown_script, magic);

		if (magic)
			ka_magic_close(magic);

		if (!script_security && script_flags & SC_ISSCRIPT) {
			report_config_error(CONFIG_SECURITY_ERROR, "SECURITY VIOLATION - start/shutdown scripts are being executed but script_security not enabled.%s",
						script_flags & SC_INSECURE ? " There are insecure scripts." : "");
		}
	}

	if (global_data->reload_time_file)
		start_reload_monitor();

	return !unsupported_change;
}

static void
print_parent_data(__attribute__((unused)) thread_ref_t thread)
{
	FILE *fp;

	log_message(LOG_INFO, "Printing parent data for process(%d) on signal", getpid());

	fp = open_dump_file(dump_file);

	if (!fp)
		return;

	dump_global_data(fp, global_data);

	fclose(fp);
}

void
reinitialise_global_vars(void)
{
	default_script_uid = 0;
	default_script_gid = 0;
}

/* SIGHUP/USR1/USR2/STATS_CLEAR handler */
static void
propagate_signal(__attribute__((unused)) void *v, int sig)
{
	/* Signal child processes */
#ifdef _WITH_VRRP_
	if (vrrp_child > 0)
		kill(vrrp_child, sig);
	else if (sig == SIGHUP && running_vrrp())
		start_vrrp_child();
#endif

	/* Only the VRRP process consumes SIGUSR2 and SIGJSON */
	if (sig == SIGUSR2 || sig == SIGSTATS_CLEAR)
		return;
#ifdef _WITH_JSON_
	if (sig == SIGJSON)
		return;
#endif

#ifdef _WITH_LVS_
	if (checkers_child > 0)
		kill(checkers_child, sig);
	else if (running_checker())
		start_check_child();
#endif
#ifdef _WITH_BFD_
	if (bfd_child > 0)
		kill(bfd_child, sig);
	else if (running_bfd())
		start_bfd_child();
#endif

	if (sig == SIGUSR1)
		thread_add_event(master, print_parent_data, NULL, 0);
}

static void
do_reload(void)
{
	reinitialise_global_vars();

	if (!reload_config())
		return;

#ifdef _USE_SYSTEMD_NOTIFY_
	systemd_notify_reloading();
#endif

	propagate_signal(NULL, SIGHUP);

#ifdef _WITH_VRRP_
	if (vrrp_child > 0)
		num_reloading++;
#endif
#ifdef _WITH_LVS_
	if (checkers_child > 0)
		num_reloading++;
#endif
#ifdef _WITH_BFD_
	if (bfd_child > 0)
		num_reloading++;
#endif
}

static void
reload_check_child_thread(thread_ref_t thread)
{
	if (thread->type == THREAD_CHILD_TIMEOUT) {
		handle_child_timeout(thread, "config check");
		return;
	}

	/* The config files have been read now */
	remove_reload_file();

	if (WIFEXITED(thread->u.c.status)) {
		if (WEXITSTATUS(thread->u.c.status)) {
			log_message(LOG_INFO, "New config failed validation, see %s for details", global_data->reload_check_config);
			return;
		}

		do_reload();
	} else
		report_child_status(thread->u.c.status, thread->u.c.pid, "reload_check");
}

static void
start_validate_reload_conf_child(void)
{
	notify_script_t script;
	int i;
	int ret;
	int argc;
	const char **argv;
	char * const *sav_argv;
	char *config_test_str;
	char *config_fd_str = NULL;
	int fd;
	int len;
	char exe_buf[128];

	exe_buf[sizeof(exe_buf) - 1] = '\0';
	ret = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf));
	if (ret == -1) {
		/* How can this happen? What can we do? */
		log_message(LOG_INFO, "readlink(\"/proc/self/exe\" failed - errno %d - config-test aborted", errno);
		return;
	} else if (ret == sizeof(exe_buf))
		strcpy(exe_buf, "/proc/self/exe");
	else {
		exe_buf[ret] = '\0';
		len = strlen(exe_buf);
		/* If keepalived has been recompiled, the original file will
		 * be marked as deleted, but we can use the new one. */
		if (len > 10 && !strcmp(exe_buf + len - 10, " (deleted)"))
			exe_buf[len - 10] = '\0';
	}

	/* Inherits the original parameters and adds new parameters "--config-test and --config-fd" */
	sav_argv = get_cmd_line_options(&argc);
	argv = MALLOC((argc + 3) * sizeof(char *));

	argv[0] = exe_buf;

	/* copy old parameters */
	for (i = 1; i < argc; i++)
		argv[i] = sav_argv[i];

	/* add --config-test */
	config_test_str = MALLOC(14 + strlen(global_data->reload_check_config) + 1);
	strcpy(config_test_str, "--config-test=");
	strcat(config_test_str, global_data->reload_check_config);
	argv[argc++] = config_test_str;

	/* add --config-fd */
	if ((fd = get_config_fd()) != -1) {
		len = 13 + 6 + 1;	/* --config-fd=XXXXXX */
		config_fd_str = MALLOC(len);
		snprintf(config_fd_str, len, "--config-fd=%d", fd);
		argv[argc++] = config_fd_str;

		/* Allow fd to be inherited by exec'd process */
		if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) & ~FD_CLOEXEC) == -1)
			log_message(LOG_INFO, "fcntl() on config-test fd failed - errno %d", errno);
	}

	argv[argc] = NULL;

	script.args = argv;
	script.num_args = argc;
	script.flags = SC_EXECABLE;
	script.uid = 0;
	script.gid = 0;

	if (truncate(global_data->reload_check_config, 0) && errno != ENOENT)
		log_message(LOG_INFO, "truncate of config check log %s failed (%d) - %m", global_data->reload_check_config, errno);

	create_reload_file();

	/* Execute the script in a child process. Parent returns, child doesn't */
	ret = system_call_script(master, reload_check_child_thread,
				  NULL, 5 * TIMER_HZ, &script);

	if (ret)
		log_message(LOG_INFO, "Could not run config-test");

	/* Restore CLOEXEC on config_copy fd */
	/* coverity[check_return] - what are we going to do if this fails? */
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	FREE(argv);
	FREE(config_test_str);
	FREE_PTR(config_fd_str);
}

void
start_reload(thread_ref_t thread)
{
	if (thread && __test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Processing queued reload");

	/* if reload_check_config is configured, validate the new config before reload */
	if (!global_data->reload_check_config) {
		do_reload();
		return;
	}

	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "validate conf before Reload");

	start_validate_reload_conf_child();
}

static void
process_reload_signal(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	if (!num_reloading)
		start_reload(NULL);
	else
		queue_reload();
}

#endif

#ifdef THREAD_DUMP
void
thread_dump_signal(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
#ifndef _ONE_PROCESS_DEBUG_
	if (prog_type == PROG_TYPE_PARENT)
		propagate_signal(NULL, sig);
#endif

	dump_thread_data(master, NULL);
}
#endif

#ifndef _ONE_PROCESS_DEBUG_
/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	int ret;
	int wait_count = 0;
	struct timeval start_time, now;
	size_t i;
	int wstatus;
	int timeout = child_wait_time * 1000;
	int signal_fd = master->signal_fd;
	struct signalfd_siginfo siginfo;
	sigset_t sigmask;
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = master->signal_fd };
	int efd;

	log_message(LOG_INFO, "Stopping");

#ifdef _USE_SYSTEMD_NOTIFY_
	systemd_notify_stopping();
#endif

#ifndef _ONE_PROCESS_DEBUG_
	if (global_data->reload_time_file)
		stop_reload_monitor();
#endif

	/* We only want to receive SIGCHLD now */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	signalfd(signal_fd, &sigmask, 0);

	/* Signal our children to terminate */
	for (i = 0; i < NUM_CHILD_TERM; i++) {
		if (*children_term[i].pid_p > 0) {
			if (kill(*children_term[i].pid_p, SIGTERM)) {
				/* ESRCH means no such process */
				if (errno == ESRCH)
					*children_term[i].pid_p = 0;
			}
			else
				wait_count++;
		}
	}

	efd = epoll_create(1);
	epoll_ctl(efd, EPOLL_CTL_ADD, signal_fd, &ev);

	gettimeofday(&start_time, NULL);
	while (wait_count) {
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

		/* We are only expecting SIGCHLD */
		if (siginfo.ssi_signo != SIGCHLD) {
			log_message(LOG_INFO, "Received signal %u code %d status %d from pid %u"
					      " while waiting for children to terminate"
					    , siginfo.ssi_signo, siginfo.ssi_code
					    , siginfo.ssi_status, siginfo.ssi_pid);
			continue;
		}

		if (siginfo.ssi_code != CLD_EXITED &&
		    siginfo.ssi_code != CLD_KILLED &&
		    siginfo.ssi_code != CLD_DUMPED) {
			/* CLD_STOPPED, CLD_CONTINUED or CLD_TRAPPED */
			log_message(LOG_INFO, "Received SIGCHLD code %d status %d from pid %u"
					      " while waiting for children to terminate"
					    , siginfo.ssi_code, siginfo.ssi_status, siginfo.ssi_pid);
			continue;
		}

		for (i = 0; i < NUM_CHILD_TERM && wait_count; i++) {
			if (*children_term[i].pid_p > 0 && *children_term[i].pid_p == (pid_t)siginfo.ssi_pid) {
				ret = waitpid(*children_term[i].pid_p, &wstatus, WNOHANG);
				if (ret == 0)
					continue;
				if (ret == -1) {
					if (!check_EINTR(errno))
						log_message(LOG_INFO, "Wait for %s child return errno %d"
								    , children_term[i].short_name, errno);
					continue;
				}

				report_child_status(wstatus, *children_term[i].pid_p, children_term[i].name);

				/* We could check ret == *children_term[i].pid_p, but it seems unneccessary */
				*children_term[i].pid_p = 0;
				wait_count--;

				break;
			}
		}

		if (wait_count) {
			gettimeofday(&now, NULL);
			timeout = (child_wait_time - (now.tv_sec - start_time.tv_sec)) * 1000 + (start_time.tv_usec - now.tv_usec) / 1000;
			if (timeout < 0)
				break;
		}
	}
	close(efd);

	/* A child may not have terminated, so force its termination */
	for (i = 0; i < NUM_CHILD_TERM; i++) {
		if (*children_term[i].pid_p) {
			log_message(LOG_INFO, "%s process failed to die - forcing termination"
					    , children_term[i].short_name);
			kill(*children_term[i].pid_p, SIGKILL);
		}
	}

	if (!global_data->shutdown_script) {
		/* register the terminate thread */
		thread_add_terminate_event(master);
	} else {
		/* If we have a shutdown script, run it now */
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Running shutdown script %s"
					    , global_data->shutdown_script->args[0]);

		if (system_call_script(master, shutdown_script_completed, NULL
					     , global_data->shutdown_script_timeout * TIMER_HZ
					     , global_data->shutdown_script) == -1)
			log_message(LOG_INFO, "Call of shutdown script %s failed"
					    , global_data->shutdown_script->args[0]);
	}
}
#endif

/* Initialize signal handler */
static void
signal_init(void)
{
#ifndef _ONE_PROCESS_DEBUG_
	signal_set(SIGHUP, process_reload_signal, NULL);
	signal_set(SIGUSR1, propagate_signal, NULL);
	signal_set(SIGUSR2, propagate_signal, NULL);
	signal_set(SIGSTATS_CLEAR, propagate_signal, NULL);
#ifdef _WITH_JSON_
	signal_set(SIGJSON, propagate_signal, NULL);
#endif
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
#ifdef THREAD_DUMP
	signal_set(SIGTDUMP, thread_dump_signal, NULL);
#endif
#endif
	signal_ignore(SIGPIPE);
}

static void
signals_ignore(void) {
#ifndef _ONE_PROCESS_DEBUG_
	signal_ignore(SIGHUP);
	signal_ignore(SIGUSR1);
	signal_ignore(SIGUSR2);
	signal_ignore(SIGSTATS_CLEAR);
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
#if defined WITH_DEBUG_OPTIONS && !defined _ONE_PROCESS_DEBUG_
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
#ifdef _SMTP_CONNECT_DEBUG_
	do_smtp_connect_debug = !!(smtp_connect_debug & mask);
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
#ifdef _CHECKSUM_DEBUG_
	do_checksum_debug = !!(checksum_debug & mask);
#endif
#ifdef _WITH_TRACK_PROCESS_
#ifdef _TRACK_PROCESS_DEBUG_
	do_track_process_debug_detail = !!(track_process_debug_detail & mask);
	do_track_process_debug = !!(track_process_debug & mask) | do_track_process_debug_detail;
#endif
#endif
#ifdef _PARSER_DEBUG_
	do_parser_debug = !!(parser_debug & mask);
#endif
#ifdef _CHECKER_DEBUG_
	do_checker_debug = !!(checker_debug & mask);
#endif
#ifdef _MEM_ERR_DEBUG_
	do_mem_err_debug = !!(mem_err_debug & mask);
#endif
#ifdef _RECVMSG_DEBUG_
	do_recvmsg_debug = !!(recvmsg_debug & mask);
	do_recvmsg_debug_dump = !!(recvmsg_debug_dump & mask);
#endif
#ifdef _EINTR_DEBUG_
	do_eintr_debug = !!(eintr_debug & mask);
#endif
#ifdef _SCRIPT_DEBUG_
	do_script_debug = !!(script_debug & mask);
#endif
#ifdef _DUMP_KEYWORDS_
	do_dump_keywords = !!(dump_keywords & mask);
#endif
#endif
}
RELAX_END

#ifdef  WITH_DEBUG_OPTIONS
static void
set_debug_options(const char *options)
{
	char all_processes, processes;
	char opt;
	const char *opt_p = options;

#ifdef _ONE_PROCESS_DEBUG_
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
#ifdef _SMTP_CONNECT_DEBUG_
		smtp_connect_debug = all_processes;
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
#ifdef _CHECKSUM_DEBUG_
		checksum_debug = all_processes;
#endif
#ifdef _TRACK_PROCESS_DEBUG_
		track_process_debug = all_processes;
		track_process_debug_detail = all_processes;
#endif
#ifdef _PARSER_DEBUG_
		parser_debug = all_processes;
#endif
#ifdef _CHECKER_DEBUG_
		checker_debug = all_processes;
#endif
#ifdef _MEM_ERR_DEBUG_
		mem_err_debug = all_processes;
#endif
#ifdef _RECVMSG_DEBUG_
		recvmsg_debug = all_processes;
		recvmsg_debug_dump = all_processes;
#endif
#ifdef _EINTR_DEBUG_
		eintr_debug = all_processes;
#endif
#ifdef _SCRIPT_DEBUG_
		script_debug = all_processes;
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

#ifdef _ONE_PROCESS_DEBUG_
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

		/* Letters used - ABCDEFGHIJKMNOPRSTUVXZ */
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
#ifdef _SMTP_CONNECT_DEBUG_
		case 'B':
			smtp_connect_debug = processes;
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
#ifdef _CHECKSUM_DEBUG_
		case 'U':
			checksum_debug = processes;
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
#ifdef _CHECKER_DEBUG_
		case 'H':
			checker_debug = processes;
			break;
#endif
#ifdef _MEM_ERR_DEBUG_
		case 'Z':
			mem_err_debug = processes;
			break;
#endif
#ifdef _RECVMSG_DEBUG_
		case 'G':
			recvmsg_debug = processes;
			break;
		case 'J':
			recvmsg_debug_dump = processes;
			break;
#endif
#ifdef _EINTR_DEBUG_
		case 'I':
			eintr_debug = processes;
			break;
#endif
#ifdef _SCRIPT_DEBUG_
		case 'V':
			script_debug = processes;
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

static void
report_distro(void)
{
	FILE *fp = fopen("/etc/os-release", "r");
	char buf[128];
	const char * const var = "PRETTY_NAME=";
	const size_t var_len = strlen(var);
	char *distro_name;
	size_t distro_len;

	if (!fp)
		return;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, var, var_len)) {
			distro_name = buf + var_len;

			/* Remove "'s and trailing \n */
			if (*distro_name == '"')
				distro_name++;
			distro_len = strlen(distro_name);
			if (distro_len && distro_name[distro_len - 1] == '\n')
				distro_name[--distro_len] = '\0';
			if (distro_len && distro_name[distro_len - 1] == '"')
				distro_name[--distro_len] = '\0';

			fprintf(stderr, "Distro: %s\n", distro_name);
			break;
		}
	}

	fclose(fp);
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
#ifdef ENABLE_LOG_TO_FILE
	fprintf(stderr, "  -g, --log-file=FILE          Also log to FILE (default " KA_TMP_DIR "/keepalived.log)\n");
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
	fprintf(stderr, "  -T, --genhash                Enter into genhash utility mode (this should be the first option used).\n");
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
	fprintf(stderr, "  -s, --namespace=NAME         Run in network namespace NAME (overrides config)\n");
	fprintf(stderr, "  -m, --core-dump              Produce core dump if terminate abnormally\n");
	fprintf(stderr, "  -M, --core-dump-pattern=PATN Also set /proc/sys/kernel/core_pattern to PATN (default 'core')\n");
#ifdef _MEM_CHECK_
	fprintf(stderr, "      --no-mem-check           disable malloc() etc mem-checks\n");
#endif
#ifdef _MEM_CHECK_LOG_
	fprintf(stderr, "  -L, --mem-check-log          Log malloc/frees to syslog\n");
#endif
	fprintf(stderr, "  -e, --all-config             Error if any configuration file missing (same as includet)\n");
	fprintf(stderr, "  -i, --config-id id           Skip any configuration lines beginning '@' that don't match id\n"
			"                                or any lines beginning @^ that do match.\n"
			"                                The config-id defaults to the node name if option not used\n");
	fprintf(stderr, "      --signum=SIGFUNC         Return signal number for STOP, RELOAD, DATA, STATS, STATS_CLEAR"
#ifdef _WITH_JSON_
								", JSON"
#endif
#ifdef THREAD_DUMP
								", TDUMP"
#endif
								"\n");
	fprintf(stderr, "  -t, --config-test[=LOG_FILE] Check the configuration for obvious errors, output to\n"
			"                                stderr by default\n");
/*	fprintf(stderr, "      --config-fd=fd_num       File descriptor to write consolidated config to\n");	*/ // Internal use only
#ifdef _WITH_PERF_
	fprintf(stderr, "      --perf[=PERF_TYPE]       Collect perf data, PERF_TYPE=all, run(default) or end\n");
#endif
#ifdef WITH_DEBUG_OPTIONS
	fprintf(stderr, "      --debug[=...]            Enable debug options. p, b, c, v specify parent, bfd, checker and vrrp processes\n");
	fprintf(stderr, "                                If no process(es) specified, the option will apply to all processes\n");
#ifdef _TIMER_CHECK_
	fprintf(stderr, "                                   T - timer debug\n");
#endif
#ifdef _SMTP_ALERT_DEBUG_
	fprintf(stderr, "                                   M - email alert debug\n");
#endif
#ifdef _SMTP_CONNECT_DEBUG_
	fprintf(stderr, "                                   B - smtp connect debug\n");
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
#ifdef _CHECKSUM_DEBUG_
	fprintf(stderr, "                                   U - checksum diagnostics\n");
#endif
#ifdef _TRACK_PROCESS_DEBUG_
	fprintf(stderr, "                                   O - track process debug\n");
	fprintf(stderr, "                                   A - track process debug with extra detail\n");
#endif
#ifdef _PARSER_DEBUG_
	fprintf(stderr, "                                   C - parser (config) debug\n");
#endif
#ifdef _CHECKER_DEBUG_
	fprintf(stderr, "                                   H - checker debug\n");
#endif
#ifdef _MEM_ERR_DEBUG_
	fprintf(stderr, "                                   Z - memory alloc/free error debug\n");
#endif
#ifdef _RECVMSG_DEBUG_
	fprintf(stderr, "                                   G - VRRP recvmsg() debug\n");
	fprintf(stderr, "                                   J - VRRP recvmsg() log rx data\n");
#endif
#ifdef _EINTR_DEBUG_
	fprintf(stderr, "                                   I - EINTR debugging\n");
#endif
#ifdef _SCRIPT_DEBUG_
	fprintf(stderr, "                                   V - script debugging\n");
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
	unsigned i;
#ifdef _WITH_LVS_
	bool first_option;
#endif

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
		{"all-config",		no_argument,		NULL, 'e'},
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
		{"genhash",		no_argument,		NULL, 'T'},
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
#ifdef _MEM_CHECK_
		{"no-mem-check",	no_argument,		NULL,  7 },
#endif
#ifdef _MEM_CHECK_LOG_
		{"mem-check-log",	no_argument,		NULL, 'L'},
#endif
		{"namespace",		required_argument,	NULL, 's'},
		{"config-id",		required_argument,	NULL, 'i'},
		{"signum",		required_argument,	NULL,  4 },
		{"config-test",		optional_argument,	NULL, 't'},
		{"config-fd",		required_argument,	NULL,  8 },
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
#ifdef _WITH_LVS_
	first_option = true;
#endif

	/* Used short options: ABCDGILMPRSVXabcdefghilmnprstuvx */
	while (longindex = -1, (c = getopt_long(argc, argv, ":vhlndu:DRS:f:p:i:es:mM::g::Gt::"
#if defined _WITH_VRRP_ && defined _WITH_LVS_
					    "PC"
#endif
#ifdef _WITH_VRRP_
					    "r:VX"
#endif
#ifdef _WITH_LVS_
					    "ac:IT"
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
			fprintf(stderr, "Running on %s %s %s\n", uname_buf.sysname, uname_buf.release, uname_buf.version);
			report_distro();
			fprintf(stderr, "\n");
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
		case 'T':
			if (!first_option)
				fprintf(stderr, "Warning -- `%s` not used as first option, previous options ignored\n", longindex == -1 ? "-T" : long_options[longindex].name);

			/* Set our process name */
			prctl(PR_SET_NAME, "genhash");

			check_genhash(false, argc, argv);
			exit(0);
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
			if (read_unsigned(optarg, &facility, 0, LOG_FACILITY_MAX, false) ||
			    (!strncmp(optarg, "local", 5) &&
			     read_unsigned(&optarg[5], &facility, 0, LOG_FACILITY_MAX, false))) {
				log_facility = LOG_FACILITY[facility].facility;
				reopen_log = true;
			} else {
				for (i = 0; i < sizeof(facility_names) / sizeof(facility_names[0]); i++) {
					if (!strcmp(optarg, facility_names[i].name)) {
						log_facility = facility_names[i].facility;
						reopen_log = true;
						break;
					}
				}

				if (!reopen_log)
					fprintf(stderr, "Invalid log facility '%s'\n", optarg);
			}
			break;
		case 'g':
#ifdef ENABLE_LOG_TO_FILE
			if (optarg && optarg[0])
				log_file_name = optarg;
			else
				log_file_name = KA_TMP_DIR "/keepalived.log";
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
			/* coverity[var_deref_model] */
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
					fprintf(stderr, "Unable to open config-test log file %s %d - %m\n", optarg, errno);
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
		case 's':
			override_namespace = optarg;
			break;
		case 'e':
			include_check_set(NULL);
			break;
		case 'i':
			FREE_CONST_PTR(config_id);
			config_id = STRDUP(optarg);
			break;
		case 4:			/* --signum */
			/* coverity[var_deref_model] */
			signum = get_signum(optarg);
			if (signum == -1) {
				fprintf(stderr, "Unknown sigfunc %s\n", optarg);
				exit(1);
			}

			/* If we want to print the signal description, strsignal(signum) can be used */
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
#ifdef _MEM_CHECK_
		case 7:
			__clear_bit(MEM_CHECK_BIT, &debug);
			break;
#endif
		case 8:
			set_config_fd(atoi(optarg));
			break;
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
#ifdef _WITH_LVS_
		first_option = false;
#endif
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (bad_option)
		exit(1);

#ifdef _MEM_CHECK_
	if (__test_bit(CONFIG_TEST_BIT, &debug))
		__clear_bit(MEM_CHECK_BIT, &debug);
#endif

	return reopen_log;
}

#ifdef THREAD_DUMP
static void
register_parent_thread_addresses(void)
{
	register_scheduler_addresses();
	register_signal_thread_addresses();
#ifndef _ONE_PROCESS_DEBUG_
	register_config_notify_addresses();
#endif

#ifdef _WITH_LVS_
	register_check_parent_addresses();
#endif
#ifdef _WITH_VRRP_
	register_vrrp_parent_addresses();
#endif
#ifdef _WITH_BFD_
	register_bfd_parent_addresses();
#endif

#ifndef _ONE_PROCESS_DEBUG_
	register_reload_addresses();
	register_signal_handler_address("propagate_signal", propagate_signal);
	register_signal_handler_address("sigend", sigend);
#endif
	register_signal_handler_address("thread_child_handler", thread_child_handler);
#ifdef THREAD_DUMP
	register_signal_handler_address("thread_dump_signal", thread_dump_signal);
#endif

	register_thread_address("start_keepalived", start_keepalived);
	register_thread_address("startup_script_completed", startup_script_completed);
	register_thread_address("shutdown_script_completed", shutdown_script_completed);
	register_thread_address("run_startup_script", run_startup_script);
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
	magic_t magic;
	unsigned script_flags;
	struct rusage usage;
	struct rusage child_usage;

#ifdef _WITH_LVS_
	char *name = strrchr(argv[0], '/');
	if (!strcmp(name ? name + 1 : argv[0], "genhash")) {
		check_genhash(true, argc, argv);
		/* Not reached */
	}
#endif

#ifdef _MEM_CHECK_
	__set_bit(MEM_CHECK_BIT, &debug);
#endif

	/* Ignore reloading signals till signal_init call */
	signals_ignore();

	/* Ensure time_now is set. We then don't have to check anywhere
	 * else if it is set. */
	set_time_now();

	/* Save command line options in case need to log them later */
	save_cmd_line_options(argc, argv);

#ifdef _USE_SYSTEMD_NOTIFY_
#ifndef _ONE_PROCESS_DEBUG_
	check_parent_systemd();
#endif
#endif

	/* We are the parent process */
#ifndef _ONE_PROCESS_DEBUG_
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
	open_syslog(PACKAGE_NAME);

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
			open_syslog(PACKAGE_NAME);
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
			/* keepalived was built for a later kernel version */
			log_message(LOG_INFO, "WARNING - keepalived was built for newer Linux %d.%d.%d, running on %s %s %s",
					(LINUX_VERSION_CODE >> 16) & 0xff,
					(LINUX_VERSION_CODE >>  8) & 0xff,
					(LINUX_VERSION_CODE      ) & 0xff,
					uname_buf.sysname, uname_buf.release, uname_buf.version);
		} else {
			/* keepalived was built for a later kernel version */
			log_message(LOG_INFO, "Running on %s %s %s (built for Linux %d.%d.%d)",
					uname_buf.sysname, uname_buf.release, uname_buf.version,
					(LINUX_VERSION_CODE >> 16) & 0xff,
					(LINUX_VERSION_CODE >>  8) & 0xff,
					(LINUX_VERSION_CODE      ) & 0xff);
		}
	}

	log_command_line(0);

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

// Change here so don't need check_conf_file()
	read_config_file(true);

	if (had_config_file_error()) {
		exit_code = KEEPALIVED_EXIT_NO_CONFIG;
		goto end;
	}

	init_global_data(global_data, NULL, false);

#if defined _WITH_VRRP_ && defined  _WITH_NFTABLES_
	if (global_data->vrrp_nf_table_name)
		set_nf_ifname_type();
#endif

	/* Update process name if necessary */
	if (global_data->process_name)
		set_process_name(global_data->process_name);

	if (override_namespace) {
		if (global_data->network_namespace) {
			log_message(LOG_INFO, "Overriding config net_namespace '%s' with command line namespace '%s'", global_data->network_namespace, override_namespace);
			FREE_CONST(global_data->network_namespace);
		}
		global_data->network_namespace = STRDUP(override_namespace);
	}

	if (!__test_bit(CONFIG_TEST_BIT, &debug) &&
	    (global_data->instance_name || global_data->network_namespace)) {
		if ((syslog_ident = make_syslog_ident(PACKAGE_NAME))) {
			log_message(LOG_INFO, "Changing syslog ident to %s", syslog_ident);
			closelog();
			open_syslog(syslog_ident);
		}
		else
			log_message(LOG_INFO, "Unable to change syslog ident");

		use_pid_dir = true;

#ifdef ENABLE_LOG_TO_FILE
		open_log_file(log_file_name,
				NULL,
				global_data->network_namespace,
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

		/* If we want to monitor processes, we have to do it before calling
		 * setns() */
#ifdef _WITH_TRACK_PROCESS_
		open_track_processes();
#endif
	}

	if (global_data->network_namespace) {
		if (global_data->network_namespace && !set_namespaces(global_data->network_namespace)) {
			log_message(LOG_ERR, "Unable to set network namespace %s - exiting", global_data->network_namespace);
			goto end;
		}
	}

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
			if (!bfd_pidfile && (bfd_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR BFD_PID_FILE, global_data->instance_name, PID_EXTENSION)))
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
				main_pidfile = RUN_DIR KEEPALIVED_PID_FILE PID_EXTENSION;
#ifdef _WITH_LVS_
			if (!checkers_pidfile)
				checkers_pidfile = RUN_DIR CHECKERS_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_VRRP_
			if (!vrrp_pidfile)
				vrrp_pidfile = RUN_DIR VRRP_PID_FILE PID_EXTENSION;
#endif
#ifdef _WITH_BFD_
			if (!bfd_pidfile)
				bfd_pidfile = RUN_DIR BFD_PID_FILE PID_EXTENSION;
#endif
		}

#ifndef _ONE_PROCESS_DEBUG_
		/* We have set the namespaces, so we can do this now */
		remove_reload_file();
#endif

		/* Check if keepalived is already running */
		if (keepalived_running(daemon_mode)) {
			log_message(LOG_INFO, "daemon is already running");
			report_stopped = false;
			goto end;
		}
	}

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug) && xdaemon() > 0) {
		closelog();
		FREE_CONST_PTR(config_id);
		FREE_PTR(orig_core_dump_pattern);
		close_std_fd();
		exit(0);
	}

#ifdef _MEM_CHECK_
	enable_mem_log_termination();
#endif

	if (global_data->startup_script || global_data->shutdown_script) {
		magic = ka_magic_open();
		script_flags = 0;
		if (global_data->startup_script)
			script_flags |= check_start_stop_script_secure(&global_data->startup_script, magic);
		if (global_data->shutdown_script)
			script_flags |= check_start_stop_script_secure(&global_data->shutdown_script, magic);

		if (magic)
			ka_magic_close(magic);

		if (!script_security && script_flags & SC_ISSCRIPT) {
			report_config_error(CONFIG_SECURITY_ERROR, "SECURITY VIOLATION - start/shutdown scripts are being executed but script_security not enabled.%s",
						script_flags & SC_INSECURE ? " There are insecure scripts." : "");
		}
	}

	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		validate_config();
		config_test_exit();
	}

	/* write the father's pidfile */
	if (!pidfile_write(main_pidfile, getpid()))
		goto end;

	if (!global_data->max_auto_priority)
		log_message(LOG_INFO, "NOTICE: setting config option max_auto_priority should result in better keepalived performance");

	/* Create the master thread */
	master = thread_make_master();

	/* Signal handling initialization  */
	signal_init();

#ifndef _ONE_PROCESS_DEBUG_
	/* Open eventfd for children notifying parent that they have read the configuration file */
	if (!__test_bit(CONFIG_TEST_BIT, &debug))
		open_config_read_fd();
#endif

	/* If we have a startup script, run it first */
	if (global_data->startup_script) {
		thread_add_event(master, run_startup_script, NULL, 0);
	} else {
		/* Init daemon */
		thread_add_event(master, start_keepalived, NULL, 0);
	}

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
		if (__test_bit(LOG_DETAIL_BIT, &debug)) {
			getrusage(RUSAGE_SELF, &usage);
			getrusage(RUSAGE_CHILDREN, &child_usage);

			log_message(LOG_INFO, "CPU usage (self/children) user: %ld.%6.6ld/%ld.%6.6ld system: %ld.%6.6ld/%ld.%6.6ld",
					usage.ru_utime.tv_sec, usage.ru_utime.tv_usec, child_usage.ru_utime.tv_sec, child_usage.ru_utime.tv_usec,
					usage.ru_stime.tv_sec, usage.ru_stime.tv_usec, child_usage.ru_stime.tv_sec, child_usage.ru_stime.tv_usec);
		}

#ifdef GIT_COMMIT
		log_message(LOG_INFO, "Stopped %s, git commit %s", version_string, GIT_COMMIT);
#else
		log_message(LOG_INFO, "Stopped %s", version_string);
#endif
	}

	if (global_data && global_data->network_namespace)
		clear_namespaces();

	if (use_pid_dir)
		remove_pid_dir();

	/* Restore original core_pattern if necessary */
	if (orig_core_dump_pattern)
		update_core_dump_pattern(orig_core_dump_pattern);

	free_parent_mallocs_startup(false);
	free_parent_mallocs_exit();
	free_global_data(global_data);

	closelog();

#ifdef _MEM_CHECK_LOG_
	if (syslog_ident)
		free(no_const_char_p(syslog_ident));	/* malloc'd in make_syslog_ident */
#else
	FREE_CONST_PTR(syslog_ident);
#endif
	close_std_fd();

	return exit_code;
}
