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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include "git-commit.h"

#include <stdlib.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <stdbool.h>

#include "main.h"
#include "config.h"
#include "signals.h"
#include "pidfile.h"
#include "bitops.h"
#include "logger.h"
#include "parser.h"
#include "notify.h"
#include "check_parser.h"
#include "vrrp_parser.h"
#include "global_parser.h"
#if HAVE_DECL_CLONE_NEWNET
#include "namespaces.h"
#endif
#include "vrrp_netlink.h"

#define	LOG_FACILITY_MAX	7
#define	VERSION_STRING		PACKAGE_NAME " v" PACKAGE_VERSION " (" VERSION_DATE ")"
#define COPYRIGHT_STRING	"Copyright(C) 2001-" COPYRIGHT_YEAR " Alexandre Cassen, <acassen@gmail.com>"
#define BUILD_OPTIONS		CONFIGURATION_OPTIONS

#define CHILD_WAIT_SECS	5

/* global var */
const char *version_string = VERSION_STRING;		/* keepalived version */
char *conf_file = KEEPALIVED_CONFIG_FILE;		/* Configuration file */
int log_facility = LOG_DAEMON;				/* Optional logging facilities */
char *main_pidfile;					/* overrule default pidfile */
static bool free_main_pidfile;
#ifdef _WITH_LVS_
pid_t checkers_child = -1;				/* Healthcheckers child process ID */
char *checkers_pidfile;					/* overrule default pidfile */
static bool free_checkers_pidfile;
#endif
#ifdef _WITH_VRRP_
pid_t vrrp_child = -1;					/* VRRP child process ID */
char *vrrp_pidfile;					/* overrule default pidfile */
static bool free_vrrp_pidfile;
#endif
unsigned long daemon_mode;				/* VRRP/CHECK subsystem selection */
#ifdef _WITH_SNMP_
bool snmp;						/* Enable SNMP support */
const char *snmp_socket;				/* Socket to use for SNMP agent */
#endif
static char *syslog_ident;				/* syslog ident if not default */
char *instance_name;					/* keepalived instance name */
bool use_pid_dir;					/* Put pid files in /var/run/keepalived */
size_t getpwnam_buf_len;				/* Buffer length needed for getpwnam_r/getgrname_r */
uid_t default_script_uid;				/* Default user/group for script execution */
gid_t default_script_gid;
unsigned os_major;					/* Kernel version */
unsigned os_minor;
unsigned os_release;

#if HAVE_DECL_CLONE_NEWNET
char *network_namespace;				/* The network namespace we are running in */
bool namespace_with_ipsets;				/* Override for using namespaces and ipsets with Linux < 3.13 */
static char *override_namespace;			/* If namespace specified on command line */
#endif

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
	}

	if (free_main_pidfile) {
		FREE_PTR(main_pidfile);
		free_main_pidfile = false;
	}
}

void
free_parent_mallocs_exit(void)
{
#if HAVE_DECL_CLONE_NEWNET
	FREE_PTR(network_namespace);
#endif

#ifdef _WITH_VRRP_
	if (free_vrrp_pidfile)
		FREE_PTR(vrrp_pidfile);
#endif
#ifdef _WITH_LVS_
	if (free_checkers_pidfile)
		FREE_PTR(checkers_pidfile);
#endif

	FREE_PTR(instance_name);
}

char *
make_syslog_ident(const char* name)
{
	size_t ident_len = strlen(name) + 1;
	char *ident;

#if HAVE_DECL_CLONE_NEWNET
	if (network_namespace)
		ident_len += strlen(network_namespace) + 1;
#endif
	if (instance_name)
		ident_len += strlen(instance_name) + 1;

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
	if (network_namespace) {
		strcat(ident, "_");
			strcat(ident, network_namespace);
		}
#endif
	if (instance_name) {
		strcat(ident, "_");
		strcat(ident, instance_name);
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

static bool
find_keepalived_child(pid_t pid, char const **prog_name)
{
#ifdef _WITH_LVS_
	if (pid == checkers_child) {
		*prog_name = PROG_CHECK;
		return true;
	}
#endif
#ifdef _WITH_VRRP_
	if (pid == vrrp_child) {
		*prog_name = PROG_VRRP;
		return true;
	}
#endif
	return false;
}

#if HAVE_DECL_CLONE_NEWNET
static vector_t *
global_init_keywords(void)
{
	/* global definitions mapping */
	init_global_keywords(false);

#ifdef _WITH_VRRP_
	init_vrrp_keywords(false);
#endif
#ifdef _WITH_LVS_
	init_check_keywords(false);
#endif

	return keywords;
}

static void
read_config_file(void)
{
	init_data(conf_file, global_init_keywords);
}
#endif

/* Daemon stop sequence */
static void
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

	pidfile_rm(main_pidfile);
#endif
}

/* Daemon init sequence */
static void
start_keepalived(void)
{
#ifdef _WITH_LVS_
	/* start healthchecker child */
	if (__test_bit(DAEMON_CHECKERS, &daemon_mode))
		start_check_child();
#endif
#ifdef _WITH_VRRP_
	/* start vrrp child */
	if (__test_bit(DAEMON_VRRP, &daemon_mode))
		start_vrrp_child();
#endif
}

/* SIGHUP/USR1/USR2 handler */
#ifndef _DEBUG_
static void
propogate_signal(__attribute__((unused)) void *v, int sig)
{
	bool unsupported_change = false;

	if (sig == SIGHUP) {
		/* Make sure there isn't an attempt to change the network namespace or instance name */
#if HAVE_DECL_CLONE_NEWNET
		char *old_network_namespace = network_namespace;
		network_namespace = NULL;
#endif
		char *old_instance_name = instance_name;
		instance_name = NULL;

		/* The only parameters handled are net_namespace and instance_name */
		read_config_file();

#if HAVE_DECL_CLONE_NEWNET
		if (!!old_network_namespace != !!network_namespace ||
		    (network_namespace && strcmp(old_network_namespace, network_namespace))) {
			log_message(LOG_INFO, "Cannot change network namespace at a reload - please restart %s", PACKAGE);
			unsupported_change = true;
		}
		FREE_PTR(network_namespace);
		network_namespace = old_network_namespace;
#endif

		if (!!old_instance_name != !!instance_name ||
		    (instance_name && strcmp(old_instance_name, instance_name))) {
			log_message(LOG_INFO, "Cannot change instance name at a reload - please restart %s", PACKAGE);
			unsupported_change = true;
		}
		FREE_PTR(instance_name);
		instance_name = old_instance_name;

		if (unsupported_change)
			return;
	}

	/* Signal child process */
#ifdef _WITH_VRRP_
	if (vrrp_child > 0)
		kill(vrrp_child, sig);
#endif
#ifdef _WITH_LVS_
	if (checkers_child > 0 && sig == SIGHUP)
		kill(checkers_child, sig);
#endif
}

/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	int status;
	int ret;
	int wait_count = 0;
	sigset_t old_set, child_wait;
	struct timespec timeout = {
		.tv_sec = CHILD_WAIT_SECS,
		.tv_nsec = 0
	};
	struct timeval start_time, now;

	/* register the terminate thread */
	thread_add_terminate_event(master);

	log_message(LOG_INFO, "Stopping");
	sigprocmask(0, NULL, &old_set);
	if (!sigismember(&old_set, SIGCHLD)) {
		sigemptyset(&child_wait);
		sigaddset(&child_wait, SIGCHLD);
		sigprocmask(SIG_BLOCK, &child_wait, NULL);
	}

#ifdef _WITH_VRRP_
	if (vrrp_child > 0) {
		kill(vrrp_child, SIGTERM);
		wait_count++;
	}
#endif
#ifdef _WITH_LVS_
	if (checkers_child > 0) {
		kill(checkers_child, SIGTERM);
		wait_count++;
	}
#endif

	gettimeofday(&start_time, NULL);
	while (wait_count) {
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
			wait_count--;
		}
#endif

#ifdef _WITH_LVS_
		if (checkers_child > 0 && checkers_child == waitpid(checkers_child, &status, WNOHANG)) {
			report_child_status(status, checkers_child, PROG_CHECK);
			wait_count--;
		}
#endif

		if (wait_count) {
			gettimeofday(&now, NULL);
			if (now.tv_usec < start_time.tv_usec) {
				timeout.tv_nsec = (start_time.tv_usec - now.tv_usec) * 1000;
				timeout.tv_sec = CHILD_WAIT_SECS - (now.tv_sec - start_time.tv_sec);
			} else if (now.tv_usec == start_time.tv_usec) {
				timeout.tv_nsec = 0;
				timeout.tv_sec = CHILD_WAIT_SECS - (now.tv_sec - start_time.tv_sec);
			} else {
				timeout.tv_nsec = (1000000L + start_time.tv_usec - now.tv_usec) * 1000;
				timeout.tv_sec = CHILD_WAIT_SECS - (now.tv_sec - start_time.tv_sec + 1);
			}

			timeout.tv_nsec = (start_time.tv_usec - now.tv_usec) * 1000;
			timeout.tv_sec = CHILD_WAIT_SECS - (now.tv_sec - start_time.tv_sec);
			if (timeout.tv_nsec < 0) {
				timeout.tv_nsec += 1000000000L;
				timeout.tv_sec--;
			}
		}
	}

	if (!sigismember(&old_set, SIGCHLD))
		sigprocmask(SIG_UNBLOCK, &child_wait, NULL);
}

/* Initialize signal handler */
static void
signal_init(void)
{
	signal_handler_init(1);
	signal_set(SIGHUP, propogate_signal, NULL);
	signal_set(SIGUSR1, propogate_signal, NULL);
	signal_set(SIGUSR2, propogate_signal, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_ignore(SIGPIPE);
}
#endif

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

	/* CORENAME_MAX_SIZE in kernel source defines the maximum string length,
	 * see core_pattern[CORENAME_MAX_SIZE] in fs/coredump.c. Currently,
	 * (Linux 4.6) defineds it to be 128, but the definition is not exposed
	 * to user-space. */
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
	fprintf(stderr, "  -l, --log-console            Log messages to local console\n");
	fprintf(stderr, "  -D, --log-detail             Detailed log messages\n");
	fprintf(stderr, "  -S, --log-facility=[0-7]     Set syslog facility to LOG_LOCAL[0-7]\n");
	fprintf(stderr, "  -X, --release-vips           Drop VIP on transition from signal.\n");
	fprintf(stderr, "  -V, --dont-release-vrrp      Don't remove VRRP VIPs and VROUTEs on daemon stop\n");
	fprintf(stderr, "  -I, --dont-release-ipvs      Don't remove IPVS topology on daemon stop\n");
	fprintf(stderr, "  -R, --dont-respawn           Don't respawn child processes\n");
	fprintf(stderr, "  -n, --dont-fork              Don't fork the daemon process\n");
	fprintf(stderr, "  -d, --dump-conf              Dump the configuration data\n");
	fprintf(stderr, "  -p, --pid=FILE               Use specified pidfile for parent process\n");
#ifdef _WITH_VRRP_
	fprintf(stderr, "  -r, --vrrp_pid=FILE          Use specified pidfile for VRRP child process\n");
#endif
#ifdef _WITH_LVS_
	fprintf(stderr, "  -c, --checkers_pid=FILE      Use specified pidfile for checkers child process\n");
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
	fprintf(stderr, "  -i, --config_id id           Skip any configuration lines beginning '@' that don't match id\n");
	fprintf(stderr, "  -v, --version                Display the version number\n");
	fprintf(stderr, "  -h, --help                   Display this help message\n");
}

/* Command line parser */
static void
parse_cmdline(int argc, char **argv)
{
	int c;

	struct option long_options[] = {
		{"use-file",          required_argument, 0, 'f'},
#if defined _WITH_VRRP_ && defined _WITH_LVS_
		{"vrrp",              no_argument,       0, 'P'},
		{"check",             no_argument,       0, 'C'},
#endif
		{"log-console",       no_argument,       0, 'l'},
		{"log-detail",        no_argument,       0, 'D'},
		{"log-facility",      required_argument, 0, 'S'},
		{"release-vips",      no_argument,       0, 'X'},
		{"dont-release-vrrp", no_argument,       0, 'V'},
		{"dont-release-ipvs", no_argument,       0, 'I'},
		{"dont-respawn",      no_argument,       0, 'R'},
		{"dont-fork",         no_argument,       0, 'n'},
		{"dump-conf",         no_argument,       0, 'd'},
		{"pid",               required_argument, 0, 'p'},
#ifdef _WITH_VRRP_
		{"vrrp_pid",          required_argument, 0, 'r'},
#endif
#ifdef _WITH_LVS_
		{"checkers_pid",      required_argument, 0, 'c'},
#endif
#ifdef _WITH_SNMP_
		{"snmp",              no_argument,       0, 'x'},
		{"snmp-agent-socket", required_argument, 0, 'A'},
#endif
		{"core-dump",         no_argument,       0, 'm'},
		{"core-dump-pattern", optional_argument, 0, 'M'},
#ifdef _MEM_CHECK_LOG_
		{"mem-check-log",     no_argument,       0, 'L'},
#endif
#if HAVE_DECL_CLONE_NEWNET
		{"namespace",         required_argument, 0, 's'},
#endif	
		{"config-id",         required_argument, 0, 'i'},
		{"version",           no_argument,       0, 'v'},
		{"help",              no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "vhlndVIDRS:f:p:i:mM"
#if defined _WITH_VRRP_ && defined _WITH_LVS_
					    "PC"
#endif
#ifdef _WITH_VRRP_ 
					    "r:"
#endif
#ifdef _WITH_LVS_
					    "c:"
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
				, long_options, NULL)) != EOF) {
		switch (c) {
		case 'v':
			fprintf(stderr, "%s", version_string);
#ifdef GIT_COMMIT
			fprintf(stderr, ", git commit %s", GIT_COMMIT);
#endif
			fprintf(stderr, "\n\n%s\n\n", COPYRIGHT_STRING);
			fprintf(stderr, "Build options: %s\n", BUILD_OPTIONS);
			exit(0);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'l':
			__set_bit(LOG_CONSOLE_BIT, &debug);
			break;
		case 'n':
			__set_bit(DONT_FORK_BIT, &debug);
			break;
		case 'd':
			__set_bit(DUMP_CONF_BIT, &debug);
			break;
		case 'V':
			__set_bit(DONT_RELEASE_VRRP_BIT, &debug);
			break;
		case 'I':
			__set_bit(DONT_RELEASE_IPVS_BIT, &debug);
			break;
		case 'D':
			__set_bit(LOG_DETAIL_BIT, &debug);
			break;
		case 'R':
			__set_bit(DONT_RESPAWN_BIT, &debug);
			break;
		case 'X':
			__set_bit(RELEASE_VIPS_BIT, &debug);
			break;
		case 'S':
			log_facility = LOG_FACILITY[atoi(optarg)].facility;
			break;
		case 'f':
			conf_file = optarg;
			break;
#if defined _WITH_VRRP_ && defined _WITH_LVS_
		case 'P':
			daemon_mode = 0;
			__set_bit(DAEMON_VRRP, &daemon_mode);
			break;
		case 'C':
			daemon_mode = 0;
			__set_bit(DAEMON_CHECKERS, &daemon_mode);
			break;
#endif
		case 'p':
			main_pidfile = optarg;
			break;
#ifdef _WITH_LVS_
		case 'c':
			checkers_pidfile = optarg;
			break;
#endif
#ifdef _WITH_VRRP_
		case 'r':
			vrrp_pidfile = optarg;
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
			config_id = optarg;
			break;
		default:
			exit(0);
			break;
		}
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}
}

/* Entry point */
int
keepalived_main(int argc, char **argv)
{
	bool report_stopped = true;
	struct utsname uname_buf;
	char *end;
	size_t buf_len;

	/* Init debugging level */
	debug = 0;

	/* Initialise pointer to child finding function */
	set_child_finder(find_keepalived_child);

	/* Initialise daemon_mode */
#ifdef _WITH_VRRP_
	__set_bit(DAEMON_VRRP, &daemon_mode);
#endif
#ifdef _WITH_LVS_
	__set_bit(DAEMON_CHECKERS, &daemon_mode);
#endif

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	parse_cmdline(argc, argv);

	openlog(PACKAGE_NAME, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0) , log_facility);

	if (__test_bit(LOG_CONSOLE_BIT, &debug))
		enable_console_log();

#ifdef GIT_COMMIT
	log_message(LOG_INFO, "Starting %s, git commit %s", version_string, GIT_COMMIT);
#else
	log_message(LOG_INFO, "Starting %s", version_string);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PACKAGE_NAME, "Parent process");
#endif

	/* Handle any core file requirements */
	core_dump_init();

	netlink_set_recv_buf_size();

	set_default_script_user(&default_script_uid, &default_script_gid);

	/* Get buffer length needed for getpwnam_r/getgrnam_r */
	getpwnam_buf_len = (size_t)sysconf(_SC_GETPW_R_SIZE_MAX);
	if ((buf_len = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX)) > getpwnam_buf_len)
		getpwnam_buf_len = buf_len;

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
				os_release = (unsigned)strtoul(end + 1, &end, 10);
				if (*end && *end != '-')
					os_major = 0;
			}
		}
		if (!os_major)
			log_message(LOG_INFO, "Unable to parse kernel version %s", uname_buf.release);
	}

	/* Check we can read the configuration file(s).
	   NOTE: the working directory will be / if we
	   forked, but will be the current working directory
	   when keepalived was run if we haven't forked.
	   This means that if any config file names are not
	   absolute file names, the behaviour will be different
	   depending on whether we forked or not. */
	if (!check_conf_file(conf_file))
		goto end;

	read_config_file();

#if HAVE_DECL_CLONE_NEWNET
	if (override_namespace) {
		if (network_namespace) {
			log_message(LOG_INFO, "Overriding config net_namespace '%s' with command line namespace '%s'", network_namespace, override_namespace);
			FREE(network_namespace);
		}
		network_namespace = override_namespace;
		override_namespace = NULL;
	}
#endif

	if (instance_name
#if HAVE_DECL_CLONE_NEWNET
			  || network_namespace
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
	}

	if (use_pid_dir) {
		/* Create the directory for pid files */
		create_pid_dir();
	}

#if HAVE_DECL_CLONE_NEWNET
	if (network_namespace) {
		if (network_namespace && !set_namespaces(network_namespace)) {
			log_message(LOG_ERR, "Unable to set network namespace %s - exiting", network_namespace);
			goto end;
		}
	}
#endif

	if (instance_name) {
		if (!main_pidfile && (main_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR KEEPALIVED_PID_FILE, instance_name, PID_EXTENSION)))
			free_main_pidfile = true;
#ifdef _WITH_LVS_
		if (!checkers_pidfile && (checkers_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR CHECKERS_PID_FILE, instance_name, PID_EXTENSION)))
			free_checkers_pidfile = true;
#endif
#ifdef _WITH_VRRP_
		if (!vrrp_pidfile && (vrrp_pidfile = make_pidfile_name(KEEPALIVED_PID_DIR VRRP_PID_FILE, instance_name, PID_EXTENSION)))
			free_vrrp_pidfile = true;
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
	}

	/* Check if keepalived is already running */
	if (keepalived_running(daemon_mode)) {
		log_message(LOG_INFO, "daemon is already running");
		report_stopped = false;
		goto end;
	}

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug))
		xdaemon(0, 0, 0);

	/* Set file creation mask */
	umask(0);

#ifdef _MEM_CHECK_
	enable_mem_log_termination();
#endif

	/* write the father's pidfile */
	if (!pidfile_write(main_pidfile, getpid()))
		goto end;

#ifndef _DEBUG_
	/* Signal handling initialization  */
	signal_init();
#endif

	/* Create the master thread */
	master = thread_make_master();

	/* Init daemon */
	start_keepalived();

#ifndef _DEBUG_
	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();
#endif

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
	if (network_namespace)
		clear_namespaces();
#endif

	if (use_pid_dir)
		remove_pid_dir();

	/* Restore original core_pattern if necessary */
	if (orig_core_dump_pattern)
		update_core_dump_pattern(orig_core_dump_pattern);

	free_parent_mallocs_startup(false);
	free_parent_mallocs_exit();

	closelog();

#ifndef _MEM_CHECK_LOG_
	FREE_PTR(syslog_ident);
#else
	if (syslog_ident)
		free(syslog_ident);
#endif

	exit(0);
}
