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

#include <sys/resource.h>

#include "main.h"
#include "config.h"
#include "signals.h"
#include "pidfile.h"
#include "bitops.h"
#include "logger.h"

#define CHILD_WAIT_SECS	5

/* global var */
char *conf_file = CONF;					/* Configuration file */
int log_facility = LOG_DAEMON;				/* Optional logging facilities */
pid_t vrrp_child = -1;					/* VRRP child process ID */
pid_t checkers_child = -1;				/* Healthcheckers child process ID */
const char *main_pidfile = KEEPALIVED_PID_FILE;		/* overrule default pidfile */
const char *checkers_pidfile = CHECKERS_PID_FILE;	/* overrule default pidfile */
const char *vrrp_pidfile = VRRP_PID_FILE;		/* overrule default pidfile */
unsigned long daemon_mode = 0;				/* VRRP/CHECK subsystem selection */
#ifdef _WITH_SNMP_
int snmp = 0;						/* Enable SNMP support */
const char *snmp_socket = NULL;				/* Socket to use for SNMP agent */
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

/* Daemon stop sequence */
static void
stop_keepalived(void)
{
	/* Just cleanup memory & exit */
	signal_handler_destroy();
	thread_destroy_master(master);

	pidfile_rm(main_pidfile);

	if (__test_bit(DAEMON_VRRP, &daemon_mode))
		pidfile_rm(vrrp_pidfile);

	if (__test_bit(DAEMON_CHECKERS, &daemon_mode))
		pidfile_rm(checkers_pidfile);

#ifdef _MEM_CHECK_
	keepalived_free_final("Parent process");
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
static void
propogate_signal(void *v, int sig)
{
	/* Signal child process */
	if (vrrp_child > 0)
		kill(vrrp_child, sig);
	if (checkers_child > 0 && sig == SIGHUP)
		kill(checkers_child, sig);
}

/* Terminate handler */
static void
sigend(void *v, int sig)
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

	if (vrrp_child > 0) {
		kill(vrrp_child, SIGTERM);
		wait_count++;
	}
	if (checkers_child > 0) {
		kill(checkers_child, SIGTERM);
		wait_count++;
	}

	gettimeofday(&start_time, NULL);
	while (wait_count) {
		ret = sigtimedwait(&child_wait, NULL, &timeout);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
		}

		if (vrrp_child > 0 && vrrp_child == waitpid(vrrp_child, &status, WNOHANG)) {
			report_child_status(status, vrrp_child, PROG_VRRP);
			wait_count--;
		}

		if (checkers_child > 0 && checkers_child == waitpid(checkers_child, &status, WNOHANG)) {
			report_child_status(status, checkers_child, PROG_CHECK);
			wait_count--;
		}
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
	signal_handler_init();
	signal_set(SIGHUP, propogate_signal, NULL);
	signal_set(SIGUSR1, propogate_signal, NULL);
	signal_set(SIGUSR2, propogate_signal, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_ignore(SIGPIPE);
}

/* To create a core file when abrt is running (a RedHat distribution),
 * and keepalived isn't installed from an RPM package, edit the file
 * “/etc/abrt/abrt.conf”, and change the value of the field
 * “ProcessUnpackaged” to “yes”. */
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
	fprintf(stderr, "  -P, --vrrp                   Only run with VRRP subsystem\n");
	fprintf(stderr, "  -C, --check                  Only run with Health-checker subsystem\n");
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
	fprintf(stderr, "  -r, --vrrp_pid=FILE          Use specified pidfile for VRRP child process\n");
	fprintf(stderr, "  -c, --checkers_pid=FILE      Use specified pidfile for checkers child process\n");
#ifdef _WITH_SNMP_
	fprintf(stderr, "  -x, --snmp                   Enable SNMP subsystem\n");
	fprintf(stderr, "  -A, --snmp-agent-socket=FILE Use the specified socket for master agent\n");
#endif
	fprintf(stderr, "  -m, --core-dump              Produce core dump if terminate abnormally\n");
	fprintf(stderr, "  -M, --core-dump-pattern=PATN Also set /proc/sys/kernel/core_pattern to PATN (default 'core')\n");
#ifdef _MEM_CHECK_LOG_
	fprintf(stderr, "  -L, --mem-check-log          Log malloc/frees to syslog\n");
#endif
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
		{"vrrp",              no_argument,       0, 'P'},
		{"check",             no_argument,       0, 'C'},
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
		{"vrrp_pid",          required_argument, 0, 'r'},
		{"checkers_pid",      required_argument, 0, 'c'},
 #ifdef _WITH_SNMP_
		{"snmp",              no_argument,       0, 'x'},
		{"snmp-agent-socket", required_argument, 0, 'A'},
 #endif
		{"core-dump",         no_argument,       0, 'm'},
		{"core-dump-pattern", optional_argument, 0, 'M'},
#ifdef _MEM_CHECK_LOG_
		{"mem-check-log",     no_argument,       0, 'L'},
#endif
		{"version",           no_argument,       0, 'v'},
		{"help",              no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "vhlndVIDRS:f:PCp:c:r:mML"
#ifdef _WITH_SNMP_
					    "xA:"
#endif
									, long_options, NULL)) != EOF) {
		switch (c) {
		case 'v':
			fprintf(stderr, "%s", VERSION_STRING);
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
		case 'P':
			daemon_mode = 0;
			__set_bit(DAEMON_VRRP, &daemon_mode);
			break;
		case 'C':
			daemon_mode = 0;
			__set_bit(DAEMON_CHECKERS, &daemon_mode);
			break;
		case 'p':
			main_pidfile = optarg;
			break;
		case 'c':
			checkers_pidfile = optarg;
			break;
		case 'r':
			vrrp_pidfile = optarg;
			break;
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
main(int argc, char **argv)
{
	int report_stopped = true;

	/* Init debugging level */
	debug = 0;

	/* Initialise daemon_mode */
	__set_bit(DAEMON_VRRP, &daemon_mode);
	__set_bit(DAEMON_CHECKERS, &daemon_mode);

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	parse_cmdline(argc, argv);

	openlog(PROG, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
		    , log_facility);
#ifdef GIT_COMMIT
	log_message(LOG_INFO, "Starting %s, git commit %s", VERSION_STRING, GIT_COMMIT);
#else
	log_message(LOG_INFO, "Starting %s", VERSION_STRING);
#endif

#ifdef _MEM_CHECK_
	mem_log_init(PROG);
#endif

	/* Handle any core file requirements */
	core_dump_init();

	/* Check if keepalived is already running */
	if (keepalived_running(daemon_mode)) {
		log_message(LOG_INFO, "daemon is already running");
		report_stopped = false;
		goto end;
	}

	if (__test_bit(LOG_CONSOLE_BIT, &debug))
		enable_console_log();

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug))
		xdaemon(0, 0, 0);

	/* Check we can read the configuration file(s).
 	   NOTE: the working directory will be / if we
 	   forked, but will be the current working directory
 	   when keepalived was run if we haven't forked.
 	   This means that if any config file names are not
 	   absolute file names, the behaviour will be different
 	   depending on whether we forked or not. */
	if (!check_conf_file(conf_file))
		goto end;

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

	/* Finish daemon process */
	stop_keepalived();
#endif

	/*
	 * Reached when terminate signal catched.
	 * finally return from system
	 */
end:
	if (report_stopped) {
#ifdef GIT_COMMIT
		log_message(LOG_INFO, "Stopped %s, git commit %s", VERSION_STRING, GIT_COMMIT);
#else
		log_message(LOG_INFO, "Stopped %s", VERSION_STRING);
#endif
	}

	/* Restore original core_pattern if necessary */
	if (orig_core_dump_pattern)
		update_core_dump_pattern(orig_core_dump_pattern);

	closelog();
	exit(0);
}
