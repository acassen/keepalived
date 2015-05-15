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

#include "main.h"
#include "config.h"
#include "signals.h"
#include "pidfile.h"
#include "bitops.h"
#include "logger.h"

/* global var */
char *conf_file = NULL;		/* Configuration file */
int log_facility = LOG_DAEMON;	/* Optional logging facilities */
pid_t vrrp_child = -1;		/* VRRP child process ID */
pid_t checkers_child = -1;	/* Healthcheckers child process ID */
int daemon_mode = 0;		/* VRRP/CHECK subsystem selection */
int linkwatch = 0;		/* Use linkwatch kernel netlink reflection */
char *main_pidfile = KEEPALIVED_PID_FILE;	/* overrule default pidfile */
char *checkers_pidfile = CHECKERS_PID_FILE;	/* overrule default pidfile */
char *vrrp_pidfile = VRRP_PID_FILE;	/* overrule default pidfile */
#ifdef _WITH_SNMP_
int snmp = 0;			/* Enable SNMP support */
const char *snmp_socket = NULL;	/* Socket to use for SNMP agent */
#endif

/* Log facility table */
static struct {
	int facility;
} LOG_FACILITY[LOG_FACILITY_MAX + 1] = {
	{LOG_LOCAL0}, {LOG_LOCAL1}, {LOG_LOCAL2}, {LOG_LOCAL3},
	{LOG_LOCAL4}, {LOG_LOCAL5}, {LOG_LOCAL6}, {LOG_LOCAL7}
};

/* Daemon stop sequence */
static void
stop_keepalived(void)
{
	log_message(LOG_INFO, "Stopping " VERSION_STRING);
	/* Just cleanup memory & exit */
	signal_handler_destroy();
	thread_destroy_master(master);

	pidfile_rm(main_pidfile);

	if (daemon_mode & 1 || !daemon_mode)
		pidfile_rm(vrrp_pidfile);

	if (daemon_mode & 2 || !daemon_mode)
		pidfile_rm(checkers_pidfile);

#ifdef _DEBUG_
	keepalived_free_final("Parent process");
#endif
}

/* Daemon init sequence */
static void
start_keepalived(void)
{
#ifdef _WITH_LVS_
	/* start healthchecker child */
	if (daemon_mode & 2 || !daemon_mode)
		start_check_child();
#endif
#ifdef _WITH_VRRP_
	/* start vrrp child */
	if (daemon_mode & 1 || !daemon_mode)
		start_vrrp_child();
#endif
}

/* SIGHUP handler */
void
sighup(void *v, int sig)
{
	/* Signal child process */
	if (vrrp_child > 0)
		kill(vrrp_child, SIGHUP);
	if (checkers_child > 0)
		kill(checkers_child, SIGHUP);
}

/* Terminate handler */
void
sigend(void *v, int sig)
{
	int status;

	/* register the terminate thread */
	thread_add_terminate_event(master);

	if (vrrp_child > 0) {
		kill(vrrp_child, SIGTERM);
		waitpid(vrrp_child, &status, WNOHANG);
	}
	if (checkers_child > 0) {
		kill(checkers_child, SIGTERM);
		waitpid(checkers_child, &status, WNOHANG);
	}
}

/* Initialize signal handler */
void
signal_init(void)
{
	signal_handler_init();
	signal_set(SIGHUP, sighup, NULL);
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	signal_ignore(SIGPIPE);
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
		{"version",           no_argument,       0, 'v'},
		{"help",              no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

#ifdef _WITH_SNMP_
	while ((c = getopt_long(argc, argv, "vhlndVIDRS:f:PCp:c:r:xA:", long_options, NULL)) != EOF) {
#else
	while ((c = getopt_long(argc, argv, "vhlndVIDRS:f:PCp:c:r:", long_options, NULL)) != EOF) {
#endif
		switch (c) {
		case 'v':
			fprintf(stderr, VERSION_STRING);
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
			daemon_mode |= 1;
			break;
		case 'C':
			daemon_mode |= 2;
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
	/* Init debugging level */
	mem_allocated = 0;
	debug = 0;

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	parse_cmdline(argc, argv);

	openlog(PROG, LOG_PID | ((__test_bit(LOG_CONSOLE_BIT, &debug)) ? LOG_CONS : 0)
		    , log_facility);
	log_message(LOG_INFO, "Starting " VERSION_STRING);

	/* Check if keepalived is already running */
	if (keepalived_running(daemon_mode)) {
		log_message(LOG_INFO, "daemon is already running");
		goto end;
	}

	if (__test_bit(LOG_CONSOLE_BIT, &debug))
		enable_console_log();

	/* daemonize process */
	if (!__test_bit(DONT_FORK_BIT, &debug))
		xdaemon(0, 0, 0);

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
	closelog();
	exit(0);
}
