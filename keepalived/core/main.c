/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 1.1.15 2007/09/15 04:07:41 acassen Exp $
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
 * Copyright (C) 2001-2007 Alexandre Cassen, <acassen@freebox.fr>
 */

#include "main.h"
#include "config.h"
#include "signals.h"

/* global var */
char *conf_file = NULL;		/* Configuration file */
int log_facility = LOG_DAEMON;	/* Optional logging facilities */
pid_t vrrp_child = -1;		/* VRRP child process ID */
pid_t checkers_child = -1;	/* Healthcheckers child process ID */
int daemon_mode = 0;		/* VRRP/CHECK subsystem selection */
int linkwatch = 0;		/* Use linkwatch kernel netlink reflection */

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
	syslog(LOG_INFO, "Stopping " VERSION_STRING);
	/* Just cleanup memory & exit */
	thread_destroy_master(master);

	if (daemon_mode == 3 || !daemon_mode)
		pidfile_rm(KEEPALIVED_PID_FILE);
	else
		pidfile_rm((daemon_mode & 1) ? KEEPALIVED_VRRP_PID_FILE :
			   KEEPALIVED_CHECKERS_PID_FILE);

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
sighup(int sig)
{
	/* Set the reloading flag */
	SET_RELOAD;

	/* Signal child process */
	if (vrrp_child > 0)
		kill(vrrp_child, SIGHUP);
	if (checkers_child > 0)
		kill(checkers_child, SIGHUP);
}

/* Terminate handler */
void
sigend(int sig)
{
	int status;

	/* register the terminate thread */
	syslog(LOG_INFO, "Terminating on signal");
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
	signal_set(SIGHUP, sighup);
	signal_set(SIGINT, sigend);
	signal_set(SIGTERM, sigend);
	signal_ignore(SIGPIPE);
	signal_noignore_sigchld();
}

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, VERSION_STRING);
	fprintf(stderr,
		"\nUsage:\n"
		"  %s\n"
		"  %s -n\n"
		"  %s -f keepalived.conf\n"
		"  %s -d\n"
		"  %s -h\n" "  %s -v\n\n", prog, prog, prog, prog, prog, prog);
	fprintf(stderr,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  %s --vrrp               -P    Only run with VRRP subsystem.\n"
		"  %s --check              -C    Only run with Health-checker subsystem.\n"
		"  %s --dont-release-vrrp  -V    Dont remove VRRP VIPs & VROUTEs on daemon stop.\n"
		"  %s --dont-release-ipvs  -I    Dont remove IPVS topology on daemon stop.\n"
		"  %s --dont-fork          -n    Dont fork the daemon process.\n"
		"  %s --use-file           -f    Use the specified configuration file.\n"
		"                                Default is /etc/keepalived/keepalived.conf.\n"
		"  %s --dump-conf          -d    Dump the configuration data.\n"
		"  %s --log-console        -l    Log message to local console.\n"
		"  %s --log-detail         -D    Detailed log messages.\n"
		"  %s --log-facility       -S    0-7 Set syslog facility to LOG_LOCAL[0-7]. (default=LOG_DAEMON)\n"
		"  %s --help               -h    Display this short inlined help screen.\n"
		"  %s --version            -v    Display the version number\n",
		prog, prog, prog, prog, prog, prog, prog, prog,
		prog, prog, prog, prog);
}

/* Command line parser */
static void
parse_cmdline(int argc, char **argv)
{
	poptContext context;
	char *option_arg = NULL;
	int c;

	struct poptOption options_table[] = {
		{"version", 'v', POPT_ARG_NONE, NULL, 'v'},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h'},
		{"log-console", 'l', POPT_ARG_NONE, NULL, 'l'},
		{"log-detail", 'D', POPT_ARG_NONE, NULL, 'D'},
		{"log-facility", 'S', POPT_ARG_STRING, &option_arg, 'S'},
		{"dont-release-vrrp", 'V', POPT_ARG_NONE, NULL, 'V'},
		{"dont-release-ipvs", 'I', POPT_ARG_NONE, NULL, 'I'},
		{"dont-fork", 'n', POPT_ARG_NONE, NULL, 'n'},
		{"dump-conf", 'd', POPT_ARG_NONE, NULL, 'd'},
		{"use-file", 'f', POPT_ARG_STRING, &option_arg, 'f'},
		{"vrrp", 'P', POPT_ARG_NONE, NULL, 'P'},
		{"check", 'C', POPT_ARG_NONE, NULL, 'C'},
		{NULL, 0, 0, NULL, 0}
	};

	context =
	    poptGetContext(PROG, argc, (const char **) argv, options_table, 0);
	if ((c = poptGetNextOpt(context)) < 0) {
		return;
	}

	/* The first option car */
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
		debug |= 1;
		break;
	case 'n':
		debug |= 2;
		break;
	case 'd':
		debug |= 4;
		break;
	case 'V':
		debug |= 8;
		break;
	case 'I':
		debug |= 16;
		break;
	case 'D':
		debug |= 32;
		break;
	case 'S':
		log_facility = LOG_FACILITY[atoi(option_arg)].facility;
		break;
	case 'f':
		conf_file = option_arg;
		break;
	case 'P':
		daemon_mode |= 1;
		break;
	case 'C':
		daemon_mode |= 2;
		break;
	}

	/* the others */
	while ((c = poptGetNextOpt(context)) >= 0) {
		switch (c) {
		case 'l':
			debug |= 1;
			break;
		case 'n':
			debug |= 2;
			break;
		case 'd':
			debug |= 4;
			break;
		case 'V':
			debug |= 8;
			break;
		case 'I':
			debug |= 16;
			break;
		case 'D':
			debug |= 32;
			break;
		case 'S':
			log_facility = LOG_FACILITY[atoi(option_arg)].facility;
			break;
		case 'f':
			conf_file = option_arg;
			break;
		case 'P':
			daemon_mode |= 1;
			break;
		case 'C':
			daemon_mode |= 2;
			break;
		}
	}

	/* check unexpected arguments */
	if ((option_arg = (char *) poptGetArg(context))) {
		fprintf(stderr, "unexpected argument %s\n", option_arg);
		return;
	}

	/* free the allocated context */
	poptFreeContext(context);
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

	openlog(PROG, LOG_PID | (debug & 1) ? LOG_CONS : 0, log_facility);
	syslog(LOG_INFO, "Starting " VERSION_STRING);

	/* Check if keepalived is already running */
	if (keepalived_running(daemon_mode)) {
		syslog(LOG_INFO, "daemon is already running");
		goto end;
	}

	/* daemonize process */
	if (!(debug & 2))
		xdaemon(0, 0, 0);

	/* write the pidfile */
	if (daemon_mode == 3 || !daemon_mode) {
		if (!pidfile_write(KEEPALIVED_PID_FILE, getpid()))
			goto end;
	} else {
		if (!pidfile_write((daemon_mode & 1) ? KEEPALIVED_VRRP_PID_FILE :
				    KEEPALIVED_CHECKERS_PID_FILE, getpid()))
			goto end;
	}

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
