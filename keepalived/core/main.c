/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 0.6.8 2002/07/16 02:41:25 acassen Exp $
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
 */

#include "main.h"

/* SIGHUP handler */
void
sighup(int sig)
{
	syslog(LOG_INFO, "Terminating on signal");

	/* register the terminate thread */
	thread_add_terminate_event(master);
}

/* SIGCHLD handler */
void
sigchld(int sig)
{
	int child;
	wait(&child);
}

/* Signal wrapper */
void *
signal_set(int signo, void (*func) (int))
{
	int ret;
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = func;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif				/* SA_RESTART */

	ret = sigaction(signo, &sig, &osig);

	if (ret < 0)
		return (SIG_ERR);
	else
		return (osig.sa_handler);
}

/* Initialize signal handler */
void
signal_init(void)
{
	signal_set(SIGHUP, sighup);
	signal_set(SIGINT, sighup);
	signal_set(SIGTERM, sighup);
	signal_set(SIGKILL, sighup);
	signal_set(SIGCHLD, sigchld);
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
		"  %s --dont-fork       -n       Dont fork the daemon process.\n"
		"  %s --use-file        -f       Use the specified configuration file.\n"
		"                                Default is /etc/keepalived/keepalived.conf.\n"
		"  %s --dump-conf       -d       Dump the configuration data.\n"
		"  %s --log-console     -l       Log message to local console.\n"
		"  %s --help            -h       Display this short inlined help screen.\n"
		"  %s --version         -v       Display the version number\n",
		prog, prog, prog, prog, prog, prog);
}

/* Command line parser */
static char *
parse_cmdline(int argc, char **argv)
{
	poptContext context;
	char *optarg = NULL;
	char *conf_file = NULL;
	int c;

	struct poptOption options_table[] = {
		{"version", 'v', POPT_ARG_NONE, NULL, 'v'},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h'},
		{"log-console", 'l', POPT_ARG_NONE, NULL, 'l'},
		{"dont-fork", 'n', POPT_ARG_NONE, NULL, 'n'},
		{"dump-conf", 'd', POPT_ARG_NONE, NULL, 'd'},
		{"use-file", 'f', POPT_ARG_STRING, &optarg, 'f'},
		{NULL, 0, 0, NULL, 0}
	};

	context =
	    poptGetContext(PROG, argc, (const char **) argv, options_table, 0);
	if ((c = poptGetNextOpt(context)) < 0) {
		return NULL;
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
	case 'f':
		conf_file = optarg;
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
		case 'f':
			conf_file = optarg;
			break;
		}
	}

	/* check unexpected arguments */
	if ((optarg = (char *) poptGetArg(context))) {
		fprintf(stderr, "unexpected argument %s\n", optarg);
		return NULL;
	}

	/* free the allocated context */
	poptFreeContext(context);

	return ((conf_file) ? conf_file : NULL);
}

/* Entry point */
int
main(int argc, char **argv)
{
	char *conf_file = NULL;
	thread thread;

	/* Init debugging level */
	debug = 0;

	/*
	 * Parse command line and set debug level.
	 * bits 0..7 reserved by main.c
	 */
	conf_file = parse_cmdline(argc, argv);

	openlog(PROG, LOG_PID | (debug & 1) ? LOG_CONS : 0, LOG_DAEMON);
	syslog(LOG_INFO, "Starting " VERSION_STRING);

	/* Check if keepalived is already running */
	if (keepalived_running()) {
		syslog(LOG_INFO, "Stopping " VERSION_STRING);
		closelog();
		exit(0);
	}

	/* daemonize process */
	if (!(debug & 2))
		xdaemon(0, 0, 0);

	/* write the pidfile */
	if (!pidfile_write(getpid())) {
		syslog(LOG_INFO, "Stopping " VERSION_STRING);
		closelog();
		exit(0);
	}

	/* Signal handling initialization  */
	signal_init();

	/* Init interface queue */
	init_interface_queue();

	/* Parse the configuration file */
#ifdef _WITH_LVS_
	init_checkers_queue();
#endif
	init_data(conf_file);
	if (!conf_data) {
		syslog(LOG_INFO, "Stopping " VERSION_STRING);
		closelog();
#ifdef _DEBUG_
		keepalived_free_final();
#endif
		exit(0);
	}

	/* SSL load static data & initialize common ctx context */
#ifdef _WITH_LVS_
	if (!init_ssl_ctx()) {
		closelog();
#ifdef _DEBUG_
		keepalived_free_final();
#endif
		exit(0);
	}
#endif

#ifdef _WITH_LVS_
	if (!init_services()) {
		syslog(LOG_INFO, "Stopping " VERSION_STRING);
		closelog();
		free_data();
		exit(0);
	}
#endif

	/* Create the master thread */
	master = thread_make_master();

	/* register workers threads */
	kernel_netlink_init();
	if_mii_poller_init();
#ifdef _WITH_LVS_
	register_checkers_thread();
#endif
	if (!vrrp_complete_init())
		goto end;
	register_vrrp_thread();

	/* Dump the configuration */
	if (debug & 4)
		dump_data();

	/* processing the master thread queues, return and execute one ready thread */
	while (thread_fetch(master, &thread)) {

		/* Run until error, used for debuging only */
#ifdef _DEBUG_
		if ((debug & 520) == 520) {
			debug &= ~520;
			thread_add_terminate_event(master);
		}
#endif
		thread_call(&thread);
	}

end:
	/* Reached when terminate signal catched */
	syslog(LOG_INFO, "Stopping " VERSION_STRING);
	/* Just cleanup memory & exit */
	thread_destroy_master(master);
#ifdef _WITH_LVS_
	free_checkers_queue();
	clear_services();
#endif
	shutdown_vrrp_instances();
	free_interface_queue();
	free_data();

	pidfile_rm();

#ifdef _DEBUG_
	keepalived_free_final();
#endif

	/* finally return from system */
	closelog();
	exit(0);
}
