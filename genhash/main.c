/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Main entry point.
 *
 * Version:     $Id: main.c,v 1.0.0 2002/11/20 21:34:18 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
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
 * Copyright (C) 2001, 2002, 2003 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "main.h"
#include "utils.h"
#include "sock.h"

/* global var */
thread_master *master = NULL;
SOCK *sock = NULL;

/* Terminate handler */
void
sigend(int sig)
{
	/* register the terminate thread */
	thread_add_terminate_event(master);
}

/* signal wrapper */
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
	signal_set(SIGHUP, sigend);
	signal_set(SIGINT, sigend);
	signal_set(SIGTERM, sigend);
	signal_set(SIGKILL, sigend);
}

/* Usage function */
static void
usage(const char *prog)
{
	fprintf(stderr, VERSION_STRING);
	fprintf(stderr,
		"Usage:\n"
		"  %s -s server-address -p port -u url\n"
		"  %s -S -s server-address -p port -u url\n"
		"  %s -h\n" "  %s -r\n\n", prog, prog, prog, prog);
	fprintf(stderr,
		"Commands:\n"
		"Either long or short options are allowed.\n"
		"  %s --use-ssl         -S       Use SSL connection to remote server.\n"
		"  %s --server          -s       Use the specified remote server address.\n"
		"  %s --port            -p       Use the specified remote server port.\n"
		"  %s --url             -u       Use the specified remote server url.\n"
		"  %s --use-virtualhost -V       Use the specified virtualhost in GET query.\n"
		"  %s --verbose         -v       Use verbose mode output.\n"
		"  %s --help            -h       Display this short inlined help screen.\n"
		"  %s --release         -r       Display the release number\n",
		prog, prog, prog, prog, prog, prog, prog, prog);
}

/* Command line parser */
static int
parse_cmdline(int argc, char **argv, REQ * req)
{
	poptContext context;
	char *optarg = NULL;
	int c;

	struct poptOption options_table[] = {
		{"release", 'r', POPT_ARG_NONE, NULL, 'r'},
		{"help", 'h', POPT_ARG_NONE, NULL, 'h'},
		{"verbose", 'v', POPT_ARG_NONE, NULL, 'v'},
		{"use-ssl", 'S', POPT_ARG_NONE, NULL, 'S'},
		{"server", 's', POPT_ARG_STRING, &optarg, 's'},
		{"port", 'p', POPT_ARG_STRING, &optarg, 'p'},
		{"url", 'u', POPT_ARG_STRING, &optarg, 'u'},
		{"use-virtualhost", 'V', POPT_ARG_STRING, &optarg, 'V'},
		{NULL, 0, 0, NULL, 0}
	};

	/* Parse the command line arguments */
	context =
	    poptGetContext(PROG, argc, (const char **) argv, options_table, 0);
	if ((c = poptGetNextOpt(context)) < 0) {
		usage(argv[0]);
		return CMD_LINE_ERROR;
	}

	/* The first option car */
	switch (c) {
	case 'r':
		fprintf(stderr, VERSION_STRING);
		break;
	case 'h':
		usage(argv[0]);
		break;
	case 'v':
		req->verbose = 1;
		break;
	case 'S':
		req->ssl = 1;
		break;
	case 's':
		inet_ston(optarg, &req->addr_ip);
		break;
	case 'V':
		req->vhost = optarg;
		break;
	default:
		usage(argv[0]);
		return CMD_LINE_ERROR;
	}

	/* the others */
	while ((c = poptGetNextOpt(context)) >= 0) {
		switch (c) {
		case 'v':
			req->verbose = 1;
			break;
		case 'S':
			req->ssl = 1;
			break;
		case 's':
			inet_ston(optarg, &req->addr_ip);
			break;
		case 'V':
			req->vhost = optarg;
			break;
		case 'p':
			req->addr_port = htons(atoi(optarg));
			break;
		case 'u':
			req->url = optarg;
			break;
		default:
			usage(argv[0]);
			return CMD_LINE_ERROR;
		}
	}

	/* check unexpected arguments */
	if ((optarg = (char *) poptGetArg(context))) {
		fprintf(stderr, "unexpected argument %s", optarg);
		return CMD_LINE_ERROR;
	}

	/* free the allocated context */
	poptFreeContext(context);

	return CMD_LINE_SUCCESS;
}

int
main(int argc, char **argv)
{
	thread thread;

	/* Allocate the room */
	req = (REQ *) MALLOC(sizeof (REQ));

	/* Command line parser */
	if (!parse_cmdline(argc, argv, req)) {
		FREE(req);
		exit(0);
	}

	/* Check minimum configuration need */
	if (!req->addr_ip && !req->addr_port && !req->url) {
		FREE(req);
		exit(0);
	}

	/* Init the reference timer */
	req->ref_time = timer_tol(timer_now());
	DBG("Reference timer = %lu\n", req->ref_time);

	/* Init SSL context */
	init_ssl();

	/* Signal handling initialization  */
	signal_init();

	/* Create the master thread */
	master = thread_make_master();

	/* Register the GET request */
	init_sock();

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 * Run until error, used for debuging only.
	 */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Finalize output informations */
	if (req->verbose)
		printf("Global response time for [%s] =%lu\n",
		       req->url, req->response_time - req->ref_time);

	/* exit cleanly */
	SSL_CTX_free(req->ctx);
	free_sock(sock);
	FREE(req);
	exit(0);
}
