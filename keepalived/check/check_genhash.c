/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        WEB CHECK. Common HTTP/SSL checker primitives.
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Jan Holmberg, <jan@artech.net>
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

#include <openssl/err.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>

#include "check_api.h"
#include "check_http.h"
#include "check_ssl.h"
#include "check_genhash.h"
#include "bitops.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "signals.h"
#include "scheduler.h"


/*
 *	Genhash utility
 */
static void
genhash_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --genhash COMMAND [OPTIONS]\n"
		"Commands:\n"
		"   -s server-address -p port -u url\n"
		"   -S -s server-address -p port -u url\n"
		"   -h\n\n", prog);
	fprintf(stderr,
		"Options:\n"
		"Either long or short options are allowed.\n"
		"   --use-ssl         -S       Use SSL connection to remote server.\n"
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
		"   --use-sni         -I       Use SNI during SSL handshake (uses virtualhost setting; see -V).\n"
#endif
		"   --server          -s       Use the specified remote server address.\n"
		"   --port            -p       Use the specified remote server port.\n"
		"   --url             -u       Use the specified remote server url.\n"
		"   --use-virtualhost -V       Use the specified virtualhost in GET query.\n"
		"   --hash            -H       Use the specified hash algorithm.\n"
		"   --verbose         -v       Use verbose mode output.\n"
		"   --help            -h       Display this short inlined help screen.\n"
		"   --fwmark          -m       Use the specified FW mark.\n"
		"   --protocol        -P       Use the specified HTTP protocol - '1.0', 1.0c', '1.1'.\n"
		"                                1.0c means 1.0 with 'Connection: close'\n"
		"   --timeout         -t       Timeout in seconds\n");
}

static int
check_genhash_parse_cmdline(int argc, char **argv, checker_t *checker)
{
	http_checker_t *http_get_check = checker->data;
	conn_opts_t *co = checker->co;
	const char *start;
	char *endptr;
	long port_num;
	url_t *url;
	uint8_t mandatory_bits = 7;
	int c;

	struct option long_options[] = {
		{"help",		no_argument,       0, 'h'},
		{"genhash",		no_argument,       0, 'T'},
		{"verbose",		no_argument,       0, 'v'},
		{"use-ssl",		no_argument,       0, 'S'},
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
		{"use-sni",		no_argument,       0, 'I'},
#endif
		{"server",		required_argument, 0, 's'},
		{"hash",		required_argument, 0, 'H'},
		{"use-virtualhost",	required_argument, 0, 'V'},
		{"port",		required_argument, 0, 'p'},
		{"url",			required_argument, 0, 'u'},
		{"fwmark",		required_argument, 0, 'm'},
		{"protocol",		required_argument, 0, 'P'},
		{"timeout",		required_argument, 0, 't'},
		{0, 0, 0, 0}
	};

	/* Trivial sanity check */
	if (argc <= 2)
		return -1;

	/* Parse the command line arguments */
	while ((c = getopt_long(argc, argv, "hTvSs:H:V:p:u:m:P:t:"
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
							       "I"
#endif
				  , long_options, NULL)) != EOF) {
		switch (c) {
		case 'h':
			genhash_usage(argv[0]);
			break;
		case 'v':
			checker->enabled = true; /* reuse as Verbose */
			break;
		case 'S':
			http_get_check->proto = PROTO_SSL;
			if (!init_ssl_ctx()) {
				fprintf(stderr, "Cannot initialize SSL context.\n");
				return -1;
			}
			break;
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
		case 'I':
			http_get_check->enable_sni = true;
			break;
#endif
		case 's':
			if (inet_stosockaddr(optarg, NULL, &co->dst)) {
				fprintf(stderr, "server should be an IP, not %s\n", optarg);
				return -1;
			}
			mandatory_bits &= ~1;
			break;
		case 'V':
			http_get_check->virtualhost = optarg;
			break;
		case 'p':
			port_num = strtol(optarg, &endptr, 10);
			if (*endptr || port_num <= 0 || port_num > 65535) {
				fprintf(stderr, "invalid port number '%s'\n", optarg);
				return -1;
			}
			checker_set_dst_port(&co->dst, htons(port_num));
			mandatory_bits &= ~2;
			break;
		case 'u':
			PMALLOC(url);
			INIT_LIST_HEAD(&url->e_list);
			url->path = STRDUP(optarg);
			url->digest = MALLOC(MD5_DIGEST_LENGTH);
			list_add_tail(&url->e_list, &http_get_check->url);
			http_get_check->url_it = url;
			mandatory_bits &= ~4;
			break;
		case 'm':
#ifdef _WITH_SO_MARK_
			start = optarg + strspn(optarg, " \t");
			co->fwmark = (unsigned)strtoul(start, &endptr, 10);
			if (*endptr || start[0] == '-' || start[0] == ' ') {
				fprintf(stderr, "invalid fwmark '%s'\n", optarg);
				return -1;
			}
#else
			fprintf(stderr, "keepalived built without fwmark support\n");
			return -1;
#endif
			break;
		case 'P':
			if (!strcmp(optarg, "1.0"))
				http_get_check->http_protocol = HTTP_PROTOCOL_1_0;
			else if (!strcmp(optarg, "1.0c") || !strcmp(optarg, "1.0C"))
				http_get_check->http_protocol = HTTP_PROTOCOL_1_0C;
			else if (!strcmp(optarg, "1.1"))
				http_get_check->http_protocol = HTTP_PROTOCOL_1_1;
			/* 1.0k and 1.1k are for test purposes and are not expected to be used */
			else if (!strcmp(optarg, "1.0k") || !strcmp(optarg, "1.0K"))
				http_get_check->http_protocol = HTTP_PROTOCOL_1_0K;
			else if (!strcmp(optarg, "1.1k") || !strcmp(optarg, "1.1K"))
				http_get_check->http_protocol = HTTP_PROTOCOL_1_1K;
			else {
				fprintf(stderr, "invalid HTTP protocol version '%s'\n", optarg);
				return -1;
			}
			break;
		case 't':
			start = optarg + strspn(optarg, " \t");
			co->connection_to = (unsigned)strtoul(start, &endptr, 10);
			if (*endptr || start[0] == '-' || !start[0]) {
				fprintf(stderr, "invalid timeout '%s'\n", optarg);
				return -1;
			}
			co->connection_to *= TIMER_HZ;
			break;
		default:
			genhash_usage(argv[0]);
			return -1;
		}
	}

	/* check unexpected arguments */
	if (optind < argc) {
		fprintf(stderr, "Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		return -1;
	}

	/* Minimum option required are: server, port & url */
	return (mandatory_bits) ? -1 : 0;
}

/* Terminate handler */
static void
sigend(__attribute__((unused)) void *v, __attribute__((unused)) int sig)
{
	/* register the terminate thread */
	thread_add_terminate_event(master);
}

void __attribute__ ((noreturn))
check_genhash(int argc, char **argv)
{
	checker_t *checker;
	http_checker_t *http_get_check;
	virtual_server_t *vs;
	real_server_t *rs;
	conn_opts_t *co;
	int ret = 0;

	/* Create a dummy checker */
	PMALLOC(check_data);
	PMALLOC(checker);
	PMALLOC(vs);
	PMALLOC(rs);
	checker->vs = vs;
	checker->rs = rs;
	PMALLOC(co);
	co->connection_to = UINT_MAX;
	checker->co = co;
	PMALLOC(http_get_check);
	INIT_LIST_HEAD(&http_get_check->url);
	http_get_check->genhash = true;
	http_get_check->proto = PROTO_HTTP;
	checker->data = http_get_check;
	checker->enabled = true;

	/* Parse command line */
	if (check_genhash_parse_cmdline(argc, argv, checker) < 0) {
		genhash_usage(argv[0]);
		ret = 1;
		goto end;
	}

	/* Submit work to I/O MUX */
	master = thread_make_master();
	signal_set(SIGINT, sigend, NULL);
	signal_set(SIGTERM, sigend, NULL);
	thread_add_event(master, http_connect_thread, checker, 0);
	launch_thread_scheduler(master);

	/* Release memory */
	thread_destroy_master(master);
  end:
	free_http_check(checker);
	FREE(vs);
	FREE(rs);
	FREE(check_data);
	exit(ret);
}
