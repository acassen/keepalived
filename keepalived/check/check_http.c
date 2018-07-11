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

#ifdef _WITH_REGEX_CHECK_
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "check_http.h"
#include "check_api.h"
#include "check_ssl.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "html.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#include "string.h"
#endif
#include "layer4.h"
#include "ipwrapper.h"
#include "smtp.h"

#define	REGISTER_CHECKER_NEW	1
#define	REGISTER_CHECKER_RETRY	2

#ifdef _WITH_REGEX_CHECK_
typedef struct {
	const char *option;
	unsigned option_bit ;
} regex_option_t;

regex_option_t regex_options[] = {
	{"allow_empty_class", PCRE2_ALLOW_EMPTY_CLASS},
	{"alt_bsux", PCRE2_ALT_BSUX},
	{"auto_callout", PCRE2_AUTO_CALLOUT},
	{"caseless", PCRE2_CASELESS},
	{"dollar_endonly", PCRE2_DOLLAR_ENDONLY},
	{"dotall", PCRE2_DOTALL},
	{"dupnames", PCRE2_DUPNAMES},
	{"extended", PCRE2_EXTENDED},
	{"firstline", PCRE2_FIRSTLINE},
	{"match_unset_backref", PCRE2_MATCH_UNSET_BACKREF},
	{"multiline", PCRE2_MULTILINE},
	{"never_ucp", PCRE2_NEVER_UCP},
	{"never_utf", PCRE2_NEVER_UTF},
	{"no_auto_capture", PCRE2_NO_AUTO_CAPTURE},
	{"no_auto_possess", PCRE2_NO_AUTO_POSSESS},
	{"no_dotstar_anchor", PCRE2_NO_DOTSTAR_ANCHOR},
	{"no_start_optimize", PCRE2_NO_START_OPTIMIZE},
	{"ucp", PCRE2_UCP},
	{"ungreedy", PCRE2_UNGREEDY},
	{"utf", PCRE2_UTF},
	{"never_backslash_c", PCRE2_NEVER_BACKSLASH_C},
	{"alt_circumflex", PCRE2_ALT_CIRCUMFLEX},
	{"alt_verbnames", PCRE2_ALT_VERBNAMES},
	{"use_offset_limit", PCRE2_USE_OFFSET_LIMIT},
	{NULL, 0}
};
#endif

static int http_connect_thread(thread_t *);

/* Configuration stream handling */
static void
free_url(void *data)
{
	url_t *url = data;
	FREE_PTR(url->path);
	FREE_PTR(url->digest);
	FREE_PTR(url->virtualhost);
#ifdef _WITH_REGEX_CHECK_
	if (url->regex) {
		// Free up the regular expression.
		FREE_PTR(url->regex);
		pcre2_code_free(url->pcre2_reCompiled);
		pcre2_match_data_free(url->pcre2_match_data);
#ifndef PCRE2_DONT_USE_JIT
		if (url->pcre2_mcontext)
			pcre2_match_context_free(url->pcre2_mcontext);
		if (url->pcre2_jit_stack)
			pcre2_jit_stack_free(url->pcre2_jit_stack);
#endif

	}
#endif
	FREE(url);
}

static char *
format_digest(uint8_t *digest, char *buf)
{
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		snprintf(buf + 2 * i, 2 + 1, "%2.2x", digest[i]);

	return buf;
}

static void
dump_url(FILE *fp, void *data)
{
	url_t *url = data;
	char digest_buf[2 * MD5_DIGEST_LENGTH + 1];

	conf_write(fp, "   Checked url = %s", url->path);
	if (url->digest)
		conf_write(fp, "     digest = %s", format_digest(url->digest, digest_buf));
	if (url->status_code)
		conf_write(fp, "     HTTP Status Code = %d", url->status_code);
	if (url->virtualhost)
		conf_write(fp, "     Virtual host = %s", url->virtualhost);
#ifdef _WITH_REGEX_CHECK_
	if (url->regex) {
		char options_buf[512];
		char *op;
		int i;

		conf_write(fp, "     Regex = \"%s\"", url->regex);
		if (url->regex_no_match)
			conf_write(fp, "     Regex no match");
		if (url->pcre2_options) {
			op = options_buf;
			for (i = 0; regex_options[i].option; i++) {
				if (url->pcre2_options & regex_options[i].option_bit) {
					*op++ = ' ';
					strcpy(op, regex_options[i].option);
					op += strlen(op);
				}
			}
		}
		else
			options_buf[0] = '\0';
		conf_write(fp, "     Regex options:%s", options_buf);
	}
#endif
}

static void
free_http_request(request_t *req)
{
	if(!req)
		return;
	if (req->ssl)
		SSL_free(req->ssl);
	if (req->buffer)
		FREE(req->buffer);
	FREE(req);
}

static void
free_http_get_check(void *data)
{
	http_checker_t *http_get_chk = CHECKER_DATA(data);
	request_t *req = http_get_chk->req;

	free_list(&http_get_chk->url);
	free_http_request(req);
	FREE_PTR(http_get_chk->virtualhost);
	FREE_PTR(http_get_chk);
	FREE_PTR(CHECKER_CO(data));
	FREE(data);
}

static void
dump_http_get_check(FILE *fp, void *data)
{
	checker_t *checker = data;
	http_checker_t *http_get_chk = checker->data;

	conf_write(fp, "   Keepalive method = %s_GET",
			http_get_chk->proto == PROTO_HTTP ? "HTTP" : "SSL");
	dump_checker_opts(fp, checker);
	if (http_get_chk->virtualhost)
		conf_write(fp, "   Virtualhost = %s", http_get_chk->virtualhost);
	dump_list(fp, http_get_chk->url);
}
static http_checker_t *
alloc_http_get(char *proto)
{
	http_checker_t *http_get_chk;

	http_get_chk = (http_checker_t *) MALLOC(sizeof (http_checker_t));
	http_get_chk->proto =
	    (!strcmp(proto, "HTTP_GET")) ? PROTO_HTTP : PROTO_SSL;
	http_get_chk->url = alloc_list(free_url, dump_url);
	http_get_chk->virtualhost = NULL;

	if (http_get_chk->proto == PROTO_SSL)
		check_data->ssl_required = true;

	return http_get_chk;
}

static bool
http_get_check_compare(void *a, void *b)
{
	http_checker_t *old = CHECKER_DATA(a);
	http_checker_t *new = CHECKER_DATA(b);
	size_t n;
	url_t *u1, *u2;

	if (!compare_conn_opts(CHECKER_CO(a), CHECKER_CO(b)))
		return false;
	if (LIST_SIZE(old->url) != LIST_SIZE(new->url))
		return false;
	if (!old->virtualhost != !new->virtualhost)
		return false;
	if (old->virtualhost && strcmp(old->virtualhost, new->virtualhost))
		return false;
	for (n = 0; n < LIST_SIZE(new->url); n++) {
		u1 = (url_t *)list_element(old->url, n);
		u2 = (url_t *)list_element(new->url, n);
		if (strcmp(u1->path, u2->path))
			return false;
		if (!u1->digest != !u2->digest)
			return false;
		if (u1->digest && memcmp(u1->digest, u2->digest, MD5_DIGEST_LENGTH))
			return false;
		if (u1->status_code != u2->status_code)
			return false;
		if (!u1->virtualhost != !u2->virtualhost)
			return false;
		if (u1->virtualhost && strcmp(u1->virtualhost, u2->virtualhost))
			return false;
#ifdef _WITH_REGEX_CHECK_
		if (!u1->regex != !u2->regex ||
		    (u1->regex && strcmp((char *)u1->regex, (char *)u2->regex)))
			return false;
		if (u1->pcre2_options != u2->pcre2_options)
			return false;
		if (u1->regex_no_match != u2->regex_no_match)
			return false;
#endif
	}

	return true;
}

static void
http_get_handler(vector_t *strvec)
{
	checker_t *checker;
	http_checker_t *http_get_chk;
	char *str = strvec_slot(strvec, 0);

	/* queue new checker */
	http_get_chk = alloc_http_get(str);
	checker = queue_checker(free_http_get_check, dump_http_get_check,
		      http_connect_thread, http_get_check_compare,
		      http_get_chk, CHECKER_NEW_CO());
	checker->default_delay_before_retry = 3 * TIMER_HZ;
}

static void
http_get_retry_handler(vector_t *strvec)
{
	checker_t *checker = LIST_TAIL_DATA(checkers_queue);
	checker->retry = CHECKER_VALUE_UINT(strvec);
}

static void
virtualhost_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	http_get_chk->virtualhost = CHECKER_VALUE_STRING(strvec);
}

static void
http_get_check(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	if (LIST_ISEMPTY(http_get_chk->url)) {
		log_message(LOG_INFO, "HTTP/SSL_GET checker has no urls specified - ignoring");
		dequeue_new_checker();
	}

	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
}

static void
url_handler(__attribute__((unused)) vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *new;

	/* allocate the new URL */
	new = (url_t *) MALLOC(sizeof (url_t));

	list_add(http_get_chk->url, new);
}

static void
path_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->path = CHECKER_VALUE_STRING(strvec);
}

static void
digest_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);
	char *digest;
	char *endptr;
	int i;

	digest = CHECKER_VALUE_STRING(strvec);

	if (url->digest) {
		log_message(LOG_INFO, "Digest '%s' is a duplicate", digest);
		return;
	}

	if (strlen(digest) != 2 * MD5_DIGEST_LENGTH) {
		log_message(LOG_INFO, "digest '%s' character length should be %d rather than %zd", digest, 2 * MD5_DIGEST_LENGTH, strlen(digest));
		return;
	}

	url->digest = MALLOC(MD5_DIGEST_LENGTH);

	for (i = MD5_DIGEST_LENGTH - 1; i >= 0; i--) {
		digest[2 * i + 2] = '\0';
		url->digest[i] = strtoul(digest + 2 * i, &endptr, 16);
		if (endptr != digest + 2 * i + 2) {
			log_message(LOG_INFO, "Unable to interpret hex digit in '%s' at offset %d/%d", digest, 2 * i, 2 * i + 1);
			FREE(url->digest);
			url->digest = NULL;
			return;
		}
	}

}

static void
status_code_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->status_code = CHECKER_VALUE_INT(strvec);
}

static void
url_virtualhost_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->virtualhost = CHECKER_VALUE_STRING(strvec);
}

#ifdef _WITH_REGEX_CHECK_
static void
regex_handler(__attribute__((unused)) vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);
	vector_t* strvec_qe = alloc_strvec_quoted_escaped(NULL);

	if (vector_size(strvec_qe) != 2) {
		log_message(LOG_INFO, "regex missing or too many fields");
		free_strvec(strvec_qe);
		return;
	}

	url->regex = CHECKER_VALUE_STRING(strvec_qe);
	free_strvec(strvec_qe);
}

static void
regex_no_match_handler(__attribute__((unused)) vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	url->regex_no_match = true;
}

static void
regex_options_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);
	unsigned i, j;
	char *str;

	for (i = 1; i < vector_size(strvec); i++) {
		str = strvec_slot(strvec, i);

		for (j = 0; regex_options[j].option; j++) {
			if (!strcmp(str, regex_options[j].option)) {
				url->pcre2_options |= regex_options[j].option_bit;
				break;
			}
		}
	}
}

static void
prepare_regex(url_t *url)
{
	int pcreErrorNumber;
	PCRE2_SIZE pcreErrorOffset;
	PCRE2_UCHAR buffer[256];

	url->pcre2_reCompiled = pcre2_compile(url->regex, PCRE2_ZERO_TERMINATED, url->pcre2_options, &pcreErrorNumber, &pcreErrorOffset, NULL);

	// pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr
	if(url->pcre2_reCompiled == NULL) {
		pcre2_get_error_message(pcreErrorNumber, buffer, sizeof buffer);
		log_message(LOG_INFO, "Invalid regex: '%s' at offset %zu: %s\n", url->regex, pcreErrorOffset, (char *)buffer);

		FREE_PTR(url->regex);

		return;
	}

	url->pcre2_match_data = pcre2_match_data_create_from_pattern(url->pcre2_reCompiled, NULL);
	pcre2_pattern_info(url->pcre2_reCompiled, PCRE2_INFO_MAXLOOKBEHIND, &url->pcre2_max_lookbehind);

#ifndef PCRE2_DONT_USE_JIT
	if ((pcreErrorNumber = pcre2_jit_compile(url->pcre2_reCompiled, PCRE2_JIT_PARTIAL_HARD /* | PCRE2_JIT_COMPLETE */))) {
		pcre2_get_error_message(pcreErrorNumber, buffer, sizeof buffer);
		log_message(LOG_INFO, "Regex JIT compilation failed: '%s': %s\n", url->regex, (char *)buffer);

		return;
	}

	url->pcre2_mcontext = pcre2_match_context_create(NULL);
	url->pcre2_jit_stack = pcre2_jit_stack_create(32 * 1024, 512 * 1024, NULL);
	pcre2_jit_stack_assign(url->pcre2_mcontext, NULL, url->pcre2_jit_stack);
#endif
}
#endif

#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
static void
enable_sni_handler(vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			log_message(LOG_INFO, "Invalid enable_sni parameter %s", FMT_STR_VSLOT(strvec, 1));
			return;
		}
	}
	http_get_chk->enable_sni = res;
}
#endif

static void
url_check(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = LIST_TAIL_DATA(http_get_chk->url);

	if (!url->path) {
		log_message(LOG_INFO, "HTTP/SSL_GET checker url has no path - ignoring");
		free_list_element(http_get_chk->url, http_get_chk->url->tail);
		return;
	}
#ifdef _WITH_REGEX_CHECK_
	if (url->regex)
		prepare_regex(url);
#endif
}
static void
install_http_ssl_check_keyword(const char *keyword)
{
	install_keyword(keyword, &http_get_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_keyword("nb_get_retry", &http_get_retry_handler);	/* Deprecated */
	install_keyword("virtualhost", &virtualhost_handler);
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	install_keyword("enable_sni", &enable_sni_handler);
#endif
	install_keyword("url", &url_handler);
	install_sublevel();
	install_keyword("path", &path_handler);
	install_keyword("digest", &digest_handler);
	install_keyword("status_code", &status_code_handler);
	install_keyword("virtualhost", &url_virtualhost_handler);
#ifdef _WITH_REGEX_CHECK_
	install_keyword("regex", &regex_handler);
	install_keyword("regex_no_match", &regex_no_match_handler);
	install_keyword("regex_options", &regex_options_handler);
#endif
	install_sublevel_end_handler(url_check);
	install_sublevel_end();
	install_sublevel_end_handler(http_get_check);
	install_sublevel_end();
}

void
install_http_check_keyword(void)
{
	install_http_ssl_check_keyword("HTTP_GET");
}

void
install_ssl_check_keyword(void)
{
	install_http_ssl_check_keyword("SSL_GET");
}

/*
 * The global design of this checker is the following :
 *
 * - All the actions are done asynchronously.
 * - All the actions handle timeout connection.
 * - All the actions handle error from low layer to upper
 *   layers.
 *
 * The global synopsis of the inter-thread-call is :
 *
 *     http_connect_thread (handle layer4 connect)
 *            v
 *     http_check_thread (handle SSL connect)
 *            v
 *     http_request_thread (send SSL GET request)
 *            v
 *     http_response_thread (initialize read stream step)
 *         /             \
 *        /               \
 *       v                 v
 *  http_read_thread   ssl_read_thread (perform HTTP|SSL stream)
 *       v              v
 *     http_handle_response (next checker thread registration)
 */

/*
 * Simple epilog functions. Handling event timeout.
 * Finish the checker with memory managment or url rety check.
 *
 * c == 0 => reset to 0 retry_it counter
 * t == 0 => reset to 0 url_it counter
 * method == 1 => register a new checker thread
 * method == 2 => register a retry on url checker thread
 */
static int
epilog(thread_t * thread, int method, unsigned t, unsigned c)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	unsigned long delay = 0;
	bool checker_was_up;
	bool rs_was_alive;

	http_get_check->url_it += t ? t : -http_get_check->url_it;
	checker->retry_it += c ? c : -checker->retry_it;

	if (method == REGISTER_CHECKER_NEW && http_get_check->url_it >= LIST_SIZE(http_get_check->url)) {
		/* All the url have been successfully checked.
		 * Check completed.
		 * check if server is currently alive.
		 */
		if (!checker->is_up || !checker->has_run) {
			log_message(LOG_INFO, "Remote Web server %s succeed on service."
					    , FMT_HTTP_RS(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (!checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK succeed on service <=");
		}

		/* Reset it counters */
		http_get_check->url_it = 0;
		checker->retry_it = 0;
	}
	/*
	 * The get retry implementation mean that we retry performing
	 * a GET on the same url until the remote web server return
	 * html buffer. This is sometime needed with some applications
	 * servers.
	 */
	else if (method == REGISTER_CHECKER_RETRY && checker->retry_it > checker->retry) {
		if (checker->is_up || !checker->has_run) {
			if (checker->has_run && checker->retry)
				log_message(LOG_INFO
				   , "Check on service %s failed after %u retry."
				   , FMT_HTTP_RS(checker)
				   , checker->retry_it - 1);
			else
				log_message(LOG_INFO
				   , "Check on service %s failed."
				   , FMT_HTTP_RS(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK failed on service"
					   " : HTTP request failed <=");
		}

		/* Reset it counters */
		http_get_check->url_it = 0;
		checker->retry_it = 0;
	}

	/* register next timer thread */
	switch (method) {
	case REGISTER_CHECKER_NEW:
		delay = checker->delay_loop;
		break;
	case REGISTER_CHECKER_RETRY:
		if (http_get_check->url_it == 0 && checker->retry_it == 0)
			delay = checker->delay_loop;
		else
			delay = checker->delay_before_retry;
		break;
	}

	/* If req == NULL, fd is not created */
	if (req) {
		free_http_request(req);
		http_get_check->req = NULL;
		close(thread->u.fd);
	}

	/* Register next checker thread */
	thread_add_timer(thread->master, http_connect_thread, checker, delay);
	return 0;
}

int
timeout_epilog(thread_t * thread, const char *debug_msg)
{
	checker_t *checker = THREAD_ARG(thread);

	/* check if server is currently alive */
	if (checker->is_up) {
		log_message(LOG_INFO, "%s server %s."
				    , debug_msg
				    , FMT_HTTP_RS(checker));
		return epilog(thread, REGISTER_CHECKER_RETRY, 0, 1);
	}

	/* do not retry if server is already known as dead */
	return epilog(thread, REGISTER_CHECKER_NEW, 0, 0);
}

/* return the url pointer of the current url iterator  */
static url_t *
fetch_next_url(http_checker_t * http_get_check)
{
	return list_element(http_get_check->url, http_get_check->url_it);
}

#ifdef _WITH_REGEX_CHECK_
/* Returns true to indicate buffer must be preserved */
static bool
check_regex(url_t *url, request_t *req)
{
	PCRE2_SIZE *ovector;
	int pcreExecRet;
	size_t keep;

	if (req->regex_matched)
		return false;

#ifndef PCRE2_DONT_USE_JIT
	pcreExecRet = pcre2_jit_match
#else
	pcreExecRet = pcre2_match
#endif
				(url->pcre2_reCompiled,
				 (unsigned char *)req->buffer,
				 req->len,		// length of string
				 req->start_offset,	// Start looking at this point
				 PCRE2_PARTIAL_HARD,	// OPTIONS
				 url->pcre2_match_data,
#ifndef PCRE2_DONT_USE_JIT
				 url->pcre2_mcontext
#else
				 NULL
#endif
				);			// context

	if (pcreExecRet == PCRE2_ERROR_PARTIAL) {
		ovector = pcre2_get_ovector_pointer(url->pcre2_match_data);
#ifdef _REGEX_DEBUG_
		log_message(LOG_INFO, "Partial returned, ovector %ld, max_lookbehind %u", ovector[0], url->pcre2_max_lookbehind);
#endif
		if ((keep = ovector[0] - url->pcre2_max_lookbehind) <= 0)
			keep = 0;

		if (keep) {
			req->start_offset = url->pcre2_max_lookbehind;
			req->len -= keep;
			memmove(req->buffer, req->buffer + keep, req->len);
		} else if (req->len == MAX_BUFFER_LENGTH) {
			log_message(LOG_INFO, "Regex partial match preserve too large - discarding");
			return false;
		}

		return true;
	}

	req->start_offset = 0;

	/* Report what happened in the pcre2_match call. */
	if(pcreExecRet < 0) {
		switch(pcreExecRet)
		{
		case PCRE2_ERROR_NOMATCH:
			/* This is not an error while doing partial matches */
#ifdef _REGEX_DEBUG_
			log_message(LOG_INFO, "String did not match the regex pattern");
#endif
			break;
		case PCRE2_ERROR_NULL:
			log_message(LOG_INFO, "Something was null in regex match");
			break;
		case PCRE2_ERROR_BADOPTION:
			log_message(LOG_INFO, "A bad option was passed to regex");
			break;
		case PCRE2_ERROR_BADMAGIC:
			log_message(LOG_INFO, "Magic number bad (compiled regex corrupt?)");
			break;
		case PCRE2_ERROR_NOMEMORY:
			log_message(LOG_INFO, "Regex an out of memory");
			break;
		default:
			log_message(LOG_INFO, "Unknown regex error %d", pcreExecRet);
			break;
		}

		return false;
	}

	req->regex_matched = true;

#ifdef _REGEX_DEBUG_
	log_message(LOG_INFO, "Result: We have a match!");
	ovector = pcre2_get_ovector_pointer(url->pcre2_match_data);
	log_message(LOG_INFO, "Match succeeded at offset %zu", ovector[0]);

	if(pcreExecRet == 0)
		log_message(LOG_INFO, "Too many substrings found");
#endif

	return false;
}
#endif

/* Handle response */
int
http_handle_response(thread_t * thread, unsigned char digest[MD5_DIGEST_LENGTH]
		     , bool empty_buffer)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	int r;
	url_t *url = fetch_next_url(http_get_check);
	enum {
		NONE,
		ON_SUCCESS,
		ON_STATUS,
		ON_DIGEST,
#ifdef _WITH_REGEX_CHECK_
		ON_REGEX,
#endif
	} last_success = NONE; /* the source of last considered success */

	/* First check if remote webserver returned data */
	if (empty_buffer)
		return timeout_epilog(thread, "Read, no data received from ");

	/* Next check the HTTP status code */
	if (url->status_code) {
		if (req->status_code != url->status_code)
			return timeout_epilog(thread, "HTTP status code error to");

		last_success = ON_STATUS;
	}
	else if (req->status_code >= 200 && req->status_code <= 299)
		last_success = ON_SUCCESS;

	/* Report a length mismatch the first time we get the specific difference */
	if (req->content_len != SIZE_MAX && req->content_len != req->rx_bytes) {
		if (url->len_mismatch != (ssize_t)req->content_len - (ssize_t)req->rx_bytes) {
			log_message(LOG_INFO, "http_check for RS %s VS %s url %s%s: content_length (%lu) does not match received bytes (%lu)",
				    FMT_RS(checker->rs, checker->vs), FMT_VS(checker->vs), url->virtualhost ? url->virtualhost : "",
				    url->path, req->content_len, req->rx_bytes);
			url->len_mismatch = (ssize_t)req->content_len - (ssize_t)req->rx_bytes;
		}
	}
	else
		url->len_mismatch = 0;

	/* Continue with MD5SUM */
	if (url->digest) {
		/* Compute MD5SUM */
		r = memcmp(url->digest, digest, MD5_DIGEST_LENGTH);

		if (r)
			return timeout_epilog(thread, "MD5 digest error to");
		last_success = ON_DIGEST;
	}

#ifdef _WITH_REGEX_CHECK_
	/* Did a regex match? */
	if (url->regex) {
		if (req->regex_matched == url->regex_no_match)
			return timeout_epilog(thread, "Regex match failed");
		last_success = ON_REGEX;
	}
#endif

	if (!checker->is_up) {
		switch (last_success) {
			case NONE:
				break;
			case ON_SUCCESS:
				log_message(LOG_INFO,
				       "HTTP success to %s url(%u)."
				       , FMT_HTTP_RS(checker)
				       , http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
			case ON_STATUS:
				log_message(LOG_INFO,
				       "HTTP status code success to %s url(%u)."
				       , FMT_HTTP_RS(checker)
				       , http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
			case ON_DIGEST:
				log_message(LOG_INFO,
					"MD5 digest success to %s url(%u)."
					, FMT_HTTP_RS(checker)
					, http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
#ifdef _WITH_REGEX_CHECK_
			case ON_REGEX:
				log_message(LOG_INFO,
					"Regex match success to %s url(%u)."
					, FMT_HTTP_RS(checker)
					, http_get_check->url_it + 1);
				return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;
#endif
		}
	}

	return epilog(thread, REGISTER_CHECKER_NEW, 0, 0) + 1;
}

/* Handle response stream performing MD5 updates */
void
http_process_response(request_t *req, size_t r, url_t *url)
{
	size_t old_req_len = req->len;

	req->len += r;

	if (!req->extracted) {
		if ((req->extracted = extract_html(req->buffer, req->len))) {
			req->status_code = extract_status_code(req->buffer, req->len);
			req->content_len = extract_content_length(req->buffer, req->len);
			r = req->len - (size_t)(req->extracted - req->buffer);
			if (r && url->digest) {
				if (req->content_len == SIZE_MAX || req->content_len > req->rx_bytes)
					MD5_Update(&req->context, req->extracted,
						   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes);
			}

			req->rx_bytes = r;
#ifdef _WITH_REGEX_CHECK_
			if (!r || !url->regex || !check_regex(url, req))
#endif
				req->len = 0;
		}
	} else if (req->len) {
		if (url->digest &&
		    (req->content_len == SIZE_MAX || req->content_len > req->rx_bytes)) {
			MD5_Update(&req->context, req->buffer + old_req_len,
				   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes);
		}

		req->rx_bytes += req->len;
#ifdef _WITH_REGEX_CHECK_
		if (!url->regex || !check_regex(url, req))
#endif
			req->len = 0;
	}
}

/* Asynchronous HTTP stream reader */
static int
http_read_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = fetch_next_url(http_get_check);
	unsigned timeout = checker->co->connection_to;
	unsigned char digest[MD5_DIGEST_LENGTH];
	ssize_t r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "Timeout HTTP read");

	/* read the HTTP stream */
	r = read(thread->u.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - req->len);

	/* Test if data are ready */
	if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
		log_message(LOG_INFO, "Read error with server %s: %s"
				    , FMT_HTTP_RS(checker)
				    , strerror(errno));
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
		return 0;
	}

	if (r == -1 || r == 0) {	/* -1:error , 0:EOF */
		/* All the HTTP stream has been parsed */
		if (url->digest)
			MD5_Final(digest, &req->context);

		if (r == -1) {
			/* We have encountered a real read error */
			return timeout_epilog(thread, "Read error with");
		}

		/* Handle response stream */
		http_handle_response(thread, digest, !req->extracted);
	} else {
		/* Handle response stream */
		http_process_response(req, (size_t)r, url);

		/*
		 * Register next http stream reader.
		 * Register itself to not perturbe global I/O multiplexer.
		 */
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
	}

	return 0;
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
static int
http_response_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = fetch_next_url(http_get_check);
	unsigned timeout = checker->co->connection_to;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT)
		return timeout_epilog(thread, "Timeout WEB read");

	/* Allocate & clean the get buffer */
	req->buffer = (char *) MALLOC(MAX_BUFFER_LENGTH);
	req->extracted = NULL;
	req->len = 0;
	req->error = 0;
#ifdef _WITH_REGEX_CHECK_
	req->regex_matched = false;
#endif
	if (url->digest)
		MD5_Init(&req->context);

	/* Register asynchronous http/ssl read thread */
	if (http_get_check->proto == PROTO_SSL)
		thread_add_read(thread->master, ssl_read_thread, checker,
				thread->u.fd, timeout);
	else
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.fd, timeout);
	return 0;
}

/* remote Web server is connected, send it the get url query.  */
static int
http_request_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	struct sockaddr_storage *addr = &checker->co->dst;
	unsigned timeout = checker->co->connection_to;
	char *vhost;
	char *request_host;
	char request_host_port[7];	/* ":" [0-9][0-9][0-9][0-9][0-9] "\0" */
	char *str_request;
	url_t *fetched_url;
	int ret = 0;

	/* Handle write timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT)
		return timeout_epilog(thread, "Timeout WEB write");

	/* Allocate & clean the GET string */
	str_request = (char *) MALLOC(GET_BUFFER_LENGTH);

	fetched_url = fetch_next_url(http_get_check);

	if (fetched_url->virtualhost)
		vhost = fetched_url->virtualhost;
	else if (http_get_check->virtualhost)
		vhost = http_get_check->virtualhost;
	else if (checker->rs->virtualhost)
		vhost = checker->rs->virtualhost;
	else if (checker->vs->virtualhost)
		vhost = checker->vs->virtualhost;
	else
		vhost = NULL;

	if (vhost) {
		/* If vhost was defined we don't need to override it's port */
		request_host = vhost;
		request_host_port[0] = '\0';
	} else {
		request_host = inet_sockaddrtos(addr);

		snprintf(request_host_port, sizeof(request_host_port), ":%d",
			 ntohs(inet_sockaddrport(addr)));
	}

	if(addr->ss_family == AF_INET6 && !vhost){
		/* if literal ipv6 address, use ipv6 template, see RFC 2732 */
		snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE_IPV6,
			fetched_url->path, request_host, request_host_port);
	} else {
		snprintf(str_request, GET_BUFFER_LENGTH, REQUEST_TEMPLATE,
			fetched_url->path, request_host, request_host_port);
	}

	DBG("Processing url(%u) of %s.", http_get_check->url_it + 1 , FMT_HTTP_RS(checker));

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL)
		ret = ssl_send_request(req->ssl, str_request, (int)strlen(str_request));
	else
		ret = (send(thread->u.fd, str_request, strlen(str_request), 0) != -1);

	FREE(str_request);

	if (!ret)
		return timeout_epilog(thread, "Cannot send get request to");

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, checker,
			thread->u.fd, timeout);
	return 1;
}

/* WEB checkers threads */
int
http_check_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
#ifdef _DEBUG_
	request_t *req = http_get_check->req;
#endif
	int ret = 1;
	int status;
	unsigned long timeout = 0;
	int ssl_err = 0;
	bool new_req = false;

	status = tcp_socket_state(thread, http_check_thread);
	switch (status) {
	case connect_error:
		return timeout_epilog(thread, "Error connecting");
		break;

	case connect_timeout:
		return timeout_epilog(thread, "Timeout connecting");
		break;

	case connect_success:
		if (!http_get_check->req) {
			http_get_check->req = (request_t *) MALLOC(sizeof (request_t));
			new_req = true;
		} else
			new_req = false;

		if (http_get_check->proto == PROTO_SSL) {
			timeout = timer_long(thread->sands) - timer_long(time_now);
			if (thread->type != THREAD_WRITE_TIMEOUT &&
			    thread->type != THREAD_READ_TIMEOUT)
				ret = ssl_connect(thread, new_req);
			else
				return timeout_epilog(thread, "Timeout connecting");

			if (ret == -1) {
				switch ((ssl_err = SSL_get_error(http_get_check->req->ssl,
								 ret))) {
				case SSL_ERROR_WANT_READ:
					thread_add_read(thread->master,
							http_check_thread,
							THREAD_ARG(thread),
							thread->u.fd, timeout);
					break;
				case SSL_ERROR_WANT_WRITE:
					thread_add_write(thread->master,
							 http_check_thread,
							 THREAD_ARG(thread),
							 thread->u.fd, timeout);
					break;
				default:
					ret = 0;
					break;
				}
				if (ret == -1)
					break;
			} else if (ret != 1)
				ret = 0;
		}

		if (ret) {
			/* Remote WEB server is connected.
			 * Register the next step thread ssl_request_thread.
			 */
			DBG("Remote Web server %s connected.", FMT_HTTP_RS(checker));
			thread_add_write(thread->master,
					 http_request_thread, checker,
					 thread->u.fd,
					 checker->co->connection_to);
		} else {
			DBG("Connection trouble to: %s."
					 , FMT_HTTP_RS(checker));
#ifdef _DEBUG_
			if (http_get_check->proto == PROTO_SSL)
				ssl_printerr(SSL_get_error
					     (req->ssl, ret));
#endif
			return timeout_epilog(thread, "SSL handshake/communication error"
						 " connecting to");
		}
		break;
	}

	return 0;
}

static int
http_connect_thread(thread_t * thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	conn_opts_t *co = checker->co;
	url_t *fetched_url;
	enum connect_result status;
	int fd;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!checker->enabled) {
		thread_add_timer(thread->master, http_connect_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	/* if there are no URLs in list, enable server w/o checking */
	fetched_url = fetch_next_url(http_get_check);
	if (!fetched_url)
		return epilog(thread, REGISTER_CHECKER_NEW, 1, 0) + 1;

	/* Create the socket */
	if ((fd = socket(co->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "WEB connection fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->delay_loop);

		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on http_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on http_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if(tcp_connection_state(fd, status, thread, http_check_thread,
			co->connection_to)) {
		close(fd);
		log_message(LOG_INFO, "WEB socket bind failed. Rescheduling");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->delay_loop);
	}

	return 0;
}

#ifdef _TIMER_DEBUG_
void
print_check_http_addresses(void)
{
	log_message(LOG_INFO, "Address of dump_http_get_check() is 0x%p", dump_http_get_check);
	log_message(LOG_INFO, "Address of http_check_thread() is 0x%p", http_check_thread);
	log_message(LOG_INFO, "Address of http_connect_thread() is 0x%p", http_connect_thread);
	log_message(LOG_INFO, "Address of http_read_thread() is 0x%p", http_read_thread);
	log_message(LOG_INFO, "Address of http_request_thread() is 0x%p", http_request_thread);
	log_message(LOG_INFO, "Address of http_response_thread() is 0x%p", http_response_thread);
}
#endif
