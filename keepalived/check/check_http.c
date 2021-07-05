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
#include <openssl/md5.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef _WITH_REGEX_CHECK_
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "check_api.h"
#include "check_http.h"
#include "check_ssl.h"
#include "bitops.h"
#include "logger.h"
#include "parser.h"
#include "utils.h"
#include "html.h"
#include "layer4.h"
#include "ipwrapper.h"
#include "smtp.h"
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

typedef enum {
	REGISTER_CHECKER_NEW,
	REGISTER_CHECKER_RETRY,
	REGISTER_CHECKER_FAILED
} register_checker_t;


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

/* Used for holding regex details during configuration */
static const unsigned char *conf_regex_pattern;
static int conf_regex_options;

#ifndef PCRE2_DONT_USE_JIT
static PCRE2_SIZE jit_stack_start;
static PCRE2_SIZE jit_stack_max;

static pcre2_match_context *mcontext;
static pcre2_jit_stack *jit_stack;
#endif

static LIST_HEAD_INITIALIZE(regexs);	/* regex_t */

#ifdef _WITH_REGEX_TIMERS_
struct timespec total_regex_times;
unsigned total_num_matches;
unsigned total_regex_urls;
bool do_regex_timers;
#endif
#endif

#ifdef _REGEX_DEBUG_
bool do_regex_debug;
#endif

/* GET processing command */
static const char *request_template =
			"GET %s HTTP/1.%d\r\n"
			"User-Agent: KeepAliveClient\r\n"
			"%s"
			"Host: %s%s\r\n\r\n";

static const char *request_template_ipv6 =
			"GET %s HTTP/1.%d\r\n"
			"User-Agent: KeepAliveClient\r\n"
			"%s"
			"Host: [%s]%s\r\n\r\n";

/* Output delimiters */
#define DELIM_BEGIN             "-----------------------["
#define DELIM_END               "]-----------------------\n"
#define HTTP_HEADER_HEXA        DELIM_BEGIN"    HTTP Header Buffer    "DELIM_END
#define HTTP_HEADER_ASCII       DELIM_BEGIN" HTTP Header Ascii Buffer "DELIM_END
#define HTML_HEADER_HEXA        DELIM_BEGIN"        HTML Buffer        "DELIM_END
#define HTML_HASH               DELIM_BEGIN"    HTML hash resulting    "DELIM_END
#define HTML_HASH_FINAL         DELIM_BEGIN" HTML hash final resulting "DELIM_END

#ifdef _WITH_REGEX_CHECK_
static void
free_regex(regex_t *regex)
{
	list_del_init(&regex->e_list);
	/* Free up the regular expression. */
	FREE_CONST_PTR(regex->pattern);
	pcre2_code_free(regex->pcre2_reCompiled);
	pcre2_match_data_free(regex->pcre2_match_data);

#ifdef _WITH_REGEX_TIMERS_
	total_regex_times.tv_sec += regex->regex_time.tv_sec;
	total_regex_times.tv_nsec += regex->regex_time.tv_nsec;
	if (total_regex_times.tv_nsec >= 1000000000L) {
		total_regex_times.tv_sec += total_regex_times.tv_nsec / 1000000000L;
		total_regex_times.tv_nsec %= 1000000000L;
	}
	total_num_matches += regex->num_match_calls;
	total_regex_urls += regex->num_regex_urls;
#endif

	FREE(regex);
}
#endif

static void
free_url(url_t *url)
{
	list_del_init(&url->e_list);
	FREE_CONST_PTR(url->path);
	FREE_CONST_PTR(url->digest);
	FREE_CONST_PTR(url->virtualhost);
#ifdef _WITH_REGEX_CHECK_
	if (url->regex) {
		if (!--url->regex->refcnt) {
			free_regex(url->regex);

			if (list_empty(&regexs)) {
#ifndef PCRE2_DONT_USE_JIT
				if (mcontext) {
					pcre2_match_context_free(mcontext);
					mcontext = NULL;
				}
				if (jit_stack) {
					pcre2_jit_stack_free(jit_stack);
					jit_stack = NULL;
				}
#endif

#ifdef _WITH_REGEX_TIMERS_
				if (do_regex_timers)
					log_message(LOG_INFO, "Total regex time %ld.%9.9ld, num match calls %u, num url checks %u", total_regex_times.tv_sec, total_regex_times.tv_nsec, total_num_matches, total_regex_urls);
#endif
			}
		}
	}
#endif
	FREE(url);
}
static void
free_url_list(list_head_t *l)
{
	url_t *url, *url_tmp;

	list_for_each_entry_safe(url, url_tmp, l, e_list)
		free_url(url);
}

static char *
format_digest(const uint8_t *digest, char *buf)
{
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		snprintf(buf + 2 * i, 2 + 1, "%2.2x", digest[i]);

	return buf;
}

static void
dump_url(FILE *fp, const url_t *url)
{
	char digest_buf[2 * MD5_DIGEST_LENGTH + 1];
	unsigned int i = 0;
	unsigned min = 0;

	conf_write(fp, "   Checked url = %s", url->path);
	if (url->digest)
		conf_write(fp, "     digest = %s", format_digest(url->digest, digest_buf));

	conf_write(fp, "     HTTP Status Code(s)");
	for (i = HTTP_STATUS_CODE_MIN; i <= HTTP_STATUS_CODE_MAX; i++) {
		if (__test_bit_array(i - HTTP_STATUS_CODE_MIN, url->status_code)) {
			if (!min)
				min = i;
		} else {
			if (!min)
				continue;
			if (i - 1 == min)
				conf_write(fp, "       %u", min);
			else
				conf_write(fp, "       %u-%u", min, i - 1);
			min = 0;
		}
	}
	if (min == HTTP_STATUS_CODE_MAX)
		conf_write(fp, "       %u", min);
	else if (min)
		conf_write(fp, "       %u-%d", min, HTTP_STATUS_CODE_MAX);

	if (url->virtualhost)
		conf_write(fp, "     Virtual host = %s", url->virtualhost);

#ifdef _WITH_REGEX_CHECK_
	if (url->regex) {
		char options_buf[512] = "";
		char *op;

		conf_write(fp, "     Regex = \"%s\"", url->regex->pattern);
		if (url->regex_no_match)
			conf_write(fp, "     Regex no match");
		if (url->regex_min_offset || url->regex_max_offset) {
			if (url->regex_max_offset)
				conf_write(fp, "     Regex min offset = %zu, max_offset = %zu", url->regex_min_offset, url->regex_max_offset - 1);
			else
				conf_write(fp, "     Regex min offset = %zu", url->regex_min_offset);
		}

		if (url->regex->pcre2_options) {
			op = options_buf;
			for (i = 0; regex_options[i].option; i++) {
				if (regex_options[i].option_bit) {
					*op++ = ' ';
					strcpy(op, regex_options[i].option);
					op += strlen(op);
				}
			}
		}
		conf_write(fp, "     Regex options:%s", options_buf);
		conf_write(fp, "     Regex ref count = %u", url->regex->refcnt);
#ifndef PCRE2_DONT_USE_JIT
		if (url->regex_use_stack)
			conf_write(fp, "     Regex stack start %zu, max %zu", jit_stack_start, jit_stack_max);
#endif
	}
#endif
}
static void
dump_url_list(FILE *fp, const list_head_t *l)
{
	url_t *url;

	list_for_each_entry(url, l, e_list)
		dump_url(fp, url);
}

static void
free_http_request(request_t *req)
{
	if(!req)
		return;
	if (req->ssl)
		SSL_free(req->ssl);
	FREE_PTR(req->buffer);
	FREE(req);
}

void
free_http_check(checker_t *checker)
{
	http_checker_t *http_get_chk = checker->data;

	free_url_list(&http_get_chk->url);
	free_http_request(http_get_chk->req);
	FREE_CONST_PTR(http_get_chk->virtualhost);
	FREE_PTR(http_get_chk);
	FREE(checker->co);
	FREE(checker);
}

static void
dump_http_check(FILE *fp, const checker_t *checker)
{
	const http_checker_t *http_get_chk = checker->data;

	conf_write(fp, "   Keepalive method = %s_GET, http protocol %s",
			http_get_chk->proto == PROTO_HTTP ? "HTTP" : "SSL",
			http_get_chk->http_protocol == HTTP_PROTOCOL_1_0C ? "1.0C" :
			  http_get_chk->http_protocol == HTTP_PROTOCOL_1_1 ? "1.1" : "1.0");
	if (http_get_chk->virtualhost)
		conf_write(fp, "   Virtualhost = %s", http_get_chk->virtualhost);
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	conf_write(fp, "   Enable SNI %sset", http_get_chk->enable_sni ? "" : "un");
#endif
	conf_write(fp, "   Fast recovery %sset", http_get_chk->fast_recovery ? "" : "un");
	dump_url_list(fp, &http_get_chk->url);
	if (http_get_chk->failed_url)
		conf_write(fp, "   Failed URL = %s", http_get_chk->failed_url->path);
}
static http_checker_t *
alloc_http_get(const char *proto)
{
	http_checker_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->url);
	new->proto = (!strcmp(proto, "HTTP_GET")) ? PROTO_HTTP : PROTO_SSL;
	new->http_protocol = HTTP_PROTOCOL_1_0;
	new->virtualhost = NULL;

	if (new->proto == PROTO_SSL)
		check_data->ssl_required = true;

	return new;
}

static size_t __attribute__ ((pure))
url_list_size(const list_head_t *l)
{
	size_t cnt = 0;
	list_head_t *e;

	list_for_each(e, l)
		cnt++;
	return cnt;
}

static bool __attribute__((pure))
compare_http_check(const checker_t *old_c, checker_t *new_c)
{
	const http_checker_t *old = old_c->data;
	const http_checker_t *new = new_c->data;
	url_t *u1, *u2 = NULL;
	unsigned i;

	if (!compare_conn_opts(old_c->co, new_c->co))
		return false;
	if (url_list_size(&old->url) != url_list_size(&new->url))
		return false;
	if (!old->virtualhost != !new->virtualhost)
		return false;
	if (old->virtualhost && strcmp(old->virtualhost, new->virtualhost))
		return false;

	list_for_each_entry(u1, &old->url, e_list) {
		u2 = (!u2) ? list_first_entry(&new->url, url_t, e_list) :
			     list_entry(u2->e_list.next, url_t, e_list);
		if (strcmp(u1->path, u2->path))
			return false;
		if (!u1->digest != !u2->digest)
			return false;
		if (u1->digest && memcmp(u1->digest, u2->digest, MD5_DIGEST_LENGTH))
			return false;
		for (i = 0; i < sizeof(u1->status_code) / sizeof(u1->status_code[0]); i++) {
			if (u1->status_code[i] != u2->status_code[i])
				return false;
		}
		if (!u1->virtualhost != !u2->virtualhost)
			return false;
		if (u1->virtualhost && strcmp(u1->virtualhost, u2->virtualhost))
			return false;
#ifdef _WITH_REGEX_CHECK_
		if (!u1->regex != !u2->regex)
			return false;
		if (u1->regex) {
			if (strcmp(PTR_CAST_CONST(char, u1->regex->pattern), PTR_CAST_CONST(char, u2->regex->pattern)))
				return false;
			if (u1->regex->pcre2_options != u2->regex->pcre2_options)
				return false;
			if (u1->regex_no_match != u2->regex_no_match)
				return false;
			if (u1->regex_min_offset != u2->regex_min_offset ||
			    u1->regex_max_offset != u2->regex_max_offset)
				return false;
		}
#endif
	}

	return true;
}

static const checker_funcs_t http_checker_funcs = { CHECKER_HTTP, free_http_check, dump_http_check, compare_http_check, NULL };

/* Configuration stream handling */
static void
http_get_handler(const vector_t *strvec)
{
	checker_t *checker;
	http_checker_t *http_get_chk;
	const char *str = strvec_slot(strvec, 0);

	/* queue new checker */
	http_get_chk = alloc_http_get(str);
	checker = queue_checker(&http_checker_funcs, http_connect_thread, http_get_chk, CHECKER_NEW_CO(), true);
	checker->default_delay_before_retry = 3 * TIMER_HZ;
}

static void
http_get_retry_handler(const vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	unsigned retry;

	report_config_error(CONFIG_GENERAL_ERROR, "nb_get_retry is deprecated - please use 'retry'");

	if (!read_unsigned_strvec(strvec, 1, &retry, 0, UINT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid nb_get_retry value '%s'", strvec_slot(strvec, 1));
		return;
	}

	checker->retry = retry;
}

static void
virtualhost_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "HTTP_GET virtualhost name missing");
		return;
	}

	http_get_chk->virtualhost = set_value(strvec);
}

static void
http_get_check_end(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	if (list_empty(&http_get_chk->url)) {
		report_config_error(CONFIG_GENERAL_ERROR, "HTTP/SSL_GET checker has no urls specified - ignoring");
		dequeue_new_checker();
	}

	if (!check_conn_opts(CHECKER_GET_CO())) {
		dequeue_new_checker();
	}
}

static void
url_handler(__attribute__((unused)) const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *new;

	/* allocate the new URL */
	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	list_add_tail(&new->e_list, &http_get_chk->url);

#ifdef _WITH_REGEX_CHECK_
	conf_regex_options = 0;
#endif

	http_get_chk->url_it = list_first_entry(&http_get_chk->url, url_t, e_list);
}

static void
path_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);

	url->path = set_value(strvec);
}

static void
digest_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);
	char *digest;
	char *endptr;
	int i;
	uint8_t *digest_buf;

	digest = STRDUP(strvec_slot(strvec, 1));

	if (url->digest) {
		report_config_error(CONFIG_GENERAL_ERROR, "Digest '%s' is a duplicate", digest);
		FREE(digest);
		return;
	}

	if (strlen(digest) != 2 * MD5_DIGEST_LENGTH) {
		report_config_error(CONFIG_GENERAL_ERROR, "digest '%s' character length should be %d rather than %zu", digest, 2 * MD5_DIGEST_LENGTH, strlen(digest));
		FREE(digest);
		return;
	}

	digest_buf = MALLOC(MD5_DIGEST_LENGTH);

	for (i = MD5_DIGEST_LENGTH - 1; i >= 0; i--) {
		digest[2 * i + 2] = '\0';
		digest_buf[i] = strtoul(digest + 2 * i, &endptr, 16);
		if (endptr != digest + 2 * i + 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to interpret hex digit in '%s' at offset %d/%d", digest, 2 * i, 2 * i + 1);
			FREE(digest_buf);
			FREE(digest);
			return;
		}
	}

	url->digest = digest_buf;

	FREE_CONST(digest);
}

static void
status_code_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);
	const char *str;
	unsigned int i, j;
	char *endptr;
	unsigned min, max;

	for (i = 1; i < vector_size(strvec); i++) {
		str = vector_slot(strvec, i);

		min = strtoul(str, &endptr, 10);
		if (*endptr == '-')
			max = strtoul(endptr + 1, &endptr, 10);
		else
			max = min;
		if (*endptr ||
		    min < HTTP_STATUS_CODE_MIN || min > HTTP_STATUS_CODE_MAX ||
		    max < HTTP_STATUS_CODE_MIN || max > HTTP_STATUS_CODE_MAX ||
		    min > max) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid HTTP_GET status code '%s'", str);
			continue;
		}

		for (j = min; j <= max; j++)
			__set_bit_array(j - HTTP_STATUS_CODE_MIN, url->status_code);
	}
}

static void
url_virtualhost_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "Missing HTTP_GET virtualhost name");
		return;
	}

	url->virtualhost = set_value(strvec);
}

static void
http_protocol_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "Missing http_protocol version");
		return;
	}

	if (!strcmp(strvec_slot(strvec, 1), "1.0"))
		http_get_chk->http_protocol = HTTP_PROTOCOL_1_0;
	else if (!strcmp(strvec_slot(strvec, 1), "1.1"))
		http_get_chk->http_protocol = HTTP_PROTOCOL_1_1;
	else if (!strcmp(strvec_slot(strvec, 1), "1.0C") ||
		 !strcmp(strvec_slot(strvec, 1), "1.0c"))
		http_get_chk->http_protocol = HTTP_PROTOCOL_1_0C;
	else {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid http_protocol version %s", strvec_slot(strvec, 1));
		return;
	}
}

#ifdef _WITH_REGEX_CHECK_
static void
regex_handler(__attribute__((unused)) const vector_t *strvec)
{
	const vector_t *strvec_qe = alloc_strvec_quoted_escaped(NULL);

	if (vector_size(strvec_qe) != 2) {
		log_message(LOG_INFO, "regex missing or too many fields");
		free_strvec(strvec_qe);
		return;
	}

	conf_regex_pattern = PTR_CAST_CONST(unsigned char, set_value(strvec_qe));
	free_strvec(strvec_qe);
}

static void
regex_no_match_handler(__attribute__((unused)) const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);

	url->regex_no_match = true;
}

static void
regex_options_handler(const vector_t *strvec)
{
	unsigned i, j;
	const char *str;

	for (i = 1; i < vector_size(strvec); i++) {
		str = strvec_slot(strvec, i);

		for (j = 0; regex_options[j].option; j++) {
			if (!strcmp(str, regex_options[j].option)) {
				conf_regex_options |= regex_options[j].option_bit;
				break;
			}
		}
	}
}

static size_t
regex_offset_handler(const vector_t *strvec, const char *type)
{
	char *endptr;
	unsigned long val;

	if (vector_size(strvec) != 2) {
		log_message(LOG_INFO, "Missing or too may options for regex_%s_offset", type);
		return 0;
	}

	val = strtoul(vector_slot(strvec, 1), &endptr, 10);
	if (*endptr) {
		log_message(LOG_INFO, "Invalid regex_%s_offset %s specified", type, strvec_slot(strvec, 1));
		return 0;
	}

	return (size_t)val;
}

static void
regex_min_offset_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);

	url->regex_min_offset = regex_offset_handler(strvec, "min");
}

static void
regex_max_offset_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);

	/* regex_max_offset is one beyond last acceptable position */
	url->regex_max_offset = regex_offset_handler(strvec, "max") + 1;
}

#ifndef PCRE2_DONT_USE_JIT
static void
regex_stack_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);
	unsigned long stack_start, stack_max;
	char *endptr;

	if (vector_size(strvec) != 3) {
		log_message(LOG_INFO, "regex_stack requires start and max values");
		return;
	}

	stack_start = strtoul(vector_slot(strvec, 1), &endptr, 10);
	if (*endptr) {
		log_message(LOG_INFO, "regex_stack invalid start value");
		return;
	}

	stack_max = strtoul(vector_slot(strvec, 2), &endptr, 10);
	if (*endptr) {
		log_message(LOG_INFO, "regex_stack invalid max value");
		return;
	}

	if (stack_start > stack_max) {
		log_message(LOG_INFO, "regex stack start cannot exceed max value");
		return;
	}

	if (stack_start > jit_stack_start)
		jit_stack_start = stack_start;
	if (stack_max > jit_stack_max)
		jit_stack_max = stack_max;
	url->regex_use_stack = true;
}
#endif

static void
prepare_regex(url_t *url)
{
	int pcreErrorNumber;
	PCRE2_SIZE pcreErrorOffset;
	PCRE2_UCHAR buffer[256];
	regex_t *r;

	/* See if this regex has already been specified */
	list_for_each_entry(r, &regexs, e_list) {
		if (r->pcre2_options == conf_regex_options &&
		    !strcmp(PTR_CAST_CONST(char, r->pattern), PTR_CAST_CONST(char, conf_regex_pattern))) {
			url->regex = r;
			FREE_CONST_PTR(conf_regex_pattern);
			url->regex->refcnt++;

			return;
		}
	}

	/* This is a new regex */
	PMALLOC(r);
	INIT_LIST_HEAD(&r->e_list);
	r->pattern = conf_regex_pattern;
	r->pcre2_options = conf_regex_options;
	conf_regex_pattern = NULL;
	r->refcnt = 1;
	r->pcre2_reCompiled = pcre2_compile(r->pattern, PCRE2_ZERO_TERMINATED, r->pcre2_options,
					    &pcreErrorNumber, &pcreErrorOffset, NULL);
	url->regex = r;

	/* pcre_compile returns NULL on error, and sets pcreErrorOffset & pcreErrorStr */
	if(r->pcre2_reCompiled == NULL) {
		pcre2_get_error_message(pcreErrorNumber, buffer, sizeof buffer);
		log_message(LOG_INFO, "Invalid regex: '%s' at offset %zu: %s\n"
				    , r->pattern, pcreErrorOffset, PTR_CAST(char, buffer));

		FREE_CONST_PTR(r->pattern);
		FREE(r);

		return;
	}

	r->pcre2_match_data = pcre2_match_data_create_from_pattern(r->pcre2_reCompiled, NULL);
	pcre2_pattern_info(r->pcre2_reCompiled, PCRE2_INFO_MAXLOOKBEHIND, &r->pcre2_max_lookbehind);

#ifndef PCRE2_DONT_USE_JIT
	if ((pcreErrorNumber = pcre2_jit_compile(r->pcre2_reCompiled, PCRE2_JIT_PARTIAL_HARD /* | PCRE2_JIT_COMPLETE */))) {
		pcre2_get_error_message(pcreErrorNumber, buffer, sizeof buffer);
		log_message(LOG_INFO, "Regex JIT compilation failed: '%s': %s\n"
				    , r->pattern, PTR_CAST(char, buffer));

		FREE_CONST_PTR(r->pattern);
		FREE(r);

		return;
	}
#endif

	list_add_tail(&r->e_list, &regexs);
}
#endif

#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
static void
enable_sni_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid enable_sni parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	http_get_chk->enable_sni = res;
}
#endif

static void
fast_recovery_handler(const vector_t *strvec)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	int res = true;

	if (vector_size(strvec) >= 2) {
		res = check_true_false(strvec_slot(strvec, 1));
		if (res == -1) {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid fast_recovery parameter %s", strvec_slot(strvec, 1));
			return;
		}
	}
	http_get_chk->fast_recovery = res;
}

static void
url_check(void)
{
	http_checker_t *http_get_chk = CHECKER_GET();
	url_t *url = list_last_entry(&http_get_chk->url, url_t, e_list);
	unsigned i;

	if (!url->path) {
		report_config_error(CONFIG_GENERAL_ERROR, "HTTP/SSL_GET checker url has no path - ignoring");
		free_url(url);
		return;
	}

	/* Set default status codes if none set */
	for (i = 0; i < sizeof(url->status_code) / sizeof(url->status_code[0]); i++) {
		if (url->status_code[i])
			break;
	}
	if (i >= sizeof(url->status_code) / sizeof(url->status_code[0])) {
		for (i = HTTP_DEFAULT_STATUS_CODE_MIN; i <= HTTP_DEFAULT_STATUS_CODE_MAX; i++)
			__set_bit_array(i - HTTP_STATUS_CODE_MIN, url->status_code);
	}

#ifdef _WITH_REGEX_CHECK_
	if (conf_regex_pattern)
		prepare_regex(url);
	else if (conf_regex_options
		 || url->regex_no_match
		 || url->regex_min_offset
		 || url->regex_max_offset
#ifndef PCRE2_DONT_USE_JIT
		 || url->regex_use_stack
#endif
					 ) {
		log_message(LOG_INFO, "regex parameters specified without regex");
		conf_regex_options = 0;
		url->regex_no_match = false;
		url->regex_min_offset = 0;
		url->regex_max_offset = 0;
#ifndef PCRE2_DONT_USE_JIT
		url->regex_use_stack = false;
#endif
	}

	if (url->regex_max_offset && url->regex_min_offset >= url->regex_max_offset) {
		log_message(LOG_INFO, "regex min offset %zu > regex_max_offset %zu - ignoring", url->regex_min_offset, url->regex_max_offset - 1);
		url->regex_min_offset = url->regex_max_offset = 0;
	}
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
	install_keyword("http_protocol", &http_protocol_handler);
#ifdef _HAVE_SSL_SET_TLSEXT_HOST_NAME_
	install_keyword("enable_sni", &enable_sni_handler);
#endif
	install_keyword("fast_recovery", &fast_recovery_handler);
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
	install_keyword("regex_min_offset", &regex_min_offset_handler);
	install_keyword("regex_max_offset", &regex_max_offset_handler);
#ifndef PCRE2_DONT_USE_JIT
	install_keyword("regex_stack", &regex_stack_handler);
#endif
#endif
	install_sublevel_end_handler(url_check);
	install_sublevel_end();
	install_sublevel_end_handler(http_get_check_end);
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
 * Finish the checker with memory management or url rety check.
 *
 * method == REGISTER_CHECKER_NEW => register a new checker thread
 * method == REGISTER_CHECKER_RETRY => register a retry on url checker thread
 * method == REGISTER_CHECKER_FAILED => register a checker on the failed URL
 */
static void
epilog(thread_ref_t thread, register_checker_t method)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	unsigned long delay = 0;
	bool checker_was_up;
	bool rs_was_alive;

	if (method == REGISTER_CHECKER_NEW) {
		if (list_is_last(&http_get_check->url_it->e_list, &http_get_check->url))
			http_get_check->url_it = NULL;
		else
			http_get_check->url_it = list_entry(http_get_check->url_it->e_list.next, url_t, e_list);
		checker->retry_it = 0;
	} else if (method == REGISTER_CHECKER_RETRY)
		checker->retry_it++;

	if (method == REGISTER_CHECKER_NEW && !http_get_check->url_it && !http_get_check->failed_url) {
		/* Check completed. All the url have been successfully checked.
		 * check if server is currently alive.
		 */
		if (!checker->is_up || !checker->has_run) {
			log_message(LOG_INFO, "Remote Web server %s succeed on service."
					    , FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(UP, checker);
			if (!checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK succeed on service <=");

			/* We have done all the checks, so mark as has run */
			checker->has_run = true;
		}

		/* Reset it counters */
		http_get_check->url_it = list_first_entry(&http_get_check->url, url_t, e_list);
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
				   , "HTTP_CHECK on service %s failed after %u retries."
				   , FMT_CHK(checker)
				   , checker->retry_it - 1);
			else
				log_message(LOG_INFO
				   , "HTTP_CHECK on service %s failed."
				   , FMT_CHK(checker));
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker_was_up && checker->rs->smtp_alert &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
				smtp_alert(SMTP_MSG_RS, checker, NULL,
					   "=> CHECK failed on service"
					   " : HTTP request failed <=");
		}

		/* Mark we have a failed URL */
		http_get_check->failed_url = http_get_check->url_it;
	}
	else if (method == REGISTER_CHECKER_NEW && http_get_check->failed_url) {
		/* If the failed URL is now up, check all the URLs */
		http_get_check->failed_url = NULL;
		http_get_check->url_it = list_first_entry(&http_get_check->url, url_t, e_list);
		checker->retry_it = 0;
	}

	/* register next timer thread */
	if (method == REGISTER_CHECKER_NEW) {
		delay = checker->delay_loop;
		if (!checker->has_run)
			checker->retry_it = checker->retry;
	}
	else if (http_get_check->failed_url)
		delay = checker->delay_before_retry > checker->delay_loop ? checker->delay_before_retry : checker->delay_loop;
	else
		delay = checker->delay_before_retry;

	/* If req == NULL, fd is not created */
	if (req) {
		free_http_request(req);
		http_get_check->req = NULL;
		thread_close_fd(thread);
	}

	/* Register next checker thread.
	 * If the checker is not up, but we are not aware of any failure,
	 * don't delay the checks if fast_recovery option specified. */
	if (http_get_check->fast_recovery &&
	    (!checker->has_run ||
	     (!checker->is_up && !http_get_check->failed_url)))
		thread_add_event(thread->master, http_connect_thread, checker, 0);
	else
		thread_add_timer(thread->master, http_connect_thread, checker, delay);

	return;
}

void
timeout_epilog(thread_ref_t thread, const char *debug_msg)
{
	checker_t *checker = THREAD_ARG(thread);

	/* check if server is currently alive */
	if (checker->is_up || !checker->has_run) {
		if (((http_checker_t *)checker->data)->genhash_flags & GENHASH) {
			printf("Connection timed out\n");
			thread_add_terminate_event(thread->master);
			return;
		}
		if (global_data->checker_log_all_failures || checker->log_all_failures)
			log_message(LOG_INFO, "%s server %s."
					    , debug_msg
					    , FMT_CHK(checker));
		checker->has_run = true;
		epilog(thread, REGISTER_CHECKER_RETRY);
		return;
	}

	/* do not retry if server is already known as dead */
	epilog(thread, REGISTER_CHECKER_FAILED);
}

/* return the url pointer of the current url iterator  */
static inline url_t *
fetch_next_url(http_checker_t * http_get_check)
{
	return http_get_check->url_it;
}

#ifdef _WITH_REGEX_CHECK_
/* Returns true to indicate buffer must be preserved */
static bool
check_regex(url_t *url, request_t *req)
{
	PCRE2_SIZE *ovector;
	int pcreExecRet;
	size_t keep;
	size_t start_offset = 0;

#ifdef _REGEX_DEBUG_
	if (do_regex_debug)
		log_message(LOG_INFO, "matched %d, min_offset %zu max_offset %zu, subject_offset %zu req->len %zu lookbehind %u start_offset %zu"
#ifdef _WITH_REGEX_TIMERS_
				", num_match_calls %u"
#endif
							,
				req->regex_matched, url->regex_min_offset, url->regex_max_offset, req->regex_subject_offset,
				req->len, url->regex->pcre2_max_lookbehind, req->start_offset
#ifdef _WITH_REGEX_TIMERS_
				, req->num_match_calls
#endif
			);
#endif

	/* If we have already matched the regex, there is no point in checking
	 * any further */
	if (req->regex_matched)
		return false;

	/* If the end of the current buffer doesn't reach the start offset specified,
	 * then skip the check */
	if (url->regex_min_offset) {
		if (req->regex_subject_offset + req->len < url->regex_min_offset - url->regex->pcre2_max_lookbehind) {
			req->regex_subject_offset += req->len;
			return false;
		}

		if (req->regex_subject_offset < url->regex_min_offset)
			start_offset = url->regex_min_offset - req->regex_subject_offset;
	}

	/* If we are beyond the end of where we want to check, then don't try matching */
	if (url->regex_max_offset &&
	    req->regex_subject_offset + req->start_offset >= url->regex_max_offset) {
		req->regex_subject_offset += req->len;
		return false;
	}

#ifndef PCRE2_DONT_USE_JIT
	if (url->regex_use_stack && !mcontext) {
		mcontext = pcre2_match_context_create(NULL);
		jit_stack = pcre2_jit_stack_create(jit_stack_start, jit_stack_max, NULL);
		pcre2_jit_stack_assign(mcontext, NULL, jit_stack);
	}
#endif

	if (req->start_offset > start_offset)
		start_offset = req->start_offset;

#ifdef _WITH_REGEX_TIMERS_
	struct timespec time_before, time_after;
	clock_gettime(CLOCK_MONOTONIC_RAW, &time_before);
#endif

#ifndef PCRE2_DONT_USE_JIT
	pcreExecRet = pcre2_jit_match
#else
	pcreExecRet = pcre2_match
#endif
				(url->regex->pcre2_reCompiled,
				 PTR_CAST(unsigned char, req->buffer),
				 req->len,
				 start_offset,
				 PCRE2_PARTIAL_HARD,
				 url->regex->pcre2_match_data,
#ifndef PCRE2_DONT_USE_JIT
				 url->regex_use_stack ? mcontext : NULL
#else
				 NULL
#endif
				);			// context

#ifdef _WITH_REGEX_TIMERS_
	clock_gettime(CLOCK_MONOTONIC_RAW, &time_after);
	req->req_time.tv_sec += time_after.tv_sec - time_before.tv_sec;
	req->req_time.tv_nsec += time_after.tv_nsec - time_before.tv_nsec;
	if (req->req_time.tv_nsec >= 1000000000L) {
		req->req_time.tv_sec += req->req_time.tv_nsec / 1000000000L;
		req->req_time.tv_nsec %= 1000000000L;
	}
	req->num_match_calls++;
#endif
	req->start_offset = 0;

	if (pcreExecRet == PCRE2_ERROR_PARTIAL) {
		ovector = pcre2_get_ovector_pointer(url->regex->pcre2_match_data);
#ifdef _REGEX_DEBUG_
		if (do_regex_debug)
			log_message(LOG_INFO, "Partial returned, ovector %zu, max_lookbehind %u", ovector[0], url->regex->pcre2_max_lookbehind);
#endif
		if ((keep = ovector[0] - url->regex->pcre2_max_lookbehind) <= 0)
			keep = 0;

		if (keep) {
			req->start_offset = url->regex->pcre2_max_lookbehind;
			req->len -= keep;
			memmove(req->buffer, req->buffer + keep, req->len);
			req->regex_subject_offset += keep;
		} else if (req->len == MAX_BUFFER_LENGTH - 1) {
			req->regex_subject_offset += req->len;
			log_message(LOG_INFO, "Regex partial match preserve too large - discarding");
			return false;
		}

		return true;
	}

	/* Report what happened in the pcre2_match call. */
	if(pcreExecRet < 0) {
		req->regex_subject_offset += req->len;

		switch(pcreExecRet)
		{
		case PCRE2_ERROR_NOMATCH:
			/* This is not an error while doing partial matches */
#ifdef _REGEX_DEBUG_
			if (do_regex_debug)
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

	if(pcreExecRet == 0)
		log_message(LOG_INFO, "Too many substrings found");

	ovector = pcre2_get_ovector_pointer(url->regex->pcre2_match_data);

	/* Check if there was a match at or before regex_max_offset */
	if (!url->regex_max_offset ||
	    (req->regex_subject_offset + ovector[0] < url->regex_max_offset)) {
		req->regex_matched = true;
#ifdef _REGEX_DEBUG_
		if (do_regex_debug)
			log_message(LOG_INFO, "Result: We have a match at offset %zu - \"%.*s\"", req->regex_subject_offset + ovector[0], (int)(ovector[1] - ovector[0]), req->buffer + ovector[0]);
	}
	else {
		log_message(LOG_INFO, "Match found but %zu bytes beyond regex_max_offset(%zu)", req->regex_subject_offset + ovector[0] - (url->regex_max_offset - 1), url->regex_max_offset - 1);
#endif
	}

	req->regex_subject_offset += req->len;

	return false;
}
#endif

/* Handle response */
void
http_handle_response(thread_ref_t thread, unsigned char digest[MD5_DIGEST_LENGTH],
		     bool empty_buffer)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = fetch_next_url(http_get_check);
	const char *msg = "HTTP status code";
	int r;

	/* Genhash mode ? */
	if (http_get_check->genhash_flags) {
		if (empty_buffer) {
			fprintf(stderr, "no data received from remote webserver\n");
		} else {
			for (r = 0; r < MD5_DIGEST_LENGTH; r++)
				printf("%02x", digest[r]);
			printf("\n");
		}

		thread_add_terminate_event(thread->master);
		return;
	}

	/* First check if remote webserver returned data */
	if (empty_buffer) {
		timeout_epilog(thread, "Read, no data received from ");
		return;
	}

	/* Next check the HTTP status code */
	if (req->status_code < HTTP_STATUS_CODE_MIN ||
	    req->status_code > HTTP_STATUS_CODE_MAX ||
	    !__test_bit_array(req->status_code - HTTP_STATUS_CODE_MIN, url->status_code)) {
		timeout_epilog(thread, "HTTP status code error to");
		return;
	}

	/* Report a length mismatch the first time we get the specific difference */
	if (req->content_len != SIZE_MAX && req->content_len != req->rx_bytes) {
		if (url->len_mismatch != (ssize_t)req->content_len - (ssize_t)req->rx_bytes) {
			log_message(LOG_INFO, "http_check for RS %s VS %s url %s%s:"
					      " content_length (%zu) does not match received bytes (%zu)"
					    , FMT_RS(checker->rs, checker->vs)
					    , FMT_VS(checker->vs)
					    , url->virtualhost ? url->virtualhost : ""
					    , url->path, req->content_len, req->rx_bytes);
			url->len_mismatch = (ssize_t)req->content_len - (ssize_t)req->rx_bytes;
		}
	} else
		url->len_mismatch = 0;

	/* Continue with MD5SUM */
	if (url->digest) {
		/* Compute MD5SUM */
		r = memcmp(url->digest, digest, MD5_DIGEST_LENGTH);

		if (r) {
			timeout_epilog(thread, "MD5 digest error to");
			return;
		}
		msg = "MD5 digest";
	}

#ifdef _WITH_REGEX_CHECK_
	/* Did a regex match? */
	if (url->regex) {
#ifdef _WITH_REGEX_TIMERS_
		url->regex->regex_time.tv_sec += req->req_time.tv_sec;
		url->regex->regex_time.tv_nsec += req->req_time.tv_nsec;
		if (url->regex->regex_time.tv_nsec >= 1000000000L) {
			url->regex->regex_time.tv_sec += url->regex->regex_time.tv_nsec / 1000000000L;
			url->regex->regex_time.tv_nsec %= 1000000000L;
		}
		url->regex->num_match_calls += req->num_match_calls;
		url->regex->num_regex_urls++;
#endif

		if (req->regex_matched == url->regex_no_match) {
			timeout_epilog(thread, "Regex match failed");
			return;
		}
		msg = "Regex match";
	}
#endif

	if (!checker->is_up) {
		log_message(LOG_INFO,
			"%s success to %s url(%s)", msg
			, FMT_CHK(checker)
			, url->path);
		epilog(thread, REGISTER_CHECKER_NEW);
		return;
	}

	epilog(thread, REGISTER_CHECKER_NEW);
}

/* Dump HTTP header */
static void
http_dump_header(char *buffer, size_t size)
{
        dump_buffer(buffer, size, stdout, 0);
        printf(HTTP_HEADER_ASCII);
        printf("%.*s\n", (int)size, buffer);
}

void
dump_digest(unsigned char *digest, unsigned len)
{
	printf("\n");
	printf(HTML_HASH);
	dump_buffer(PTR_CAST(char, digest), len, stdout, 0);

	printf(HTML_HASH_FINAL);
}

/* Handle response stream performing MD5 updates */
void
http_process_response(thread_ref_t thread, request_t *req, size_t r, url_t *url)
{
	size_t old_req_len = req->len;
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);

	req->len += r;
	req->buffer[req->len] = '\0';	/* Terminate the received data since it is used as a string */

	if (!req->extracted) {
		if (http_get_check->genhash_flags & GENHASH_VERBOSE)
			printf(HTTP_HEADER_HEXA);
		if ((req->extracted = extract_html(req->buffer, req->len))) {
			req->status_code = extract_status_code(req->buffer, req->len);
			req->content_len = extract_content_length(req->buffer, req->len);

			if (http_get_check->genhash_flags & GENHASH_VERBOSE)
                                http_dump_header(req->buffer, req->extracted - req->buffer);

			r = req->len - (size_t)(req->extracted - req->buffer);
			if (r && url->digest) {
				if (req->content_len == SIZE_MAX || req->content_len > req->rx_bytes) {
					EVP_DigestUpdate(req->context, req->extracted,
						   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes);
					if (http_get_check->genhash_flags & GENHASH_VERBOSE) {
						printf(HTML_HEADER_HEXA);
						dump_buffer(req->extracted, req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes, stdout, 0);
					}
				}
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
			EVP_DigestUpdate(req->context, req->buffer + old_req_len,
				   req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes);
			if (http_get_check->genhash_flags & GENHASH_VERBOSE)
				dump_buffer(req->buffer + old_req_len, req->content_len == SIZE_MAX || req->content_len >= req->rx_bytes + r ? r : req->content_len - req->rx_bytes, stdout, 0);
		}

		req->rx_bytes += req->len;
#ifdef _WITH_REGEX_CHECK_
		if (!url->regex || !check_regex(url, req))
#endif
			req->len = 0;
	}
}

/* Asynchronous HTTP stream reader */
static void
http_read_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = fetch_next_url(http_get_check);
	unsigned timeout = checker->co->connection_to;
	unsigned char digest[MD5_DIGEST_LENGTH];
	ssize_t r = 0;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		timeout_epilog(thread, "Timeout HTTP read");
		return;
	}

	/* read the HTTP stream */
	r = read(thread->u.f.fd, req->buffer + req->len,
		 MAX_BUFFER_LENGTH - 1 - req->len);	/* Allow space for adding '\0' */

	/* Test if data are ready */
	if (r == -1 && (check_EAGAIN(errno) || check_EINTR(errno))) {
		log_message(LOG_INFO, "Read error with server %s: %s"
				    , FMT_CHK(checker)
				    , strerror(errno));
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
		return;
	}

	if (r <= 0) {	/* -1:error , 0:EOF */
		/* All the HTTP stream has been parsed */
		if (url->digest) {
			EVP_DigestFinal_ex(req->context, digest, NULL);
			EVP_MD_CTX_free(req->context);
			req->context = NULL;
			if (http_get_check->genhash_flags & GENHASH_VERBOSE)
				dump_digest(digest, MD5_DIGEST_LENGTH);
		}

		if (r == -1) {
			/* We have encountered a real read error */
			timeout_epilog(thread, "Read error with");
			return;
		}

		/* Handle response stream */
		http_handle_response(thread, digest, !req->extracted);
		return;
	}

	/* Handle response stream */
	http_process_response(thread, req, (size_t)r, url);

	/*
	 * Register next http stream reader.
	 * Register itself to not perturbe global I/O multiplexer.
	 */
	thread_add_read(thread->master, http_read_thread, checker,
			thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
}

/*
 * Read get result from the remote web server.
 * Apply trigger check to this result.
 */
static void
http_response_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	url_t *url = fetch_next_url(http_get_check);
	unsigned timeout = checker->co->connection_to;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		timeout_epilog(thread, "Timeout WEB read");
		return;
	}

	/* Allocate & clean the get buffer */
	req->buffer = PTR_CAST(char, MALLOC(MAX_BUFFER_LENGTH));
	req->extracted = NULL;
	req->len = 0;
	req->error = 0;
#ifdef _WITH_REGEX_CHECK_
	req->regex_matched = false;
	req->regex_subject_offset = 0;
#ifdef _WITH_REGEX_TIMERS_
	req->num_match_calls = 0;
#endif
#endif
	if (url->digest) {
		req->context = EVP_MD_CTX_new();
		EVP_DigestInit_ex(req->context, EVP_md5(), NULL);
	}

	/* Register asynchronous http/ssl read thread */
	if (http_get_check->proto == PROTO_SSL)
		thread_add_read(thread->master, ssl_read_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
	else
		thread_add_read(thread->master, http_read_thread, checker,
				thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
}

/* remote Web server is connected, send it the get url query.  */
static void
http_request_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	request_t *req = http_get_check->req;
	struct sockaddr_storage *addr = &checker->co->dst;
	unsigned timeout = checker->co->connection_to;
	const char *vhost;
	const char *request_host;
	char request_host_port[7];	/* ":" [0-9][0-9][0-9][0-9][0-9] "\0" */
	char *str_request;
	url_t *fetched_url;
	int ret = 0;

	/* Handle write timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		timeout_epilog(thread, "Timeout WEB write");
		return;
	}

	/* Allocate & clean the GET string */
	str_request = PTR_CAST(char, MALLOC(GET_BUFFER_LENGTH));

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

		/* if literal ipv6 address, use ipv6 template, see RFC 2732 */
	snprintf(str_request, GET_BUFFER_LENGTH, (addr->ss_family == AF_INET6 && !vhost) ? request_template_ipv6 : request_template,
			fetched_url->path,
			http_get_check->http_protocol == HTTP_PROTOCOL_1_1 ? 1 : 0,
			http_get_check->http_protocol == HTTP_PROTOCOL_1_0C || http_get_check->http_protocol == HTTP_PROTOCOL_1_1 ? "Connection: close\r\n" : "",
			request_host, request_host_port);

#ifdef _CHECKER_DEBUG_
	if (do_checker_debug)
		log_message(LOG_DEBUG, "Processing url(%s) of %s.", fetched_url->path, FMT_CHK(checker));
#endif

	/* Send the GET request to remote Web server */
	if (http_get_check->proto == PROTO_SSL)
		ret = ssl_send_request(req->ssl, str_request, (int)strlen(str_request));
	else
		ret = (send(thread->u.f.fd, str_request, strlen(str_request), 0) != -1);

	FREE(str_request);

	if (!ret) {
		timeout_epilog(thread, "Cannot send get request to");
		return;
	}

	/* Register read timeouted thread */
	thread_add_read(thread->master, http_response_thread, checker,
			thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
	thread_del_write(thread);
	return;
}

/* WEB checkers threads */
static void
http_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	http_checker_t *http_get_check = CHECKER_ARG(checker);
	int ret = 1;
	int status;
	unsigned long timeout = 0;
	int ssl_err = 0;
	bool new_req = false;

	status = tcp_socket_state(thread, http_check_thread, 0);
	switch (status) {
	case connect_error:
		timeout_epilog(thread, "Error connecting");
		return;
		break;

	case connect_timeout:
		timeout_epilog(thread, "Timeout connecting");
		return;
		break;

	case connect_fail:
		timeout_epilog(thread, "Connection failed");
		return;
		break;

	case connect_success:
		if (!http_get_check->req) {
			PMALLOC(http_get_check->req);
			new_req = true;
		} else
			new_req = false;

		if (http_get_check->proto == PROTO_SSL) {
			timeout = timer_long(thread->sands) - timer_long(time_now);
			if (thread->type != THREAD_WRITE_TIMEOUT &&
			    thread->type != THREAD_READ_TIMEOUT)
				ret = ssl_connect(thread, new_req);
			else {
				timeout_epilog(thread, "Timeout connecting");
				return;
			}

			if (ret == -1) {
				switch ((ssl_err = SSL_get_error(http_get_check->req->ssl,
								 ret))) {
				case SSL_ERROR_WANT_READ:
					thread_add_read(thread->master,
							http_check_thread,
							THREAD_ARG(thread),
							thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
					thread_del_write(thread);
					break;
				case SSL_ERROR_WANT_WRITE:
					thread_add_write(thread->master,
							 http_check_thread,
							 THREAD_ARG(thread),
							 thread->u.f.fd, timeout, THREAD_DESTROY_CLOSE_FD);
					thread_del_read(thread);
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
#ifdef _CHECKER_DEBUG_
			if (do_checker_debug)
				log_message(LOG_DEBUG, "Remote Web server %s connected.", FMT_CHK(checker));
#endif
			thread_add_write(thread->master,
					 http_request_thread, checker,
					 thread->u.f.fd,
					 checker->co->connection_to, THREAD_DESTROY_CLOSE_FD);
			thread_del_read(thread);
		} else {
#ifdef _CHECKER_DEBUG_
			if (do_checker_debug)
				log_message(LOG_DEBUG, "Connection trouble to: %s." , FMT_CHK(checker));

			if (http_get_check->proto == PROTO_SSL)
				ssl_printerr(SSL_get_error (http_get_check->req->ssl, ret));
#endif
			timeout_epilog(thread, "SSL handshake/communication error"
						 " connecting to");
			return;
		}
		break;
	}
}

void
http_connect_thread(thread_ref_t thread)
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
		return;
	}

	/* if there are no URLs in list, enable server w/o checking */
	fetched_url = fetch_next_url(http_get_check);
	if (!fetched_url) {
		epilog(thread, REGISTER_CHECKER_NEW);
		return;
	}

	/* Create the socket */
	if ((fd = socket(co->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "WEB connection fail to create socket. Rescheduling.");
		thread_add_timer(thread->master, http_connect_thread, checker,
				checker->delay_loop);

		return;
	}

	status = tcp_bind_connect(fd, co);

	/* handle tcp connection status & register check worker thread */
	if (tcp_connection_state(fd, status, thread, http_check_thread, co->connection_to, 0)) {
		close(fd);
		if (status == connect_fail) {
			timeout_epilog(thread, "HTTP_CHECK - network unreachable");
		} else {
			log_message(LOG_INFO, "WEB socket bind failed. Rescheduling");
			thread_add_timer(thread->master, http_connect_thread, checker,
					 checker->delay_loop);
		}
	}
}

#ifdef THREAD_DUMP
void
register_check_http_addresses(void)
{
	register_thread_address("http_check_thread", http_check_thread);
	register_thread_address("http_connect_thread", http_connect_thread);
	register_thread_address("http_read_thread", http_read_thread);
	register_thread_address("http_request_thread", http_request_thread);
	register_thread_address("http_response_thread", http_response_thread);
}
#endif
