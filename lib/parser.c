/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
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

#include <glob.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <linux/version.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <inttypes.h>

#include "parser.h"
#include "memory.h"
#include "logger.h"
#include "rttables.h"
#include "scheduler.h"
#include "notify.h"
#include "list.h"
#include "bitops.h"
#include "utils.h"


#define DEF_LINE_END	"\n"

#define BOB "{"
#define EOB "}"
#define WHITE_SPACE_STR " \t\f\n\r\v"

typedef struct _defs {
	const char *name;
	size_t name_len;
	const char *value;
	size_t value_len;
	bool multiline;
	const char *(*fn)(const struct _defs *);
	unsigned max_params;
	const char *params;
	const char *params_end;
} def_t;

typedef struct _multiline_stack_ent {
	const char *ptr;
	size_t seq_depth;
} multiline_stack_ent;

/* global vars */
vector_t *keywords;
const char *config_id;
const char *WHITE_SPACE = WHITE_SPACE_STR;
#ifdef _PARSER_DEBUG_
bool do_parser_debug;
#endif
#ifdef _DUMP_KEYWORDS_
bool do_dump_keywords;
#endif

/* local vars */
static vector_t *current_keywords;
static FILE *current_stream;
static const char *current_file_name;
static size_t current_file_line_no;
static int sublevel = 0;
static int skip_sublevel = 0;
static list multiline_stack;
size_t multiline_seq_depth = 0;
static char *buf_extern;
static config_err_t config_err = CONFIG_OK; /* Highest level of config error for --config-test */
static unsigned int random_seed;
bool random_seed_configured;

/* Parameter definitions */
static list defs;

/* Forward declarations for recursion */
static bool read_line(char *, size_t);

void
report_config_error(config_err_t err, const char *format, ...)
{
	va_list args;
	char *format_buf = NULL;

	/* current_file_name will be set if there is more than one config file, in which
	 * case we need to specify the file name. */
	if (current_file_name) {
		/* "(file_name:line_no) format" + '\0' */
		format_buf = MALLOC(1 + strlen(current_file_name) + 1 + 10 + 1 + 1 + strlen(format) + 1);
		sprintf(format_buf, "(%s:%zu) %s", current_file_name, current_file_line_no, format);
	} else if (current_file_line_no) {	/* Set while reading from config files */
		/* "(Line line_no) format" + '\0' */
		format_buf = MALLOC(1 + 5 + 10 + 1 + 1 + strlen(format) + 1);
		sprintf(format_buf, "(%s %zu) %s", "Line", current_file_line_no, format);
	}

	va_start(args, format);

	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		vfprintf(stderr, format_buf ? format_buf : format, args);
		fputc('\n', stderr);

		if (config_err == CONFIG_OK || config_err < err)
			config_err = err;
	}
	else
		vlog_message(LOG_INFO, format_buf ? format_buf : format, args);

	va_end(args);

	if (format_buf)
		FREE(format_buf);
}

config_err_t __attribute__ ((pure))
get_config_status(void)
{
	return config_err;
}

static const char * __attribute__ ((noreturn))
null_strvec(const vector_t *strvec, size_t index)
{
	if (index - 1 < vector_size(strvec) && index > 0 && vector_slot(strvec, index - 1))
		report_config_error(CONFIG_MISSING_PARAMETER, "*** Configuration line starting `%s` is missing a parameter after keyword `%s` at word position %zu", vector_slot(strvec, 0) ? (char *)vector_slot(strvec, 0) : "***MISSING ***", (char *)vector_slot(strvec, index - 1), index + 1);
	else
		report_config_error(CONFIG_MISSING_PARAMETER, "*** Configuration line starting `%s` is missing a parameter at word position %zu", vector_slot(strvec, 0) ? (char *)vector_slot(strvec, 0) : "***MISSING ***", index + 1);

	exit(KEEPALIVED_EXIT_CONFIG);
}

static bool
read_int_func(const char *number, int base, int *res, int min_val, int max_val, __attribute__((unused)) bool ignore_error)
{
	long val;
	char *endptr;
	const char *warn = "";

#ifndef _STRICT_CONFIG_
	if (ignore_error && !__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	errno = 0;
	val = strtol(number, &endptr, base);
	*res = (int)val;

	if (*endptr)
		report_config_error(CONFIG_INVALID_NUMBER, "%sinvalid number '%s'", warn, number);
	else if (errno == ERANGE || val < INT_MIN || val > INT_MAX)
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside integer range", warn, number);
	else if (val < min_val || val > max_val)
		report_config_error(CONFIG_INVALID_NUMBER, "number '%s' outside range [%d, %d]", number, min_val, max_val);
	else
		return true;

#ifdef _STRICT_CONFIG_
	return false;
#else
	return ignore_error && val >= min_val && val <= max_val && !__test_bit(CONFIG_TEST_BIT, &debug);
#endif
}

static bool
read_unsigned_func(const char *number, int base, unsigned *res, unsigned min_val, unsigned max_val, __attribute__((unused)) bool ignore_error)
{
	unsigned long val;
	char *endptr;
	const char *warn = "";
	size_t offset;

#ifndef _STRICT_CONFIG_
	if (ignore_error && !__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	/* In case the string starts with spaces (even in the configuration this
	 * can be achieved by enclosing the number in quotes - e.g. weight "  -100")
	 * skip any leading whitespace */
	offset = strspn(number, WHITE_SPACE);

	errno = 0;
	val = strtoul(number + offset, &endptr, base);
	*res = (unsigned)val;

	if (number[offset] == '-')
		report_config_error(CONFIG_INVALID_NUMBER, "%snegative number '%s'", warn, number);
	else if (*endptr)
		report_config_error(CONFIG_INVALID_NUMBER, "%sinvalid number '%s'", warn, number);
	else if (errno == ERANGE || val > UINT_MAX)
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside unsigned integer range", warn, number);
	else if (val < min_val || val > max_val)
		report_config_error(CONFIG_INVALID_NUMBER, "number '%s' outside range [%u, %u]", number, min_val, max_val);
	else
		return true;

#ifdef _STRICT_CONFIG_
	return false;
#else
	return ignore_error && val >= min_val && val <= max_val && !__test_bit(CONFIG_TEST_BIT, &debug);
#endif
}

static bool
read_unsigned64_func(const char *number, int base, uint64_t *res, uint64_t min_val, uint64_t max_val, __attribute__((unused)) bool ignore_error)
{
	unsigned long long val;
	char *endptr;
	const char *warn = "";
	size_t offset;

#ifndef _STRICT_CONFIG_
	if (ignore_error && !__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	/* In case the string starts with spaces (even in the configuration this
	 * can be achieved by enclosing the number in quotes - e.g. weight "  -100")
	 * skip any leading whitespace */
	offset = strspn(number, WHITE_SPACE);

	errno = 0;
	val = strtoull(number + offset, &endptr, base);
	*res = (unsigned)val;

	if (number[offset] == '-')
		report_config_error(CONFIG_INVALID_NUMBER, "%snegative number '%s'", warn, number);
	else if (*endptr)
		report_config_error(CONFIG_INVALID_NUMBER, "%sinvalid number '%s'", warn, number);
	else if (errno == ERANGE)
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside unsigned 64 bit range", warn, number);
	else if (val < min_val || val > max_val)
		report_config_error(CONFIG_INVALID_NUMBER, "number '%s' outside range [%" PRIu64 ", %" PRIu64 "]", number, min_val, max_val);
	else
		return true;

#ifdef _STRICT_CONFIG_
	return false;
#else
	return ignore_error && val >= min_val && val <= max_val && !__test_bit(CONFIG_TEST_BIT, &debug);
#endif
}

static bool
read_double_func(const char *number, double *res, double min_val, double max_val, __attribute__((unused)) bool ignore_error)
{
	double val;
	char *endptr;
	const char *warn = "";
	int ftype;

#ifndef _STRICT_CONFIG_
	if (ignore_error && !__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	errno = 0;
	val = strtod(number, &endptr);
	*res = val;

	if (*endptr)
		report_config_error(CONFIG_INVALID_NUMBER, "%sinvalid number '%s'", warn, number);
	else if (errno == ERANGE)
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' out of range", warn, number);
	else {
		ftype = fpclassify(val);
		if (ftype == FP_INFINITE)	/* +/- Inf */
			report_config_error(CONFIG_INVALID_NUMBER, "infinite number '%s'", number);
		else if (ftype == FP_NAN)	/* NaN */
			report_config_error(CONFIG_INVALID_NUMBER, "not a number '%s'", number);
		else if (ftype == FP_SUBNORMAL)	{ /* to small */
			*res = 0.0F;
			return true;
		}
		else if (val < min_val || val > max_val)
			report_config_error(CONFIG_INVALID_NUMBER, "number '%s' outside range [%g, %g]", number, min_val, max_val);
		else /* FP_NORMAL or FP_ZERO */
			return true;
	}

#ifdef _STRICT_CONFIG_
	return false;
#else
	return ignore_error && val >= min_val && val <= max_val && !__test_bit(CONFIG_TEST_BIT, &debug);
#endif
}

bool
read_int(const char *str, int *res, int min_val, int max_val, bool ignore_error)
{
	return read_int_func(str, 10, res, min_val, max_val, ignore_error);
}

bool
read_unsigned(const char *str, unsigned *res, unsigned min_val, unsigned max_val, bool ignore_error)
{
	return read_unsigned_func(str, 10, res, min_val, max_val, ignore_error);
}

bool
read_unsigned64(const char *str, uint64_t *res, uint64_t min_val, uint64_t max_val, bool ignore_error)
{
	return read_unsigned64_func(str, 10, res, min_val, max_val, ignore_error);
}

bool
read_double(const char *str, double *res, double min_val, double max_val, bool ignore_error)
{
	return read_double_func(str, res, min_val, max_val, ignore_error);
}

bool
read_int_strvec(const vector_t *strvec, size_t index, int *res, int min_val, int max_val, bool ignore_error)
{
	return read_int_func(strvec_slot(strvec, index), 10, res, min_val, max_val, ignore_error);
}

bool
read_unsigned_strvec(const vector_t *strvec, size_t index, unsigned *res, unsigned min_val, unsigned max_val, bool ignore_error)
{
	return read_unsigned_func(strvec_slot(strvec, index), 10, res, min_val, max_val, ignore_error);
}

bool
read_unsigned64_strvec(const vector_t *strvec, size_t index, uint64_t *res, uint64_t min_val, uint64_t max_val, bool ignore_error)
{
	return read_unsigned64_func(strvec_slot(strvec, index), 10, res, min_val, max_val, ignore_error);
}

bool
read_double_strvec(const vector_t *strvec, size_t index, double *res, double min_val, double max_val, bool ignore_error)
{
	return read_double_func(strvec_slot(strvec, index), res, min_val, max_val, ignore_error);
}

bool
read_unsigned_base_strvec(const vector_t *strvec, size_t index, int base, unsigned *res, unsigned min_val, unsigned max_val, bool ignore_error)
{
	return read_unsigned_func(strvec_slot(strvec, index), base, res, min_val, max_val, ignore_error);
}

void
set_random_seed(unsigned int seed)
{
	random_seed = seed;
	random_seed_configured = true;
}

static void
keyword_alloc(vector_t *keywords_vec, const char *string, void (*handler) (const vector_t *), bool active)
{
	keyword_t *keyword;

	vector_alloc_slot(keywords_vec);

	keyword = (keyword_t *) MALLOC(sizeof(keyword_t));
	keyword->string = string;
	keyword->handler = handler;
	keyword->active = active;

	vector_set_slot(keywords_vec, keyword);
}

static void
keyword_alloc_sub(vector_t *keywords_vec, const char *string, void (*handler) (const vector_t *))
{
	int i = 0;
	keyword_t *keyword;

	/* fetch last keyword */
	keyword = vector_slot(keywords_vec, vector_size(keywords_vec) - 1);

	/* Don't install subordinate keywords if configuration block inactive */
	if (!keyword->active)
		return;

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword = vector_slot(keyword->sub, vector_size(keyword->sub) - 1);

	/* First sub level allocation */
	if (!keyword->sub)
		keyword->sub = vector_alloc();

	/* add new sub keyword */
	keyword_alloc(keyword->sub, string, handler, true);
}

/* Exported helpers */
void
install_sublevel(void)
{
	sublevel++;
}

void
install_sublevel_end(void)
{
	sublevel--;
}

void
install_keyword_root(const char *string, void (*handler) (const vector_t *), bool active)
{
	/* If the root keyword is inactive, the handler will still be called,
	 * but with a NULL strvec */
	keyword_alloc(keywords, string, handler, active);
}

void
install_root_end_handler(void (*handler) (void))
{
	keyword_t *keyword;

	/* fetch last keyword */
	keyword = vector_slot(keywords, vector_size(keywords) - 1);

	if (!keyword->active)
		return;

	keyword->sub_close_handler = handler;
}

void
install_keyword(const char *string, void (*handler) (const vector_t *))
{
	keyword_alloc_sub(keywords, string, handler);
}

void
install_sublevel_end_handler(void (*handler) (void))
{
	int i = 0;
	keyword_t *keyword;

	/* fetch last keyword */
	keyword = vector_slot(keywords, vector_size(keywords) - 1);

	if (!keyword->active)
		return;

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword = vector_slot(keyword->sub, vector_size(keyword->sub) - 1);
	keyword->sub_close_handler = handler;
}

#ifdef _DUMP_KEYWORDS_
static void
dump_keywords(vector_t *keydump, int level, FILE *fp)
{
	unsigned int i;
	keyword_t *keyword_vec;
	char file_name[22];

	if (!level) {
		snprintf(file_name, sizeof(file_name), "/tmp/keywords.%d", getpid());
		fp = fopen_safe(file_name, "w");
		if (!fp)
			return;
	}

	for (i = 0; i < vector_size(keydump); i++) {
		keyword_vec = vector_slot(keydump, i);
		fprintf(fp, "%*sKeyword : %s (%s)\n", level * 2, "", keyword_vec->string, keyword_vec->active ? "active": "disabled");
		if (keyword_vec->sub)
			dump_keywords(keyword_vec->sub, level + 1, fp);
	}

	if (!level)
		fclose(fp);
}
#endif

static void
free_keywords(vector_t *keywords_vec)
{
	keyword_t *keyword_vec;
	unsigned int i;

	for (i = 0; i < vector_size(keywords_vec); i++) {
		keyword_vec = vector_slot(keywords_vec, i);
		if (keyword_vec->sub)
			free_keywords(keyword_vec->sub);
		FREE(keyword_vec);
	}
	vector_free(keywords_vec);
}

/* Functions used for standard definitions */
static const char *
get_cwd(__attribute__((unused))const def_t *def)
{
	char *dir = MALLOC(PATH_MAX);

	/* Since keepalived doesn't do a chroot(), we don't need to be concerned
	 * about (unreachable) - see getcwd(3) man page. */
	return getcwd(dir, PATH_MAX);
}

static const char *
get_instance(__attribute__((unused))const def_t *def)
{
	return STRDUP(config_id);
}

static const char *
get_random(const def_t *def)
{
	unsigned long min = 0;
	unsigned long max = 32767;
	long val;
	char *endp;
	char *rand_str;
	size_t rand_str_len = 0;

	/* We have already checked that the parameter string comprises
	 * only spaces and decimal digits */
	if (def->params) {
		min = strtoul(def->params, &endp, 10);
		if (endp < def->params_end) {
			max = strtoul(endp, &endp, 10);
			if (endp != def->params_end + 1)
				log_message(LOG_INFO, "Too many parameters or extra text for ${_RANDOM %.*s}", (int)(def->params_end - def->params + 1), def->params);
		}
	}

	val = max;
	do {
		rand_str_len++;
	} while (val /= 10);
	rand_str = MALLOC(rand_str_len + 1);

	/* coverity[dont_call] */
	val = random() % (max - min + 1) + min;
	snprintf(rand_str, rand_str_len + 1, "%ld", val);

	return rand_str;
}

const vector_t *
alloc_strvec_quoted_escaped(const char *src)
{
	vector_t *strvec;
	char cur_quote = 0;
	char *ofs_op;
	char *op_buf;
	const char *ofs, *ofs1;
	char op_char;

	if (!src) {
		if (!buf_extern)
			return NULL;
		src = buf_extern;
	}

	/* Create a vector and alloc each command piece */
	strvec = vector_alloc();
	op_buf = MALLOC(MAXBUF);

	ofs = src;
	while (*ofs) {
		/* Find the next 'word' */
		ofs += strspn(ofs, WHITE_SPACE);
		if (!*ofs)
			break;

		ofs_op = op_buf;

		while (*ofs) {
			ofs1 = strpbrk(ofs, cur_quote == '"' ? "\"\\" : cur_quote == '\'' ? "'\\" : WHITE_SPACE_STR "'\"\\");

			if (!ofs1) {
				size_t len;
				if (cur_quote) {
					report_config_error(CONFIG_UNMATCHED_QUOTE, "String '%s': missing terminating %c", src, cur_quote);
					goto err_exit;
				}
				strcpy(ofs_op, ofs);
				len =  strlen(ofs);
				ofs += len;
				ofs_op += len;
				break;
			}

			/* Save the wanted text */
			strncpy(ofs_op, ofs, ofs1 - ofs);
			ofs_op += ofs1 - ofs;
			ofs = ofs1;

			if (*ofs == '\\') {
				/* It is a '\' */
				ofs++;

				if (!*ofs) {
					log_message(LOG_INFO, "Missing escape char at end: '%s'", src);
					goto err_exit;
				}

				if (*ofs == 'x' && isxdigit(ofs[1])) {
					op_char = 0;
					ofs++;
					while (isxdigit(*ofs)) {
						op_char <<= 4;
						op_char |= isdigit(*ofs) ? *ofs - '0' : (10 + *ofs - (isupper(*ofs)  ? 'A' : 'a'));
						ofs++;
					}
				}
				else if (*ofs == 'c' && ofs[1]) {
					op_char = *++ofs & 0x1f;	/* Convert to control character */
					ofs++;
				}
				else if (*ofs >= '0' && *ofs <= '7') {
					op_char = *ofs++ - '0';
					if (*ofs >= '0' && *ofs <= '7') {
						op_char <<= 3;
						op_char += *ofs++ - '0';
					}
					if (*ofs >= '0' && *ofs <= '7') {
						op_char <<= 3;
						op_char += *ofs++ - '0';
					}
				}
				else {
					switch (*ofs) {
					case 'a':
						op_char = '\a';
						break;
					case 'b':
						op_char = '\b';
						break;
					case 'E':
						op_char = 0x1b;
						break;
					case 'f':
						op_char = '\f';
						break;
					case 'n':
						op_char = '\n';
						break;
					case 'r':
						op_char = '\r';
						break;
					case 't':
						op_char = '\t';
						break;
					case 'v':
						op_char = '\v';
						break;
					default: /* \"'  */
						op_char = *ofs;
						break;
					}
					ofs++;
				}

				*ofs_op++ = op_char;
				continue;
			}

			if (cur_quote) {
				/* It's the close quote */
				ofs++;
				cur_quote = 0;
				continue;
			}

			if (*ofs == '"' || *ofs == '\'') {
				cur_quote = *ofs++;
				continue;
			}

			break;
		}

		/* Alloc & set the slot */
		vector_alloc_slot(strvec);
		vector_set_slot(strvec, STRNDUP(op_buf, ofs_op - op_buf));
	}

	FREE(op_buf);

	if (!vector_size(strvec)) {
		free_strvec(strvec);
		return NULL;
	}

	return strvec;

err_exit:
	free_strvec(strvec);
	FREE(op_buf);
	return NULL;
}

vector_t *
alloc_strvec_r(const char *string)
{
	const char *cp, *start;
	size_t str_len;
	vector_t *strvec;

	if (!string)
		return NULL;

	/* Create a vector and alloc each command piece */
	strvec = vector_alloc();

	cp = string;
	while (true) {
		cp += strspn(cp, WHITE_SPACE);
		if (!*cp)
			break;

		start = cp;

		/* Save a quoted string without the ""s as a single string */
		if (*start == '"') {
			start++;
			if (!(cp = strchr(start, '"'))) {
				report_config_error(CONFIG_UNMATCHED_QUOTE, "Unmatched quote: '%s'", string);
				break;
			}
			str_len = (size_t)(cp - start);
			cp++;
		} else {
			cp += strcspn(start, WHITE_SPACE_STR "\"");
			str_len = (size_t)(cp - start);
		}

		/* Alloc & set the slot */
		vector_alloc_slot(strvec);
		vector_set_slot(strvec, STRNDUP(start, str_len));
	}

	if (!vector_size(strvec)) {
		free_strvec(strvec);
		return NULL;
	}

	return strvec;
}

typedef struct _seq {
	const char *var;
	int next;
	int last;
	int step;
	const char *text;
} seq_t;

static list seq_list;	/* List of seq_t */

#ifdef _PARSER_DEBUG_
static void
dump_seqs(void)
{
	seq_t *seq;
	element e;

	LIST_FOREACH(seq_list, seq, e)
		log_message(LOG_INFO, "SEQ: %s => %d -> %d step %d: '%s'", seq->var, seq->next, seq->last, seq->step, seq->text);
	log_message(LOG_INFO, "%s", "");
}
#endif

static void
free_seq(void *s)
{
	seq_t *seq = s;

	FREE_CONST(seq->var);
	FREE_CONST(seq->text);
	FREE(seq);
}

static bool
add_seq(char *buf)
{
	char *p = buf + 4;	/* Skip ~SEQ */
	long one, two, three;
	long start, step, end;
	seq_t *seq_ent;
	const char *var;
	const char *var_end;

	p += strspn(p, " \t");
	if (*p++ != '(')
		return false;
	p += strspn(p, " \t");

	var = p;

	p += strcspn(p, " \t,)");
	var_end = p;
	p += strspn(p, " \t");
	if (!*p || *p == ')' || p == var) {
		report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ definition '%s'", buf);
		return false;
	}

	p++;
	do {
		// Handle missing number
		one = strtol(p, &p, 0);
		p += strspn(p, " \t");
		if (*p == ')') {
			end = one;
			step = (end < 1) ? -1 : 1;
			start = (end < 0) ? -1 : 1;

			break;
		}

		if (*p != ',') {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ definition '%s'", buf);
			return false;
		}

		two = strtol(p + 1, &p, 0);
		p += strspn(p, " \t");
		if (*p == ')') {
			start = one;
			end = two;
			step = start <= end ? 1 : -1;

			break;
		}

		if (*p != ',') {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ definition '%s'", buf);
			return false;
		}

		three = strtol(p + 1, &p, 0);
		p += strspn(p, " \t");
		if (*p != ')') {
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ definition '%s'", buf);
			return false;
		}

		start = one;
		step = two;
		end = three;

		if (!step ||
		    (start < end && step < 0) ||
		    (start > end && step > 0))
		{
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ values '%s'", buf);
			return false;
		}
	} while (false);

	p += strspn(p + 1, " \t") + 1;

	PMALLOC(seq_ent);
	seq_ent->var = STRNDUP(var, var_end - var);
	seq_ent->next = start;
	seq_ent->step = step;
	seq_ent->last = end;
	seq_ent->text = STRDUP(p);

	if (!seq_list)
		seq_list = alloc_list(free_seq, NULL);
	list_add(seq_list, seq_ent);

	return true;
}

#ifdef _PARSER_DEBUG_
static void
dump_definitions(void)
{
	const def_t *def;
	element e;

	LIST_FOREACH(defs, def, e)
		log_message(LOG_INFO, "Defn %s = '%s'", def->name, def->value);
	log_message(LOG_INFO, "%s", "");
}
#endif

/* recursive configuration stream handler */
static int kw_level;
static int block_depth;

static bool
process_stream(vector_t *keywords_vec, int need_bob)
{
	unsigned int i;
	keyword_t *keyword_vec;
	const char *str;
	char *buf;
	vector_t *strvec;
	vector_t *prev_keywords = current_keywords;
	current_keywords = keywords_vec;
	int bob_needed = 0;
	bool ret_err = false;
	bool ret;

	buf = MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		strvec = alloc_strvec(buf);

		if (!strvec)
			continue;

		str = vector_slot(strvec, 0);

		if (skip_sublevel == -1) {
			/* There wasn't a '{' on the keyword line */
			if (!strcmp(str, BOB)) {
				/* We've got the opening '{' now */
				skip_sublevel = 1;
				need_bob = 0;
				free_strvec(strvec);
				continue;
			}

			/* The skipped keyword doesn't have a {} block, so we no longer want to skip */
			skip_sublevel = 0;
		}
		if (skip_sublevel) {
			for (i = 0; i < vector_size(strvec); i++) {
				str = vector_slot(strvec,i);
				if (!strcmp(str,BOB))
					skip_sublevel++;
				else if (!strcmp(str,EOB)) {
					if (--skip_sublevel == 0)
						break;
				}
			}

			/* If we have reached the outer level of the block and we have
			 * nested keyword level, then we need to return to restore the
			 * next level up of keywords. */
			if (!strcmp(str, EOB) && skip_sublevel == 0 && kw_level > 0) {
				ret_err = true;
				free_strvec(strvec);
				break;
			}

			free_strvec(strvec);
			continue;
		}

		if (need_bob) {
			need_bob = 0;
			if (!strcmp(str, BOB) && kw_level > 0) {
				free_strvec(strvec);
				continue;
			}
			else
				report_config_error(CONFIG_MISSING_BOB, "Missing '%s' at beginning of configuration block", BOB);
		}
		else if (!strcmp(str, BOB)) {
			report_config_error(CONFIG_UNEXPECTED_BOB, "Unexpected '%s' - ignoring", BOB);
			free_strvec(strvec);
			continue;
		}

		if (!strcmp(str, EOB) && kw_level > 0) {
			free_strvec(strvec);
			break;
		}

		if (!strncmp(str, "~SEQ", 4)) {
			if (!add_seq(buf))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ specification '%s'", buf);
			free_strvec(strvec);
#ifdef _PARSER_DEBUG_
			if (do_parser_debug) {
				dump_definitions();
				dump_seqs();
			}
#endif
			continue;
		}

		for (i = 0; i < vector_size(keywords_vec); i++) {
			keyword_vec = vector_slot(keywords_vec, i);

			if (!strcmp(keyword_vec->string, str)) {
				if (!keyword_vec->active) {
					if (!strcmp(vector_slot(strvec, vector_size(strvec)-1), BOB))
						skip_sublevel = 1;
					else
						skip_sublevel = -1;

					/* Sometimes a process wants to know if another process
					 * has any of a type of configuration. For example, there
					 * is no point starting the VRRP process of there are no
					 * vrrp instances, and so the parent process would be
					 * interested in that. */
					if (keyword_vec->handler)
						(*keyword_vec->handler)(NULL);
				}

				/* There is an inconsistency here. 'static_ipaddress' for example
				 * does not have sub levels, but needs a '{' */
				if (keyword_vec->sub) {
					/* Remove a trailing '{' */
					char *bob = vector_slot(strvec, vector_size(strvec)-1) ;
					if (!strcmp(bob, BOB)) {
						vector_unset(strvec, vector_size(strvec)-1);
						FREE(bob);
						bob_needed = 0;
					}
					else
						bob_needed = 1;
				}

				if (keyword_vec->active && keyword_vec->handler) {
					buf_extern = buf;	/* In case the raw line wants to be accessed */
					(*keyword_vec->handler) (strvec);
				}

				if (keyword_vec->sub) {
					kw_level++;
					ret = process_stream(keyword_vec->sub, bob_needed);
					kw_level--;

					/* We mustn't run any close handler if the block was skipped */
					if (!ret && keyword_vec->active && keyword_vec->sub_close_handler)
						(*keyword_vec->sub_close_handler) ();
				}
				break;
			}
		}

		if (i >= vector_size(keywords_vec))
			report_config_error(CONFIG_UNKNOWN_KEYWORD, "Unknown keyword '%s'", str);

		free_strvec(strvec);
	}

	current_keywords = prev_keywords;
	FREE(buf);
	return ret_err;
}

static bool
read_conf_file(const char *conf_file)
{
	FILE *stream;
	glob_t globbuf;
	size_t i;
	int	res;
	struct stat stb;
	unsigned num_matches = 0;

	globbuf.gl_offs = 0;
	res = glob(conf_file, GLOB_MARK
#if HAVE_DECL_GLOB_BRACE
					| GLOB_BRACE
#endif
						    , NULL, &globbuf);

	if (res) {
		if (res == GLOB_NOMATCH)
			log_message(LOG_INFO, "No config files matched '%s'.", conf_file);
		else
			log_message(LOG_INFO, "Error reading config file(s): glob(\"%s\") returned %d, skipping.", conf_file, res);
		return true;
	}

	for (i = 0; i < globbuf.gl_pathc; i++) {
		if (globbuf.gl_pathv[i][strlen(globbuf.gl_pathv[i])-1] == '/') {
			/* This is a directory - so skip */
			continue;
		}

		log_message(LOG_INFO, "Opening file '%s'.", globbuf.gl_pathv[i]);
		stream = fopen(globbuf.gl_pathv[i], "r");
		if (!stream) {
			log_message(LOG_INFO, "Configuration file '%s' open problem (%s) - skipping"
				       , globbuf.gl_pathv[i], strerror(errno));
			continue;
		}

		/* Make sure what we have opened is a regular file, and not for example a directory or executable */
		if (fstat(fileno(stream), &stb) ||
		    !S_ISREG(stb.st_mode) ||
		    (stb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
			log_message(LOG_INFO, "Configuration file '%s' is not a regular non-executable file - skipping", globbuf.gl_pathv[i]);
			fclose(stream);
			continue;
		}

		num_matches++;

		current_stream = stream;

		/* We only want to report the file name if there is more than one file used */
		if (current_file_name || globbuf.gl_pathc > 1)
			current_file_name = globbuf.gl_pathv[i];
		current_file_line_no = 0;

		int curdir_fd = -1;
		if (strchr(globbuf.gl_pathv[i], '/')) {
			/* If the filename contains a directory element, change to that directory.
			   The man page open(2) states that fchdir() didn't support O_PATH until Linux 3.5,
			   even though testing on Linux 3.1 shows it appears to work. To be safe, don't
			   use it until Linux 3.5. */
			curdir_fd = open(".", O_RDONLY | O_DIRECTORY
#if HAVE_DECL_O_PATH && LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
								     | O_PATH
#endif
									     );

			char *confpath = strdup(globbuf.gl_pathv[i]);
			dirname(confpath);
			if (chdir(confpath) < 0)
				log_message(LOG_INFO, "chdir(%s) error (%s)", confpath, strerror(errno));
			free(confpath);
		}

		process_stream(current_keywords, 0);
		fclose(stream);

		free_list(&seq_list);

		/* If we changed directory, restore the previous directory */
		if (curdir_fd != -1) {
			if ((res = fchdir(curdir_fd)))
				log_message(LOG_INFO, "Failed to restore previous directory after include");
			close(curdir_fd);
			if (res)
				return true;
		}
	}

	globfree(&globbuf);

	if (!num_matches)
		log_message(LOG_INFO, "No config files matched '%s'.", conf_file);

	return false;
}

bool check_conf_file(const char *conf_file)
{
	glob_t globbuf;
	size_t i;
	bool ret = true;
	int res;
	struct stat stb;
	unsigned num_matches = 0;

	globbuf.gl_offs = 0;
	res = glob(conf_file, GLOB_MARK
#if HAVE_DECL_GLOB_BRACE
					| GLOB_BRACE
#endif
						    , NULL, &globbuf);
	if (res) {
		report_config_error(CONFIG_FILE_NOT_FOUND, "Unable to find configuration file %s (glob returned %d)", conf_file, res);
		return false;
	}

	for (i = 0; i < globbuf.gl_pathc; i++) {
		if (globbuf.gl_pathv[i][strlen(globbuf.gl_pathv[i])-1] == '/') {
			/* This is a directory - so skip */
			continue;
		}

		if (access(globbuf.gl_pathv[i], R_OK)) {
			log_message(LOG_INFO, "Unable to read configuration file %s", globbuf.gl_pathv[i]);
			ret = false;
			break;
		}

		/* Make sure that the file is a regular file, and not for example a directory or executable */
		if (stat(globbuf.gl_pathv[i], &stb) ||
		    !S_ISREG(stb.st_mode) ||
		     (stb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
			log_message(LOG_INFO, "Configuration file '%s' is not a regular non-executable file", globbuf.gl_pathv[i]);
			ret = false;
			break;
		}

		num_matches++;
	}

	if (ret) {
		if (num_matches > 1)
			report_config_error(CONFIG_MULTIPLE_FILES, "WARNING, more than one file matches configuration file %s, using %s", conf_file, globbuf.gl_pathv[0]);
		else if (num_matches == 0) {
			report_config_error(CONFIG_FILE_NOT_FOUND, "Unable to find configuration file %s", conf_file);
			ret = false;
		}
	}

	globfree(&globbuf);

	return ret;
}

static bool
check_include(const char *buf)
{
	const vector_t *strvec;
	bool ret = false;
	FILE *prev_stream;
	const char *prev_file_name;
	size_t prev_file_line_no;

	/* Simple check first for include */
	if (!strstr(buf, "include"))
		return false;

	strvec = alloc_strvec(buf);

	if (!strvec)
		return false;

	if(!strcmp("include", vector_slot(strvec, 0)) && vector_size(strvec) == 2) {
		prev_stream = current_stream;
		prev_file_name = current_file_name;
		prev_file_line_no = current_file_line_no;

		read_conf_file(vector_slot(strvec, 1));

		current_stream = prev_stream;
		current_file_name = prev_file_name;
		current_file_line_no = prev_file_line_no;

		ret = true;
	}

	free_strvec(strvec);
	return ret;
}

static def_t * __attribute__ ((pure))
find_definition(const char *name, size_t len, bool definition)
{
	element e;
	def_t *def;
	const char *p;
	bool using_braces = false;
	bool allow_multiline;
	const char *param_start = NULL;
	const char *param_end = NULL;

	if (LIST_ISEMPTY(defs))
		return NULL;

	if (!definition && *name == BOB[0]) {
		using_braces = true;
		name++;
	}

	if (!isalpha(*name) && *name != '_')
		return NULL;

	if (!len) {
		for (len = 1, p = name + 1; *p != '\0' && (isalnum(*p) || *p == '_'); len++, p++);

		/* Check we have a suitable end character */
		if (using_braces) {
			if (!definition) {
				/* Allow for parameters to the definition */
				while (*p && (*p == ' ' || isdigit (*p))) {
					if (*p != ' ') {
					       if (!param_start)
						       param_start = p;
					       param_end = p;
					}
					p++;
				}
				/* Ensure don't end with a space */
				if (param_start && param_end + 1 != p)
					return NULL;
			}
			if (*p != EOB[0])
				return NULL;
		} else if (!definition && *p != ' ' && *p != '\t' && *p != '\0')
			return NULL;
	}

	if (definition ||
	    (!using_braces && name[len] == '\0') ||
	    (using_braces && name[len+1] == '\0'))
		allow_multiline = true;
	else
		allow_multiline = false;

	LIST_FOREACH(defs, def, e) {
		if (def->name_len == len &&
		    (allow_multiline || !def->multiline) &&
		    !strncmp(def->name, name, len)) {
			if (param_start && !def->max_params)
				return NULL;
			if (param_start) {
				def->params = param_start;
				def->params_end = param_end;
			}
			else
				def->params = NULL;
			return def;
		}
	}

	return NULL;
}

static void
multiline_stack_push(const char *ptr)
{
	multiline_stack_ent *stack_ent;

	if (!LIST_EXISTS(multiline_stack))
		multiline_stack = alloc_list(free_list_element_simple, NULL);

	PMALLOC(stack_ent);
	stack_ent->ptr = ptr;
	stack_ent->seq_depth = multiline_seq_depth;

	list_add(multiline_stack, stack_ent);
}

static const char *
multiline_stack_pop(void)
{
	multiline_stack_ent *stack_ent;
	const char *next_ptr;

	if (!LIST_EXISTS(multiline_stack) || LIST_ISEMPTY(multiline_stack))
		return NULL;

	stack_ent = LIST_TAIL_DATA(multiline_stack);
	next_ptr = stack_ent->ptr;
	multiline_seq_depth = stack_ent->seq_depth;

	list_remove(multiline_stack, multiline_stack->tail);

	return next_ptr;
}

static bool
replace_param(char *buf, size_t max_len, char const **multiline_ptr_ptr)
{
	char *cur_pos = buf;
	size_t len_used = strlen(buf);
	def_t *def;
	char *s, *d;
	const char *e;
	ssize_t i;
	size_t extra_braces;
	size_t replacing_len;
	size_t replaced_len;
	const char *next_ptr = NULL;
	bool found_defn = false;
	const char *multiline_ptr = *multiline_ptr_ptr;

	while ((cur_pos = strchr(cur_pos, '$')) && cur_pos[1] != '\0') {
		if ((def = find_definition(cur_pos + 1, 0, false))) {
			found_defn = true;
			extra_braces = cur_pos[1] == BOB[0] ? 2 : 0;
			next_ptr = multiline_ptr;

			/* We are in a multiline expansion, and now have another
			 * one, so save the previous state on the multiline stack */
			if (def->multiline && multiline_ptr)
				multiline_stack_push(multiline_ptr);

			if (def->multiline)
				multiline_seq_depth = LIST_EXISTS(seq_list) ? seq_list->count : 0;

			if (def->fn) {
				/* This is a standard definition that uses a function for the replacement text */
				if (def->value)
					FREE_CONST(def->value);
				def->value = (*def->fn)(def);
				def->value_len = strlen(def->value);
			}

			/* Ensure there is enough room to replace $PARAM or ${PARAM} with value */
			replaced_len = def->name_len;
			if (def->multiline) {
				replacing_len = strcspn(def->value, DEF_LINE_END);
				next_ptr = def->value + replacing_len + 1;
				multiline_ptr = next_ptr;
			}
			else {
				if (def->params)
					replaced_len = def->params_end - (cur_pos + 1 )+ (extra_braces ? 0 : 1);
				replacing_len = def->value_len;
			}

			if (len_used + replacing_len - (replaced_len + 1 + extra_braces) >= max_len) {
				log_message(LOG_INFO, "Parameter substitution on line '%s' would exceed maximum line length", buf);
				return NULL;
			}

			if (replaced_len + 1 + extra_braces != replacing_len) {
				/* We need to move the existing text */
				if (replaced_len + 1 + extra_braces < replacing_len) {
					/* We are lengthening the buf text */
					s = cur_pos + strlen(cur_pos);
					d = s - (replaced_len + 1 + extra_braces) + replacing_len;
					e = cur_pos;
					i = -1;
				} else {
					/* We are shortening the buf text */
					s = cur_pos + (replaced_len + 1 + extra_braces) - replacing_len;
					d = cur_pos;
					if (def->params)
						e = def->params_end + (extra_braces ? 2 : 1);
					else
						e = cur_pos + strlen(cur_pos);
					i = 1;
				}
				do {
					*d = *s;
					if (s == e)
						break;
					d += i;
					s += i;
				} while (true);

				len_used = len_used + replacing_len - (replaced_len + 1 + extra_braces);
			}

			/* Now copy the replacement text */
			strncpy(cur_pos, def->value, replacing_len);

			if (def->value[strspn(def->value, " \t")] == '~')
				break;
		}
		else
			cur_pos++;
	}

	/* If we did a replacement, update the multiline_ptr */
	if (found_defn)
		*multiline_ptr_ptr = next_ptr;

	return found_defn;
}

static void
free_definition(void *d)
{
	def_t *def = d;

	FREE_CONST(def->name);
	FREE_CONST_PTR(def->value);
	FREE(def);
}

static def_t*
set_definition(const char *name, const char *value)
{
	def_t *def;
	size_t name_len = strlen(name);

	if ((def = find_definition(name, name_len, false))) {
		FREE_CONST(def->value);
		def->fn = NULL;		/* Allow a standard definition to be overridden */
	}
	else {
		def = MALLOC(sizeof(*def));
		def->name_len = name_len;
		def->name = STRNDUP(name, def->name_len);

		if (!LIST_EXISTS(defs))
			defs = alloc_list(free_definition, NULL);
		list_add(defs, def);
	}
	def->value_len = strlen(value);
	def->value = STRNDUP(value, def->value_len);

#ifdef _PARSER_DEBUG_
	if (do_parser_debug)
		log_message(LOG_INFO, "Definition %s now '%s'", def->name, def->value);
#endif

	return def;
}

/* A definition is of the form $NAME=TEXT */
static def_t*
check_definition(const char *buf)
{
	const char *p;
	def_t* def;
	size_t def_name_len;
	char *str;

	if (buf[0] != '$')
		return false;

	if (!isalpha(buf[1]) && buf[1] != '_')
		return NULL;

	for (p = buf + 2; *p; p++) {
		if (*p == '=')
			break;
		if (!isalnum(*p) &&
		    !isdigit(*p) &&
		    *p != '_')
			return NULL;
	}

	def_name_len = (size_t)(p - &buf[1]);

	p += strspn(p, " \t");
	if (*p != '=')
		return NULL;

	if ((def = find_definition(&buf[1], def_name_len, true))) {
		FREE_CONST(def->value);
		def->fn = NULL;		/* Allow a standard definition to be overridden */
	}
	else {
		def = MALLOC(sizeof(*def));
		def->name_len = def_name_len;
		def->name = STRNDUP(buf + 1, def->name_len);

		if (!LIST_EXISTS(defs))
			defs = alloc_list(free_definition, NULL);
		list_add(defs, def);
	}

	/* Skip leading whitespace */
	p += strspn(p + 1, " \t") + 1;
	def->value_len = strlen(p);
	if (p[def->value_len - 1] == '\\') {
		/* Remove trailing whitespace */
		while (def->value_len >= 2 &&
		       isblank(p[def->value_len - 2]))
			def->value_len--;

		if (def->value_len < 2) {
			/* If the string has nothing except spaces and terminating '\'
			 * point to the string terminator. */
			p += def->value_len;
			def->value_len = 0;
		}
		def->multiline = true;
	} else
		def->multiline = false;

	str = STRNDUP(p, def->value_len);

	/* If it a multiline definition, we need to mark the end of the first line
	 * by overwriting the '\' with the line end marker. */
	if (def->value_len >= 2 && def->multiline)
		str[def->value_len - 1] = DEF_LINE_END[0];

	def->value = str;

	return def;
}

static void
add_std_definition(const char *name, const char *value, const char *(*fn)(const def_t *), unsigned max_params)
{
	def_t* def;

	def = MALLOC(sizeof(*def));
	def->name_len = strlen(name);
	def->name = STRNDUP(name, def->name_len);
	if (value) {
		def->value_len = strlen(value);
		def->value = STRNDUP(value, def->value_len);
	}
	def->fn = fn;
	def->max_params = max_params;

	if (!LIST_EXISTS(defs))
		defs = alloc_list(free_definition, NULL);
	list_add(defs, def);
}

static void
set_std_definitions(void)
{
	time_t tim;

	add_std_definition("_PWD", NULL, get_cwd, 0);
	add_std_definition("_INSTANCE", NULL, get_instance, 0);
	add_std_definition("_RANDOM", NULL, get_random, 2);

	/* In case $_RANDOM is used, seed the pseudo RNG */
	if (random_seed_configured)
		srandom(random_seed);
	else {
		time(&tim);
		srandom((unsigned int)tim);
	}
}

static void
free_parser_data(void)
{
	if (LIST_EXISTS(defs))
		free_list(&defs);

	if (LIST_EXISTS(multiline_stack))
		free_list(&multiline_stack);
}

/* decomment() removes comments, the escaping of comment start characters,
 * and leading and trailing whitespace, including whitespace before a
 * terminating \ character */
static void
decomment(char *str)
{
	bool quote = false;
	bool cont = false;
	char *skip = NULL;
	char *p = str + strspn(str, " \t");

	/* Remove leading whitespace */
	if (p != str)
		memmove(str, p, strlen(p) + 1);

	p = str;
	while ((p = strpbrk(p, "!#\"\\"))) {
		if (*p == '"') {
			if (!skip)
				quote = !quote;
			p++;
			continue;
		}
		if (*p == '\\') {
			if (p[1]) {
				/* Don't modify quoted strings */
				if (!quote && (p[1] == '#' || p[1] == '!')) {
					memmove(p, p + 1, strlen(p + 1) + 1);
					p++;
				} else
					p += 2;
				continue;
			}
			*p = '\0';
			cont = true;
			break;
		}
		if (!quote && !skip && (*p == '!' || *p == '#'))
			skip = p;
		p++;
	}

	if (quote)
		report_config_error(CONFIG_GENERAL_ERROR, "Unterminated quote '%s'", str);

	if (skip)
		*skip = '\0';

	/* Remove trailing whitespace */
	p = str + strlen(str) - 1;
	while (p >= str && isblank(*p))		// This line causes a strict-overflow=4 warning in gcc 5.4.0
		*p-- = '\0';
	if (cont) {
		*++p = '\\';
		*++p = '\0';
	}
}

static bool
read_line(char *buf, size_t size)
{
	static def_t *def = NULL;
	static const char *next_ptr = NULL;
	static char *line_residue = NULL;

	size_t len ;
	bool eof = false;
	size_t config_id_len;
	char *buf_start;
	bool rev_cmp;
	size_t ofs;
	bool recheck;
	bool multiline_param_def = false;
	char *end;
	size_t skip;
	char *p;

	config_id_len = config_id ? strlen(config_id) : 0;
	do {
		if (line_residue) {
			strcpy(buf, line_residue);
			FREE(line_residue);
			line_residue = NULL;
		}
		else if (!LIST_ISEMPTY(seq_list) &&
			 seq_list->count > multiline_seq_depth) {
			seq_t *seq = LIST_TAIL_DATA(seq_list);
			char val[12];
			snprintf(val, sizeof(val), "%d", seq->next);
#ifdef _PARSER_DEBUG_
			if (do_parser_debug)
				log_message(LOG_INFO, "Processing seq %d of %s for '%s'",  seq->next, seq->var, seq->text);
#endif
			set_definition(seq->var, val);
			strcpy(buf, seq->text);
			seq->next += seq->step;
			if ((seq->step > 0 && seq->next > seq->last) ||
			    (seq->step < 0 && seq->next < seq->last)) {
#ifdef _PARSER_DEBUG_
				if (do_parser_debug)
					log_message(LOG_INFO, "Removing seq %s for '%s'", seq->var, seq->text);
#endif
				list_remove(seq_list, seq_list->tail);
			}
		}
		else if (next_ptr) {
			/* We are expanding a multiline parameter, so copy next line */
			end = strchr(next_ptr, DEF_LINE_END[0]);
			if (!end) {
				strcpy(buf, next_ptr);
				if (!LIST_ISEMPTY(multiline_stack))
					next_ptr = multiline_stack_pop();
				else {
					next_ptr = NULL;
					multiline_seq_depth = 0;
				}
			} else {
				strncpy(buf, next_ptr, (size_t)(end - next_ptr));
				buf[end - next_ptr] = '\0';
				next_ptr = end + 1;
			}
		}
		else {
			/* Get the next non-blank line */
			do {
				if (!fgets(buf, (int)size, current_stream))
				{
					eof = true;
					len = 0;
					break;
				}

				/* Check if we have read the end of a line */
				len = strlen(buf);
				if (buf[0] && buf[len-1] == '\n')
					current_file_line_no++;

				/* Remove end of line chars */
				while (len && (buf[len-1] == '\n' || buf[len-1] == '\r'))
					len--;

				if (!len && multiline_param_def) {
					multiline_param_def = false;
					if (!def->value_len)
						def->multiline = false;
				}
			} while (!len);

			buf[len] = '\0';

			if (len)
				decomment(buf);

			if (!buf[0])
				break;
		}

		len = strlen(buf);

		/* Handle multi-line definitions */
		if (multiline_param_def) {
			/* Remove trailing whitespace */
			if (len && buf[len-1] == '\\') {
				len--;
				while (len >= 1 && isblank(buf[len - 1]))
					len--;
				buf[len++] = DEF_LINE_END[0];
			} else {
				multiline_param_def = false;
				if (!def->value_len)
					def->multiline = false;
			}

			/* Don't add blank lines */
			if (len >= 2 ||
			    (len && !multiline_param_def)) {
				/* Add the line to the definition */
				char *str = REALLOC_CONST(def->value, def->value_len + len + 1);
				strncpy(str + def->value_len, buf, len);
				def->value_len += len;
				str[def->value_len] = '\0';
				def->value = str;
			}

			buf[0] = '\0';
			continue;
		}

		if (len == 0)
			continue;

		recheck = false;
		do {
			if (buf[0] == '@') {
				/* If the line starts '@', check the following word matches the system id.
				   @^ reverses the sense of the match */
				if (buf[1] == '^') {
					rev_cmp = true;
					ofs = 2;
				} else {
					rev_cmp = false;
					ofs = 1;
				}

				/* We need something after the system_id */
				if (!(buf_start = strpbrk(buf + ofs, " \t"))) {
					buf[0] = '\0';
					break;
				}

				/* Check if config_id matches/doesn't match as appropriate */
				if ((!config_id ||
				     (size_t)(buf_start - (buf + ofs)) != config_id_len ||
				     strncmp(buf + ofs, config_id, config_id_len)) != rev_cmp) {
					buf[0] = '\0';
					break;
				}

				/* Remove the @config_id from start of line */
				buf_start += strspn(buf_start, " \t");
				len -= (buf_start - buf);
				memmove(buf, buf_start, len + 1);
			}

			if (buf[0] == '$' && (def = check_definition(buf))) {
				/* check_definition() saves the definition */
				if (def->multiline)
					multiline_param_def = true;
				buf[0] = '\0';
				break;
			}

			if (buf[0] == '~')
				break;

			if (!LIST_ISEMPTY(defs) && (p = strchr(buf, '$'))) {
				if (!replace_param(buf, size, &next_ptr)) {
					/* If nothing has changed, we don't need to do any more processing */
					break;
				}

				if (buf[0] == '@')
					recheck = true;
				if (strchr(buf, '$'))
					recheck = true;
			}
		} while (recheck);
	} while (buf[0] == '\0' || check_include(buf));

	/* Search for BOB[0] or EOB[0] not in "" */
	if (buf[0]) {
		p = buf;
		if (p[0] != BOB[0] && p[0] != EOB[0]) {
			while ((p = strpbrk(p, BOB EOB "\""))) {
				if (*p != '"')
					break;

				/* Skip over anything in ""s */
				if (!(p = strchr(p + 1, '"')))
					break;

				p++;
			}
		}

		if (p && (p[0] == BOB[0] || p[0] == EOB[0])) {
			if (p == buf)
				skip = strspn(p + 1, " \t") + 1;
			else
				skip = 0;

			if (p[skip]) {
				/* Skip trailing whitespace */
				len = strlen(p + skip);
				while (len && (p[skip+len-1] == ' ' || p[skip+len-1] == '\t'))
					len--;
				line_residue = MALLOC(len + 1);
				p[skip+len] = '\0';
				strcpy(line_residue, p + skip);
				p[skip] = '\0';
			}
		}

		/* Skip trailing whitespace */
		len = strlen(buf);
		while (len && (buf[len-1] == ' ' || buf[len-1] == '\t'))
			len--;
		buf[len] = '\0';

		/* Check that we haven't got too many '}'s */
		if (!strcmp(buf, BOB))
			block_depth++;
		else if (!strcmp(buf, EOB)) {
			if (block_depth-- < 1) {
				report_config_error(CONFIG_UNEXPECTED_EOB, "Extra '}' found");
				block_depth = 0;
			}
		}
	}

#ifdef _PARSER_DEBUG_
	if (do_parser_debug)
		log_message(LOG_INFO, "read_line(%d): '%s'", block_depth, buf);
#endif

	return !eof;
}

void
alloc_value_block(void (*alloc_func) (const vector_t *), const char *block_type)
{
	char *buf;
	const char *str = NULL;
	const vector_t *vec = NULL;
	bool first_line = true;

	buf = (char *) MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		if (!(vec = alloc_strvec(buf)))
			continue;

		if (first_line) {
			first_line = false;

			if (!strcmp(vector_slot(vec, 0), BOB)) {
				free_strvec(vec);
				continue;
			}

			log_message(LOG_INFO, "'%s' missing from beginning of block %s", BOB, block_type);
		}

		str = vector_slot(vec, 0);
		if (!strcmp(str, EOB)) {
			free_strvec(vec);
			break;
		}

		if (vector_size(vec))
			(*alloc_func) (vec);

		free_strvec(vec);
	}
	FREE(buf);
}

static vector_t *read_value_block_vec;
static void
read_value_block_line(const vector_t *strvec)
{
	size_t word;
	const char *str;

	if (!read_value_block_vec)
		read_value_block_vec = vector_alloc();

	vector_foreach_slot(strvec, str, word) {
		vector_alloc_slot(read_value_block_vec);
		vector_set_slot(read_value_block_vec, STRDUP(str));
	}
}

const vector_t *
read_value_block(const vector_t *strvec)
{
	vector_t *ret_vec;

	alloc_value_block(read_value_block_line, vector_slot(strvec,0));

	ret_vec = read_value_block_vec;
	read_value_block_vec = NULL;

	return ret_vec;
}

/* min_time and max_time are in micro-seconds. The returned value is also in micro-seconds */
bool
read_timer(const vector_t *strvec, size_t index, unsigned long *res, unsigned long min_time, unsigned long max_time, bool ignore_error)
{
	double timer;
	bool ret;
	double fmin_time, fmax_time;

	fmin_time = (double)min_time / TIMER_HZ;
	fmax_time = (double)((max_time) ? max_time : TIMER_MAXIMUM) / TIMER_HZ;

	ret = read_double_strvec(strvec, index, &timer, fmin_time, fmax_time, ignore_error);
	*res = timer * TIMER_HZ > TIMER_MAXIMUM ? TIMER_MAXIMUM : (unsigned long)(timer * TIMER_HZ);

	return ret;
}

/* Checks for on/true/yes or off/false/no */
int __attribute__ ((pure))
check_true_false(const char *str)
{
	if (!strcmp(str, "true") || !strcmp(str, "on") || !strcmp(str, "yes"))
		return true;
	if (!strcmp(str, "false") || !strcmp(str, "off") || !strcmp(str, "no"))
		return false;

	return -1;	/* error */
}

void skip_block(bool need_block_start)
{
	/* Don't process the rest of the configuration block */
	if (need_block_start)
		skip_sublevel = -1;
	else
		skip_sublevel = 1;
}

/* Data initialization */
void
init_data(const char *conf_file, const vector_t * (*init_keywords) (void))
{
	/* Init Keywords structure */
	keywords = vector_alloc();

	(*init_keywords) ();

	/* Add out standard definitions */
	set_std_definitions();

#ifdef _DUMP_KEYWORDS_
	/* Dump configuration */
	if (do_dump_keywords)
		dump_keywords(keywords, 0, NULL);
#endif

	/* Stream handling */
	current_keywords = keywords;

	current_file_name = NULL;
	current_file_line_no = 0;

	/* A parent process may have left these set */
	block_depth = 0;
	kw_level = 0;

	register_null_strvec_handler(null_strvec);
	read_conf_file(conf_file);
	unregister_null_strvec_handler();

	/* Report if there are missing '}'s. If there are missing '{'s it will already have been reported */
	if (block_depth > 0)
		report_config_error(CONFIG_MISSING_EOB, "There are %d missing '%s's or extra '%s's", block_depth, EOB, BOB);

	/* We have finished reading the configuration files, so any configuration
	 * errors report from now mustn't include a reference to the config file name */
	current_file_line_no = 0;

	/* Close the password database if it was opened */
	endpwent();

	free_keywords(keywords);
	free_parser_data();
#ifdef _WITH_VRRP_
	clear_rt_names();
#endif
	notify_resource_release();
}
