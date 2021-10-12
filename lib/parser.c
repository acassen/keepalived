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
#include <signal.h>
#include <dirent.h>
#ifdef HAVE_MEMFD_CREATE
#include <sys/mman.h>
#endif
#ifdef USE_MEMFD_CREATE_SYSCALL
#include <sys/syscall.h>
#include <linux/memfd.h>
#endif

#include "parser.h"
#include "memory.h"
#include "logger.h"
#include "list_head.h"
#include "rttables.h"
#include "scheduler.h"
#include "notify.h"
#include "bitops.h"
#include "utils.h"
#include "process.h"
#include "signals.h"

#ifdef USE_MEMFD_CREATE_SYSCALL
#ifndef SYS_memfd_create
#define SYS_memfd_create __NR_memfd_create
#endif
#endif

/* In order to ensure that all processes read the same configuration, the first
 * process that reads the configuration writes it to a temporary file, and all
 * the other processes read that temporary file.
 *
 * For simplicity, the temporary file is by default, and if memfd_create() is
 * supported, a memfd type file, otherwise it will be an anonymous file in the
 * filesystem that includes KA_TMP_DIR (default /tmp). The default can be
 * overridden by the global_defs tmp_config_directory option.
 *
 * The temporary file contains all the lines of the original configuration file(s)
 * stripped of leading and training whitespace and comments, with the following
 * exceptions:
 * 1. include statements are passed as blank lines.
 * 2. When an included file is opened, a line starting "# " followed by the file
 *    name is written.
 * 3. When an included file is closed, a single character line "!" is written.
 * 4. Any include file processing errors are written to the file preceeded by "#! ".
 *
 * The reasons for 2 and 3 are so that configuration errors can be logged with the
 * correct file name and line number.
 * The reason for 4 is so that include file processing errors can be written to the
 * log files of all processes.
 */

#define DEF_LINE_END	"\n"

#define BOB "{"
#define EOB "}"
#define WHITE_SPACE_STR " \t\f\n\r\v"

/* INCLUDE_R will error if a returned entry is:
 *   not readable
 *   a directory
 *   not a regular, non executable, file
 *   cannot chdir() to the directory of the file
 */
typedef enum _include {
	INCLUDE = 0,		/* No error if no files match etc */
	INCLUDE_R = 0x01,	/* Error if directory, not readable, etc */
	INCLUDE_M = 0x02,	/* Error if no files match unless wildcard specified */
	INCLUDE_W = 0x04,	/* Error if no files match even if wildcard used */
	INCLUDE_B = 0x08,	/* All glob brace specifiers must match */
} include_t;


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

	/* Linked list member */
	list_head_t e_list;
} def_t;

typedef struct _multiline_stack_ent {
	const char *ptr;
	size_t seq_depth;

	/* Linked list member */
	list_head_t e_list;
} multiline_stack_ent;

/* Structures used for ~LST */
typedef struct param {
	const char	*name;
	list_head_t	e_list;
} param_t;

typedef struct value {
	const char	*val;
	list_head_t	e_list;
} value_t;

typedef struct value_set {
	list_head_t	values;		/* value_t */
	list_head_t	e_list;
} value_set_t;

/* Structure for ~SEQ or ~LST */
typedef struct _seq {
	const char *var;
	long next;
	value_set_t *next_var;
	long last;
	long step;
	bool hex;
	const char *text;
	list_head_t lst_params;		/* param_t */
	list_head_t lst_values;		/* value_set_t */

	/* Linked list member */
	list_head_t e_list;
} seq_t;

/* Structure for include file stack */
typedef struct _include_file {
	glob_t		globbuf;
	unsigned	glob_next;
	const char	*file_name;
	int		curdir_fd;
	FILE		*stream;
	unsigned	num_matches;
	const char	*current_file_name;  //can be derived from globbuf_gl_pathv[glob_next-1]
	size_t		current_line_no;
	include_t	include_type;
	unsigned	sav_include_check;

	list_head_t	e_list;
} include_file_t;


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
#ifndef _ONE_PROCESS_DEBUG_
const char *config_save_dir;
#endif

/* Error handling variables */
static unsigned include_check;

/* The following 3 variables should be static, but that causes an optimiser bug in GCC */
#if HAVE_DECL_GLOB_ALTDIRFUNC
unsigned missing_directories;
unsigned missing_files;
bool have_wildcards;
#endif
static bool config_file_error;

/* local vars */
static vector_t *current_keywords;
static int sublevel = 0;
static int skip_sublevel = 0;
static LIST_HEAD_INITIALIZE(multiline_stack); /* multiline_stack_ent */
static size_t multiline_seq_depth = 0;
static char *buf_extern;
static config_err_t config_err = CONFIG_OK; /* Highest level of config error for --config-test */
static unsigned int random_seed;
static bool random_seed_configured;
static LIST_HEAD_INITIALIZE(seq_list);	/* seq_t */
static unsigned seq_list_count = 0;

/* recursive configuration stream handler */
static int kw_level;
static int block_depth;

static FILE *conf_copy;
static bool write_conf_copy;
static bool read_conf_copy;

/* Parameter definitions */
static LIST_HEAD_INITIALIZE(defs); /* def_t */

/* Forward declarations for recursion */
static bool replace_param(char *, size_t, char const **);

/* Stack of include files */
LIST_HEAD_INITIALIZE(include_stack);


static void __attribute__ ((format (printf, 2, 0 )))
vreport_config_error(config_err_t err, const char *format, va_list args)
{
	char *format_buf = NULL;
	include_file_t *file = NULL;

	if (!list_empty(&include_stack)) {
		file = list_first_entry(&include_stack, include_file_t, e_list);
		if (!file->current_file_name && !list_is_last(&file->e_list, &include_stack))
			file = list_first_entry(&file->e_list, include_file_t, e_list);
	}

	/* current_file_name will be set if there is more than one config file, in which
	 * case we need to specify the file name. */
	if (file) {
		if (file->current_file_name) {
			/* "(file_name: Line line_no) format" + '\0' */
			format_buf = MALLOC(1 + strlen(file->current_file_name) + 1 + 6 + 10 + 1 + 1 + strlen(format) + 1);
			sprintf(format_buf, "(%s: Line %zu) %s", file->current_file_name, file->current_line_no, format);
		} else if (file->current_line_no) {	/* Set while reading from config files */
			/* "(Line line_no) format" + '\0' */
			format_buf = MALLOC(1 + 5 + 10 + 1 + 1 + strlen(format) + 1);
			sprintf(format_buf, "(%s %zu) %s", "Line", file->current_line_no, format);
		}
	}

	if (config_err == CONFIG_OK || config_err < err)
		config_err = err;

	if (__test_bit(CONFIG_TEST_BIT, &debug)) {
		vfprintf(stderr, format_buf ? format_buf : format, args);
		fputc('\n', stderr);
	}
	else
		vlog_message(LOG_INFO, format_buf ? format_buf : format, args);

	if (format_buf)
		FREE(format_buf);
}

void
report_config_error(config_err_t err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vreport_config_error(err, format, args);
	va_end(args);
}

static void __attribute__ ((format (printf, 2, 3)))
file_config_error(include_t error_type, const char *format, ...)
{
	va_list args;
	include_file_t *file = NULL;

	if (!list_empty(&include_stack))
		file = list_first_entry(&include_stack, include_file_t, e_list);

	va_start(args, format);

	vreport_config_error(((include_check | (file ? file->include_type : 0)) & error_type)
			      ? CONFIG_FILE_NOT_FOUND : CONFIG_OK, format, args);
	if ((include_check | (file ? file->include_type : 0)) & error_type)
		config_file_error = true;

	/* If there is an error and we are writing the config,
	 * write the error to the file so the processes reading
	 * it can log the error. */
	if (write_conf_copy) {
		va_end(args);
		va_start(args, format);
		fprintf(conf_copy, "#! ");
		vfprintf(conf_copy, format, args);
		fprintf(conf_copy, "\n");
	}

	va_end(args);
}

#ifdef USE_MEMFD_CREATE_SYSCALL
static int
memfd_create(const char *name, unsigned int flags)
{
        int ret;

        ret = syscall(SYS_memfd_create, name, flags);

        return ret;
}
#endif

static inline int
open_tmpfile(const char *dir, int flags, mode_t mode)
{
#if HAVE_DECL_O_TMPFILE
	return open(dir, flags | O_TMPFILE, mode);
#else
	int fd;
	char *filename;
	int dir_len = strlen(dir);

	filename = MALLOC(dir_len + 1 + 17 + 1);  /* dir / keepalived_XXXXXX \0 */
	strcpy(filename, dir);
	filename[dir_len] = '/';
	strcpy(filename + dir_len + 1, "keepalived_XXXXXX");

	fd = mkostemp(filename, flags);
	unlink(filename);
	fchmod(fd, mode);

	FREE(filename);

	return fd;
#endif
}

void
use_disk_copy_for_config(const char *dir_name)
{
	int fd;
	int fd_mem;
	char buf[512];
	ssize_t len;
	FILE *new_conf_copy;

	if (!write_conf_copy)
		return;

	fd = open_tmpfile(dir_name, O_RDWR | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot open config directory %s for writing, errno %d - %m", dir_name, errno);
		return;
	}

	/* Copy what we have already written to the disk based file */
	rewind(conf_copy);
	fd_mem = fileno(conf_copy);
	lseek(fd_mem, 0L, SEEK_SET);

	while ((len = read(fd_mem, buf, sizeof(buf))) > 0) {
		if (write(fd, buf, len) != len)
			break;
	}

	if (len) {
		log_message(LOG_INFO, "Unable to config to new disk file on %s", dir_name);
		close(fd);
		return;
	}

	new_conf_copy = fdopen(fd, "a+");
	if (!new_conf_copy) {
		log_message(LOG_INFO, "fdopen of disk file error %d - %m", errno);
		close(fd);
		return;
	}

	fclose(conf_copy);
	conf_copy = new_conf_copy;
}

void
clear_config_status(void)
{
	config_err = CONFIG_OK;
}

config_err_t __attribute__ ((pure))
get_config_status(void)
{
	return config_err;
}

static void __attribute__ ((noreturn))
null_strvec(const vector_t *strvec, size_t index)
{
	if (index > 0 && index - 1 < vector_size(strvec) && vector_slot(strvec, index - 1))
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
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside range [%u, %u]", warn, number, min_val, max_val);
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

/* Read a fractional decimal with up to shift decimal places. Return value * 10^shift. For example to read 3.312 as milliseconds, but
 * return 3312, as micro-seconds, specify a shift value of 3 (i.e. 10^3 = 1000). The min_val and max_val are in the units of the returned value.
 */
static bool
read_decimal_unsigned_long_func(const char *param, unsigned long *res, unsigned long min_val, unsigned long max_val, unsigned shift, bool ignore_error)
{
	size_t param_len = strlen(param);
	char *updated_param;
	const char *dp;
	unsigned num_dp;
	const char *warn = "";
	unsigned i;
	bool round_up = false;
	bool valid_number;
	unsigned long long val;
	char *endptr;
	int sav_errno;

#ifndef _STRICT_CONFIG_
	if (ignore_error && !__test_bit(CONFIG_TEST_BIT, &debug))
		warn = "WARNING - ";
#endif

	if (param[0] == '-') {
		report_config_error(CONFIG_INVALID_NUMBER, "%snegative number '%s'", warn, param);
		return false;
	}

	/* Make sure we don't have too many decimal places */
	dp = strchr(param, '.');
	num_dp = dp ? param_len - (dp - param) - 1 : 0;
	if (num_dp > shift) {
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' has too many decimal places", warn, param);
		round_up = dp[shift + 1] >= '5';
		num_dp = shift;
	}

	updated_param = MALLOC(param_len + shift + 1);	/* Allow to add shift trailing 0's and '\0' */

	if (dp) {
		strncpy(updated_param, param, dp - param);
		strncpy(updated_param + (dp - param), dp + 1, num_dp);
		updated_param[dp - param + num_dp] = '\0';
	} else
		strcpy(updated_param, param);

	/* Add any necessary trailing 0s */
	num_dp = shift - num_dp;
	for (i = 0; i < num_dp; i++)
		strcat(updated_param, "0");

	errno = 0;
	val = strtoull(updated_param, &endptr, 10);
	if (round_up)
		val++;
	*res = (unsigned long)val;

	valid_number = !*endptr;
	sav_errno = errno;
	FREE(updated_param);

	if (!valid_number)
		report_config_error(CONFIG_INVALID_NUMBER, "%sinvalid number '%s'", warn, param);
	else if (sav_errno == ERANGE
#if ULLONG_MAX > ULONG_MAX
				     || val > ULONG_MAX
#endif
							) {
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside unsigned decimal range", warn, param);
		return false;
	} else if (val < min_val || val > max_val) {
		unsigned long dp_val = 1;
		unsigned d;
		for (d = 0; d < shift; d++)
			dp_val *= 10;
		report_config_error(CONFIG_INVALID_NUMBER, "%snumber '%s' outside range [%lu.%*.*lu, %lu.%*.*lu]",
			warn, param, min_val / dp_val, (int)shift, (int)shift, min_val % dp_val, max_val / dp_val, (int)shift, (int)shift, max_val % dp_val);
	} else
		return true;

#ifdef _STRICT_CONFIG_
	return false;
#else
	return ignore_error && val >= min_val && val <= max_val;
#endif
}

static bool
read_decimal_unsigned_func(const char *str, unsigned *res, unsigned min_val, unsigned max_val, unsigned shift, bool ignore_error)
{
	unsigned long resl;
	int ret;

	ret = read_decimal_unsigned_long_func(str, &resl, min_val, max_val, shift, ignore_error);
	if (ret)
		*res = (unsigned)resl;

	return ret;
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
read_decimal_unsigned(const char *str, unsigned *res, unsigned min_val, unsigned max_val, unsigned shift, bool ignore_error)
{
	return read_decimal_unsigned_func(str, res, min_val, max_val, shift, ignore_error);
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
read_unsigned_base_strvec(const vector_t *strvec, size_t index, int base, unsigned *res, unsigned min_val, unsigned max_val, bool ignore_error)
{
	return read_unsigned_func(strvec_slot(strvec, index), base, res, min_val, max_val, ignore_error);
}

bool
read_decimal_unsigned_strvec(const vector_t *strvec, size_t index, unsigned *res, unsigned min_val, unsigned max_val, unsigned shift, bool ignore_error)
{
	return read_decimal_unsigned_func(strvec_slot(strvec, index), res, min_val, max_val, shift, ignore_error);
}

/* read_hex_str() reads a hex string, which can include spaces, and saves the string in
 * MALLOC'd memory at data.
 * Hex characters 0-9, A-F and a-f are valid.
 * The string can include wildcard characters, x or X, in which
 * case mask will be allocated and used to indicate the wildcard half octets (nibbles)
 */
static uint8_t
hex_val(char p, bool allow_wildcard)
{
	if (p >= '0' && p <= '9')
		return p - '0';
	if (p >= 'a')
		p -= ('a' - 'A');
	if (p >= 'A' && p <= 'F')
		return p - 'A' + 10;

	if (allow_wildcard && p == 'X')
		return 0xfe;

	return 0xff;
}

uint16_t
read_hex_str(const char *str, uint8_t **data, uint8_t **data_mask)
{
	size_t str_len;
	uint8_t *buf;
	uint8_t *mask;
	const char *p = str;
	uint8_t val = 0;
	uint8_t val1;
	uint8_t mask_val;
	bool using_mask = false;
	uint16_t len;

	/* The output octet string cannot be longer than (strlen(str) + 1)/2 */
	str_len = (strlen(str) + 1) / 2;
	buf = MALLOC(str_len);
	mask = MALLOC(str_len);

	len = 0;
	while (true) {
		/* Skip spaces */
		while (*p == ' ' || *p == '\t')
			p++;

		if (!*p)
			break;

		val = hex_val(*p++, !!data_mask);
		if (val == 0xff)
			break;
		if (val == 0xfe) {
			mask_val = 0x0f;
			val = 0;
			using_mask = true;
		} else
			mask_val = 0;

		if (*p && *p != ' ') {
			val1 = val << 4;
			mask_val <<= 4;
			val = hex_val(*p++, !!data_mask);
			if (val == 0xff)
				break;
			if (val == 0xfe) {
				mask_val |= 0x0f;
				val = 0;
				using_mask = true;
			}
			val |= val1;
		}

		buf[len] = val;
		mask[len] = mask_val;
		len++;
	}

	if (val == 0xff || !len) {
		FREE_ONLY(buf);
		FREE_ONLY(mask);
		return 0;
	}

	/* Reduce the buffer size of appropriate */
	if (len < str_len) {
		buf = REALLOC(buf, len);
		if (using_mask)
			mask = REALLOC(mask, len);
	}

	*data = buf;
	if (using_mask)
		*data_mask = mask;
	else
		FREE_ONLY(mask);

#if 0
	for (int i = 0;  i < len; i++)
		printf("%2.2X ", buf[i]);
	printf("\n");

	for (i = 0;  i < len; i++)
		printf("%2.2X ", mask[i]);
	printf("\n");
#endif

	return len;
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

	PMALLOC(keyword);
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
	char *file_name;
	char file_name_len;

	if (!level) {
		file_name_len = strlen(tmp_dir) + 1 + 8 + 1 + PID_MAX_DIGITS + 1;		/* TMP_DIR/keywords.PID\0 */
		file_name = MALLOC(file_name_len);
		snprintf(file_name, file_name_len, "%s/keywords.%d", tmp_dir, getpid());

		fp = fopen_safe(file_name, "w");

		FREE(file_name);

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

static const char * __attribute__((malloc))
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

#ifdef _PARSER_DEBUG_
static void
dump_seq_lst(const seq_t *seq)
{
	param_t *param;
	value_set_t *value_set;
	value_t *value;
	char *buf = MALLOC(1024);
	char *p;

	/* List the parameters */
	p = buf;
	list_for_each_entry(param, &seq->lst_params, e_list)
		p += snprintf(p, buf + 1024 - p, "%s%s", p == buf ? "" : ", ", param->name);
	log_message(LOG_INFO, "LST parameters: %s", buf);

	/* List the values */
	list_for_each_entry(value_set, &seq->lst_values, e_list) {
		/* List the values in the value set */
		buf[0] = '\0';
		p = buf;
		list_for_each_entry(value, &value_set->values, e_list)
			p += snprintf(p, buf + 1024 - p, "%s%s", p == buf ? "" : ", ", value->val);
		log_message(LOG_INFO, "    values:     %s", buf);
	}

	FREE(buf);
}

static void
dump_seqs(void)
{
	seq_t *seq;

	list_for_each_entry(seq, &seq_list, e_list) {
		if (!list_empty(&seq->lst_params)) {
			dump_seq_lst(seq);
		} else if (seq->hex)
			log_message(LOG_INFO, "SEQ: %s => 0x%lx -> 0x%lx step %ld: '%s'", seq->var, (unsigned long)seq->next, (unsigned long)seq->last, seq->step, seq->text);
		else
			log_message(LOG_INFO, "SEQ: %s => %ld -> %ld step %ld: '%s'", seq->var, seq->next, seq->last, seq->step, seq->text);
	}
	log_message(LOG_INFO, "%s", "");
}
#endif

static void
free_seq(seq_t *seq)
{
	list_del_init(&seq->e_list);
	FREE_CONST(seq->var);
	FREE_CONST(seq->text);
	FREE(seq);
	seq_list_count--;
}

static void
free_seq_lst(seq_t *seq)
{
	param_t *param, *param_tmp;
	value_set_t *value_set, *value_set_tmp;
	value_t *value, *value_tmp;

	list_del_init(&seq->e_list);

	/* Free the parameters */
	list_for_each_entry_safe(param, param_tmp, &seq->lst_params, e_list) {
		list_del_init(&param->e_list);
		FREE_CONST(param->name);
		FREE(param);
	}

	/* Free the values */
	list_for_each_entry_safe(value_set, value_set_tmp, &seq->lst_values, e_list) {
		/* Free the values in a value set */
		list_for_each_entry_safe(value, value_tmp, &value_set->values, e_list) {
			list_del_init(&value->e_list);
			FREE_CONST(value->val);
			FREE(value);
		}
		list_del_init(&value_set->e_list);
		FREE(value_set);
	}

	FREE_CONST(seq->text);
	FREE(seq);
	seq_list_count--;
}

static void
free_seq_list(list_head_t *l)
{
	seq_t *seq, *seq_tmp;

	list_for_each_entry_safe(seq, seq_tmp, l, e_list) {
		if (list_empty(&seq->lst_params))
			free_seq(seq);
		else
			free_seq_lst(seq);
	}
}

static bool
add_seq(char *buf)
{
	char *p = buf + 4;	/* Skip ~SEQ */
	bool hex;
	long one, two, three;
	long start, step, end;
	seq_t *seq_ent;
	const char *var;
	const char *var_end;
	const char *multiline = NULL;
	char seq_buf[3 * 20 + 3 + 1]; /* 3 longs, each with , or ) after plus terminating nul */
	char *end_seq;

	/* Do we want the output in hex format - e.g. for IPv6 addresses */
	if (*p == 'x') {
		p++;
		hex = true;
	} else
		hex = false;

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

	/* Convert any parameters of ~SEQ which are definitions */
	p++;
	p += strspn(p, " \t");
	end_seq = strchr(p, ')');
	if ((size_t)(end_seq + 1 - p + 1) > sizeof(seq_buf)) {
		report_config_error(CONFIG_GENERAL_ERROR, "~SEQ parameter strings too long '%s'", buf);
		return false;
	}
	strncpy(seq_buf, p, end_seq + 1 - p);
	seq_buf[end_seq + 1 - p] = '\0';
	replace_param(seq_buf, sizeof(seq_buf), &multiline);
	if (multiline) {
		report_config_error(CONFIG_GENERAL_ERROR, "~SEQ parameter is multiline definition '%s'", buf);
		return false;
	}

	p = seq_buf;
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

	if (hex && (start < 0 || end < 0)) {
		report_config_error(CONFIG_GENERAL_ERROR, "~SEQx is only valid for positive numbers '%s'", buf);
		return false;
	}

	p = end_seq;
	p += strspn(p + 1, " \t") + 1;

	PMALLOC(seq_ent);
	INIT_LIST_HEAD(&seq_ent->e_list);
	INIT_LIST_HEAD(&seq_ent->lst_params);
	INIT_LIST_HEAD(&seq_ent->lst_values);
	seq_ent->var = STRNDUP(var, var_end - var);
	seq_ent->next = start;
	seq_ent->step = step;
	seq_ent->last = end;
	seq_ent->hex = hex;
	seq_ent->text = STRDUP(p);

	list_add_tail(&seq_ent->e_list, &seq_list);
	seq_list_count++;

	return true;
}

static bool
add_lst(char *buf)
{
	char *p = buf + 4;	/* Skip ~LST */
	seq_t *seq_ent;
	const char *var;
	const char *var_end;
	param_t *param;
	value_set_t *value_set;
	value_t *value;
	unsigned num_vars = 0;
	unsigned num_values;
	char end_char;

	PMALLOC(seq_ent);
	INIT_LIST_HEAD(&seq_ent->e_list);
	INIT_LIST_HEAD(&seq_ent->lst_params);
	INIT_LIST_HEAD(&seq_ent->lst_values);

	p += strspn(p, " \t");
	if (*p++ != '(') {
		free_seq_lst(seq_ent);
		return false;
	}

	p += strspn(p, " \t");

	if (*p == '{') {
		end_char = '}';
		p++;
		p += strspn(p, " \t");
	} else
		end_char = ',';

	while (true) {
		var = p;
		var_end = p += strcspn(p, " \t,}");
		PMALLOC(param);
		INIT_LIST_HEAD(&param->e_list);

		param->name = STRNDUP(var, var_end - var);
		list_add_tail(&param->e_list, &seq_ent->lst_params);

		p += strspn(p, " \t");
		if (*p == end_char)
			break;
		if (*p != ',') {
			free_seq_lst(seq_ent);
			return false;
		}
		p += strspn(p + 1, " \t") + 1;
		num_vars++;
	}
	if (*p == '}')
		p += strspn(p + 1, " \t") + 1;
	if (*p++ != ',') {
		free_seq_lst(seq_ent);
		return false;
	}

	/* Read the values */
	p += strspn(p, " \t");

	while (true) {
		PMALLOC(value_set);
		INIT_LIST_HEAD(&value_set->e_list);
		INIT_LIST_HEAD(&value_set->values);

		if (*p == '{') {
			end_char = '}';
			p++;
			p += strspn(p, " \t");
		} else
			end_char = ',';

		/* Read one set of values */
		num_values = 0;
		while (true) {
			var = p;
			var_end = p += strcspn(p, " \t,})");
			PMALLOC(value);
			INIT_LIST_HEAD(&value->e_list);

			value->val = STRNDUP(var, var_end - var);
			list_add_tail(&value->e_list, &value_set->values);

			p += strspn(p, " \t");
			if (*p == end_char || (*p == ')' && end_char == ','))
				break;
			if (*p != ',') {
				free_seq_lst(seq_ent);
				return false;
			}
			p += strspn(p + 1, " \t") + 1;

			if (++num_values > num_vars) {
				report_config_error(CONFIG_GENERAL_ERROR, "~LST specification has too many values '%s'", buf);
				free_seq_lst(seq_ent);
				return false;
			}
		}

		/* Any missing parameters are blank */
		for (; num_values < num_vars; num_values++) {
			PMALLOC(value);
			value->val = STRDUP("");
			INIT_LIST_HEAD(&value->e_list);
			list_add_tail(&value->e_list, &value_set->values);
		}

		/* Add the value_set to the list of value_sets */
		list_add_tail(&value_set->e_list, &seq_ent->lst_values);

		if (*p == '}' && end_char == '}')
			p += strspn(p + 1, " \t") + 1;
		if (*p == ')')
			break;
		if (*p != ',') {
			free_seq_lst(seq_ent);
			return false;
		}

		p += strspn(p + 1, " \t") + 1;
	}

	if (list_empty(&seq_ent->lst_params) || list_empty(&seq_ent->lst_values)) {
		free_seq_lst(seq_ent);
		return false;
	}

	p += strspn(p + 1, " \t") + 1;
	seq_ent->next_var = list_first_entry(&seq_ent->lst_values, value_set_t, e_list);
	seq_ent->text = STRDUP(p);
	list_add_tail(&seq_ent->e_list, &seq_list);
	seq_list_count++;

	return true;
}

#ifdef _PARSER_DEBUG_
static void
dump_definitions(void)
{
	def_t *def;

	list_for_each_entry(def, &defs, e_list)
		log_message(LOG_INFO, "Defn %s = '%s'", def->name, def->value);
	log_message(LOG_INFO, "%s", "");
}
#endif

#if HAVE_DECL_GLOB_ALTDIRFUNC
static DIR *
gl_opendir(const char *name)
{
	DIR *dirp;

	have_wildcards = true;

	dirp = opendir(name);

	if (!dirp)
		missing_directories++;

	return dirp;
}

static int
gl_lstat(const char *pathname, struct stat *statbuf)
{
	int ret;

	ret = lstat(pathname, statbuf);

	if (ret)
		missing_files++;

	return ret;
}

static bool __attribute__((pure))
have_brace(const char *conf_file)
{
	const char *p = conf_file;

	if (!*p)
		return false;

	do {
		if (*p == '\\')
			p++;
		else if (*p == '{')
			return true;
	} while (*++p);

	return false;
}
#endif

static bool
open_and_check_glob(glob_t *globbuf, const char *conf_file, include_t include_type)
{
	int	res;

	globbuf->gl_offs = 0;

#if HAVE_DECL_GLOB_ALTDIRFUNC
	globbuf->gl_closedir = (void *)closedir;
	globbuf->gl_readdir = (void *)readdir;
	globbuf->gl_opendir = (void *)gl_opendir;
	globbuf->gl_lstat = (void *)gl_lstat;
	globbuf->gl_stat = (void *)stat;
#endif

	/* NOTE: the following three variables are not declared static, since otherwise GCC (at least v9.3.0,
	 * 9.3.1 and 10.2.1) -O1 optimisation assumes that they cannot be altered by the call to glob(), if
	 * they have static scope. Declaring them static volatile also solves the problem, as does not
	 * initialising the values in this function (which just wouldn't work).
	 * This is an optimisation error of course, since the gl_opendir() and gl_lstat() functions can modify
	 * the values, and pointers to these functions are passed to glob().
	 * What makes this even more difficult is that if the values of missing_directories and missing_files
	 * are printed in a log_message() after the return from glob(), then everything works OK.
	 *
	 * See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=97783 for more details.
	 */
#if HAVE_DECL_GLOB_ALTDIRFUNC
	missing_files = 0;
	missing_directories = 0;
	have_wildcards = false;
#endif

	res = glob(conf_file, GLOB_MARK
#if HAVE_DECL_GLOB_BRACE
					| GLOB_BRACE
#endif
#if HAVE_DECL_GLOB_ALTDIRFUNC
					| GLOB_ALTDIRFUNC
#endif
						    , NULL, globbuf);

	if (res) {
		if (res == GLOB_NOMATCH) {
#if HAVE_DECL_GLOB_ALTDIRFUNC
			if (missing_files || missing_directories)
				file_config_error(have_brace(conf_file) ? INCLUDE_B : INCLUDE_M, "Config files missing '%s'.", conf_file);
			else if (have_wildcards && ((include_check | include_type) & INCLUDE_W))
				file_config_error(INCLUDE_W, "No config files matched '%s'.", conf_file);
#else
			if ((include_check | include_type) & INCLUDE_W)
				file_config_error(INCLUDE_W, "No config files matched '%s'.", conf_file);
#endif
		} else
			file_config_error(INCLUDE_R, "Error reading config file(s): glob(\"%s\") returned %d, skipping.", conf_file, res);

		return false;
	}

#if HAVE_DECL_GLOB_ALTDIRFUNC
	if (missing_directories || missing_files) {
		file_config_error(INCLUDE_B, "Some config files missing: \"%s\".", conf_file);

		if ((include_check | include_type) & INCLUDE_B) {
			globfree(globbuf);
			return false;
		}
	}
#endif

	return true;
}

static bool
check_glob_file(const char *file_name)
{
	struct stat stb;

	if (file_name[0] && file_name[strlen(file_name)-1] == '/') {
		/* This is a directory - so skip */
		file_config_error(INCLUDE_R, "Configuration file '%s' is a directory - skipping"
				, file_name);
		return false;
	}

	/* Make sure what we have opened is a regular file, and not for example a directory or executable */
	if (stat(file_name, &stb) ||
	    !S_ISREG(stb.st_mode) ||
	    (stb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		file_config_error(INCLUDE_R, "Configuration file '%s' is not a regular non-executable file - skipping", file_name);
		return false;
	}

	return true;
}

bool
check_conf_file(const char *conf_file)
{
	glob_t globbuf;
	size_t i;
	bool ret = true;
	unsigned num_matches = 0;

	if (!open_and_check_glob(&globbuf, conf_file, INCLUDE))
		return false;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		if (!check_glob_file(globbuf.gl_pathv[i])) {
			ret = false;
			continue;
		}

		if (access(globbuf.gl_pathv[i], R_OK)) {
			report_config_error(CONFIG_FILE_NOT_FOUND, "Unable to read configuration file %s", globbuf.gl_pathv[i]);
			ret = false;
			break;
		}

		num_matches++;
	}

	if (ret) {
		if (num_matches > 1)
			report_config_error(CONFIG_MULTIPLE_FILES, "WARNING, multiple configuration file matches of %s, starting with %s", conf_file, globbuf.gl_pathv[0]);
		else if (num_matches == 0) {
			report_config_error(CONFIG_FILE_NOT_FOUND, "Unable to find configuration file %s", conf_file);
			ret = false;
		}
	}

	globfree(&globbuf);

	return ret;
}

static def_t * __attribute__ ((pure))
find_definition(const char *name, size_t len, bool definition)
{
	def_t *def;
	const char *p;
	bool using_braces = false;
	bool allow_multiline;
	const char *param_start = NULL;
	const char *param_end = NULL;

	if (list_empty(&defs))
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
		} else if (!definition && *p != ' ' && *p != '\t' && *p != ',' && *p != ')' && *p != '\0')
			return NULL;
	}

	if (definition ||
	    (!using_braces && name[len] == '\0') ||
	    (using_braces && name[len+1] == '\0'))
		allow_multiline = true;
	else
		allow_multiline = false;

	list_for_each_entry(def, &defs, e_list) {
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
free_multiline_stack_list(list_head_t *l)
{
	multiline_stack_ent *stack, *stack_tmp;

	list_for_each_entry_safe(stack, stack_tmp, l, e_list) {
		list_del_init(&stack->e_list);
		FREE(stack);
	}
}

static void
multiline_stack_push(const char *ptr)
{
	multiline_stack_ent *stack_ent;

	PMALLOC(stack_ent);
	INIT_LIST_HEAD(&stack_ent->e_list);
	stack_ent->ptr = ptr;
	stack_ent->seq_depth = multiline_seq_depth;

	list_add_tail(&stack_ent->e_list, &multiline_stack);
}

static const char *
multiline_stack_pop(void)
{
	multiline_stack_ent *stack_ent;
	const char *next_ptr;

	if (list_empty(&multiline_stack))
		return NULL;

	stack_ent = list_last_entry(&multiline_stack, multiline_stack_ent, e_list);
	next_ptr = stack_ent->ptr;
	multiline_seq_depth = stack_ent->seq_depth;

	list_del_init(&stack_ent->e_list);
	FREE(stack_ent);

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
				multiline_seq_depth = seq_list_count;

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
free_def(def_t *def)
{
	list_del_init(&def->e_list);
	FREE_CONST(def->name);
	FREE_CONST_PTR(def->value);
	FREE(def);
}
static void
free_def_list(list_head_t *l)
{
	def_t *def, *def_tmp;

	list_for_each_entry_safe(def, def_tmp, l, e_list)
		free_def(def);
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
		PMALLOC(def);
		INIT_LIST_HEAD(&def->e_list);
		def->name_len = name_len;
		def->name = STRNDUP(name, def->name_len);

		list_add_tail(&def->e_list, &defs);
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
		PMALLOC(def);
		INIT_LIST_HEAD(&def->e_list);
		def->name_len = def_name_len;
		def->name = STRNDUP(buf + 1, def->name_len);

		list_add_tail(&def->e_list, &defs);
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

	PMALLOC(def);
	INIT_LIST_HEAD(&def->e_list);
	def->name_len = strlen(name);
	def->name = STRNDUP(name, def->name_len);
	if (value) {
		def->value_len = strlen(value);
		def->value = STRNDUP(value, def->value_len);
	}
	def->fn = fn;
	def->max_params = max_params;

	list_add_tail(&def->e_list, &defs);
}

static void
set_std_definitions(void)
{
	time_t tim;

	add_std_definition("_PWD", NULL, get_cwd, 0);
	add_std_definition("_INSTANCE", NULL, get_instance, 0);
	add_std_definition("_RANDOM", NULL, get_random, 2);
	add_std_definition("_HASH", "#", NULL, 0);
	add_std_definition("_BANG", "!", NULL, 0);

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
	free_def_list(&defs);
	free_multiline_stack_list(&multiline_stack);
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

	alloc_value_block(read_value_block_line, strvec);

	ret_vec = read_value_block_vec;
	read_value_block_vec = NULL;

	return ret_vec;
}

/* min_time and max_time are in micro-seconds. The returned value is also in micro-seconds */
bool
read_timer(const vector_t *strvec, size_t index, unsigned long *res, unsigned long min_time, unsigned long max_time, bool ignore_error)
{
	unsigned long timer;
	bool ret;

	if (!max_time)
		max_time = TIMER_MAXIMUM;

	ret = read_decimal_unsigned_long_func(strvec_slot(strvec, index), &timer, min_time, max_time, TIMER_HZ_DIGITS, ignore_error);

	if (ret)
		*res = timer;

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

static bool
open_conf_file(include_file_t *file)
{
	unsigned i;
	FILE *stream;

	while (file->glob_next < file->globbuf.gl_pathc) {
		i = file->glob_next++;

		if (!check_glob_file(file->globbuf.gl_pathv[i]))
			continue;

		stream = fopen(file->globbuf.gl_pathv[i], "r");
		if (!stream) {
			file_config_error(INCLUDE_R, "Configuration file '%s' open problem (%s) - skipping"
					       , file->globbuf.gl_pathv[i], strerror(errno));
			continue;
		}

		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "Opening file '%s'.", file->globbuf.gl_pathv[i]);

		/* Allow tracking of file names/numbers */
		if (write_conf_copy)
			fprintf(conf_copy, "# %s\n", file->globbuf.gl_pathv[i]);

		file->stream = stream;
		file->num_matches++;

		/* We only want to report the file name if there is more than one file used */
		if (!list_is_last(&file->e_list, &include_stack) || file->globbuf.gl_pathc > 1)
			file->current_file_name = file->globbuf.gl_pathv[i];
		file->current_line_no = 0;

		if (strchr(file->globbuf.gl_pathv[i], '/')) {
			/* If the filename contains a directory element, change to that directory. */
			file->curdir_fd = open(".", O_RDONLY | O_DIRECTORY | O_PATH);

			char *confpath = STRDUP(file->globbuf.gl_pathv[i]);
			dirname(confpath);
			if (chdir(confpath) < 0)
				file_config_error(INCLUDE_R, "chdir(%s) error (%s)", confpath, strerror(errno));
			FREE(confpath);
		} else
			file->curdir_fd = -1;

		return true;
	}

	return false;
}

static bool
open_glob_file(const char *conf_file, include_t include_type)
{
	include_file_t *file;

	PMALLOC(file);
	INIT_LIST_HEAD(&file->e_list);

	file->include_type = include_type;
	file->sav_include_check = include_check;
	list_head_add(&file->e_list, &include_stack);

	if (!open_and_check_glob(&file->globbuf, conf_file, include_type)) {
		list_head_del(&file->e_list);
		FREE(file);
		return false;
	}

	if (!open_conf_file(file)) {
		if (!file->globbuf.gl_pathc)
			file_config_error(INCLUDE_R, "%s - no matching file", conf_file);

		globfree(&file->globbuf);
		list_head_del(&file->e_list);
		FREE(file);
		return false;
	}

	file->file_name = STRDUP(conf_file);

	return true;
}

static bool
end_file(include_file_t *file)
{
	int res;

	if (file->stream != conf_copy)
		fclose(file->stream);

	if (write_conf_copy) {
		/* Indicate a file is being closed */
		fprintf(conf_copy, "!\n");
	}

// WHY??
//	free_seq_list(&seq_list);

	/* Restore the include_check value from when this glob was opened */
	include_check = file->sav_include_check;

	/* If we changed directory, restore the previous directory */
	if (file->curdir_fd != -1) {
		if ((res = fchdir(file->curdir_fd)))
			log_message(LOG_INFO, "Failed to restore previous directory after include");
		close(file->curdir_fd);
		if (res)
			return false;
	}

	return true;
}

static void
end_glob(include_file_t *file)
{
	if (!file->num_matches)
		log_message(LOG_INFO, "No config files matched '%s'.", file->file_name);

	globfree(&file->globbuf);
	FREE_CONST_PTR(file->file_name);

	list_del_init(&file->e_list);
	FREE(file);
}

static bool
get_next_file(void)
{
	include_file_t *file = list_first_entry(&include_stack, include_file_t, e_list);

	end_file(file);

	if (open_conf_file(file))
		return true;

	end_glob(file);

	if (list_empty(&include_stack))
		return false;

	file = list_first_entry(&include_stack, include_file_t, e_list);

	return true;
}

static bool
is_include(const char *buf)
{
	if (strncmp(buf, "include", 7))
		return false;

	if (!buf[7])
		return false;

	if (isspace(buf[7]))
		return true;

	/* Is "include" followed by one of the value include types? */
	if (isspace(buf[8]) && strchr("rmwba", buf[7]))
		return true;

	return false;
}

static bool
check_include(const char *buf)
{
	const char *p;
	include_t include_type;

	if (!is_include(buf))
		return false;

	if (isspace(buf[7])) {
		p = buf + 8;
		include_type = INCLUDE;
	} else {
		p = buf + 9;
		if (buf[7] == 'r')
			include_type = INCLUDE_R;
		else if (buf[7] == 'a')
			include_type = INCLUDE_R | INCLUDE_M | INCLUDE_B | INCLUDE_W;
		else if (buf[7] == 'w')
			include_type = INCLUDE_R | INCLUDE_M | INCLUDE_W;
#if HAVE_DECL_GLOB_ALTDIRFUNC
		else if (buf[7] == 'm')
			include_type = INCLUDE_R | INCLUDE_M;
		else /* if (buf[7] == 'b') */
			include_type = INCLUDE_R | INCLUDE_B;
#else
		else {
			report_config_error(CONFIG_WARNING, "include%c not supported - treating as includer", buf[7]);
			include_type = INCLUDE_R;
		}
#endif
	}

	p += strspn(p, " \t");

	open_glob_file(p, include_type);

	return true;
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
	list_head_t *next_value;
	value_t *value;
	param_t *param;
	include_file_t *file;

	config_id_len = config_id ? strlen(config_id) : 0;
	do {
		if (line_residue) {
			strcpy(buf, line_residue);
			FREE(line_residue);
			line_residue = NULL;
		} else if (!list_empty(&seq_list) &&
			seq_list_count > multiline_seq_depth) {
			seq_t *seq = list_last_entry(&seq_list, seq_t, e_list);
			if (list_empty(&seq->lst_params)) {
				char val[21];
				if (seq->hex)
					snprintf(val, sizeof(val), "%lx", (unsigned long)seq->next);
				else
					snprintf(val, sizeof(val), "%ld", seq->next);
#ifdef _PARSER_DEBUG_
				if (do_parser_debug)
					log_message(LOG_INFO, "Processing seq %ld of %s for '%s'",  seq->next, seq->var, seq->text);
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
					free_seq(seq);
				}
			} else {
				next_value = seq->next_var->values.next;
				list_for_each_entry(param, &seq->lst_params, e_list) {
					value = list_entry(next_value, value_t, e_list);
#ifdef _PARSER_DEBUG_
					if (do_parser_debug)
						log_message(LOG_INFO, "Processing lst %s = '%s'",  param->name, value->val);
#endif
					set_definition(param->name, value->val);
					strcpy(buf, seq->text);
					next_value = next_value->next;
				}
				if (list_is_last(&seq->next_var->e_list, &seq->lst_values)) {
#ifdef _PARSER_DEBUG_
					if (do_parser_debug)
						log_message(LOG_INFO, "Removing lst");
#endif
					free_seq_lst(seq);
				} else
					seq->next_var = list_entry(seq->next_var->e_list.next, value_set_t, e_list);
			}
		} else if (next_ptr) {
			/* We are expanding a multiline parameter, so copy next line */
			end = strchr(next_ptr, DEF_LINE_END[0]);
			if (!end) {
				strcpy(buf, next_ptr);
				if (!list_empty(&multiline_stack))
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
		} else {
			/* Get the next non-blank line */

			/* Check we haven't completed all the files */
			if (list_empty(&include_stack)) {
				eof = true;
				buf[0] = '\0';
				break;
			}

			file = list_first_entry(&include_stack, include_file_t, e_list);

			do {
				if (!fgets(buf, (int)size, file->stream))
				{
					if (get_next_file()) {
						file = list_first_entry(&include_stack, include_file_t, e_list);
						buf[0] = '\0';
						continue;
					}

					eof = true;
					buf[0] = '\0';
					break;
				}

				if (read_conf_copy) {
					if (buf[0] == '#') {
						if (buf[1] == '!') {
#ifndef _ONE_PROCESS_DEBUG_
							if (prog_type == PROG_TYPE_PARENT)
#endif
								report_config_error(CONFIG_FILE_NOT_FOUND, "%.*s", (int)strlen(buf + 3) - 1, buf + 3);
							buf[0] = '\0';
							continue;
						}

						FILE *fps = file->stream;

						PMALLOC(file);
						INIT_LIST_HEAD(&file->e_list);

						file->stream = fps;
						file->globbuf.gl_offs = 0;
						file->num_matches = 1;
						buf[strlen(buf) - 1] = '\0';
						file->file_name = STRDUP(buf + 2);
						file->current_file_name = file->file_name;
						list_head_add(&file->e_list, &include_stack);
						if (strchr(file->current_file_name, '/')) {
							/* If the filename contains a directory element, change to that directory. */
							file->curdir_fd = open(".", O_RDONLY | O_DIRECTORY | O_PATH);

							char *confpath = STRDUP(buf + 2);
							dirname(confpath);
							if (chdir(confpath) < 0)
								log_message(LOG_INFO, "chdir(%s) error (%s)", confpath, strerror(errno));
							FREE(confpath);
						} else
							file->curdir_fd = -1;

						buf[0] = '\0';
						continue;
					} else if (buf[0] == '!') {
						if (file->curdir_fd != -1) {
							if (fchdir(file->curdir_fd))
								log_message(LOG_INFO, "Failed to restore previous directory after include");
							close(file->curdir_fd);
						}
						file = list_first_entry(&include_stack, include_file_t, e_list);
						FREE_CONST_PTR(file->current_file_name);

						list_del_init(&file->e_list);
						FREE(file);
						file = list_first_entry(&include_stack, include_file_t, e_list);

						buf[0] = '\0';
						continue;
					}
				}

				/* Check if we have read the end of a line */
				len = strlen(buf);
				if (len && buf[len-1] == '\n') {
					file->current_line_no++;
					len--;
				}

				/* Remove end of line chars */
				while (len && (buf[len-1] == '\n' || buf[len-1] == '\r'))
					len--;

				if (!len && multiline_param_def) {
					multiline_param_def = false;
					if (!def->value_len)
						def->multiline = false;
				}

				buf[len] = '\0';
				if (!len) {
					/* We need to preserve line numbers */
					if (write_conf_copy)
						fprintf(conf_copy, "\n");
					continue;
				}

				decomment(buf);

				if (write_conf_copy) {
					if (is_include(buf)) {
						/* We need to preserve line numbers */
						fprintf(conf_copy, "\n");
					} else
						fprintf(conf_copy, "%s\n", buf);
				}
			} while (!buf[0]);

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

		do {
			recheck = false;
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

// TODO TODO TODO - how do we deal with multiple ~SEQ on one line?
// Do we need to find closing ) and process rest of line?
			if (!strncmp(buf, "~SEQ", 4) || !strncmp(buf, "~LST", 4)) {
				if (buf[1] == 'S') {
					if (!add_seq(buf))
						report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~SEQ specification '%s'", buf);
				} else {
					if (!add_lst(buf))
						report_config_error(CONFIG_GENERAL_ERROR, "Invalid ~LST specification '%s'", buf);
				}
#ifdef _PARSER_DEBUG_
				if (do_parser_debug) {
					dump_definitions();
					dump_seqs();
				}
#endif
				buf[0] = '\0';
				continue;
			}

			if (buf[0] == '~')
				break;

			if (!list_empty(&defs) && (p = strchr(buf, '$'))) {
				if (!replace_param(buf, size, &next_ptr)) {
					/* If nothing has changed, we don't need to do any more processing */
					break;
				}

				decomment(buf);

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

#if defined _MEM_CHECK_ && 0
	log_mem_check_message("read_line returns (eof %d) '%s'", eof, buf);
#endif

	return !eof;
}

void
alloc_value_block(void (*alloc_func) (const vector_t *), const vector_t *strvec)
{
	char *buf;
	const char *str;
	vector_t *vec;
	vector_t *first_vec = NULL;
	bool need_bob = true;
	bool had_eob = false;

	if (vector_active(strvec) > 1) {
		if (!strcmp(strvec_slot(strvec, 1), BOB)) {
			need_bob = false;
			if (vector_active(strvec) > 2) {
				first_vec = vector_copy(strvec);
				vector_unset(first_vec, 0);
				vector_unset(first_vec, 1);
				if (!strcmp(strvec_slot(strvec, vector_active(first_vec) - 1), EOB)) {
					vector_unset(first_vec, vector_active(first_vec) - 1);
					had_eob = true;
				}
				first_vec = vector_compact(first_vec);
			}
		} else
			report_config_error(CONFIG_GENERAL_ERROR, "Block %s has extra parameters %s ..."
								, strvec_slot(strvec, 0), strvec_slot(strvec, 1));
	}

	buf = (char *)MALLOC(MAXBUF);
	while (first_vec || read_line(buf, MAXBUF)) {
		if (first_vec)
			vec = first_vec;
		else if (!(vec = alloc_strvec(buf)))
			continue;

		if (!first_vec) {
			if (need_bob) {
				need_bob = false;

				if (!strcmp(vector_slot(vec, 0), BOB)) {
					if (vector_size(vec) == 1) {
						free_strvec(vec);
						continue;
					}

					/* Remove the BOB */
					vec = strvec_remove_slot(vec, 0);
				} else
					log_message(LOG_INFO, "'%s' missing from beginning of block %s", BOB, strvec_slot(strvec, 0));
			}

			/* Check if line read ends with EOB */
			str = vector_slot(vec, vector_active(vec) - 1);
			if (!strcmp(str, EOB)) {
				if (vector_active(vec) == 1) {
					free_strvec(vec);
					break;
				}

				had_eob = true;
				vec = strvec_remove_slot(vec, vector_active(vec) - 1);
			}
		}

		if (vector_size(vec))
			(*alloc_func)(vec);

		if (first_vec) {
			vector_free(first_vec);
			first_vec = NULL;
		} else
			free_strvec(vec);

		if (had_eob)
			break;
	}

	FREE(buf);
}

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

/* Data initialization */
void
init_data(const char *conf_file, const vector_t * (*init_keywords) (void), bool copy_config)
{
	bool file_opened = false;
	int fd;
#ifndef _ONE_PROCESS_DEBUG_
	static unsigned conf_num = 0;
#endif

	/* A parent process or previous config load may have left these set */
	block_depth = 0;
	kw_level = 0;
	sublevel = 0;
	skip_sublevel = 0;
	multiline_seq_depth = 0;
	random_seed = 0;
	random_seed_configured = false;

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

	if (copy_config) {
		if (!conf_copy) {
#if defined HAVE_MEMFD_CREATE || defined USE_MEMFD_CREATE_SYSCALL
			fd = memfd_create("/keepalived/consolidated_configuration", MFD_CLOEXEC);

			/* SELinux can allow memfd_create() to succeed, but reads and writes fail.
			 * Perversely the open does not log an SELinux error if keepalived has no
			 * permissions for "tmpfs", but if it has read and write permissions but
			 * not open permission, then the open fails. */
			if (fd != -1) {
				char read_byte;		/* coverity[suspicious_sizeof] is generated if this is an int */

				if (read(fd, &read_byte, 1) == -1) {
					if (errno == EACCES)
						log_message(LOG_INFO, "SELinux permissions for memfd (tmpfs) appear to be missing for keepalived");
					else
						log_message(LOG_INFO, "read from memfd failed with errno %d - %m", errno);
					close(fd);
					fd = open_tmpfile(RUNSTATEDIR, O_RDWR | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
				}
			}
#endif
#ifndef HAVE_MEMFD_CREATE
#ifdef USE_MEMFD_CREATE_SYSCALL
			if (fd == -1 && errno == ENOSYS)
#endif
				fd = open_tmpfile(RUNSTATEDIR, O_RDWR | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
#endif
			if (fd == -1)
				log_message(LOG_INFO, "conf_copy open error %d - %m", errno);
			else {
				conf_copy = fdopen(fd, "w+");
				if (!conf_copy)
					log_message(LOG_INFO, "fdopen of conf_copy fd error %d - %m", errno);
			}
		} else {
			if (ftruncate(fileno(conf_copy), 0))
				log_message(LOG_INFO, "Failed to truncate config copy file (%d) - %m", errno);

			rewind(conf_copy);
		}

		if (conf_copy)
			write_conf_copy = true;
	}

	if (!copy_config && conf_copy) {
		include_file_t *file;

		PMALLOC(file);
		INIT_LIST_HEAD(&file->e_list);

		file->globbuf.gl_offs = 0;
		file->stream = conf_copy;
		file->num_matches = 1;
		file->curdir_fd = -1;
		errno = 0;
		rewind(conf_copy);
		if (errno)
			log_message(LOG_INFO, "rewind config file failed (%d) - %m", errno);
		file->file_name = STRDUP(conf_file);
		file->current_file_name = file->file_name;

		list_head_add(&file->e_list, &include_stack);

		read_conf_copy = true;
		file_opened = true;
	} else if (open_glob_file(conf_file, INCLUDE_R | INCLUDE_M | INCLUDE_W)) {
		/* Opened the first file */
		file_opened = true;

		log_message(LOG_INFO, "Configuration file %s", conf_file);
	} else
		file_config_error(INCLUDE_R, "Failed to open configuration file");

	if (file_opened) {
		register_null_strvec_handler(null_strvec);
		process_stream(current_keywords, 0);
		unregister_null_strvec_handler();

/* Is this right - the seq_list should be empty ???? */
		free_seq_list(&seq_list);

		/* Report if there are missing '}'s. If there are missing '{'s it will already have been reported */
		if (block_depth > 0)
			report_config_error(CONFIG_MISSING_EOB, "There are %d missing '%s's or extra '%s's"
						      , block_depth, EOB, BOB);
	}

	if (conf_copy && write_conf_copy) {
		fflush(conf_copy);
		write_conf_copy = false;

		/* Set file offset to beginning ready for next write */
		rewind(conf_copy);

#ifndef _ONE_PROCESS_DEBUG_
		if (config_save_dir) {
			char buf[128];
			pid_t pid = getpid();

			sprintf(buf, "cp /proc/%d/fd/%d %s/keepalived.conf.%d.%u", pid, fileno(conf_copy), config_save_dir, pid, conf_num++);
			if (system(buf)) {
				/* If it fails, there is nothing we can do about it */
			};
		}
#endif
	}

	/* Close the password database if it was opened */
	endpwent();

	free_keywords(keywords);
	free_parser_data();

	notify_resource_release();
}

int
get_config_fd(void)
{
	if (!conf_copy)
		return -1;

	return fileno(conf_copy);
}

void
set_config_fd(int fd)
{
	conf_copy = fdopen(fd, "w+");
	if (conf_copy) {
		write_conf_copy = true;
		rewind(conf_copy);
	} else
		log_message(LOG_INFO, "Unable to open config copy file (%d) - %m", errno);
}

void include_check_set(const vector_t *strvec)
{
	const char *word;
	unsigned int i;
	int add_remove = 0;	/* -1 = remove, +1 = add, 0 = set */
	unsigned new_flag;
	int offset;

	if (strvec && vector_size(strvec) > 1) {
		for (i = 1; i < vector_size(strvec); i++) {
			word = strvec_slot(strvec, i);

			/* Are we adding or removing bits, or setting? */
			add_remove = 0;
			offset = 1;
			if (word[0] == '-')
				add_remove = -1;
			else if (word[0] == '+')
				add_remove = +1;
			else {
				offset = 0;
				if (i == 1)
					include_check = 0;
				else {
					report_config_error(CONFIG_GENERAL_ERROR, "Duplicate include_check '%s' specified - ignoring", word);
					continue;
				}
			}

			new_flag = 0;
			if (!strcmp(word + offset, "read"))
				new_flag = INCLUDE_R;
			else if (!strcmp(word + offset, "match"))
				new_flag = INCLUDE_M;
			else if (!strcmp(word + offset, "wildcard_match"))
				new_flag = INCLUDE_W;
			else if (!strcmp(word + offset, "brace_match"))
				new_flag = INCLUDE_B;
			else
				report_config_error(CONFIG_GENERAL_ERROR, "Unknown include_check type '%s' - ignoring", word + offset);
#if !HAVE_DECL_GLOB_ALTDIRFUNC
			if (new_flag & (INCLUDE_M | INCLUDE_B)) {
				if (!add_remove) {
					report_config_error(CONFIG_WARNING, "include_check type '%s' - not supported, treating as 'read'", word + offset);
					new_flag = INCLUDE_R;
				} else {
					report_config_error(CONFIG_WARNING, "include_check type '%s' - not supported, ignoring", word + offset);
					new_flag = 0;
				}
			}
#endif

			if (new_flag) {
				if (!add_remove)
					include_check = INCLUDE_R | new_flag;
				else if (add_remove == 1)
					include_check |= new_flag;
				else /* if (add_remove == -1) */
					include_check &= ~new_flag;
			}
		}
	} else
		include_check = INCLUDE_R | INCLUDE_M | INCLUDE_W | INCLUDE_B;
}

bool
had_config_file_error(void)
{
	return config_file_error;
}

void
separate_config_file(void)
{
	char buf[32];	/* /proc/self/fd/2147483647\0 */
	int fd_orig;
	int fd;

	if (!conf_copy) {
		log_message(LOG_INFO, "No conf_copy");
		return;
	}

	/* We need to open the config file on a different file descriptor so that
	 * it can be read independantly from the other keepalived processes */
	fd_orig = fileno(conf_copy);
	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd_orig);
	if ((fd = open(buf, O_RDONLY)) == -1) {
		log_message(LOG_INFO, "Failed to open %s for conf_copy", buf);
		return;
	}
#ifdef HAVE_DUP3
	dup3(fd, fd_orig, O_CLOEXEC);
#else
	dup2(fd, fd_orig);
	fcntl(fd_orig, F_SETFD, fcntl(fd_orig, F_GETFD) | FD_CLOEXEC);
#endif
	close(fd);
}
