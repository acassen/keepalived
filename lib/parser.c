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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include "config.h"

#include <glob.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "parser.h"
#include "memory.h"
#include "logger.h"
#include "rttables.h"
#include "scheduler.h"

#define DUMP_KEYWORDS	0

/* global vars */
vector_t *keywords;
bool reload = 0;
char *config_id;

/* local vars */
static vector_t *current_keywords;
static FILE *current_stream;
static int sublevel = 0;
static int skip_sublevel = 0;

static char *
null_strvec(const vector_t *strvec, size_t index)
{ 
	if (index - 1 < vector_size(strvec) && index > 0 && vector_slot(strvec, index - 1))
		log_message(LOG_INFO, "*** Configuration line starting `%s` is missing a parameter after keyword `%s` at word position %zu", vector_slot(strvec, 0) ? (char *)vector_slot(strvec, 0) : "***MISSING ***", (char *)vector_slot(strvec, index - 1), index + 1);
	else
		log_message(LOG_INFO, "*** Configuration line starting `%s` is missing a parameter at word position %zu", vector_slot(strvec, 0) ? (char *)vector_slot(strvec, 0) : "***MISSING ***", index + 1);

	exit(KEEPALIVED_EXIT_CONFIG);

	return NULL;
} 

static void
keyword_alloc(vector_t *keywords_vec, const char *string, void (*handler) (vector_t *), bool active)
{
	keyword_t *keyword;

	vector_alloc_slot(keywords_vec);

	keyword = (keyword_t *) MALLOC(sizeof(keyword_t));
	keyword->string = string;
	keyword->handler = (active) ? handler : NULL;
	keyword->active = active;

	vector_set_slot(keywords_vec, keyword);
}

static void
keyword_alloc_sub(vector_t *keywords_vec, const char *string, void (*handler) (vector_t *))
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
install_keyword_root(const char *string, void (*handler) (vector_t *), bool active)
{
	keyword_alloc(keywords, string, handler, active);
}

void
install_keyword(const char *string, void (*handler) (vector_t *))
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

#if DUMP_KEYWORDS
static void
dump_keywords(vector_t *keydump, int level, FILE *fp)
{
	unsigned int i;
	keyword_t *keyword_vec;
	char file_name[21];

	if (!level) {
		sprintf(file_name, "/tmp/keywords.%d", getpid());
		snprintf(file_name, sizeof(file_name), "/tmp/keywords.%d", getpid());
		fp = fopen(file_name, "w");
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

vector_t *
alloc_strvec(char *string)
{
	char *cp, *start, *token;
	size_t str_len;
	vector_t *strvec;

	if (!string)
		return NULL;

	cp = string;

	/* Skip white spaces */
	while (isspace((int) *cp) && *cp != '\0')
		cp++;

	/* Return if there is only white spaces */
	if (*cp == '\0')
		return NULL;

	/* Return if string begin with a comment */
	if (*cp == '!' || *cp == '#')
		return NULL;

	/* Create a vector and alloc each command piece */
	strvec = vector_alloc();

	while (1) {
		start = cp;

		/* Save a quoted string without the "s as a single string */
		if (*cp == '"') {
			start++;
			if (!(cp = strchr(start, '"'))) {
				log_message(LOG_INFO, "Unmatched quote: '%s'", string);
				return strvec;
			}
			str_len = (size_t)(cp - start);
			cp++;
		} else {
			while (!isspace((int) *cp) && *cp != '\0' && *cp != '"'
						   && *cp != '!' && *cp != '#')
				cp++;
			str_len = (size_t)(cp - start);
		}
		token = MALLOC(str_len + 1);
		memcpy(token, start, str_len);
		token[str_len] = '\0';

		/* Alloc & set the slot */
		vector_alloc_slot(strvec);
		vector_set_slot(strvec, token);

		while (isspace((int) *cp) && *cp != '\0')
			cp++;
		if (*cp == '\0' || *cp == '!' || *cp == '#')
			return strvec;
	}
}

/* recursive configuration stream handler */
static int kw_level = 0;
static void
process_stream(vector_t *keywords_vec, int need_bob)
{
	unsigned int i;
	keyword_t *keyword_vec;
	char *str;
	char *buf;
	vector_t *strvec;
	vector_t *prev_keywords = current_keywords;
	current_keywords = keywords_vec;
	int bob_needed = 0;
	size_t config_id_len = 0;
	char *buf_start;

	if (config_id)
		config_id_len = strlen(config_id);

	buf = MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		if (buf[0] == '@') {
			/* If the line starts '@', check the following word matches the system id */
			if (!config_id)
				continue;
			buf_start = strpbrk(buf, " \t");
			if ((size_t)(buf_start - (buf + 1)) != config_id_len ||
			    strncmp(buf + 1, config_id, config_id_len))
				continue;
		}
		else
			buf_start = buf;

		strvec = alloc_strvec(buf_start);
		memset(buf, 0, MAXBUF);

		if (!strvec)
			continue;

		str = vector_slot(strvec, 0);

		if (skip_sublevel == -1) {
			/* There wasn't a '{' on the keyword line */
			if (!strcmp(str, BOB)) {
				/* We've got the opening '{' now */
				skip_sublevel = 1;
				free_strvec(strvec);
				continue;
			}
			else {
				/* The skipped keyword doesn't have a {} block, so we no longer want to skip */
				skip_sublevel = 0;
			}
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
				log_message(LOG_INFO, "Missing '{' at beginning of configuration block");
		}
		else if (!strcmp(str, BOB)) {
			log_message(LOG_INFO, "Unexpected '{' - ignoring");
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

				if (keyword_vec->handler)
					(*keyword_vec->handler) (strvec);

				if (keyword_vec->sub) {
					kw_level++;
					process_stream(keyword_vec->sub, bob_needed);
					kw_level--;
					if (keyword_vec->active && keyword_vec->sub_close_handler)
						(*keyword_vec->sub_close_handler) ();
				}
				break;
			}
		}

		if (i >= vector_size(keywords_vec))
			log_message(LOG_INFO, "Unknown keyword '%s'", str );

		free_strvec(strvec);
	}

	current_keywords = prev_keywords;
	FREE(buf);
	return;
}

static void
read_conf_file(const char *conf_file)
{
	FILE *stream;
	char *path;
	int ret;
	glob_t globbuf;
	size_t i;
	int	res;
	struct stat stb;

	globbuf.gl_offs = 0;
	res = glob(conf_file, 0, NULL, &globbuf);

	if (res) {
		log_message(LOG_INFO, "Unable to find config file(s) '%s'.", conf_file);
		exit(KEEPALIVED_EXIT_CONFIG);
	}

	for(i = 0; i < globbuf.gl_pathc; i++){
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

		current_stream = stream;

		char prev_path[PATH_MAX];
		path = getcwd(prev_path, PATH_MAX);
		if (!path) {
			log_message(LOG_INFO, "getcwd(%s) error (%s)"
					    , prev_path, strerror(errno));
		}

		char *confpath = strdup(globbuf.gl_pathv[i]);
		dirname(confpath);
		ret = chdir(confpath);
		if (ret < 0) {
			log_message(LOG_INFO, "chdir(%s) error (%s)"
					    , confpath, strerror(errno));
		}
		free(confpath);
		process_stream(current_keywords, 0);
		fclose(stream);

		ret = chdir(prev_path);
		if (ret < 0) {
			log_message(LOG_INFO, "chdir(%s) error (%s)"
					    , prev_path, strerror(errno));
		}
	}

	globfree(&globbuf);
}

bool check_conf_file(const char *conf_file)
{
	glob_t globbuf;
	size_t i;
	bool ret = true;
	int res;
	struct stat stb;

	globbuf.gl_offs = 0;
	res = glob(conf_file, 0, NULL, &globbuf);
	if (res) {
		log_message(LOG_INFO, "Unable to find configuration file %s (glob returned %d)", conf_file, res);
		return false;
	}

	if (globbuf.gl_pathc == 0) {
		log_message(LOG_INFO, "Unable to find configuration file %s", conf_file);
		ret = false;
	} else {
		for (i = 0; i < globbuf.gl_pathc; i++) {
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
		}
	}

	globfree(&globbuf);

	return ret;
}

static bool
check_include(char *buf)
{
	vector_t *strvec;
	bool ret = false;
	FILE *prev_stream;

	strvec = alloc_strvec(buf);

	if (!strvec)
		return false;

	if(!strcmp("include", vector_slot(strvec, 0)) && vector_size(strvec) == 2) {
		prev_stream = current_stream;

		read_conf_file(vector_slot(strvec, 1));

		current_stream = prev_stream;
		ret = true;
	}

	free_strvec(strvec);
	return ret;
}

bool
read_line(char *buf, size_t size)
{
	size_t len ;
	bool eof = false;

	do {
		if (fgets(buf, (int)size, current_stream)) {
			len = strlen(buf);
			if (len && (buf[len-1] == '\n' || buf[len-1] == '\r'))
				buf[len-1] = '\0';
			if (len > 1 && (buf[len-2] == '\n' || buf[len-2] == '\r'))
				buf[len-2] = '\0';
		}
		else
		{
			eof = true;
			buf[0] = '\0';
			break;
		}
	} while (check_include(buf));

	return !eof;
}

vector_t *
read_value_block(vector_t *strvec)
{
	char *buf;
	unsigned int word;
	char *str = NULL;
	char *dup;
	vector_t *vec = NULL;
	vector_t *elements = vector_alloc();
	int first = 1;
	int need_bob = 1;
	int got_eob = 0;

	buf = (char *) MALLOC(MAXBUF);
	while (first || read_line(buf, MAXBUF)) {
		if (first && vector_size(strvec) > 1) {
			vec = strvec;
			word = 1;
		}
		else {
			vec = alloc_strvec(buf);
			word = 0;
		}
		if (vec) {
			str = vector_slot(vec, word);
			if (need_bob) {
				if (!strcmp(str, BOB))
					word++;
				else
					log_message(LOG_INFO, "'{' missing at beginning of block %s", FMT_STR_VSLOT(strvec,0));
				need_bob = 0;
			}

			for (; word < vector_size(vec); word++) {
				str = vector_slot(vec, word);
				if (!strcmp(str, EOB)) {
					if (word != vector_size(vec) - 1)
						log_message(LOG_INFO, "Extra characters after '}' - \"%s\"", buf);
					got_eob = 1;
					break;
				}
				dup = (char *) MALLOC(strlen(str) + 1);
				memcpy(dup, str, strlen(str));
				vector_alloc_slot(elements);
				vector_set_slot(elements, dup);
			}
			if (vec != strvec)
				free_strvec(vec);
			if (got_eob)
				break;
		}
		memset(buf, 0, MAXBUF);
		first = 0;
	}

	FREE(buf);
	return elements;
}

void
alloc_value_block(void (*alloc_func) (vector_t *))
{
	char *buf;
	char *str = NULL;
	vector_t *vec = NULL;

	buf = (char *) MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		vec = alloc_strvec(buf);
		if (vec) {
			str = vector_slot(vec, 0);
			if (!strcmp(str, EOB)) {
				free_strvec(vec);
				break;
			}

			if (vector_size(vec))
				(*alloc_func) (vec);

			free_strvec(vec);
		}
		memset(buf, 0, MAXBUF);
	}
	FREE(buf);
}

void *
set_value(vector_t *strvec)
{
	char *str;
	size_t size;
	char *alloc;

	if (vector_size(strvec) < 2)
		return NULL;

	str = vector_slot(strvec, 1);
	size = strlen(str);

	alloc = (char *) MALLOC(size + 1);
	if (!alloc)
		return NULL;

	memcpy(alloc, str, size);

	return alloc;
}

/* Checks for on/true/yes or off/false/no */
int
check_true_false(char *str)
{
	if (!strcmp(str, "true") || !strcmp(str, "on") || !strcmp(str, "yes"))
		return true;
	if (!strcmp(str, "false") || !strcmp(str, "off") || !strcmp(str, "no"))
		return false;

	return -1;	/* error */
}

void skip_block(void)
{
	/* Don't process the rest of the configuration block */
	skip_sublevel = 1;
}

/* Data initialization */
void
init_data(const char *conf_file, vector_t * (*init_keywords) (void))
{
	/* Init Keywords structure */
	keywords = vector_alloc();

	(*init_keywords) ();

#if DUMP_KEYWORDS
	/* Dump configuration */
	dump_keywords(keywords, 0, NULL);
#endif

	/* Stream handling */
	current_keywords = keywords;

	register_null_strvec_handler(null_strvec);
	read_conf_file(conf_file);
	unregister_null_strvec_handler();

	free_keywords(keywords);
	clear_rt_names();
}
