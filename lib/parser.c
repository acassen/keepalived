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

#include <glob.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include "parser.h"
#include "memory.h"
#include "logger.h"

#define DUMP_KEYWORDS	0

/* global vars */
vector_t *keywords;
vector_t *current_keywords;
FILE *current_stream;
char *current_conf_file;
int reload = 0;

/* local vars */
static int sublevel = 0;
static int skip_sublevel = 0;

/* Forward references */
static void process_stream(vector_t *, int);

static void
keyword_alloc(vector_t *keywords_vec, char *string, void (*handler) (vector_t *), bool active)
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
keyword_alloc_sub(vector_t *keywords_vec, char *string, void (*handler) (vector_t *), bool active)
{
	int i = 0;
	keyword_t *keyword;

	/* fetch last keyword */
	keyword = vector_slot(keywords_vec, vector_size(keywords_vec) - 1);

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword =
		    vector_slot(keyword->sub, vector_size(keyword->sub) - 1);

	/* First sub level allocation */
	if (!keyword->sub)
		keyword->sub = vector_alloc();

	/* add new sub keyword */
	keyword_alloc(keyword->sub, string, handler, active);
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
install_keyword_root(char *string, void (*handler) (vector_t *), bool active)
{
	keyword_alloc(keywords, string, handler, active);
}

void
install_keyword(char *string, void (*handler) (vector_t *), bool active)
{
	keyword_alloc_sub(keywords, string, handler, active);
}

void
install_sublevel_end_handler(void (*handler) (void), bool active)
{
	int i = 0;
	keyword_t *keyword;

	/* fetch last keyword */
	keyword = vector_slot(keywords, vector_size(keywords) - 1);

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword =
		    vector_slot(keyword->sub, vector_size(keyword->sub) - 1);
	keyword->sub_close_handler = (active) ? handler: NULL;
}

#if DUMP_KEYWORDS
static void
dump_keywords(vector_t *keydump, int level, FILE *fp)
{
	int i;
	keyword_t *keyword_vec;
	char file_name[21];

	if (!level) {
		sprintf(file_name, "/tmp/keywords.%d", getpid());
		fp = fopen(file_name, "w");
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

void
free_keywords(vector_t *keywords_vec)
{
	keyword_t *keyword_vec;
	int i;

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
	int str_len;
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
			str_len = cp - start;
			cp++;
		} else {
			while (!isspace((int) *cp) && *cp != '\0' && *cp != '"'
						   && *cp != '!' && *cp != '#')
				cp++;
			str_len = cp - start;
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

void read_conf_file(char *conf_file)
{
	FILE *stream;
	char *path;
	int ret;
sleep(2);
	glob_t globbuf;

	globbuf.gl_offs = 0;
	glob(conf_file, 0, NULL, &globbuf);

	int i;
	for(i = 0; i < globbuf.gl_pathc; i++){
		log_message(LOG_INFO, "Opening file '%s'.", globbuf.gl_pathv[i]);
		stream = fopen(globbuf.gl_pathv[i], "r");
		if (!stream) {
			log_message(LOG_INFO, "Configuration file '%s' open problem (%s)..."
				       , globbuf.gl_pathv[i], strerror(errno));
			return;
		}
		current_stream = stream;
		current_conf_file = globbuf.gl_pathv[i];
		
		char prev_path[MAXBUF];
		path = getcwd(prev_path, MAXBUF);
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

int
check_include(char *buf)
{
	char *str;
	vector_t *strvec;
	char *path;
	int ret;

	strvec = alloc_strvec(buf);

	if (!strvec){
		return 0;
	}
	str = vector_slot(strvec, 0);
	
	if (!strcmp(str, EOB)) {
		free_strvec(strvec);
		return 0;
	}

	if(!strcmp("include", str) && vector_size(strvec) == 2){
		char *conf_file = vector_slot(strvec, 1);

		FILE *prev_stream = current_stream;
		char *prev_conf_file = current_conf_file;
		char prev_path[MAXBUF];
		path = getcwd(prev_path, MAXBUF);
		if (!path) {
			log_message(LOG_INFO, "getcwd(%s) error (%s)"
					    , prev_path, strerror(errno));
		}

		read_conf_file(conf_file);
		current_stream = prev_stream;
		current_conf_file = prev_conf_file;
		ret = chdir(prev_path);
		if (ret < 0) {
			log_message(LOG_INFO, "chdir(%s) error (%s)"
					    , prev_path, strerror(errno));
		}
		free_strvec(strvec);
		return 1;
	}
	free_strvec(strvec);
	return 0;
}

int
read_line(char *buf, int size)
{
	int ch;

	do {
		int count = 0;
		memset(buf, 0, size);
		while ((ch = fgetc(current_stream)) != EOF && (int) ch != '\n'
			   && (int) ch != '\r') {
			if (count < size)
				buf[count] = (int) ch;
			else
				break;
			count++;
		}
	} while (check_include(buf) == 1);
	return (ch == EOF) ? 0 : 1;
}

vector_t *
read_value_block(vector_t *strvec)
{
	char *buf;
	int word;
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
alloc_value_block(vector_t *strvec, void (*alloc_func) (vector_t *))
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
	char *str = vector_slot(strvec, 1);
	int size = strlen(str);
	char *alloc;

	alloc = (char *) MALLOC(size + 1);
	memcpy(alloc, str, size);

	return alloc;
}

void skip_block(void)
{
	/* Don't process the rest of the configuration block */
	skip_sublevel = 1;
}

/* recursive configuration stream handler */
static int kw_level = 0;
static void
process_stream(vector_t *keywords_vec, int need_bob)
{
	int i;
	keyword_t *keyword_vec;
	char *str;
	char *buf;
	vector_t *strvec;
	vector_t *prev_keywords = current_keywords;
	current_keywords = keywords_vec;
	int bob_needed = 0;

	buf = zalloc(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		strvec = alloc_strvec(buf);
		memset(buf,0, MAXBUF);

		if (!strvec)
			continue;

		str = vector_slot(strvec, 0);

		if (need_bob) {
			need_bob = 0;
			if (!strcmp(str, BOB) && kw_level > 0)
				str[0] = 0;
			else
				log_message(LOG_INFO, "Missing '{' at beginning of configuration block");
		}
		else if (!skip_sublevel && !strcmp(str, BOB)) {
			log_message(LOG_INFO, "Unexpected '{' - ignoring");
			free_strvec(strvec);
			continue;
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

			if (!skip_sublevel)
				break;
			continue;
		}

		if (!strcmp(str, EOB) && kw_level > 0) {
			free_strvec(strvec);
			break;
		}

		for (i = 0; i < vector_size(keywords_vec); i++) {
			keyword_vec = vector_slot(keywords_vec, i);

			if (!strcmp(keyword_vec->string, str)) {
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

				if (keyword_vec->active && keyword_vec->handler)
					(*keyword_vec->handler) (strvec);

				if (keyword_vec->sub) {
					if (!keyword_vec->active)
						skip_block();

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
	free(buf);
	return;
}

/* Data initialization */
void
init_data(char *conf_file, vector_t * (*init_keywords) (void))
{
	/* Init Keywords structure */
	keywords = vector_alloc();
	(*init_keywords) ();

#if DUMP_KEYWORDS
	/* Dump configuration */
	vector_dump(keywords);
	dump_keywords(keywords, 0, NULL);
#endif

	/* Stream handling */
	current_keywords = keywords;
	read_conf_file((conf_file) ? conf_file : CONF);
	free_keywords(keywords);
}
