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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <glob.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include "parser.h"
#include "memory.h"
#include "logger.h"

/* global vars */
vector keywords;
vector current_keywords;
FILE *current_stream;
char *current_conf_file;
int reload = 0;

/* local vars */
static int sublevel = 0;

void
keyword_alloc(vector keywords_vec, char *string, void (*handler) (vector))
{
	struct keyword *keyword;

	vector_alloc_slot(keywords_vec);

	keyword = (struct keyword *) MALLOC(sizeof (struct keyword));
	keyword->string = string;
	keyword->handler = handler;

	vector_set_slot(keywords_vec, keyword);
}

void
keyword_alloc_sub(vector keywords_vec, char *string, void (*handler) (vector))
{
	int i = 0;
	struct keyword *keyword;

	/* fetch last keyword */
	keyword = VECTOR_SLOT(keywords_vec, VECTOR_SIZE(keywords_vec) - 1);

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword =
		    VECTOR_SLOT(keyword->sub, VECTOR_SIZE(keyword->sub) - 1);

	/* First sub level allocation */
	if (!keyword->sub)
		keyword->sub = vector_alloc();

	/* add new sub keyword */
	keyword_alloc(keyword->sub, string, handler);
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
install_keyword_root(char *string, void (*handler) (vector))
{
	keyword_alloc(keywords, string, handler);
}

void
install_keyword(char *string, void (*handler) (vector))
{
	keyword_alloc_sub(keywords, string, handler);
}

void
dump_keywords(vector keydump, int level)
{
	int i, j;
	struct keyword *keyword_vec;

	for (i = 0; i < VECTOR_SIZE(keydump); i++) {
		keyword_vec = VECTOR_SLOT(keydump, i);
		for (j = 0; j < level; j++)
			printf("  ");
		printf("Keyword : %s\n", keyword_vec->string);
		if (keyword_vec->sub)
			dump_keywords(keyword_vec->sub, level + 1);
	}
}

void
free_keywords(vector keywords_vec)
{
	struct keyword *keyword_vec;
	int i;

	for (i = 0; i < VECTOR_SIZE(keywords_vec); i++) {
		keyword_vec = VECTOR_SLOT(keywords_vec, i);
		if (keyword_vec->sub)
			free_keywords(keyword_vec->sub);
		FREE(keyword_vec);
	}
	vector_free(keywords_vec);
}

vector
alloc_strvec(char *string)
{
	char *cp, *start, *token;
	int str_len;
	vector strvec;

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
		if (*cp == '"') {
			cp++;
			token = MALLOC(2);
			*(token) = '"';
			*(token + 1) = '\0';
		} else {
			while (!isspace((int) *cp) && *cp != '\0' && *cp != '"')
				cp++;
			str_len = cp - start;
			token = MALLOC(str_len + 1);
			memcpy(token, start, str_len);
			*(token + str_len) = '\0';
		}

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

	glob_t globbuf;

	globbuf.gl_offs = 0;
	glob(conf_file, 0, NULL, &globbuf);

	int i;
	for(i = 0; i < globbuf.gl_pathc; i++){
		log_message(LOG_INFO, "Opening file '%s'.\n",globbuf.gl_pathv[i]);
		stream = fopen(globbuf.gl_pathv[i], "r");
		if (!stream) {
			log_message(LOG_INFO, "Configuration file '%s' open problem (%s)...\n"
				       , globbuf.gl_pathv[i], strerror(errno));
			return;
		}
		current_stream = stream;
		current_conf_file = globbuf.gl_pathv[i];
		
		char prev_path[MAXBUF];
		path = getcwd(prev_path, MAXBUF);

		char *confpath = strdup(globbuf.gl_pathv[i]);
		dirname(confpath);
		ret = chdir(confpath);
		process_stream(current_keywords);
		fclose(stream);

		ret = chdir(prev_path);
	}

	globfree(&globbuf);
}

int
check_include(char *buf)
{
	char *str;
	vector strvec;
	char *path;
	int ret;

	strvec = alloc_strvec(buf);

	if (!strvec){
		return 0;
	}
	str = VECTOR_SLOT(strvec, 0);
	
	if (!strcmp(str, EOB)) {
		free_strvec(strvec);
		return 0;
	}

	if(!strcmp("include", str) && VECTOR_SIZE(strvec) == 2){
		char *conf_file = VECTOR_SLOT(strvec, 1);

		FILE *prev_stream = current_stream;
		char *prev_conf_file = current_conf_file;
		char prev_path[MAXBUF];
		path = getcwd(prev_path, MAXBUF);
		read_conf_file(conf_file);
		current_stream = prev_stream;
		current_conf_file = prev_conf_file;
		ret = chdir(prev_path);
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
		memset(buf, 0, MAXBUF);
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

vector
read_value_block(void)
{
	char *buf;
	int i;
	char *str = NULL;
	char *dup;
	vector vec = NULL;
	vector elements = vector_alloc();

	buf = (char *) MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		vec = alloc_strvec(buf);
		if (vec) {
			str = VECTOR_SLOT(vec, 0);
			if (!strcmp(str, EOB)) {
				free_strvec(vec);
				break;
			}

			if (VECTOR_SIZE(vec))
				for (i = 0; i < VECTOR_SIZE(vec); i++) {
					str = VECTOR_SLOT(vec, i);
					dup = (char *) MALLOC(strlen(str) + 1);
					memcpy(dup, str, strlen(str));
					vector_alloc_slot(elements);
					vector_set_slot(elements, dup);
				}
			free_strvec(vec);
		}
		memset(buf, 0, MAXBUF);
	}

	FREE(buf);
	return elements;
}

void
alloc_value_block(vector strvec, void (*alloc_func) (vector))
{
	char *buf;
	char *str = NULL;
	vector vec = NULL;

	buf = (char *) MALLOC(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		vec = alloc_strvec(buf);
		if (vec) {
			str = VECTOR_SLOT(vec, 0);
			if (!strcmp(str, EOB)) {
				free_strvec(vec);
				break;
			}

			if (VECTOR_SIZE(vec))
				(*alloc_func) (vec);

			free_strvec(vec);
		}
		memset(buf, 0, MAXBUF);
	}
	FREE(buf);
}


void *
set_value(vector strvec)
{
	char *str = VECTOR_SLOT(strvec, 1);
	int size = strlen(str);
	int i = 0;
	int len = 0;
	char *alloc = NULL;
	char *tmp;

	if (*str == '"') {
		for (i = 2; i < VECTOR_SIZE(strvec); i++) {
			str = VECTOR_SLOT(strvec, i);
			len += strlen(str);
			if (!alloc)
				alloc =
				    (char *) MALLOC(sizeof (char *) *
						    (len + 1));
			else {
				alloc =
				    REALLOC(alloc, sizeof (char *) * (len + 1));
				tmp = VECTOR_SLOT(strvec, i-1);
				if (*str != '"' && *tmp != '"')
					strncat(alloc, " ", 1);
			}

			if (i != VECTOR_SIZE(strvec)-1)
				strncat(alloc, str, strlen(str));
		}
	} else {
		alloc = MALLOC(sizeof (char *) * (size + 1));
		memcpy(alloc, str, size);
	}
	return alloc;
}

/* recursive configuration stream handler */
static int kw_level = 0;
void
process_stream(vector keywords_vec)
{
	int i;
	struct keyword *keyword_vec;
	char *str;
	char *buf;
	vector strvec;
	vector prev_keywords = current_keywords;
	current_keywords = keywords_vec;

	buf = zalloc(MAXBUF);
	while (read_line(buf, MAXBUF)) {
		strvec = alloc_strvec(buf);
		memset(buf,0, MAXBUF);

		if (!strvec)
			continue;

		str = VECTOR_SLOT(strvec, 0);

		if (!strcmp(str, EOB) && kw_level > 0) {
			free_strvec(strvec);
			break;
		}

		for (i = 0; i < VECTOR_SIZE(keywords_vec); i++) {
			keyword_vec = VECTOR_SLOT(keywords_vec, i);

			if (!strcmp(keyword_vec->string, str)) {
				if (keyword_vec->handler)
					(*keyword_vec->handler) (strvec);

				if (keyword_vec->sub) {
					kw_level++;
					process_stream(keyword_vec->sub);
					kw_level--;
				}
				break;
			}
		}

		free_strvec(strvec);
	}

	current_keywords = prev_keywords;
	free(buf);
	return;
}

/* Data initialization */
void
init_data(char *conf_file, vector (*init_keywords) (void))
{
	/* Init Keywords structure */
	keywords = vector_alloc();
	(*init_keywords) ();

#if 0
	/* Dump configuration */
	vector_dump(keywords);
	dump_keywords(keywords, 0);
#endif

	/* Stream handling */
	current_keywords = keywords;
	read_conf_file((conf_file) ? conf_file : CONF);
	free_keywords(keywords);
}
