/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        FILE CHECK. Monitor contents if a file
 *
 * Authors:     Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdio.h>

#include "check_file.h"
#include "list.h"
#include "check_data.h"
#include "track_file.h"
#include "parser.h"
#include "check_data.h"


static void
free_file_check(checker_t *checker)
{
	FREE(checker);
}

static void
dump_file_check(FILE *fp, const checker_t *checker)
{
	tracked_file_t *tfp = checker->data;

	conf_write(fp, "   Keepalive method = FILE_CHECK");
	conf_write(fp, "     Tracked file = %s", tfp->fname);
}

static bool
file_check_compare(const checker_t *a, const checker_t *b)
{
	return a->data == b->data;
}

static void
track_file_handler(const vector_t *strvec)
{
	virtual_server_t *vs;
	real_server_t *rs;
	tracked_file_monitor_t *tfile;
	tracked_file_t *vsf;

	vs = LIST_TAIL_DATA(check_data->vs);
	rs = LIST_TAIL_DATA(vs->rs);
	tfile = LIST_TAIL_DATA(rs->track_files);

	vsf = find_tracked_file_by_name(strvec_slot(strvec, 1), check_data->track_files);
	if (!vsf) {
		report_config_error(CONFIG_GENERAL_ERROR, "track_file %s not found", strvec_slot(strvec, 1));
		return;
	}

	tfile->file = vsf;
}

static void
file_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	tracked_file_monitor_t *tfile;
	virtual_server_t *vs;
	real_server_t *rs;

	vs = LIST_TAIL_DATA(check_data->vs);
	rs = LIST_TAIL_DATA(vs->rs);

	if (!LIST_EXISTS(rs->track_files))
		rs->track_files = alloc_track_file_list();

	PMALLOC(tfile);
	list_add(rs->track_files, tfile);
}

static void
track_file_weight_handler(const vector_t *strvec)
{
	virtual_server_t *vs;
	real_server_t *rs;
	tracked_file_monitor_t *tfile;
	int weight;
	bool reverse = false;

	vs = LIST_TAIL_DATA(check_data->vs);
	rs = LIST_TAIL_DATA(vs->rs);
	tfile = LIST_TAIL_DATA(rs->track_files);

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "track file weight missing");
		return;
	}

	if (!read_int_strvec(strvec, 1, &weight, -IPVS_WEIGHT_MAX, IPVS_WEIGHT_MAX, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "weight for track file must be in "
				 "[-IPVS_WEIGHT_MAX..IPVS_WEIGHT_MAX] inclusive. Ignoring...");
		return;
	}

	if (vector_size(strvec) >= 3) {
		if (!strcmp(strvec_slot(strvec, 2), "reverse"))
			reverse = true;
		else if (!strcmp(strvec_slot(strvec, 2), "noreverse"))
			reverse = false;
		else {
			report_config_error(CONFIG_GENERAL_ERROR, "unknown track file weight option %s - ignoring",
					 strvec_slot(strvec, 2));
			return;
		}
	}

	tfile->weight = weight;
	tfile->weight_reverse = reverse;
}

static void
file_end_handler(void)
{
	virtual_server_t *vs;
	real_server_t *rs;
	tracked_file_monitor_t *tfile;

	vs = LIST_TAIL_DATA(check_data->vs);
	rs = LIST_TAIL_DATA(vs->rs);
	tfile = LIST_TAIL_DATA(rs->track_files);

	if (!tfile->file) {
		report_config_error(CONFIG_GENERAL_ERROR, "FILE_CHECK has no track_file specified - ignoring");
		list_remove(rs->track_files, LIST_TAIL(rs->track_files));
	}

	if (!tfile->weight) {
		tfile->weight = tfile->file->weight;
		tfile->weight_reverse = tfile->file->weight_reverse;
	}
}

void
install_file_check_keyword(void)
{
	install_keyword("FILE_CHECK", &file_check_handler);
	install_sublevel();
	install_keyword("track_file", &track_file_handler);
	install_keyword("weight", &track_file_weight_handler);
	install_sublevel_end_handler(&file_end_handler);
	install_sublevel_end();
}

void
add_rs_to_track_files(void)
{
	virtual_server_t *vs;
	real_server_t *rs;
	element e, e1, e2;
	tracked_file_monitor_t *tfl;
	checker_t *new_checker;

	LIST_FOREACH(check_data->vs, vs, e) {
		LIST_FOREACH(vs->rs, rs, e1) {
			LIST_FOREACH(rs->track_files, tfl, e2) {
				/* queue new checker */
				new_checker = queue_checker(free_file_check, dump_file_check, NULL, file_check_compare, tfl->file, NULL, false);
				new_checker->vs = vs;
				new_checker->rs = rs;

				add_obj_to_track_file(new_checker, tfl, FMT_RS(rs, vs), dump_tracking_rs);
			}
		}
	}
}

#ifdef THREAD_DUMP
void
register_check_file_addresses(void)
{
	register_track_file_inotify_addresses();
}
#endif
