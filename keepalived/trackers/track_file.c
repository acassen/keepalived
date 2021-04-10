/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Track file framework.
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
 * Copyright (C) 2001-2020 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#include "track_file.h"
#include "tracker.h"
#include "list_head.h"
#include "vector.h"
#include "parser.h"
#include "bitops.h"
#include "main.h"	/* For reload */
#include "utils.h"	/* For debug */
#include "logger.h"
#ifdef _WITH_LVS_
#include "ipwrapper.h"
#include "check_data.h"
#endif
#ifdef _WITH_VRRP_
#include "vrrp_scheduler.h"

/* Possibly remove */
#include "vrrp_data.h"
#endif

/* Used for initialising track files */
static enum {
	TRACK_FILE_NO_INIT,
	TRACK_FILE_CREATE,
	TRACK_FILE_INIT,
} track_file_init;
static int track_file_init_value;
static tracked_file_t *cur_track_file;


static int inotify_fd = -1;
static thread_ref_t inotify_thread;


/* Track file dump */
static void
dump_track_file_monitor(FILE *fp, const tracked_file_monitor_t *tfile)
{
	conf_write(fp, "     %s, weight %d%s", tfile->file->fname, tfile->weight, tfile->weight_reverse ? " reverse" : "");
}
void
dump_track_file_monitor_list(FILE *fp, const list_head_t *l)
{
	tracked_file_monitor_t *tfile;

	list_for_each_entry(tfile, l, e_list)
		dump_track_file_monitor(fp, tfile);

}

/* Configuration processing */
void
free_track_file_monitor(tracked_file_monitor_t *tfile)
{
	list_del_init(&tfile->e_list);
	FREE(tfile);
}
void
free_track_file_monitor_list(list_head_t *l)
{
	tracked_file_monitor_t *tfile, *tfile_tmp;

	list_for_each_entry_safe(tfile, tfile_tmp, l, e_list)
		free_track_file_monitor(tfile);
}

tracked_file_t * __attribute__ ((pure))
find_tracked_file_by_name(const char *name, list_head_t *l)
{
	tracked_file_t *file;

	list_for_each_entry(file, l, e_list) {
		if (!strcmp(file->fname, name))
			return file;
	}
	return NULL;
}

// Some of the following code is VRRP specific, and so should be in vrrp_track_file.c
void
vrrp_alloc_track_file(const char *name, list_head_t *tracked_files, list_head_t *track_file, const vector_t *strvec)
{
	tracked_file_t *vsf;
	tracked_file_monitor_t *tfile;
	const char *tracked = strvec_slot(strvec, 0);
	tracked_file_monitor_t *etfile;
	int weight;
	bool reverse;

	vsf = find_tracked_file_by_name(tracked, tracked_files);

	/* Ignoring if no file found */
	if (!vsf) {
		report_config_error(CONFIG_GENERAL_ERROR, "(%s) track file %s not found, ignoring..."
							, name, tracked);
		return;
	}

	/* Check this object isn't already tracking the file */
	list_for_each_entry(etfile, track_file, e_list) {
		if (etfile->file == vsf) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) duplicate track_file %s - ignoring"
								, name, tracked);
			return;
		}
	}

	weight = vsf->weight;
	reverse = vsf->weight_reverse;
	if (vector_size(strvec) >= 2) {
		if (strcmp(strvec_slot(strvec, 1), "weight")) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track file option %s - ignoring"
								, name, strvec_slot(strvec, 1));
			return;
		}

		if (vector_size(strvec) == 2) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight without value specified"
								  " for track file %s - ignoring"
								, name, tracked);
			return;
		}

		if (!read_int_strvec(strvec, 2, &weight, -254, 254, true)) {
			report_config_error(CONFIG_GENERAL_ERROR, "(%s) weight for track file %s must be in "
					 "[-254..254] inclusive. Ignoring...", name, tracked);
			weight = vsf->weight;
		}

		if (vector_size(strvec) >= 4) {
			if (!strcmp(strvec_slot(strvec, 3), "reverse"))
				reverse = true;
			else if (!strcmp(strvec_slot(strvec, 3), "noreverse"))
				reverse = false;
			else {
				report_config_error(CONFIG_GENERAL_ERROR, "(%s) unknown track file %s weight option %s - ignoring",
						 name, tracked, strvec_slot(strvec, 3));
				return;
			}
		}
	}

	PMALLOC(tfile);
	INIT_LIST_HEAD(&tfile->e_list);
	tfile->file = vsf;
	tfile->weight = weight;
	tfile->weight_reverse = reverse;
	list_add_tail(&tfile->e_list, track_file);
}

/* Parsers for track_file */
static void
track_file_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	/* Allocate new file structure */
	PMALLOC(cur_track_file);
	INIT_LIST_HEAD(&cur_track_file->e_list);
	INIT_LIST_HEAD(&cur_track_file->tracking_obj);
	cur_track_file->fname = STRDUP(strvec_slot(strvec, 1));
	cur_track_file->weight = 1;

	track_file_init = TRACK_FILE_NO_INIT;
}

#ifdef _WITH_VRRP_
static void
vrrp_track_file_handler(const vector_t *strvec)
{
	if (!strvec)
		return;

	log_message(LOG_INFO, "\"vrrp_track_file\" is deprecated, please use \"track_file\"");

	track_file_handler(strvec);
}
#endif

static void
track_file_file_handler(const vector_t *strvec)
{
	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "track file file name missing");
		return;
	}

	if (!cur_track_file)
		return;

	if (cur_track_file->file_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "File already set for track file %s - ignoring %s"
							, cur_track_file->fname, strvec_slot(strvec, 1));
		return;
	}

	cur_track_file->file_path = set_value(strvec);
}

static void
track_file_weight_handler(const vector_t *strvec)
{
	int weight;

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "No weight specified for track file %s - ignoring"
							, cur_track_file->fname);
		return;
	}

	if (!cur_track_file)
		return;

	if (cur_track_file->weight != 1) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight already set for track file %s - ignoring %s"
							, cur_track_file->fname, strvec_slot(strvec, 1));
		return;
	}

	if (!read_int_strvec(strvec, 1, &weight, -254, 254, true)) {
		report_config_error(CONFIG_GENERAL_ERROR, "Weight (%s) for track_file %s must be between "
							  "[-254..254] inclusive. Ignoring..."
							, strvec_slot(strvec, 1), cur_track_file->fname);
		weight = 1;
	}
	cur_track_file->weight = weight;

	if (vector_size(strvec) >= 3) {
		if (!strcmp(strvec_slot(strvec, 2), "reverse"))
			cur_track_file->weight_reverse = true;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "track_file %s unknown weight option %s"
								, cur_track_file->fname, strvec_slot(strvec, 2));
	}
}

static void
track_file_init_handler(const vector_t *strvec)
{
	unsigned i;
	const char *word;
	int value;

	if (!cur_track_file)
		return;

	track_file_init = TRACK_FILE_CREATE;
	track_file_init_value = 0;

	for (i = 1; i < vector_size(strvec); i++) {
		word = strvec_slot(strvec, i);
		word += strspn(word, WHITE_SPACE);
		if (isdigit(word[0]) || word[0] == '-') {
			if (!read_int_strvec(strvec, i, &value, INT_MIN, INT_MAX, false)) {
				/* It is not a valid integer */
				report_config_error(CONFIG_GENERAL_ERROR, "Track file %s init value %s is invalid"
									, cur_track_file->fname, word);
				value = 0;
			}
			else if (value < -254 || value > 254) {
// This is not valid for checker process
				report_config_error(CONFIG_GENERAL_ERROR, "Track file %s init value %d is"
									  " outside sensible range [%d, %d]"
									, cur_track_file->fname, value, -254, 254);
			}

			track_file_init_value = value;
		}
		else if (!strcmp(word, "overwrite"))
			track_file_init = TRACK_FILE_INIT;
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unknown track file init option %s", word);
	}
}

static void
track_file_end_handler(void)
{
	struct stat statb;
	FILE *tf;
	int ret;
	tracked_file_t *track_file;

	if (!cur_track_file)
		return;

	if (!cur_track_file->file_path) {
		report_config_error(CONFIG_GENERAL_ERROR, "No file set for track_file %s - ignoring"
							, cur_track_file->fname);
		return;
	}

	track_file = cur_track_file;
	cur_track_file = NULL;

#ifdef _WITH_VRRP_
	if (vrrp_data)
		list_add_tail(&track_file->e_list, &vrrp_data->vrrp_track_files);
#endif

#ifdef _WITH_LVS_
	if (check_data) {
#if defined _ONE_PROCESS_DEBUG_ && defined _WITH_VRRP_
		/* If we want it for both VRRP and LVS we must duplicate the data */
		if (vrrp_data) {
			tracked_file_t *dup_track_file;

			PMALLOC(dup_track_file);
			*dup_track_file = *track_file;
			track_file = dup_track_file;
		}
#endif
		list_add_tail(&track_file->e_list, &check_data->track_files);
	}
#endif

	if (track_file_init == TRACK_FILE_NO_INIT)
		return;

	ret = stat(track_file->file_path, &statb);
	if (!ret) {
		if (track_file_init == TRACK_FILE_CREATE) {
			/* The file exists */
			return;
		}
		if ((statb.st_mode & S_IFMT) != S_IFREG) {
			/* It is not a regular file */
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot initialise track file %s"
								  " - it is not a regular file"
								, track_file->fname);
			return;
		}

		/* Don't overwrite a file on reload */
		if (reload)
			return;
	}

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		/* Write the value to the file */
		if ((tf = fopen_safe(track_file->file_path, "w"))) {
			fprintf(tf, "%d\n", track_file_init_value);
			fclose(tf);
		}
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to initialise track file %s"
								, track_file->fname);
	}
}

void
add_track_file_keywords(bool active)
{
	/* Track file declarations */
	install_keyword_root("track_file", &track_file_handler, active);
	install_keyword("file", &track_file_file_handler);
	install_keyword("weight", &track_file_weight_handler);
	install_keyword("init_file", &track_file_init_handler);
	install_sublevel_end_handler(&track_file_end_handler);

#ifdef _WITH_VRRP_
	install_keyword_root("vrrp_track_file", &vrrp_track_file_handler, active);	/* Deprecated synonym - after v2.0.20 */
	install_keyword("file", &track_file_file_handler);
	install_keyword("weight", &track_file_weight_handler);
	install_keyword("init_file", &track_file_init_handler);
	install_sublevel_end_handler(&track_file_end_handler);
#endif
}

void
free_tracking_obj_list(list_head_t *l)
{
	tracking_obj_t *top, *top_tmp;

	list_for_each_entry_safe(top, top_tmp, l, e_list)
		free_tracking_obj(top);
}

static void
free_track_file(tracked_file_t *file)
{
	list_del_init(&file->e_list);
	free_tracking_obj_list(&file->tracking_obj);
	FREE_CONST(file->fname);
	FREE_CONST(file->file_path);
	FREE(file);
}
void
free_track_file_list(list_head_t *l)
{
	tracked_file_t *file, *file_tmp;

	list_for_each_entry_safe(file, file_tmp, l, e_list)
		free_track_file(file);
}

void
dump_tracking_obj_list(FILE *fp, const list_head_t *l, obj_dump_func_t dump)
{
	tracking_obj_t *top;

	if (list_empty(l))
		return;

	conf_write(fp, "   Tracking instances :");
	list_for_each_entry(top, l, e_list) {
		if (dump)
			(*dump) (fp, top);
	}
}

static void
dump_track_file(FILE *fp, const tracked_file_t *file)
{
	conf_write(fp, " Track file = %s", file->fname);
	conf_write(fp, "   File = %s", file->file_path);
	conf_write(fp, "   Status = %" PRIi64, file->last_status);
	conf_write(fp, "   Weight = %d%s", file->weight, file->weight_reverse ? " reverse" : "");
	dump_tracking_obj_list(fp, &file->tracking_obj, file->tracking_obj_dump);
}
void
dump_track_file_list(FILE *fp, const list_head_t *l)
{
	tracked_file_t *file;

	list_for_each_entry(file, l, e_list)
		dump_track_file(fp, file);
}

void
add_obj_to_track_file(void *obj, tracked_file_monitor_t *tfl, const char *name, obj_dump_func_t dump)
{
	tracked_file_t *file = tfl->file;
	tracking_obj_t *top;

	if (!file)
		return;

	if (!file->tracking_obj_dump)
		file->tracking_obj_dump = dump;

	/* Is this file already tracking the vrrp instance directly?
	 * For this to be the case, the file was added directly on the vrrp instance,
	 * and now we are adding it for a sync group. */
	list_for_each_entry(top, &file->tracking_obj, e_list) {
		if (top->obj.obj == obj) {
			/* Update the weight appropriately. We will use the sync group's
			 * weight unless the vrrp setting is unweighted. */
			log_message(LOG_INFO, "(%s) track_file %s is configured on object"
					    , name, file->fname);
			if (top->weight) {
				top->weight = tfl->weight;
				top->weight_multiplier = tfl->weight_reverse ? -1 : 1;
			}
			return;
		}
	}

	PMALLOC(top);
	INIT_LIST_HEAD(&top->e_list);
	top->obj.obj = obj;
	top->weight = tfl->weight;
	top->weight_multiplier = tfl->weight_reverse ? -1 : 1;
	list_add_tail(&top->e_list, &file->tracking_obj);
}

static void
remove_track_file(tracked_file_t *file)
{
	tracked_file_monitor_t *tft, *tft_tmp;
	list_head_t *track_file_list;
	tracking_obj_t *top;

	/* Search through the objects tracking this file */
	list_for_each_entry(top, &file->tracking_obj, e_list) {
#ifdef _WITH_VRRP_
		if (vrrp_data)
			track_file_list = &top->obj.vrrp->track_file;
		else
#endif
#ifdef _WITH_LVS_
		if (check_data)
			track_file_list = &top->obj.checker->rs->track_files;
		else
#endif
			break;

		/* Search for the matching track file */
		list_for_each_entry_safe(tft, tft_tmp, track_file_list, e_list) {
			if (tft->file == file) {
				free_track_file_monitor(tft);
				break;
			}
		}
	}

	free_track_file(file);
}

#ifdef _WITH_VRRP_
static void
process_update_vrrp_track_file_status(const tracked_file_t *tfile, int new_status, const tracking_obj_t *top)
{
	int previous_status;
	vrrp_t *vrrp = top->obj.vrrp;

	if (new_status < -254)
		new_status = -254;
	else if (new_status > 253)
		new_status = 253;

	previous_status = !top->weight ? (!!tfile->last_status == (top->weight_multiplier == 1) ? -254 : 0 ) : tfile->last_status * top->weight * top->weight_multiplier;
#ifdef TMP_TRACK_FILE_DEBUG
	log_message(LOG_INFO, "top->weight %d, mult %d tfile->last_status %" PRIi64 ", previous_status %d new_status %d"
			    , top->weight, top->weight_multiplier, tfile->last_status, previous_status, new_status);
#endif
	if (previous_status < -254)
		previous_status = -254;
	else if (previous_status > 253)
		previous_status = 253;

	if (previous_status == new_status)
		return;

	if (new_status == -254) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): tracked file %s now FAULT state"
					    , vrrp->iname, tfile->fname);
		if (top->weight)
			vrrp->total_priority -= previous_status;
		down_instance(vrrp);
	} else if (previous_status == -254) {
		if (top->weight) {
			vrrp->total_priority += new_status;
			vrrp->effective_priority = vrrp->total_priority >= VRRP_PRIO_OWNER ? VRRP_PRIO_OWNER - 1 : vrrp->total_priority < 1 ? 1 : vrrp->total_priority;
		}
		if (__test_bit(LOG_DETAIL_BIT, &debug)) {
			log_message(LOG_INFO, "(%s): tracked file %s leaving FAULT state"
					    , vrrp->iname, tfile->fname);
			if (new_status)
				log_message(LOG_INFO, "(%s) Setting effective priority to %d"
						    , vrrp->iname, vrrp->effective_priority);
		}
		try_up_instance(vrrp, false);
	} else {
		vrrp->total_priority += new_status - previous_status;
		vrrp_set_effective_priority(vrrp);
	}
}
#endif

#ifdef _WITH_LVS_
void
process_update_checker_track_file_status(const tracked_file_t *tfile, int new_status, const tracking_obj_t *top)
{
	int previous_status;
	int64_t previous_status64;
	checker_t *checker = top->obj.checker;

	previous_status64 = !top->weight ? (!tfile->last_status != (top->weight_multiplier == 1) ? IPVS_WEIGHT_FAULT : 0 ) : (int64_t)tfile->last_status * top->weight * top->weight_multiplier;
	previous_status = weight_range(previous_status64);

	if (previous_status == new_status)
		return;

	if (new_status == IPVS_WEIGHT_FAULT) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): tracked file %s now FAULT state"
					    , FMT_RS(checker->rs, checker->vs), tfile->fname);
		update_svr_checker_state(DOWN, checker);
		checker->rs->effective_weight -= checker->cur_weight;
		checker->cur_weight = 0;
	} else if (previous_status == IPVS_WEIGHT_FAULT) {
		if (__test_bit(LOG_DETAIL_BIT, &debug))
			log_message(LOG_INFO, "(%s): tracked file %s leaving FAULT state"
					    , FMT_RS(checker->rs, checker->vs), tfile->fname);
		checker->cur_weight = new_status;
		checker->rs->effective_weight += new_status;
		update_svr_checker_state(UP, checker);
	}
	else {
#ifdef TMP_TRACK_FILE_DEBUG
		log_message(LOG_INFO, "Updated weight to %" PRIi64 " (weight %d, new_status %d previous_status %d)"
				    , checker->rs->effective_weight + new_status - previous_status
				    , real_weight(checker->rs->effective_weight), new_status, previous_status);
#endif
		update_svr_wgt(checker->rs->effective_weight + new_status - previous_status, checker->vs, checker->rs, true);
		checker->cur_weight = new_status;
	}
}
#endif

static void
update_track_file_status(tracked_file_t *tfile, int64_t new_status)
{
	tracking_obj_t *top;
	int status;

	if (new_status == tfile->last_status)
		return;

	/* Process the objects tracking the file */
	list_for_each_entry(top, &tfile->tracking_obj, e_list) {
		/* If the tracking weight is 0, a non-zero value means
		 * failure, a 0 status means success */
		if (!top->weight)
			status = !new_status != (top->weight_multiplier == 1) ? INT_MIN : 0;
		else
			status = weight_range((int64_t)new_status * top->weight * top->weight_multiplier);

#ifdef _WITH_VRRP_
		if (vrrp_data)
			process_update_vrrp_track_file_status(tfile, status, top);
#endif
#ifdef _WITH_LVS_
		if (check_data)
			process_update_checker_track_file_status(tfile, status, top);
#endif
	}
}

static void
process_track_file(tracked_file_t *tfile, bool init)
{
	int64_t new_status = 0;
	char buf[128];
	int fd;
	ssize_t len;

	if ((fd = open(tfile->file_path, O_RDONLY | O_NONBLOCK)) != -1) {
		len = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (len > 0) {
			buf[len] = '\0';
			/* If there is an error, we want to use 0,
			 * so we don't really mind if there is an error */
			errno = 0;
#if LONG_MAX > INT32_MAX
			new_status = strtol(buf, NULL, 0);
#else
			new_status = strtoll(buf, NULL, 0);
#endif
			if (errno || new_status < (int64_t)INT32_MIN || new_status > (int64_t)INT32_MAX + 1) {
				log_message(LOG_INFO, "Invalid number %" PRId64 " read from %s - ignoring",  new_status, tfile->file_path);
				return;
			}
		}
	}

	if (!init)
		update_track_file_status(tfile, new_status);

#ifdef TMP_TRACK_FILE_DEBUG
	log_message(LOG_INFO, "Read %s: long val %ld, val %d, last status %" PRIi64
			    , tfile->file_path, new_status, (int)new_status, tfile->last_status);
#endif

	tfile->last_status = new_status;
}

static void
process_inotify(thread_ref_t thread)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1] __attribute__((aligned(__alignof__(struct inotify_event))));
	char *buf_ptr;
	ssize_t len;
	struct inotify_event* event;
	tracked_file_t *tfile;
	int fd = thread->u.f.fd;
	list_head_t *track_files = thread->arg;

	inotify_thread = thread_add_read(master, process_inotify, track_files, fd, TIMER_NEVER, 0);

	while (true) {
		if ((len = read(fd, buf, sizeof(buf))) < (ssize_t)sizeof(struct inotify_event)) {
			if (len == -1) {
				if (check_EAGAIN(errno))
					return;

				if (check_EINTR(errno))
					continue;

				log_message(LOG_INFO, "inotify read() returned error %d - %m", errno);
				return;
			}

			log_message(LOG_INFO, "inotify read() returned short length %zd", len);
			return;
		}

		/* Try and keep coverity happy. It thinks event->name is not null
		 * terminated in the strcmp() below */
		buf[sizeof(buf) - 1] = 0;

		/* The following line causes a strict-overflow=4 warning on gcc 5.4.0 */
		for (buf_ptr = buf; buf_ptr < buf + len; buf_ptr += event->len + sizeof(struct inotify_event)) {
			event = PTR_CAST(struct inotify_event, buf_ptr);

			/* We are not interested in directories */
			if (event->mask & IN_ISDIR)
				continue;

			if (!(event->mask & (IN_DELETE | IN_CLOSE_WRITE | IN_MOVE))) {
				log_message(LOG_INFO, "Unknown inotify event 0x%x", event->mask);
				continue;
			}

			list_for_each_entry(tfile, track_files, e_list) {
				/* Is this event for our file */
				if (tfile->wd != event->wd ||
				    strcmp(tfile->file_part, event->name))
					continue;

				if (event->mask & (IN_MOVED_FROM | IN_DELETE)) {
					/* The file has disappeared. Treat as though the value is 0 */
					update_track_file_status(tfile, 0);

					tfile->last_status = 0;
				}
				else {	/* event->mask & (IN_MOVED_TO | IN_CLOSE_WRITE) */
					/* The file has been writted/moved in */
					process_track_file(tfile, false);
				}
			}
		}
	}

	/* NOT REACHED */
}

void
init_track_files(list_head_t *track_files)
{
	tracked_file_t *tfile, *tfile_tmp;
	char *resolved_path;
	char *dir_end = NULL;
	char *new_path;
	struct stat stat_buf;
	char *realpath_buf;
	bool file_exists;

	if (inotify_fd != -1) {
		/* This should not happen */
		close(inotify_fd);
		inotify_fd = -1;
	}

	realpath_buf = MALLOC(PATH_MAX);

	list_for_each_entry_safe(tfile, tfile_tmp, track_files, e_list) {
		if (list_empty(&tfile->tracking_obj)) {
			/* Nothing is tracking this file, so forget it */
			remove_track_file(tfile);
			continue;
		}

		file_exists = false;

		resolved_path = realpath(tfile->file_path, realpath_buf);
		if (resolved_path) {
			if (strcmp(tfile->file_path, resolved_path)) {
				FREE_CONST(tfile->file_path);
				tfile->file_path = STRDUP(resolved_path);
			}

			file_exists = true;
		}
		else if (errno == ENOENT) {
			/* Resolve the directory */
			if (!(dir_end = strrchr(tfile->file_path, '/')))
				resolved_path = realpath(".", realpath_buf);
			else {
				*dir_end = '\0';
				resolved_path = realpath(tfile->file_path, realpath_buf);

				/* Check it is a directory */
				if (resolved_path &&
				    (stat(resolved_path, &stat_buf) ||
				     !S_ISDIR(stat_buf.st_mode))) {
					resolved_path = NULL;
				}
			}

			if (!resolved_path) {
				report_config_error(CONFIG_GENERAL_ERROR, "Track file directory for %s "
									  "does not exist - removing"
									, tfile->fname);
				remove_track_file(tfile);
				continue;
			}

			/* Make the file name with the resolved directory path */
			if (strcmp(tfile->file_path, resolved_path)) {
				new_path = MALLOC(strlen(resolved_path) + strlen((!dir_end) ? tfile->file_path : dir_end + 1) + 2);
				strcpy(new_path, resolved_path);
				strcat(new_path, "/");
				strcat(new_path, dir_end ? dir_end + 1 : tfile->file_path);
				FREE_CONST(tfile->file_path);
				tfile->file_path = new_path;
			}
			else if (dir_end)
				*dir_end = '/';
		}
		else {
			report_config_error(CONFIG_GENERAL_ERROR, "track file %s is not accessible"
								  " - ignoring", tfile->fname);
			remove_track_file(tfile);
			continue;
		}

		if (inotify_fd == -1) {
			inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);

			if (inotify_fd == -1) {
				log_message(LOG_INFO, "Unable to monitor track files");
				break;
			}
		}

		tfile->file_part = strrchr(tfile->file_path, '/') + 1;
		new_path = STRNDUP(tfile->file_path, tfile->file_part - tfile->file_path);
		tfile->wd = inotify_add_watch(inotify_fd, new_path, IN_CLOSE_WRITE | IN_DELETE | IN_MOVE);
		FREE(new_path);

		/* If the file exists, read it now */
		if (file_exists)
			process_track_file(tfile, true);
	}

	FREE(realpath_buf);

	if (inotify_fd != -1)
		inotify_thread = thread_add_read(master, process_inotify, track_files, inotify_fd, TIMER_NEVER, 0);
}

void
stop_track_files(void)
{
	if (inotify_thread) {
		thread_cancel(inotify_thread);
		inotify_thread = NULL;
	}

	if (inotify_fd != -1) {
		close(inotify_fd);
		inotify_fd = -1;
	}
}

#ifdef THREAD_DUMP
void
register_track_file_inotify_addresses(void)
{
	register_thread_address("process_inotify", process_inotify);
}
#endif
