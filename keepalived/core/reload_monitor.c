/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduled reload handling.
 *
 * Author:      Quentin Armitage <quentin@armitage.org.uk>
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
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

/* For kill */
#include <sys/types.h>
#include <signal.h>

#include "reload_monitor.h"
#include "logger.h"
#include "global_data.h"
#include "scheduler.h"
#include "utils.h"

static int dir_wd, file_wd;

static thread_ref_t inotify_thread;
static thread_ref_t reload_timer_thread_p;

static const char *file_name;

#ifndef HAVE_TIMEGM
static char tz_utc[] = "TZ=UTC";
static char *utc_env[] = { tz_utc, NULL};
#endif

// #define RELOAD_DEBUG

static void
reload_timer_thread(__attribute__((unused)) thread_ref_t thread)
{
	int inotify_fd = inotify_thread->u.f.fd;

	reload_timer_thread_p = NULL;

	/* We don't want to know that the file is being removed */
	thread_cancel(inotify_thread);
	inotify_thread = NULL;

	close(inotify_fd);

	if (!global_data->reload_repeat ||
	    global_data->reload_date_specified)
		unlink(global_data->reload_time_file);

	kill(getpid(), SIGHUP);
	/*
	or
	reload_config();
	*/

	return;
}

static char *
format_time_t(char *str, size_t len, time_t t)
{
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(str, len, "%Y-%m-%d %H:%M:%S", &tm);

	return str;
}

#ifndef HAVE_TIMEGM
static time_t
timegm(struct tm *tm)
{
	char **sav_env = environ;
	time_t t;

	environ = utc_env;

	t = mktime(tm);

	/* Restore previous settings */
	environ = sav_env;
	tzset();

	return t;
}
#endif

inline static void
cancel_reload(bool log)
{
	char time_str[20];

	if (!reload_timer_thread_p)
		return;

	thread_cancel(reload_timer_thread_p);
	reload_timer_thread_p = NULL;

	if (log && global_data->reload_time)
		log_message(LOG_INFO, "Cancelling reload scheduled for %s", format_time_t(time_str, sizeof(time_str), global_data->reload_time));

	global_data->reload_time = 0;
}

static time_t
parse_datetime(const char *timestr, bool *date_specified)
{
#ifdef RELOAD_DEBUG
	char buf[128];
#endif
	time_t now = time(NULL);
	time_t t;
	struct tm tm, tm1;
	size_t len;
	char *end;
	bool utc = false;

	len = strlen(timestr);

	if (len && timestr[len - 1] == 'Z') {
		utc = true;
		len--;
	}

	if (len != 8 && len != 17 && len != 19) {
		log_message(LOG_INFO, "Reload time %s format is incorrect - ignoring", timestr);
		return -1;
	}

	if (utc)
		gmtime_r(&now, &tm);
	else
		localtime_r(&now, &tm);

	end = strptime(timestr, len == 8 ? "%H:%M:%S" : len == 17 ? "%y-%m-%d %H:%M:%S" : "%Y-%m-%d %H:%M:%S", &tm);
	if (!end || end[utc ? 1 : 0]) {
		log_message(LOG_INFO, "Reload date/time %s invalid - ignoring", timestr);
		return -1;
	}

#ifdef RELOAD_DEBUG
	log_message(LOG_INFO, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d %s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_isdst ? " DST" : "");
#endif

	tm.tm_isdst = -1;
#ifdef RELOAD_DEBUG
	strftime(buf, sizeof(buf), "%c", &tm);
	log_message(LOG_INFO, "strf - %s", buf);
#endif

	tm1 = tm;
	t = mktime(&tm1);
	if (tm.tm_year != tm1.tm_year ||
	    tm.tm_mon != tm1.tm_mon ||
	    tm.tm_mday != tm1.tm_mday ||
	    tm.tm_hour != tm1.tm_hour ||
	    tm.tm_min != tm1.tm_min ||
	    tm.tm_sec != tm1.tm_sec) {
		log_message(LOG_INFO, "Reload time %s is not valid - ignoring", timestr);
		return -1;
	}

	if (utc)
		t = timegm(&tm1);

	if (t <= now) {
		if (len == 8) {
			tm1.tm_mday++;
			t = utc ? timegm(&tm1) : mktime(&tm1);
#ifdef RELOAD_DEBUG
			log_message(LOG_INFO, "Going to tomorrow");
#endif
		} else {
			log_message(LOG_INFO, "Reload time %s is in the past - ignoring", timestr);
			return -2;
		}
	}

	*date_specified = (len >= 17);

#ifdef RELOAD_DEBUG
	localtime_r(&t, &tm1);
	strftime(buf, sizeof(buf), "%c", &tm1);
	log_message(LOG_INFO, "mktime - %s%s - %s", buf, tm1.tm_isdst ? " DST" : "", *tzname);
#endif

	return t;
}

static void
read_file(void)
{
	FILE *fp = fopen(global_data->reload_time_file, "r");
	size_t len;
	time_t reload_time;
	char	time_buf[21];
	char	old_time_buf[20];
	unsigned long delay;

	if (fp) {
		if (fgets(time_buf, sizeof(time_buf), fp)) {
			if ((len = strlen(time_buf)) && time_buf[len - 1] == '\n')
				time_buf[--len] = '\0';
		} else {
#ifdef RELOAD_DEBUG
			log_message(LOG_INFO, "fgets returned NULL");
#endif
			cancel_reload(true);
			fclose(fp);
			return;
		}
		fclose(fp);
	} else {
		cancel_reload(true);
		return;
	}

	reload_time = parse_datetime(time_buf, &global_data->reload_date_specified);

	if (reload_time <= -1) {
		if (reload_time == -1)
			log_message(LOG_INFO, "Invalid reload time '%s' specified - ignoring", time_buf);
		else if (reload_time == -2)
			log_message(LOG_INFO, "Reload date/time is in the past - ignoring");

		cancel_reload(true);

		return;
	}

	if (reload_time != global_data->reload_time) {
		set_time_now();
		delay = (reload_time - time_now.tv_sec) * TIMER_HZ - time_now.tv_usec;

		if (global_data->reload_time)
			format_time_t(old_time_buf, sizeof(old_time_buf), global_data->reload_time);
		if (reload_time)
			format_time_t(time_buf, sizeof(time_buf), reload_time);

		if (reload_timer_thread_p) {
			if (reload_time) {
				log_message(LOG_INFO, "Reload time updated from %s to %s", old_time_buf, time_buf);
				timer_thread_update_timeout(reload_timer_thread_p, delay);
			} else
				cancel_reload(true);
		} else {
			if (reload_time) {
				log_message(LOG_INFO, "Scheduling reload for %s", time_buf);
				reload_timer_thread_p = thread_add_timer(master, reload_timer_thread, NULL, delay);
			} else
				log_message(LOG_INFO, "Cancelling reload but no thread");
		}

		global_data->reload_time = reload_time;
	}
}

static int
watch_file(int fd)
{
	int wd;

#ifdef RELOAD_DEBUG
	log_message(LOG_INFO, "add watch for %s", global_data->reload_time_file);
#endif

	if ((wd = inotify_add_watch(fd, global_data->reload_time_file, IN_CLOSE_WRITE)) == -1) {
#ifdef RELOAD_DEBUG
		log_message(LOG_INFO, "inotify_add_watch(%s) failed - errno %d - %m", global_data->reload_time_file, errno);
#endif
		return -1;
	}

	read_file();

	return wd;
}

static void
inotify_event_thread(thread_ref_t thread)
{
	char buf[256] __attribute__((aligned(__alignof__(struct inotify_event))));
	char *buf_ptr;
	struct inotify_event* event;
	ssize_t len;

	while (true) {
		if ((len = read(thread->u.f.fd, buf, sizeof(buf))) < (ssize_t)sizeof(struct inotify_event)) {
			if (len == -1) {
				if (!check_EAGAIN(errno))
					log_message(LOG_INFO, "inotify read() returned error %d - %m", errno);
// Look to see how handled elsewhere
			} else
				log_message(LOG_INFO, "inotify read() returned short length %zd", len);

			break;
		}

#ifdef RELOAD_DEBUG
		log_message(LOG_INFO, "read returned %zd bytes", len);
#endif

		for (buf_ptr = buf; buf_ptr < buf + len; buf_ptr += event->len + sizeof(struct inotify_event)) {
			event = PTR_CAST(struct inotify_event, buf_ptr);

#ifdef RELOAD_DEBUG
			log_message(LOG_INFO, "File %s, wd %d, cookie %" PRIu32, event->len ? event->name : "[NONE]", event->wd, event->cookie);
			if (event->mask & IN_ACCESS) log_message(LOG_INFO, " IN_ACCESS");
			if (event->mask & IN_ATTRIB) log_message(LOG_INFO, " IN_ATTRIB");
			if (event->mask & IN_CLOSE_WRITE) log_message(LOG_INFO, " IN_CLOSE_WRITE");
			if (event->mask & IN_CLOSE_NOWRITE) log_message(LOG_INFO, " IN_CLOSE_NOWRITE");
			if (event->mask & IN_CREATE) log_message(LOG_INFO, " IN_CREATE");
			if (event->mask & IN_DELETE) log_message(LOG_INFO, " IN_DELETE");
			if (event->mask & IN_DELETE_SELF) log_message(LOG_INFO, " IN_DELETE_SELF");
			if (event->mask & IN_MODIFY) log_message(LOG_INFO, " IN_MODIFY");
			if (event->mask & IN_MOVE_SELF) log_message(LOG_INFO, " IN_MOVE_SELF");
			if (event->mask & IN_MOVED_FROM) log_message(LOG_INFO, " IN_MOVED_FROM");
			if (event->mask & IN_MOVED_TO) log_message(LOG_INFO, " IN_MOVED_TO");
			if (event->mask & IN_OPEN) log_message(LOG_INFO, " IN_OPEN");
			if (event->mask & IN_IGNORED) log_message(LOG_INFO, " IN_IGNORED");
			if (event->mask & IN_ISDIR) log_message(LOG_INFO, " IN_ISDIR");
			if (event->mask & IN_Q_OVERFLOW) log_message(LOG_INFO, " IN_Q_OVERFLOW");
			if (event->mask & IN_UNMOUNT) log_message(LOG_INFO, " IN_UNMOUNT");
#endif

			if (file_wd != -1 && event->wd == file_wd) {
#if 0
				if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
					inotify_rm_watch(thread->u.f.fd, file_wd);
#ifdef RELOAD_DEBUG
					log_message(LOG_INFO, "Removed watch %d", file_wd);
#endif
					file_wd = -1;
					cancel_reload(true);
				}
#endif
				if (event->mask & (IN_CLOSE_WRITE))
					read_file();
			}

			if (event->wd == dir_wd) {
				if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
					/* The directory has gone */
					cancel_reload(true);

					close(thread->u.f.fd);
					log_message(LOG_INFO, "Directory of reload timer file has disappeared. Monitoring stopped.");

					return;
				}

				/* coverity[string_null] */
				if (event->mask & (IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM) &&
				    event->len &&
				    !strcmp(event->name, file_name)) {
					if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
						file_wd = watch_file(thread->u.f.fd);
#ifdef RELOAD_DEBUG
						log_message(LOG_INFO, "file_wd = %d", file_wd);
#endif
					}
					else if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
						inotify_rm_watch(thread->u.f.fd, file_wd);
#ifdef RELOAD_DEBUG
						log_message(LOG_INFO, "Removed watch by IN_%s %d", (event->mask & IN_DELETE) ? "DELETE" : "MOVED_FROM", file_wd);
#endif
						file_wd = -1;
						cancel_reload(true);
					}
				}
			}
		}
	}

	inotify_thread = thread_add_read(master, inotify_event_thread, NULL, thread->u.f.fd, TIMER_NEVER, 0);
}

void
start_reload_monitor(void)
{
	int inotify_fd;
	char *dir;
#ifdef RELOAD_DEBUG
	char time_buf[20];
#endif

	inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);

	file_name = strrchr(global_data->reload_time_file, '/');
	if (!file_name) {
		dir = MALLOC(2);
		dir[0] = '/';
		dir[1] = '\0';
	} else {
		dir = MALLOC(file_name - global_data->reload_time_file + 1);
		strncpy(dir, global_data->reload_time_file, file_name - global_data->reload_time_file);
	}

	if ((dir_wd = inotify_add_watch(inotify_fd, dir,
		IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE_SELF | IN_MOVE_SELF)) == -1) {
		log_message(LOG_INFO, "Unable to monitor reload timer file directory %s- ignoring", dir);
		FREE(dir);
		return;
	}
	FREE(dir);

	if (!file_name)
		file_name = global_data->reload_time_file;
	else
		file_name++;

	file_wd = watch_file(inotify_fd);
#ifdef RELOAD_DEBUG
	log_message(LOG_INFO, "dir_wd = %d, file_wd = %d", dir_wd, file_wd);
	if (global_data->reload_time)
		log_message(LOG_INFO, "Reload scheduled for %s", format_time_t(time_buf, sizeof(time_buf), global_data->reload_time));
#endif

	inotify_thread = thread_add_read(master, inotify_event_thread, NULL, inotify_fd, TIMER_NEVER, 0);
}

void
stop_reload_monitor(void)
{
	int fd;

	if (!inotify_thread)
		return;

	fd = inotify_thread->u.f.fd;

	thread_cancel(inotify_thread);
	inotify_thread = NULL;
	cancel_reload(false);

	close(fd);

	file_name = NULL;
}

#ifdef THREAD_DUMP
void
register_reload_addresses(void)
{
	register_thread_address("inotify_event_thread", inotify_event_thread);
	register_thread_address("reload_timer_thread", reload_timer_thread);
}
#endif
