/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Config read completion notification
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
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
 * Copyright (C) 2021-2021 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <inttypes.h>

#include "config_notify.h"
#include "logger.h"
#include "scheduler.h"
#include "systemd.h"
#include "main.h"

static int child_reloaded_event = -1;
static bool loaded;
static bool reload_queued;


void
queue_reload(void)
{
	if (__test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_INFO, "Reload already in progress, request queued");

	reload_queued = true;
}

static void
child_reloaded_thread(__attribute__((unused)) thread_ref_t thread)
{
	uint64_t event_count;
	int ret;

	ret = read(thread->u.f.fd, &event_count, sizeof(event_count));

	if (ret != sizeof(event_count)) {
		log_message(LOG_INFO, "read eventfd returned %d, errno %d - %m", ret, errno);
		return;
	}

	if (num_reloading >= event_count) {
		num_reloading -= event_count;

		if (!num_reloading) {
			log_message(LOG_INFO, "%s complete", loaded ? "Reload" : "Startup");
			loaded = true;
#ifdef _USE_SYSTEMD_NOTIFY_
			systemd_notify_running();
#endif

			if (reload_queued) {
				reload_queued = false;
				thread_add_event(master, start_reload, NULL, 0);
			}
		}
	} else
		log_message(LOG_INFO, "read eventfd count %" PRIu64 ", num_reloading %u", event_count, num_reloading);

	thread_add_read(master, child_reloaded_thread, NULL, child_reloaded_event, TIMER_NEVER, 0);
}

void
open_config_read_fd(void)
{
	child_reloaded_event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	thread_add_read(master, child_reloaded_thread, NULL, child_reloaded_event, TIMER_NEVER, 0);
}

void
notify_config_read(void)
{
	uint64_t one = 1;

	/* If we are not the parent, tell it we have completed reading the configuration */
	if (write(child_reloaded_event, &one, sizeof(one)) <= 0)
		log_message(LOG_INFO, "Write child_reloaded_event errno %d - %m", errno);
}

#ifdef THREAD_DUMP
void
register_config_notify_addresses(void)
{
	register_thread_address("child_reloaded_thread", child_reloaded_thread);
	register_thread_address("start_reload", start_reload);
}
#endif
