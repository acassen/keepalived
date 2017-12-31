/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD event handling
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
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
 * Copyright (C) 2015-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <assert.h>
#include <unistd.h>

#include "bfd.h"
#include "bfd_event.h"
#include "bfd_daemon.h"
#include "logger.h"
#include "main.h"
#include "memory.h"
#include "bitops.h"
#include "utils.h"
#include "global_data.h"

void
bfd_event_send(bfd_t *bfd)
{
	bfd_event_t evt;
	int ret;

	assert(bfd);

	/* If there is no VRRP process running, don't write to the pipe */
	if (!__test_bit(DAEMON_VRRP, &daemon_mode) || !have_vrrp_instances)
		return;

	memset(&evt, 0, sizeof evt);
	strcpy(evt.iname, bfd->iname);
	evt.state = bfd->local_state == BFD_STATE_UP ? BFD_STATE_UP : BFD_STATE_DOWN;
	evt.sent_time = timer_now();

	ret = write(bfd_event_pipe[1], &evt, sizeof evt);
	if (ret == -1 && __test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_ERR, "BFD_Instance(%s) write() error %m",
			    bfd->iname);
}
