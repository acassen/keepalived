/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        Print running LVS/checker state information
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
 * Copyright (C) 2019-2019 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <string.h>

#include "logger.h"

#include "check_print.h"
#include "check_data.h"
#include "utils.h"

static const char *dump_file = "/tmp/keepalived_check.data";

void
check_print_data(void)
{
	FILE *file = fopen_safe(dump_file, "w");

	if (!file) {
		log_message(LOG_INFO, "Can't open %s (%d: %s)",
			dump_file, errno, strerror(errno));
		return;
	}

	dump_data_check(file);

	fclose(file);
}
