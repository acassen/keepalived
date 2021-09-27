// FUSE: Filesystem in Userspace
// Copyright (C) 2001-2005 Miklos Szeredi <miklos@szeredi.hu>
// This program can be distributed under the terms of the GNU GPL.
// See the file COPYING.

// See https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/html/callbacks.html
// and http://www.oug.org/files/presentations/losug-fuse.pdf

/* On Fedora, install fuse (runtime), fuse-devel (build time) */

/* To run:
 *   ./ka MOUNTPOINT
 *
 * To terminate:
 *   fusermount -u MOUNTPOINT
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "bfd_fuse.h"
#include "logger.h"
#include "fuse_interface.h"

/* To remove */
#include <stdlib.h>

static struct ent bfd_list[] = {
	{ "dummy file", NULL, NULL, NULL},
	{NULL, NULL, NULL, NULL}
} ;

static struct ent top[] = {
	{"", bfd_list, NULL, NULL},
	{NULL, NULL, NULL, NULL}
} ;

static void *fuses;
//static const char *mountpoint = "/tmp/ka/fs";
static const char *mountpoint = "/tmp/keepaliveda/low/state/bfd";

void
start_bfd_fuse(void)
{
	fuses = start_fuse(mountpoint, top, false);
}

void
stop_bfd_fuse(void)
{
	if (fuses)
		stop_fuse(fuses, NULL);
	fuses = NULL;
}
