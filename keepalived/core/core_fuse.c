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

#include "core_fuse.h"
#include "logger.h"
#include "fuse_interface.h"

/* To remove */
#include <stdlib.h>


static struct ent vrrp_dir[] = {
	{NULL, NULL, NULL, NULL}
};

static struct ent ipvs_dir[] = {
	{NULL, NULL, NULL, NULL}
};

static struct ent bfd_dir[] = {
	{NULL, NULL, NULL, NULL}
};

static struct ent root[] = {
	{"global_data", NULL, NULL, NULL},
#ifdef _WITH_VRRP_
	{"vrrp", vrrp_dir, NULL, NULL},
#endif
#ifdef _WITH_LVS_
	{"ipvs", ipvs_dir, NULL, NULL},
#endif
#ifdef _WITH_BFD_
	{"bfd", bfd_dir, NULL, NULL},
#endif
	{NULL, NULL, NULL, NULL}
};

static struct ent top[] = {
	{"", root, NULL, NULL},
	{NULL, NULL, NULL, NULL}
} ;

static void *fuses;
//static const char *mountpoint = "/tmp/ka/fs";
static const char *mountpoint = "/tmp/keepaliveda/low/state";

void
start_core_fuse(void)
{
	fuses = start_fuse(mountpoint, top, true);
}

void
stop_core_fuse(void)
{
	if (fuses)
		stop_fuse(fuses, mountpoint);
	fuses = NULL;
}
