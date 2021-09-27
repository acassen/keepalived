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

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/select.h>

#include "fuse_interface.h"
#include "scheduler.h"
#include "logger.h"
#include "utils.h"
#include "memory.h"
#include "fuse_log.h"


#define MIN(a,b) (a<b ? a : b)


typedef struct fuse_thread_data {
	struct fuse *fuse;
	struct ent *top;
} fuse_thread_data_t;

const char *tbd_str = "Not yet implemented\n";

struct timespec start_time;
static struct ent *top;

static void
*hello_init(__attribute__((unused)) struct fuse_conn_info *conn, __attribute__((unused)) struct fuse_config *cfg)
{
	log_conn(conn);
	log_fuse_context(fuse_get_context());
void *root = fuse_get_context()->private_data;
	log_message(LOG_INFO, "hello_init(root = %p)", root);

	return fuse_get_context()->private_data;
}

static int
hello_open(const char *path, struct fuse_file_info *fi)
{
//	if(strcmp(path, hello_path) != 0)
//		return -ENOENT;
log_message(LOG_INFO, "In open for %s", path);
	if((fi->flags & 3) != O_RDONLY)
		return -EACCES;
	return 0;
}

static const struct ent *
find_path(const char *path, struct ent* ents)
{
	const char *end;
	size_t len;
	struct ent *f;

//log_message(LOG_INFO, "Find %s in %p (%s)", path, ents, ents == top ? "top" : ents == root_ent ? "root" : ents == vrrp_list ? "vrrp_list" : "?");
	if (path[0] == '/' && !path[1])
		return ents;

       	end = strchr(path, '/');
	if (!end)
		len = strlen(path);
	else
		len = end - path;

	for (f = ents; f->fname; f++) {
		if (f->populate || (!f->populate && strlen(f->fname) == len && !strncmp(f->fname, path, len))) {
			if (f->set) {
				if (!(*f->set)(path, len))
					return NULL;
			}
			if (!end)
				return f;
			if (f->entries)
				return find_path(end + 1, f->entries);
			return NULL;
		}

	}
	return NULL;
}

static int
hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler, __attribute__((unused)) off_t offset, __attribute__((unused)) struct fuse_file_info *fi, __attribute__((unused)) enum fuse_readdir_flags flags)
{
	const struct ent *f;

	f = find_path(path, top);
	if (!f || !f->entries)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	if (f->entries->populate)
		(*f->entries->populate)(buf, filler);
	else {
		for (f = f->entries; f->fname; f++) {
			filler(buf, f->fname, NULL, 0, 0);
		}
	}

	return 0;
}

static int
hello_getattr(const char *path, struct stat *stbuf, __attribute__((unused)) struct fuse_file_info *fi)
{
	const struct ent *f;

log_message(LOG_INFO, "getattr called for %s", path);
	memset(stbuf, 0, sizeof(struct stat));
	if (!(f = find_path(path, top)))
		return -ENOENT;

	if(f->entries) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 1;
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = 20;
	}

	stbuf->st_atim.tv_sec = start_time.tv_sec;
	stbuf->st_atim.tv_nsec = start_time.tv_nsec;
	stbuf->st_mtim.tv_sec = start_time.tv_sec;
	stbuf->st_mtim.tv_nsec = start_time.tv_nsec;
	stbuf->st_ctim.tv_sec = start_time.tv_sec;
	stbuf->st_ctim.tv_nsec = start_time.tv_nsec;

	return 0;
}

static int
hello_read(const char *path, char *buf, size_t size, off_t offset, __attribute__((unused)) struct fuse_file_info *fi)
{
	size_t len = strlen(tbd_str);
log_message(LOG_INFO, "In read for %s, offset %ld, size %zu, str_len %zu", path, offset, size, len);
//	if(strcmp(path, hello_path) != 0)
//		return -ENOENT;
	if (offset > (off_t)len)
		return 0;

	size = MIN(size, len - offset);
	memcpy(buf, tbd_str + offset, size);
log_message(LOG_INFO, "copying %zu chars, buf now `%s`", size, buf);
	return size;
}

static struct fuse_operations hello_oper = {
	.getattr = hello_getattr,
	.readdir = hello_readdir,
	.open = hello_open,
	.read = hello_read,
	.init = hello_init,
	};


static void
fuse_read_thread(thread_ref_t thread)
{
	fuse_thread_data_t *td = PTR_CAST(fuse_thread_data_t, thread->arg);
	struct fuse_session *se = fuse_get_session(td->fuse);
	struct fuse_buf fbuf = { .size = 0 };

log_message(LOG_INFO, "Got fuse message fuse %p, se %p", td->fuse, se);
	top = td->top;

	// Add a while loop to continue receiving
	fuse_session_receive_buf(se, &fbuf);
	fuse_session_process_buf(se, &fbuf);

	thread_add_read(thread->master, fuse_read_thread, td, thread->u.f.fd, TIMER_NEVER, 0);
}

static void
create_mountpoint(const char *mountpoint)
{
	int error;

	/* We want to create the PID directory with permissions rwxr-xr-x */
	if (umask_val & (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
		umask(umask_val & ~(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH));

	error = mkdir(mountpoint, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) && errno != EEXIST;

	/* Restore the default umask */
	if (umask_val & (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
		umask(umask_val);

	if (error)
		log_message(LOG_INFO, "mkdir failed");
}

static void
remove_mountpoint(const char *mountpoint)
{
	unlink(mountpoint);
}

void *
start_fuse(const char *mountpoint, struct ent *root, bool add_mountpoint)
{
	struct fuse *fuse;
	int res = 0;
	struct fuse_cmdline_opts opts;
	union {
		const char *argv_c[2];
		char *argv[2];
	} argvs = { .argv_c[0] = "keepalived", .argv_c[1] = mountpoint };
	fuse_thread_data_t *td;

	/* Let libfuse to use our logging function */
	fuse_set_log_func((fuse_log_func_t)vlog_message);

	if (!start_time.tv_sec)
		clock_gettime(CLOCK_REALTIME, &start_time);

	if (add_mountpoint)
		create_mountpoint(mountpoint);

	struct fuse_args args = FUSE_ARGS_INIT(sizeof(argvs.argv) / sizeof(argvs.argv[0]), argvs.argv);
	if (fuse_parse_cmdline(&args, &opts) != 0) {
		log_message(LOG_INFO, "fuse_parse_cmdline error");
		return NULL;
	}

	fuse = fuse_new(&args, &hello_oper, sizeof(struct fuse_operations), root);
        if (fuse == NULL) {
                res = 3;
                log_message(LOG_INFO, "fuse_new error");
		return NULL;
        }

        if (fuse_mount(fuse, mountpoint) != 0) {
                res = 4;
                log_message(LOG_INFO, "fuse_mount failed");
		return NULL;
        }

	td = MALLOC(sizeof(fuse_thread_data_t));
	td->fuse = fuse;
	td->top = root;
log_message(LOG_INFO, "Adding fuse read thread, fuse %p, session %p, fd %d, root %p", fuse, fuse_get_session(fuse), fuse_session_fd(fuse_get_session(fuse)), root);

	thread_add_read(master, fuse_read_thread, td, fuse_session_fd(fuse_get_session(fuse)), TIMER_NEVER, 0);

if (res)
log_message(LOG_INFO, "start_fuse res %d", res);

	return (fuse);
}

void
stop_fuse(void *fuse_v, const char *mountpoint)
{
	struct fuse *fuse = PTR_CAST(struct fuse, fuse_v);

	fuse_unmount(fuse);
	fuse_destroy(fuse);

	if (mountpoint)
		remove_mountpoint(mountpoint);
}

#ifdef THREAD_DUMP
void
register_fuse_thread_addresses(void)
{
	register_thread_address("fuse_read_thread", fuse_read_thread);
}
#endif
