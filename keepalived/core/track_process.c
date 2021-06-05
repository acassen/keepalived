/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Process tracking framework.
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
 * Copyright (C) 2018-2018 Alexandre Cassen, <acassen@gmail.com>
 */

/* For details on the proc connector, see:
 *
 * https://stackoverflow.com/questions/26852228/detect-new-process-creation-instantly-in-linux
 * https://unix.stackexchange.com/questions/260162/how-to-track-newly-created-processes-in-linux
 * http://netsplit.com/the-proc-connector-and-socket-filters
 */

#include "config.h"

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "track_process.h"
#include "global_data.h"
#include "list_head.h"
#include "rbtree.h"
#include "vrrp_data.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "main.h"
#include "process.h"
#include "align.h"


static thread_ref_t read_thread;
static thread_ref_t reload_thread;
static rb_root_t process_tree = RB_ROOT;
static int nl_sock = -1;
static unsigned num_cpus;
static int64_t *cpu_seq;
static bool need_reinitialise;
bool proc_events_not_supported;
bool proc_events_responded;

#ifdef _TRACK_PROCESS_DEBUG_
bool do_track_process_debug;
bool do_track_process_debug_detail;
#endif

#ifdef _INCLUDE_UNUSED_CODE_
static void
dump_process_tree(const char *str)
{
	tracked_process_instance_t *tpi;
	ref_tracked_process_t *rtpr;

	log_message(LOG_INFO, "Process tree - %s", str);
	rb_for_each_entry(tpi, &process_tree, pid_tree) {
		log_message(LOG_INFO, "Pid %d", tpi->pid);
		list_for_each_entry(rtpr, &tpi->processes, e_list)
			log_message(LOG_INFO, "  %s", rtpr->process->pname);
	}
}
#endif

static void
set_rcv_buf(unsigned buf_size, bool force)
{
	if (setsockopt(nl_sock, SOL_SOCKET, force ? SO_RCVBUFFORCE : SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0)
		log_message(LOG_INFO, "Cannot set process monitor SO_RCVBUF%s option. errno=%d (%m)"
				    , force ? "FORCE" : "", errno);
}

static void
free_ref_tracked_process(ref_tracked_process_t *rtpr)
{
	list_del_init(&rtpr->e_list);
	FREE(rtpr);
}
static void
free_ref_tracked_process_list(list_head_t *l)
{
	ref_tracked_process_t *rtpr, *rtpr_tmp;

	list_for_each_entry_safe(rtpr, rtpr_tmp, l, e_list)
		free_ref_tracked_process(rtpr);
}
static ref_tracked_process_t *
alloc_ref_tracked_process(vrrp_tracked_process_t *tpr, tracked_process_instance_t *tpi)
{
	ref_tracked_process_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->e_list);
	new->process = tpr;
	list_add_tail(&new->e_list, &tpi->processes);

	return new;
}
static void
free_tracked_process_instance(tracked_process_instance_t *tpi)
{
	free_ref_tracked_process_list(&tpi->processes);
	rb_erase(&tpi->pid_tree, &process_tree);
	FREE(tpi);
}
static void
free_process_tree(void)
{
	tracked_process_instance_t *tpi, *next;

	rb_for_each_entry_safe(tpi, next, &process_tree, pid_tree) {
		free_ref_tracked_process_list(&tpi->processes);
		rb_erase(&tpi->pid_tree, &process_tree);
		FREE(tpi);
	}
}

static int
pid_compare(const tracked_process_instance_t *tpi1, const tracked_process_instance_t *tpi2)
{
	return less_equal_greater_than(tpi1->pid, tpi2->pid);
}

static inline tracked_process_instance_t *
alloc_tracked_process_instance(pid_t pid)
{
	tracked_process_instance_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->processes);
	new->pid = pid;
	RB_CLEAR_NODE(&new->pid_tree);
	rb_insert_sort(&process_tree, new, pid_tree, pid_compare);

	return new;
}
static inline tracked_process_instance_t *
add_process(pid_t pid, vrrp_tracked_process_t *tpr, tracked_process_instance_t *tpi)
{
	tracked_process_instance_t tp = { .pid = pid };

	if (!tpi && !(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare)))
		tpi = alloc_tracked_process_instance(tp.pid);
	alloc_ref_tracked_process(tpr, tpi);
	++tpr->num_cur_proc;

	return tpi;
}

#ifdef _INCLUDE_UNUSED_CODE_
static int scandir_filter(const struct dirent *dirent)
{
	if (dirent->d_type != DT_DIR)
		return false;

	if (dirent->d_name[0] <= '0' || dirent->d_name[0] > '9')
		return false;

	return true;
}

static int
scandir_sort(const struct dirent **a, const struct dirent **b)
{
	return 0;
}

static pid_t
read_procs(const char *name)
{
	struct dirent **namelist;
	struct dirent **ent_p;
	struct dirent *ent;
	int ret;

	ret = scandir("/proc", &namelist, scandir_filter, scandir_sort);
	log_message(LOG_INFO, "scandir returned %d\n", ret);

	for (ent_p = namelist, ent = *namelist; ret--; ent = *++ent_p) {
		log_message(LOG_INFO, "0x%p: %s\n", ent, ent->d_name);
		free(ent);	/* malloc'd by scandir() */
	}

	free(namelist);	/* malloc'd by scandir() */
}
#endif

static bool
check_params(vrrp_tracked_process_t *tpr, const char *params, size_t params_len)
{
	if (tpr->param_match == PARAM_MATCH_EXACT &&
	    !tpr->process_params &&
	    params_len == 0)
		return true;

	if (params_len < tpr->process_params_len)
		return false;

	if (tpr->param_match == PARAM_MATCH_EXACT)
		return (params_len == tpr->process_params_len &&
			(!tpr->process_params ||
			 !memcmp(params, tpr->process_params, tpr->process_params_len)));

	if (!tpr->process_params)
		return true;

	if (tpr->param_match == PARAM_MATCH_PARTIAL)
		return !memcmp(params, tpr->process_params, tpr->process_params_len);

	/* tpr->param_match == PARAM_MATCH_INITIAL */
	return tpr->process_params_len == 1 ||
	       !memcmp(params, tpr->process_params, tpr->process_params_len - 1);
}

static void
read_procs(list_head_t *processes)
{
	/* /proc/PID/status has line State: which can be Z for zombie process (but cmdline is empty then)
	 * /proc/PID/stat has cmd name as 2nd field in (), and state as third field. For states see
	 * man proc(5)
	 * pgrep uses status and cmdline files. Without -f, pgrep looks at comm (in status/stat/comm). If
	 * -f is specified, it reads cmdline.
	 * To change comm for a process, use prctl(PR_SET_NAME). */
	DIR *proc_dir = opendir("/proc");
	struct dirent *ent;
	char cmdline[1 + 4 + 1 + PID_MAX_DIGITS + 1 + 7 + 1];	/* "/proc/xxxxxxx/cmdline" */
	int fd;
	char *cmd_buf;
	size_t cmd_buf_len;
	char stat_buf[128];
	char *p;
	char *comm;
	ssize_t len = 0;
	ssize_t cmdline_len = 0;
	char *proc_name;
	vrrp_tracked_process_t *tpr;
	const char *param_start;

	cmd_buf_len = vrrp_data->vrrp_max_process_name_len + 2;
	cmd_buf = MALLOC(cmd_buf_len);

	while ((ent = readdir(proc_dir))) {
		if (ent->d_type != DT_DIR)
			continue;
		if (ent->d_name[0] <= '0' || ent->d_name[0] > '9')
			continue;

		/* We want to avoid reading /proc/PID/cmdline, since it reads the process
		 * address space, and if the process is swapped out, then it will have to be
		 * swapped in to read it. */
		if (vrrp_data->vrrp_use_process_cmdline) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%.*s/cmdline", PID_MAX_DIGITS, ent->d_name);

			if ((fd = open(cmdline, O_RDONLY)) == -1)
				continue;

			/* Read max name len + null byte + 1 extra char */
			cmdline_len = read(fd, cmd_buf, vrrp_data->vrrp_max_process_name_len + 1);
			close(fd);
			if (cmdline_len < 0)
				continue;
			cmd_buf[cmdline_len] = '\0';
		}

		if (vrrp_data->vrrp_use_process_comm) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%.*s/stat", PID_MAX_DIGITS, ent->d_name);

			if ((fd = open(cmdline, O_RDONLY)) == -1)
				continue;

			len = read(fd, stat_buf, sizeof(stat_buf) - 1);
			close(fd);
			if (len < 0)
				continue;
			stat_buf[len] = '\0';
			if (len && stat_buf[len-1] == '\n')
				stat_buf[len - 1] = '\0';

			/* Find the comm field, terminate it and check not a zombie process */
			p = strchr(stat_buf + 2, '(');
			if (!p)
				continue;

			comm = p + 1;
			p = strchr(p, ')');
			if (!p)
				continue;
			*p = '\0';
			if (p[2] == 'Z')
				continue;
		}
		else
			comm = NULL;	/* Avoid compiler warning */

		list_for_each_entry(tpr, processes, e_list) {
			if (tpr->full_command)
				proc_name = cmd_buf;
			else if (comm)
				proc_name = comm;
			else /* This should never happen, but coverity produces a "Explicit null dereference" error */
				continue;

			if (!strcmp(proc_name, tpr->process_path)) {
				/* We have got a match */

				/* Do we need to check parameters? */
				if (tpr->param_match != PARAM_MATCH_NONE) {
					param_start = proc_name + strlen(proc_name) + 1;
					if (!check_params(tpr, param_start, proc_name + cmdline_len - param_start))
						continue;
				}

				add_process(atoi(ent->d_name), tpr, NULL);
			}
		}
	}

	closedir(proc_dir);
	FREE(cmd_buf);
}

static void
update_process_status(vrrp_tracked_process_t *tpr, bool now_up)
{
	if (now_up == tpr->have_quorum) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "update process status no change for %s", tpr->pname);
#endif
		return;
	}

	tpr->have_quorum = now_up;

	process_update_track_process_status(tpr, now_up);
}

static void
remove_process_from_track(tracked_process_instance_t *tpi, vrrp_tracked_process_t *tpr)
{
	ref_tracked_process_t *rtpr, *rtpr_tmp;

	list_for_each_entry_safe(rtpr, rtpr_tmp, &tpi->processes, e_list) {
		if (rtpr->process == tpr) {
			free_ref_tracked_process(rtpr);
			if (tpr->num_cur_proc-- == tpr->quorum ||
			    tpr->num_cur_proc == tpr->quorum_max) {
				if (tpr->fork_timer_thread) {
					thread_cancel(tpr->fork_timer_thread);
					tpr->fork_timer_thread = NULL;
				}
				update_process_status(tpr, tpr->num_cur_proc == tpr->quorum_max);
			}
			return;
		}
	}
}

static void
check_process(pid_t pid, char *comm, tracked_process_instance_t *tpi)
{
	char cmdline[1 + 4 + 1 + PID_MAX_DIGITS + 1 + 7 + 1];	/* "/proc/xxxxxxx/{cmdline,comm}" */
	int fd;
	char *cmd_buf = NULL;
	size_t cmd_buf_len;
	char comm_buf[17];
	ssize_t len = 0;
	ssize_t cmdline_len = 0;
	char *proc_name;
	const char *param_start;
	vrrp_tracked_process_t *tpr;
	bool had_process;
	tracked_process_instance_t tp = { .pid = pid };
	bool have_comm = !!comm;
#ifdef _TRACK_PROCESS_DEBUG_
	int sav_errno;
#endif

	/* Are we counting this process now? */
	if (!tpi)
		tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);
	had_process = !!tpi;

	/* We want to avoid reading /proc/PID/cmdline, since it reads the process
	 * address space, and if the process is swapped out, then it will have to be
	 * swapped in to read it. */
	if (!have_comm) {
		if (vrrp_data->vrrp_use_process_cmdline) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);

			if ((fd = open(cmdline, O_RDONLY)) == -1) {
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "check_process failed to open %s, errno %d", cmdline, errno);
#endif
				return;
			}

			cmd_buf_len = vrrp_data->vrrp_max_process_name_len + 3;
			cmd_buf = MALLOC(cmd_buf_len);
			cmdline_len = read(fd, cmd_buf, vrrp_data->vrrp_max_process_name_len + 2);
#ifdef _TRACK_PROCESS_DEBUG_
			sav_errno = errno;
#endif
			close(fd);
			if (cmdline_len < 0) {
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "check_process failed to read %s, errno %d", cmdline, sav_errno);
#endif
				FREE(cmd_buf);
				return;
			}
			cmd_buf[cmdline_len] = '\0';
		}

		if (vrrp_data->vrrp_use_process_comm) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%d/comm", pid);

			if ((fd = open(cmdline, O_RDONLY)) == -1) {
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "check_process failed to open %s, errno %d", cmdline, errno);
#endif
				FREE_PTR(cmd_buf);
				return;
			}

			len = read(fd, comm_buf, sizeof(comm_buf) - 1);
#ifdef _TRACK_PROCESS_DEBUG_
			sav_errno = errno;
#endif
			close(fd);
			if (len < 0) {
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "check_process failed to read %s, errno %d", cmdline, sav_errno);
#endif
				FREE_PTR(cmd_buf);
				return;
			}
			comm_buf[len] = '\0';
			if (len && comm_buf[len-1] == '\n')
				comm_buf[len-1] = '\0';
			comm = comm_buf;
		}
	}

#ifdef _TRACK_PROCESS_DEBUG_
	if (do_track_process_debug_detail)
		log_message(LOG_INFO, "check_process %s (cmdline %s)", comm, cmd_buf ? cmd_buf : "[none]");
#endif

	list_for_each_entry(tpr, &vrrp_data->vrrp_track_processes, e_list) {
		if (tpr->full_command) {
			/* If this is a PROC_EVENT_COMM, we aren't dealing with the command line */
			if (have_comm)
				continue;
			proc_name = cmd_buf;
		} else if (comm)
			proc_name = comm;
		else /* This should never happen, but coverity produces a "Dereference after null check" error */
			continue;

		if (!strcmp(proc_name, tpr->process_path)) {
			/* We have got a match */

			/* Do we need to check parameters? */
			if (tpr->param_match != PARAM_MATCH_NONE) {
				param_start = proc_name + strlen(proc_name) + 1;
				if (!check_params(tpr, param_start, proc_name + cmdline_len - param_start)) {
#ifdef _TRACK_PROCESS_DEBUG_
					if (do_track_process_debug_detail)
						log_message(LOG_INFO, "check_process parameter mis-match");
#endif
					if (had_process)
						remove_process_from_track(tpi, tpr);
					continue;
				}
			}

			tpi = add_process(pid, tpr, tpi);

#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug_detail)
				log_message(LOG_INFO, "check_process adding process %d to %s", pid, tpr->pname);
#endif

			if (tpr->num_cur_proc == tpr->quorum ||
			    tpr->num_cur_proc == tpr->quorum_max + 1) {
				/* Cancel terminate timer thread if any, otherwise update status */
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "check_process %s num_proc now %u, quorum [%u:%u]", tpr->pname, tpr->num_cur_proc, tpr->quorum, tpr->quorum_max);
#endif

				if (tpr->terminate_timer_thread) {
					thread_cancel(tpr->terminate_timer_thread);
					tpr->terminate_timer_thread = NULL;
				}
				update_process_status(tpr, tpr->num_cur_proc == tpr->quorum);
			}
		}
		else if (had_process && !have_comm) {
#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug_detail)
				log_message(LOG_INFO, "check_process removing %d from %s", pid, tpr->pname);
#endif
			remove_process_from_track(tpi, tpr);
		}
	}

	FREE_PTR(cmd_buf);

	if (!tpi)
		return;

	/* If we were monitoring the process, and are no longer,
	 * remove it */
	if (list_empty(&tpi->processes))
		free_tracked_process_instance(tpi);
}

static void
process_gained_quorum_timer_thread(thread_ref_t thread)
{
	vrrp_tracked_process_t *tpr = thread->arg;

#ifdef _TRACK_PROCESS_DEBUG_
	if (do_track_process_debug_detail)
		log_message(LOG_INFO, "quorum gained timer for %s expired", tpr->pname);
#endif

	update_process_status(tpr,
			      tpr->num_cur_proc >= tpr->quorum &&
			      tpr->num_cur_proc <= tpr->quorum_max);
	tpr->fork_timer_thread = NULL;
}

static void
check_process_fork(pid_t parent_pid, pid_t child_pid)
{
	tracked_process_instance_t tp = { .pid = parent_pid };
	tracked_process_instance_t *tpi, *tpi_child;
	vrrp_tracked_process_t *tpr;
	ref_tracked_process_t *rtpr;

	/* If we aren't interested in the parent, we aren't interested in the child */
	if (!(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare))) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Ignoring fork for untracked pid %d", parent_pid);
#endif
		return;
	}

	tpi_child = alloc_tracked_process_instance(child_pid);
#ifdef _TRACK_PROCESS_DEBUG_
	if (do_track_process_debug_detail)
		log_message(LOG_INFO, "Adding new child %d of parent %d", child_pid, parent_pid);
#endif

	list_for_each_entry(rtpr, &tpi->processes, e_list) {
		tpr = rtpr->process;

#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Adding new child %d to track_process %s", child_pid, tpr->pname);
#endif

		/* Add a new reference */
		alloc_ref_tracked_process(tpr, tpi_child);
		if (++tpr->num_cur_proc == tpr->quorum ||
		    tpr->num_cur_proc == tpr->quorum_max + 1) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "track_process %s num_proc now %u, quorum [%u:%u]", tpr->pname, tpr->num_cur_proc, tpr->quorum, tpr->quorum_max);
#endif
			if (tpr->terminate_timer_thread) {
				thread_cancel(tpr->terminate_timer_thread);	// Cancel terminate timer
				tpr->terminate_timer_thread = NULL;
			} else if (tpr->fork_delay) {
				tpr->fork_timer_thread = thread_add_timer(master, process_gained_quorum_timer_thread, tpr, tpr->fork_delay);
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Adding timer %d for %s up", tpr->fork_delay, tpr->pname);
#endif
				continue;
			}
			update_process_status(tpr, tpr->num_cur_proc == tpr->quorum);
		}
	}
}

static void
process_lost_quorum_timer_thread(thread_ref_t thread)
{
	vrrp_tracked_process_t *tpr = thread->arg;

#ifdef _TRACK_PROCESS_DEBUG_
	if (do_track_process_debug_detail)
		log_message(LOG_INFO, "quorum lost timer for %s expired", tpr->pname);
#endif

	update_process_status(tpr,
			      tpr->num_cur_proc >= tpr->quorum &&
			      tpr->num_cur_proc <= tpr->quorum_max);
	tpr->terminate_timer_thread = NULL;
}

static void
check_process_termination(pid_t pid)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;
	vrrp_tracked_process_t *tpr;
	ref_tracked_process_t *rtpr;

	tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);
	if (!tpi) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Ignoring exit of untracked pid %d", pid);
#endif
		return;
	}

	list_for_each_entry(rtpr, &tpi->processes, e_list) {
		tpr = rtpr->process;

		if (tpr->num_cur_proc-- == tpr->quorum ||
		    tpr->num_cur_proc == tpr->quorum_max) {
#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug_detail)
				log_message(LOG_INFO, "process exit %s num_proc now %u, quorum [%u:%u]", tpr->pname, tpr->num_cur_proc, tpr->quorum, tpr->quorum_max);
#endif
			if (tpr->fork_timer_thread) {
				thread_cancel(tpr->fork_timer_thread);	// Cancel fork timer
				tpr->fork_timer_thread = NULL;
			} else if (tpr->terminate_delay) {
				tpr->terminate_timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->terminate_delay);
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Adding timer %d for %s termination", tpr->fork_delay, tpr->pname);
#endif
				continue;
			}
			update_process_status(tpr, tpr->num_cur_proc == tpr->quorum_max);
		}
	}

	free_tracked_process_instance(tpi);
}

static void
check_process_comm_change(pid_t pid, char *comm)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;
	vrrp_tracked_process_t *tpr;
	ref_tracked_process_t *rtpr, *rtpr_tmp;

	tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);
	if (!tpi) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "comm_change pid %d not found", pid);
#endif
		goto end;
	}

	/* The process was being monitored by its old name */
	list_for_each_entry_safe(rtpr, rtpr_tmp, &tpi->processes, e_list) {
		tpr = rtpr->process;

		if (tpr->full_command)
			continue;

		/* Check that the name really has changed */
		if (!strcmp(comm, tpr->process_path))
			return;

#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "comm change remove pid %d", pid);
#endif
		free_ref_tracked_process(rtpr);
		if (tpr->num_cur_proc-- == tpr->quorum ||
		    tpr->num_cur_proc == tpr->quorum_max) {
#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug_detail)
				log_message(LOG_INFO, "comm change %s num_proc now %u, quorum [%u:%u]"
						    , tpr->pname, tpr->num_cur_proc
						    , tpr->quorum, tpr->quorum_max);
#endif
			if (tpr->fork_timer_thread) {
				thread_cancel(tpr->fork_timer_thread);	// Cancel fork timer
				tpr->fork_timer_thread = NULL;
			}
			update_process_status(tpr, tpr->num_cur_proc == tpr->quorum_max);
		}
	}

  end:
	/* Handle the new process name */
	check_process(pid, comm, tpi);
}

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int
nl_connect(void)
{
	int rc;
	int nl_sd;
	struct sockaddr_nl sa_nl;

	nl_sd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_CONNECTOR);
	if (nl_sd == -1) {
		if (errno == EPROTONOSUPPORT) {
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "track_process not available - is CONFIG_PROC_EVENTS enabled in kernel config?");
			proc_events_not_supported = true;
		} else
			log_message(LOG_INFO, "Failed to open process monitoring socket - errno %d - %m", errno);
		return -1;
	}

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	rc = bind(nl_sd, PTR_CAST(struct sockaddr, &sa_nl), sizeof(sa_nl));
	if (rc == -1) {
		log_message(LOG_INFO, "Failed to bind to process monitoring socket - errno %d - %m", errno);
		close(nl_sd);
		return -1;
	}

	return nl_sd;
}

/*
 * subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sd, bool enable)
{
	int rc;
	struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
		struct nlmsghdr nl_hdr;
		struct __attribute__ ((__packed__)) {
			struct cn_msg cn_msg;
			enum proc_cn_mcast_op cn_mcast;
		};
	} nlcn_msg;

	memset(&nlcn_msg, 0, sizeof(nlcn_msg));
	nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
	nlcn_msg.nl_hdr.nlmsg_pid = getpid();
	nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

	nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
	nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
	nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

	nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

	rc = send(nl_sd, &nlcn_msg, sizeof(nlcn_msg), 0);
	if (rc == -1) {
		log_message(LOG_INFO, "Failed to set/clear process event listen - errno %d - %m", errno);
		return -1;
	}

	return 0;
}

static void
reinitialise_track_processes(void)
{
	reload_thread = NULL;
	unsigned buf_size;
	socklen_t buf_size_len = sizeof(buf_size);
	unsigned i;
	vrrp_tracked_process_t *tpr;

	need_reinitialise = false;

	if (getsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, &buf_size_len) < 0) {
		log_message(LOG_INFO, "Cannot get process monitor SO_RCVBUF option. errno=%d (%m)", errno);
		return;
	}

	buf_size *= 2;
	set_rcv_buf(buf_size, global_data->process_monitor_rcv_bufs_force);

	log_message(LOG_INFO, "Setting global_def process_monitor_rcv_bufs to %u"
			      " - recommend updating configuration file"
			    , buf_size);

	/* Reset the sequence numbers */
	for (i = 0; i < num_cpus; i++)
		cpu_seq[i] = -1;

	/* Remove the existing process tree */
	free_process_tree();

	/* Save process counters, and clear any down timers */
	list_for_each_entry(tpr, &vrrp_data->vrrp_track_processes, e_list) {
		tpr->sav_num_cur_proc = tpr->num_cur_proc;
		tpr->num_cur_proc = 0;
		if (tpr->fork_timer_thread) {
			thread_cancel(tpr->fork_timer_thread);
			tpr->fork_timer_thread = NULL;
		}
		if (tpr->terminate_timer_thread) {
			thread_cancel(tpr->terminate_timer_thread);
			tpr->terminate_timer_thread = NULL;
		}
	}

	/* Re read processes */
	read_procs(&vrrp_data->vrrp_track_processes);

	/* See if anything changed */
	list_for_each_entry(tpr, &vrrp_data->vrrp_track_processes, e_list) {
		if (tpr->sav_num_cur_proc != tpr->num_cur_proc) {
			if ((tpr->sav_num_cur_proc < tpr->quorum) == (tpr->num_cur_proc < tpr->quorum) &&
			    (tpr->sav_num_cur_proc > tpr->quorum_max) == (tpr->num_cur_proc > tpr->quorum_max)) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed"
							      " from %u to %u"
							    , tpr->pname
							    , tpr->sav_num_cur_proc
							    , tpr->num_cur_proc);
				continue;
			}
			if (tpr->num_cur_proc >= tpr->quorum &&
			    tpr->num_cur_proc <= tpr->quorum_max) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed"
							      " from %u to %u, quorum up"
							    , tpr->pname
							    , tpr->sav_num_cur_proc
							    , tpr->num_cur_proc);
				if (tpr->fork_delay)
					tpr->fork_timer_thread = thread_add_timer(master, process_gained_quorum_timer_thread, tpr, tpr->terminate_delay);
				process_update_track_process_status(tpr, true);
			} else {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed"
							      " from %u to %u, quorum down"
							    , tpr->pname
							    , tpr->sav_num_cur_proc
							    , tpr->num_cur_proc);
				if (tpr->terminate_delay)
					tpr->terminate_timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->terminate_delay);
				else
					process_update_track_process_status(tpr, false);
			}
		}
	}

	return;
}

static void
process_lost_messages_timer_thread(__attribute__((unused)) thread_ref_t thread)
{
	reinitialise_track_processes();
}

/*
 * handle a single process event
 *
 * There is a ?design bug in the kernel. struct proc_event has 8 byte alignment,
 * but struct nlmsghdr is 16 bytes long, the payload is then 4 byte aligned, which
 * starts with a struct cn_msg which is 20 bytes long and is immediately followed by
 * the struct proc_event. This means that if the buffer for the data is 8 byte
 * aligned, then proc_event ends up 4 byte aligned but NOT 8 byte aligned.
 *
 * A consequence of the above is that there cannot be multiple chained netlink
 * messages in one receive block, since if the first proc_event is 8 byte aligned,
 * the second one will not be 8 byte aligned.
 *
 * The kernel, in drivers/connector/cn_proc.c, allocates an 8 byte aligned buffer
 * and then start building the packet at a 4 byte offset into the buffer in order
 * to work around the problem.
 *
 * The normal approach of a loop for receiving netlink messages:
 *
 * for (nlmsghdr = (struct nlmsghdr *)buf;
 *      NLMSG_OK (nlmsghdr, len); nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {
 *
 * will not work while maintaining 8 byte alignment of the proc_event structures.
 * However, the kernel does not send chained proc_event messages currently, and can't
 * without the alignment problem being resolved, so it should be safe to rely on that.
 *
 * For receiving, we can either use the kernel's approach of allocating an 8 byte
 * aligned buffer and receive at an offset of 4 bytes, or alternatively, as we have
 * chosen to do, use a scatter read.
 *
 */
static int
handle_proc_ev(int nl_sd)
{
	ssize_t len;
	struct sockaddr_nl addr;
	union nlmsghdr_alignment {
		struct nlmsghdr nlmsghdr;
		char dummy[NLMSG_ALIGN(sizeof(struct nlmsghdr))];
	} u;
	struct cn_msg cn_msg;
	struct proc_event proc_ev;
	struct iovec iov[3] = { { &u, sizeof(u) },
				{ &cn_msg, sizeof(struct cn_msg) },
				{ &proc_ev, sizeof(struct proc_event) } };
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 3 };

	msg.msg_name = &addr;
	while (msg.msg_namelen = sizeof(addr), (len = recvmsg(nl_sd, &msg, 0))) {
		if (len == -1) {
			if (check_EINTR(errno))
				continue;
			if (check_EAGAIN(errno))
				return 0;

			if (errno == ENOBUFS) {
				/* We have missed some messages. Allow time for
				 * things to settle down, and reinitialise. */
				if (reload_thread)
					thread_cancel(reload_thread);
				reload_thread = thread_add_timer(master, process_lost_messages_timer_thread, NULL, TIMER_HZ);
				need_reinitialise = true;
			}
			else
				log_message(LOG_INFO, "process monitor netlink recv error %d - %m", errno);

			return -1;
		}

		/* Ensure the message has been sent by the kernel */
		if (msg.msg_namelen != sizeof(addr) || addr.nl_pid != 0) {
			log_message(LOG_INFO, "addrlen %u, expect %zu, pid %u", msg.msg_namelen, sizeof addr, addr.nl_pid);
			return -1;
		}

		if (!NLMSG_OK (&u.nlmsghdr, len)) {
			log_message(LOG_INFO, "proc_event !NLMSG_OK");
			return -1;
		}

		if (u.nlmsghdr.nlmsg_type == NLMSG_ERROR ||
		    u.nlmsghdr.nlmsg_type == NLMSG_NOOP)
			continue;

		if (cn_msg.id.idx != CN_IDX_PROC ||
		    cn_msg.id.val != CN_VAL_PROC)
			continue;

		/* On 3.10 kernel, proc_ev->cpu can be UINT32_MAX */
		if (proc_ev.cpu >= num_cpus)
			continue;

		/* PROC_EVENT_NONE is an ack, otherwise not an ack */
		if ((proc_ev.what == PROC_EVENT_NONE) != cn_msg.ack)
			continue;

		if (cpu_seq) {
			if ((!need_reinitialise || __test_bit(LOG_DETAIL_BIT, &debug)) &&
			    cpu_seq[proc_ev.cpu] != -1 &&
			    !(cpu_seq[proc_ev.cpu] + 1 == cn_msg.seq ||
			      (cn_msg.seq == 0 && cpu_seq[proc_ev.cpu] == UINT32_MAX)))
				log_message(LOG_INFO, "Missed %" PRIi64 " messages on CPU %u", cn_msg.seq - cpu_seq[proc_ev.cpu] - 1, proc_ev.cpu);

			cpu_seq[proc_ev.cpu] = cn_msg.seq;
		}

#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug) {
			switch (proc_ev.what)
			{
			case PROC_EVENT_NONE:
				log_message(LOG_INFO, "set mcast listen ok");
				break;
			case PROC_EVENT_FORK:
				/* See if we have parent pid, in which case this is a new process */
				log_message(LOG_INFO, "fork: parent tid=%d pid=%d -> child tid=%d pid=%d",
						proc_ev.event_data.fork.parent_pid,
						proc_ev.event_data.fork.parent_tgid,
						proc_ev.event_data.fork.child_pid,
						proc_ev.event_data.fork.child_tgid);
				break;
			case PROC_EVENT_EXEC:
				log_message(LOG_INFO, "exec: tid=%d pid=%d",
						proc_ev.event_data.exec.process_pid,
						proc_ev.event_data.exec.process_tgid);
				break;
			case PROC_EVENT_UID:
				log_message(LOG_INFO, "uid change: tid=%d pid=%d from %" PRIu32 " to %" PRIu32,
						proc_ev.event_data.id.process_pid,
						proc_ev.event_data.id.process_tgid,
						proc_ev.event_data.id.r.ruid,
						proc_ev.event_data.id.e.euid);
				break;
			case PROC_EVENT_GID:
				log_message(LOG_INFO, "gid change: tid=%d pid=%d from %" PRIu32 " to %" PRIu32,
						proc_ev.event_data.id.process_pid,
						proc_ev.event_data.id.process_tgid,
						proc_ev.event_data.id.r.rgid,
						proc_ev.event_data.id.e.egid);
				break;
			case PROC_EVENT_SID:
				log_message(LOG_INFO, "sid change: tid=%d pid=%d",
						proc_ev.event_data.sid.process_pid,
						proc_ev.event_data.sid.process_tgid);
				break;
			case PROC_EVENT_PTRACE:
				log_message(LOG_INFO, "ptrace change: tid=%d pid=%d tracer tid=%d, pid=%d",
						proc_ev.event_data.ptrace.process_pid,
						proc_ev.event_data.ptrace.process_tgid,
						proc_ev.event_data.ptrace.tracer_pid,
						proc_ev.event_data.ptrace.tracer_tgid);
				break;
			case PROC_EVENT_COMM:
				log_message(LOG_INFO, "comm: tid=%d pid=%d comm %s",
						proc_ev.event_data.comm.process_pid,
						proc_ev.event_data.comm.process_tgid,
						proc_ev.event_data.comm.comm);
				break;
			case PROC_EVENT_COREDUMP:
				log_message(LOG_INFO, "coredump: tid=%d pid=%d",
						proc_ev.event_data.coredump.process_pid,
						proc_ev.event_data.coredump.process_tgid);
				break;
			case PROC_EVENT_EXIT:
				log_message(LOG_INFO, "exit: tid=%d pid=%d exit_code=%u, signal=%u,",
						proc_ev.event_data.exit.process_pid,
						proc_ev.event_data.exit.process_tgid,
						proc_ev.event_data.exit.exit_code,
						proc_ev.event_data.exit.exit_signal);
				break;
			default:
				log_message(LOG_INFO, "unhandled proc event %u", proc_ev.what);
				break;
			}
		}
#endif

		switch (proc_ev.what)
		{
		case PROC_EVENT_NONE:
			proc_events_responded = true;
			if (__test_bit(LOG_DETAIL_BIT, &debug))
				log_message(LOG_INFO, "proc_events has confirmed it is configured");
			break;
		case PROC_EVENT_FORK:
			/* See if we have parent pid, in which case this is a new process.
			 * For a process fork, child_pid == child_tgid.
			 * For a new thread, child_pid != child_tgid and parent_pid/tgid is
			 * the parent process of the process doing the pthread_create(). */
			if (proc_ev.event_data.fork.child_tgid == proc_ev.event_data.fork.child_pid)
				check_process_fork(proc_ev.event_data.fork.parent_tgid, proc_ev.event_data.fork.child_tgid);
#ifdef _TRACK_PROCESS_DEBUG_
			else if (do_track_process_debug_detail)
				log_message(LOG_INFO, "Ignoring new thread %d for pid %d", proc_ev.event_data.fork.child_tgid, proc_ev.event_data.fork.child_pid);
#endif
			break;
		case PROC_EVENT_EXEC:
			/* We may be losing a process. Check if have pid, and check new cmdline */
			if (proc_ev.event_data.exec.process_tgid == proc_ev.event_data.exec.process_pid)
				check_process(proc_ev.event_data.exec.process_tgid, NULL, NULL);
#ifdef _TRACK_PROCESS_DEBUG_
			else if (do_track_process_debug_detail)
				log_message(LOG_INFO, "Ignoring exec of thread %d of pid %d", proc_ev.event_data.exec.process_tgid, proc_ev.event_data.exec.process_pid);
#endif
			break;
		case PROC_EVENT_COMM:
			if (proc_ev.event_data.comm.process_tgid == proc_ev.event_data.comm.process_pid)
				check_process_comm_change(proc_ev.event_data.comm.process_tgid, proc_ev.event_data.comm.comm);
#ifdef _TRACK_PROCESS_DEBUG_
			else if (do_track_process_debug_detail)
				log_message(LOG_INFO, "Ignoring COMM event of thread %d of pid %d", proc_ev.event_data.comm.process_tgid, proc_ev.event_data.comm.process_pid);
#endif
			break;
		case PROC_EVENT_EXIT:
			/* We aren't interested in thread termination */
			if (proc_ev.event_data.exit.process_tgid == proc_ev.event_data.exit.process_pid)
				check_process_termination(proc_ev.event_data.exit.process_tgid);
#ifdef _TRACK_PROCESS_DEBUG_
			else if (do_track_process_debug_detail)
				log_message(LOG_INFO, "Ignoring exit of thread %d of pid %d", proc_ev.event_data.exit.process_tgid, proc_ev.event_data.exit.process_pid);
#endif
			break;
		default:
			break;
		}

#ifdef CHECK_ONLY_ONE_NLMSG
		struct nlmsghdr *next_nlh = NLMSG_NEXT(&u.nlmsghdr, len);
		if (NLMSG_OK(next_nlh, len))
			log_message(LOG_INFO, "NLMSG_OK(next_nlh, len)) returns yes");
#endif
	}

	if (len == 0)
		log_message(LOG_INFO, "proc_event recvmsg returned 0");

	return 0;
}

static void
read_process_update(thread_ref_t thread)
{
	handle_proc_ev(thread->u.f.fd);

	read_thread = thread_add_read(thread->master, read_process_update, NULL, thread->u.f.fd, TIMER_NEVER, 0);
}

static void
proc_events_ack_timer_thread(__attribute__((unused)) thread_ref_t thread)
{
	if (!proc_events_responded)
		log_message(LOG_INFO, "WARNING - the kernel does not support proc events - track_process will not work");
}

bool
open_track_processes(void)
{
	nl_sock = nl_connect();
	if (nl_sock == -1)
		return true ;

	return false;
}

bool
close_track_processes(void)
{
	if (nl_sock == -1)
		return true;

	close(nl_sock);

	nl_sock = -1;

	return false;
}

bool
init_track_processes(list_head_t *processes)
{
	int rc = EXIT_SUCCESS;
	unsigned i;
	long num;

	if (global_data->process_monitor_rcv_bufs)
		set_rcv_buf(global_data->process_monitor_rcv_bufs, global_data->process_monitor_rcv_bufs_force);

	rc = set_proc_ev_listen(nl_sock, true);
	if (rc == -1) {
		close(nl_sock);
		nl_sock = -1;
		return EXIT_FAILURE;
	}

	/* We get a PROC_EVENT_NONE if the proc_events_connector is built
	 * into the kernel. We have to timeout not receiving a message to
	 * know that proc evnets are not available. */
	if (!proc_events_responded)
		thread_add_timer(master, proc_events_ack_timer_thread, NULL, TIMER_HZ / 10);

	if (!cpu_seq) {
		/* should we consider only ONLINE CPU ? */
		num = sysconf(_SC_NPROCESSORS_CONF);
		if (num > 0) {
			num_cpus = num;
			cpu_seq = MALLOC(num_cpus * sizeof(*cpu_seq));
			for (i = 0; i < num_cpus; i++)
				cpu_seq[i] = -1;
		}
		else
			log_message(LOG_INFO, "sysconf returned %ld CPUs"
					      " - ignoring and won't track process event sequence numbers"
					    , num);
	}

	read_procs(processes);

	read_thread = thread_add_read(master, read_process_update, NULL, nl_sock, TIMER_NEVER, 0);

	return rc;
}

void
reload_track_processes(void)
{
	/* Remove the existing process tree */
	free_process_tree();

	/* Re read processes */
	read_procs(&vrrp_data->vrrp_track_processes);

	/* Add read thread */
	read_thread = thread_add_read(master, read_process_update, NULL, nl_sock, TIMER_NEVER, 0);

	return;
}

void
end_process_monitor(void)
{
	vrrp_tracked_process_t *tpr;

	if (!cpu_seq)
		return;

	if (nl_sock != -1) {
		set_proc_ev_listen(nl_sock, false);

		if (read_thread) {
			thread_cancel(read_thread);
			read_thread = NULL;
		}

		close(nl_sock);
		nl_sock = -1;
	}

	FREE_PTR(cpu_seq);

	/* Cancel any timer threads */
	list_for_each_entry(tpr, &vrrp_data->vrrp_track_processes, e_list) {
		if (tpr->fork_timer_thread) {
			thread_cancel(tpr->fork_timer_thread);
			tpr->fork_timer_thread = NULL;
		}
		if (tpr->terminate_timer_thread) {
			thread_cancel(tpr->terminate_timer_thread);
			tpr->terminate_timer_thread = NULL;
		}
	}

	/* Remove the existing process tree */
	free_process_tree();
}

#ifdef THREAD_DUMP
void
register_process_monitor_addresses(void)
{
	register_thread_address("process_lost_quorum", process_lost_quorum_timer_thread);
	register_thread_address("process_lost_messages", process_lost_messages_timer_thread);
	register_thread_address("read_process_update", read_process_update);
	register_thread_address("proc_events_ack_timer", proc_events_ack_timer_thread);
}
#endif
