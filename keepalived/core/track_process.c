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
#include "list.h"
#if !HAVE_DECL_SOCK_NONBLOCK
#include "old_socket.h"
#endif
#include "rbtree.h"
#include "vrrp_data.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "main.h"


static thread_ref_t read_thread;
static thread_ref_t reload_thread;
static rb_root_t process_tree = RB_ROOT;
static int nl_sock = -1;
static unsigned num_cpus;
static int64_t *cpu_seq;
static bool need_reinitialise;
bool proc_events_not_supported;

#ifdef _TRACK_PROCESS_DEBUG_
bool do_track_process_debug;
bool do_track_process_debug_detail;
#endif

static void
set_rcv_buf(unsigned buf_size, bool force)
{
	if (setsockopt(nl_sock, SOL_SOCKET, force ? SO_RCVBUFFORCE : SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0)
		log_message(LOG_INFO, "Cannot set process monitor SO_RCVBUF%s option. errno=%d (%m)", force ? "FORCE" : "", errno);
}

static int
pid_compare(const tracked_process_instance_t *tpi1, const tracked_process_instance_t *tpi2)
{
	return tpi1->pid - tpi2->pid;
}

static inline tracked_process_instance_t *
add_process(pid_t pid, vrrp_tracked_process_t *tpr, tracked_process_instance_t *tpi)
{
	tracked_process_instance_t tp = { .pid = pid };

	if (!tpi && !(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare))) {
		PMALLOC(tpi);
		tpi->pid = tp.pid;
		tpi->processes = alloc_list(NULL, NULL);
		RB_CLEAR_NODE(&tpi->pid_tree);
		rb_insert_sort(&process_tree, tpi, pid_tree, pid_compare);
	}

	list_add(tpi->processes, tpr);
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
		free(ent);
	}

	free(namelist);
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
read_procs(list processes)
{
	/* /proc/PID/status has line State: which can be Z for zombie process (but cmdline is empty then)
	 * /proc/PID/stat has cmd name as 2nd field in (), and state as third field. For states see
	 * man proc(5)
	 * pgrep uses status and cmdline files. Without -f, pgrep looks at comm (in status/stat/comm). If
	 * -f is specified, it reads cmdline.
	 * To change comm for a process, use prctl(PR_SET_NAME). */
	DIR *proc_dir = opendir("/proc");
	struct dirent *ent;
	char cmdline[22];	/* "/proc/xxxxxxx/cmdline" */
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
	element e;
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
			snprintf(cmdline, sizeof(cmdline), "/proc/%.7s/cmdline", ent->d_name);

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
			snprintf(cmdline, sizeof(cmdline), "/proc/%.7s/stat", ent->d_name);

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

		LIST_FOREACH(processes, tpr, e) {
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
	vrrp_tracked_process_t *proc;
	element e;

	LIST_FOREACH(tpi->processes, proc, e) {
		if (proc == tpr) {
			free_list_element(tpi->processes, e);
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
	char cmdline[22];	/* "/proc/xxxxxxx/cmdline" */
	int fd;
	char *cmd_buf = NULL;
	size_t cmd_buf_len;
	char comm_buf[17];
	ssize_t len = 0;
	ssize_t cmdline_len = 0;
	char *proc_name;
	const char *param_start;
	vrrp_tracked_process_t *tpr;
	element e;
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

	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
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
	if (LIST_ISEMPTY(tpi->processes)) {
		free_list(&tpi->processes);
		rb_erase(&tpi->pid_tree, &process_tree);
		FREE(tpi);
	}
}

static int
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

	return 0;
}

static void
check_process_fork(pid_t parent_pid, pid_t child_pid)
{
	tracked_process_instance_t tp = { .pid = parent_pid };
	tracked_process_instance_t *tpi, *tpi_child;
	vrrp_tracked_process_t *tpr;
	element e;

	/* If we aren't interested in the parent, we aren't interested in the child */
	if (!(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare))) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Ignoring fork for untracked pid %d", parent_pid);
#endif
		return;
	}

	PMALLOC(tpi_child);
	tpi_child->pid = child_pid;
	tpi_child->processes = alloc_list(NULL, NULL);
	RB_CLEAR_NODE(&tpi_child->pid_tree);
	rb_insert_sort(&process_tree, tpi_child, pid_tree, pid_compare);
#ifdef _TRACK_PROCESS_DEBUG_
	if (do_track_process_debug_detail)
		log_message(LOG_INFO, "Adding new child %d of parent %d", child_pid, parent_pid);
#endif

	LIST_FOREACH(tpi->processes, tpr, e)
	{
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Adding new child %d to track_process %s", child_pid, tpr->pname);
#endif
		list_add(tpi_child->processes, tpr);
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

static int
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

	return 0;
}

static void
check_process_termination(pid_t pid)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;
	vrrp_tracked_process_t *tpr;
	element e;

	tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);

	if (!tpi) {
#ifdef _TRACK_PROCESS_DEBUG_
		if (do_track_process_debug_detail)
			log_message(LOG_INFO, "Ignoring exit of untracked pid %d", pid);
#endif
		return;
	}

	LIST_FOREACH(tpi->processes, tpr, e) {
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

	free_list(&tpi->processes);
	rb_erase(&tpi->pid_tree, &process_tree);
	FREE(tpi);
}

#if HAVE_DECL_PROC_EVENT_COMM
static void
check_process_comm_change(pid_t pid, char *comm)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;
	vrrp_tracked_process_t *tpr;
	element e, next;

	tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);

	if (tpi) {
		/* The process was being monitored by its old name */
		LIST_FOREACH_NEXT(tpi->processes, tpr, e, next) {
			if (tpr->full_command)
				continue;

			/* Check that the name really has changed */
			if (!strcmp(comm, tpr->process_path))
				return;

#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug_detail)
				log_message(LOG_INFO, "comm change remove pid %d", pid);
#endif
			list_remove(tpi->processes, e);
			if (tpr->num_cur_proc-- == tpr->quorum ||
			    tpr->num_cur_proc == tpr->quorum_max) {
#ifdef _TRACK_PROCESS_DEBUG_
				if (do_track_process_debug_detail)
					log_message(LOG_INFO, "comm change %s num_proc now %u, quorum [%u:%u]", tpr->pname, tpr->num_cur_proc, tpr->quorum, tpr->quorum_max);
#endif
				if (tpr->fork_timer_thread) {
					thread_cancel(tpr->fork_timer_thread);	// Cancel fork timer
					tpr->fork_timer_thread = NULL;
				}
				update_process_status(tpr, tpr->num_cur_proc == tpr->quorum_max);
			}
		}
	}
#ifdef _TRACK_PROCESS_DEBUG_
	else if (do_track_process_debug_detail)
		log_message(LOG_INFO, "comm_change pid %d not found", pid);
#endif

	/* Handle the new process name */
	check_process(pid, comm, tpi);
}
#endif

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

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(nl_sd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on netlink process socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(nl_sd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on netlink process socket - %s (%d)", strerror(errno), errno);
#endif

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	rc = bind(nl_sd, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
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
	element e;
	tracked_process_instance_t *tpi, *next;

	need_reinitialise = false;

	if (getsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, &buf_size_len) < 0) {
		log_message(LOG_INFO, "Cannot get process monitor SO_RCVBUF option. errno=%d (%m)", errno);
		return;
	}

	buf_size *= 2;
	set_rcv_buf(buf_size, global_data->process_monitor_rcv_bufs_force);

	log_message(LOG_INFO, "Setting global_def process_monitor_rcv_bufs to %u - recommend updating configuration file", buf_size);

	/* Reset the sequence numbers */
	for (i = 0; i < num_cpus; i++)
		cpu_seq[i] = -1;

	/* Remove the existing process tree */
	rb_for_each_entry_safe(tpi, next, &process_tree, pid_tree) {
		free_list(&tpi->processes);
		rb_erase(&tpi->pid_tree, &process_tree);
		FREE(tpi);
	}

	/* Save process counters, and clear any down timers */
	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
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
	read_procs(vrrp_data->vrrp_track_processes);

	/* See if anything changed */
	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
		if (tpr->sav_num_cur_proc != tpr->num_cur_proc) {
			if ((tpr->sav_num_cur_proc < tpr->quorum) == (tpr->num_cur_proc < tpr->quorum) &&
			    (tpr->sav_num_cur_proc > tpr->quorum_max) == (tpr->num_cur_proc > tpr->quorum_max)) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				continue;
			}
			if (tpr->num_cur_proc >= tpr->quorum &&
			    tpr->num_cur_proc <= tpr->quorum_max) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u, quorum up", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				if (tpr->fork_delay)
					tpr->fork_timer_thread = thread_add_timer(master, process_gained_quorum_timer_thread, tpr, tpr->terminate_delay);
				process_update_track_process_status(tpr, true);
			} else {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u, quorum down", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				if (tpr->terminate_delay)
					tpr->terminate_timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->terminate_delay);
				else
					process_update_track_process_status(tpr, false);
			}
		}
	}

	return;
}

static int
process_lost_messages_timer_thread(__attribute__((unused)) thread_ref_t thread)
{
	reinitialise_track_processes();

	return 0;
}

/*
 * handle a single process event
 */
static int handle_proc_ev(int nl_sd)
{
	struct nlmsghdr *nlmsghdr;
	ssize_t len;
	char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];
	struct cn_msg *cn_msg;
	struct proc_event *proc_ev;
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);

	while ((len = recvfrom(nl_sd, &buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen))) {
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
		if (addrlen != sizeof(addr) || addr.nl_pid != 0) {
			log_message(LOG_INFO, "addrlen %u, expect %zu, pid %u", addrlen, sizeof addr, addr.nl_pid);
			return -1;
		}

		for (nlmsghdr = (struct nlmsghdr *)buf;
			NLMSG_OK (nlmsghdr, len);
			nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

			if (nlmsghdr->nlmsg_type == NLMSG_ERROR ||
			    nlmsghdr->nlmsg_type == NLMSG_NOOP)
				continue;

			cn_msg = NLMSG_DATA(nlmsghdr);
			if (cn_msg->id.idx != CN_IDX_PROC ||
			    cn_msg->id.val != CN_VAL_PROC ||
			    cn_msg->ack)
				continue;

			proc_ev = (struct proc_event *)cn_msg->data;

			/* On 3.10 kernel, proc_ev->cpu can be UINT32_MAX */
			if (proc_ev->cpu >= num_cpus)
				continue;

			if (cpu_seq) {
				if ((!need_reinitialise || __test_bit(LOG_DETAIL_BIT, &debug)) &&
				    cpu_seq[proc_ev->cpu] != -1 &&
				    !(cpu_seq[proc_ev->cpu] + 1 == cn_msg->seq ||
				      (cn_msg->seq == 0 && cpu_seq[proc_ev->cpu] == UINT32_MAX)))
					log_message(LOG_INFO, "Missed %" PRIi64 " messages on CPU %u", cn_msg->seq - cpu_seq[proc_ev->cpu] - 1, proc_ev->cpu);

				cpu_seq[proc_ev->cpu] = cn_msg->seq;
			}

#ifdef _TRACK_PROCESS_DEBUG_
			if (do_track_process_debug) {
				switch (proc_ev->what)
				{
				case PROC_EVENT_NONE:
					log_message(LOG_INFO, "set mcast listen ok");
					break;
				case PROC_EVENT_FORK:
					/* See if we have parent pid, in which case this is a new process */
					log_message(LOG_INFO, "fork: parent tid=%d pid=%d -> child tid=%d pid=%d",
							proc_ev->event_data.fork.parent_pid,
							proc_ev->event_data.fork.parent_tgid,
							proc_ev->event_data.fork.child_pid,
							proc_ev->event_data.fork.child_tgid);
					break;
				case PROC_EVENT_EXEC:
					log_message(LOG_INFO, "exec: tid=%d pid=%d",
							proc_ev->event_data.exec.process_pid,
							proc_ev->event_data.exec.process_tgid);
					break;
				case PROC_EVENT_UID:
					log_message(LOG_INFO, "uid change: tid=%d pid=%d from %" PRIu32 " to %" PRIu32,
							proc_ev->event_data.id.process_pid,
							proc_ev->event_data.id.process_tgid,
							proc_ev->event_data.id.r.ruid,
							proc_ev->event_data.id.e.euid);
					break;
				case PROC_EVENT_GID:
					log_message(LOG_INFO, "gid change: tid=%d pid=%d from %" PRIu32 " to %" PRIu32,
							proc_ev->event_data.id.process_pid,
							proc_ev->event_data.id.process_tgid,
							proc_ev->event_data.id.r.rgid,
							proc_ev->event_data.id.e.egid);
					break;
#if HAVE_DECL_PROC_EVENT_SID	/* Since Linux v2.6.32 */
				case PROC_EVENT_SID:
					log_message(LOG_INFO, "sid change: tid=%d pid=%d",
							proc_ev->event_data.sid.process_pid,
							proc_ev->event_data.sid.process_tgid);
					break;
#endif
#if HAVE_DECL_PROC_EVENT_PTRACE	/* Since Linux v3.1 */
				case PROC_EVENT_PTRACE:
					log_message(LOG_INFO, "ptrace change: tid=%d pid=%d tracer tid=%d, pid=%d",
							proc_ev->event_data.ptrace.process_pid,
							proc_ev->event_data.ptrace.process_tgid,
							proc_ev->event_data.ptrace.tracer_pid,
							proc_ev->event_data.ptrace.tracer_tgid);
					break;
#endif
#if HAVE_DECL_PROC_EVENT_COMM		/* Since Linux v3.2 */
				case PROC_EVENT_COMM:
					log_message(LOG_INFO, "comm: tid=%d pid=%d comm %s",
							proc_ev->event_data.comm.process_pid,
							proc_ev->event_data.comm.process_tgid,
							proc_ev->event_data.comm.comm);
					break;
#endif
#if HAVE_DECL_PROC_EVENT_COREDUMP	/* Since Linux v3.10 */
				case PROC_EVENT_COREDUMP:
					log_message(LOG_INFO, "coredump: tid=%d pid=%d",
							proc_ev->event_data.coredump.process_pid,
							proc_ev->event_data.coredump.process_tgid);
					break;
#endif
				case PROC_EVENT_EXIT:
					log_message(LOG_INFO, "exit: tid=%d pid=%d exit_code=%u, signal=%u,",
							proc_ev->event_data.exit.process_pid,
							proc_ev->event_data.exit.process_tgid,
							proc_ev->event_data.exit.exit_code,
							proc_ev->event_data.exit.exit_signal);
					break;
				default:
					log_message(LOG_INFO, "unhandled proc event %u", proc_ev->what);
					break;
				}
			}
#endif

			switch (proc_ev->what)
			{
			case PROC_EVENT_FORK:
				/* See if we have parent pid, in which case this is a new process.
				 * For a process fork, child_pid == child_tgid.
				 * For a new thread, child_pid != child_tgid and parent_pid/tgid is
				 * the parent process of the process doing the pthread_create(). */
				if (proc_ev->event_data.fork.child_tgid == proc_ev->event_data.fork.child_pid)
					check_process_fork(proc_ev->event_data.fork.parent_tgid, proc_ev->event_data.fork.child_tgid);
#ifdef _TRACK_PROCESS_DEBUG_
				else if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Ignoring new thread %d for pid %d", proc_ev->event_data.fork.child_tgid, proc_ev->event_data.fork.child_pid);
#endif
				break;
			case PROC_EVENT_EXEC:
				/* We may be losing a process. Check if have pid, and check new cmdline */
				if (proc_ev->event_data.exec.process_tgid == proc_ev->event_data.exec.process_pid)
					check_process(proc_ev->event_data.exec.process_tgid, NULL, NULL);
#ifdef _TRACK_PROCESS_DEBUG_
				else if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Ignoring exec of thread %d of pid %d", proc_ev->event_data.exec.process_tgid, proc_ev->event_data.exec.process_pid);
#endif
				break;
#if HAVE_DECL_PROC_EVENT_COMM		/* Since Linux v3.2 */
			/* NOTE: not having PROC_EVENT_COMM means that changes to /proc/PID/comm
			 * will not be detected */
			case PROC_EVENT_COMM:
				if (proc_ev->event_data.comm.process_tgid == proc_ev->event_data.comm.process_pid)
					check_process_comm_change(proc_ev->event_data.comm.process_tgid, proc_ev->event_data.comm.comm);
#ifdef _TRACK_PROCESS_DEBUG_
				else if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Ignoring COMM event of thread %d of pid %d", proc_ev->event_data.comm.process_tgid, proc_ev->event_data.comm.process_pid);
#endif
				break;
#endif
			case PROC_EVENT_EXIT:
				/* We aren't interested in thread termination */
				if (proc_ev->event_data.exit.process_tgid == proc_ev->event_data.exit.process_pid)
					check_process_termination(proc_ev->event_data.exit.process_tgid);
#ifdef _TRACK_PROCESS_DEBUG_
				else if (do_track_process_debug_detail)
					log_message(LOG_INFO, "Ignoring exit of thread %d of pid %d", proc_ev->event_data.exit.process_tgid, proc_ev->event_data.exit.process_pid);
#endif
				break;
			default:
				break;
			}
		}
	}
	if (len == 0)
		log_message(LOG_INFO, "recvfrom returned %zd", len);

	return 0;
}

static int
read_process_update(thread_ref_t thread)
{
	int rc = EXIT_SUCCESS;

	rc = handle_proc_ev(thread->u.f.fd);

	read_thread = thread_add_read(thread->master, read_process_update, NULL, thread->u.f.fd, TIMER_NEVER, false);

	return rc;
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
init_track_processes(list processes)
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

	if (!cpu_seq) {
		num = sysconf(_SC_NPROCESSORS_CONF);
		if (num > 0) {
			num_cpus = num;
			cpu_seq = MALLOC(num_cpus * sizeof(*cpu_seq));
			for (i = 0; i < num_cpus; i++)
				cpu_seq[i] = -1;
		}
		else
			log_message(LOG_INFO, "sysconf returned %ld CPUs - ignoring and won't track process event sequence numbers", num);
	}

	read_procs(processes);

	read_thread = thread_add_read(master, read_process_update, NULL, nl_sock, TIMER_NEVER, false);

	return rc;
}

void
reload_track_processes(void)
{
	tracked_process_instance_t *tpi, *next;

	/* Remove the existing process tree */
	rb_for_each_entry_safe(tpi, next, &process_tree, pid_tree) {
		free_list(&tpi->processes);
		rb_erase(&tpi->pid_tree, &process_tree);
		FREE(tpi);
	}

	/* Re read processes */
	read_procs(vrrp_data->vrrp_track_processes);

	/* Add read thread */
	read_thread = thread_add_read(master, read_process_update, NULL, nl_sock, TIMER_NEVER, false);

	return;
}

void
end_process_monitor(void)
{
	vrrp_tracked_process_t *tpr;
	element e;
	tracked_process_instance_t *tpi, *next;

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
	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
		if (tpr->fork_timer_thread) {
			thread_cancel(tpr->fork_timer_thread);
			tpr->fork_timer_thread = NULL;
		}
		if (tpr->terminate_timer_thread) {
			thread_cancel(tpr->terminate_timer_thread);
			tpr->terminate_timer_thread = NULL;
		}
	}

	rb_for_each_entry_safe(tpi, next, &process_tree, pid_tree) {
		free_list(&tpi->processes);
		rb_erase(&tpi->pid_tree, &process_tree);
		FREE(tpi);
	}
}

#ifdef THREAD_DUMP
void
register_process_monitor_addresses(void)
{
	register_thread_address("process_lost_quorum", process_lost_quorum_timer_thread);
	register_thread_address("process_lost_messages", process_lost_messages_timer_thread);
	register_thread_address("monitor_processes", read_process_update);
}
#endif
