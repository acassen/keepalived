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

static thread_t *read_thread;
static thread_t *reload_thread;
static rb_root_t process_tree = RB_ROOT;
static int nl_sock = -1;
unsigned num_cpus;
static int64_t *cpu_seq;
static bool need_reinitialise;

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

static inline void
add_process(pid_t pid, vrrp_tracked_process_t *tpr)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;

	if (!(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare))) {
		PMALLOC(tpi);
		tpi->pid = tp.pid;
		tpi->processes = alloc_list(NULL, NULL);
		RB_CLEAR_NODE(&tpi->pid_tree);
		rb_insert_sort(&process_tree, tpi, pid_tree, pid_compare);
	}

	list_add(tpi->processes, tpr);
	++tpr->num_cur_proc;
}

#ifdef UNUSED_CODE
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
	char cmd_buf[vrrp_data->vrrp_max_process_name_len + 2];
	char stat_buf[128];
	char *p;
	char *comm;
	ssize_t len;
	char *proc_name;
	vrrp_tracked_process_t *tpr;
	element e;

	while ((ent = readdir(proc_dir))) {
		if (ent->d_type != DT_DIR)
			continue;
		if (ent->d_name[0] <= '0' || ent->d_name[0] >= '9')
			continue;

		/* We want to avoid reading /proc/PID/cmdline, since it reads the process
		 * address space, and if the process is swapped out, then it will have to be
		 * swapped in to read it. */
		if (vrrp_data->vrrp_use_process_cmdline) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%.7s/cmdline", ent->d_name);

			if ((fd = open(cmdline, O_RDONLY)) == -1)
				continue;

			len = read(fd, cmd_buf, sizeof(cmd_buf) - 1);
			close(fd);
			cmd_buf[len] = '\0';
		}

		if (vrrp_data->vrrp_use_process_comm) {
			snprintf(cmdline, sizeof(cmdline), "/proc/%.7s/stat", ent->d_name);

			if ((fd = open(cmdline, O_RDONLY)) == -1)
				continue;

			len = read(fd, stat_buf, sizeof(stat_buf) - 1);
			close(fd);
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

		LIST_FOREACH(processes, tpr, e) {
			if (tpr->full_command)
				proc_name = cmd_buf;
			else
				proc_name = comm;

			if (!strcmp(proc_name, tpr->process_path)) {
				/* We have got a match */
				add_process(atoi(ent->d_name), tpr);
			}
		}
	}

	closedir(proc_dir);
}

static void
check_process(pid_t pid, char *comm)
{
	char cmdline[22];	/* "/proc/xxxxxxx/cmdline" */
	int fd;
	char cmd_buf[vrrp_data->vrrp_max_process_name_len + 2];
	char comm_buf[17];
	ssize_t len;
	char *proc_name;
	vrrp_tracked_process_t *tpr;
	element e;

	/* We want to avoid reading /proc/PID/cmdline, since it reads the process
	 * address space, and if the process is swapped out, then it will have to be
	 * swapped in to read it. */
	if (vrrp_data->vrrp_use_process_cmdline) {
		snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pid);

		if ((fd = open(cmdline, O_RDONLY)) == -1)
			return;

		len = read(fd, cmd_buf, sizeof(cmd_buf) - 1);
		close(fd);
		cmd_buf[len] = '\0';
	}

	if (vrrp_data->vrrp_use_process_comm && !comm) {
		snprintf(cmdline, sizeof(cmdline), "/proc/%d/comm", pid);

		if ((fd = open(cmdline, O_RDONLY)) == -1)
			return;

		len = read(fd, comm_buf, sizeof(comm_buf) - 1);
		close(fd);
		comm_buf[len] = '\0';
		if (len && comm_buf[len-1] == '\n')
			comm_buf[len-1] = '\0';
		comm = comm_buf;
	}

	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
		if (tpr->full_command)
			proc_name = cmd_buf;
		else
			proc_name = comm;

		if (!strcmp(proc_name, tpr->process_path)) {
			/* We have got a match */
			add_process(pid, tpr);

			if (tpr->num_cur_proc == tpr->quorum) {
				/* Cancel timer thread if any, otherwise update status */
				if (tpr->timer_thread) {
					thread_cancel(tpr->timer_thread);
					tpr->timer_thread = NULL;
				}
				else
					process_update_track_process_status(tpr, true);
			}
		}
	}
}

static void
check_process_fork(pid_t parent_pid, pid_t child_pid)
{
	tracked_process_instance_t tp = { .pid = parent_pid };
	tracked_process_instance_t *tpi, *tpi_child;
	vrrp_tracked_process_t *tpr;
	element e;

	/* If we aren't interested in the parent, we aren't interested in the child */
	if (!(tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare)))
		return;

	PMALLOC(tpi_child);
	tpi_child->pid = child_pid;
	tpi_child->processes = alloc_list(NULL, NULL);
	RB_CLEAR_NODE(&tpi_child->pid_tree);
	rb_insert_sort(&process_tree, tpi_child, pid_tree, pid_compare);

	LIST_FOREACH(tpi->processes, tpr, e)
	{
		list_add(tpi_child->processes, tpr);
		if (++tpr->num_cur_proc == tpr->quorum)
			process_update_track_process_status(tpr, true);
	}
}

static int
process_lost_quorum_timer_thread(thread_t *thread)
{
	vrrp_tracked_process_t *tpr = thread->arg;

	process_update_track_process_status(tpr, false);
	tpr->timer_thread = NULL;

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

	if (!tpi)
		return;

	LIST_FOREACH(tpi->processes, tpr, e)
	{
		if (tpr->num_cur_proc-- == tpr->quorum) {
			if (tpr->delay)
				tpr->timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->delay);
			else
				process_update_track_process_status(tpr, false);
		}
	}

	free_list(&tpi->processes);
	rb_erase(&tpi->pid_tree, &process_tree);
	FREE(tpi);
}

static void
check_process_comm_change(pid_t pid, char *comm)
{
	tracked_process_instance_t tp = { .pid = pid };
	tracked_process_instance_t *tpi;
	vrrp_tracked_process_t *tpr;
	element e, next;

	tpi = rb_search(&process_tree, &tp, pid_tree, pid_compare);

	if (tpi) {
		LIST_FOREACH_NEXT(tpi->processes, tpr, e, next)
		{
			if (tpr->full_command)
				continue;

			list_remove(tpi->processes, e);
			if (tpr->num_cur_proc-- == tpr->quorum) {
				if (tpr->delay)
					tpr->timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->delay);
				else
					process_update_track_process_status(tpr, false);
			}
		}

		if (LIST_ISEMPTY(tpi->processes)) {
			free_list(&tpi->processes);
			rb_erase(&tpi->pid_tree, &process_tree);
			FREE(tpi);
		}
	}

	check_process(pid, comm);
}

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int
nl_connect(void)
{
	int rc;
	int nl_sock;
	struct sockaddr_nl sa_nl;

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_CONNECTOR);
	if (nl_sock == -1) {
		log_message(LOG_INFO, "Failed to open process monitoring socket - errno %d - %m", errno);
		return -1;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
        if (set_sock_flags(nl_sock, F_SETFL, O_NONBLOCK))
                log_message(LOG_INFO, "Unable to set NONBLOCK on netlink process socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
        if (set_sock_flags(nl_sock, F_SETFD, FD_CLOEXEC))
                log_message(LOG_INFO, "Unable to set CLOEXEC on netlink process socket - %s (%d)", strerror(errno), errno);
#endif

	sa_nl.nl_family = AF_NETLINK;
	sa_nl.nl_groups = CN_IDX_PROC;
	sa_nl.nl_pid = getpid();

	rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
	if (rc == -1) {
		log_message(LOG_INFO, "Failed to bind to process monitoring socket - errno %d - %m", errno);
		close(nl_sock);
		return -1;
	}

	return nl_sock;
}

/*
 * subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sock, bool enable)
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

	rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
	if (rc == -1) {
		log_message(LOG_INFO, "Failed to set/clear process event listen - errno %d - %m", errno);
		return -1;
	}

	return 0;
}

void
reload_track_processes(void)
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
		if (tpr->timer_thread) {
			thread_cancel(tpr->timer_thread);
			tpr->timer_thread = NULL;
		}
	}

	/* Re read processes */
	read_procs(vrrp_data->vrrp_track_processes);

	/* See if anything changed */
	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
		if (tpr->sav_num_cur_proc != tpr->num_cur_proc) {
			if ((tpr->sav_num_cur_proc < tpr->quorum) == (tpr->num_cur_proc < tpr->quorum)) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				continue;
			}
			if (tpr->num_cur_proc >= tpr->quorum) {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u, quorum up", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				process_update_track_process_status(tpr, true);
			} else {
				if (__test_bit(LOG_DETAIL_BIT, &debug))
					log_message(LOG_INFO, "Process %s, number of current processes changed from %u to %u, quorum down", tpr->pname, tpr->sav_num_cur_proc, tpr->num_cur_proc);
				if (tpr->delay)
					tpr->timer_thread = thread_add_timer(master, process_lost_quorum_timer_thread, tpr, tpr->delay);
				else
					process_update_track_process_status(tpr, false);
			}
		}
	}

	return;
}

static int
process_lost_messages_timer_thread(__attribute__((unused)) thread_t *thread)
{
	reload_track_processes();

	return 0;
}

/*
 * handle a single process event
 */
static int handle_proc_ev(int nl_sock)
{
	struct nlmsghdr *nlmsghdr;
	ssize_t len;
	char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];
	struct cn_msg *cn_msg;
	struct proc_event *proc_ev;

	while ((len = recv(nl_sock, &buf, sizeof(buf), 0))) {
		if (len == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
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
		for (nlmsghdr = (struct nlmsghdr *)buf;
                        NLMSG_OK (nlmsghdr, len);
                        nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

			if (nlmsghdr->nlmsg_type == NLMSG_ERROR ||
			    nlmsghdr->nlmsg_type == NLMSG_NOOP)
				continue;

			cn_msg = NLMSG_DATA(nlmsghdr);
			if ((cn_msg->id.idx != CN_IDX_PROC) ||
                            (cn_msg->id.val != CN_VAL_PROC))
                                continue;

			proc_ev = (struct proc_event *)cn_msg->data;
			if ((!need_reinitialise || __test_bit(LOG_DETAIL_BIT, &debug)) &&
			    cpu_seq[proc_ev->cpu] != -1 &&
			    !(cpu_seq[proc_ev->cpu] + 1 == cn_msg->seq ||
			      (cn_msg->seq == 0 && cpu_seq[proc_ev->cpu] == UINT32_MAX)))
				log_message(LOG_INFO, "Missed %ld messages on CPU %d", cn_msg->seq - cpu_seq[proc_ev->cpu] - 1, proc_ev->cpu);

			cpu_seq[proc_ev->cpu] = cn_msg->seq;

			switch (proc_ev->what)
			{
			case PROC_EVENT_NONE:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "set mcast listen ok");
#endif
				break;
			case PROC_EVENT_FORK:
#ifdef LOG_ALL_PROCESS_EVENTS
				/* See if we have parent pid, in which case this is a new process */
				log_message(LOG_INFO, "fork: parent tid=%d pid=%d -> child tid=%d pid=%d",
						proc_ev->event_data.fork.parent_pid,
						proc_ev->event_data.fork.parent_tgid,
						proc_ev->event_data.fork.child_pid,
						proc_ev->event_data.fork.child_tgid);
#endif
				check_process_fork(proc_ev->event_data.fork.parent_pid, proc_ev->event_data.fork.child_pid);
				break;
			case PROC_EVENT_EXEC:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "exec: tid=%d pid=%d",
						proc_ev->event_data.exec.process_pid,
						proc_ev->event_data.exec.process_tgid);
#endif
				// We may be losing a process. Check if have pid, and check new cmdline */
				check_process(proc_ev->event_data.exec.process_pid, NULL);
				break;
			case PROC_EVENT_UID:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "uid change: tid=%d pid=%d from %d to %d",
						proc_ev->event_data.id.process_pid,
						proc_ev->event_data.id.process_tgid,
						proc_ev->event_data.id.r.ruid,
						proc_ev->event_data.id.e.euid);
#endif
				break;
			case PROC_EVENT_GID:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "gid change: tid=%d pid=%d from %d to %d",
						proc_ev->event_data.id.process_pid,
						proc_ev->event_data.id.process_tgid,
						proc_ev->event_data.id.r.rgid,
						proc_ev->event_data.id.e.egid);
#endif
				break;
			case PROC_EVENT_SID:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "sid change: tid=%d pid=%d",
						proc_ev->event_data.sid.process_pid,
						proc_ev->event_data.sid.process_tgid);
#endif
				break;
			case PROC_EVENT_PTRACE:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "ptrace change: tid=%d pid=%d tracer tid=%d, pid=%d",
						proc_ev->event_data.ptrace.process_pid,
						proc_ev->event_data.ptrace.process_tgid,
						proc_ev->event_data.ptrace.tracer_tgid,
						proc_ev->event_data.ptrace.tracer_pid);
#endif
				break;
			case PROC_EVENT_COMM:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "comm: tid=%d pid=%d comm %s",
						proc_ev->event_data.comm.process_pid,
						proc_ev->event_data.comm.process_tgid,
						proc_ev->event_data.comm.comm);
#endif
				check_process_comm_change(proc_ev->event_data.comm.process_pid, proc_ev->event_data.comm.comm);
				break;
			case PROC_EVENT_COREDUMP:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "coredump: tid=%d pid=%d",
						proc_ev->event_data.coredump.process_pid,
						proc_ev->event_data.coredump.process_tgid);
#endif
				break;
			case PROC_EVENT_EXIT:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "exit: tid=%d pid=%d exit_code=%u, signal=%u,",
						proc_ev->event_data.exit.process_pid,
						proc_ev->event_data.exit.process_tgid,
						proc_ev->event_data.exit.exit_code,
						proc_ev->event_data.exit.exit_signal);
#endif
				check_process_termination(proc_ev->event_data.exit.process_pid);
				break;
			default:
#ifdef LOG_ALL_PROCESS_EVENTS
				log_message(LOG_INFO, "unhandled proc event %d", proc_ev->what);
#endif
				break;
			}
		}
	}

	return 0;
}

static int
read_process_update(thread_t *thread)
{
	int rc = EXIT_SUCCESS;

	rc = handle_proc_ev(thread->u.fd);

	read_thread = thread_add_read(thread->master, read_process_update, NULL, thread->u.fd, TIMER_NEVER);

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

	if (global_data->process_monitor_rcv_bufs)
		set_rcv_buf(global_data->process_monitor_rcv_bufs, global_data->process_monitor_rcv_bufs_force);

	rc = set_proc_ev_listen(nl_sock, true);
	if (rc == -1) {
		close(nl_sock);
		nl_sock = -1;
		return EXIT_FAILURE;
	}

	if (!cpu_seq) {
		num_cpus = sysconf(_SC_NPROCESSORS_CONF);
		cpu_seq = MALLOC(num_cpus * sizeof(*cpu_seq));
		for (i = 0; i < num_cpus; i++)
			cpu_seq[i] = -1;
	}

	read_procs(processes);

	read_thread = thread_add_read(master, read_process_update, NULL, nl_sock, TIMER_NEVER);

	return rc;
}

void
end_process_monitor(void)
{
	vrrp_tracked_process_t *tpr;
	element e;
	tracked_process_instance_t *tpi, *next;

	set_proc_ev_listen(nl_sock, false);

	if (read_thread) {
		thread_cancel(read_thread);
		read_thread = NULL;
	}

	close(nl_sock);
	nl_sock = -1;

	FREE_PTR(cpu_seq);

	/* Cancel any timer threads */
	LIST_FOREACH(vrrp_data->vrrp_track_processes, tpr, e) {
		if (tpr->timer_thread) {
			thread_cancel(tpr->timer_thread);
			tpr->timer_thread = NULL;
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
