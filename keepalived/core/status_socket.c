/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Unix socket for unified status queries across all daemons.
 *              Runs in parent process, receives status updates from
 *              VRRP, Checker, and BFD child daemons via pipes.
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
 * Copyright (C) 2001-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#ifdef _WITH_STATUS_SOCKET_

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "status_socket.h"
#include "status_event.h"
#include "scheduler.h"
#include "logger.h"
#include "global_data.h"
#include "memory.h"
#include "utils.h"
#include "main.h"

#define STATUS_SOCKET_DEFAULT_PATH	"/var/run/keepalived/status.sock"
#define STATUS_SOCKET_BACKLOG		5
#define STATUS_SOCKET_TIMEOUT		(5 * TIMER_HZ)
#define STATUS_SOCKET_MAX_REQUEST	64
#define STATUS_SOCKET_MAX_RESPONSE	4096

/* Status pipes - defined here, declared extern in status_event.h */
#ifdef _WITH_VRRP_
int status_vrrp_pipe[2] = { -1, -1 };
#endif
#ifdef _WITH_LVS_
int status_checker_pipe[2] = { -1, -1 };
#endif
#ifdef _WITH_BFD_
int status_bfd_pipe[2] = { -1, -1 };
#endif

/* Unix socket fd */
static int status_socket_fd = -1;

/* Thread master reference */
static thread_master_t *status_master;

/* Aggregated state from each daemon */
static struct daemon_state {
	uint8_t		state;
	uint32_t	num_instances;
	uint32_t	num_fault;
	uint32_t	num_master;
	timeval_t	last_update;
	bool		running;
} vrrp_state, checker_state, bfd_state;

static const char *
state_to_string(uint8_t state)
{
	switch (state) {
	case STATUS_STATE_INIT:
		return "INIT";
	case STATUS_STATE_UP:
		return "UP";
	case STATUS_STATE_DOWN:
		return "DOWN";
	case STATUS_STATE_FAULT:
		return "FAULT";
	default:
		return "UNKNOWN";
	}
}

static void
build_health_response(char *buf, size_t bufsize)
{
	bool any_fault = false;
	bool any_running = false;

#ifdef _WITH_VRRP_
	if (vrrp_state.running) {
		any_running = true;
		if (vrrp_state.state == STATUS_STATE_FAULT)
			any_fault = true;
	}
#endif
#ifdef _WITH_LVS_
	if (checker_state.running) {
		any_running = true;
		if (checker_state.state == STATUS_STATE_FAULT)
			any_fault = true;
	}
#endif
#ifdef _WITH_BFD_
	if (bfd_state.running) {
		any_running = true;
		if (bfd_state.state == STATUS_STATE_FAULT)
			any_fault = true;
	}
#endif

	if (!any_running) {
		snprintf(buf, bufsize, "UNKNOWN\n");
		return;
	}

	if (any_fault) {
		snprintf(buf, bufsize, "FAULT\n");
		return;
	}

#ifdef _WITH_VRRP_
	if (vrrp_state.running && vrrp_state.num_master > 0) {
		snprintf(buf, bufsize, "MASTER\n");
		return;
	}
#endif

	snprintf(buf, bufsize, "BACKUP\n");
}

static void
build_status_response(char *buf, size_t bufsize)
{
	int len;
	size_t remaining = bufsize;
	char *p = buf;

	len = snprintf(p, remaining, "{");
	if (len < 0 || (size_t)len >= remaining)
		return;
	p += len;
	remaining -= len;

	bool first = true;

#ifdef _WITH_VRRP_
	if (vrrp_state.running) {
		len = snprintf(p, remaining,
			       "%s\"vrrp\":{\"state\":\"%s\",\"instances\":%u,\"fault\":%u,\"master\":%u}",
			       first ? "" : ",",
			       state_to_string(vrrp_state.state),
			       vrrp_state.num_instances,
			       vrrp_state.num_fault,
			       vrrp_state.num_master);
		if (len < 0 || (size_t)len >= remaining)
			return;
		p += len;
		remaining -= len;
		first = false;
	}
#endif

#ifdef _WITH_LVS_
	if (checker_state.running) {
		len = snprintf(p, remaining,
			       "%s\"checker\":{\"state\":\"%s\",\"instances\":%u,\"fault\":%u}",
			       first ? "" : ",",
			       state_to_string(checker_state.state),
			       checker_state.num_instances,
			       checker_state.num_fault);
		if (len < 0 || (size_t)len >= remaining)
			return;
		p += len;
		remaining -= len;
		first = false;
	}
#endif

#ifdef _WITH_BFD_
	if (bfd_state.running) {
		len = snprintf(p, remaining,
			       "%s\"bfd\":{\"state\":\"%s\",\"instances\":%u,\"fault\":%u}",
			       first ? "" : ",",
			       state_to_string(bfd_state.state),
			       bfd_state.num_instances,
			       bfd_state.num_fault);
		if (len < 0 || (size_t)len >= remaining)
			return;
		p += len;
		remaining -= len;
	}
#endif

	snprintf(p, remaining, "}\n");
}

static void
handle_client_request(thread_ref_t thread)
{
	int client_fd = thread->u.f.fd;
	char request[STATUS_SOCKET_MAX_REQUEST];
	char response[STATUS_SOCKET_MAX_RESPONSE];
	ssize_t n;

	n = read(client_fd, request, sizeof(request) - 1);
	if (n <= 0) {
		close(client_fd);
		return;
	}
	request[n] = '\0';

	/* Remove trailing newline */
	while (n > 0 && (request[n - 1] == '\n' || request[n - 1] == '\r'))
		request[--n] = '\0';

	if (strncmp(request, "HEALTH", 6) == 0) {
		build_health_response(response, sizeof(response));
	} else if (strncmp(request, "STATUS", 6) == 0) {
		build_status_response(response, sizeof(response));
	} else {
		snprintf(response, sizeof(response),
			 "ERROR: Unknown command. Use HEALTH or STATUS.\n");
	}

	if (write(client_fd, response, strlen(response)) < 0)
		log_message(LOG_INFO, "Status socket: write to client failed - %s",
			    strerror(errno));

	close(client_fd);
}

static void
accept_client_connection(thread_ref_t thread)
{
	int client_fd;

	client_fd = accept(status_socket_fd, NULL, NULL);
	if (client_fd >= 0) {
		fcntl(client_fd, F_SETFL, O_NONBLOCK | fcntl(client_fd, F_GETFL));
		thread_add_read(status_master, handle_client_request, NULL,
				client_fd, STATUS_SOCKET_TIMEOUT, 0);
	}

	/* Re-register for next connection */
	thread_add_read(status_master, accept_client_connection, NULL,
			status_socket_fd, TIMER_NEVER, 0);
}

#ifdef _WITH_VRRP_
static void
read_vrrp_status_pipe(thread_ref_t thread)
{
	status_event_t evt;
	ssize_t n;

	n = read(thread->u.f.fd, &evt, sizeof(evt));
	if (n == sizeof(evt)) {
		vrrp_state.state = evt.overall_state;
		vrrp_state.num_instances = evt.num_instances;
		vrrp_state.num_fault = evt.num_fault;
		vrrp_state.num_master = evt.num_master;
		vrrp_state.last_update = evt.sent_time;
		vrrp_state.running = true;
	}

	/* Re-register for next event */
	thread_add_read(status_master, read_vrrp_status_pipe, NULL,
			status_vrrp_pipe[0], TIMER_NEVER, 0);
}
#endif

#ifdef _WITH_LVS_
static void
read_checker_status_pipe(thread_ref_t thread)
{
	status_event_t evt;
	ssize_t n;

	n = read(thread->u.f.fd, &evt, sizeof(evt));
	if (n == sizeof(evt)) {
		checker_state.state = evt.overall_state;
		checker_state.num_instances = evt.num_instances;
		checker_state.num_fault = evt.num_fault;
		checker_state.last_update = evt.sent_time;
		checker_state.running = true;
	}

	/* Re-register for next event */
	thread_add_read(status_master, read_checker_status_pipe, NULL,
			status_checker_pipe[0], TIMER_NEVER, 0);
}
#endif

#ifdef _WITH_BFD_
static void
read_bfd_status_pipe(thread_ref_t thread)
{
	status_event_t evt;
	ssize_t n;

	n = read(thread->u.f.fd, &evt, sizeof(evt));
	if (n == sizeof(evt)) {
		bfd_state.state = evt.overall_state;
		bfd_state.num_instances = evt.num_instances;
		bfd_state.num_fault = evt.num_fault;
		bfd_state.last_update = evt.sent_time;
		bfd_state.running = true;
	}

	/* Re-register for next event */
	thread_add_read(status_master, read_bfd_status_pipe, NULL,
			status_bfd_pipe[0], TIMER_NEVER, 0);
}
#endif

bool
open_status_pipes(void)
{
#ifdef _WITH_VRRP_
	if (running_vrrp()) {
		if (open_pipe(status_vrrp_pipe) == -1) {
			log_message(LOG_ERR, "Status socket: Unable to create VRRP status pipe: %m");
			return false;
		}
	}
#endif

#ifdef _WITH_LVS_
	if (running_checker()) {
		if (open_pipe(status_checker_pipe) == -1) {
			log_message(LOG_ERR, "Status socket: Unable to create checker status pipe: %m");
			return false;
		}
	}
#endif

#ifdef _WITH_BFD_
	if (running_bfd()) {
		if (open_pipe(status_bfd_pipe) == -1) {
			log_message(LOG_ERR, "Status socket: Unable to create BFD status pipe: %m");
			return false;
		}
	}
#endif

	return true;
}

void
close_status_write_pipes(void)
{
	/* Close write ends in parent - children write, parent reads */
#ifdef _WITH_VRRP_
	if (status_vrrp_pipe[1] >= 0) {
		close(status_vrrp_pipe[1]);
		status_vrrp_pipe[1] = -1;
	}
#endif
#ifdef _WITH_LVS_
	if (status_checker_pipe[1] >= 0) {
		close(status_checker_pipe[1]);
		status_checker_pipe[1] = -1;
	}
#endif
#ifdef _WITH_BFD_
	if (status_bfd_pipe[1] >= 0) {
		close(status_bfd_pipe[1]);
		status_bfd_pipe[1] = -1;
	}
#endif
}

bool
status_socket_init(thread_master_t *m)
{
	struct sockaddr_un addr;
	const char *path;
	mode_t mode;

	status_master = m;
	path = global_data->status_socket_path ? global_data->status_socket_path
					       : STATUS_SOCKET_DEFAULT_PATH;
	mode = global_data->status_socket_mode ? global_data->status_socket_mode : 0600;

	/* Remove stale socket */
	unlink(path);

	status_socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (status_socket_fd < 0) {
		log_message(LOG_INFO, "Status socket: failed to create socket - %s",
			    strerror(errno));
		return false;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(status_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_message(LOG_INFO, "Status socket: failed to bind to %s - %s",
			    path, strerror(errno));
		close(status_socket_fd);
		status_socket_fd = -1;
		return false;
	}

	if (chmod(path, mode) < 0)
		log_message(LOG_INFO, "Status socket: failed to set permissions on %s - %s",
			    path, strerror(errno));

	if (listen(status_socket_fd, STATUS_SOCKET_BACKLOG) < 0) {
		log_message(LOG_INFO, "Status socket: failed to listen on %s - %s",
			    path, strerror(errno));
		close(status_socket_fd);
		status_socket_fd = -1;
		unlink(path);
		return false;
	}

	/* Close write ends of pipes - parent only reads */
	close_status_write_pipes();

	/* Register pipe readers for each daemon */
#ifdef _WITH_VRRP_
	if (status_vrrp_pipe[0] >= 0)
		thread_add_read(status_master, read_vrrp_status_pipe, NULL,
				status_vrrp_pipe[0], TIMER_NEVER, 0);
#endif
#ifdef _WITH_LVS_
	if (status_checker_pipe[0] >= 0)
		thread_add_read(status_master, read_checker_status_pipe, NULL,
				status_checker_pipe[0], TIMER_NEVER, 0);
#endif
#ifdef _WITH_BFD_
	if (status_bfd_pipe[0] >= 0)
		thread_add_read(status_master, read_bfd_status_pipe, NULL,
				status_bfd_pipe[0], TIMER_NEVER, 0);
#endif

	/* Register socket accept handler */
	thread_add_read(status_master, accept_client_connection, NULL,
			status_socket_fd, TIMER_NEVER, 0);

	log_message(LOG_INFO, "Status socket listening on %s", path);
	return true;
}

void
status_socket_close(void)
{
	const char *path;

	if (status_socket_fd >= 0) {
		close(status_socket_fd);
		status_socket_fd = -1;
	}

	/* Close read ends of pipes */
#ifdef _WITH_VRRP_
	if (status_vrrp_pipe[0] >= 0) {
		close(status_vrrp_pipe[0]);
		status_vrrp_pipe[0] = -1;
	}
#endif
#ifdef _WITH_LVS_
	if (status_checker_pipe[0] >= 0) {
		close(status_checker_pipe[0]);
		status_checker_pipe[0] = -1;
	}
#endif
#ifdef _WITH_BFD_
	if (status_bfd_pipe[0] >= 0) {
		close(status_bfd_pipe[0]);
		status_bfd_pipe[0] = -1;
	}
#endif

	if (global_data && global_data->status_socket_path)
		path = global_data->status_socket_path;
	else
		path = STATUS_SOCKET_DEFAULT_PATH;

	unlink(path);
}

/* Functions for children to send status events to parent */
#ifdef _WITH_VRRP_
void
status_send_vrrp_event(uint8_t state, uint32_t num_inst,
		       uint32_t num_fault, uint32_t num_master)
{
	status_event_t evt;

	if (status_vrrp_pipe[1] < 0)
		return;

	memset(&evt, 0, sizeof(evt));
	evt.daemon_type = STATUS_DAEMON_VRRP;
	evt.overall_state = state;
	evt.num_instances = num_inst;
	evt.num_fault = num_fault;
	evt.num_master = num_master;
	evt.sent_time = timer_now();

	if (write(status_vrrp_pipe[1], &evt, sizeof(evt)) < 0 &&
	    __test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_ERR, "Status socket: VRRP pipe write error - %m");
}
#endif

#ifdef _WITH_LVS_
void
status_send_checker_event(uint8_t state, uint32_t num_inst, uint32_t num_fault)
{
	status_event_t evt;

	if (status_checker_pipe[1] < 0)
		return;

	memset(&evt, 0, sizeof(evt));
	evt.daemon_type = STATUS_DAEMON_CHECKER;
	evt.overall_state = state;
	evt.num_instances = num_inst;
	evt.num_fault = num_fault;
	evt.sent_time = timer_now();

	if (write(status_checker_pipe[1], &evt, sizeof(evt)) < 0 &&
	    __test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_ERR, "Status socket: Checker pipe write error - %m");
}
#endif

#ifdef _WITH_BFD_
void
status_send_bfd_event(uint8_t state, uint32_t num_inst, uint32_t num_fault)
{
	status_event_t evt;

	if (status_bfd_pipe[1] < 0)
		return;

	memset(&evt, 0, sizeof(evt));
	evt.daemon_type = STATUS_DAEMON_BFD;
	evt.overall_state = state;
	evt.num_instances = num_inst;
	evt.num_fault = num_fault;
	evt.sent_time = timer_now();

	if (write(status_bfd_pipe[1], &evt, sizeof(evt)) < 0 &&
	    __test_bit(LOG_DETAIL_BIT, &debug))
		log_message(LOG_ERR, "Status socket: BFD pipe write error - %m");
}
#endif

#ifdef THREAD_DUMP
void
register_status_socket_addresses(void)
{
	register_thread_address("status_socket_accept", accept_client_connection);
	register_thread_address("status_socket_client", handle_client_request);
#ifdef _WITH_VRRP_
	register_thread_address("status_vrrp_pipe_read", read_vrrp_status_pipe);
#endif
#ifdef _WITH_LVS_
	register_thread_address("status_checker_pipe_read", read_checker_status_pipe);
#endif
#ifdef _WITH_BFD_
	register_thread_address("status_bfd_pipe_read", read_bfd_status_pipe);
#endif
}
#endif

#endif /* _WITH_STATUS_SOCKET_ */
