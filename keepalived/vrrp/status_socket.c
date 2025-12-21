/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Unix socket for status queries and health checks.
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
#include "scheduler.h"
#include "logger.h"
#include "global_data.h"
#include "vrrp_data.h"
#include "vrrp.h"
#include "list_head.h"
#include "memory.h"

#define STATUS_SOCKET_DEFAULT_PATH	"/var/run/keepalived/status.sock"
#define STATUS_SOCKET_BACKLOG		5
#define STATUS_SOCKET_TIMEOUT		(5 * TIMER_HZ)
#define STATUS_SOCKET_MAX_REQUEST	64
#define STATUS_SOCKET_MAX_RESPONSE	4096

static int status_socket_fd = -1;
static thread_master_t *status_master;

static const char *
state_to_string(int state)
{
	switch (state) {
	case VRRP_STATE_INIT:
		return "INIT";
	case VRRP_STATE_BACK:
		return "BACKUP";
	case VRRP_STATE_MAST:
		return "MASTER";
	case VRRP_STATE_FAULT:
		return "FAULT";
	case VRRP_STATE_STOP:
		return "STOP";
	default:
		return "UNKNOWN";
	}
}

static void
build_health_response(char *buf, size_t bufsize)
{
	vrrp_t *vrrp;
	bool has_fault = false;
	bool has_master = false;

	if (!vrrp_data || list_empty(&vrrp_data->vrrp)) {
		snprintf(buf, bufsize, "UNKNOWN\n");
		return;
	}

	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		if (vrrp->state == VRRP_STATE_FAULT)
			has_fault = true;
		if (vrrp->state == VRRP_STATE_MAST)
			has_master = true;
	}

	if (has_fault)
		snprintf(buf, bufsize, "FAULT\n");
	else if (has_master)
		snprintf(buf, bufsize, "MASTER\n");
	else
		snprintf(buf, bufsize, "BACKUP\n");
}

static void
build_status_response(char *buf, size_t bufsize)
{
	vrrp_t *vrrp;
	int len;
	size_t remaining = bufsize;
	char *p = buf;

	if (!vrrp_data || list_empty(&vrrp_data->vrrp)) {
		snprintf(buf, bufsize, "{\"instances\":[]}\n");
		return;
	}

	len = snprintf(p, remaining, "{\"instances\":[");
	if (len < 0 || (size_t)len >= remaining)
		return;
	p += len;
	remaining -= len;

	bool first = true;
	list_for_each_entry(vrrp, &vrrp_data->vrrp, e_list) {
		len = snprintf(p, remaining, "%s{\"name\":\"%s\",\"state\":\"%s\",\"vrid\":%u,\"priority\":%u}",
			       first ? "" : ",",
			       vrrp->iname,
			       state_to_string(vrrp->state),
			       vrrp->vrid,
			       vrrp->effective_priority);
		if (len < 0 || (size_t)len >= remaining)
			break;
		p += len;
		remaining -= len;
		first = false;
	}

	snprintf(p, remaining, "]}\n");
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
		snprintf(response, sizeof(response), "ERROR: Unknown command. Use HEALTH or STATUS.\n");
	}

	if (write(client_fd, response, strlen(response)) < 0)
		log_message(LOG_INFO, "Status socket: write to client failed - %s", strerror(errno));

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

bool
status_socket_init(thread_master_t *m)
{
	struct sockaddr_un addr;
	const char *path;
	mode_t mode;

	if (!global_data->enable_status_socket)
		return true;

	status_master = m;
	path = global_data->status_socket_path ? global_data->status_socket_path : STATUS_SOCKET_DEFAULT_PATH;
	mode = global_data->status_socket_mode ? global_data->status_socket_mode : 0600;

	/* Remove stale socket */
	unlink(path);

	status_socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (status_socket_fd < 0) {
		log_message(LOG_INFO, "Status socket: failed to create socket - %s", strerror(errno));
		return false;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(status_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_message(LOG_INFO, "Status socket: failed to bind to %s - %s", path, strerror(errno));
		close(status_socket_fd);
		status_socket_fd = -1;
		return false;
	}

	if (chmod(path, mode) < 0)
		log_message(LOG_INFO, "Status socket: failed to set permissions on %s - %s", path, strerror(errno));

	if (listen(status_socket_fd, STATUS_SOCKET_BACKLOG) < 0) {
		log_message(LOG_INFO, "Status socket: failed to listen on %s - %s", path, strerror(errno));
		close(status_socket_fd);
		status_socket_fd = -1;
		unlink(path);
		return false;
	}

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

	if (global_data && global_data->status_socket_path)
		path = global_data->status_socket_path;
	else
		path = STATUS_SOCKET_DEFAULT_PATH;

	unlink(path);
}

#ifdef THREAD_DUMP
void
register_status_socket_addresses(void)
{
	register_thread_address("status_socket_accept", accept_client_connection);
	register_thread_address("status_socket_client", handle_client_request);
}
#endif

#endif /* _WITH_STATUS_SOCKET_ */
