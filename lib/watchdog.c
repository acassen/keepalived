/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Software watchdog framework.
 *  
 * Version:     $Id: watchdog.c,v 1.1.3 2003/09/29 02:37:13 acassen Exp $
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
 * Copyright (C) 2001, 2002, 2003 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include "watchdog.h"
#include "memory.h"
#include "parser.h"

/* Extern vars */
extern thread_master *master;
extern int reload;

/* Watchdog connection reader */
static int
wdog_read(thread *thread)
{
	int sd;
	int nbytes;
	char *path;
	unsigned char *buf;

	sd = THREAD_FD(thread);
	path = THREAD_ARG(thread);

	/* Wait until read event */
	if (thread->type == THREAD_READ_TIMEOUT) {
		thread_add_read(master, wdog_read, path, sd,
				WATCHDOG_TIMER);
		return 0;
	}

	/* Process incoming data */
	buf = (char *) MALLOC(WDOG_READ_BUFSIZ);
	nbytes = read(sd, buf, WDOG_READ_BUFSIZ);
	if (nbytes <= 0) {
		syslog(LOG_INFO, "Watchdog: Error reading to %s wdog socket",
		       path);
		FREE(buf);
		return -1;
	}

	/* Register next thread */
	thread_add_read(master, wdog_read, path, sd,
			WATCHDOG_TIMER);
	FREE(buf);
	return 0;
}

/* Watchdog connection acceptor */
static int
wdog_accept(thread *thread)
{
	struct sockaddr_un sock;
	int sd, accept_sd;
	int len;
	char *path;

	sd = THREAD_FD(thread);
	path = THREAD_ARG(thread);

	/* Wait until accept event */
	if (thread->type == THREAD_READ_TIMEOUT) {
		thread_add_read(master, wdog_accept, path, sd,
				WATCHDOG_TIMER);
		return 0;
	}

	/* Set unix domain socket */
	memset(&sock, 0, sizeof(struct sockaddr_un));
	len = sizeof(struct sockaddr_un);

	/* Accept incoming connection */
	accept_sd = accept(sd, (struct sockaddr *) &sock, &len);
	if (accept_sd < 0) {
		syslog(LOG_INFO, "Watchdog: Error accepting on %s wdog socket: %s",
		       path, strerror(errno));
		return -1;
	}

	/* Register read thread */
	thread_add_read(master, wdog_read, path, accept_sd,
			WATCHDOG_TIMER);
	return 0;
}

/* Watchdog initialization */
int
wdog_init(char *path)
{
	struct sockaddr_un sock;
	int sd, len, err;
	mode_t old_mask;

	/* Free stalled socket */
	unlink(path);

	/* Mask */
	old_mask = umask(0077);

	/* Simple welcome msg */
	syslog(LOG_INFO, "Watchdog: Starting listener on %s wdog socket"
		       , path);

	/* Create unix domain socket */
	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0) {
		syslog(LOG_INFO, "Watchdog: Error creating %s wdog socket",
		       path);
		return -1;
	}

	/* Create listening socket */
	memset(&sock, 0, sizeof(struct sockaddr_un));
	sock.sun_family = AF_UNIX;
	strncpy(sock.sun_path, path, strlen(path));
	len = sizeof(sock.sun_family) + strlen(path);
	err = bind(sd, (struct sockaddr *) &sock, len);
	if (err < 0) {
		syslog(LOG_INFO, "Watchdog: Error binding %s wdog socket",
		       path);
		close(sd);
		return -1;
	}

	/* Only parent process can connect child wdog listener */
	err = listen(sd, 1);
	if (err < 0) {
		syslog(LOG_INFO, "Watchdog: Error listening %s wdog socket",
		       path);
		close(sd);
		return -1;
	}

	/* Restore old mask */
	umask(old_mask);

	/* Register acceptor thread */
	thread_add_read(master, wdog_accept, path, sd,
			WATCHDOG_TIMER);
	return sd;
}

/* Close watchdog channel */
void
wdog_close(int sd, char *path)
{
	if (sd > 0) {
		close(sd);
		sd = -1;
	}
	if (path)
		unlink(path);
}

/* Watchdog thread */
static int
wdog_thread(thread *thread)
{
	wdog_data *wdata = THREAD_ARG(thread);
	int ret, status;

	/* Refresh if reload */
	if (reload)
		goto reload;

        /* Send watchdog string */
	ret = (send(wdata->wdog_sd, WATCHDOG_STRING, strlen(WATCHDOG_STRING),
		    MSG_NOSIGNAL) != -1) ? 1 : 0;

	/* connection trouble */
	if (!ret) {
		syslog(LOG_INFO, "Watchdog: Error while sending data"
				 " to %s. error=(%s)."
			       , wdata->wdog_string, strerror(errno));

		/* Test if pid is alive */
		if (wdata->wdog_pid > 0) {
			if (kill(wdata->wdog_pid, 0)) {
				/* Process has gone */
				syslog(LOG_INFO, "Watchdog: %s no longer"
						 " exist, restarting..."
					       , wdata->wdog_string);
				close(wdata->wdog_sd);      /* avoid sd leak */
				(*wdata->wdog_start) ();
				return 0;
			} else {
				/* Dead loop detected */
				syslog(LOG_INFO, "Watchdog: %s dead loop"
						 " detected, restarting..."
					       , wdata->wdog_string);
				close(wdata->wdog_sd);      /* avoid sd leak */
				kill(wdata->wdog_pid, SIGTERM);
				wait(&status);
				(*wdata->wdog_start) ();
				return 0;
			}
		}

		/* Unexpected error */
		syslog(LOG_INFO, "Watchdog: %s unexpected error,"
				 " restarting..."
			       , wdata->wdog_string);
		(*wdata->wdog_start) ();
		return 0;
	}

	/* Register next timer thread */
	thread_add_timer(master, wdog_thread, wdata, WATCHDOG_DELAY);
	return 0;

reload:
	close(wdata->wdog_sd);
	wdata->wdog_sd = -1;
	thread_add_timer(master, wdog_boot_thread, wdata,
			 WATCHDOG_DELAY);
	return 0;
}

/* Client watchdog channel */
static int
wdog_connect(wdog_data *wdata)
{
	struct sockaddr_un sock;
	int len, err;

	/* Create unix domain socket */
	wdata->wdog_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (wdata->wdog_sd < 0) {
		syslog(LOG_INFO, "Watchdog: Error creating %s wdog connect socket",
		       wdata->wdog_path);
		return -1;
	}

	/* create connection socket */
	memset(&sock, 0, sizeof(struct sockaddr_un));
	sock.sun_family = AF_UNIX;
	strncpy(sock.sun_path, wdata->wdog_path, strlen(wdata->wdog_path));
	len = sizeof(sock.sun_family) + strlen(wdata->wdog_path);
	err = connect(wdata->wdog_sd, (struct sockaddr *) &sock, len);
	if (err < 0) {
		syslog(LOG_INFO, "Watchdog: Error connecting %s wdog socket",
		       wdata->wdog_path);
		close(wdata->wdog_sd);
		return -1;
	}
	
	/* Register watchdog handler */
	syslog(LOG_INFO, "Watchdog: success connecting %s wdog socket",
	       wdata->wdog_path);

	/* First connection succes unset reload flag */
	if (reload)
		UNSET_RELOAD;
	thread_add_timer(master, wdog_thread, wdata, WATCHDOG_DELAY);
	return 0;
}

/* Bootstrap thread */
int
wdog_boot_thread(thread *thread)
{
	wdog_data *wdata = THREAD_ARG(thread);
	int err;

	/* connect VRRP child domain socket */
	err = wdog_connect(wdata);

	/* Retry child connect until success */
	if (err < 0)
		thread_add_timer(master, wdog_boot_thread,
				 wdata, WATCHDOG_DELAY);
	return 0;
}
