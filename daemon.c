/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 0.6.3 2002/06/18 21:39:17 acassen Exp $
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
 */

#include "daemon.h"

/* Daemonization function coming from zebra source code */
pid_t xdaemon(int nochdir, int noclose, int exitflag)
{
  pid_t pid;

  /* In case of fork is error. */
  pid = fork ();
  if (pid < 0) {
    perror ("fork");
    return -1;
  }

  /* In case of this is parent process. */
  if (pid != 0 ) {
    if (!exitflag)
      exit(0);
    else
      return pid;
  }

  /* Become session leader and get pid. */
  pid = setsid();
  if (pid < -1) {
    perror ("setsid");
    return -1;
  }

  /* Change directory to root. */
  if (!nochdir)
    chdir ("/");

  /* File descriptor close. */
  if (!noclose) {
    int fd;

    fd = open("/dev/null", O_RDWR, 0);
    if (fd != -1) {
      dup2(fd, STDIN_FILENO);
      dup2(fd, STDOUT_FILENO);
      dup2(fd, STDERR_FILENO);
      if (fd > 2)
        close (fd);
    }
  }

  umask (0);
  return 0;
}
