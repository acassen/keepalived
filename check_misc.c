/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        MISC CHECK. Perform a system call to run an extra
 *              system prog or script.
 *
 * Version:     $Id: check_misc.c,v 0.4.9a 2001/12/20 17:14:25 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Eric Jarman, <ehj38230@cmsu2.cmsu.edu>
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

#include "check_misc.h"

/* does this need to be threaded? */
int misc_check_call(char* cmdline)
{
  int retval;

  retval = system(cmdline);

  if (retval == 127) {
    /* couldn't exec command */
    syslog(LOG_DEBUG,"Couldn't exec command: %s", cmdline);
  } else if (retval == -1) {
    /* other error */
    syslog(LOG_DEBUG,"Error exec-ing command: %s", cmdline);
  } else {
    /* everything is good */
    syslog(LOG_DEBUG, "Successfully exec command: %s retval is %d"
                    , cmdline, retval);
  }

  return retval;
}

int misc_check_thread(thread *thread)
{
  thread_arg *thread_arg;
  int status;

  thread_arg = THREAD_ARG(thread);

  status = misc_check_call(thread_arg->svr->method->u.misc_check_path);

  if (status == 0) {
    /* everything is good */
    if (!thread_arg->svr->alive) {
      perform_svr_state(UP, thread_arg->vs, thread_arg->svr);
    }
  } else {
   if (thread_arg->svr->alive) {
     perform_svr_state(DOWN, thread_arg->vs, thread_arg->svr);
   }
  }

  /* Register next timer checker */
  thread_add_timer(thread->master, misc_check_thread, thread_arg,
  thread_arg->vs->delay_loop);

  return 0;
}
