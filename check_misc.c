/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        MISC CHECK. Perform a system call to run an extra
 *              system prog or script.
 *
 * Version:     $Id: check_misc.c,v 0.5.5 2002/04/10 02:34:23 acassen Exp $
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
#include "check_api.h"
#include "memory.h"
#include "ipwrapper.h"
#include "smtp.h"
#include "utils.h"
#include "parser.h"
#include "daemon.h"

int misc_check_thread(thread *);

/* Configuration stream handling */
void free_misc_check(void *data)
{
  misc_checker *misc_chk = CHECKER_DATA(data);

  FREE(misc_chk->path);
  FREE(misc_chk);
  FREE(data);
}
void dump_misc_check(void *data)
{
  misc_checker *misc_chk = CHECKER_DATA(data);

  syslog(LOG_INFO, "   Keepalive method = MISC_CHECK");
  syslog(LOG_INFO, "   script = %s"
                 , misc_chk->path);
}
void misc_check_handler(vector strvec)
{
  misc_checker *misc_chk = (misc_checker *)MALLOC(sizeof(misc_checker));

  /* queue new checker */
  queue_checker(free_misc_check, dump_misc_check
                               , misc_check_thread
                               , misc_chk);
}
void misc_path_handler(vector strvec)
{
  misc_checker *misc_chk = CHECKER_GET();

  misc_chk->path = CHECKER_VALUE_STRING(strvec);
}
void install_misc_check_keyword(void)
{
  install_keyword("MISC_CHECK", &misc_check_handler);
  install_sublevel();
    install_keyword("misc_path", &misc_path_handler);
  install_sublevel_end();
}

int misc_check_call(char* cmdline)
{
  int retval;

  retval = system(cmdline);

  if (retval == 127) {
    /* couldn't exec command */
    syslog(LOG_DEBUG, "Couldn't exec command: %s", cmdline);
  } else if (retval == -1) {
    /* other error */
    syslog(LOG_DEBUG, "Error exec-ing command: %s", cmdline);
  } else {
    /* everything is good */
    syslog(LOG_DEBUG, "Successfully exec command: %s retval is %d"
                    , cmdline, retval);
  }

  return retval;
}

int misc_check_thread(thread *thread)
{
  checker *checker;
  misc_checker *misc_chk;
  int status;

  checker  = THREAD_ARG(thread);
  misc_chk = CHECKER_ARG(checker);

  /* Register next timer checker */
  thread_add_timer(thread->master, misc_check_thread
                                 , checker
                                 , checker->vs->delay_loop);

  /* Daemonization to not degrade our scheduling timer */
  if (xdaemon(0, 0, 1))
    return 0x80000000;

  status = misc_check_call(misc_chk->path);

  if (status >= 0) { /* script error assumed  not an svr error */
    if (status == 0) {
      /* everything is good */
      if (!checker->rs->alive) {
        smtp_alert(thread->master, checker->rs
                                 , "UP"
                                 , "=> MISC CHECK succeed on service <=\n\n");
        perform_svr_state(UP, checker->vs, checker->rs);
      }
    } else {
      if (checker->rs->alive) {
        smtp_alert(thread->master, checker->rs
                                 , "DOWN"
                                 , "=> MISC CHECK failed on service <=\n\n");
        perform_svr_state(DOWN, checker->vs, checker->rs);
      }
    }
  }

  exit(0);
}
