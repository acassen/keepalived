/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *
 * Version:     $Id: main.c,v 0.3.8 2001/11/04 21:41:32 acassen Exp $
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

#include "main.h"

/* SIGHUP handler */
void sighup(int sig)
{
  syslog(LOG_INFO, "Terminating on signal");

  /* register the terminate thread */
  thread_add_terminate_event(master);
}

/* Signal wrapper */
void * signal_set(int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0)
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* Initialize signal handler */
void signal_init()
{
  signal_set (SIGHUP,  sighup);
  signal_set (SIGINT,  sighup);
  signal_set (SIGTERM, sighup);
  signal_set (SIGKILL, sighup);
}

/* Daemonization function coming from zebra source code */
int daemon (int nochdir, int noclose)
{
  pid_t pid;

  pid = fork ();

  /* In case of fork is error. */
  if (pid < 0) {
    perror ("fork");
    return -1;
  }

  /* In case of this is parent process. */
  if (pid != 0)
    exit (0);

  /* Become session leader and get pid. */
  pid = setsid();

  if (pid < -1) {
    perror ("setsid");
    return -1;
  }

  /* Change directory to root. */
  if (! nochdir)
    chdir ("/");

  /* File descriptor close. */
  if (! noclose) {
    int fd;

    fd = open ("/dev/null", O_RDWR, 0);
    if (fd != -1) {
      dup2 (fd, STDIN_FILENO);
      dup2 (fd, STDOUT_FILENO);
      dup2 (fd, STDERR_FILENO);
      if (fd > 2)
        close (fd);
    }
  }

  umask (0);

  return 0;
}

/* Entry point */
int main(int argc, char **argv)
{
  configuration_data *conf_data;
  struct thread thread;

  openlog(PROG,LOG_PID, LOG_DAEMON);
  syslog(LOG_INFO, "Starting "PROG" v"VERSION);

  /* Check if keepalived is already running */
  if (keepalived_running()) {
    syslog(LOG_INFO, "Stopping "PROG" v"VERSION);
    closelog();
    exit(0);
  }
  /* write the pidfile */
  if (!pidfile_write(getpid())) {
    syslog(LOG_INFO, "Stopping "PROG" v"VERSION);
    closelog();
    exit(0);
  }

  /* Parse the configuration file */
  if (!(conf_data = (configuration_data *)conf_reader())) {
    closelog();
    exit(0);
  }

#ifdef DEBUG
  dump_conf(conf_data);
#endif

  if (!init_services(conf_data->lvstopology)) {
    syslog(LOG_INFO, "Stopping "PROG" v"VERSION);
    closelog();
    clear_conf(conf_data);
    exit(0);
  }

  /* Signal handling initialization  */
  signal_init();

  /* daemonize process */
  daemon(0, 0);

  /* Create the master thread */
  master = thread_make_master();

  /* registering worker threads */
  register_worker_thread(master, conf_data);

  /* processing the master thread queues, return and execute one ready thread */
  while(thread_fetch(master, &thread))
    thread_call(&thread);

  /* Reached when terminate signal catched */
  syslog(LOG_INFO, "Stopping "PROG" v"VERSION);

  /* We then cleanup the room & closelog */
  thread_destroy_master(master);
  clear_services(conf_data->lvstopology);
  clear_conf(conf_data);
  closelog();
  pidfile_rm();

  /* finally return from system */
  exit(0);
}
