/* 
 * Soft:        Keepalived is a failover program for the LVS project 
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *  
 * Version:     $Id: keepalived.c,v 0.2.1 2000/12/09 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:       
 *              Alexandre Cassen      :       Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */             

#include "keepalived.h"

int main(int argc, char **argv)
{
  printf(PROG" v"VERSION"\n");

  if (chdir(CONF_HOME_DIR)) {
    fprintf(stderr,"%s: ",CONF_HOME_DIR);
    perror(NULL);
    exit(1);
  }

  logmessage("Starting keepalived daemon\n",getpid());

  switch (fork()) {
    case -1:
      perror("fork()");
      exit(3);
    case 0:
      close(STDIN_FILENO);
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
      if (setsid() == -1) exit(4);
      break;
    default:
      return 0;
  }

  if (signal(SIGTERM,sig_handler) == SIG_IGN)
    signal(SIGTERM,SIG_IGN);

  signal(SIGINT,sig_handler);
  signal(SIGHUP,sig_handler);

  if ((lstVS=(virtualserver *)ConfReader(lstVS,delay_loop))==NULL) {
    logmessage("Config file contain no data\n",getpid());
    exit(0);
  }

  if (!init_services(lstVS)) {
    logmessage("Ending keepalived daemon\n",getpid());
    return 0;
  }

  logmessage("Using LVS dynamic data representation :\n",getpid());
  PrintLst(lstVS);

  while (keep_going) {
    perform_checks(lstVS);
/*    sleep(delay_loop); */
    sleep(60);
  }

  return 0;
}

void sig_handler(int signum)
{
  keep_going=0;
  ClearLst(lstVS);
  logmessage("Ending keepalived daemon\n",getpid());
  signal(signum,sig_handler);
}

void perform_ipvs(int alive, virtualserver *lstptr)
{
  char *logbuffer;
  
  logbuffer=(char *)malloc(LOGBUFFER_LENGTH);

  if (!lstptr->svr->alive && alive) {
    lstptr->svr->alive=alive;
    memset(logbuffer,0,LOGBUFFER_LENGTH);
    sprintf(logbuffer,"Adding service [%s:%s] to VS [%s:%s]\n",
            lstptr->svr->addr_ip,lstptr->svr->addr_port,
            lstptr->addr_ip,lstptr->addr_port);
    logmessage(logbuffer,getpid());
    ipvs_pool_cmd(IPVS_CMD_ADD,lstptr);
  } else {
    lstptr->svr->alive=alive;
    memset(logbuffer,0,LOGBUFFER_LENGTH);
    sprintf(logbuffer,"Removing service [%s:%s] from VS [%s:%s]\n",
            lstptr->svr->addr_ip,lstptr->svr->addr_port,
            lstptr->addr_ip,lstptr->addr_port);
    logmessage(logbuffer,getpid());
    ipvs_pool_cmd(IPVS_CMD_DEL,lstptr);
  }
  free(logbuffer);
}

int init_services(virtualserver *lstptr)
{
  realserver *pointersvr;

  while(lstptr != NULL) {
    pointersvr=lstptr->svr;
    while(lstptr->svr != NULL) {
      if (!ipvs_pool_cmd(IPVS_CMD_ADD,lstptr))
        return 0;
      lstptr->svr=(realserver *)lstptr->svr->next;
    }
    lstptr->svr=pointersvr;
    lstptr=(virtualserver *)lstptr->next;
  }
  return 1;
}

void perform_checks(virtualserver * lstptr)
{
  char MD5Result[0x40];
  realserver *pointersvr;
  char *logbuffer;

  logbuffer=(char *)malloc(LOGBUFFER_LENGTH);

  while(lstptr != NULL) {
    pointersvr=lstptr->svr;
    while(lstptr->svr != NULL) {

      if (strcmp(lstptr->svr->keepalive_method,"ICMP_CHECK") == 0) {
        if (ICMP_CHECK(lstptr->svr->addr_ip)) {
          if (!lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"ICMP check succeed to %s.\n",lstptr->svr->addr_ip);
            logmessage(logbuffer,getpid());
            perform_ipvs(1,lstptr);
          }
        } else {
          if (lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"ICMP check failed to %s.\n",lstptr->svr->addr_ip);
            logmessage(logbuffer,getpid());
            perform_ipvs(0,lstptr);
          }
        }
      }

      if (strcmp(lstptr->svr->keepalive_method,"TCP_CHECK") == 0) {
        if (TCP_CHECK(lstptr->addr_ip,lstptr->svr->addr_ip,lstptr->svr->addr_port)) {
          logmessage("TCP check succeed\n",getpid());
          if (!lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"TCP check succeed to %s:%s.\n",lstptr->svr->addr_ip,
                                                              lstptr->svr->addr_port);
            logmessage(logbuffer,getpid());
            perform_ipvs(1,lstptr);
          }
        } else {
          logmessage("TCP check failed\n",getpid());
          if (lstptr->svr->alive) {
            bzero(logbuffer,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"TCP check failed to %s:%s.\n",lstptr->svr->addr_ip,
                                                             lstptr->svr->addr_port);
            logmessage(logbuffer,getpid());
            perform_ipvs(0,lstptr);
          }
        }
      }

      if (strcmp(lstptr->svr->keepalive_method,"HTTP_GET") == 0) {

        if(HTTP_GET(lstptr->addr_ip,lstptr->svr->addr_ip,lstptr->svr->addr_port,
                 lstptr->svr->keepalive_url,MD5Result)) {

          if (strcmp(lstptr->svr->keepalive_result,MD5Result) == 0) {
            logmessage("HTTP GET check succeed\n",getpid());
            if (!lstptr->svr->alive) {
              memset(logbuffer,0,LOGBUFFER_LENGTH);
              sprintf(logbuffer,"HTTP GET check succeed to %s:%s.\n",lstptr->svr->addr_ip,
                                                                     lstptr->svr->addr_port);
              logmessage(logbuffer,getpid());
              perform_ipvs(1,lstptr);
            }
          } else {
            logmessage("HTTP GET check failed\n",getpid());
            if (lstptr->svr->alive) {
              memset(logbuffer,0,LOGBUFFER_LENGTH);
              sprintf(logbuffer,"HTTP GET check failed to %s:%s.\n",lstptr->svr->addr_ip,
                                                                  lstptr->svr->addr_port);
              logmessage(logbuffer,getpid());
              perform_ipvs(0,lstptr);
            }
          }
        } else {
          if(lstptr->svr->alive) {
            perform_ipvs(0,lstptr);
          }
        }

      }
      lstptr->svr=(realserver *)lstptr->svr->next;
    }
    lstptr->svr=pointersvr;
    lstptr=(virtualserver *)lstptr->next;
  }
  free(logbuffer);
}
