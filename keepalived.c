/* 
 * Soft:        Keepalived is a failover program for the LVS project 
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Main program structure.
 *  
 * Version:     $Id: keepalived.c,v 0.2.6 2001/03/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:       
 *         Alexandre Cassen : 2001/03/01 :
 *          <+> Adding support for multi-url md5sum check.
 *          <+> Adding pidfile lock.
 *          <+> Change the signalhandling.
 *          <+> Change the dynamic data structure.
 *          <+> Use a global var to stock the daemon pid.
 *
 *          Alexandre Cassen : 2000/12/09 : Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */             

#include "keepalived.h"

int main(int argc, char **argv)
{
  struct sigaction nact, oact;

  printf(PROG" v"VERSION"\n");

  if (chdir(CONF_HOME_DIR)) {
    fprintf(stderr,"%s: ",CONF_HOME_DIR);
    perror(NULL);
    exit(1);
  }

  initdaemonpid(getpid());
  logmessage("Starting keepalived daemon\n");

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

  initdaemonpid(getpid());
  if(keepalived_running()) {
    logmessage("Keepalived is already running.\n");
    return(0);
  } else
    if(!pidfile_write(getpid()))
      logmessage("Can not write keepalived pidfile.\n");

  /* init signal handling */
  sigemptyset(&nact.sa_mask);
  nact.sa_handler = sig_handler;
  nact.sa_flags = SA_RESTART;
  sigaction(SIGALRM,&nact,&oact);
  sigaction(SIGTERM,&nact,&oact);
  sigaction(SIGKILL,&nact,&oact);
  sigaction(SIGSEGV,&nact,&oact);
  sigaction(SIGHUP,&nact,&oact);
  sigaction(SIGINT,&nact,&oact);

  if ((lstCONF=(configuration_data *)ConfReader(lstCONF))==NULL) {
    logmessage("Config file contain no data\n");
    exit(0);
  }

  logmessage("Using LVS dynamic data representation :\n");
  PrintConf(lstCONF);

  if (!init_services(lstCONF->lvstopology)) {
    logmessage("Ending keepalived daemon\n");
    return 0;
  }

  while (keep_going) {
    perform_checks(lstCONF);
    sleep(atoi(lstCONF->delay_loop));
  }
}

static void sig_handler(int signum)
{
  keep_going=0;
  ClearConf(lstCONF);
  logmessage("Ending keepalived daemon\n");
  pidfile_rm();
  exit(1);
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
    logmessage(logbuffer);
    ipvs_pool_cmd(IPVS_CMD_ADD,lstptr);
  } else {
    lstptr->svr->alive=alive;
    memset(logbuffer,0,LOGBUFFER_LENGTH);
    sprintf(logbuffer,"Removing service [%s:%s] from VS [%s:%s]\n",
            lstptr->svr->addr_ip,lstptr->svr->addr_port,
            lstptr->addr_ip,lstptr->addr_port);
    logmessage(logbuffer);
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

void perform_checks(configuration_data *lstconf)
{
  char *MD5Result;
  virtualserver *lstptr;
  realserver *pointersvr;
  urls *pointerurls;
  char *logbuffer;
  int connectionerror;
  int digesterror;

  lstptr=lstconf->lvstopology;

  logbuffer=(char *)malloc(LOGBUFFER_LENGTH);
  MD5Result=(char *)malloc(16*2*sizeof(char *));

  while(lstptr != NULL) {
    pointersvr=lstptr->svr;
    while(lstptr->svr != NULL) {

      if (lstptr->svr->method->flag_type == ICMP_CHECK_ID) {
        if (ICMP_CHECK(lstptr->svr->addr_ip)) {

          if (!lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"ICMP check succeed to %s.\n",lstptr->svr->addr_ip);
            logmessage(logbuffer);
            perform_ipvs(1,lstptr);
            SMTP_SEND_ALERTES(lstconf,lstptr,"UP","=> ICMP CHECK succeed on service <=\n\n"
                                                    "The service has been added to the server pool\n");
          }
        } else {
          if (lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"ICMP check failed to %s.\n",lstptr->svr->addr_ip);
            logmessage(logbuffer);
            perform_ipvs(0,lstptr);
            SMTP_SEND_ALERTES(lstconf,lstptr,"DOWN","=> ICMP CHECK failed on service <=\n\n"
                                                    "The service has been removed from the server pool\n");
          }
        }
      }

      if (lstptr->svr->method->flag_type == TCP_CHECK_ID) {
        if (TCP_CHECK(lstptr->svr->addr_ip,lstptr->svr->addr_port)) {
          if (!lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"TCP check succeed to %s:%s.\n",lstptr->svr->addr_ip,
                                                              lstptr->svr->addr_port);
            logmessage(logbuffer);
            perform_ipvs(1,lstptr);
            SMTP_SEND_ALERTES(lstconf,lstptr,"UP","=> TCP CHECK succeed on service <=\n\n"
                                                    "The service has been added to the server pool\n");
          }
        } else {
          if (lstptr->svr->alive) {
            memset(logbuffer,0,LOGBUFFER_LENGTH);
            sprintf(logbuffer,"TCP check failed to %s:%s.\n",lstptr->svr->addr_ip,
                                                             lstptr->svr->addr_port);
            logmessage(logbuffer);
            perform_ipvs(0,lstptr);
            SMTP_SEND_ALERTES(lstconf,lstptr,"DOWN","=> TCP CHECK failed on service <=\n\n"
                                                    "The service has been removed from the server pool\n");
          }
        }
      }

      if (lstptr->svr->method->flag_type == HTTP_GET_ID) {
        connectionerror=0;
        digesterror=0;

        /* perform the multi urls md5 check */
        pointerurls=lstptr->svr->method->http_get->check_urls;
        while((lstptr->svr->method->http_get->check_urls != NULL) && 
              !connectionerror && !digesterror) {
          memset(MD5Result,0,16*2*sizeof(char *));

          if(!HTTP_GET(lstptr->svr->addr_ip,lstptr->svr->addr_port,
                      lstptr->svr->method->http_get->check_urls->url,MD5Result,
                      atoi(lstptr->svr->method->http_get->connection_to),
                      atoi(lstptr->svr->method->http_get->nb_get_retry),
                      atoi(lstptr->svr->method->http_get->delay_before_retry)))
            connectionerror=1;

          if (strcmp(lstptr->svr->method->http_get->check_urls->digest,MD5Result) != 0)
            digesterror=1;

          lstptr->svr->method->http_get->check_urls=(urls *)lstptr->svr->method->http_get->check_urls->next;
        }
        lstptr->svr->method->http_get->check_urls=pointerurls;

        if(!connectionerror) {

          if (!digesterror) {

            if (!lstptr->svr->alive) {
              memset(logbuffer,0,LOGBUFFER_LENGTH);
              sprintf(logbuffer,"HTTP GET check succeed to %s:%s.\n",lstptr->svr->addr_ip,
                                                                     lstptr->svr->addr_port);
              logmessage(logbuffer);
              perform_ipvs(1,lstptr);
              SMTP_SEND_ALERTES(lstconf,lstptr,"UP","=> HTTP GET check succeed on service <=\n\n"
                                                    "The service has been added to the server pool\n");
            }
          } else {
            if (lstptr->svr->alive) {
              memset(logbuffer,0,LOGBUFFER_LENGTH);
              sprintf(logbuffer,"HTTP GET check failed to %s:%s.\n",lstptr->svr->addr_ip,
                                                                  lstptr->svr->addr_port);
              logmessage(logbuffer);
              perform_ipvs(0,lstptr);
              SMTP_SEND_ALERTES(lstconf,lstptr,"DOWN","=> HTTP GET check failed on service <=\n\n"
                                                      "The service has been removed from the server pool\n");
            }
          }
        } else {
          if(lstptr->svr->alive) {
            perform_ipvs(0,lstptr);
            SMTP_SEND_ALERTES(lstconf,lstptr,"DOWN","=> HTTP GET check failed on service <=\n\n"
                                                    "The service has been removed from the server pool\n");
          }
        }

      }
      lstptr->svr=(realserver *)lstptr->svr->next;
    }
    lstptr->svr=pointersvr;
    lstptr=(virtualserver *)lstptr->next;
  }
  free(MD5Result);
  free(logbuffer);
}
