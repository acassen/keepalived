/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
 *  
 * Version:     $Id: cfreader.c,v 0.2.6 2001/03/01 $
 * 
 * Author:      Alexandre Cassen, <Alexandre.Cassen@wanadoo.fr>
 *              
 * Changes:     
 *              Alexandre Cassen : 2001/03/01 :
 *               <+> Change the dynamic data structure. Move to a tree data
 *                   structure.
 *               <+> Revisited the pointer handling for the dynamic data
 *                   structure.
 *               <+> Adding keywords support for the configuration file.
 *               <+> Adding support for email notification.
 *
 *              Alexandre Cassen : 2000/12/09 : Initial release
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include "cfreader.h"

int AlreadyExist_VS(virtualserver *lstptr, char ip[16], char port[6])
{
  virtualserver *pointerptr=lstptr;

  while(lstptr != NULL) {
    if((strcmp(lstptr->addr_ip,ip)==0) && (strcmp(lstptr->addr_port,port)==0)) {
      lstptr=pointerptr;
      return 1;
    }
    lstptr=(virtualserver *)lstptr->next;
  }
  lstptr=pointerptr;
  return 0;
}

int AlreadyExist_SVR(realserver *lstptr, char ip[16], char port[6])
{
  realserver *pointerptr=lstptr;

  while(lstptr != NULL) {
    if((strcmp(lstptr->addr_ip,ip)==0) && (strcmp(lstptr->addr_port,port)==0)) {
      lstptr=pointerptr;
      return 1;
    }
    lstptr=(realserver *)lstptr->next;
  }
  lstptr=pointerptr;
  return 0;
}

notification_email * AddItem_Email(notification_email *lstemail,notification_email *email)
{
  notification_email *pointerlst=lstemail;

  if (lstemail != NULL) {
    while(lstemail->next != NULL) lstemail=(notification_email *)lstemail->next;
    lstemail->next=(struct notification_email *)email;
    return pointerlst;
  } else {
    lstemail=email;
    return lstemail;
  }
}

virtualserver * AddItem_VS(virtualserver *lstvs,virtualserver *vs)
{
  virtualserver *pointerlst=lstvs;

  if(AlreadyExist_VS(lstvs,vs->addr_ip,vs->addr_port)) return lstvs;

  if (lstvs != NULL) {
    while(lstvs->next != NULL) lstvs=(virtualserver *)lstvs->next;
    lstvs->next=(struct virtualserver *)vs;
    return pointerlst;
  } else {
    lstvs=vs;
    return lstvs;
  }
}

realserver * AddItem_SVR(realserver *lstsvr,realserver *svr)
{
  realserver *pointerlst=lstsvr;

  if(AlreadyExist_SVR(lstsvr,svr->addr_ip,svr->addr_port)) return lstsvr;

  if (lstsvr != NULL) {
    while(lstsvr->next != NULL) lstsvr=(realserver *)lstsvr->next;
    lstsvr->next=(struct realserver *)svr;
    return pointerlst;
  } else {
    lstsvr=svr;
    return lstsvr;
  }
}

urls * AddItem_Url(urls *lsturls,urls *url)
{
  urls *pointerlst=lsturls;

  if (lsturls != NULL) {
    while(lsturls->next != NULL) lsturls=(urls *)lsturls->next;
    lsturls->next=(struct urls *)url;
    return pointerlst;
  } else {
    lsturls=url;
    return lsturls;
  }
}

urls * RemoveUrl(urls * lstptr)
{
  urls *t;

  t=(urls *)lstptr->next;
  free(lstptr);
  return t;
}

realserver * RemoveSVR(realserver * lstptr)
{
  realserver *t;

  t=(realserver *)lstptr->next;

  if(lstptr->method->http_get != NULL) {
    while(lstptr->method->http_get->check_urls != NULL)
      lstptr->method->http_get->check_urls=RemoveUrl(lstptr->method->http_get->check_urls);
    free(lstptr->method->http_get);
  }

  if(lstptr->method->tcp_vanilla != NULL)
    free(lstptr->method->tcp_vanilla);

  free(lstptr->method);
  free(lstptr);
  return t;
}

virtualserver * RemoveVS(virtualserver * lstptr)
{
  virtualserver *t;

  t=(virtualserver *)lstptr->next;
  while(lstptr->svr != NULL) lstptr->svr=RemoveSVR(lstptr->svr);
  free(lstptr);
  return t;
}

notification_email * RemoveEmail(notification_email *lstptr)
{
  notification_email *t;

  t=(notification_email *)lstptr->next;
  free(lstptr);
  return t;
}

void ClearConf(configuration_data * lstptr)
{
  while(lstptr->email != NULL)
    lstptr->email=RemoveEmail(lstptr->email);

  while(lstptr->lvstopology != NULL)
    lstptr->lvstopology=RemoveVS(lstptr->lvstopology);
}

void PrintConf(configuration_data *lstconf)
{
  notification_email *pointeremail;
  virtualserver *pointervs;
  realserver *pointersvr;
  urls *pointerurls;
  char *tempbuffer;

  tempbuffer=(char *)malloc(TEMPBUFFERLENGTH);
  memset(tempbuffer,0,TEMPBUFFERLENGTH);

  if(lstconf == NULL) {
    logmessage("Empty data configuration !!!\n");
  } else {
    logmessage("------< Global definitions >------\n");
    memset(tempbuffer,0,TEMPBUFFERLENGTH);
    sprintf(tempbuffer," LVS ID = %s\n",lstconf->lvs_id);
    logmessage(tempbuffer);
    memset(tempbuffer,0,TEMPBUFFERLENGTH);
    sprintf(tempbuffer," Delay loop = %s, Smtp server = %s\n",
                     lstconf->delay_loop,lstconf->smtp_server);
    logmessage(tempbuffer);
    memset(tempbuffer,0,TEMPBUFFERLENGTH);
    sprintf(tempbuffer," Email notification from = %s\n",lstconf->email_from);
    logmessage(tempbuffer);

    pointeremail=lstconf->email;
    while(lstconf->email != NULL) {
      memset(tempbuffer,0,TEMPBUFFERLENGTH);
      sprintf(tempbuffer," Email notification = %s\n",lstconf->email->addr);
      logmessage(tempbuffer);

      lstconf->email=(notification_email *)lstconf->email->next;
    }
    lstconf->email=pointeremail;

    logmessage("------< LVS Topology >------\n");
    pointervs=lstconf->lvstopology;
    while(lstconf->lvstopology != NULL) {
      memset(tempbuffer,0,TEMPBUFFERLENGTH);
      sprintf(tempbuffer," VS IP = %s, PORT = %s\n",lstconf->lvstopology->addr_ip,
                                                    lstconf->lvstopology->addr_port);
      logmessage(tempbuffer);

      sprintf(tempbuffer," -> lb_algo = %s, lb_kind = %s, persistence = %s, protocol = %s\n",
                         lstconf->lvstopology->sched,lstconf->lvstopology->loadbalancing_kind,
                         lstconf->lvstopology->timeout_persistence,lstconf->lvstopology->service_type);
      logmessage(tempbuffer);

      pointersvr=lstconf->lvstopology->svr;
      while(lstconf->lvstopology->svr != NULL) {
        sprintf(tempbuffer,"    -> SVR IP = %s, PORT = %s, WEIGHT = %s\n",
                           lstconf->lvstopology->svr->addr_ip,lstconf->lvstopology->svr->addr_port,
                           lstconf->lvstopology->svr->weight);
        logmessage(tempbuffer);

        /* Displaying ICMP_CHECK resume */
        if (lstconf->lvstopology->svr->method->flag_type == ICMP_CHECK_ID)
          logmessage("       -> Keepalive method = ICMP_CHECK\n");

        /* Displaying TCP_CHECK resume */
        if (lstconf->lvstopology->svr->method->flag_type == TCP_CHECK_ID) {
          logmessage("       -> Keepalive method = TCP_CHECK\n");
          sprintf(tempbuffer,"       -> Connection timeout = %s\n",
                             lstconf->lvstopology->svr->method->tcp_vanilla->connection_to);
          logmessage(tempbuffer);
        }

        /* Displaying HTTP_GET resume */
        if (lstconf->lvstopology->svr->method->flag_type == HTTP_GET_ID) {
          pointerurls=lstconf->lvstopology->svr->method->http_get->check_urls;
          logmessage("       -> Keepalive method = HTTP_GET\n");
          while (lstconf->lvstopology->svr->method->http_get->check_urls  != NULL) {
            sprintf(tempbuffer,"       -> Url = %s, Digest = %s\n",
                               lstconf->lvstopology->svr->method->http_get->check_urls->url,
                               lstconf->lvstopology->svr->method->http_get->check_urls->digest);
            logmessage(tempbuffer);
            lstconf->lvstopology->svr->method->http_get->check_urls=(urls *)lstconf->lvstopology->svr->method->http_get->check_urls->next;
          }
          lstconf->lvstopology->svr->method->http_get->check_urls=pointerurls;

          sprintf(tempbuffer,"       -> Connection timeout = %s, Nb get retry = %s\n",
                             lstconf->lvstopology->svr->method->http_get->connection_to,
                             lstconf->lvstopology->svr->method->http_get->nb_get_retry);
          logmessage(tempbuffer);
          sprintf(tempbuffer,"       -> Delay before retry = %s\n",
                             lstconf->lvstopology->svr->method->http_get->delay_before_retry);
          logmessage(tempbuffer);
        }

        lstconf->lvstopology->svr=(realserver *)lstconf->lvstopology->svr->next;
      }
      lstconf->lvstopology->svr=pointersvr;

      lstconf->lvstopology=(virtualserver *)lstconf->lvstopology->next;
    }
    lstconf->lvstopology=pointervs;

  }
  free(tempbuffer);
}

configuration_data * ConfReader(configuration_data *conf_data)
{
  FILE *stream;
  char *string="";
  virtualserver *pointervs;
  virtualserver *vsfill;
  realserver *svrfill;
  notification_email *emailfill;
  keepalive_check *methodfill;
  http_get_check *httpgetfill;
  urls *urlsfill;
  tcp_vanilla_check *tcpcheckfill;

  stream=fopen(CONFFILE,"r");
  if(stream==NULL) {
    logmessage("ConfReader : Can not read the config file\n");
    return(NULL);
  }

  string=(char *)malloc(TEMPBUFFERLENGTH);
  memset(string,0,TEMPBUFFERLENGTH);
  conf_data=(configuration_data *)malloc(sizeof(configuration_data));
  memset(conf_data,0,sizeof(configuration_data));

  /* Initialise the dynamic data structure */
  conf_data->email=NULL;
  conf_data->lvstopology=NULL;

  while(!feof(stream)) {
    fscanf(stream,"%s",string);

    /* Fill in the global defs structure */
    if(strcmp(string,GLOBALDEFS) == 0)
      do {
        if(strcmp(string,DELAY) == 0)
          fscanf(stream,"%s",conf_data->delay_loop);
        if(strcmp(string,SMTP) == 0)
          fscanf(stream,"%s",conf_data->smtp_server);
        if(strcmp(string,EMAILFROM) == 0)
          fscanf(stream,"%s",conf_data->email_from);
        if(strcmp(string,LVSID) == 0)
          fscanf(stream,"%s",conf_data->lvs_id);
        if(strcmp(string,EMAIL) == 0)
          do {
            fscanf(stream,"%s",string);
            if(strcmp(string,BEGINFLAG)!=0 && strcmp(string,ENDFLAG)!=0) {
              emailfill=(notification_email *)malloc(sizeof(notification_email));
              memset(emailfill,0,sizeof(notification_email));
              strncat(emailfill->addr,string,sizeof(emailfill->addr));
              emailfill->next=NULL;
              conf_data->email = AddItem_Email(conf_data->email,emailfill);
            }
          } while(strcmp(string,ENDFLAG) != 0);
        fscanf(stream,"%s",string);
      } while(strcmp(string,ENDFLAG) != 0);

    /* Fill in virtual server structure */
    if(strcmp(string,VS) == 0) {
      vsfill=(virtualserver *)malloc(sizeof(virtualserver));
      vsfill->next=NULL;
      conf_data->lvstopology = AddItem_VS(conf_data->lvstopology,vsfill);

      pointervs=conf_data->lvstopology;
      while(conf_data->lvstopology->next != NULL)
        conf_data->lvstopology=(virtualserver *)conf_data->lvstopology->next;

      fscanf(stream,"%s",vsfill->addr_ip);
      fscanf(stream,"%s",vsfill->addr_port);
      do {
        if(strcmp(string,LBSCHED) == 0)
          fscanf(stream,"%s",vsfill->sched);
        if(strcmp(string,LBKIND) == 0)
          fscanf(stream,"%s",vsfill->loadbalancing_kind);
        if(strcmp(string,PTIMEOUT) == 0)
          fscanf(stream,"%s",vsfill->timeout_persistence);
        if(strcmp(string,PROTOCOL) == 0)
          fscanf(stream,"%s",vsfill->service_type);

        /* Fill in real server structure */
        if(strcmp(string,SVR) == 0) {
          svrfill=(realserver *)malloc(sizeof(realserver));
          memset(svrfill,0,sizeof(realserver));
          fscanf(stream,"%s",svrfill->addr_ip);
          fscanf(stream,"%s",svrfill->addr_port);
          svrfill->alive=1;
          do {
            if(strcmp(string,BEGINFLAG)!=0 && strcmp(string,ENDFLAG)!=0) {
              if(strcmp(string,WEIGHT) == 0)
                fscanf(stream,"%s",svrfill->weight);

              if(strcmp(string,ICMPCHECK) == 0) {
                methodfill=(keepalive_check *)malloc(sizeof(keepalive_check));
                memset(methodfill,0,sizeof(keepalive_check));
                methodfill->flag_type=ICMP_CHECK_ID;
                methodfill->http_get=NULL;
                methodfill->tcp_vanilla=NULL;
              }

              if(strcmp(string,TCPCHECK) == 0) {
                methodfill=(keepalive_check *)malloc(sizeof(keepalive_check));
                memset(methodfill,0,sizeof(keepalive_check));
                methodfill->flag_type=TCP_CHECK_ID;
                tcpcheckfill=(tcp_vanilla_check *)malloc(sizeof(tcp_vanilla_check));
                memset(tcpcheckfill,0,sizeof(tcp_vanilla_check));
                do {
                  fscanf(stream,"%s",string);
                  if(strcmp(string,BEGINFLAG)!=0 && strcmp(string,ENDFLAG)!=0) {
                    if(strcmp(string,CTIMEOUT) == 0)
                      fscanf(stream,"%s",tcpcheckfill->connection_to);
                  }
                } while (strcmp(string,ENDFLAG) != 0);
                methodfill->http_get=NULL;
                methodfill->tcp_vanilla=tcpcheckfill;
              }

              if(strcmp(string,HTTPGET) == 0) {
                methodfill=(keepalive_check *)malloc(sizeof(keepalive_check));
                memset(methodfill,0,sizeof(keepalive_check));
                methodfill->flag_type=HTTP_GET_ID;
                httpgetfill=(http_get_check *)malloc(sizeof(http_get_check));
                memset(httpgetfill,0,sizeof(http_get_check));
                httpgetfill->check_urls=NULL;
                do {
                  if(strcmp(string,BEGINFLAG)!=0 && strcmp(string,ENDFLAG)!=0) {

                    if(strcmp(string,CTIMEOUT) == 0)
                      fscanf(stream,"%s",httpgetfill->connection_to);
                    if(strcmp(string,NBGETRETRY) == 0)
                      fscanf(stream,"%s",httpgetfill->nb_get_retry);
                    if(strcmp(string,DELAYRETRY) == 0)
                      fscanf(stream,"%s",httpgetfill->delay_before_retry);

                    if(strcmp(string,URL) == 0) {
                      urlsfill=(urls *)malloc(sizeof(urls));
                      memset(urlsfill,0,sizeof(urls));
                      urlsfill->next=NULL;
                      do {
                        fscanf(stream,"%s",string);
                        if(strcmp(string,BEGINFLAG)!=0 && strcmp(string,ENDFLAG)!=0) {

                          if(strcmp(string,URLPATH) == 0)
                            fscanf(stream,"%s",urlsfill->url);
                          if(strcmp(string,DIGEST) == 0)
                            fscanf(stream,"%s",urlsfill->digest);
                        
                        }
                      } while (strcmp(string,ENDFLAG) != 0);
                      httpgetfill->check_urls=AddItem_Url(httpgetfill->check_urls,urlsfill);
                    }

                  }
                  fscanf(stream,"%s",string);
                } while (strcmp(string,ENDFLAG) != 0);
                methodfill->http_get=httpgetfill;
                methodfill->tcp_vanilla=NULL;
              }
            }
            fscanf(stream,"%s",string);
          } while(strcmp(string,ENDFLAG) != 0);
          svrfill->method=methodfill;
          svrfill->next=NULL;
          conf_data->lvstopology->svr = AddItem_SVR(conf_data->lvstopology->svr,svrfill);
        }

        fscanf(stream,"%s",string);
      } while(strcmp(string,ENDFLAG) != 0);
      conf_data->lvstopology=pointervs;
    }
  }

  free(string);
  fclose(stream);

  return(conf_data);
}
