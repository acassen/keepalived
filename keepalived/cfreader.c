/* 
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 * 
 * Part:        Configuration file parser/reader. Place into the dynamic
 *              data structure representation the conf file representing
 *              the loadbalanced server pool.
 *  
 * Version:     $Id: cfreader.c,v 0.2.1 2000/12/09 $
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

virtualserver * AddItem_VS(virtualserver *lstptr, char ip[16], char port[6], char sched[6], char tpersistence[4])
{
  virtualserver *pointerlst=lstptr;

  if(AlreadyExist_VS(lstptr,ip,port)) return lstptr;

  if (lstptr != NULL) {
    while(lstptr->next != NULL) lstptr=(virtualserver *)lstptr->next;
    lstptr->next=(struct virtualserver *)malloc(sizeof(virtualserver));
    lstptr=(virtualserver *)lstptr->next;
    lstptr->svr=NULL;
    lstptr->next=NULL;
    
    /* Fill in the data structure */
    strncat(lstptr->addr_ip,ip,sizeof(lstptr->addr_ip));
    strncat(lstptr->addr_port,port,sizeof(lstptr->addr_port));
    strncat(lstptr->sched,sched,sizeof(lstptr->sched));
    strncat(lstptr->timeout_persistence,tpersistence,sizeof(lstptr->timeout_persistence));
    
    return pointerlst;
  } else {
    lstptr=(virtualserver *)malloc(sizeof(virtualserver));
    lstptr->svr=NULL;
    lstptr->next=NULL;
    
    /* Fill in the data structure */
    strncat(lstptr->addr_ip,ip,sizeof(lstptr->addr_ip));
    strncat(lstptr->addr_port,port,sizeof(lstptr->addr_port));
    strncat(lstptr->sched,sched,sizeof(lstptr->sched));
    strncat(lstptr->timeout_persistence,tpersistence,sizeof(lstptr->timeout_persistence));

    return lstptr;
  }
}

virtualserver * AddItem_SVR(virtualserver *lstvs, 
                            char ip_vs[16], char port_vs[6],
                            realserver *server)
{
  virtualserver *pointerlst=lstvs;
  realserver *pointersvr;


  while( (lstvs->next != NULL) && 
         !((strcmp(lstvs->addr_ip,ip_vs)==0)  &&
           (strcmp(lstvs->addr_port,port_vs)==0)) )
    lstvs=(virtualserver *)lstvs->next;
  
  if( (strcmp(lstvs->addr_ip,ip_vs)==0) && 
      (strcmp(lstvs->addr_port,port_vs)==0) ) {

    if(AlreadyExist_SVR(lstvs->svr,server->addr_ip,server->addr_port)) return pointerlst;

    if (lstvs->svr != NULL) {
      pointersvr=lstvs->svr;

      while(lstvs->svr->next != NULL) lstvs->svr=(realserver *)lstvs->svr->next;

      lstvs->svr->next=(struct realserver *)server;

      lstvs->svr=pointersvr;
    } else {
      lstvs->svr=(realserver *)server;
    }
  }
  return pointerlst;
}

void PrintLst(virtualserver * lstptr)
{
  realserver *pointersvr;
  char *tempbuff;

  tempbuff=(char *)malloc(TEMPBUFFERLENGTH);
  
  if(lstptr == NULL) 
    printf("Queue empty !!!\n");
  else
    while(lstptr != NULL) {
      memset(tempbuff,0,TEMPBUFFERLENGTH);
      sprintf(tempbuff,"VS IP = %s, Port = %s, SCHED = %s, PERSISTENCE TIMEOUT = %s\n",
                       lstptr->addr_ip, lstptr->addr_port,
                       lstptr->sched, lstptr->timeout_persistence);
      logmessage(tempbuff,getpid());
      pointersvr=lstptr->svr;
      while(lstptr->svr != NULL) {
        memset(tempbuff,0,TEMPBUFFERLENGTH);
        sprintf(tempbuff," -> SVR IP = %s, Port = %s\n",lstptr->svr->addr_ip,lstptr->svr->addr_port);
        logmessage(tempbuff,getpid());

        memset(tempbuff,0,TEMPBUFFERLENGTH);
        sprintf(tempbuff,"    -> KM = %s, KA = %s, KU = %s, KR = %s\n",
                         lstptr->svr->keepalive_method, lstptr->svr->keepalive_url,
                         lstptr->svr->keepalive_algo, lstptr->svr->keepalive_result);
        logmessage(tempbuff,getpid());

        memset(tempbuff,0,TEMPBUFFERLENGTH);
        sprintf(tempbuff,"    -> LB = %s, Weight = %s, ST = %s, Alive = %d\n",
                         lstptr->svr->loadbalancing_kind, lstptr->svr->weight,
                         lstptr->svr->service_type, lstptr->svr->alive);
        logmessage(tempbuff,getpid());

        lstptr->svr=(realserver *)lstptr->svr->next;
      }
      lstptr->svr=pointersvr;
      lstptr=(virtualserver *)lstptr->next;
    }
  free(tempbuff);
}

realserver * RemoveSVR(realserver * lstptr)
{
  realserver *t;

//  printf("  Removing SVR : (%s,%s)\n",lstptr->addr_ip,lstptr->addr_port);
  t=(realserver *)lstptr->next;
  free(lstptr);
  return t;
}

virtualserver * RemoveVS(virtualserver * lstptr)
{
  virtualserver *t;

//  printf("Removing VS : (%s,%s)\n",lstptr->addr_ip,lstptr->addr_port);
  t=(virtualserver *)lstptr->next;
  while(lstptr->svr != NULL) lstptr->svr=RemoveSVR(lstptr->svr);
  free(lstptr);
  return t;
}

void ClearLst(virtualserver * lstptr)
{
  while(lstptr != NULL) {
    lstptr=RemoveVS(lstptr);
  }
}

virtualserver * AddItem(virtualserver *lstvs, char ip_vs[16], char port_vs[6],
                            char ip_svr[16], char port_svr[16], char kmethod[12],
                            char kurl[101],char kalgo[11], char kresult[33], char lbkind[6],
                            char weight[4], char stype[4])
{
  realserver *server;
  server=(realserver *)malloc(sizeof(realserver));

  strncat(server->addr_ip,ip_svr,sizeof(server->addr_ip));
  strncat(server->addr_port,port_svr,sizeof(server->addr_port));
  strncat(server->keepalive_method,kmethod,sizeof(server->keepalive_method));
  strncat(server->keepalive_url,kurl,sizeof(server->keepalive_url));
  strncat(server->keepalive_algo,kalgo,sizeof(server->keepalive_algo));
  strncat(server->keepalive_result,kresult,sizeof(server->keepalive_result));
  strncat(server->loadbalancing_kind,lbkind,sizeof(server->loadbalancing_kind));
  strncat(server->weight,weight,sizeof(server->weight));
  strncat(server->service_type,stype,sizeof(server->service_type));

  server->alive=1;
  server->next=NULL;

  lstvs=AddItem_SVR(lstvs,ip_vs,port_vs,server);

  return lstvs;
}

virtualserver * ConfReader(virtualserver *lst_vs, int delay_loop)
{
  FILE *stream;
  char *string="";
  virtualserver *vsfill;
  realserver *svrfill;

  lst_vs=NULL; /* Initialise the dynamic data structure */

  string=(char *)malloc(TEMPBUFFERLENGTH);
  vsfill=(virtualserver *)malloc(sizeof(virtualserver));
  svrfill=(realserver *)malloc(sizeof(realserver));
  svrfill->alive=1;
  svrfill->next=NULL;
 
  stream=fopen(CONFFILE,"r");
  if(stream==NULL) {
    logmessage("ConfReader : Can not read the config file\n",getpid());
    return(NULL);
  }

  while(!feof(stream)) {
    fscanf(stream,"%s",string);
    if(strcmp(string,DELAYWORD) == 0) {
      fscanf(stream,"%s",string);
      delay_loop=atoi(string);
    }
    if(strcmp(string,VSWORD) == 0) {
      fscanf(stream,"%s",vsfill->addr_ip);
      fscanf(stream,"%s",vsfill->addr_port);
      fscanf(stream,"%s",vsfill->sched);
      fscanf(stream,"%s",vsfill->timeout_persistence);
      lst_vs = AddItem_VS(lst_vs,vsfill->addr_ip,vsfill->addr_port,vsfill->sched,
                          vsfill->timeout_persistence);
      fscanf(stream,"%s",string);
      fscanf(stream,"%s",string);
      do {
        if(strcmp(string,SVRWORD) == 0) {
          fscanf(stream,"%s",svrfill->addr_ip);
          fscanf(stream,"%s",svrfill->addr_port);
          fscanf(stream,"%s",string);
          fscanf(stream,"%s",svrfill->keepalive_method);
          fscanf(stream,"%s",svrfill->keepalive_url);
          fscanf(stream,"%s",svrfill->keepalive_algo);
          fscanf(stream,"%s",svrfill->keepalive_result);
          fscanf(stream,"%s",svrfill->loadbalancing_kind);
          fscanf(stream,"%s",svrfill->weight);
          fscanf(stream,"%s",svrfill->service_type);
          fscanf(stream,"%s",string);

          lst_vs = AddItem(lst_vs,vsfill->addr_ip,vsfill->addr_port,
                                  svrfill->addr_ip,svrfill->addr_port,svrfill->keepalive_method,
                                  svrfill->keepalive_url,svrfill->keepalive_algo,
                                  svrfill->keepalive_result,svrfill->loadbalancing_kind,
                                  svrfill->weight,
                                  svrfill->service_type); 
        }
        fscanf(stream,"%s",string);
      } while(strcmp(string,ENDFLAG) != 0);
    }
  }

  free(string);
  free(vsfill);
  free(svrfill);
  fclose(stream);

  return lst_vs;
}
