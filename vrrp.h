/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Version:     $Id: vrrp.h,v 0.4.0 2001/08/24 00:35:19 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              Based on the Jerome Etienne, <jetienne@arobas.net> code.
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

#ifndef _VRRP_H
#define _VRRP_H

/* system include */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

/* local include */
#include "vrrp_iproute.h"
#include "vrrp_ipaddress.h"
#include "vrrp_ipsecah.h"

typedef struct {	/* rfc2338.5.1 */
	uint8_t		vers_type;	/* 0-3=type, 4-7=version */
	uint8_t		vrid;		/* virtual router id */
	uint8_t		priority;	/* router priority */
	uint8_t		naddr;		/* address counter */
	uint8_t		auth_type;	/* authentification type */
	uint8_t		adver_int;	/* advertissement interval(in sec) */
	uint16_t	chksum;		/* checksum (ip-like one) */
/* here <naddr> ip addresses */
/* here authentification infos */
} vrrp_pkt;

/* protocol constants */
#define INADDR_VRRP_GROUP 0xe0000012	/* multicast addr - rfc2338.5.2.2 */
#define VRRP_IP_TTL	255	/* in and out pkt ttl -- rfc2338.5.2.3 */
#define IPPROTO_VRRP	112	/* IP protocol number -- rfc2338.5.2.4*/
#define VRRP_VERSION	2	/* current version -- rfc2338.5.3.1 */
#define VRRP_PKT_ADVERT	1	/* packet type -- rfc2338.5.3.2 */
#define VRRP_PRIO_OWNER	255	/* priority of the ip owner -- rfc2338.5.3.4 */
#define VRRP_PRIO_DFL	100	/* default priority -- rfc2338.5.3.4 */
#define VRRP_PRIO_STOP	0	/* priority to stop -- rfc2338.5.3.4 */
#define VRRP_AUTH_NONE	0	/* no authentification -- rfc2338.5.3.6 */
#define VRRP_AUTH_PASS	1	/* password authentification -- rfc2338.5.3.6 */
#define VRRP_AUTH_AH	2	/* AH(IPSec) authentification - rfc2338.5.3.6 */
#define VRRP_ADVER_DFL	1	/* advert. interval (in sec) -- rfc2338.5.3.7 */
#define VRRP_PREEMPT_DFL 1	/* rfc2338.6.1.2.Preempt_Mode */

typedef struct {	/* parameters per interface -- rfc2338.6.1.1 */
	int		auth_type;	/* authentification type. VRRP_AUTH_* */
	uint8_t		auth_data[8];	/* authentification data */

	uint32_t	ipaddr;		/* the address of the interface */
	char		hwaddr[6];	/* hardcoded for ethernet */
	char		ifname[10];	/* the device name for this ipaddr */
	/*
	 * To have my own ip_id creates collision with kernel ip->id
	 * but it should be ok because the packets are unlikely to be
	 * fragmented (they are non routable and small)
	 * This packet isnt routed, i can check the outgoing MTU
	 * to warn the user only if the outoing mtu is too small
	 */
	int		ip_id;

} vrrp_if;

typedef struct {
	uint32_t	addr;		/* the ip address */
	int		deletable;	/* TRUE if one of my primary addr */
} vip_addr;

typedef struct {	/* parameters per virtual router -- rfc2338.6.1.2 */
	int	vrid;		/* virtual id. from 1(!) to 255 */
	int	priority;	/* priority value */
	int	naddr;		/* number of ip addresses */
	vip_addr *vaddr;	/* point on the ip address array */
	int	adver_int;	/* delay between advertisements(in sec) */	
	char	hwaddr[6];	/* VMAC -- rfc2338.7.3 */

#if 0	/* dynamically calculated */
	double	skew_time;	/* skew Master_Down_Interval. (256-Prio)/256 */	
	int	mast_down_int;	/* interval for backup to declare master down*/
#endif
	int	preempt;	/* true if a higher prio preempt a lower one */
	int	state;		/* internal state (init/backup/master) */
	int	wantstate;	/* user explicitly wants a state (back/mast) */
	int	sockfd;		/* the socket descriptor */
	int	initF;		/* true if the struct is init */
	int	no_vmac;	/* dont handle the virtual MAC --rfc2338.7.3 */

	/* rfc2336.6.2 */
	uint32_t	ms_down_timer;
	uint32_t	adver_timer;

	/* IPSEC AH counter def --rfc2402.3.3.2 */
	seq_counter *ipsecah_counter;

	/* interface parameters */
	vrrp_if	*vif;
} vrrp_rt;

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_STATE_INIT	1	/* rfc2338.6.4.1 */
#define VRRP_STATE_BACK	2	/* rfc2338.6.4.2 */
#define VRRP_STATE_MAST	3	/* rfc2338.6.4.3 */
#define VRRP_STATE_NONE	99	/* internal */

/* VRRP packet handling */
#define VRRP_PACKET_OK   0
#define VRRP_PACKET_KO   1
#define VRRP_PACKET_DROP 2
#define VRRP_PACKET_NULL 3

#define VRRP_AUTH_LEN	8

#define VRRP_IS_BAD_VID(id) ((id)<1 || (id)>255)	/* rfc2338.6.1.vrid */
#define VRRP_IS_BAD_PRIORITY(p) ((p)<1 || (p)>255)	/* rfc2338.6.1.prio */
#define VRRP_IS_BAD_ADVERT_INT(d) ((d)<1)

#define VRRP_TIMER_HZ			1000000
#define VRRP_TIMER_SKEW( srv ) ((256-(srv)->priority)*VRRP_TIMER_HZ/256) 

#define VRRP_MIN( a , b )	( (a) < (b) ? (a) : (b) )
#define VRRP_MAX( a , b )	( (a) > (b) ? (a) : (b) )

/* prototypes */
extern int complete_vrrp_init(vrrp_rt *vsrv);
extern void vrrp_state_stop_instance(vrrp_rt *vsrv);

#endif
