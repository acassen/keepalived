/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        vrrp.c program include file.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_H
#define _VRRP_H

/* system include */
#include <unistd.h>

#ifdef VRRP_COUNTER
#include <zmq.h>
#endif

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_iproute.h"
#include "vrrp_ipsecah.h"
#include "vrrp_if.h"
#include "vrrp_track.h"
#include "timer.h"
#include "utils.h"
#include "vector.h"
#include "list.h"

#ifdef VRRP_COUNTER
/* vrrp counters globals and extern */
#define VRRP_INVALID_ZMQ_CONTEXT NULL
#define VRRP_INVALID_ZMQ_SOCKET NULL
#define VRRP_COUNTER_NULL_STRING "0,0,0,0,0,0,0,0,0,0,0,0"
#define VRRP_INVALID_ID 256
#define VRRP_MAX_COUNTER_STR 100
/* max no of chars for len of an ipc token in decimal */
#define VRRP_IPC_TOKEN_LEN  22

/* max no of ipc tokens
 * 255 vrrp instances + vrrp all/specific identifier + msg type */
#define VRRP_MAX_IPC_TOKEN  259

/* max ipc buffer size for sending data */
#define KA_VRRP_MAX_SEND_IPC_BUF 50

/* max ipc buffer size for data received */
#define KA_VRRP_MAX_RECV_IPC_BUF 300

/* namespace file as an input to keepalived package where
 * zmq socket would bind upon. The location of file could be 
 * user preference. The current namspace file uses the zmq ipc
 * transport mechanism as this is inter-process communication */  
#define VRRP_IPC_NAMESPACE "ipc:///tmp/zmq_pipe"

#define VRRP_MAX_INSTANCE_ID 255

/* enum for vrrp counter message type */
typedef enum {
    VRRP_KA_MSG_GET_INSTANCE_COUNTER = 1,
    VRRP_KA_MSG_GET_ALL_GLOBAL_COUNTER,
    VRRP_KA_MSG_MASTER_DETAILS_INFO,
    VRRP_KA_MSG_CLEAR_STATISTICS,
    VRRP_KA_MSG_VRRP_DOES_NOT_EXIST,
} msg_type_counter_t;

/* enum for vrrp counter field */
typedef enum {
    TRANSITION_TO_MASTER = 0,
    ADVERTISEMENT_RECEIVED,
    ADVERTISEMENT_INTERVAL_ERRORS,
    AUTHENTICATION_FAILURES,
    TTL_ERRORS,
    PRIORITY_ZERO_PKTS_RECEIVED,
    PRIORITY_ZERO_PKTS_SENT,
    INVALID_TYPE_PKTS_RECEIVED,
    STATS_ADDRESS_LIST_ERRORS,
    INVALID_AUTH_TYPE,
    AUTH_TYPE_MISMATCH,
    PACKET_LENGTH_ERROR
} counter_fields_t;
#endif

typedef struct _vrrphdr {			/* rfc2338.5.1 */
	uint8_t			vers_type;	/* 0-3=type, 4-7=version */
	uint8_t			vrid;		/* virtual router id */
	uint8_t			priority;	/* router priority */
	uint8_t			naddr;		/* address counter */
	uint8_t			auth_type;	/* authentification type */
	uint8_t			adver_int;	/* advertissement interval(in sec) */
	uint16_t		chksum;		/* checksum (ip-like one) */
	/* here <naddr> ip addresses */
	/* here authentification infos */
} vrrphdr_t;

/* protocol constants */
#define INADDR_VRRP_GROUP	0xe0000012	/* multicast addr - rfc2338.5.2.2 */
#define VRRP_IP_TTL		255		/* in and out pkt ttl -- rfc2338.5.2.3 */
#define IPPROTO_VRRP		112		/* IP protocol number -- rfc2338.5.2.4 */
#define VRRP_VERSION		2		/* current version -- rfc2338.5.3.1 */
#define VRRP_PKT_ADVERT		1		/* packet type -- rfc2338.5.3.2 */
#define VRRP_PRIO_OWNER		255		/* priority of the ip owner -- rfc2338.5.3.4 */
#define VRRP_PRIO_DFL		100		/* default priority -- rfc2338.5.3.4 */
#define VRRP_PRIO_STOP		0		/* priority to stop -- rfc2338.5.3.4 */
#define VRRP_AUTH_NONE		0		/* no authentification -- rfc2338.5.3.6 */
#define VRRP_AUTH_PASS		1		/* password authentification -- rfc2338.5.3.6 */
#define VRRP_AUTH_AH		2		/* AH(IPSec) authentification - rfc2338.5.3.6 */
#define VRRP_ADVER_DFL		1		/* advert. interval (in sec) -- rfc2338.5.3.7 */
#define VRRP_GARP_DELAY 	(5 * TIMER_HZ)	/* Default delay to launch gratuitous arp */
#define VRRP_GARP_REP		5		/* Default repeat value for MASTER state gratuitous arp */
#define VRRP_GARP_REFRESH_REP	1		/* Default repeat value for refresh gratuitous arp */

/*
 * parameters per vrrp sync group. A vrrp_sync_group is a set
 * of VRRP instances that need to be state sync together.
 */
typedef struct _vrrp_sgroup {
	char			*gname;			/* Group name */
	vector_t		*iname;			/* Set of VRRP instances in this group */
	list			index_list;		/* List of VRRP instances */
	int			state;			/* current stable state */
	int			global_tracking;	/* Use floating priority and scripts
							 * All VRRP must share same tracking conf
							 */

	/* State transition notification */
	int			notify_exec;
	char			*script_backup;
	char			*script_master;
	char			*script_fault;
	char			*script;
	int			smtp_alert;
} vrrp_sgroup_t;

#ifdef VRRP_COUNTER
/* structure for counter statistics info */
typedef struct _vrrp_counter_stats {
	long unsigned    transition_to_master;			/* No. of times the router was Master */
	long unsigned    advertise_rcvd;                    	/* No. of VRRP advertisements received */
	long unsigned    advt_intvl_err;                     	/* No. of VRRP advertisements received adv interval errors */
	long unsigned    auth_failures;                    	/* No. of VRRP advertisements received that don't pass authentication check */
	long unsigned    ttl_errors;                      	/* No. of VRRP advertisements received with time to live error */
	long unsigned    priority_zero_pkts_rcvd;           	/* No. of VRRP advertisements received with zero priority */
	long unsigned    priority_zero_pkts_sent;          	/* No. of VRRP advertisements sent with zero priority */
	long unsigned    invalid_type_pkts_rcvd;           	/* No. of VRRP advertisements received with inavlid Type */
	long unsigned    stats_address_list_errors;        	/* No. of VRRP advertisements received with address list errors */
	long unsigned    invalid_auth_type;                	/* No. of VRRP advertisements received with unknown Auth type */
	long unsigned    auth_type_mismatch;              	/* No. of VRRP advertisements received with 'Auth Type' !=
											to the locally configure Auth method */
	long unsigned    packet_length_error;              	/* No. of VRRP advertisements received with packet length
											less than length of VRRP header */
} vrrp_stats_t;

/* structure for master router details info*/
typedef struct  master_router_info {
	int            	master_priority;			/* Master router's priority */
	int            	master_adv_intvl;			/* Master router's advertisement interval */
	interface_t	master_ifp;				/* Master router's interface IP address */
} master_details_info_t;

/* structure for zmq IPC info from keepalived */
typedef struct _vrrp_extended_info_detail {
	vrrp_stats_t		counter_info;			/* Counter info details */
	master_details_info_t	master_info;			/* Master info details */
} vrrp_extended_t;
#endif

/* parameters per virtual router -- rfc2338.6.1.2 */
typedef struct _vrrp_t {
	sa_family_t		family;			/* AF_INET|AF_INET6 */
	char			*iname;			/* Instance Name */
	vrrp_sgroup_t		*sync;			/* Sync group we belong to */
	interface_t		*ifp;			/* Interface we belong to */
	int			dont_track_primary;	/* If set ignores ifp faults */
	int			vmac_flags;		/* VRRP VMAC flags */
	char			vmac_ifname[IFNAMSIZ];	/* Name of VRRP VMAC interface */
	unsigned int		vmac_ifindex;		/* ifindex of vmac interface */
	list			track_ifp;		/* Interface state we monitor */
	list			track_script;		/* Script state we monitor */
	struct sockaddr_storage	saddr;			/* Src IP address to use in VRRP IP header */
	struct sockaddr_storage	pkt_saddr;		/* Src IP address received in VRRP IP header */
	list			unicast_peer;		/* List of Unicast peer to send advert to */
	char			*lvs_syncd_if;		/* handle LVS sync daemon state using this
							 * instance FSM & running on specific interface
							 * => eth0 for example.
							 */
	int			garp_delay;		/* Delay to launch gratuitous ARP */
	timeval_t		garp_refresh;		/* Next scheduled gratuitous ARP refresh */
	timeval_t		garp_refresh_timer;	/* Next scheduled gratuitous ARP timer */
	int			garp_rep;		/* gratuitous ARP repeat value */
	int			garp_refresh_rep;	/* refresh gratuitous ARP repeat value */
	int			vrid;			/* virtual id. from 1(!) to 255 */
	int			base_priority;		/* configured priority value */
	int			effective_priority;	/* effective priority value */
	int			vipset;			/* All the vips are set ? */
	list			vip;			/* list of virtual ip addresses */
	list			evip;			/* list of protocol excluded VIPs.
							 * Those VIPs will not be presents into the
							 * VRRP adverts
							 */
	list			vroutes;		/* list of virtual routes */
	int			adver_int;		/* delay between advertisements(in sec) */
	int			nopreempt;		/* true if higher prio does not preempt lower */
	long			preempt_delay;		/* Seconds*TIMER_HZ after startup until
							 * preemption based on higher prio over lower
							 * prio is allowed.  0 means no delay.
							 */
	timeval_t		preempt_time;		/* Time after which preemption can happen */
	int			state;			/* internal state (init/backup/master) */
	int			init_state;		/* the initial state of the instance */
	int			wantstate;		/* user explicitly wants a state (back/mast) */
	int			fd_in;			/* IN socket descriptor */
	int			fd_out;			/* OUT socket descriptor */

	int			debug;			/* Debug level 0-4 */

	int			quick_sync;		/* Will be set when waiting for the other members
							 * in the sync group to become master.
							 * If set the next check will occur in one interval
							 * instead of three intervals.
							 */
	/* State transition notification */
	int			smtp_alert;
	int			notify_exec;
	char			*script_backup;
	char			*script_master;
	char			*script_fault;
	char			*script_stop;
	char			*script;

	/* rfc2336.6.2 */
	uint32_t		ms_down_timer;
	timeval_t		sands;

	/* Sending buffer */
	char			*send_buffer;		/* Allocated send buffer */
	int			send_buffer_size;

	/* Authentication data */
	int			auth_type;		/* authentification type. VRRP_AUTH_* */
	uint8_t			auth_data[8];		/* authentification data */

	/*
	 * To have my own ip_id creates collision with kernel ip->id
	 * but it should be ok because the packets are unlikely to be
	 * fragmented (they are non routable and small)
	 * This packet isnt routed, i can check the outgoing MTU
	 * to warn the user only if the outoing mtu is too small
	 */
	int			ip_id;

	/* IPSEC AH counter def --rfc2402.3.3.2 */
	seq_counter_t		*ipsecah_counter;

	#ifdef VRRP_COUNTER
	/*
	 * vrrp_extended_t structure contains info about all the ipc data needed
	 * by other daemons from keepalived. The IPC mechanism used here is zmq
	 */
	vrrp_extended_t		extended_detail_info;
	#endif
} vrrp_t;

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_STATE_INIT			0	/* rfc2338.6.4.1 */
#define VRRP_STATE_BACK			1	/* rfc2338.6.4.2 */
#define VRRP_STATE_MAST			2	/* rfc2338.6.4.3 */
#define VRRP_STATE_FAULT		3	/* internal */
#define VRRP_STATE_GOTO_MASTER		4	/* internal */
#define VRRP_STATE_LEAVE_MASTER		5	/* internal */
#define VRRP_STATE_GOTO_FAULT 		98	/* internal */
#define VRRP_DISPATCHER 		99	/* internal */
#define VRRP_MCAST_RETRY		10	/* internal */
#define VRRP_MAX_FSM_STATE		4	/* internal */

/* VRRP packet handling */
#define VRRP_PACKET_OK       0
#define VRRP_PACKET_KO       1
#define VRRP_PACKET_DROP     2
#define VRRP_PACKET_NULL     3
#define VRRP_PACKET_OTHER    4	/* Muliple VRRP on LAN, Identify "other" VRRP */

/* VRRP Packet fixed length */
#define VRRP_MAX_VIP		20
#define VRRP_PACKET_TEMP_LEN	1024
#define VRRP_AUTH_LEN		8
#define VRRP_VIP_TYPE		(1 << 0)
#define VRRP_EVIP_TYPE		(1 << 1)

/* VRRP macro */
#define VRRP_IS_BAD_VID(id)		((id)<1 || (id)>255)	/* rfc2338.6.1.vrid */
#define VRRP_IS_BAD_PRIORITY(p)		((p)<1 || (p)>255)	/* rfc2338.6.1.prio */
#define VRRP_IS_BAD_ADVERT_INT(d) 	((d)<1)
#define VRRP_IS_BAD_DEBUG_INT(d)	((d)<0 || (d)>4)
#define VRRP_IS_BAD_PREEMPT_DELAY(d)	((d)<0 || (d)>TIMER_MAX_SEC)
#define VRRP_SEND_BUFFER(V)		((V)->send_buffer)
#define VRRP_SEND_BUFFER_SIZE(V)	((V)->send_buffer_size)

#define VRRP_TIMER_SKEW(svr)	((256-(svr)->base_priority)*TIMER_HZ/256)
#define VRRP_VIP_ISSET(V)	((V)->vipset)

#define VRRP_MIN(a, b)	((a) < (b)?(a):(b))
#define VRRP_MAX(a, b)	((a) > (b)?(a):(b))

#define VRRP_PKT_SADDR(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in *) &(V)->saddr)->sin_addr.s_addr : IF_ADDR((V)->ifp))

#define VRRP_IF_ISUP(V)        ((IF_ISUP((V)->ifp) || (V)->dont_track_primary) & \
                               ((!LIST_ISEMPTY((V)->track_ifp)) ? TRACK_ISUP((V)->track_ifp) : 1))

#define VRRP_SCRIPT_ISUP(V)    ((!LIST_ISEMPTY((V)->track_script)) ? SCRIPT_ISUP((V)->track_script) : 1)

#define VRRP_ISUP(V)           (VRRP_IF_ISUP(V) && VRRP_SCRIPT_ISUP(V))

/* prototypes */
extern vrrphdr_t *vrrp_get_header(sa_family_t, char *, int *);
extern int open_vrrp_send_socket(sa_family_t, int, int, int);
extern int open_vrrp_socket(sa_family_t, int, int, int);
extern int new_vrrp_socket(vrrp_t *);
extern void close_vrrp_socket(vrrp_t *);
extern void vrrp_send_link_update(vrrp_t *, int);
extern int vrrp_send_adv(vrrp_t *, int);
extern int vrrp_state_fault_rx(vrrp_t *, char *, int);
extern int vrrp_state_master_rx(vrrp_t *, char *, int);
extern int vrrp_state_master_tx(vrrp_t *, const int);
extern void vrrp_state_backup(vrrp_t *, char *, int);
extern void vrrp_state_goto_master(vrrp_t *);
extern void vrrp_state_leave_master(vrrp_t *);
extern int vrrp_ipsecah_len(void);
extern int vrrp_complete_init(void);
extern int vrrp_ipvs_needed(void);
extern void shutdown_vrrp_instances(void);
extern void clear_diff_vrrp(void);
extern void clear_diff_script(void);
extern void vrrp_restore_interface(vrrp_t *, int);

/* Prototype for vrrp counter api */
#ifdef VRRP_COUNTER
extern void *keepalive_zmq_main(void *value);
#endif

#endif
