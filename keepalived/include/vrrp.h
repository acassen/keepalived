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

typedef struct _vrrphdr {			/* rfc2338.5.1 */
	uint8_t			vers_type;	/* 0-3=type, 4-7=version */
	uint8_t			vrid;		/* virtual router id */
	uint8_t			priority;	/* router priority */
	uint8_t			naddr;		/* address counter */
	union {
		struct {
	uint8_t			auth_type;	/* authentification type */
			uint8_t adver_int;	/* advertisement interval (in sec) */
		} v2;
		struct {
			uint16_t adver_int;	/* advertisement interval (in centi-sec (100ms)) */
		} v3;
	};
	uint16_t		chksum;		/* checksum (ip-like one) */
	/* here <naddr> ip addresses */
	/* here authentification infos */
} vrrphdr_t;

typedef struct {
	uint32_t src;
	uint32_t dst;
	uint8_t  zero;
	uint8_t  proto;
	uint16_t len;
} ipv4_phdr_t;

/* protocol constants */
#define INADDR_VRRP_GROUP	0xe0000012	/* multicast addr - rfc2338.5.2.2 */
#define VRRP_IP_TTL		255		/* in and out pkt ttl -- rfc2338.5.2.3 */
#define IPPROTO_VRRP		112		/* IP protocol number -- rfc2338.5.2.4 */
#define VRRP_VERSION_2		2		/* VRRP version 2 -- rfc2338.5.3.1 */
#define VRRP_VERSION_3		3		/* VRRP version 3 -- rfc5798.5.2.1 */
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

/* Statistics */
typedef struct _vrrp_stats {
	int		advert_rcvd;
	int		advert_sent;

	int		become_master;
	int		release_master;

	int		packet_len_err;
	int		advert_interval_err;
	int		ip_ttl_err;
	int		invalid_type_rcvd;
	int		addr_list_err;

	int		invalid_authtype;
	int		authtype_mismatch;
	int		auth_failure;

	int		pri_zero_rcvd;
	int		pri_zero_sent;
} vrrp_stats;

/* parameters per virtual router -- rfc2338.6.1.2 */
typedef struct _vrrp_t {
	sa_family_t		family;			/* AF_INET|AF_INET6 */
	char			*iname;			/* Instance Name */
	vrrp_sgroup_t		*sync;			/* Sync group we belong to */
	char			base_iface[IFNAMSIZ];	/* base interface name */
	vrrp_stats		*stats;			/* Statistics */
	interface_t		*ifp;			/* Interface we belong to */
	int			dont_track_primary;	/* If set ignores ifp faults */
	unsigned long		vmac_flags;		/* VRRP VMAC flags */
	char			vmac_ifname[IFNAMSIZ];	/* Name of VRRP VMAC interface */
	unsigned int		vmac_ifindex;		/* ifindex of vmac interface */
	list			track_ifp;		/* Interface state we monitor */
	list			track_script;		/* Script state we monitor */
	struct sockaddr_storage	saddr;			/* Src IP address to use in VRRP IP header */
	struct sockaddr_storage	pkt_saddr;		/* Src IP address received in VRRP IP header */
	list			unicast_peer;		/* List of Unicast peer to send advert to */
	struct sockaddr_storage master_saddr;		/* Store last heard Master address */
	uint8_t			master_priority;	/* Store last heard priority */
	timeval_t		last_transition;	/* Store transition time */
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
	int			adver_int;		/* locally configured delay between advertisements*/
	int			master_adver_int; /* In v3, when we become BACKUP, we use the MASTER's
								   * adver_int. If we become MASTER again, we use the
								   * value we were originally configured with.
								   */
	bool			accept;			/* Allow the non-master owner to process
							 * the packets destined to VIP.
							 */
	bool			iptable_rules_set;	/* Iptable drop rules set to VIP list ? */
	int			nopreempt;		/* true if higher prio does not preempt lower */
	long			preempt_delay;		/* Seconds*TIMER_HZ after startup until
							 * preemption based on higher prio over lower
							 * prio is allowed.  0 means no delay.
							 */
	timeval_t		preempt_time;		/* Time after which preemption can happen */
	int 			preempt_delay_active;
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

	int version;            /* VRRP version (2 or 3) */

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

	/* Authentication data (only valid for VRRPv2) */
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

	/* IPSEC AH counter def (only valid for VRRPv2) --rfc2402.3.3.2 */
	seq_counter_t		*ipsecah_counter;
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
#define VRRP_IS_BAD_VERSION(id)         ((id) < 2 || (id) > 3)
#define VRRP_IS_BAD_VID(id)		((id) < 1 || (id) > 255)	/* rfc2338.6.1.vrid */
#define VRRP_IS_BAD_PRIORITY(p)		((p)<1 || (p)>255)	/* rfc2338.6.1.prio */
#define VRRP_IS_BAD_ADVERT_INT(d) 	((d)<1)
#define VRRP_IS_BAD_DEBUG_INT(d)	((d)<0 || (d)>4)
#define VRRP_IS_BAD_PREEMPT_DELAY(d)	((d)<0 || (d)>TIMER_MAX_SEC)
#define VRRP_SEND_BUFFER(V)		((V)->send_buffer)
#define VRRP_SEND_BUFFER_SIZE(V)	((V)->send_buffer_size)

#define VRRP_TIMER_SKEW(svr)	((svr)->version == VRRP_VERSION_3 ? (((256-(svr)->base_priority) * (svr)->adver_int)/256) : ((256-(svr)->base_priority) * TIMER_HZ/256))
#define VRRP_VIP_ISSET(V)	((V)->vipset)

#define VRRP_MIN(a, b)	((a) < (b)?(a):(b))
#define VRRP_MAX(a, b)	((a) > (b)?(a):(b))

#define VRRP_PKT_SADDR(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in *) &(V)->saddr)->sin_addr.s_addr : IF_ADDR((V)->ifp))
#define VRRP_PKT_SADDR6(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in6 *) &(V)->saddr)->sin6_addr : IF_ADDR6((V)->ifp))

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

#endif
