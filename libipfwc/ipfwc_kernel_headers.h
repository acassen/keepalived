/* This is the userspace/kernel interface for Generic IP Chains,
   required for libc6. */
#ifndef _FWCHAINS_KERNEL_HEADERS_H
#define _FWCHAINS_KERNEL_HEADERS_H

#if defined(__GLIBC__) && __GLIBC__ == 2
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/types.h>

typedef u_int64_t __u64;
typedef u_int32_t __u32;
typedef int32_t __s32;
typedef u_int16_t __u16;
typedef u_int8_t __u8;

#else /* libc5 */
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif

#define IP_FW_MAX_LABEL_LENGTH 8
typedef char ip_chainlabel[IP_FW_MAX_LABEL_LENGTH+1];

struct ip_fw 
{
	struct in_addr fw_src, fw_dst;		/* Source and destination IP addr */
	struct in_addr fw_smsk, fw_dmsk;	/* Mask for src and dest IP addr */
	__u32 fw_mark;                          /* ID to stamp on packet */
	__u16 fw_proto;                         /* Protocol, 0 = ANY */
	__u16 fw_flg;			        /* Flags word */
        __u16 fw_invflg;                        /* Inverse flags */
	__u16 fw_spts[2];                       /* Source port range. */
        __u16 fw_dpts[2];                       /* Destination port range. */
	__u16 fw_redirpt;                       /* Port to redirect to. */ 
	__u16 fw_outputsize;                    /* Max amount to output to
						   NETLINK */
	char           fw_vianame[IFNAMSIZ];	/* name of interface "via" */
	__u8           fw_tosand, fw_tosxor;	/* Revised packet priority */
};

struct ip_fwuser
{
	struct ip_fw ipfw;
	ip_chainlabel label;
};

/* Values for "fw_flg" field .  */
#define IP_FW_F_PRN	0x0001	/* Print packet if it matches */
#define IP_FW_F_TCPSYN	0x0002	/* For tcp packets-check SYN only */
#define IP_FW_F_FRAG	0x0004  /* Set if rule is a fragment rule */
#define IP_FW_F_MARKABS	0x0008  /* Set the mark to fw_mark, not add. */
#define IP_FW_F_WILDIF	0x0010  /* Need only match start of interface name. */
#define IP_FW_F_NETLINK 0x0020  /* Redirect to netlink: 2.1.x only */
#define IP_FW_F_MASK	0x003F	/* All possible flag bits mask   */

/* Values for "fw_invflg" field. */
#define IP_FW_INV_SRCIP 0x0001  /* Invert the sense of fw_src. */
#define IP_FW_INV_DSTIP 0x0002  /* Invert the sense of fw_dst. */
#define IP_FW_INV_PROTO 0x0004  /* Invert the sense of fw_proto. */
#define IP_FW_INV_SRCPT 0x0008  /* Invert the sense of source ports. */
#define IP_FW_INV_DSTPT 0x0010  /* Invert the sense of destination ports. */
#define IP_FW_INV_VIA   0x0020  /* Invert the sense of fw_vianame. */
#define IP_FW_INV_SYN   0x0040  /* Invert the sense of IP_FW_F_TCPSYN. */
#define IP_FW_INV_FRAG  0x0080  /* Invert the sense of IP_FW_F_FRAG. */

/*    
 *	New IP firewall options for [gs]etsockopt at the RAW IP level.
 *	Unlike BSD Linux inherits IP options so you don't have to use
 * a raw socket for this. Instead we check rights in the calls.  */

#define IP_FW_BASE_CTL  	64	/* base for firewall socket options */

#define IP_FW_APPEND		(IP_FW_BASE_CTL)    /* Takes ip_fwchange */
#define IP_FW_REPLACE		(IP_FW_BASE_CTL+1)  /* Takes ip_fwnew */
#define IP_FW_DELETE_NUM	(IP_FW_BASE_CTL+2)  /* Takes ip_fwdelnum */
#define IP_FW_DELETE		(IP_FW_BASE_CTL+3)  /* Takes ip_fwchange */
#define IP_FW_INSERT		(IP_FW_BASE_CTL+4)  /* Takes ip_fwnew */
#define IP_FW_FLUSH		(IP_FW_BASE_CTL+5)  /* Takes ip_chainlabel */
#define IP_FW_ZERO		(IP_FW_BASE_CTL+6)  /* Takes ip_chainlabel */
#define IP_FW_CHECK		(IP_FW_BASE_CTL+7)  /* Takes ip_fwtest */
#define IP_FW_MASQ_TIMEOUTS	(IP_FW_BASE_CTL+8)  /* Takes 3 ints */
#define IP_FW_CREATECHAIN	(IP_FW_BASE_CTL+9)  /* Takes ip_chainlabel */
#define IP_FW_DELETECHAIN	(IP_FW_BASE_CTL+10) /* Takes ip_chainlabel */
#define IP_FW_POLICY		(IP_FW_BASE_CTL+11) /* Takes ip_fwpolicy */
/* Masquerade controls */
#define IP_FW_MASQ_INSERT	(IP_FW_BASE_CTL+12)
#define IP_FW_MASQ_ADD		(IP_FW_BASE_CTL+13)
#define IP_FW_MASQ_DEL		(IP_FW_BASE_CTL+14)
#define IP_FW_MASQ_FLUSH  	(IP_FW_BASE_CTL+15)

/* Builtin chain labels */
#define IP_FW_LABEL_FORWARD	"forward"
#define IP_FW_LABEL_INPUT	"input"
#define IP_FW_LABEL_OUTPUT	"output"

/* Special targets */
#define IP_FW_LABEL_MASQUERADE  "MASQ"
#define IP_FW_LABEL_REDIRECT    "REDIRECT"
#define IP_FW_LABEL_ACCEPT	"ACCEPT"
#define IP_FW_LABEL_BLOCK	"DENY"
#define IP_FW_LABEL_REJECT	"REJECT"
#define IP_FW_LABEL_RETURN	"RETURN"

/* Files in /proc/net */
#define IP_FW_PROC_CHAINS	"ip_fwchains"
#define IP_FW_PROC_CHAIN_NAMES	"ip_fwnames"

struct ip_fwpkt
{
	struct iphdr fwp_iph;			/* IP header */
	union {
		struct tcphdr fwp_tcph;		/* TCP header or */
		struct udphdr fwp_udph;		/* UDP header */
		struct icmphdr fwp_icmph;	/* ICMP header */
	} fwp_protoh;
	struct in_addr fwp_via;			/* interface address */
	char           fwp_vianame[IFNAMSIZ];	/* interface name */
};

/* The argument to IP_FW_DELETE and IP_FW_APPEND */
struct ip_fwchange
{
	struct ip_fwuser fwc_rule;
	ip_chainlabel fwc_label;
};	

/* The argument to IP_FW_CHECK. */
struct ip_fwtest
{
	struct ip_fwpkt fwt_packet; /* Packet to be tested */
	ip_chainlabel fwt_label;   /* Block to start test in */
};
						
/* The argument to IP_FW_DELETE_NUM */
struct ip_fwdelnum
{
	__u32 fwd_rulenum;
	ip_chainlabel fwd_label;
};

/* The argument to IP_FW_REPLACE and IP_FW_INSERT */
struct ip_fwnew
{
	__u32 fwn_rulenum;
	struct ip_fwuser fwn_rule;
	ip_chainlabel fwn_label;
};
 
/* The argument to IP_FW_POLICY */
struct ip_fwpolicy
{
	ip_chainlabel fwp_policy;
	ip_chainlabel fwp_label;
};
/*      
 * timeouts for ip masquerading
 */

struct ip_fw_masq;

/* Masquerading stuff */
#define IP_FW_MASQCTL_MAX 256
#define IP_MASQ_MOD_NMAX  32

struct ip_fw_masqctl
{
	int mctl_action;
	union {
		struct {
			char name[IP_MASQ_MOD_NMAX];
			char data[1];
		} mod;
	} u;
};
#endif
