/* Library which manipulates firewall rules.  Version 0.2. */

/* (C)1998 Paul ``Rusty'' Russell - Placed under the GNU GPL (See
   COPYING for details). */

/* 0.2:  Accounting rules now return target label of "" not "-", so they
 * can be fed right back in, as expected. */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "libipfwc.h"

#define IP_VERSION	4
#define IP_OFFSET	0x1FFF

static int sockfd = -1;
static void *ipfwc_fn = NULL;

static int init = 0;

/* Some people try -j REDIRECT or -j MASQ, without kernel support; a
   little hacky, but record it out here in case we get an error. --RR */
static enum {
	IPFWC_NORMAL,
	IPFWC_MASQ,
	IPFWC_REDIRECT
} ipfwc_type;

static void ipfwc_settype(const struct ip_fwuser *fw)
{
	if (strcmp(fw->label, "MASQ") == 0)
		ipfwc_type = IPFWC_MASQ;
	else if (strcmp(fw->label, "REDIRECT") == 0)
		ipfwc_type = IPFWC_REDIRECT;
	else ipfwc_type = IPFWC_NORMAL;
}

static int ipfwc_init()
{
	ipfwc_fn = ipfwc_init;
	init = 1;
	return ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) != -1);
}

static int
do_setsockopt(int cmd, const void *data, int length)
{
	return setsockopt(sockfd, IPPROTO_IP, cmd, (char *)data, length) != -1;
}

/* Insert the entry `fw' in chain `chain' into position `rulenum'. */
int ipfwc_insert_entry(const ip_chainlabel chain, 
                       const struct ip_fwuser *fw, 
                       unsigned int rulenum)
{
	struct ip_fwnew new = { rulenum, *fw, "" };
	memcpy(new.fwn_label, chain, sizeof(new.fwn_label));

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_insert_entry;
	ipfwc_settype(fw);
	return do_setsockopt(IP_FW_INSERT, &new, sizeof(new));
}

/* Atomically replace rule `rulenum' in `chain' with `fw'. */
int ipfwc_replace_entry(const ip_chainlabel chain, 
                        const struct ip_fwuser *fw, 
                        unsigned int rulenum)
{
	struct ip_fwnew new = { rulenum, *fw, "" };
	memcpy(new.fwn_label, chain, sizeof(new.fwn_label));

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_replace_entry;
	ipfwc_settype(fw);
	return do_setsockopt(IP_FW_REPLACE, &new, sizeof(new));
}

/* Append entry `fw' to chain `chain'.  Equivalent to insert with
   rulenum = length of chain. */
int ipfwc_append_entry(const ip_chainlabel chain, const struct ip_fwuser *fw)
{
	struct ip_fwchange new = { *fw, "" };
	memcpy(new.fwc_label, chain, sizeof(new.fwc_label));

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_append_entry;
	ipfwc_settype(fw);
	return do_setsockopt(IP_FW_APPEND, &new, sizeof(new));	
}

/* Delete the first rule in `chain' which matches `fw'. */
int ipfwc_delete_entry(const ip_chainlabel chain, const struct ip_fwuser *fw)
{
	struct ip_fwchange del = { *fw, "" };
	memcpy(del.fwc_label, chain, sizeof(del.fwc_label));

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_delete_entry;
	return do_setsockopt(IP_FW_DELETE, &del, sizeof(del));	
}

/* Delete the rule in position `rulenum' in `chain'. */
int ipfwc_delete_num_entry(const ip_chainlabel chain, unsigned int rulenum)
{
	struct ip_fwdelnum del = { rulenum, "" };
	memcpy(del.fwd_label, chain, sizeof(del.fwd_label));

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_delete_num_entry;
	return do_setsockopt(IP_FW_DELETE_NUM, &del, sizeof(del));
}

static struct ip_fwtest *
fw_to_fwtest(const struct ip_fw *fw, const ip_chainlabel chain)
{
	static struct ip_fwtest ipfwt;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;

	strcpy(ipfwt.fwt_label, chain);

	iph = &ipfwt.fwt_packet.fwp_iph;

	iph->version = IP_VERSION;
	iph->ihl = sizeof(struct iphdr) / 4;
	iph->tot_len = sizeof(struct ip_fwpkt);
	iph->frag_off &= htons(~IP_OFFSET);
	iph->protocol = fw->fw_proto;

	iph->saddr = fw->fw_src.s_addr;
	iph->daddr = fw->fw_dst.s_addr;

	strncpy(ipfwt.fwt_packet.fwp_vianame, fw->fw_vianame, IFNAMSIZ);

	if (fw->fw_flg & IP_FW_F_FRAG)
		iph->frag_off |= htons(2); /* = 64 bytes - why not? */

	/* The tcp and udp headers are ignored for fragments, anyway */
	switch (iph->protocol) {
	case IPPROTO_TCP:
		tcph = &ipfwt.fwt_packet.fwp_protoh.fwp_tcph;
		tcph->source = htons(fw->fw_spts[0]);
		tcph->dest = htons(fw->fw_dpts[0]);
		tcph->syn = (fw->fw_flg & IP_FW_F_TCPSYN) ? 1 : 0;
		break;
	case IPPROTO_UDP:
		udph = &ipfwt.fwt_packet.fwp_protoh.fwp_udph;
		udph->source = htons(fw->fw_spts[0]);
		udph->dest = htons(fw->fw_dpts[0]);
		break;
	case IPPROTO_ICMP:
		icmph = &ipfwt.fwt_packet.fwp_protoh.fwp_icmph;
		icmph->type = fw->fw_spts[0];
		icmph->code = fw->fw_dpts[0];
		break;
	}

	return &ipfwt;
}

/* Check the packet `fw' on chain `chain'.  Returns the verdict, or
   NULL and sets errno. */
const char *ipfwc_check_packet(const ip_chainlabel chain, 
                               struct ip_fw *fw)
{
	int old_errno = errno;

	if (!init && !ipfwc_init()) return NULL;

	ipfwc_fn = ipfwc_check_packet;
	if (do_setsockopt(IP_FW_CHECK, fw_to_fwtest(fw, chain), 
			  sizeof(struct ip_fwtest)))
		return "accepted";
	else switch (errno) {
	case ECONNRESET:
		errno = old_errno;
		return "masqueraded";
	case ETIMEDOUT:
		errno = old_errno;
		return "denied";
	case ECONNREFUSED:
		errno = old_errno;
		return "rejected";
	case ECONNABORTED:
		errno = old_errno;
		return "redirected";
	case ELOOP:
		errno = old_errno;
		return "caught in loop";
	case ENFILE:
		errno = old_errno;
		return "passed through chain";

	default:
		return NULL;
	}
}

/* Flushes the entries in the given chain (ie. empties chain). */
int ipfwc_flush_entries(const ip_chainlabel chain)
{
	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_flush_entries;
	return do_setsockopt(IP_FW_FLUSH, chain, sizeof(ip_chainlabel));
}

/* Zeroes the counters in a chain. */
int ipfwc_zero_entries(const ip_chainlabel chain)
{
	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_zero_entries;
	return do_setsockopt(IP_FW_ZERO, chain, sizeof(ip_chainlabel));
}

/* Creates a new chain. */
int ipfwc_create_chain(const ip_chainlabel chain)
{
	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_create_chain;
	return do_setsockopt(IP_FW_CREATECHAIN, chain, sizeof(ip_chainlabel));
}

/* Deletes a chain. */
int ipfwc_delete_chain(const ip_chainlabel chain)
{
	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_delete_chain;
	return do_setsockopt(IP_FW_DELETECHAIN, chain, sizeof(ip_chainlabel));
}

/* Sets the policy on a built-in chain. */
int ipfwc_set_policy(const ip_chainlabel chain, const ip_chainlabel policy)
{
	struct ip_fwpolicy fwp;

	if (!init && !ipfwc_init()) return 0;

	ipfwc_fn = ipfwc_set_policy;
	memcpy(fwp.fwp_policy, policy, sizeof(fwp.fwp_policy));
	memcpy(fwp.fwp_label, chain, sizeof(fwp.fwp_label));
	return do_setsockopt(IP_FW_POLICY, &fwp, sizeof(fwp));
}

/* Gets the names of all the chains.  Returns single malloc()d region;
   and array of ip_chainlabels.  Fills in num_chains.  Returns NULL on
   error.  */
struct ipfwc_fwchain *ipfwc_get_chainnames(unsigned int *num_chains)
{
	int nread;
	static unsigned int maxnum = 4;
	static struct ipfwc_fwchain *chains = NULL;
	FILE *fp;
	__u32 pkthi, pktlo, bytehi, bytelo;

	ipfwc_fn = ipfwc_get_chainnames;
	if (!chains) {
		chains = malloc(sizeof(struct ipfwc_fwchain) * maxnum);

		if (!chains) {
			errno = ENOMEM;
			return NULL;
		}
	}

	/* Read names from IP_FW_PROC_CHAIN_NAMES */
	fp = fopen("/proc/net/"IP_FW_PROC_CHAIN_NAMES, "r");
	if (!fp) {
		/* Bad kernel version? */
		if (errno == ENOENT) errno = 0;
		return NULL;
	}

	*num_chains = 0;
	while ((nread = fscanf(fp,"%s %s %u %u %u %u %u", 
			       chains[*num_chains].label, 
			       chains[*num_chains].policy, 
			       &chains[*num_chains].refcnt, 
			       &pkthi, &pktlo, &bytehi, &bytelo)) == 7) {
		chains[*num_chains].packets = ((__u64)pkthi)<<32 | pktlo;
		chains[*num_chains].bytes = ((__u64)bytehi)<<32 | bytelo;
		(*num_chains)++;
		if (*num_chains >= maxnum) {
			maxnum *= 2;
			chains = realloc(chains, 
					 sizeof(struct ipfwc_fwchain)*maxnum);
			if (!chains) {
				fclose(fp);
				errno = ENOMEM;
				return NULL;
			}
		}
	}

	/* Bad kernel version? */
	if (nread != -1) {
		fclose(fp);
		errno = 0;
		return NULL;
	}

	return chains;
}	

static const struct ipfwc_fwchain *
find_chain(const ip_chainlabel label,
	   const struct ipfwc_fwchain *chains,
	   unsigned int num_chains)
{
	unsigned int i;

	for (i = 0; i < num_chains; i++) {
		if (strcmp(label, chains[i].label) == 0)
			return chains+i;
	}
	return NULL;
}

#define _IPFWC_FMT2(i) "%" #i "s "
#define _IPFWC_FMT(i) _IPFWC_FMT2(i)
#define IPFWC_CHAIN_FMT _IPFWC_FMT(IP_FW_MAX_LABEL_LENGTH)

/* Take a snapshot of the rules.  Returns internal pointer to array of
   ipfwc_fwrules.  Fills in num_rules.  Returns NULL on error. */
struct ipfwc_fwrule *ipfwc_get_rules(unsigned int *num_rules, int zero)
{
	FILE *fp;
	__u32 pkthi, pktlo, bytehi, bytelo;
	unsigned int num_chains;
	struct ipfwc_fwchain *chains = ipfwc_get_chainnames(&num_chains);
	static unsigned int maxnum = 4;
	static struct ipfwc_fwrule *rules = NULL;
	ip_chainlabel label;
	int nread;
	unsigned short tosand, tosxor;

	ipfwc_fn = ipfwc_get_rules;
	if (!rules) {
		rules = malloc(sizeof(struct ipfwc_fwrule) * maxnum);
		if (!rules) {
			errno = ENOMEM;
			return NULL;
		}
	}

	fp = fopen("/proc/net/"IP_FW_PROC_CHAINS, zero ? "r+" : "r");
	if (!fp) {
		if (errno == ENOENT) errno = 0;
		return NULL;
	}

	*num_rules = 0;
	while ((nread = fscanf(fp,
			       IPFWC_CHAIN_FMT		/* Chain name */
			       "%X/%X->%X/%X "		/* IPs */
			       "%s "			/* Interface */
			       "%hX %hX "		/* flg & invflg */
			       "%hu "			/* Protocol */
			       "%u %u %u %u "		/* Counters */
			       "%hu-%hu %hu-%hu "	/* Ports */
			       "A%hX X%hX "		/* TOS masks */
			       "%hX "			/* fw_redir */
			       "%u "			/* fw_mark */
			       "%hu "			/* output size */
			       "%s",			/* Target */
			       label,
			       &rules[*num_rules].ipfw.ipfw.fw_src.s_addr,
			       &rules[*num_rules].ipfw.ipfw.fw_smsk.s_addr,
			       &rules[*num_rules].ipfw.ipfw.fw_dst.s_addr,
			       &rules[*num_rules].ipfw.ipfw.fw_dmsk.s_addr,
			       rules[*num_rules].ipfw.ipfw.fw_vianame,
			       &rules[*num_rules].ipfw.ipfw.fw_flg, 
			       &rules[*num_rules].ipfw.ipfw.fw_invflg,
			       &rules[*num_rules].ipfw.ipfw.fw_proto,
			       &pkthi, &pktlo, &bytehi, &bytelo,
			       &rules[*num_rules].ipfw.ipfw.fw_spts[0], 
			       &rules[*num_rules].ipfw.ipfw.fw_spts[1],
			       &rules[*num_rules].ipfw.ipfw.fw_dpts[0], 
			       &rules[*num_rules].ipfw.ipfw.fw_dpts[1],
			       &tosand, &tosxor,
			       &rules[*num_rules].ipfw.ipfw.fw_redirpt,
			       &rules[*num_rules].ipfw.ipfw.fw_mark,
			       &rules[*num_rules].ipfw.ipfw.fw_outputsize,
			       rules[*num_rules].ipfw.label)) == 23) {
		if (strcmp("-", rules[*num_rules].ipfw.label) == 0)
			(rules[*num_rules].ipfw.label)[0] = '\0';
		if (strcmp("-", rules[*num_rules].ipfw.ipfw.fw_vianame) == 0)
			(rules[*num_rules].ipfw.ipfw.fw_vianame)[0] = '\0';
		rules[*num_rules].ipfw.ipfw.fw_tosand = (unsigned char)tosand;
		rules[*num_rules].ipfw.ipfw.fw_tosxor = (unsigned char)tosxor;

		/* we always keep these addresses in network byte order */
		rules[*num_rules].ipfw.ipfw.fw_src.s_addr
			= htonl(rules[*num_rules].ipfw.ipfw.fw_src.s_addr);
		rules[*num_rules].ipfw.ipfw.fw_smsk.s_addr
			= htonl(rules[*num_rules].ipfw.ipfw.fw_smsk.s_addr);
		rules[*num_rules].ipfw.ipfw.fw_dst.s_addr
			= htonl(rules[*num_rules].ipfw.ipfw.fw_dst.s_addr);
		rules[*num_rules].ipfw.ipfw.fw_dmsk.s_addr
			= htonl(rules[*num_rules].ipfw.ipfw.fw_dmsk.s_addr);

		rules[*num_rules].packets = ((__u64)pkthi)<<32 | pktlo;
		rules[*num_rules].bytes = ((__u64)bytehi)<<32 | bytelo;

		rules[*num_rules].chain
			= find_chain(label, chains, num_chains);

		(*num_rules)++;
		if (*num_rules >= maxnum) {
			maxnum *= 2;
			rules = realloc(rules, 
					sizeof(struct ipfwc_fwrule)*maxnum);
			if (!rules) {
				fclose(fp);
				errno = ENOMEM;
				return NULL;
			}
		}
	}

	/* Bad kernel version? */
	if (nread != -1) {
		fclose(fp);
		errno = 0;
		return NULL;
	}

	return rules;
}

/* Get raw socket. */
int ipfwc_get_raw_socket()
{
	return sockfd;
}

/* Translates errno numbers into more human-readable form than strerror.
 * `ipfwc_fn' is a pointer to the function which returned the error. */
const char *ipfwc_strerror(int err)
{
	unsigned int i;
	static char message[200];
	struct table_struct {
		void *fn;
		int err;
		const char *message;
		int support_warning;
	} table [] = 
	  { { ipfwc_insert_entry, ENOENT, "No target by that name", 1 },
	    { ipfwc_replace_entry, ENOENT, "No target by that name", 1 },
	    { ipfwc_append_entry, ENOENT, "No target by that name", 1 },
	    { NULL, ENOENT, "No chain by that name", 0 },
	    { NULL, 0, "Incompatible with this kernel", 0 },
	    { ipfwc_init, EPERM, "Permission denied (you must be root)", 0 },
	    { ipfwc_delete_chain, ENOTEMPTY, "Chain is not empty", 0 },
	    { ipfwc_create_chain, EEXIST, "Chain already exists", 0 },
	    /* EINVAL for CHECK probably means bad interface. */
	    { ipfwc_check_packet, EINVAL, 
	      "bad arguments (does that interface exist?)", 0 },
	    /* EINVAL for DELETE probably means no matching rule */
	    { ipfwc_delete_entry, EINVAL,
	      "bad rule (does a matching rule exist in that chain?)", 0 },
	    { ipfwc_insert_entry, EINVAL,
	      "bad rule (does a matching rule exist in that chain?)", 0 },
	    { ipfwc_delete_num_entry, EINVAL,
	      "bad rule (does a matching rule exist in that chain?)", 0 },
	    { ipfwc_replace_entry, EINVAL,
	      "bad rule (does a matching rule exist in that chain?)", 0 }
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].fn || table[i].fn == ipfwc_fn)
		    && table[i].err == err) {
			strcpy(message, table[i].message);

			if (table[i].support_warning)
				switch (ipfwc_type) {
				case IPFWC_MASQ:
					strcat(message, " (Maybe this kernel"
					       " doesn't support"
					       " masquerading?)");
					break;
				case IPFWC_REDIRECT:
					strcat(message, " (Maybe this kernel"
					       " doesn't support"
					       " transparent proxying?)");
					break;
				default:
				}
			return message;
		}
	}
	return strerror(err);
}

