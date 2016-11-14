/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
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

#include "config.h"

/* local include */
#include "vrrp_ipaddress.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables.h"
#endif
#include "vrrp_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"
#include "global_data.h"
#include "rttables.h"


#define INFINITY_LIFE_TIME      0xFFFFFFFF

char *
ipaddresstos(char *buf, ip_address_t *ipaddress)
{
	static char addr_str[INET6_ADDRSTRLEN];

	if (!buf)
		buf = addr_str;

	if (IP_IS6(ipaddress)) {
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, buf, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &ipaddress->u.sin.sin_addr, buf, INET_ADDRSTRLEN);
	}

	return buf;
}

/* Add/Delete IP address to a specific interface_t */
int
netlink_ipaddress(ip_address_t *ipaddress, int cmd)
{
	struct ifa_cacheinfo cinfo;
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[256];
	} req;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = (cmd == IPADDRESS_DEL) ? RTM_DELADDR : RTM_NEWADDR;
	req.ifa = ipaddress->ifa;

	if (IP_IS6(ipaddress)) {
		if (cmd == IPADDRESS_ADD) {
			/* Mark IPv6 address as deprecated (rfc3484) in order to prevent
			 * using VRRP VIP as source address in healthchecking use cases.
			 */
			if (ipaddress->ifa.ifa_prefixlen == 128) {
				memset(&cinfo, 0, sizeof(cinfo));
				cinfo.ifa_prefered = 0;
				cinfo.ifa_valid = INFINITY_LIFE_TIME;

				log_message(LOG_INFO, "%s has a prefix length of 128, setting "
						      "preferred_lft to 0", ipaddresstos(NULL, ipaddress));
				addattr_l(&req.n, sizeof(req), IFA_CACHEINFO, &cinfo,
					  sizeof(cinfo));
			}

			/* Disable, per VIP, Duplicate Address Detection algorithm (DAD).
			 * Using the nodad flag has the following benefits:
			 *
			 * (1) The address becomes immediately usable after they're
			 *     configured.
			 * (2) In the case of a temporary layer-2 / split-brain problem
			 *     we can avoid that the active VIP transitions into the
			 *     dadfailed phase and stays there forever - leaving us
			 *     without service. HA/VRRP setups have their own "DAD"-like
			 *     functionality, so it's not really needed from the IPv6 stack.
			 */
#ifdef IFA_F_NODAD	/* Since Linux 2.6.19 */
			req.ifa.ifa_flags |= IFA_F_NODAD;
#endif
		}

		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin6_addr, sizeof(ipaddress->u.sin6_addr));
	} else {
		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));

		if (cmd == IPADDRESS_ADD) {
			if (ipaddress->u.sin.sin_brd.s_addr)
				addattr_l(&req.n, sizeof(req), IFA_BROADCAST,
					  &ipaddress->u.sin.sin_brd, sizeof(ipaddress->u.sin.sin_brd));
		}
		else {
			/* IPADDRESS_DEL */
			addattr_l(&req.n, sizeof(req), IFA_ADDRESS,
				  &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));
		}
	}

	if (cmd == IPADDRESS_ADD)
		if (ipaddress->label)
			addattr_l(&req.n, sizeof (req), IFA_LABEL,
				  ipaddress->label, strlen(ipaddress->label) + 1);

	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;

	return status;
}

/* Add/Delete a list of IP addresses */
bool
netlink_iplist(list ip_list, int cmd)
{
	ip_address_t *ipaddr;
	element e;
	bool changed_entries = false;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return false;

	/*
	 * If "--dont-release-vrrp" is set then try to release addresses
	 * that may be there, even if we didn't set them.
	 */
	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if ((cmd == IPADDRESS_ADD && !ipaddr->set) ||
		    (cmd == IPADDRESS_DEL &&
		     (ipaddr->set || __test_bit(DONT_RELEASE_VRRP_BIT, &debug)))) {
			if (netlink_ipaddress(ipaddr, cmd) > 0) {
				ipaddr->set = !(cmd == IPADDRESS_DEL);
				changed_entries = true;
			}
			else
				ipaddr->set = false;
		}
	}

	return changed_entries;
}

#ifndef _HAVE_LIBIPTC_
static void
handle_iptable_rule_to_NA(ip_address_t *ipaddress, int cmd, bool force)
{
	char  *argv[14];
	unsigned int i = 0;
	int if_specifier = -1;
	int type_specifier ;
	char *addr_str;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = "ip6tables";
	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr)) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ipaddress->ifp->ifname;
	}
	argv[i++] = "-p";
	argv[i++] = "icmpv6";
	argv[i++] = "--icmpv6-type";
	type_specifier = i;
	argv[i++] = "136";
	argv[i++] = "-j";
	argv[i++] = "ACCEPT";
	argv[i] = NULL;

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NAs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "135";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NSs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	/* Allow NSs to be sent - this should only happen if the underlying interface
	   doesn't have an IPv6 address */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NSs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "136";

	/* Allow NAs to be sent in reply to an NS */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NAs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);
}

/* add/remove iptable drop rule to VIP */
static void
handle_iptable_rule_to_vip(ip_address_t *ipaddress, int cmd, __attribute__((unused)) void *unused, bool force)
{
	char  *argv[10];
	unsigned int i = 0;
	int if_specifier = -1;
	char *addr_str;
	char *ifname = NULL;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	if (IP_IS6(ipaddress)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
			ifname = ipaddress->ifp->ifname;
		handle_iptable_rule_to_NA(ipaddress, cmd, force);
		argv[i++] = "ip6tables";
	} else {
		argv[i++] = "iptables";
	}

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (ifname) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ifname;
	}
	argv[i++] = "-j";
	argv[i++] = "DROP";
	argv[i] = NULL;

	if (fork_exec(argv) < 0) {
		if (!force)
			log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
					     " to vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
	}
	else
		ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain ;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
				     " from vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
}
#endif

/* add/remove iptable drop rules to iplist */
void
handle_iptable_rule_to_iplist(struct ipt_handle *h, list ip_list, int cmd, bool force)
{
	ip_address_t *ipaddr;
	element e;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return;

	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set ||
		    force)
			handle_iptable_rule_to_vip(ipaddr, cmd, h, force);
	}
}

/* IP address dump/allocation */
void
free_ipaddress(void *if_data)
{
	ip_address_t *ipaddr = if_data;

	FREE_PTR(ipaddr->label);
	FREE(ipaddr);
}

void
dump_ipaddress(void *if_data)
{
	ip_address_t *ipaddr = if_data;
	char broadcast[INET_ADDRSTRLEN + 5] = "";

	if (!IP_IS6(ipaddr) && ipaddr->u.sin.sin_brd.s_addr) {
		snprintf(broadcast, 21, " brd %s",
			 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}

	log_message(LOG_INFO, "     %s/%d%s dev %s scope %s%s%s"
			    , ipaddresstos(NULL, ipaddr)
			    , ipaddr->ifa.ifa_prefixlen
			    , broadcast
			    , IF_NAME(ipaddr->ifp)
			    , get_rttables_scope(ipaddr->ifa.ifa_scope)
			    , ipaddr->label ? " label " : ""
			    , ipaddr->label ? ipaddr->label : "");
}
ip_address_t *
parse_ipaddress(ip_address_t *ip_address, char *str, int allow_default)
{
	ip_address_t *new = ip_address;
	void *addr;
	char *p;

	/* No ip address, allocate a brand new one */
	if (!new) {
		new = (ip_address_t *) MALLOC(sizeof(ip_address_t));
	}

	/* Handle the specials */
	if (allow_default) {
		if (!strcmp(str, "default")) {
			new->ifa.ifa_family = AF_INET;
			return new;
		} else if (!strcmp(str, "default6")) {
			new->ifa.ifa_family = AF_INET6;
			return new;
		}
	}

	/* Parse ip address */
	new->ifa.ifa_family = (strchr(str, ':')) ? AF_INET6 : AF_INET;
	new->ifa.ifa_prefixlen = (IP_IS6(new)) ? 128 : 32;
	p = strchr(str, '/');
	if (p) {
		new->ifa.ifa_prefixlen = (uint8_t)atoi(p + 1);
		*p = 0;
	}

	addr = (IP_IS6(new)) ? (void *) &new->u.sin6_addr :
			       (void *) &new->u.sin.sin_addr;
	if (!inet_pton(IP_FAMILY(new), str, addr)) {
		log_message(LOG_INFO, "VRRP parsed invalid IP %s. skipping IP...", str);
		if (!ip_address)
			FREE(new);
		new = NULL;
	}

	/* Restore slash */
	if (p) {
		*p = '/';
	}

	return new;
}
void
alloc_ipaddress(list ip_list, vector_t *strvec, interface_t *ifp)
{
/* The way this works is slightly strange.
 *
 * If !ifp, then this is being called for a static address, in which
 * case either dev DEVNAME must be specified, or we will attempt to
 * add the address to DFTL_INT.
 * Otherwise, we are being called for a VIP/eVIP. We don't set the
 * interface for the address unless dev DEVNAME is specified, in case
 * a VMAC is added later. When the complete configuration is checked,
 * if the ifindex is 0, then it will be set to the interface of the
 * vrrp_instance (VMAC or physical interface).
 */
	ip_address_t *new;
	interface_t *ifp_local;
	char *str;
	unsigned int i = 0, addr_idx = 0;
	uint8_t scope;
	int param_avail;

	new = (ip_address_t *) MALLOC(sizeof(ip_address_t));

	/* We expect the address first */
	if (!parse_ipaddress(new, strvec_slot(strvec,0), false)) {
		FREE(new);
		return;
	}

	addr_idx = i++;

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		/* cmd parsing */
		param_avail = (vector_size(strvec) >= i+2);

		/* All keywords require a following word, so check if one is there */
		if (!param_avail) {
			log_message(LOG_INFO, "No %s parameter specified for %s", str, FMT_STR_VSLOT(strvec, addr_idx));
			break;
		}
		if (!strcmp(str, "dev")) {
			if (new->ifp) {
				log_message(LOG_INFO, "Cannot specify static ipaddress device more than once for %s", FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
			ifp_local = if_get_by_ifname(strvec_slot(strvec, ++i));
			if (!ifp_local) {
				log_message(LOG_INFO, "VRRP is trying to assign ip address %s to unknown %s"
				       " interface !!! go out and fix your conf !!!",
				       FMT_STR_VSLOT(strvec, addr_idx),
				       FMT_STR_VSLOT(strvec, i));
				FREE(new);
				return;
			}
			new->ifa.ifa_index = IF_INDEX(ifp_local);
			new->ifp = ifp_local;
		} else if (!strcmp(str, "scope")) {
			if (!find_rttables_scope(strvec_slot(strvec, ++i), &scope))
				log_message(LOG_INFO, "Invalid scope '%s' specified for %s - ignoring", FMT_STR_VSLOT(strvec,i), FMT_STR_VSLOT(strvec, addr_idx));
			else
				new->ifa.ifa_scope = scope;
		} else if (!strcmp(str, "broadcast") || !strcmp(str, "brd")) {
			if (IP_IS6(new)) {
				log_message(LOG_INFO, "VRRP is trying to assign a broadcast %s to the IPv6 address %s !!?? "
						      "WTF... skipping VIP..."
						    , FMT_STR_VSLOT(strvec, i), FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
			if (!inet_pton(AF_INET, strvec_slot(strvec, ++i), &new->u.sin.sin_brd)) {
				log_message(LOG_INFO, "VRRP is trying to assign invalid broadcast %s. "
						      "skipping VIP...", FMT_STR_VSLOT(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "label")) {
			new->label = MALLOC(IFNAMSIZ);
			strncpy(new->label, strvec_slot(strvec, ++i), IFNAMSIZ);
		} else
			log_message(LOG_INFO, "Unknown configuration entry '%s' for ip address - ignoring", str);
		i++;
	}

	if (!ifp && !new->ifp) {
		if (!global_data->default_ifp) {
			global_data->default_ifp = if_get_by_ifname(DFLT_INT);
			if (!global_data->default_ifp) {
				log_message(LOG_INFO, "Default interface " DFLT_INT
					    " does not exist and no interface specified. "
					    "Skipping static address %s.", FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
		}
		new->ifa.ifa_index = IF_INDEX(global_data->default_ifp);
		new->ifp = global_data->default_ifp;
	}

	if (new->ifa.ifa_family == AF_INET6) {
		if (new->ifa.ifa_scope) {
			log_message(LOG_INFO, "Cannot specify scope for IPv6 addresses (%s) - ignoring scope", FMT_STR_VSLOT(strvec, addr_idx));
			new->ifa.ifa_scope = 0;
		}
		if (new->label) {
			log_message(LOG_INFO, "Cannot specify label for IPv6 addresses (%s) - ignoring label", FMT_STR_VSLOT(strvec, addr_idx));
			FREE(new->label);
			new->label = NULL;
		}
	}

	list_add(ip_list, new);
}

/* Find an address in a list */
static int
address_exist(list l, ip_address_t *ipaddress)
{
	ip_address_t *ipaddr;
	element e;

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if (IP_ISEQ(ipaddr, ipaddress)) {
			ipaddr->set = ipaddress->set;
			ipaddr->iptable_rule_set = ipaddress->iptable_rule_set;
			return 1;
		}
	}

	return 0;
}

/* Clear diff addresses */
void
clear_diff_address(struct ipt_handle *h, list l, list n)
{
	ip_address_t *ipaddr;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr;

	/* No addresses in previous conf */
	if (LIST_ISEMPTY(l))
		return;

	ipaddr = ELEMENT_DATA(LIST_HEAD(l));

	/* All addresses removed */
	if (LIST_ISEMPTY(n)) {
		log_message(LOG_INFO, "Removing a complete VIP or e-VIP block");
		netlink_iplist(l, IPADDRESS_DEL);
		handle_iptable_rule_to_iplist(h, l, IPADDRESS_DEL, false);
		return;
	}

	for (e = LIST_HEAD(l); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);

		if (!address_exist(n, ipaddr) && ipaddr->set) {
			addr = (IP_IS6(ipaddr)) ? (void *) &ipaddr->u.sin6_addr :
						  (void *) &ipaddr->u.sin.sin_addr;
			inet_ntop(IP_FAMILY(ipaddr), addr, addr_str, INET6_ADDRSTRLEN);

			log_message(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
					    , addr_str
					    , ipaddr->ifa.ifa_prefixlen
					    , IF_NAME(if_get_by_ifindex(ipaddr->ifa.ifa_index)));
			netlink_ipaddress(ipaddr, IPADDRESS_DEL);
			if (ipaddr->iptable_rule_set)
				handle_iptable_rule_to_vip(ipaddr, IPADDRESS_DEL, h, false);
		}
	}
}

/* Clear static ip address */
void
clear_diff_saddresses(void)
{
	clear_diff_address(NULL, old_vrrp_data->static_addresses, vrrp_data->static_addresses);
}
