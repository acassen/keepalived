/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        CI-LINUX checker. Integration to Compaq Cluster Infrastructure.
 *
 * Version:     $Id: check_ci.c,v 1.0.0 2003/01/06 19:40:11 acassen Exp $
 *
 * Authors:     Alexandre Cassen, <acassen@linux-vs.org>
 *              Aneesh Kumar K.V, <aneesh.kumar@digital.com>
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

#include "check_ci.h"
#include "check_api.h"
#include "memory.h"
#include "parser.h"
#include "smtp.h"
#include "ipwrapper.h"

/* CI nodemap declaration */
static nodenum_ip_map_t *nodemap;

/* Configuration stream handling */
void
free_ci_check(void *data)
{
	if (nodemap) {
		FREE(nodemap);
		nodemap = NULL;
	}
}
void
dump_ci_check(void *data)
{
	syslog(LOG_INFO, "   Keepalive method = CI-LINUX");
}

void
ci_get_handler(vector strvec)
{
	int size = sizeof (nodenum_ip_map_t) * cluster_maxnodes() + 1;
	nodemap = (nodenum_ip_map_t *) ALLOC(size);

	/*
	 * If we can not initialize node map we don t queue a new checker.
	 * The default action if so is:
	 *   The realserver activity will not be monitored by the CI-LINUX
	 *   Healchecker. This mean that this realserver will be present into
	 *   LVS topology even if it is failing.
	 */
	if (initialize_nodemap(nodemap) < 0) {
		syslog(LOG_ERR,
		       "[CI-LINUX] Failed to initialize the node map from %s",
		       CLUSTERTAB);
	} else
		queue_checker(free_ci_check, dump_ci_check, ci_check_thread,
			      NULL);
}

void
install_ci_check_keyword(void)
{
	install_keyword("CI-LINUX", &ci_get_handler);
}

int
initialize_nodemap(nodenum_ip_map_t * nodemap)
{
	FILE *fp;
	char buf[BUFFSIZE];
	int node_number;

	if ((fp = fopen(CLUSTERTAB, "r")) == NULL)
		return -1;

	while (fscanf(fp, "%s", buf) != EOF) {
		if (buf[0] == '#') {
			if (fscanf(fp, "%[^\n]", buf) == EOF) {
				syslog(LOG_ERR,
				       "[CI-LINUX] %s File Format Error",
				       CLUSTERTAB);
				return -1;
			}
			bzero(buf, BUFFSIZE);
			continue;
		}
		node_number = atoi(buf);
		if (node_number > cluster_maxnodes()) {
			syslog(LOG_ERR,
			       "[CI-LINUX] Node number greater than MAX node num\n");
			return -1;
		}
		if (fscanf(fp, "%s", buf) == EOF) {
			syslog(LOG_ERR, "[CI-LINUX] %s File Format Error",
			       CLUSTERTAB);
			return -1;
		}
		inet_ston(buf, &nodemap[node_number].addr_ip);
		if (fscanf(fp, "%[^\n]", buf) == EOF) {
			syslog(LOG_ERR, "[CI-LINUX] %s File Format Error",
			       CLUSTERTAB);
			return -1;
		}
		bzero(buf, BUFFSIZE);
	}
	return 1;
}

clusternode_t
address_to_nodenum(uint32_t addr_ip)
{
	int i;
	int max_nodes = cluster_maxnodes();

	for (i = 1; i <= max_nodes; i++) {
		if (nodemap[i].addr_ip == addr_ip)
			return i;
	}
	return 0;		/* Not a valid node */
}

int
nodestatus(uint32_t addr_ip)
{
	int node_num;
	clusternode_info_t ni;

	if ((node_num = address_to_nodenum(addr_ip)) == 0)
		return UNKNOWN_NODE;

	if (clusternode_info(node_num, sizeof (ni), &ni) >= 0)
		/*
		 * I am insterested only in two state
		 * either fully up or down.
		 */
		return (ni.node_state == CLUSTERNODE_UP) ? UP : DOWN;
	else
		syslog(LOG_ERR,
		       "[CI-LINUX] Error in getting the cluster information");

	return UNKNOWN_NODE;
}

/* Cluster Infrastructure checker thread */
int
ci_check_thread(thread * thread)
{
	checker *checker = THREAD_ARG(thread);
	int status;

	/*
	 * Register a new checker thread & return
	 * if checker is disabled
	 */
	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, ci_check_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	/* Check the CI node status */
	status = nodestatus(CHECKER_RIP(checker));

	switch (status) {
	case UP:
		if (!ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, NULL, "UP",
				   "=> CI-Linux  CHECK succeed on service <=\n\n");
			perform_svr_state(UP, checker->vs, checker->rs);
		}
		break;
	case DOWN:
		if (ISALIVE(checker->rs)) {
			smtp_alert(thread->master, checker->rs, NULL, NULL, "DOWN",
				   "=> CI-Linux CHECK failed on service <=\n\n");
			perform_svr_state(DOWN, checker->vs, checker->rs);
		}
		break;
	default:
		syslog(LOG_ERR, "[CI-LINUX] Unknown node status");
	}

	/* Register the next check */
	thread_add_timer(thread->master, ci_check_thread, checker,
			 checker->vs->delay_loop);
	return 0;
}
