/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Routing table names parser/reader. Place into the dynamic
 *              data structure representation the table names and ids.
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
 * Copyright (C) 2001-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/*
   iproute has been moving the location of its config files around recently,
   and not so recently.

	Version	Commit	Date		Change
	3.3	fb72129	01/03/12	use CONFDIR for path for config files - edit Makefile to change
	4.1	06ec903	13/04/15	Allow CONFDIR to be set in environment to make (default /etc/iproute2)
	4.4	13ada95	24/11/15	add support for rt_tables.d
	4.10	719e331	09/01/17	add support for rt_protos.d
	5.15	cee0cf8	14/10/21	adds --libdir option to configure
	6.3	bdb8d85	27/03/23	add support for IFA_PROT
	6.5	0a0a8f1	26/07/23	read from /usr/lib/iproute2/FOO unless /etc/iproute2/FOO exists - both specifiable to make
	6.6	946753a	15/09/23	ensure CONF_USR_DIR honours configure lib path - uses $(LIBDIR)
		deb66ac	06/11/23	revert 946753a4
	6.7	9626923	15/11/23	change using /usr/lib/iproute2 to /usr/share/iproute2
	6.13	b43f84a	14/10/24	add rt_addrprotos.d subdirectories

    Debian, Ubuntu, RHEL and openSUSE moved from /etc/iproute2 to /usr/share/iproute2
    Mint, Gentoo and Archlinux currently use /etc/iproute2
    Alpine by default uses busybox which doesn't support these files
	If iproute2 is installed it uses /usr/share/iproute2
    Fedora is potentially a problem. Up to Fedora 39 it used /etc/iproute2.
	The initial version of iproute2 in Fedora 40 was v6.5 and it used 
	    /usr/lib/iproute2 or /usr/lib64/iproute2. When iproute2 was upgraded
	    to v6.7 it moved to using /usr/share/iproute2.
	Fedora 41 uses /usr/share/iproute2.
	Since Fedora 40 upgraded to iproute2 v6.7 in February 2024, it is reasonable
	to assume that if Fedora 40 upgrades to this version of keepalived, i.e.
	November 2024 or later, that iproute2 will have already been upgraded to v6.7
	(or later). We therefore do not need to support /usr/lib{,64}/iproute2.	

    I have been unable to find any distro that uses CONFDIR/CONF_{USR,ETC}_DIR or --libdir,
    but if there is one, they should set --with-iproute-usr-dir and --with-iproute-etc-dir
    configure options for keepalived (if the man pages for iproute2 or /usr/bin/ip are
    installed in the build environment, configure should be able to work out the paths itself).
*/

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <dirent.h>
#include <errno.h>
#if HAVE_DECL_IFA_PROTO
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "list_head.h"
#include "memory.h"
#include "logger.h"
#include "parser.h"
#include "rttables.h"


#if !defined IPROUTE_USR_DIR && !defined IPROUTE_ETC_DIR
#define IPROUTE_ETC_DIR "/etc/iproute2"
#endif

#define RT_TABLES_FILE	"rt_tables"
#define	RT_DSFIELD_FILE "rt_dsfield"
#define	RT_REALMS_FILE	"rt_realms"
#define	RT_PROTOS_FILE	"rt_protos"
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
#define	RT_GROUPS_FILE	"group"
#endif
#define	RT_SCOPES_FILE	"rt_scopes"
#if HAVE_DECL_IFA_PROTO
#define RT_ADDRPROTOS_FILE "rt_addrprotos"
#endif

typedef struct _rt_entry {
	unsigned int	id;
	const char	*name;

	/* Linked list member */
	list_head_t	e_list;
} rt_entry_t;

typedef enum {
	DIRS_NOT_CHECKED,
	DIRS_EXIST,
	DIRS_DONT_EXIST,
} dir_state_t;

static rt_entry_t const rtntypes[] = {
	{ RTN_LOCAL, "local", {0}},
	{ RTN_NAT, "nat", {0}},
	{ RTN_BROADCAST, "broadcast", {0}},
	{ RTN_BROADCAST, "brd", {0}},
	{ RTN_ANYCAST, "anycast", {0}},
	{ RTN_MULTICAST, "multicast", {0}},
	{ RTN_PROHIBIT, "prohibit", {0}},
	{ RTN_UNREACHABLE, "unreachable", {0}},
	{ RTN_BLACKHOLE, "blackhole", {0}},
	{ RTN_XRESOLVE, "xresolve", {0}},
	{ RTN_UNICAST, "unicast", {0}},
	{ RTN_THROW, "throw", {0}},
	{ 0, NULL, {0}},
};

static rt_entry_t const rtprot_default[] = {
	{ RTPROT_UNSPEC, "none", {0}},
	{ RTPROT_REDIRECT, "redirect", {0}},
	{ RTPROT_KERNEL, "kernel", {0}},
	{ RTPROT_BOOT, "boot", {0}},
	{ RTPROT_STATIC, "static", {0}},

	{ RTPROT_GATED, "gated", {0}},
	{ RTPROT_RA, "ra", {0}},
	{ RTPROT_MRT, "mrt", {0}},
	{ RTPROT_ZEBRA, "zebra", {0}},
	{ RTPROT_BIRD, "bird", {0}},
#ifdef RTPROT_BABEL		/* Since Linux 3.19 */
	{ RTPROT_BABEL, "babel", {0}},
#endif
	{ RTPROT_DNROUTED, "dnrouted", {0}},
	{ RTPROT_XORP, "xorp", {0}},
	{ RTPROT_NTK, "ntk", {0}},
	{ RTPROT_DHCP, "dhcp", {0}},
	{ 0, NULL, {0}},
};

static rt_entry_t const rttable_default[] = {
	{ RT_TABLE_DEFAULT, "default", {0}},
	{ RT_TABLE_MAIN, "main", {0}},
	{ RT_TABLE_LOCAL, "local", {0}},
	{ 0, NULL, {0}},
};

static rt_entry_t const rtscope_default[] = {
	{ RT_SCOPE_UNIVERSE, "global", {0}},
	{ RT_SCOPE_NOWHERE, "nowhere", {0}},
	{ RT_SCOPE_HOST, "host", {0}},
	{ RT_SCOPE_LINK, "link", {0}},
	{ RT_SCOPE_SITE, "site", {0}},
	{ 0, NULL, {0}},
};

#if HAVE_DECL_IFA_PROTO
static rt_entry_t const rtaddrproto_default[] = {
	{ IFAPROT_UNSPEC, "unspecified", {0}},
	{ IFAPROT_KERNEL_LO, "kernel_lo", {0}},
	{ IFAPROT_KERNEL_RA, "kernel_ra", {0}},
	{ IFAPROT_KERNEL_LL, "kernel_ll", {0}},
	{ 0, NULL, {0}},
};
#endif

#define	MAX_RT_BUF	128

static LIST_HEAD_INITIALIZE(rt_tables);
static LIST_HEAD_INITIALIZE(rt_dsfields);
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
static LIST_HEAD_INITIALIZE(rt_groups);
#endif
static LIST_HEAD_INITIALIZE(rt_realms);
static LIST_HEAD_INITIALIZE(rt_protos);
#if HAVE_DECL_IFA_PROTO
static LIST_HEAD_INITIALIZE(rt_addrprotos);
#endif
static LIST_HEAD_INITIALIZE(rt_scopes);

static char ret_buf[11];	/* uint32_t in decimal */

static dir_state_t dir_state = DIRS_NOT_CHECKED;

static void
free_rt_entry(rt_entry_t *rte)
{
	list_del_init(&rte->e_list);
	if (rte->name)
		FREE_CONST(rte->name);
	FREE(rte);
}

static void
free_rt_entry_list(list_head_t *l)
{
	rt_entry_t *rte, *rte_tmp;

	list_for_each_entry_safe(rte, rte_tmp, l, e_list)
		free_rt_entry(rte);
}

#if 0
static void
dump_rt_entry(FILE *fp, const rt_entry_t *rte)
{
	conf_write(fp, "rt_table %u, name %s", rte->id, rte->name);
}
static void
dump_rt_entry_list(FILE *fp, const list_head_t *l)
{
	rt_entry_t *rte;

	list_for_each_entry(rte, l, e_list)
		dump_rt_entry(fp, rte);
}
#endif

void
clear_rt_names(void)
{
	free_rt_entry_list(&rt_tables);
	free_rt_entry_list(&rt_dsfields);
#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
	free_rt_entry_list(&rt_groups);
#endif
	free_rt_entry_list(&rt_realms);
	free_rt_entry_list(&rt_protos);
#if HAVE_DECL_IFA_PROTO
	free_rt_entry_list(&rt_addrprotos);
#endif
	free_rt_entry_list(&rt_scopes);
}

static void
read_file(const char *file_name, list_head_t *l, uint32_t max)
{
	FILE *fp;
	rt_entry_t *rte;
	char buf[MAX_RT_BUF];
	unsigned long id;
	const char *number, *name;
	char *endptr;
	size_t len;

	fp = fopen(file_name, "r");
	if (!fp)
		return;

	while (fgets(buf, sizeof(buf), fp)) {
		/* Remove comments */
		if ((endptr = strchr(buf, '#')))
			*endptr = '\0';

		/* Remove trailing '\n' and skip empty lines */
		if (!(len = strlen(buf)))
			continue;
		if (buf[len - 1] == '\n') {
			if (len == 1)
				continue;
			buf[len - 1] = '\0';
		}

		/* check we have only two fields, and get them */
		if (!(number = strtok(buf, " \t")))
			continue;
		if (!(name = strtok(NULL, " \t")))
			continue;
		if (strtok(NULL, " \t"))
			continue;

		PMALLOC(rte);
		if (!rte)
			goto err;
		INIT_LIST_HEAD(&rte->e_list);

		id = strtoul(number, &endptr, 0);
		if (*number == '-' || number == endptr || *endptr || id > max) {
			FREE(rte);
			continue;
		}
		rte->id = (unsigned)id;

		rte->name = STRDUP(name);
		if (!rte->name) {
			FREE(rte);
			goto err;
		}

		list_add_tail(&rte->e_list, l);
	}

	fclose(fp);

	return;
err:
	fclose(fp);

	free_rt_entry_list(l);
}

static void
add_default(list_head_t *l, const rt_entry_t *default_list)
{
	rt_entry_t *rte;
	bool found;

	for (; default_list->name; default_list++) {
		found = false;
		list_for_each_entry(rte, l, e_list) {
			if (rte->id == default_list->id) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		PMALLOC(rte);
		INIT_LIST_HEAD(&rte->e_list);
		rte->name = STRDUP(default_list->name);
		if (!rte->name) {
			FREE(rte);
			return;
		}

		rte->id = default_list->id;

		list_add_tail(&rte->e_list, l);
	}
}

static bool
wanted_file(char *file_path, const char *path, const char *dir, const char *name)
{
	struct stat statbuf;
	size_t len;

	/* Skip hidden files and . and .. */
	if (name[0] == '.')
		return false;

	/* We only want filenames ending '.conf' */
	len = strlen(name);
	if (len <= 5 || strcmp(name + len - 5, ".conf"))
		return false;

	/* Ensure what we have is a regular file */
	snprintf(file_path, PATH_MAX, "%s/%s.d/%s", path, dir, name);
	if (stat(file_path, &statbuf) || (statbuf.st_mode & S_IFMT) != S_IFREG)
		return false;

	return true;
}

static void
initialise_list(list_head_t *l, const char *file_name, const rt_entry_t *default_list, uint32_t max)
{
	char *path;
#ifdef IPROUTE_USR_DIR
	char *etc_path;
#endif
	struct stat statbuf;
	struct dirent *ent;
	DIR *dir;

	if (!list_empty(l))
		return;

	if (dir_state == DIRS_NOT_CHECKED) {
#ifdef IPROUTE_USR_DIR
		if (!stat(IPROUTE_USR_DIR, &statbuf) && (statbuf.st_mode & S_IFMT) == S_IFDIR)
			dir_state = DIRS_EXIST;
		else
#endif
		if (!stat(IPROUTE_ETC_DIR, &statbuf) && (statbuf.st_mode & S_IFMT) == S_IFDIR)
			dir_state = DIRS_EXIST;
		else
			dir_state = DIRS_DONT_EXIST;
	}

	if (dir_state == DIRS_EXIST) {
		path = MALLOC(PATH_MAX);
#ifdef IPROUTE_USR_DIR
		etc_path = MALLOC(PATH_MAX);
#endif

		/* The default location is IPROUTE_USR_DIR, but it is overridden
		 * if the file exists in IPROUTE_USR_DIR. */
		snprintf(path, PATH_MAX, "%s/%s", IPROUTE_ETC_DIR, file_name);
		if (!stat(path, &statbuf) && (statbuf.st_mode & S_IFMT) == S_IFREG)
			read_file(path, l, max);
#ifdef IPROUTE_USR_DIR
		else {
			snprintf(path, PATH_MAX, "%s/%s", IPROUTE_USR_DIR, file_name);
			if (!stat(path, &statbuf) && (statbuf.st_mode & S_IFMT) == S_IFREG)
				read_file(path, l, max);
		}
#endif

		/* iproute2 uses subdirectories for rt_protos, rt_addrprotos, rt_tables
		 * (and protodown_reasons) as at v6.11.
		 * To futureproof our code, we will read subdirectories for all files,
		 * in case iproute2 introduces support for them in the future.
		 * We need to check all files ending .conf under IPROUTE_USR_DIR and read
		 * them unless the matching file exists under IPROUTE_ETC_DIR. We then read
		 * all relevant files under IPROUTE_ETC_DIR. */
#ifdef IPROUTE_USR_DIR
		snprintf(path, PATH_MAX, "%s/%s.d", IPROUTE_USR_DIR, file_name);
		if ((dir = opendir(path))) {
			while ((ent = readdir(dir))) {
				if (!wanted_file(path, IPROUTE_USR_DIR, file_name, ent->d_name))
					continue;

				/* Check if the file exists in IPROUTE_ETC_DIR. We just check if there is a matching
				 * entry, and don't care what type the entry is */
				snprintf(etc_path, PATH_MAX, "%s/%s.d/%s", IPROUTE_ETC_DIR, file_name, ent->d_name);
				if (!stat(etc_path, &statbuf))
					continue;

				read_file(path, l, max);
			}

			closedir(dir);
		}
#endif

		/* Now read the entries in the IPROUTE_ETC_DIR subdirectory */
		snprintf(path, PATH_MAX, "%s/%s.d", IPROUTE_ETC_DIR, file_name);
		if ((dir = opendir(path))) {
			while ((ent = readdir(dir))) {
				if (!wanted_file(path, IPROUTE_ETC_DIR, file_name, ent->d_name))
					continue;

				read_file(path, l, max);
			}

			closedir(dir);
		}

		FREE_PTR(path);
#ifdef IPROUTE_USR_DIR
		FREE_PTR(etc_path);
#endif
	}

	if (default_list)
		add_default(l, default_list);
}

static bool
find_entry(const char *name, unsigned int *id, list_head_t *l, const char* file_name, const rt_entry_t *default_list, uint32_t max)
{
	char *endptr;
	unsigned long l_id;
	rt_entry_t *rte;

	/* If the name is numeric, return its value */
	l_id = strtoul(name, &endptr, 0);
	*id = (unsigned int)l_id;
	if (endptr != name && *endptr == '\0')
		return (*id <= max);

	initialise_list(l, file_name, default_list, max);

	list_for_each_entry(rte, l, e_list) {
		if (!strcmp(rte->name, name)) {
			*id = rte->id;
			return true;
		}
	}

	return false;
}

bool
find_rttables_table(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_tables, RT_TABLES_FILE, rttable_default, RT_TABLE_MAX);
}

bool
find_rttables_dsfield(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_dsfields, RT_DSFIELD_FILE, NULL, 255);
	*id = val & 0xff;

	return ret;
}

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP
bool
find_rttables_group(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_groups, RT_GROUPS_FILE, NULL, INT32_MAX);
}
#endif

bool
find_rttables_realms(const char *name, uint32_t *id)
{
	return find_entry(name, id, &rt_realms, RT_REALMS_FILE, NULL, 255);
}

bool
find_rttables_proto(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_protos, RT_PROTOS_FILE, rtprot_default, 255);
	*id = val & 0xff;

	return ret;
}

bool
find_rttables_rtntype(const char *str, uint8_t *id)
{
	char *end;
	unsigned long res;
	int i;

	for (i = 0; rtntypes[i].name; i++) {
		if (!strcmp(str, rtntypes[i].name)) {
			*id = (uint8_t)rtntypes[i].id;
			return true;
		}
	}

	res = strtoul(str, &end, 0);
	if (*end || res > 255 || str[0] == '-')
		return false;

	*id = (uint8_t)res;
	return true;
}

static const char *
get_entry(unsigned int id, list_head_t *l, const char* file_name, const rt_entry_t *default_list, uint32_t max)
{
	rt_entry_t *rte;

	initialise_list(l, file_name, default_list, max);

	list_for_each_entry(rte, l, e_list) {
		if (rte->id == id)
			return rte->name;
	}

	snprintf(ret_buf, sizeof(ret_buf), "%u", id);
	return ret_buf;
}

#if HAVE_DECL_FRA_SUPPRESS_IFGROUP && defined _WITH_SNMP_VRRP_
const char *
get_rttables_group(uint32_t id)
{
	return get_entry(id, &rt_groups, RT_GROUPS_FILE, NULL, INT32_MAX);
}
#endif

const char *
get_rttables_rtntype(uint8_t val)
{
	int i;

	for (i = 0; rtntypes[i].name; i++) {
		if (val == rtntypes[i].id)
			return rtntypes[i].name;
	}

	snprintf(ret_buf, sizeof(ret_buf), "%u", val);
	return ret_buf;
}

bool
find_rttables_scope(const char *name, uint8_t *id)
{
	uint32_t val;
	bool ret;

	ret = find_entry(name, &val, &rt_scopes, RT_SCOPES_FILE, rtscope_default, 255);
	*id = val & 0xff;

	return ret;
}

const char *
get_rttables_scope(uint32_t id)
{
	return get_entry(id, &rt_scopes, RT_SCOPES_FILE, rtscope_default, 255);
}

#if HAVE_DECL_IFA_PROTO
static const char *
get_rttables_addrproto(uint32_t id)
{
	return get_entry(id, &rt_addrprotos, RT_ADDRPROTOS_FILE, rtaddrproto_default, 255);
}

static void
write_addrproto_config(const char *name, uint32_t val)
{
	char buf[256];
	FILE *fp;
	char *v, *e;
	int ver_maj, ver_min, ver_rel;
	char *res;
	const char *path, *dir = NULL;
	bool file_exists = false;
	struct stat statbuf;

	fp = popen("ip -V 2>&1", "re");
	res = fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (!res)
		return;

	/* Format is:
	 *     ip utility, iproute2-5.10.0
	 * or
	 *     ip utility, iproute2-6.7.0, libbpf 1.2.3
         * or
         *     BusyBox v1.36.1 (2024-06-10 07:11:47 UTC) multi-call binary
	 *
	 * Busybox does not support the iproute2 configuration files.
         */
        if (!strstr(buf, "iproute2"))
                return;
        if (strstr(buf, "BusyBox"))
                return;

	if (!(v = strchr(buf, '-')))
		return;

	v++;
	if ((e = strchr(v, ',')))
		*e = '\0';
	if (sscanf(v, "%d.%d.%d", &ver_maj, &ver_min, &ver_rel) != 3)
		return;

	if (ver_maj >= 7 || (ver_maj == 6 && ver_min >= 13)) {
		dir = IPROUTE_ETC_DIR "/" RT_ADDRPROTOS_FILE ".d";
		path = IPROUTE_ETC_DIR "/" RT_ADDRPROTOS_FILE ".d/keepalived.conf" ;
	} else if (ver_maj == 6 && ver_min >= 3)
		path = IPROUTE_ETC_DIR "/" RT_ADDRPROTOS_FILE;
	else
		return;

	/* If IPROUTE_ETC_DIR doesn't exist, create it */
	if (stat(IPROUTE_ETC_DIR, &statbuf)) {
#ifdef IPROUTE_USR_DIR
		if (stat(IPROUTE_USR_DIR, &statbuf))
#endif
		{
			/* Use sensible defaults for directory permission */
			statbuf.st_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		}

		/* Create directory */
		if (mkdir(IPROUTE_ETC_DIR, statbuf.st_mode & ~S_IFMT)) {
			log_message(LOG_INFO, "Unable to create directory " IPROUTE_ETC_DIR " for rt_addrproto keepalived");
			return;
		}
	}

	if (dir) {
		if (!mkdir(dir, statbuf.st_mode & ~S_IFMT))	// This may fail if the directory already exists
			chmod(dir, statbuf.st_mode & ~S_IFMT);
		else if (errno == EEXIST)
			file_exists = !stat(path, &statbuf);
	} else {
		/* Check if rt_addrprotos file exists */
		file_exists = !stat(path, &statbuf);
	}

	if (!(fp = fopen(path, "a")))
		return;

	if (!file_exists)
		chmod(path, statbuf.st_mode & ~S_IFMT & ~(S_IXUSR | S_IXGRP | S_IXOTH));

	fprintf(fp, "%u\t%s\t# added by keepalived\n", val, name);

	fclose(fp);
}

bool
create_rttables_addrproto(const char *name, uint8_t *id)
{
	unsigned val;
	rt_entry_t *rte;

	/* We need to find a free value - try RTPROT_KEEPALIVED first */
	val = RTPROT_KEEPALIVED;
	if (!get_rttables_addrproto(val)) {
		for (val = 0; val <= 255; val++) {
			if (get_rttables_addrproto(val))
				break;
		}
	}

	if (val > 255)
		return false;

	*id = val & 0xff;

	/* Add the entry so other configuration can use it */
	PMALLOC(rte);
	if (!rte)
		return false;

	rte->id = val;
	rte->name = STRDUP(name);
	if (!rte->name) {
		FREE(rte);
		return false;
	}

	list_add_tail(&rte->e_list, &rt_addrprotos);

	/* Save the entry so iproute can use it */
	if (dir_state != DIRS_DONT_EXIST)
		write_addrproto_config(name, *id);

	return true;
}

bool
find_rttables_addrproto(const char *name, uint8_t *id)
{
	uint32_t val;

	if (!find_entry(name, &val, &rt_addrprotos, RT_ADDRPROTOS_FILE, rtaddrproto_default, 255))
		return false;

	*id = val & 0xff;

	return true;
}
#endif
