/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Command tree library.
 *              This code is coming from quagga.net.
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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@linux-vs.org>
 */

#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "memory.h"
#include "config.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "timer.h"
#include "logger.h"

/* Command vector which includes some level of command lists. Normally
 * each daemon maintains its own cmdvec. */
vector_t *cmdvec = NULL;

desc_t desc_cr;
char *command_cr = NULL;

/* Host information structure. */
host_t host;

/* Standard command node structures. */
static cmd_node_t auth_node = {
	AUTH_NODE,
	"Password: ",
};

static cmd_node_t view_node = {
	VIEW_NODE,
	"%s> ",
};

static cmd_node_t auth_enable_node = {
	AUTH_ENABLE_NODE,
	"Password: ",
};

static cmd_node_t enable_node = {
	ENABLE_NODE,
	"%s# ",
};

static cmd_node_t config_node = {
	CONFIG_NODE,
	"%s(config)# ",
	1
};

/* Default motd string. */
static const char *default_motd = "\r\n Welcome to Keepalived VTY.\r\n";


/* Utility function to concatenate argv argument into a single string
 * with inserting ' ' character between each argument. */
char *
argv_concat(const char **argv, int argc, int shift)
{
	int i;
	size_t len = 0, arglen;
	char *str, *p;

	for (i = shift; i < argc; i++)
		len += strlen(argv[i])+1;
	if (!len)
		return NULL;
	p = str = (char *) MALLOC(len);
	for (i = shift; i < argc; i++) {
		memcpy(p, argv[i], (arglen = strlen(argv[i])));
		p += arglen;
		*p++ = ' ';
	}
	*(p-1) = '\0';
	return str;
}

/* Install top node of command vector. */
void
install_node(cmd_node_t *node, int (*func) (vty_t *))
{
	vector_set_index(cmdvec, node->node, node);
	node->func = func;
	node->cmd_vector = vector_init(VECTOR_DEFAULT_SIZE);
}

/* Compare two command's string.  Used in sort_node (). */
static int
cmp_node(const void *p, const void *q)
{
	const cmd_element_t *a = *(cmd_element_t * const *)p;
	const cmd_element_t *b = *(cmd_element_t * const *)q;

	return strcmp(a->string, b->string);
}

static int
cmp_desc(const void *p, const void *q)
{
	const desc_t *a = *(desc_t * const *)p;
	const desc_t *b = *(desc_t * const *)q;

	return strcmp(a->cmd, b->cmd);
}

/* Sort each node's command element according to command string. */
void
sort_node(void)
{
	unsigned int i, j;
	cmd_node_t *cnode;
	vector_t *descvec;
	cmd_element_t *cmd_element;

	for (i = 0; i < vector_active(cmdvec); i++) {
		if ((cnode = vector_slot(cmdvec, i)) != NULL) {	
			vector_t *cmd_vector = cnode->cmd_vector;
			qsort(cmd_vector->slot, vector_active(cmd_vector), 
			      sizeof (void *), cmp_node);

			for (j = 0; j < vector_active(cmd_vector); j++) {
				if ((cmd_element = vector_slot(cmd_vector, j)) != NULL
				    && vector_active(cmd_element->strvec)) {
					descvec = vector_slot(cmd_element->strvec,
							      vector_active(cmd_element->strvec) - 1);
					qsort(descvec->slot, vector_active(descvec), 
					      sizeof (void *), cmp_desc);
				}
			}
		}
	}
}

/* Breaking up string into each command piece. I assume given
 * character is separated by a space character. Return value is a
 * vector which includes char ** data element. It supports
 * quoted string as a single slot and commented string at
 * the end of parsed string */
vector_t *
cmd_make_strvec(const char *string)
{
	const char *cp, *start;
	char *token;
	int strlen;
	vector_t *strvec;
  
	if (string == NULL)
		return NULL;
  
	cp = string;

	/* Skip white spaces. */
	while (isspace((int) *cp) && *cp != '\0')
		cp++;

	/* Return if there is only white spaces */
	if (*cp == '\0')
		return NULL;

	if (*cp == '!' || *cp == '#')
		return NULL;

	/* Prepare return vector. */
	strvec = vector_init(VECTOR_DEFAULT_SIZE);

	/* Copy each command piece and set into vector. */
	while (1) {
		start = cp;
		if (*cp == '"') {
			cp++;
			token = MALLOC(2);
			*(token) = '"';
			*(token + 1) = '\0';
		} else {
			while (!(isspace((int) *cp) || *cp == '\r' || *cp == '\n') &&
			       *cp != '\0' && *cp != '"')
				cp++;
			strlen = cp - start;
			token = (char *) MALLOC(strlen + 1);
			memcpy(token, start, strlen);
			*(token + strlen) = '\0';
		}

		/* Alloc & set the slot */
		vector_alloc_slot(strvec);
		vector_set_slot(strvec, token);

		while ((isspace((int) *cp) || *cp == '\n' || *cp == '\r') &&
		       *cp != '\0')
			cp++;

		if (*cp == '\0' || *cp == '!' || *cp == '#')
			return strvec;
	}
}

/* Free allocated string vector. */
void
cmd_free_strvec(vector_t *v)
{
	unsigned int i;
	char *cp;

	if (!v)
		return;

	for (i = 0; i < vector_active (v); i++) {
		if ((cp = vector_slot (v, i)) != NULL) {
			FREE(cp);
		}
	}

	vector_free(v);
}

/* Fetch next description.  Used in cmd_make_descvec(). */
static char *
cmd_desc_str(const char **string)
{
	const char *cp, *start;
	char *token;
	int strlen;
  
	cp = *string;

	if (cp == NULL)
		return NULL;

	/* Skip white spaces. */
	while (isspace ((int) *cp) && *cp != '\0')
		cp++;

	/* Return if there is only white spaces */
	if (*cp == '\0')
		return NULL;

	start = cp;

	while (!(*cp == '\r' || *cp == '\n') && *cp != '\0')
		cp++;

	strlen = cp - start;
	token = (char *) MALLOC(strlen + 1);
	memcpy(token, start, strlen);
	*(token + strlen) = '\0';

	*string = cp;

	return token;
}

/* New string vector. */
static vector_t *
cmd_make_descvec(const char *string, const char *descstr)
{
	int multiple = 0;
	const char *sp;
	char *token;
	int len;
	const char *cp;
	const char *dp;
	vector_t *allvec;
	vector_t *strvec = NULL;
	desc_t *desc;

	cp = string;
	dp = descstr;

	if (cp == NULL)
		return NULL;

	allvec = vector_init(VECTOR_DEFAULT_SIZE);

	while (1) {
		while (isspace ((int) *cp) && *cp != '\0')
			cp++;

		if (*cp == '(') {
			multiple = 1;
			cp++;
		}

		if (*cp == ')') {
			multiple = 0;
			cp++;
		}

		if (*cp == '|') {
			if (!multiple) {
				log_message(LOG_ERR, "Command parse error!: %s\n", string);
				exit(1);
			}
			cp++;
		}
      
		while (isspace ((int) *cp) && *cp != '\0')
			cp++;

		if (*cp == '(') {
			multiple = 1;
			cp++;
		}

		if (*cp == '\0') 
			return allvec;

		sp = cp;

		while (!(isspace ((int) *cp) || *cp == '\r' ||
		       *cp == '\n' || *cp == ')' || *cp == '|') && *cp != '\0')
			cp++;

		len = cp - sp;

		token = (char *) MALLOC(len + 1);
		memcpy (token, sp, len);
		*(token + len) = '\0';

		desc = (desc_t *) MALLOC(sizeof(desc_t));
		desc->cmd = token;
		desc->str = cmd_desc_str(&dp);

		if (multiple) {
			if (multiple == 1) {
				strvec = vector_init(VECTOR_DEFAULT_SIZE);
				vector_set(allvec, strvec);
			}
			multiple++;
		} else {
			strvec = vector_init(VECTOR_DEFAULT_SIZE);
			vector_set(allvec, strvec);
		}
		vector_set(strvec, desc);
	}
}

/* Count mandantory string vector size.  This is to determine inputed
 * command has enough command length. */
static int
cmd_cmdsize(vector_t *strvec)
{
	unsigned int i;
	int size = 0;
	vector_t *descvec;
	desc_t *desc;

	for (i = 0; i < vector_active (strvec); i++) {
		if ((descvec = vector_slot (strvec, i)) != NULL) {
			if ((vector_active (descvec)) == 1
			    && (desc = vector_slot (descvec, 0)) != NULL) {
				if (desc->cmd == NULL || CMD_OPTION (desc->cmd))
					return size;
				else
					size++;
			} else {
				size++;
			}
		}
	}

	return size;
}

/* Return prompt character of specified node. */
const char *
cmd_prompt(node_type_t node)
{
	cmd_node_t *cnode;

	cnode = vector_slot(cmdvec, node);
	return cnode->prompt;
}

/* Install a command into a node. */
void
install_element(node_type_t ntype, cmd_element_t *cmd)
{
	cmd_node_t *cnode;
  
	/* cmd_init hasn't been called */
	if (!cmdvec)
		return;
  
	cnode = vector_slot(cmdvec, ntype);

	if (cnode == NULL) {
		log_message(LOG_ERR, "Command node %d doesn't exist, please check it\n"
				   , ntype);
		exit(1);
	}

	vector_set(cnode->cmd_vector, cmd);

	if (cmd->strvec == NULL)
		cmd->strvec = cmd_make_descvec(cmd->string, cmd->doc);

	cmd->cmdsize = cmd_cmdsize(cmd->strvec);
}

static const unsigned char itoa64[] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
to64(char *s, long v, int n)
{
	while (--n >= 0) {
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}
}

static char *
zencrypt (const char *passwd)
{
	char salt[6];
	timeval_t tv;
	char *crypt(const char *, const char *);

	gettimeofday(&tv,0);
  
	to64(&salt[0], random(), 3);
	to64(&salt[3], tv.tv_usec, 3);
	salt[5] = '\0';

	return crypt(passwd, salt);
}

/* This function write configuration of this host. */
static int
config_write_host(vty_t *vty)
{
	if (host.name)
		vty_out(vty, "hostname %s%s", host.name, VTY_NEWLINE);

	if (host.encrypt) {
		if (host.password_encrypt)
			vty_out(vty, "password 8 %s%s", host.password_encrypt, VTY_NEWLINE); 
		if (host.enable_encrypt)
			vty_out(vty, "enable password 8 %s%s", host.enable_encrypt, VTY_NEWLINE); 
	} else {
		if (host.password)
			vty_out(vty, "password %s%s", host.password, VTY_NEWLINE);
		if (host.enable)
			vty_out(vty, "enable password %s%s", host.enable, VTY_NEWLINE);
	}

	if (host.advanced)
		vty_out(vty, "service advanced-vty%s", VTY_NEWLINE);

	if (host.encrypt)
		vty_out(vty, "service password-encryption%s", VTY_NEWLINE);

	if (host.lines >= 0)
		vty_out(vty, "service terminal-length %d%s", host.lines,
			VTY_NEWLINE);

	if (host.motdfile)
		vty_out(vty, "banner motd file %s%s", host.motdfile, VTY_NEWLINE);
	else if (!host.motd)
		vty_out(vty, "no banner motd%s", VTY_NEWLINE);

	return 1;
}

/* Utility function for getting command vector. */
static vector_t *
cmd_node_vector(vector_t *v, node_type_t ntype)
{
	cmd_node_t *cnode = vector_slot(v, ntype);

	return cnode->cmd_vector;
}

/* Completion match types. */
static match_type_t
cmd_ipv4_match(const char *str)
{
	const char *sp;
	int dots = 0, nums = 0;
	char buf[4];

	if (str == NULL)
		return partly_match;

	for (;;) {
		memset(buf, 0, sizeof(buf));
		sp = str;
		while (*str != '\0') {
			if (*str == '.') {
				if (dots >= 3)
					return no_match;

				if (*(str + 1) == '.')
					return no_match;

				if (*(str + 1) == '\0')
					return partly_match;

				dots++;
				break;
			}
			if (!isdigit ((int) *str))
				return no_match;

			str++;
		}

		if (str - sp > 3)
			return no_match;

		strncpy (buf, sp, str - sp);
		if (atoi (buf) > 255)
			return no_match;

		nums++;

		if (*str == '\0')
			break;

		str++;
    	}

	if (nums < 4)
		return partly_match;

	return exact_match;
}

static match_type_t
cmd_ipv4_prefix_match(const char *str)
{
	const char *sp;
	int dots = 0;
	char buf[4];

	if (str == NULL)
		return partly_match;

	for (;;) {
		memset (buf, 0, sizeof (buf));
		sp = str;
		while (*str != '\0' && *str != '/') {
			if (*str == '.') {
				if (dots == 3)
					return no_match;

				if (*(str + 1) == '.' || *(str + 1) == '/')
					return no_match;

				if (*(str + 1) == '\0')
					return partly_match;

				dots++;
				break;
			}

			if (!isdigit ((int) *str))
				return no_match;

			str++;
		}

		if (str - sp > 3)
			return no_match;

		strncpy (buf, sp, str - sp);
		if (atoi (buf) > 255)
			return no_match;

		if (dots == 3) {
			if (*str == '/') {
				if (*(str + 1) == '\0')
					return partly_match;

				str++;
				break;
			} else if (*str == '\0') {
				return partly_match;
			}
		}

		if (*str == '\0')
			return partly_match;

		str++;
	}

	sp = str;
	while (*str != '\0') {
		if (!isdigit ((int) *str))
			return no_match;

		str++;
	}

	if (atoi (sp) > 32)
		return no_match;

	return exact_match;
}

static match_type_t
cmd_ipv6_match(const char *str)
{
	struct sockaddr_in6 sin6_dummy;
	int ret;

	if (str == NULL)
		return partly_match;

	if (strspn(str, IPV6_ADDR_STR) != strlen (str))
		return no_match;

	/* use inet_pton that has a better support,
	 * for example inet_pton can support the automatic addresses:
	 *  ::1.2.3.4
	 */
	ret = inet_pton(AF_INET6, str, &sin6_dummy.sin6_addr);
	if (ret == 1)
		return exact_match;

	return no_match;
}

static match_type_t
cmd_ipv6_prefix_match(const char *str)
{
	int state = STATE_START;
	int colons = 0, nums = 0, double_colon = 0;
	int mask;
	const char *sp = NULL;
	char *endptr = NULL;

	if (str == NULL)
		return partly_match;

	if (strspn(str, IPV6_PREFIX_STR) != strlen (str))
		return no_match;

	while (*str != '\0' && state != STATE_MASK) {
		switch (state) {
		case STATE_START:
			if (*str == ':') {
				if (*(str + 1) != ':' && *(str + 1) != '\0')
					return no_match;
				colons--;
				state = STATE_COLON;
			} else {
				sp = str;
				state = STATE_ADDR;
			}
			continue;

		case STATE_COLON:
			colons++;
			if (*(str + 1) == '/')
				return no_match;

			if (*(str + 1) == ':') {
				state = STATE_DOUBLE;
			} else {
				sp = str + 1;
				state = STATE_ADDR;
			}
			break;

		case STATE_DOUBLE:
			if (double_colon)
				return no_match;

			if (*(str + 1) == ':')
				return no_match;

			if (*(str + 1) != '\0' && *(str + 1) != '/')
				colons++;
			sp = str + 1;

			state = (*(str + 1) == '/') ? STATE_SLASH : STATE_ADDR;

			double_colon++;
			nums += 1;
			break;

		case STATE_ADDR:
			if (*(str + 1) == ':' || *(str + 1) == '.' ||
			    *(str + 1) == '\0' || *(str + 1) == '/') {
				if (str - sp > 3)
					return no_match;

				for (; sp <= str; sp++)
					if (*sp == '/')
						return no_match;

				nums++;

				if (*(str + 1) == ':') {
					state = STATE_COLON;
				} else if (*(str + 1) == '.') {
					if (!(colons || double_colon))
						return no_match;
					state = STATE_DOT;
				} else if (*(str + 1) == '/') {
					state = STATE_SLASH;
				}
			}
			break;

		case STATE_DOT:
			state = STATE_ADDR;
			break;

		case STATE_SLASH:
			if (*(str + 1) == '\0')
				return partly_match;

			state = STATE_MASK;
			break;

		default:
			break;
		}

		if (nums > 11)
			return no_match;

		if (colons > 7)
			return no_match;

		str++;
	}

	if (state < STATE_MASK)
		return partly_match;

	mask = strtol(str, &endptr, 10);
	if (*endptr != '\0')
		return no_match;

	if (mask < 0 || mask > 128)
		return no_match;
  
	return exact_match;
}

static int
cmd_range_match(const char *range, const char *str)
{
	char *p;
	char buf[DECIMAL_STRLEN_MAX + 1];
	char *endptr = NULL;
	unsigned long min, max, val;

	if (str == NULL)
		return 1;

	val = strtoul(str, &endptr, 10);
	if (*endptr != '\0')
		return 0;

	range++;
	p = strchr(range, '-');
	if (p == NULL)
		return 0;
	if (p - range > DECIMAL_STRLEN_MAX)
		return 0;
	strncpy(buf, range, p - range);
	buf[p - range] = '\0';
	min = strtoul(buf, &endptr, 10);
	if (*endptr != '\0')
		return 0;

	range = p + 1;
	p = strchr (range, '>');
	if (p == NULL)
		return 0;
	if (p - range > DECIMAL_STRLEN_MAX)
		return 0;
	strncpy(buf, range, p - range);
	buf[p - range] = '\0';
	max = strtoul(buf, &endptr, 10);
	if (*endptr != '\0')
		return 0;

	if (val < min || val > max)
		return 0;

	return 1;
}

/* Make completion match and return match type flag. */
static match_type_t
cmd_filter_by_completion(char *command, vector_t *v, unsigned int index)
{
	unsigned int i;
	const char *str;
	cmd_element_t *cmd_element;
	match_type_t match_type;
	vector_t *descvec;
	desc_t *desc;

	match_type = no_match;

	/* If command and cmd_element string does not match set NULL to vector */
	for (i = 0; i < vector_active (v); i++) {
		if ((cmd_element = vector_slot(v, i)) != NULL) {
			if (index >= vector_active(cmd_element->strvec)) {
				vector_slot(v, i) = NULL;
			} else {
				unsigned int j;
				int matched = 0;

				descvec = vector_slot(cmd_element->strvec, index);

				for (j = 0; j < vector_active(descvec); j++) {
					if ((desc = vector_slot(descvec, j))) {
						str = desc->cmd;

						if (CMD_VARARG(str)) {
							if (match_type < vararg_match)
								match_type = vararg_match;
							matched++;
						} else if (CMD_RANGE(str)) {
							if (cmd_range_match(str, command)) {
								if (match_type < range_match)
									match_type = range_match;
								matched++;
							}
						} else if (CMD_IPV6(str)) {
							if (cmd_ipv6_match(command)) {
								if (match_type < ipv6_match)
									match_type = ipv6_match;
								matched++;
							}
						} else if (CMD_IPV6_PREFIX(str)) {
							if (cmd_ipv6_prefix_match(command)) {
								if (match_type < ipv6_prefix_match)
									match_type = ipv6_prefix_match;
								matched++;
							}
						} else if (CMD_IPV4(str)) {
							if (cmd_ipv4_match(command)) {
								if (match_type < ipv4_match)
									match_type = ipv4_match;
								matched++;
							}
						} else if (CMD_IPV4_PREFIX(str)) {
							if (cmd_ipv4_prefix_match(command)) {
								if (match_type < ipv4_prefix_match)
									match_type = ipv4_prefix_match;
								matched++;
							}
						} else if (CMD_OPTION(str) || CMD_VARIABLE(str)) {
							if (match_type < extend_match)
								match_type = extend_match;
							matched++;
						} else if (strncmp(command, str, strlen(command)) == 0) {
							if (strcmp(command, str) == 0) {
								match_type = exact_match;
							} else {
								if (match_type < partly_match)
									match_type = partly_match;
							}
							matched++;
						}
					}
				}

				if (!matched)
					vector_slot(v, i) = NULL;
			}
		}
	}

	return match_type;
}

/* Filter vector by command character with index. */
static match_type_t
cmd_filter_by_string(char *command, vector_t *v, unsigned int index)
{
	unsigned int i;
	const char *str;
	cmd_element_t *cmd_element;
	match_type_t match_type;
	vector_t *descvec;
	desc_t *desc;

	match_type = no_match;

	/* If command and cmd_element string does not match set NULL to vector */
	for (i = 0; i < vector_active(v); i++) {
		if ((cmd_element = vector_slot (v, i)) != NULL) {
			/* If given index is bigger than max string vector of command,
			 * set NULL */
			if (index >= vector_active(cmd_element->strvec)) {
				vector_slot(v, i) = NULL;
			} else {
				unsigned int j;
				int matched = 0;

				descvec = vector_slot(cmd_element->strvec, index);

				for (j = 0; j < vector_active(descvec); j++) {
					if ((desc = vector_slot(descvec, j))) {
						str = desc->cmd;

						if (CMD_VARARG(str)) {
							if (match_type < vararg_match)
								match_type = vararg_match;
							matched++;
						} else if (CMD_RANGE (str)) {
							if (cmd_range_match(str, command)) {
								if (match_type < range_match)
									match_type = range_match;
								matched++;
							}
						} else if (CMD_IPV6(str)) {
							if (cmd_ipv6_match (command) == exact_match) {
								if (match_type < ipv6_match)
									match_type = ipv6_match;
								matched++;
							}
						} else if (CMD_IPV6_PREFIX(str)) {
							if (cmd_ipv6_prefix_match(command) == exact_match) {
								if (match_type < ipv6_prefix_match)
									match_type = ipv6_prefix_match;
								matched++;
							}
						} else if (CMD_IPV4(str)) {
							if (cmd_ipv4_match (command) == exact_match) {
								if (match_type < ipv4_match)
									match_type = ipv4_match;
								matched++;
							}
						} else if (CMD_IPV4_PREFIX(str)) {
							if (cmd_ipv4_prefix_match(command) == exact_match) {
								if (match_type < ipv4_prefix_match)
									match_type = ipv4_prefix_match;
								matched++;
							}
						} else if (CMD_OPTION(str) || CMD_VARIABLE(str)) {
							if (match_type < extend_match)
								match_type = extend_match;
							matched++;
						} else {
							if (strcmp(command, str) == 0) {
								match_type = exact_match;
								matched++;
							}
						}
					}
				}

				if (!matched)
					vector_slot(v, i) = NULL;
			}
		}
	}

	return match_type;
}

/* Check ambiguous match */
static int
is_cmd_ambiguous(char *command, vector_t *v, int index, match_type_t type)
{
	unsigned int i, j;
	const char *str = NULL;
	cmd_element_t *cmd_element;
	const char *matched = NULL;
	vector_t *descvec;
	desc_t *desc;

	for (i = 0; i < vector_active(v); i++) {
		if ((cmd_element = vector_slot(v, i)) != NULL) {
			int match = 0;

			descvec = vector_slot(cmd_element->strvec, index);

			for (j = 0; j < vector_active (descvec); j++) {
				if ((desc = vector_slot (descvec, j))) {
					match_type_t ret;
	      
					str = desc->cmd;

					switch (type) {
					case exact_match:
						if (!(CMD_OPTION(str) || CMD_VARIABLE(str)) &&
						    strcmp(command, str) == 0)
							match++;
						break;

					case partly_match:
						if (!(CMD_OPTION (str) || CMD_VARIABLE (str)) &&
						    strncmp(command, str, strlen(command)) == 0) {
							if (matched && strcmp(matched, str) != 0)
								return 1;	/* There is ambiguous match. */
							else
								matched = str;
							match++;
						}
						break;

					case range_match:
						if (cmd_range_match(str, command)) {
							if (matched && strcmp(matched, str) != 0)
								return 1;
							else
								matched = str;
							match++;
						}
						break;

					case ipv6_match:
						if (CMD_IPV6(str))
							match++;
						break;

					case ipv6_prefix_match:
						if ((ret = cmd_ipv6_prefix_match(command)) != no_match) {
							if (ret == partly_match)
								return 2;	/* There is incomplete match. */
							match++;
						}
						break;

					case ipv4_match:
						if (CMD_IPV4(str))
							match++;
						break;

					case ipv4_prefix_match:
						if ((ret = cmd_ipv4_prefix_match(command)) != no_match) {
							if (ret == partly_match)
								return 2;	/* There is incomplete match. */
							match++;
						}
						break;

					case extend_match:
						if (CMD_OPTION(str) || CMD_VARIABLE(str))
							match++;
						break;

					case no_match:
					default:
						break;
					}
				}
			}

			if (!match)
				vector_slot(v, i) = NULL;
		}
	}

	return 0;
}

/* If src matches dst return dst string, otherwise return NULL */
static const char *
cmd_entry_function(const char *src, const char *dst)
{
	/* Skip variable arguments. */
	if (CMD_OPTION(dst) || CMD_VARIABLE(dst) || CMD_VARARG(dst) ||
	    CMD_IPV4(dst) || CMD_IPV4_PREFIX(dst) || CMD_RANGE(dst))
		return NULL;

	/* In case of 'command \t', given src is NULL string. */
	if (src == NULL)
		return dst;

	/* Matched with input string. */
	if (strncmp(src, dst, strlen (src)) == 0)
		return dst;

	return NULL;
}

/* If src matches dst return dst string, otherwise return NULL */
/* This version will return the dst string always if it is
   CMD_VARIABLE for '?' key processing */
static const char *
cmd_entry_function_desc(const char *src, const char *dst)
{
	if (CMD_VARARG(dst))
		return dst;

	if (CMD_RANGE(dst)) {
		if (cmd_range_match(dst, src))
			return dst;
		return NULL;
	}

	if (CMD_IPV6 (dst)) {
		if (cmd_ipv6_match(src))
			return dst;
		return NULL;
	}

	if (CMD_IPV6_PREFIX(dst)) {
		if (cmd_ipv6_prefix_match(src))
			return dst;
		return NULL;
	}

	if (CMD_IPV4(dst)) {
		if (cmd_ipv4_match(src))
			return dst;
		return NULL;
	}

	if (CMD_IPV4_PREFIX(dst)) {
		if (cmd_ipv4_prefix_match(src))
			return dst;
		return NULL;
	}

	/* Optional or variable commands always match on '?' */
	if (CMD_OPTION(dst) || CMD_VARIABLE(dst))
		return dst;

	/* In case of 'command \t', given src is NULL string. */
	if (src == NULL)
		return dst;

	if (strncmp(src, dst, strlen(src)) == 0)
		return dst;

	return NULL;
}

/* Check same string element existence.  If it isn't there return
 *  1. */
static int
cmd_unique_string(vector_t *v, const char *str)
{
	unsigned int i;
	char *match;

	for (i = 0; i < vector_active(v); i++) {
		if ((match = vector_slot(v, i)) != NULL) {
			if (strcmp(match, str) == 0) {
				return 0;
			}
		}
	}

	return 1;
}

/* Compare string to description vector.  If there is same string
 * return 1 else return 0. */
static int
desc_unique_string(vector_t *v, const char *str)
{
	unsigned int i;
	desc_t *desc;

	for (i = 0; i < vector_active(v); i++) {
		if ((desc = vector_slot(v, i)) != NULL) {
			if (strcmp(desc->cmd, str) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

static int 
cmd_try_do_shortcut(node_type_t node, char* first_word)
{
	if (first_word != NULL && node != AUTH_NODE &&
	    node != VIEW_NODE && node != AUTH_ENABLE_NODE &&
	    node != ENABLE_NODE &&
	    strcmp("do", first_word) == 0)
		return 1;

	return 0;
}

/* '?' describe command support. */
static vector_t *
cmd_describe_command_real(vector_t *vline, vty_t *vty, int *status)
{
	vector_t *cmd_vector;
	vector_t *matchvec;
	cmd_element_t *cmd_element;
	unsigned int index, i;
	int ret;
	match_type_t match;
	char *command;

	/* Set index. */
	if (vector_active(vline) == 0) {
		*status = CMD_ERR_NO_MATCH;
		return NULL;
	}

	index = vector_active (vline) - 1;
  
	/* Make copy vector of current node's command vector. */
	cmd_vector = vector_copy(cmd_node_vector(cmdvec, vty->node));

	/* Prepare match vector */
	matchvec = vector_init(INIT_MATCHVEC_SIZE);

	/* Filter commands. */
	/* Only words precedes current word will be checked in this loop. */
	for (i = 0; i < index; i++) {
		if ((command = vector_slot(vline, i))) {
			match = cmd_filter_by_completion(command, cmd_vector, i);
	
			if (match == vararg_match) {
				cmd_element_t *cmd_element;
				vector_t *descvec;
				unsigned int j, k;

				for (j = 0; j < vector_active(cmd_vector); j++)
					if ((cmd_element = vector_slot(cmd_vector, j)) != NULL
					    && (vector_active(cmd_element->strvec))) {
						descvec = vector_slot(cmd_element->strvec,
								      vector_active(cmd_element->strvec) - 1);
						for (k = 0; k < vector_active(descvec); k++) {
							desc_t *desc = vector_slot(descvec, k);
							vector_set(matchvec, desc);
						}
					}
            
					vector_set(matchvec, &desc_cr);
					vector_free(cmd_vector);

					return matchvec;
			}

			if ((ret = is_cmd_ambiguous(command, cmd_vector, i, match)) == 1) {
				vector_free(cmd_vector);
				vector_free(matchvec);
				*status = CMD_ERR_AMBIGUOUS;
				return NULL;
			} else if (ret == 2) {
				vector_free(cmd_vector);
				vector_free(matchvec);
				*status = CMD_ERR_NO_MATCH;
				return NULL;
			}
		}
	}

	/* Prepare match vector:
	 *  matchvec = vector_init (INIT_MATCHVEC_SIZE); */

	/* Make sure that cmd_vector is filtered based on current word */
	command = vector_slot(vline, index);
	if (command)
		match = cmd_filter_by_completion(command, cmd_vector, index);

	/* Make description vector. */
	for (i = 0; i < vector_active(cmd_vector); i++) {
		if ((cmd_element = vector_slot(cmd_vector, i)) != NULL) {
			vector_t *strvec = cmd_element->strvec;

			/* if command is NULL, index may be equal to vector_active */
			if (command && index >= vector_active(strvec)) {
				vector_slot(cmd_vector, i) = NULL;
			} else {
				/* Check if command is completed. */
				if (command == NULL && index == vector_active(strvec)) {
					if (!desc_unique_string(matchvec, command_cr))
						vector_set(matchvec, &desc_cr);
				} else {
					unsigned int j;
					vector_t *descvec = vector_slot(strvec, index);
					desc_t *desc;

					for (j = 0; j < vector_active (descvec); j++) {
						if ((desc = vector_slot (descvec, j))) {
							const char *string;

							string = cmd_entry_function_desc(command, desc->cmd);
							if (string) {
								/* Uniqueness check */
								if (!desc_unique_string(matchvec, string))
									vector_set(matchvec, desc);
							}
						}
					}
				}
			}
		}
	}

	vector_free(cmd_vector);

	if (vector_slot(matchvec, 0) == NULL) {
		vector_free(matchvec);
		*status = CMD_ERR_NO_MATCH;
		return NULL;
	}

	*status = CMD_SUCCESS;
	return matchvec;
}

vector_t *
cmd_describe_command(vector_t *vline, vty_t *vty, int *status)
{
	vector_t *ret;

	if (cmd_try_do_shortcut(vty->node, vector_slot(vline, 0))) {
		node_type_t onode;
		vector_t *shifted_vline;
		unsigned int index;

		onode = vty->node;
		vty->node = ENABLE_NODE;
		/* We can try it on enable node, cos' the vty is authenticated */

		shifted_vline = vector_init(vector_count(vline));
		/* use memcpy? */
		for (index = 1; index < vector_active(vline); index++) {
			vector_set_index(shifted_vline, index-1, vector_lookup(vline, index));
		}

		ret = cmd_describe_command_real(shifted_vline, vty, status);

		vector_free(shifted_vline);
		vty->node = onode;
		return ret;
	}


	return cmd_describe_command_real(vline, vty, status);
}


/* Check LCD of matched command. */
static int
cmd_lcd(char **matched)
{
	int i, j, lcd = -1;
	char *s1, *s2;
	char c1, c2;

	if (matched[0] == NULL || matched[1] == NULL)
		return 0;

	for (i = 1; matched[i] != NULL; i++) {
		s1 = matched[i - 1];
		s2 = matched[i];

		for (j = 0; (c1 = s1[j]) && (c2 = s2[j]); j++) {
			if (c1 != c2)
				break;
		}

		if (lcd < 0) {
			lcd = j;
		} else {
			if (lcd > j)
				lcd = j;
		}
	}

	return lcd;
}

/* Command line completion support. */
static char **
cmd_complete_command_real(vector_t *vline, vty_t *vty, int *status)
{
	vector_t *cmd_vector = vector_copy(cmd_node_vector(cmdvec, vty->node));
	vector_t *matchvec;
	cmd_element_t *cmd_element;
	unsigned int index, i;
	char **match_str;
	desc_t *desc;
	vector_t *descvec;
	char *command;
	int lcd;

	if (vector_active(vline) == 0) {
		vector_free(cmd_vector);
		*status = CMD_ERR_NO_MATCH;
		return NULL;
	}

	index = vector_active (vline) - 1;

	/* First, filter by preceeding command string */
	for (i = 0; i < index; i++) {
		if ((command = vector_slot(vline, i))) {
			match_type_t match;
			int ret;

			/* First try completion match, if there is exactly match return 1 */
			match = cmd_filter_by_completion(command, cmd_vector, i);

			/* If there is exact match then filter ambiguous match else check
			 * ambiguousness. */
			if ((ret = is_cmd_ambiguous(command, cmd_vector, i, match)) == 1) {
				vector_free(cmd_vector);
				*status = CMD_ERR_AMBIGUOUS;
				return NULL;
			}
		}
	}
  
	/* Prepare match vector. */
	matchvec = vector_init(INIT_MATCHVEC_SIZE);

	/* Now we got into completion */
	for (i = 0; i < vector_active(cmd_vector); i++) {
		if ((cmd_element = vector_slot(cmd_vector, i))) {
			const char *string;
			vector_t *strvec = cmd_element->strvec;

			/* Check field length */
			if (index >= vector_active(strvec)) {
				vector_slot(cmd_vector, i) = NULL;
			} else {
				unsigned int j;

				descvec = vector_slot(strvec, index);
				for (j = 0; j < vector_active(descvec); j++) {
					if ((desc = vector_slot(descvec, j))) {
						if ((string = 
							cmd_entry_function(vector_slot(vline, index),
									   desc->cmd)))
								if (cmd_unique_string (matchvec, string))
									vector_set(matchvec, strdup(string));
					}
				}
			}
		}
	}

	/* We don't need cmd_vector any more. */
	vector_free(cmd_vector);

	/* No matched command */
	if (vector_slot(matchvec, 0) == NULL) {
		vector_free(matchvec);

		/* In case of 'command \t' pattern.  Do you need '?' command at
		 * the end of the line. */
		if (vector_slot(vline, index) == '\0')
			*status = CMD_ERR_NOTHING_TODO;
		else
			*status = CMD_ERR_NO_MATCH;
		return NULL;
	}

	/* Only one matched */
	if (vector_slot(matchvec, 1) == NULL) {
		match_str = (char **) matchvec->slot;
		vector_only_wrapper_free(matchvec);
		*status = CMD_COMPLETE_FULL_MATCH;
		return match_str;
	}

	/* Make it sure last element is NULL. */
	vector_set(matchvec, NULL);

	/* Check LCD of matched strings. */
	if (vector_slot (vline, index) != NULL) {
		lcd = cmd_lcd((char **) matchvec->slot);

		if (lcd) {
			int len = strlen(vector_slot(vline, index));

			if (len < lcd) {
				char *lcdstr;

				lcdstr = MALLOC(lcd + 1);
				memcpy(lcdstr, matchvec->slot[0], lcd);
				lcdstr[lcd] = '\0';

				/* Free matchvec. */
				for (i = 0; i < vector_active(matchvec); i++) {
					if (vector_slot(matchvec, i))
						FREE(vector_slot(matchvec, i));
				}
				vector_free(matchvec);

				/* Make new matchvec. */
				matchvec = vector_init(INIT_MATCHVEC_SIZE);
				vector_set(matchvec, lcdstr);
				match_str = (char **) matchvec->slot;
				vector_only_wrapper_free(matchvec);

				*status = CMD_COMPLETE_MATCH;
				return match_str;
			}
		}
	}

	match_str = (char **) matchvec->slot;
	vector_only_wrapper_free(matchvec);
	*status = CMD_COMPLETE_LIST_MATCH;
	return match_str;
}

char **
cmd_complete_command(vector_t *vline, vty_t *vty, int *status)
{
	char **ret;

	if (cmd_try_do_shortcut(vty->node, vector_slot(vline, 0))) {
		node_type_t onode;
		vector_t *shifted_vline;
		unsigned int index;

		onode = vty->node;
		vty->node = ENABLE_NODE;
		/* We can try it on enable node, cos' the vty is authenticated */

		shifted_vline = vector_init(vector_count(vline));
		/* use memcpy? */
		for (index = 1; index < vector_active(vline); index++) {
			vector_set_index (shifted_vline, index-1, vector_lookup(vline, index));
		}

		ret = cmd_complete_command_real(shifted_vline, vty, status);

		vector_free(shifted_vline);
		vty->node = onode;
		return ret;
	}

	return cmd_complete_command_real(vline, vty, status);
}

/* return parent node */
/* MUST eventually converge on CONFIG_NODE */
node_type_t
node_parent(node_type_t node)
{
	return CONFIG_NODE;
}

/* Execute command by argument vline vector. */
static int
cmd_execute_command_real(vector_t *vline, vty_t *vty, cmd_element_t **cmd)
{
	unsigned int index, i;
	vector_t *cmd_vector;
	cmd_element_t *cmd_element;
	cmd_element_t *matched_element;
	unsigned int matched_count, incomplete_count;
	int argc;
	const char *argv[CMD_ARGC_MAX];
	match_type_t match = 0;
	int varflag;
	char *command;

	/* Make copy of command elements. */
	cmd_vector = vector_copy(cmd_node_vector(cmdvec, vty->node));

	for (index = 0; index < vector_active(vline); index++) {
		if ((command = vector_slot(vline, index))) {
			int ret;

			match = cmd_filter_by_completion(command, cmd_vector, index);

			if (match == vararg_match)
				break;
        
			ret = is_cmd_ambiguous(command, cmd_vector, index, match);
			if (ret == 1) {
				vector_free(cmd_vector);
				return CMD_ERR_AMBIGUOUS;
			} else if (ret == 2) {
				vector_free(cmd_vector);
				return CMD_ERR_NO_MATCH;
			}
		}
	}

	/* Check matched count. */
	matched_element = NULL;
	matched_count = 0;
	incomplete_count = 0;

	for (i = 0; i < vector_active(cmd_vector); i++) {
		if ((cmd_element = vector_slot(cmd_vector, i))) {
			if (match == vararg_match || index >= cmd_element->cmdsize) {
				matched_element = cmd_element;
				matched_count++;
			} else {
				incomplete_count++;
			}
		}
	}

	/* Finish of using cmd_vector. */
	vector_free(cmd_vector);

	/* To execute command, matched_count must be 1. */
	if (matched_count == 0) {
		if (incomplete_count)
			return CMD_ERR_INCOMPLETE;
		return CMD_ERR_NO_MATCH;
	}

	if (matched_count > 1)
		return CMD_ERR_AMBIGUOUS;

	/* Argument treatment */
	varflag = argc = 0;

	for (i = 0; i < vector_active(vline); i++) {
		if (varflag) {
			argv[argc++] = vector_slot(vline, i);
		} else {
			vector_t *descvec = vector_slot(matched_element->strvec, i);

			if (vector_active(descvec) == 1) {
				desc_t *desc = vector_slot (descvec, 0);

				if (CMD_VARARG(desc->cmd))
					varflag = 1;

				if (varflag || CMD_VARIABLE(desc->cmd) || CMD_OPTION(desc->cmd))
					argv[argc++] = vector_slot (vline, i);
			} else {
				argv[argc++] = vector_slot (vline, i);
			}
		}

		if (argc >= CMD_ARGC_MAX)
			return CMD_ERR_EXEED_ARGC_MAX;
	}

	/* For vtysh execution. */
	if (cmd)
		*cmd = matched_element;

	if (matched_element->daemon)
		return CMD_SUCCESS_DAEMON;

	/* Execute matched command. */
	return (*matched_element->func) (matched_element, vty, argc, argv);
}

int
cmd_execute_command(vector_t *vline, vty_t *vty, cmd_element_t **cmd, int vtysh)
{
	int ret, saved_ret, tried = 0;
	node_type_t onode, try_node;

	onode = try_node = vty->node;

	if (cmd_try_do_shortcut(vty->node, vector_slot(vline, 0))) {
		vector_t *shifted_vline;
		unsigned int index;

		vty->node = ENABLE_NODE;
		/* We can try it on enable node, cos' the vty is authenticated */

		shifted_vline = vector_init(vector_count(vline));
		/* use memcpy? */
		for (index = 1; index < vector_active (vline); index++) {
			vector_set_index(shifted_vline, index-1, vector_lookup(vline, index));
		}

		ret = cmd_execute_command_real(shifted_vline, vty, cmd);

		vector_free(shifted_vline);
		vty->node = onode;
		return ret;
	}


	saved_ret = ret = cmd_execute_command_real(vline, vty, cmd);

	if (vtysh)
		return saved_ret;

	/* This assumes all nodes above CONFIG_NODE are childs of CONFIG_NODE */
	while (ret != CMD_SUCCESS && ret != CMD_WARNING  && vty->node > CONFIG_NODE) {
		try_node = node_parent(try_node);
		vty->node = try_node;
		ret = cmd_execute_command_real(vline, vty, cmd);
		tried = 1;
		if (ret == CMD_SUCCESS || ret == CMD_WARNING) {
			/* succesfull command, leave the node as is */
			return ret;
		}
	}

	/* no command succeeded, reset the vty to the original node and
	 * return the error for this node */
	if (tried)
		vty->node = onode;

	return saved_ret;
}

/* Execute command by argument readline. */
int
cmd_execute_command_strict(vector_t *vline, vty_t *vty, cmd_element_t **cmd)
{
	unsigned int index, i;
	vector_t *cmd_vector;
	cmd_element_t *cmd_element;
	cmd_element_t *matched_element;
	unsigned int matched_count, incomplete_count;
	int argc;
	const char *argv[CMD_ARGC_MAX];
	int varflag;
	match_type_t match = 0;
	char *command;

	/* Make copy of command element */
	cmd_vector = vector_copy(cmd_node_vector(cmdvec, vty->node));

	for (index = 0; index < vector_active (vline); index++) {
		if ((command = vector_slot(vline, index))) {
			int ret;
	
			match = cmd_filter_by_string(vector_slot(vline, index),
						     cmd_vector, index);

			/* If command meets '.VARARG' then finish matching. */
			if (match == vararg_match)
				break;
        
			ret = is_cmd_ambiguous(command, cmd_vector, index, match);
			if (ret == 1) {
				vector_free(cmd_vector);
				return CMD_ERR_AMBIGUOUS;
			} else if (ret == 2) {
				vector_free(cmd_vector);
				return CMD_ERR_NO_MATCH;
			}
		}
	}

	/* Check matched count. */
	matched_element = NULL;
	matched_count = 0;
	incomplete_count = 0;
	for (i = 0; i < vector_active (cmd_vector); i++) {
		if (vector_slot (cmd_vector, i) != NULL) {
			cmd_element = vector_slot (cmd_vector, i);

			if (match == vararg_match || index >= cmd_element->cmdsize) {
				matched_element = cmd_element;
				matched_count++;
			} else {
				incomplete_count++;
			}
		}
	}

	/* Finish of using cmd_vector. */
	vector_free(cmd_vector);

	/* To execute command, matched_count must be 1. */
	if (matched_count == 0) {
		if (incomplete_count)
			return CMD_ERR_INCOMPLETE;
		return CMD_ERR_NO_MATCH;
	}

	if (matched_count > 1)
		return CMD_ERR_AMBIGUOUS;

	/* Argument treatment */
	varflag = argc = 0;

	for (i = 0; i < vector_active(vline); i++) {
		if (varflag) {
			argv[argc++] = vector_slot(vline, i);
		} else {
			vector_t *descvec = vector_slot(matched_element->strvec, i);

			if (vector_active(descvec) == 1) {
				desc_t *desc = vector_slot(descvec, 0);

				if (CMD_VARARG(desc->cmd))
					varflag = 1;

				if (varflag || CMD_VARIABLE(desc->cmd) || CMD_OPTION(desc->cmd))
					argv[argc++] = vector_slot (vline, i);
				} else {
					argv[argc++] = vector_slot (vline, i);
				}
		}

		if (argc >= CMD_ARGC_MAX)
			return CMD_ERR_EXEED_ARGC_MAX;
	}

	/* For vtysh execution. */
	if (cmd)
		*cmd = matched_element;

	if (matched_element->daemon)
		return CMD_SUCCESS_DAEMON;

	/* Now execute matched command */
	return (*matched_element->func) (matched_element, vty, argc, argv);
}

/* Configration make from file. */
int
config_from_file(vty_t *vty, FILE *fp)
{
	int ret;
	vector_t *vline;

	while (fgets(vty->buf, VTY_BUFSIZ, fp)) {
		vline = cmd_make_strvec(vty->buf);

		/* In case of comment line */
		if (vline == NULL)
			continue;

		/* Execute configuration command : this is strict match */
		ret = cmd_execute_command_strict(vline, vty, NULL);

		/* Try again with setting node to CONFIG_NODE */
		while (ret != CMD_SUCCESS && ret != CMD_WARNING &&
		       ret != CMD_ERR_NOTHING_TODO && vty->node != CONFIG_NODE) {
			vty->node = node_parent(vty->node);
			ret = cmd_execute_command_strict (vline, vty, NULL);
		}

		cmd_free_strvec(vline);

		if (ret != CMD_SUCCESS && ret != CMD_WARNING &&
		    ret != CMD_ERR_NOTHING_TODO)
			return ret;
	}

	return CMD_SUCCESS;
}

/* Configration from terminal */
DEFUN(config_terminal,
      config_terminal_cmd,
      "configure terminal",
      "Configuration from vty interface\n"
      "Configuration terminal\n")
{
	if (vty_config_lock (vty)) {
		vty->node = CONFIG_NODE;
	} else {
		vty_out(vty, "VTY configuration is locked by other VTY%s", VTY_NEWLINE);
			return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* Enable command */
DEFUN(enable, 
      config_enable_cmd,
      "enable",
      "Turn on privileged mode command\n")
{
	/* If enable password is NULL, change to ENABLE_NODE */
	if ((host.enable == NULL && host.enable_encrypt == NULL) ||
	    vty->type == VTY_SHELL_SERV)
		vty->node = ENABLE_NODE;
	else
		vty->node = AUTH_ENABLE_NODE;

	return CMD_SUCCESS;
}

/* Disable command */
DEFUN(disable, 
      config_disable_cmd,
      "disable",
      "Turn off privileged mode command\n")
{
	if (vty->node == ENABLE_NODE)
		vty->node = VIEW_NODE;
	return CMD_SUCCESS;
}

/* Down vty node level. */
DEFUN(config_exit,
      config_exit_cmd,
      "exit",
      "Exit current mode and down to previous mode\n")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		if (vty_shell(vty))
			exit (0);
		vty->status = VTY_CLOSE;
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		vty_config_unlock(vty);
		break;
	case VTY_NODE:
	case CFG_LOG_NODE:
		vty->node = CONFIG_NODE;
		break;
	default:
		break;
	}

	return CMD_SUCCESS;
}

/* quit is alias of exit. */
ALIAS(config_exit,
      config_quit_cmd,
      "quit",
      "Exit current mode and down to previous mode\n")
       
/* End of configuration. */
DEFUN(config_end,
      config_end_cmd,
      "end",
      "End current mode and change to enable mode.")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	case CFG_LOG_NODE:
	case CONFIG_NODE:
	case VTY_NODE:
		vty_config_unlock (vty);
		vty->node = ENABLE_NODE;
		break;
	default:
		break;
	}

	return CMD_SUCCESS;
}

/* Show version. */
DEFUN(show_version,
      show_version_cmd,
      "show version",
      SHOW_STR
      "Displays Keepalived version\n")
{
	vty_out(vty, "%s (%s).%s", VERSION_STRING, host.name?host.name:"",
		VTY_NEWLINE);
	vty_out(vty, "%s%s", COPYRIGHT_STRING, VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN(config_help,
      config_help_cmd,
      "help",
      "Description of the interactive help system\n")
{
	vty_out(vty, "This VTY provides advanced help feature.  When you need help,%s\
anytime at the command line please press '?'.%s\
%s\
If nothing matches, the help list will be empty and you must backup%s\
 until entering a '?' shows the available options.%s\
Two styles of help are provided:%s\
1. Full help is available when you are ready to enter a%s\
   command argument (e.g. 'show ?') and describes each possible%s\
   argument.%s\
2. Partial help is provided when an abbreviated argument is entered%s\
   and you want to know what arguments match the input%s\
   (e.g. 'show me?'.)%s%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN(config_list,
      config_list_cmd,
      "list",
      "Print command list\n")
{
	unsigned int i;
	cmd_node_t *cnode = vector_slot(cmdvec, vty->node);
	cmd_element_t *cmd;

	for (i = 0; i < vector_active (cnode->cmd_vector); i++)
		if ((cmd = vector_slot (cnode->cmd_vector, i)) != NULL &&
		    cmd->attr != CMD_ATTR_HIDDEN)
			vty_out(vty, "  %s%s", cmd->string, VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Write current configuration into file. */
DEFUN(config_write_file, 
      config_write_file_cmd,
      "write file",  
      "Write running configuration to memory, network, or terminal\n"
      "Write to configuration file\n")
{
	unsigned int i;
	int fd;
	cmd_node_t *node;
	char *config_file;
	char *config_file_tmp = NULL;
	char *config_file_sav = NULL;
	int ret = CMD_WARNING;
	vty_t *file_vty;

	/* Check and see if we are operating under vtysh configuration */
	if (host.config == NULL) {
		vty_out(vty, "Can't save to configuration file, using vtysh.%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Get filename. */
	config_file = host.config;
  
	config_file_sav = MALLOC(strlen(config_file) + strlen(CONF_BACKUP_EXT) + 1);
	strcpy(config_file_sav, config_file);
	strcat(config_file_sav, CONF_BACKUP_EXT);

	config_file_tmp = MALLOC(strlen(config_file) + 8);
	sprintf(config_file_tmp, "%s.XXXXXX", config_file);
  
	/* Open file to configuration write. */
	fd = mkstemp(config_file_tmp);
	if (fd < 0) {
		vty_out(vty, "Can't open configuration file %s.%s", config_file_tmp
			   , VTY_NEWLINE);
		goto finished;
	}
  
	/* Make vty for configuration file. */
	file_vty = vty_new();
	file_vty->fd = fd;
	file_vty->type = VTY_FILE;

	/* Config file header print. */
	vty_out(file_vty, "!\n! Keepalived configuration saved from vty\n!   ");
	vty_time_print(file_vty, 1);
	vty_out(file_vty, "!\n");

	for (i = 0; i < vector_active(cmdvec); i++) {
		if ((node = vector_slot(cmdvec, i)) && node->func) {
			if ((*node->func) (file_vty))
				vty_out(file_vty, "!\n");
		}
	}

	vty_close (file_vty);

	if (unlink(config_file_sav) != 0) {
		if (errno != ENOENT) {
			vty_out(vty, "Can't unlink backup configuration file %s.%s", config_file_sav
				   , VTY_NEWLINE);
			goto finished;
		}
	}

	if (link(config_file, config_file_sav) != 0) {
		vty_out(vty, "Can't backup old configuration file %s.%s", config_file_sav
			   , VTY_NEWLINE);
		goto finished;
	}

	sync();

	if (unlink(config_file) != 0) {
		vty_out(vty, "Can't unlink configuration file %s.%s", config_file
			   , VTY_NEWLINE);
		goto finished;
	}

	if (link(config_file_tmp, config_file) != 0) {
		vty_out(vty, "Can't save configuration file %s.%s", config_file
			   , VTY_NEWLINE);
		goto finished;
	}

	sync();
  
	if (chmod(config_file, 0600) != 0) {
		vty_out(vty, "Can't chmod configuration file %s: %s (%d).%s" 
			   , config_file, strerror(errno), errno, VTY_NEWLINE);
		goto finished;
	}

	vty_out(vty, "Configuration saved to %s%s", config_file, VTY_NEWLINE);
	ret = CMD_SUCCESS;

  finished:
	unlink(config_file_tmp);
	FREE(config_file_tmp);
	FREE(config_file_sav);
	return ret;
}

ALIAS(config_write_file, 
      config_write_cmd,
      "write",  
      "Write running configuration to memory, network, or terminal\n")

ALIAS(config_write_file, 
      config_write_memory_cmd,
      "write memory",  
      "Write running configuration to memory, network, or terminal\n"
      "Write configuration to the file (same as write file)\n")

ALIAS(config_write_file, 
      copy_runningconfig_startupconfig_cmd,
      "copy running-config startup-config",  
      "Copy configuration\n"
      "Copy running config to... \n"
      "Copy running config to startup config (same as write file)\n")

/* Write current configuration into the terminal. */
DEFUN(config_write_terminal,
      config_write_terminal_cmd,
      "write terminal",
      "Write running configuration to memory, network, or terminal\n"
      "Write to terminal\n")
{
	unsigned int i;
	cmd_node_t *node;

	if (vty->type == VTY_SHELL_SERV) {
		for (i = 0; i < vector_active(cmdvec); i++) {
			if ((node = vector_slot(cmdvec, i)) && node->func && node->vtysh) {
				if ((*node->func) (vty))
					vty_out(vty, "!%s", VTY_NEWLINE);
			}
		}
	} else {
		vty_out(vty, "%sCurrent configuration:%s", VTY_NEWLINE, VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);

		for (i = 0; i < vector_active(cmdvec); i++) {
			if ((node = vector_slot(cmdvec, i)) && node->func) {
				if ((*node->func) (vty))
					vty_out(vty, "!%s", VTY_NEWLINE);
			}
		}
		vty_out (vty, "end%s",VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/* Write current configuration into the terminal. */
ALIAS(config_write_terminal,
      show_running_config_cmd,
      "show running-config",
      SHOW_STR
      "running configuration\n")

/* Write startup configuration into the terminal. */
DEFUN(show_startup_config,
      show_startup_config_cmd,
      "show startup-config",
      SHOW_STR
      "Contentes of startup configuration\n")
{
	char buf[BUFSIZ];
	FILE *confp;

	confp = fopen(host.config, "r");
	if (confp == NULL) {
		vty_out(vty, "Can't open configuration file [%s]%s"
			   , host.config, VTY_NEWLINE);
		return CMD_WARNING;
	}

	while (fgets(buf, BUFSIZ, confp)) {
		char *cp = buf;

		while (*cp != '\r' && *cp != '\n' && *cp != '\0')
			cp++;
		*cp = '\0';

		vty_out(vty, "%s%s", buf, VTY_NEWLINE);
	}

	fclose(confp);

	return CMD_SUCCESS;
}

/* Hostname configuration */
DEFUN(config_hostname, 
      hostname_cmd,
      "hostname WORD",
      "Set system's network name\n"
      "This system's network name\n")
{
	if (!isalpha((int) *argv[0])) {
		vty_out(vty, "Please specify string starting with alphabet%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	FREE_PTR(host.name);
    
	host.name = strdup(argv[0]);
	return CMD_SUCCESS;
}

DEFUN (config_no_hostname, 
       no_hostname_cmd,
       "no hostname [HOSTNAME]",
       NO_STR
       "Reset system's network name\n"
       "Host name of this router\n")
{
	FREE_PTR(host.name);
	host.name = NULL;
	return CMD_SUCCESS;
}

/* VTY interface password set. */
DEFUN(config_password, password_cmd,
      "password (8|) WORD",
      "Assign the terminal connection password\n"
      "Specifies a HIDDEN password will follow\n"
      "dummy string \n"
      "The HIDDEN line password string\n")
{
	/* Argument check. */
	if (argc == 0) {
		vty_out(vty, "Please specify password.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc == 2) {
		if (*argv[0] == '8') {
			FREE_PTR(host.password);
			host.password = NULL;
			FREE_PTR(host.password_encrypt);
			host.password_encrypt = strdup(argv[1]);
			return CMD_SUCCESS;
		} else {
			vty_out(vty, "Unknown encryption type.%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (!isalnum ((int) *argv[0])) {
		vty_out(vty, "Please specify string starting with alphanumeric%s"
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	FREE_PTR(host.password);
	host.password = NULL;

	if (host.encrypt) {
		FREE_PTR(host.password_encrypt);
		host.password_encrypt = strdup(zencrypt(argv[0]));
	} else
		host.password = strdup(argv[0]);

	return CMD_SUCCESS;
}

ALIAS(config_password, password_text_cmd,
      "password LINE",
      "Assign the terminal connection password\n"
      "The UNENCRYPTED (cleartext) line password\n")

/* VTY enable password set. */
DEFUN(config_enable_password, enable_password_cmd,
      "enable password (8|) WORD",
      "Modify enable password parameters\n"
      "Assign the privileged level password\n"
      "Specifies a HIDDEN password will follow\n"
      "dummy string \n"
      "The HIDDEN 'enable' password string\n")
{
	/* Argument check. */
	if (argc == 0) {
		vty_out(vty, "Please specify password.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Crypt type is specified. */
	if (argc == 2) {
		if (*argv[0] == '8') {
			FREE_PTR(host.enable);
			host.enable = NULL;

			FREE_PTR(host.enable_encrypt);
			host.enable_encrypt = strdup(argv[1]);

			return CMD_SUCCESS;
		} else {
			vty_out(vty, "Unknown encryption type.%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (!isalnum ((int) *argv[0])) {
		vty_out(vty, "Please specify string starting with alphanumeric%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	FREE_PTR(host.enable);
	host.enable = NULL;

	/* Plain password input. */
	if (host.encrypt) {
		FREE_PTR(host.enable_encrypt);
		host.enable_encrypt = strdup(zencrypt(argv[0]));
	} else {
		host.enable = strdup(argv[0]);
	}

	return CMD_SUCCESS;
}

ALIAS(config_enable_password,
      enable_password_text_cmd,
      "enable password LINE",
      "Modify enable password parameters\n"
      "Assign the privileged level password\n"
      "The UNENCRYPTED (cleartext) 'enable' password\n")

/* VTY enable password delete. */
DEFUN(no_config_enable_password, no_enable_password_cmd,
      "no enable password",
      NO_STR
      "Modify enable password parameters\n"
      "Assign the privileged level password\n")
{
	FREE_PTR(host.enable);
	host.enable = NULL;

	FREE_PTR(host.enable_encrypt);
	host.enable_encrypt = NULL;

	return CMD_SUCCESS;
}
	
DEFUN(service_password_encrypt,
      service_password_encrypt_cmd,
      "service password-encryption",
      "Set up miscellaneous service\n"
      "Enable encrypted passwords\n")
{
	if (host.encrypt)
		return CMD_SUCCESS;

	host.encrypt = 1;

	if (host.password) {
		FREE_PTR(host.password_encrypt);
		host.password_encrypt = strdup(zencrypt(host.password));
	}

	if (host.enable) {
		FREE_PTR(host.enable_encrypt);
		host.enable_encrypt = strdup(zencrypt(host.enable));
	}

	return CMD_SUCCESS;
}

DEFUN(no_service_password_encrypt,
      no_service_password_encrypt_cmd,
      "no service password-encryption",
      NO_STR
      "Set up miscellaneous service\n"
      "Enable encrypted passwords\n")
{
	if (!host.encrypt)
		return CMD_SUCCESS;

	host.encrypt = 0;

	FREE_PTR(host.password_encrypt);
	host.password_encrypt = NULL;

	FREE_PTR(host.enable_encrypt);
	host.enable_encrypt = NULL;

	return CMD_SUCCESS;
}

DEFUN(config_terminal_length, config_terminal_length_cmd,
      "terminal length <0-512>",
      "Set terminal line parameters\n"
      "Set number of lines on a screen\n"
      "Number of lines on screen (0 for no pausing)\n")
{
	int lines;
	char *endptr = NULL;

	lines = strtol(argv[0], &endptr, 10);
	if (lines < 0 || lines > 512 || *endptr != '\0') {
		vty_out(vty, "length is malformed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty->lines = lines;

	return CMD_SUCCESS;
}

DEFUN(config_terminal_no_length, config_terminal_no_length_cmd,
      "terminal no length",
      "Set terminal line parameters\n"
      NO_STR
      "Set number of lines on a screen\n")
{
	vty->lines = -1;
	return CMD_SUCCESS;
}

DEFUN(service_terminal_length, service_terminal_length_cmd,
      "service terminal-length <0-512>",
      "Set up miscellaneous service\n"
      "System wide terminal length configuration\n"
      "Number of lines of VTY (0 means no line control)\n")
{
	int lines;
	char *endptr = NULL;

	lines = strtol(argv[0], &endptr, 10);
	if (lines < 0 || lines > 512 || *endptr != '\0') {
		vty_out(vty, "length is malformed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	host.lines = lines;

	return CMD_SUCCESS;
}

DEFUN(no_service_terminal_length, no_service_terminal_length_cmd,
      "no service terminal-length [<0-512>]",
      NO_STR
      "Set up miscellaneous service\n"
      "System wide terminal length configuration\n"
      "Number of lines of VTY (0 means no line control)\n")
{
	host.lines = -1;
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(do_echo,
	     echo_cmd,
	     "echo .MESSAGE",
	     "Echo a message back to the vty\n"
	     "The message to echo\n")
{
	char *message;

	vty_out(vty, "%s%s", ((message = argv_concat(argv, argc, 0)) ? message : "")
		   , VTY_NEWLINE);
	FREE_PTR(message);
	return CMD_SUCCESS;
}

DEFUN(banner_motd_file,
      banner_motd_file_cmd,
      "banner motd file [FILE]",
      "Set banner\n"
      "Banner for motd\n"
      "Banner from a file\n"
      "Filename\n")
{
	FREE_PTR(host.motdfile);
	host.motdfile = strdup(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(banner_motd_default,
      banner_motd_default_cmd,
      "banner motd default",
      "Set banner string\n"
      "Strings for motd\n"
      "Default string\n")
{
	host.motd = default_motd;
	return CMD_SUCCESS;
}

DEFUN(no_banner_motd,
      no_banner_motd_cmd,
      "no banner motd",
      NO_STR
      "Set banner string\n"
      "Strings for motd\n")
{
	host.motd = NULL;
	FREE_PTR(host.motdfile);
	host.motdfile = NULL;
	return CMD_SUCCESS;
}

/* Set config filename.  Called from vty.c */
void
host_config_set(char *filename)
{
	FREE_PTR(host.config);
	host.config = strdup(filename);
}

void
install_default(node_type_t node)
{
	install_element(node, &config_exit_cmd);
	install_element(node, &config_quit_cmd);
	install_element(node, &config_end_cmd);
	install_element(node, &config_help_cmd);
	install_element(node, &config_list_cmd);

	install_element(node, &config_write_terminal_cmd);
	install_element(node, &config_write_file_cmd);
	install_element(node, &config_write_memory_cmd);
	install_element(node, &config_write_cmd);
	install_element(node, &show_running_config_cmd);
}

/* Initialize command interface. Install basic nodes and commands. */
void
cmd_init(void)
{
	command_cr = strdup("<cr>");
	desc_cr.cmd = command_cr;
	desc_cr.str = strdup("");

	/* Allocate initial top vector of commands. */
	cmdvec = vector_init(VECTOR_DEFAULT_SIZE);

	/* Default host value settings. */
	host.name = NULL;
	host.password = NULL;
	host.enable = NULL;
	host.logfile = NULL;
	host.config = NULL;
	host.lines = -1;
	host.motd = default_motd;
	host.motdfile = NULL;

	/* Install top nodes. */
	install_node(&view_node, NULL);
	install_node(&enable_node, NULL);
	install_node(&auth_node, NULL);
	install_node(&auth_enable_node, NULL);
	install_node(&config_node, config_write_host);

	/* Each node's basic commands. */
	install_element(VIEW_NODE, &show_version_cmd);
	install_element(VIEW_NODE, &config_list_cmd);
	install_element(VIEW_NODE, &config_exit_cmd);
	install_element(VIEW_NODE, &config_quit_cmd);
	install_element(VIEW_NODE, &config_help_cmd);
	install_element(VIEW_NODE, &config_enable_cmd);
	install_element(VIEW_NODE, &config_terminal_length_cmd);
	install_element(VIEW_NODE, &config_terminal_no_length_cmd);
	install_element(VIEW_NODE, &echo_cmd);

	install_default(ENABLE_NODE);
	install_element(ENABLE_NODE, &config_disable_cmd);
	install_element(ENABLE_NODE, &config_terminal_cmd);
	install_element(ENABLE_NODE, &copy_runningconfig_startupconfig_cmd);

	install_element(ENABLE_NODE, &show_startup_config_cmd);
	install_element(ENABLE_NODE, &show_version_cmd);

	install_element(ENABLE_NODE, &config_terminal_length_cmd);
	install_element(ENABLE_NODE, &config_terminal_no_length_cmd);
	install_element(ENABLE_NODE, &echo_cmd);

	install_default(CONFIG_NODE);
  
	install_element(CONFIG_NODE, &hostname_cmd);
	install_element(CONFIG_NODE, &no_hostname_cmd);

	install_element(CONFIG_NODE, &password_cmd);
	install_element(CONFIG_NODE, &password_text_cmd);
	install_element(CONFIG_NODE, &enable_password_cmd);
	install_element(CONFIG_NODE, &enable_password_text_cmd);
	install_element(CONFIG_NODE, &no_enable_password_cmd);

	install_element(CONFIG_NODE, &service_password_encrypt_cmd);
	install_element(CONFIG_NODE, &no_service_password_encrypt_cmd);
	install_element(CONFIG_NODE, &banner_motd_default_cmd);
	install_element(CONFIG_NODE, &banner_motd_file_cmd);
	install_element(CONFIG_NODE, &no_banner_motd_cmd);
	install_element(CONFIG_NODE, &service_terminal_length_cmd);
	install_element(CONFIG_NODE, &no_service_terminal_length_cmd);

	srand(time(NULL));
}

void
cmd_terminate(void)
{
	unsigned int i, j, k, l;
	cmd_node_t *cmd_node;
	cmd_element_t *cmd_element;
	desc_t *desc;
	vector_t *cmd_node_v, *cmd_element_v, *desc_v;

	if (cmdvec) {
		for (i = 0; i < vector_active(cmdvec); i++) {
			if ((cmd_node = vector_slot(cmdvec, i)) != NULL) {
				cmd_node_v = cmd_node->cmd_vector;

				for (j = 0; j < vector_active(cmd_node_v); j++) {
					if ((cmd_element = vector_slot(cmd_node_v, j)) != NULL &&
					    cmd_element->strvec != NULL) {
						cmd_element_v = cmd_element->strvec;

						for (k = 0; k < vector_active(cmd_element_v); k++) {
							if ((desc_v = vector_slot(cmd_element_v, k)) != NULL) {
								for (l = 0; l < vector_active(desc_v); l++)
									if ((desc = vector_slot(desc_v, l)) != NULL) {
										FREE_PTR(desc->cmd);
										FREE_PTR(desc->str);
										FREE(desc);
									}
									vector_free(desc_v);
							}
						}

						cmd_element->strvec = NULL;
						vector_free(cmd_element_v);
					}
				}

				vector_free(cmd_node_v);
			}
		}

		vector_free (cmdvec);
		cmdvec = NULL;
	}

	FREE_PTR(command_cr);
	FREE_PTR(desc_cr.str);
	FREE_PTR(host.name);
	FREE_PTR(host.password);
	FREE_PTR(host.password_encrypt);
	FREE_PTR(host.enable);
	FREE_PTR(host.enable_encrypt);
	FREE_PTR(host.motdfile);
	FREE_PTR(host.config);
}
