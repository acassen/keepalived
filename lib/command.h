/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        command.c include file.
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

#ifndef _COMMAND_H
#define _COMMAND_H

#include "vector.h"
#include "vty.h"

/*
 *	command definition
 */
typedef struct _host {
	char			*name;			/* Host name of this router. */

	char			*password;		/* Password for vty interface. */
	char			*password_encrypt;

	char			*enable;		/* Enable password */
	char			*enable_encrypt;

	int			lines;			/* System wide terminal lines. */

	char			*logfile;		/* Log filename. */

	char			*config;		/* config file name of this host */

	int			advanced;		/* Flags for services */
	int			encrypt;

	const char		*motd;			/* Banner configuration. */
	char			*motdfile;
} host_t;

/* There are some command levels which called from command node. */
typedef enum _node_type {
	AUTH_NODE,					/* Authentication mode of vty interface. */
	VIEW_NODE,					/* View node. Default mode of vty interface. */
	AUTH_ENABLE_NODE,				/* Authentication mode for change enable. */
	ENABLE_NODE,					/* Enable node. */
	CONFIG_NODE,					/* Config node. Default mode of config file. */
	SERVICE_NODE,					/* Service node. */
	DEBUG_NODE,					/* Debug node. */
	CFG_LOG_NODE,					/* Configure the logging */

	VTY_NODE,					/* Vty node. */

	GLOBAL_NODE,					/* Global daemon commands. */
	CHECK_NODE,					/* Checker framework commands. */
	VRRP_NODE,					/* VRRP framework commands. */
} node_type_t;

/* Completion match types. */
typedef enum _match_type {
	no_match,
	extend_match,
	ipv4_prefix_match,
	ipv4_match,
	ipv6_prefix_match,
	ipv6_match,
	range_match,
	vararg_match,
	partly_match,
	exact_match
} match_type_t;

/* Node which has some commands and prompt string and configuration
 * function pointer . */
typedef struct _cmd_node {
	node_type_t		node;			/* Node index. */
	const char		*prompt;		/* Prompt character at vty interface. */
	int			vtysh;			/* Is this node's configuration goes to vtysh ? */
	int			(*func) (vty_t *);	/* Node's configuration write function */
	vector_t		*cmd_vector;		/* Vector of this node's command list. */
} cmd_node_t;

/* Structure of command element. */
typedef struct _cmd_element {
	const char		*string;		/* Command specification by string. */
	int			(*func) (struct _cmd_element *,
					 vty_t *, int, const char *[]);
	const char		*doc;			/* Documentation of this command. */
	int			daemon;			/* Daemon to which this command belong. */
	vector_t		*strvec;		/* Pointing out each description vector. */
	unsigned int		cmdsize;		/* Command index count. */
	char			*config;		/* Configuration string */
	vector_t		*subconfig;		/* Sub configuration string */
	uint8_t			attr;			/* Command attributes */
} cmd_element_t;

/* Command description structure. */
typedef struct _desc {
	char			*cmd;			/* Command string. */
	char			*str;			/* Command's description. */
} desc_t;


/*
 *	Some defines
 */

enum {
	CMD_ATTR_HIDDEN = 1,
};

#define CMD_SUCCESS		0
#define CMD_WARNING		1
#define CMD_ERR_NO_MATCH	2
#define CMD_ERR_AMBIGUOUS	3
#define CMD_ERR_INCOMPLETE	4
#define CMD_ERR_EXEED_ARGC_MAX	5
#define CMD_ERR_NOTHING_TODO	6
#define CMD_COMPLETE_FULL_MATCH	7
#define CMD_COMPLETE_MATCH	8
#define CMD_COMPLETE_LIST_MATCH	9
#define CMD_SUCCESS_DAEMON	10

#define CMD_ARGC_MAX		256

#define IPV6_ADDR_STR		"0123456789abcdefABCDEF:.%"
#define IPV6_PREFIX_STR		"0123456789abcdefABCDEF:.%/"
#define STATE_START		1
#define STATE_COLON		2
#define STATE_DOUBLE		3
#define STATE_ADDR		4
#define STATE_DOT		5
#define STATE_SLASH		6
#define STATE_MASK		7

#define DECIMAL_STRLEN_MAX	10
#define INIT_MATCHVEC_SIZE	10


/*
 *	Some usefull macros
 */

/* helper defines for end-user DEFUN* macros */
#define DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attrs, dnum)	\
	cmd_element_t cmdname = {						\
		.string = cmdstr,						\
		.func = funcname,						\
		.doc = helpstr,							\
		.attr = attrs,							\
		.daemon = dnum,							\
	};

#define DEFUN_CMD_FUNC_DECL(funcname) \
	static int funcname(cmd_element_t *, vty_t *, int, const char *[]);

#define DEFUN_CMD_FUNC_TEXT(funcname)						\
	static int funcname(cmd_element_t *self __attribute__ ((unused)),	\
			    vty_t *vty __attribute__ ((unused)),		\
			    int argc __attribute__ ((unused)),			\
			    const char *argv[] __attribute__ ((unused)))

/* DEFUN for vty command interafce. Little bit hacky ;-). */
#define DEFUN(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0)		\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, attr)			\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)		\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_HIDDEN(funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_ATTR (funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* DEFUN_NOSH for commands that vtysh should ignore */
#define DEFUN_NOSH(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN(funcname, cmdname, cmdstr, helpstr)

/* DEFSH for vtysh. */
#define DEFSH(daemon, cmdname, cmdstr, helpstr)					\
	DEFUN_CMD_ELEMENT(NULL, cmdname, cmdstr, helpstr, 0, daemon)

/* DEFUN + DEFSH */
#define DEFUNSH(daemon, funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon)	\
	DEFUN_CMD_FUNC_TEXT(funcname)

/* DEFUN + DEFSH with attributes */
#define DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr, attr)		\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, daemon)	\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUNSH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr)		\
	DEFUNSH_ATTR (daemon, funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* ALIAS macro which define existing command's alias. */
#define ALIAS(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0)

#define ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, attr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)

#define ALIAS_HIDDEN(funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, 0)

#define ALIAS_SH(daemon, funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon)

#define ALIAS_SH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr)		\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, daemon)

#define CMD_OPTION(S)	((S[0]) == '[')
#define CMD_VARIABLE(S)	(((S[0]) >= 'A' && (S[0]) <= 'Z') || ((S[0]) == '<'))
#define CMD_VARARG(S)	((S[0]) == '.')
#define CMD_RANGE(S)	((S[0] == '<'))

#define CMD_IPV4(S)		((strcmp((S), "A.B.C.D") == 0))
#define CMD_IPV4_PREFIX(S)	((strcmp((S), "A.B.C.D/M") == 0))
#define CMD_IPV6(S)		((strcmp((S), "X:X::X:X") == 0))
#define CMD_IPV6_PREFIX(S)	((strcmp((S), "X:X::X:X/M") == 0))

/* Common descriptions. */
#define SHOW_STR "Show running system information\n"
#define IP_STR "IP information\n"
#define IPV6_STR "IPv6 information\n"
#define NO_STR "Negate a command or set its defaults\n"
#define CLEAR_STR "Reset functions\n"
#define DEBUG_STR "Debugging functions (see also 'undebug')\n"
#define UNDEBUG_STR "Disable debugging functions (see also 'debug')\n"
#define ROUTER_STR "Enable a routing process\n"
#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"
#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"
#define V4NOTATION_STR "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define IP6_STR "IPv6 Information\n"
#define SECONDS_STR "<1-65535> Seconds\n"
#define ROUTE_STR "Routing Table\n"
#define PREFIX_LIST_STR "Build a prefix list\n"

#define CONF_BACKUP_EXT ".sav"


/*
 *	Global vars
 */
extern cmd_element_t config_exit_cmd;
extern cmd_element_t config_help_cmd;
extern cmd_element_t config_list_cmd;
extern host_t host;
extern char *command_cr;


/*
 *	Prototypes
 */
extern void install_node(cmd_node_t *, int (*) (vty_t *));
extern void install_default(node_type_t);
extern void install_element(node_type_t, cmd_element_t *);
extern void sort_node(void);
extern char *argv_concat(const char **, int, int);
extern vector_t *cmd_make_strvec(const char *);
extern void cmd_free_strvec(vector_t *);
extern vector_t *cmd_describe_command(vector_t *, vty_t *, int *);
extern char **cmd_complete_command(vector_t *, vty_t *, int *);
extern const char *cmd_prompt(node_type_t);
extern int config_from_file(vty_t *, FILE *);
extern node_type_t node_parent(node_type_t);
extern int cmd_execute_command(vector_t *, vty_t *, cmd_element_t **, int);
extern int cmd_execute_command_strict(vector_t *, vty_t *, cmd_element_t **);
extern void config_replace_string(cmd_element_t *, char *, ...);
extern void cmd_init(void);
extern void cmd_terminate(void);
extern char *host_config_file(void);
extern void host_config_set(char *);

#endif
