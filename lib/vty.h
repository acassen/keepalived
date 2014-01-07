/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        vty.c include file.
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

#ifndef _VTY_H
#define _VTY_H

#include <netinet/in.h>
#include "timer.h"
#include "scheduler.h"
#include "buffer.h"

#define VTY_BUFSIZ 512
#define VTY_MAXHIST 20
#define TELNET_NAWS_SB_LEN 5

typedef enum _event {
	VTY_SERV,
	VTY_READ,
	VTY_WRITE,
	VTY_TIMEOUT_RESET
} event_t;

typedef enum _vty_type {
	VTY_TERM,
	VTY_FILE,
	VTY_SHELL,
	VTY_SHELL_SERV
} vty_type_t;

typedef enum _vty_status {
	VTY_NORMAL,
	VTY_CLOSE,
	VTY_MORE,
	VTY_MORELINE
} vty_status_t;


/* VTY struct. */
typedef struct _vty {
	int			fd;				/* File descripter of this vty. */
	vty_type_t		type;				/* Is this vty connect to file or not */
	int			node;				/* Node status of this vty */
	int			fail;				/* Failure count */
	buffer_t		*obuf;				/* Output buffer */
	char			*buf;				/* Command input buffer */
	int			cp;				/* Command cursor point */
	int			length;				/* Command length */
	int			max;				/* Command max length */
	char			*hist[VTY_MAXHIST];		/* Histry of command */
	int			hp;				/* History lookup current point */
	int			hindex;				/* History insert end point */
	void			*index;				/* For current referencing point */
	void			*index_sub;			/* For multiple level index treatment such
								 * as key chain and key.
								 */
	unsigned char		escape;				/* For escape character. */
	vty_status_t		status;				/* Current vty status. */
	unsigned char		iac;				/* IAC handling: was the last character received
								 * the IAC (interpret-as-command) escape character
								 * (and therefore the next character will be the
								 * command code)?  Refer to Telnet RFC 854.
								 */
	unsigned char		iac_sb_in_progress;		/* IAC SB (option subnegotiation) handling */
	unsigned char		sb_buf[TELNET_NAWS_SB_LEN];	/* At the moment, we care only about the NAWS
								 * (window size) negotiation, and that requires
								 * just a 5-character buffer (RFC 1073):
								 * <NAWS char> <16-bit width> <16-bit height>
								 */
	size_t			sb_len;				/* How many subnegotiation characters have we
								 * received?  We just drop those that do not
								 * fit in the buffer.
								 */
	int			width;				/* Window width */
	int			height;				/* Window height */
	int			lines;				/* Configure lines */
	int			monitor;			/* Terminal monitor */
	int			config;				/* In configure mode */
	thread_t		*t_read;			/* Read thread */
	thread_t		*t_write;			/* Write thread */
	unsigned long		v_timeout;			/* Timeout seconds */
	thread_t		*t_timeout;			/* Timeout thread */
	struct sockaddr_storage	address;			/* What address is this vty comming from. */
} vty_t;

/* Integrated configuration file. */
#define INTEGRATE_DEFAULT_CONFIG "keepalived.conf"

/* Small macro to determine newline is newline only or linefeed needed. */
#define VTY_NEWLINE	((vty->type == VTY_TERM) ? "\r\n" : "\n")

/* Default time out value */
#define VTY_TIMEOUT_DEFAULT	600
#define VTY_IO_TIMEOUT		(10 * TIMER_HZ)

/* Vty read buffer size. */
#define VTY_READ_BUFSIZ 512

/* Directory separator. */
#define DIRECTORY_SEP '/'
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif

/* Utility macros to convert VTY argument to unsigned long or integer. */
#define VTY_GET_LONG(NAME,V,STR)					\
do {									\
  char *endptr = NULL;							\
  errno = 0;								\
  (V) = strtoul((STR), &endptr, 10);					\
  if (*(STR) == '-' || *endptr != '\0' || errno) {			\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)

#define VTY_GET_INTEGER_RANGE(NAME,V,STR,MIN,MAX)			\
do {									\
  unsigned long tmpl;							\
  VTY_GET_LONG(NAME, tmpl, STR);					\
  if ((tmpl < (MIN)) || (tmpl > (MAX))) {				\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
  (V) = tmpl;								\
} while (0)

#define VTY_GET_INTEGER(NAME,V,STR) \
	VTY_GET_INTEGER_RANGE(NAME,V,STR,0U,UINT32_MAX)

#define VTY_GET_IPV4_ADDRESS(NAME,V,STR)				\
do {									\
  int retv;								\
  retv = inet_aton((STR), &(V));					\
  if (!retv) {								\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)

#define VTY_GET_IPV4_PREFIX(NAME,V,STR)					\
do {									\
  int retv;								\
  retv = str2prefix_ipv4((STR), &(V));					\
  if (retv <= 0) {							\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)

/* Exported variables */
extern char integrate_default[];

/* Prototypes. */
extern void vty_init(void);
extern void vty_terminate(void);
extern int vty_listen(struct sockaddr_storage *);
extern void vty_reset(void);
extern vty_t *vty_new(void);
extern int vty_out(vty_t *, const char *, ...) PRINTF_ATTRIBUTE(2, 3);
extern int vty_read_config(char *, char *);
extern void vty_time_print(vty_t *, int);
extern void vty_serv_sock(const char *, unsigned short, const char *);
extern void vty_close(vty_t *);
extern char *vty_get_cwd(void);
extern int vty_config_lock(vty_t *);
extern int vty_config_unlock(vty_t *);
extern int vty_shell(vty_t *);
extern int vty_shell_serv(vty_t *);
extern void vty_time_print(vty_t *, int);
extern void vty_hello(vty_t *);

#endif
