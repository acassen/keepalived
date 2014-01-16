/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Virtual Terminal.
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
#include <errno.h>
#include <ctype.h>
#include <termios.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <arpa/telnet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/tcp.h>

#include "scheduler.h"
#include "vty.h"
#include "timer.h"
#include "utils.h"
#include "command.h"
#include "memory.h"
#include "logger.h"


static void vty_event(event_t, int, vty_t *);

/* Extern host structure from command.c */
extern host_t host;

/* Vector which store each vty structure. */
static vector_t *vtyvec;

/* Vty timeout value. */
static unsigned long vty_timeout_val = VTY_TIMEOUT_DEFAULT;

/* VTY server thread. */
vector_t *Vvty_serv_thread;

/* Current directory. */
char *vty_cwd = NULL;

/* Configure lock. */
static int vty_config;

/* Login password check. */
static int no_password_check = 0;

/* Integrated configuration file path */
#define SYSCONFDIR	"/etc/keepalived"
char integrate_default[] = SYSCONFDIR INTEGRATE_DEFAULT_CONFIG;

/* VTY standard output function. */
int
vty_out(vty_t *vty, const char *format, ...)
{
	va_list args;
	int len = 0;
	int size = 1024;
	char buf[1024];
	char *tmp = NULL;
	char *p = NULL;

	if (vty_shell (vty)) {
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	} else {
		/* Try to write to initial buffer.  */
		va_start(args, format);
		len = vsnprintf(buf, sizeof buf, format, args);
		va_end(args);

		/* Initial buffer is not enough.  */
		if (len < 0 || len >= size) {
		for (;;) {
			if (len > -1)
				size = len + 1;
			else
				size = size * 2;

			tmp = REALLOC(p, size);
			if (! tmp) {
				FREE(p);
				return -1;
			}
			p = tmp;

			va_start(args, format);
			len = vsnprintf(p, size, format, args);
			va_end(args);

			if (len > -1 && len < size)
				break;
		}
	}

	/* When initial buffer is enough to store all output.  */
	if (! p)
		p = buf;

	/* Pointer p must point out buffer. */
	buffer_put(vty->obuf, (u_char *) p, len);

	/* If p is not different with buf, it is allocated buffer.  */
	if (p != buf)
		FREE(p);
	}

	return len;
}

/* Output current time to vty. */
void
vty_time_print(vty_t *vty, int cr)
{
	struct tm tmp;
	time_t current_time;
	char buf[25];

	/* Get current time */
	current_time = time(NULL);
	memset(&tmp, 0, sizeof(struct tm));
	tmp.tm_isdst = -1;
	localtime_r(&current_time, &tmp);
	strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", &tmp);

	vty_out(vty, "%s%s", buf, (cr)?"\n":" ");
}

/* Say hello to vty interface. */
void
vty_hello (vty_t *vty)
{
	if (host.motdfile) {
		FILE *f;
		char buf[4096];

		f = fopen(host.motdfile, "r");
		if (f) {
			while (fgets(buf, sizeof(buf), f)) {
				char *s;
				/* work backwards to ignore trailling isspace() */
				for (s = buf + strlen(buf); (s > buf) && isspace((int)*(s - 1));
				     s--);
					*s = '\0';
				vty_out(vty, "%s%s", buf, VTY_NEWLINE);
			}
			fclose (f);
		} else {
			vty_out(vty, "MOTD file not found%s", VTY_NEWLINE);
		}
	} else if (host.motd) {
		vty_out(vty, "%s", host.motd);
	}
}

/* Put out prompt and wait input from user. */
static void
vty_prompt(vty_t *vty)
{
	struct utsname names;
	const char*hostname;

	if (vty->type == VTY_TERM) {
		hostname = host.name;
		if (!hostname) {
			uname(&names);
			hostname = names.nodename;
		}
		vty_out(vty, cmd_prompt (vty->node), hostname);
	}
}

/* Send WILL TELOPT_ECHO to remote server. */
static void
vty_will_echo(vty_t *vty)
{
	unsigned char cmd[] = { IAC, WILL, TELOPT_ECHO, '\0' };
	vty_out(vty, "%s", cmd);
}

/* Make suppress Go-Ahead telnet option. */
static void
vty_will_suppress_go_ahead(vty_t *vty)
{
	unsigned char cmd[] = { IAC, WILL, TELOPT_SGA, '\0' };
	vty_out(vty, "%s", cmd);
}

/* Make don't use linemode over telnet. */
static void
vty_dont_linemode(vty_t *vty)
{
	unsigned char cmd[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
	vty_out(vty, "%s", cmd);
}

/* Use window size. */
static void
vty_do_window_size(vty_t *vty)
{
	unsigned char cmd[] = { IAC, DO, TELOPT_NAWS, '\0' };
	vty_out(vty, "%s", cmd);
}

/* Allocate new vty struct. */
vty_t *
vty_new(void)
{
	vty_t *new = (vty_t *) MALLOC(sizeof(vty_t));

	new->obuf = buffer_new(0);	/* Use default buffer size. */
	new->buf = (char *) MALLOC(VTY_BUFSIZ);
	new->max = VTY_BUFSIZ;

	return new;
}

/* Authentication of vty */
static void
vty_auth(vty_t *vty, char *buf)
{
	char *passwd = NULL;
	node_type_t next_node = 0;
	int fail;
	char *crypt (const char *, const char *);

	switch (vty->node) {
	case AUTH_NODE:
		if (host.encrypt)
			passwd = host.password_encrypt;
		else
			passwd = host.password;
		if (host.advanced)
			next_node = host.enable ? VIEW_NODE : ENABLE_NODE;
		else
			next_node = VIEW_NODE;
		break;
	case AUTH_ENABLE_NODE:
		if (host.encrypt)
			passwd = host.enable_encrypt;
		else
			passwd = host.enable;
		next_node = ENABLE_NODE;
		break;
	}

	if (passwd) {
		if (host.encrypt)
			fail = strcmp (crypt(buf, passwd), passwd);
		else
			fail = strcmp (buf, passwd);
	} else {
		fail = 1;
	}

	if (!fail) {
		vty->fail = 0;
		vty->node = next_node;	/* Success ! */
	} else {
		vty->fail++;
		if (vty->fail >= 3) {
			if (vty->node == AUTH_NODE) {
				vty_out(vty, "%% Bad passwords, too many failures!%s", VTY_NEWLINE);
				vty->status = VTY_CLOSE;
			} else {
				/* AUTH_ENABLE_NODE */
				vty->fail = 0;
				vty_out(vty, "%% Bad enable passwords, too many failures!%s", VTY_NEWLINE);
				vty->node = VIEW_NODE;
			}
		}
	}
}

/* Command execution over the vty interface. */
static int
vty_command(vty_t *vty, char *buf)
{
	int ret;
	vector_t *vline;

	/* Split readline string up into the vector */
	vline = cmd_make_strvec(buf);

	if (vline == NULL)
		return CMD_SUCCESS;

	ret = cmd_execute_command(vline, vty, NULL, 0);

	if (ret != CMD_SUCCESS) {
		switch (ret) {
		case CMD_WARNING:
			if (vty->type == VTY_FILE)
				vty_out(vty, "Warning...%s", VTY_NEWLINE);
			break;
		case CMD_ERR_AMBIGUOUS:
			vty_out(vty, "%% Ambiguous command.%s", VTY_NEWLINE);
			break;
		case CMD_ERR_NO_MATCH:
			vty_out(vty, "%% Unknown command: %s%s", buf, VTY_NEWLINE);
			break;
		case CMD_ERR_INCOMPLETE:
			vty_out(vty, "%% Command incomplete.%s", VTY_NEWLINE);
			break;
		}
	}

	cmd_free_strvec(vline);

	return ret;
}

static const char telnet_backward_char = 0x08;
static const char telnet_space_char = ' ';

/* Basic function to write buffer to vty. */
static void
vty_write(vty_t *vty, const char *buf, size_t nbytes)
{
	if ((vty->node == AUTH_NODE) || (vty->node == AUTH_ENABLE_NODE))
		return;

	/* Should we do buffering here ?  And make vty_flush (vty) ? */
	buffer_put(vty->obuf, buf, nbytes);
}

/* Ensure length of input buffer.  Is buffer is short, double it. */
static void
vty_ensure(vty_t *vty, int length)
{
	if (vty->max <= length) {
		vty->max *= 2;
		vty->buf = REALLOC(vty->buf, vty->max);
	}
}

/* Basic function to insert character into vty. */
static void
vty_self_insert(vty_t *vty, char c)
{
	int i, length;

	vty_ensure(vty, vty->length + 1);
	length = vty->length - vty->cp;
	memmove(&vty->buf[vty->cp + 1], &vty->buf[vty->cp], length);
	vty->buf[vty->cp] = c;

	vty_write(vty, &vty->buf[vty->cp], length + 1);
	for (i = 0; i < length; i++)
		vty_write(vty, &telnet_backward_char, 1);

	vty->cp++;
	vty->length++;
}

/* Self insert character 'c' in overwrite mode. */
static void
vty_self_insert_overwrite(vty_t *vty, char c)
{
	vty_ensure(vty, vty->length + 1);
	vty->buf[vty->cp++] = c;

	if (vty->cp > vty->length)
		vty->length++;

	if ((vty->node == AUTH_NODE) || (vty->node == AUTH_ENABLE_NODE))
		return;

	vty_write(vty, &c, 1);
}

/* Insert a word into vty interface with overwrite mode. */
static void
vty_insert_word_overwrite(vty_t *vty, char *str)
{
	int len = strlen (str);
	vty_write(vty, str, len);
	strcpy(&vty->buf[vty->cp], str);
	vty->cp += len;
	vty->length = vty->cp;
}

/* Forward character. */
static void
vty_forward_char(vty_t *vty)
{
	if (vty->cp < vty->length) {
		vty_write(vty, &vty->buf[vty->cp], 1);
		vty->cp++;
	}
}

/* Backward character. */
static void
vty_backward_char(vty_t *vty)
{
	if (vty->cp > 0) {
		vty->cp--;
		vty_write(vty, &telnet_backward_char, 1);
	}
}

/* Move to the beginning of the line. */
static void
vty_beginning_of_line(vty_t *vty)
{
	while (vty->cp) {
		vty_backward_char(vty);
	}
}

/* Move to the end of the line. */
static void
vty_end_of_line(vty_t *vty)
{
  while (vty->cp < vty->length)
    vty_forward_char (vty);
}

static void vty_kill_line_from_beginning(vty_t *);
static void vty_redraw_line(vty_t *);

/* Print command line history.  This function is called from
 * vty_next_line and vty_previous_line. */
static void
vty_history_print(vty_t *vty)
{
	int length;

	vty_kill_line_from_beginning(vty);

	/* Get previous line from history buffer */
	length = strlen(vty->hist[vty->hp]);
	memcpy(vty->buf, vty->hist[vty->hp], length);
	vty->cp = vty->length = length;

	/* Redraw current line */
	vty_redraw_line(vty);
}

/* Show next command line history. */
static void
vty_next_line(vty_t *vty)
{
	int try_index;

	if (vty->hp == vty->hindex)
		return;

	/* Try is there history exist or not. */
	try_index = vty->hp;
	if (try_index == (VTY_MAXHIST - 1)) {
		try_index = 0;
	} else {
		try_index++;
	}

	/* If there is not history return. */
	if (vty->hist[try_index] == NULL) {
		return;
	} else {
		vty->hp = try_index;
	}

	vty_history_print(vty);
}

/* Show previous command line history. */
static void
vty_previous_line(vty_t *vty)
{
	int try_index;

	try_index = vty->hp;
	if (try_index == 0) {
		try_index = VTY_MAXHIST - 1;
	} else {
		try_index--;
	}

	if (vty->hist[try_index] == NULL) {
		return;
	} else {
		vty->hp = try_index;
	}

	vty_history_print(vty);
}

/* This function redraw all of the command line character. */
static void
vty_redraw_line(vty_t *vty)
{
	vty_write(vty, vty->buf, vty->length);
	vty->cp = vty->length;
}

/* Forward word. */
static void
vty_forward_word(vty_t *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_forward_char(vty);
  
	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_forward_char(vty);
}

/* Backward word without skipping training space. */
static void
vty_backward_pure_word(vty_t *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_backward_char(vty);
}

/* Backward word. */
static void
vty_backward_word(vty_t *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
		vty_backward_char(vty);

	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_backward_char(vty);
}

/* When '^D' is typed at the beginning of the line we move to the down
 * level. */
static void
vty_down_level(vty_t *vty)
{
	vty_out(vty, "%s", VTY_NEWLINE);
		(*config_exit_cmd.func) (NULL, vty, 0, NULL);
	vty_prompt(vty);
	vty->cp = 0;
}

/* When '^Z' is received from vty, move down to the enable mode. */
static void
vty_end_config(vty_t *vty)
{
	vty_out(vty, "%s", VTY_NEWLINE);

	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	case CONFIG_NODE:
	case VTY_NODE:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		break;
	default:
		/* Unknown node, we have to ignore it. */
		break;
	}

	vty_prompt(vty);
	vty->cp = 0;
}

/* Delete a charcter at the current point. */
static void
vty_delete_char(vty_t *vty)
{
	int i, size;

	if (vty->length == 0) {
		vty_down_level(vty);
		return;
	}

	if (vty->cp == vty->length)
		return;			/* completion need here? */

	size = vty->length - vty->cp;

	vty->length--;
	memmove(&vty->buf[vty->cp], &vty->buf[vty->cp + 1], size - 1);
	vty->buf[vty->length] = '\0';
  
	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
		return;

	vty_write(vty, &vty->buf[vty->cp], size - 1);
	vty_write(vty, &telnet_space_char, 1);

	for (i = 0; i < size; i++)
		vty_write (vty, &telnet_backward_char, 1);
}

/* Delete a character before the point. */
static void
vty_delete_backward_char(vty_t *vty)
{
	if (vty->cp == 0)
		return;

	vty_backward_char(vty);
	vty_delete_char(vty);
}

/* Kill rest of line from current point. */
static void
vty_kill_line(vty_t *vty)
{
	int i, size;

	size = vty->length - vty->cp;
  
	if (size == 0)
		return;

	for (i = 0; i < size; i++)
		vty_write(vty, &telnet_space_char, 1);
	for (i = 0; i < size; i++)
		vty_write(vty, &telnet_backward_char, 1);

	memset (&vty->buf[vty->cp], 0, size);
	vty->length = vty->cp;
}

/* Kill line from the beginning. */
static void
vty_kill_line_from_beginning(vty_t *vty)
{
  vty_beginning_of_line (vty);
  vty_kill_line (vty);
}

/* Delete a word before the point. */
static void
vty_forward_kill_word(vty_t *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_delete_char(vty);
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_delete_char(vty);
}

/* Delete a word before the point. */
static void
vty_backward_kill_word(vty_t *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
		vty_delete_backward_char(vty);
	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_delete_backward_char(vty);
}

/* Transpose chars before or at the point. */
static void
vty_transpose_chars(vty_t *vty)
{
	char c1, c2;

	/* If length is short or point is near by the beginning of line then
	 * return. */
	if (vty->length < 2 || vty->cp < 1)
		return;

	/* In case of point is located at the end of the line. */
	if (vty->cp == vty->length) {
		c1 = vty->buf[vty->cp - 1];
		c2 = vty->buf[vty->cp - 2];

		vty_backward_char(vty);
		vty_backward_char(vty);
		vty_self_insert_overwrite(vty, c1);
		vty_self_insert_overwrite(vty, c2);
	} else {
		c1 = vty->buf[vty->cp];
		c2 = vty->buf[vty->cp - 1];

		vty_backward_char(vty);
		vty_self_insert_overwrite(vty, c1);
		vty_self_insert_overwrite(vty, c2);
	}
}

/* Do completion at vty interface. */
static void
vty_complete_command(vty_t *vty)
{
	int i, ret;
	char **matched = NULL;
	vector_t *vline;

	if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
		return;

	vline = cmd_make_strvec(vty->buf);
	if (vline == NULL)
		return;

	/* In case of 'help \t'. */
	if (isspace ((int) vty->buf[vty->length - 1]))
		vector_set(vline, '\0');

	matched = cmd_complete_command(vline, vty, &ret);
  
	cmd_free_strvec(vline);

	vty_out(vty, "%s", VTY_NEWLINE);
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		vty_out(vty, "%% Ambiguous command.%s", VTY_NEWLINE);
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_ERR_NO_MATCH:
		/* vty_out (vty, "%% There is no matched command.%s", VTY_NEWLINE); */
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_COMPLETE_FULL_MATCH:
		vty_prompt(vty);
		vty_redraw_line(vty);
		vty_backward_pure_word(vty);
		vty_insert_word_overwrite(vty, matched[0]);
		vty_self_insert(vty, ' ');
		FREE(matched[0]);
		break;
	case CMD_COMPLETE_MATCH:
		vty_prompt (vty);
		vty_redraw_line (vty);
		vty_backward_pure_word (vty);
		vty_insert_word_overwrite (vty, matched[0]);
		FREE(matched[0]);
		vector_only_index_free (matched);
		return;
		break;
	case CMD_COMPLETE_LIST_MATCH:
		for (i = 0; matched[i] != NULL; i++) {
			if (i != 0 && ((i % 6) == 0))
				vty_out(vty, "%s", VTY_NEWLINE);
			vty_out(vty, "%-10s ", matched[i]);
			FREE(matched[i]);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	case CMD_ERR_NOTHING_TODO:
		vty_prompt(vty);
		vty_redraw_line(vty);
		break;
	default:
		break;
	}
	if (matched)
		vector_only_index_free(matched);
}

static void
vty_describe_fold(vty_t *vty, int cmd_width, unsigned int desc_width, desc_t *desc)
{
	char *buf;
	const char *cmd, *p;
	int pos;

	cmd = desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd;

	if (desc_width <= 0) {
		vty_out(vty, "  %-*s  %s%s", cmd_width, cmd, desc->str, VTY_NEWLINE);
		return;
	}

	buf = (char *) MALLOC(strlen (desc->str) + 1);

	for (p = desc->str; strlen (p) > desc_width; p += pos + 1) {
		for (pos = desc_width; pos > 0; pos--)
			if (*(p + pos) == ' ')
				break;

		if (pos == 0)
			break;

		strncpy (buf, p, pos);
		buf[pos] = '\0';
		vty_out(vty, "  %-*s  %s%s", cmd_width, cmd, buf, VTY_NEWLINE);

		cmd = "";
	}

	vty_out(vty, "  %-*s  %s%s", cmd_width, cmd, p, VTY_NEWLINE);

	FREE(buf);
}

/* Describe matched command function. */
static void
vty_describe_command(vty_t *vty)
{
	int ret;
	vector_t *vline, *describe;
	unsigned int i, width, desc_width;
	desc_t *desc, *desc_cr = NULL;

	vline = cmd_make_strvec(vty->buf);

	/* In case of '> ?'. */
	if (vline == NULL) {
		vline = vector_init(1);
		vector_set(vline, '\0');
	} else {
		if (isspace ((int) vty->buf[vty->length - 1])) {
			vector_set(vline, '\0');
		}
	}

	describe = cmd_describe_command(vline, vty, &ret);

	vty_out(vty, "%s", VTY_NEWLINE);

	/* Ambiguous error. */
	switch (ret) {
	case CMD_ERR_AMBIGUOUS:
		vty_out(vty, "%% Ambiguous command.%s", VTY_NEWLINE);
		goto out;
		break;
	case CMD_ERR_NO_MATCH:
		vty_out(vty, "%% There is no matched command.%s", VTY_NEWLINE);
		goto out;
		break;
	}  

	/* Get width of command string. */
	width = 0;
	for (i = 0; i < vector_active (describe); i++) {
		if ((desc = vector_slot (describe, i)) != NULL) {
			unsigned int len;

			if (desc->cmd[0] == '\0')
				continue;

			len = strlen (desc->cmd);
			if (desc->cmd[0] == '.')
				len--;

			if (width < len)
				width = len;
		}
	}

	/* Get width of description string. */
	desc_width = vty->width - (width + 6);

	/* Print out description. */
	for (i = 0; i < vector_active (describe); i++) {
		if ((desc = vector_slot(describe, i)) != NULL) {
			if (desc->cmd[0] == '\0')
				continue;
	
			if (strcmp (desc->cmd, command_cr) == 0) {
				desc_cr = desc;
				continue;
			}

			if (!desc->str) {
				vty_out(vty, "  %-s%s",
					desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
					VTY_NEWLINE);
			} else if (desc_width >= strlen (desc->str)) {
				vty_out(vty, "  %-*s  %s%s", width,
					desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
					desc->str, VTY_NEWLINE);
			} else {
				vty_describe_fold(vty, width, desc_width, desc);
			}
		}
	}

	if ((desc = desc_cr)) {
		if (!desc->str) {
			vty_out(vty, "  %-s%s",
				desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
				VTY_NEWLINE);
		} else if (desc_width >= strlen (desc->str)) {
			vty_out(vty, "  %-*s  %s%s", width,
				desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
				desc->str, VTY_NEWLINE);
		} else {
			vty_describe_fold(vty, width, desc_width, desc);
		}
    }

out:
	cmd_free_strvec(vline);
	if (describe)
		vector_free(describe);

	vty_prompt(vty);
	vty_redraw_line(vty);
}

static void
vty_clear_buf(vty_t *vty)
{
	memset(vty->buf, 0, vty->max);
}

/* ^C stop current input and do not add command line to the history. */
static void
vty_stop_input(vty_t *vty)
{
	vty->cp = vty->length = 0;
	vty_clear_buf(vty);
	vty_out(vty, "%s", VTY_NEWLINE);

	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	case CONFIG_NODE:
	case VTY_NODE:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		break;
	default:
		/* Unknown node, we have to ignore it. */
		break;
	}
	vty_prompt(vty);

	/* Set history pointer to the latest one. */
	vty->hp = vty->hindex;
}

/* Add current command line to the history buffer. */
static void
vty_hist_add(vty_t *vty)
{
	int index;

	if (vty->length == 0)
		return;

	index = vty->hindex ? vty->hindex - 1 : VTY_MAXHIST - 1;

	/* Ignore the same string as previous one. */
	if (vty->hist[index]) {
		if (strcmp (vty->buf, vty->hist[index]) == 0) {
			vty->hp = vty->hindex;
			return;
		}
	}

	/* Insert history entry. */
	FREE_PTR(vty->hist[vty->hindex]);
	vty->hist[vty->hindex] = strdup(vty->buf);

	/* History index rotation. */
	vty->hindex++;
	if (vty->hindex == VTY_MAXHIST)
		vty->hindex = 0;

	vty->hp = vty->hindex;
}

/* Get telnet window size. */
static int
vty_telnet_option(vty_t *vty, unsigned char *buf, int nbytes)
{
	switch (buf[0]) {
	case SB:
		vty->sb_len = 0;
		vty->iac_sb_in_progress = 1;
		return 0;
		break;
	case SE: 
	{
		if (!vty->iac_sb_in_progress)
			return 0;

		if ((vty->sb_len == 0) || (vty->sb_buf[0] == '\0')) {
			vty->iac_sb_in_progress = 0;
			return 0;
		}

		switch (vty->sb_buf[0]) {
		case TELOPT_NAWS:
			if (vty->sb_len != TELNET_NAWS_SB_LEN) {
				log_message(LOG_ERR, "RFC 1073 violation detected: telnet NAWS option "
						     "should send %d characters, but we received %lu"
						   , TELNET_NAWS_SB_LEN, (u_long)vty->sb_len);
			} else if (sizeof(vty->sb_buf) < TELNET_NAWS_SB_LEN) {
				log_message(LOG_ERR, "Bug detected: sizeof(vty->sb_buf) %lu < %d, "
						     "too small to handle the telnet NAWS option"
						   , (u_long)sizeof(vty->sb_buf), TELNET_NAWS_SB_LEN);
			} else {
				vty->width = ((vty->sb_buf[1] << 8)|vty->sb_buf[2]);
				vty->height = ((vty->sb_buf[3] << 8)|vty->sb_buf[4]);
			}
			break;
		}
		vty->iac_sb_in_progress = 0;
		return 0;
		break;
	}
	default:
		break;
	}

	return 1;
}

/* Execute current command line. */
static int
vty_execute(vty_t *vty)
{
	int ret;

	ret = CMD_SUCCESS;

	switch (vty->node) {
	case AUTH_NODE:
	case AUTH_ENABLE_NODE:
		vty_auth(vty, vty->buf);
		break;
	default:
		ret = vty_command(vty, vty->buf);
		if (vty->type == VTY_TERM)
			vty_hist_add(vty);
		break;
	}

	/* Clear command line buffer. */
	vty->cp = vty->length = 0;
	vty_clear_buf(vty);

	if (vty->status != VTY_CLOSE)
		vty_prompt(vty);

	return ret;
}

#define CONTROL(X)  ((X) - '@')
#define VTY_NORMAL     0
#define VTY_PRE_ESCAPE 1
#define VTY_ESCAPE     2

/* Escape character command map. */
static void
vty_escape_map(unsigned char c, vty_t *vty)
{
	switch (c) {
	case ('A'):
		vty_previous_line(vty);
		break;
	case ('B'):
		vty_next_line(vty);
		break;
	case ('C'):
		vty_forward_char(vty);
		break;
	case ('D'):
		vty_backward_char(vty);
		break;
	default:
		break;
	}

	/* Go back to normal mode. */
	vty->escape = VTY_NORMAL;
}

/* Quit print out to the buffer. */
static void
vty_buffer_reset(vty_t *vty)
{
	buffer_reset(vty->obuf);
	vty_prompt(vty);
	vty_redraw_line(vty);
}

/* Read data via vty socket. */
static int
vty_read(thread_t *thread)
{
	int i, nbytes;
	unsigned char buf[VTY_READ_BUFSIZ];

	int vty_sock = THREAD_FD(thread);
	vty_t *vty = THREAD_ARG(thread);
	vty->t_read = NULL;

	/* Handle Read Timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		vty_event(VTY_READ, vty_sock, vty);
		return 0;
	}

	/* Read raw data from socket */
	if ((nbytes = read(vty->fd, buf, VTY_READ_BUFSIZ)) <= 0) {
		if (nbytes < 0) {
			if (ERRNO_IO_RETRY(errno)) {
				vty_event(VTY_READ, vty_sock, vty);
				return 0;
			}
			vty->monitor = 0; /* disable monitoring to avoid infinite recursion */
			log_message(LOG_WARNING, "%s: read error on vty client fd %d, closing: %s"
					       , __func__, vty->fd, strerror(errno));
		}
		buffer_reset(vty->obuf);
		vty->status = VTY_CLOSE;
	}

	for (i = 0; i < nbytes; i++) {
		if (buf[i] == IAC) {
			if (!vty->iac) {
				vty->iac = 1;
				continue;
			} else {
				vty->iac = 0;
			}
		}
      
		if (vty->iac_sb_in_progress && !vty->iac) {
			if (vty->sb_len < sizeof(vty->sb_buf))
				vty->sb_buf[vty->sb_len] = buf[i];
			vty->sb_len++;
			continue;
		}

		if (vty->iac) {
			/* In case of telnet command */
			int ret = 0;
			ret = vty_telnet_option(vty, buf + i, nbytes - i);
			vty->iac = 0;
			i += ret;
			continue;
		}
	        
		if (vty->status == VTY_MORE) {
			switch (buf[i]) {
			case CONTROL('C'):
			case 'q':
			case 'Q':
				vty_buffer_reset(vty);
				break;
			default:
				break;
			}
			continue;
		}

		/* Escape character. */
		if (vty->escape == VTY_ESCAPE) {
			vty_escape_map(buf[i], vty);
			continue;
		}

		/* Pre-escape status. */
		if (vty->escape == VTY_PRE_ESCAPE) {
			switch (buf[i]) {
			case '[':
				vty->escape = VTY_ESCAPE;
				break;
			case 'b':
				vty_backward_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case 'f':
				vty_forward_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case 'd':
				vty_forward_kill_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			case CONTROL('H'):
			case 0x7f:
				vty_backward_kill_word(vty);
				vty->escape = VTY_NORMAL;
				break;
			default:
				vty->escape = VTY_NORMAL;
				break;
			}
			continue;
		}

		switch (buf[i]) {
		case CONTROL('A'):
			vty_beginning_of_line(vty);
			break;
		case CONTROL('B'):
			vty_backward_char(vty);
			break;
		case CONTROL('C'):
			vty_stop_input(vty);
			break;
		case CONTROL('D'):
			vty_delete_char(vty);
			break;
		case CONTROL('E'):
			vty_end_of_line(vty);
			break;
		case CONTROL('F'):
			vty_forward_char (vty);
			break;
		case CONTROL('H'):
		case 0x7f:
			vty_delete_backward_char(vty);
			break;
		case CONTROL('K'):
			vty_kill_line(vty);
			break;
		case CONTROL('N'):
			vty_next_line(vty);
			break;
		case CONTROL('P'):
			vty_previous_line(vty);
			break;
		case CONTROL('T'):
			vty_transpose_chars(vty);
			break;
		case CONTROL('U'):
			vty_kill_line_from_beginning(vty);
			break;
		case CONTROL('W'):
			vty_backward_kill_word(vty);
			break;
		case CONTROL('Z'):
			vty_end_config(vty);
			break;
		case '\n':
		case '\r':
			vty_out(vty, "%s", VTY_NEWLINE);
			vty_execute(vty);
			break;
		case '\t':
			vty_complete_command(vty);
			break;
		case '?':
			if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE) {
				vty_self_insert(vty, buf[i]);
			} else {
				vty_describe_command(vty);
			}
			break;
		case '\033':
			if (i + 1 < nbytes && buf[i + 1] == '[') {
				vty->escape = VTY_ESCAPE;
				i++;
			} else {
				vty->escape = VTY_PRE_ESCAPE;
			}
			break;
		default:
			if (buf[i] > 31 && buf[i] < 127)
				vty_self_insert(vty, buf[i]);
			break;
		}
	}

	/* Check status. */
	if (vty->status == VTY_CLOSE) {
		vty_close (vty);
	} else {
		vty_event(VTY_WRITE, vty_sock, vty);
		vty_event(VTY_READ, vty_sock, vty);
	}

	return 0;
}

/* Flush buffer to the vty. */
static int
vty_flush(thread_t *thread)
{
	int erase;
	buffer_status_t flushrc;
	int vty_sock = THREAD_FD(thread);
	vty_t *vty = THREAD_ARG(thread);

	vty->t_write = NULL;

	/* Handle Write Timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		vty_event(VTY_WRITE, vty_sock, vty);
		return 0;
	}

	/* Tempolary disable read thread. */
	if ((vty->lines == 0) && vty->t_read) {
		thread_cancel(vty->t_read);
		vty->t_read = NULL;
	}

	/* Function execution continue. */
	erase = ((vty->status == VTY_MORE || vty->status == VTY_MORELINE));

	/* N.B. if width is 0, that means we don't know the window size. */
	if ((vty->lines == 0) || (vty->width == 0)) {
		flushrc = buffer_flush_available(vty->obuf, vty->fd);
	} else if (vty->status == VTY_MORELINE) {
		flushrc = buffer_flush_window(vty->obuf, vty->fd, vty->width,
					      1, erase, 0);
	} else {
		flushrc = buffer_flush_window(vty->obuf, vty->fd, vty->width,
					      vty->lines >= 0 ? vty->lines :
							        vty->height,
					      erase, 0);
	}

	switch (flushrc) {
	case BUFFER_ERROR:
		vty->monitor = 0; /* disable monitoring to avoid infinite recursion */
		log_message(LOG_WARNING, "buffer_flush failed on vty client fd %d, closing"
				       , vty->fd);
		buffer_reset(vty->obuf);
		vty_close(vty);
		return 0;
	case BUFFER_EMPTY:
		if (vty->status == VTY_CLOSE) {
			vty_close (vty);
		} else {
			vty->status = VTY_NORMAL;
			if (vty->lines == 0) {
				vty_event(VTY_READ, vty_sock, vty);
			}
		}
		break;
	case BUFFER_PENDING:
		/* There is more data waiting to be written. */
		vty->status = VTY_MORE;
		if (vty->lines == 0) {
			vty_event(VTY_WRITE, vty_sock, vty);
		}
		break;
	}

	return 0;
}

/* Create new vty structure. */
static vty_t *
vty_create(int vty_sock, struct sockaddr_storage *addr)
{
	vty_t *vty;

	/* Allocate new vty structure and set up default values. */
	vty = vty_new();
	vty->fd = vty_sock;
	vty->type = VTY_TERM;
	vty->address = *addr;
	if (no_password_check) {
		vty->node = (host.advanced) ? ENABLE_NODE : VIEW_NODE;
	} else {
		vty->node = AUTH_NODE;
	}

	vty->fail = 0;
	vty->cp = 0;
	vty_clear_buf(vty);
	vty->length = 0;
	memset(vty->hist, 0, sizeof(vty->hist));
	vty->hp = 0;
	vty->hindex = 0;
	vector_set_index(vtyvec, vty_sock, vty);
	vty->status = VTY_NORMAL;
	vty->v_timeout = vty_timeout_val;
	vty->lines = (host.lines >= 0) ? host.lines: -1;
	vty->iac = 0;
	vty->iac_sb_in_progress = 0;
	vty->sb_len = 0;

	if (!no_password_check) {
		/* Vty is not available if password isn't set. */
		if (host.password == NULL && host.password_encrypt == NULL) {
			vty_out(vty, "Vty password is not set.%s", VTY_NEWLINE);
			vty->status = VTY_CLOSE;
			vty_close(vty);
			return NULL;
		}
	}

	/* Say hello to the world. */
	vty_hello(vty);
	if (!no_password_check) {
		vty_out(vty, "%sUser Access Verification%s%s"
			   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	}

	/* Setting up terminal. */
	vty_will_echo(vty);
	vty_will_suppress_go_ahead(vty);

	vty_dont_linemode(vty);
	vty_do_window_size(vty);

	vty_prompt(vty);

	/* Add read/write thread. */
	vty_event(VTY_WRITE, vty_sock, vty);
	vty_event(VTY_READ, vty_sock, vty);

	return vty;
}

/* Accept connection from the network. */
static int
vty_accept(thread_t *thread)
{
	struct sockaddr_storage sock;
	socklen_t len;
	int vty_sock, ret, val;
	unsigned int on = 1;
	int accept_sock = THREAD_FD(thread);

	/* Handle Read Timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		vty_event(VTY_SERV, accept_sock, NULL);
		return 0;
	}

	/* We continue hearing vty socket. */
	vty_event(VTY_SERV, accept_sock, NULL);

	/* We can handle IPv4 or IPv6 socket. */
	memset(&sock, 0, sizeof(struct sockaddr_storage));
	len = sizeof(struct sockaddr_storage);
	vty_sock = accept(accept_sock, (struct sockaddr *) &sock, &len);
	if (vty_sock < 0) {
		log_message(LOG_WARNING, "can't accept vty socket : %s"
				       , strerror(errno));
		return -1;
	}

	/* Make socket non-block. */
	val = fcntl(vty_sock, F_GETFL, 0);
	fcntl(vty_sock, F_SETFL, val | O_NONBLOCK);

	/* Set NODELAY */
	ret = setsockopt(vty_sock, IPPROTO_TCP, TCP_NODELAY, 
			 (char *) &on, sizeof(on));
	if (ret < 0) {
		log_message(LOG_INFO, "can't set sockopt to vty_sock : %s"
				    , strerror(errno));
	}

	log_message(LOG_INFO, "Vty connection from %s"
			    , inet_sockaddrtos(&sock));

	vty_create(vty_sock, &sock);
	return 0;
}

/* Start listner thread */
int
vty_listen(struct sockaddr_storage *addr)
{
	int accept_sock, ret, on = 1;
	socklen_t len;
	mode_t old_mask;

	/* Mask */
	old_mask = umask(0077);

	/* Socket */
	accept_sock = socket(addr->ss_family, SOCK_STREAM, 0);
	if (accept_sock < 0) {
		log_message(LOG_INFO, "Vty error creating listening socket on [%s]:%d (%s)"
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr))
				    , strerror(errno));
		return -1;
	}

	/* Socket tweaking */
	ret = setsockopt(accept_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ret < 0) {
		log_message(LOG_INFO, "Vty error cant do SO_REUSEADDR errno=%d (%s)"
				    , errno
				    , strerror(errno));
		close(accept_sock);
		return -1;
	}

	/* Socket bind */
	len = sizeof(*addr);
	ret = bind(accept_sock, (struct sockaddr *) addr, len);
	if (ret < 0) {
		log_message(LOG_INFO, "Vty error cant bind to [%s]:%d (%s)"
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr))
				    , strerror(errno));
		close(accept_sock);
		return -1;
	}

	/* Socket listen */
	ret = listen(accept_sock, 3);
	if (ret < 0) {
		log_message(LOG_INFO, "Vty error cant listen to [%s]:%d (%s)"
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr))
				    , strerror(errno));
		close(accept_sock);
		return -1;

	}

	/* Restore old mask */
	umask(old_mask);

	log_message(LOG_INFO, "Vty start listening on [%s]:%d"
			    , inet_sockaddrtos(addr)
			    , ntohs(inet_sockaddrport(addr)));

	vty_event(VTY_SERV, accept_sock, NULL);
	return accept_sock;
}

/* Close vty interface.  Warning: call this only from functions that
 * will be careful not to access the vty afterwards (since it has
 * now been freed).  This is safest from top-level functions (called
 * directly by the thread dispatcher). */
void
vty_close(vty_t *vty)
{
	int i;

	/* Cancel threads.*/
	if (vty->t_read)
		thread_cancel(vty->t_read);
	if (vty->t_write)
		thread_cancel(vty->t_write);
	if (vty->t_timeout)
		thread_cancel(vty->t_timeout);

	/* Flush buffer. */
	buffer_flush_all(vty->obuf, vty->fd);

	/* Free input buffer. */
	buffer_free(vty->obuf);

	/* Free command history. */
	for (i = 0; i < VTY_MAXHIST; i++) {
		FREE_PTR(vty->hist[i]);
	}

	/* Unset vector. */
	vector_unset(vtyvec, vty->fd);

	/* Close socket. */
	if (vty->fd > 0)
		close(vty->fd);

	FREE_PTR(vty->buf);

	/* Check configure. */
	vty_config_unlock(vty);

	/* OK free vty. */
	FREE(vty);
}

/* When time out occur output message then close connection. */
static int
vty_timeout(thread_t *thread)
{
	vty_t *vty;

	vty = THREAD_ARG(thread);
	vty->t_timeout = NULL;
	vty->v_timeout = 0;

	/* Clear buffer*/
	buffer_reset(vty->obuf);
	vty_out(vty, "%sVty connection is timed out.%s", VTY_NEWLINE, VTY_NEWLINE);

	/* Close connection. */
	vty->status = VTY_CLOSE;
	vty_close(vty);

	return 0;
}

/* Read up configuration file from file_name. */
static int
vty_read_file(FILE *confp)
{
	int ret;
	vty_t *vty;

	vty = vty_new();
	vty->fd = 0;			/* stdout */
	vty->type = VTY_TERM;
	vty->node = CONFIG_NODE;
  
	/* Execute configuration file */
	ret = config_from_file(vty, confp);

	if (!((ret == CMD_SUCCESS) || (ret == CMD_ERR_NOTHING_TODO))) {
		switch (ret) {
		case CMD_ERR_AMBIGUOUS:
			log_message(LOG_ERR, "Ambiguous command.\n");
			break;
		case CMD_ERR_NO_MATCH:
			log_message(LOG_ERR, "There is no such command.\n");
			break;
		}
		log_message(LOG_ERR, "Error occured during reading below line.\n%s\n"
				   , vty->buf);
		vty_close(vty);
		return -1;
	}

	vty_close(vty);
	return 0;
}

static FILE *
vty_use_backup_config(char *fullpath)
{
	char *fullpath_sav, *fullpath_tmp;
	FILE *ret = NULL;
	struct stat buf;
	int tmp, sav;
	int c, retval;
	char buffer[512];
  
	fullpath_sav = MALLOC(strlen(fullpath) + strlen (CONF_BACKUP_EXT) + 1);
	strcpy(fullpath_sav, fullpath);
	strcat(fullpath_sav, CONF_BACKUP_EXT);
	if (stat (fullpath_sav, &buf) == -1) {
		FREE(fullpath_sav);
		return NULL;
	}

	fullpath_tmp = MALLOC(strlen(fullpath) + 8);
	sprintf(fullpath_tmp, "%s.XXXXXX", fullpath);
  
	/* Open file to configuration write. */
	tmp = mkstemp(fullpath_tmp);
	if (tmp < 0) {
		FREE(fullpath_sav);
		FREE(fullpath_tmp);
		return NULL;
	}

	sav = open(fullpath_sav, O_RDONLY);
	if (sav < 0) {
		unlink(fullpath_tmp);
		FREE(fullpath_sav);
		FREE(fullpath_tmp);
		return NULL;
	}
  
	while((c = read(sav, buffer, 512)) > 0) {
		retval = write(tmp, buffer, c);
		if (retval < 0) {
			unlink(fullpath_tmp);
			FREE(fullpath_sav);
			FREE(fullpath_tmp);
			close(sav);
			close(tmp);
			return NULL;
		}
	}
  
	close(sav);
	close(tmp);
  
	if (chmod(fullpath_tmp, 0600) != 0) {
		unlink(fullpath_tmp);
		FREE(fullpath_sav);
		FREE(fullpath_tmp);
		return NULL;
	}
  
	if (link(fullpath_tmp, fullpath) == 0)
		ret = fopen(fullpath, "r");

	unlink(fullpath_tmp);
  
	FREE(fullpath_sav);
	FREE(fullpath_tmp);
	return ret;
}

/* Read up configuration file from file_name. */
int
vty_read_config(char *config_file, char *config_default_dir)
{
	char cwd[MAXPATHLEN];
	FILE *confp = NULL;
	char *fullpath;
	char *tmp = NULL;
	char *retpath;

	/* If -f flag specified. */
	if (config_file != NULL) {
		if (!IS_DIRECTORY_SEP(config_file[0])) {
			retpath = getcwd(cwd, MAXPATHLEN);
			if (!retpath) {
				log_message(LOG_ERR, "%s: failed to get current working directory: %s\n"
						   , __func__, strerror(errno));
				return -1;
			}
			tmp = MALLOC(strlen(cwd) + strlen(config_file) + 2);
			sprintf(tmp, "%s/%s", cwd, config_file);
			fullpath = tmp;
		} else {
			fullpath = config_file;
		}

		confp = fopen(fullpath, "r");

		if (confp == NULL) {
			log_message(LOG_ERR, "%s: failed to open configuration file %s: %s\n"
					   , __func__, fullpath, strerror (errno));
          
			confp = vty_use_backup_config(fullpath);
			if (confp) {
				log_message(LOG_ERR, "WARNING: using backup configuration file!\n");
			} else {
				log_message(LOG_ERR, "can't open configuration file [%s]\n"
						   , config_file);
				FREE_PTR(tmp);
				return -1;
			}
		}
	} else {
		confp = fopen(config_default_dir, "r");
		if (confp == NULL) {
			log_message(LOG_ERR, "%s: failed to open configuration file %s: %s\n"
					   , __func__, config_default_dir, strerror(errno));
          
			confp = vty_use_backup_config(config_default_dir);
			if (confp) {
				log_message(LOG_ERR, "WARNING: using backup configuration file!\n");
				fullpath = config_default_dir;
			} else {
				log_message(LOG_ERR, "can't open configuration file [%s]\n"
						   , config_default_dir);
				return -1;
			}
		} else {
			fullpath = config_default_dir;
		}
	}

	vty_read_file(confp);
	fclose(confp);
	host_config_set(fullpath);
	FREE_PTR(tmp);
	return 0;
}

int
vty_config_lock(vty_t *vty)
{
	if (vty_config == 0) {
		vty->config = 1;
		vty_config = 1;
	}

	return vty->config;
}

int
vty_config_unlock(vty_t *vty)
{
	if (vty_config == 1 && vty->config == 1) {
		vty->config = 0;
		vty_config = 0;
	}

	return vty->config;
}

/* Master of the threads. */
static void
vty_event(event_t event, int sock, vty_t *vty)
{
	thread_t *vty_serv_thread;

	switch (event) {
	case VTY_SERV:
		vty_serv_thread = thread_add_read(master, vty_accept, vty, sock,
						  VTY_IO_TIMEOUT);
		vector_set_index(Vvty_serv_thread, sock, vty_serv_thread);
		break;

	case VTY_READ:
		vty->t_read = thread_add_read(master, vty_read, vty, sock, VTY_IO_TIMEOUT);

		/* Time out treatment. */
		if (vty->v_timeout) {
			if (vty->t_timeout)
				thread_cancel(vty->t_timeout);
			vty->t_timeout = thread_add_timer(master, vty_timeout, vty,
							  vty->v_timeout*TIMER_HZ);
		}
		break;

	case VTY_WRITE:
		if (!vty->t_write)
			vty->t_write = thread_add_write(master, vty_flush, vty, sock,
							VTY_IO_TIMEOUT);
		break;

	case VTY_TIMEOUT_RESET:
		if (vty->t_timeout) {
			thread_cancel(vty->t_timeout);
			vty->t_timeout = NULL;
		}

		if (vty->v_timeout) {
			vty->t_timeout = thread_add_timer(master, vty_timeout, vty,
							  vty->v_timeout*TIMER_HZ);
		}
		break;
	}
}

DEFUN(config_who,
      config_who_cmd,
      "who",
      "Display who is on vty\n")
{
	char ipaddr[INET6_ADDRSTRLEN];
	unsigned int i;
	vty_t *v;

	for (i = 0; i < vector_active(vtyvec); i++) {
		if ((v = vector_slot(vtyvec, i)) != NULL) {
			vty_out(vty, "%svty[%d] connected from %s.%s"
				   , v->config ? "*" : " "
				   , i, inet_sockaddrtos2(&v->address, ipaddr)
				   , VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}

/* Move to vty configuration mode. */
DEFUN(line_vty,
      line_vty_cmd,
      "line vty",
      "Configure a terminal line\n"
      "Virtual terminal\n")
{
	vty->node = VTY_NODE;
	return CMD_SUCCESS;
}

/* Set time out value. */
static int
exec_timeout(vty_t *vty, const char *min_str, const char *sec_str)
{
	unsigned long timeout = 0;

	/* min_str and sec_str are already checked by parser.  So it must be
	  all digit string. */
	if (min_str) {
		timeout = strtol(min_str, NULL, 10);
		timeout *= 60;
	}

	if (sec_str) {
		timeout += strtol(sec_str, NULL, 10);
	}

	vty_timeout_val = timeout;
	vty->v_timeout = timeout;
	vty_event(VTY_TIMEOUT_RESET, 0, vty);

	return CMD_SUCCESS;
}

DEFUN(exec_timeout_min,
      exec_timeout_min_cmd,
      "exec-timeout <0-35791>",
      "Set timeout value\n"
      "Timeout value in minutes\n")
{
	return exec_timeout(vty, argv[0], NULL);
}

DEFUN(exec_timeout_sec,
      exec_timeout_sec_cmd,
      "exec-timeout <0-35791> <0-2147483>",
      "Set the EXEC timeout\n"
      "Timeout in minutes\n"
      "Timeout in seconds\n")
{
	return exec_timeout(vty, argv[0], argv[1]);
}

DEFUN(no_exec_timeout,
      no_exec_timeout_cmd,
      "no exec-timeout",
      NO_STR
      "Set the EXEC timeout\n")
{
	return exec_timeout(vty, NULL, NULL);
}

/* vty login. */
DEFUN(vty_login,
      vty_login_cmd,
      "login",
      "Enable password checking\n")
{
	no_password_check = 0;
	return CMD_SUCCESS;
}

DEFUN(no_vty_login,
      no_vty_login_cmd,
      "no login",
      NO_STR
      "Enable password checking\n")
{
	no_password_check = 1;
	return CMD_SUCCESS;
}

/* initial mode. */
DEFUN(service_advanced_vty,
      service_advanced_vty_cmd,
      "service advanced-vty",
      "Set up miscellaneous service\n"
      "Enable advanced mode vty interface\n")
{
	host.advanced = 1;
	return CMD_SUCCESS;
}

DEFUN(no_service_advanced_vty,
      no_service_advanced_vty_cmd,
      "no service advanced-vty",
      NO_STR
      "Set up miscellaneous service\n"
      "Enable advanced mode vty interface\n")
{
	host.advanced = 0;
	return CMD_SUCCESS;
}

DEFUN(terminal_monitor,
      terminal_monitor_cmd,
      "terminal monitor",
      "Set terminal line parameters\n"
      "Copy debug output to the current terminal line\n")
{
	vty->monitor = 1;
	return CMD_SUCCESS;
}

DEFUN(terminal_no_monitor,
      terminal_no_monitor_cmd,
      "terminal no monitor",
      "Set terminal line parameters\n"
      NO_STR
      "Copy debug output to the current terminal line\n")
{
	vty->monitor = 0;
	return CMD_SUCCESS;
}

ALIAS(terminal_no_monitor,
      no_terminal_monitor_cmd,
      "no terminal monitor",
      NO_STR
      "Set terminal line parameters\n"
      "Copy debug output to the current terminal line\n")

DEFUN(show_history,
      show_history_cmd,
      "show history",
      SHOW_STR
      "Display the session command history\n")
{
	int index;

	for (index = vty->hindex + 1; index != vty->hindex;) {
		if (index == VTY_MAXHIST) {
			index = 0;
			continue;
		}

		if (vty->hist[index] != NULL) {
			vty_out(vty, "  %s%s", vty->hist[index], VTY_NEWLINE);
		}

		index++;
	}

	return CMD_SUCCESS;
}

/* Display current configuration. */
static int
vty_config_write(vty_t *vty)
{
	vty_out(vty, "line vty%s", VTY_NEWLINE);

	/* exec-timeout */
	if (vty_timeout_val != VTY_TIMEOUT_DEFAULT) {
		vty_out(vty, " exec-timeout %ld %ld%s", 
			vty_timeout_val / 60,
			vty_timeout_val % 60, VTY_NEWLINE);
	}

	/* login */
	if (no_password_check)
		vty_out(vty, " no login%s", VTY_NEWLINE);
    
	vty_out(vty, "!%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

cmd_node_t vty_node = {
	VTY_NODE,
	"%s(config-line)# ",
	1,
};

/* Reset all VTY status. */
void
vty_reset(void)
{
	unsigned int i;
	vty_t *vty;
	thread_t *vty_serv_thread;

	for (i = 0; i < vector_active(vtyvec); i++) {
		if ((vty = vector_slot(vtyvec, i)) != NULL) {
			buffer_reset(vty->obuf);
			vty->status = VTY_CLOSE;
			vty_close(vty);
		}
	}

	for (i = 0; i < vector_active(Vvty_serv_thread); i++) {
		if ((vty_serv_thread = vector_slot(Vvty_serv_thread, i)) != NULL) {
			thread_cancel(vty_serv_thread);
			vector_slot(Vvty_serv_thread, i) = NULL;
			close(i);
		}
	}

	vty_timeout_val = VTY_TIMEOUT_DEFAULT;
}

static void
vty_save_cwd(void)
{
	char cwd[MAXPATHLEN];
	char *c;
	int retval;
	char *retpath;

	c = getcwd(cwd, MAXPATHLEN);

	if (!c) {
		retval = chdir(SYSCONFDIR);
		if (!retval)
			return;
		retpath = getcwd(cwd, MAXPATHLEN);
		if (!retpath)
			return;
	}

	vty_cwd = MALLOC(strlen(cwd) + 1);
	strcpy(vty_cwd, cwd);
}

char *
vty_get_cwd(void)
{
	return vty_cwd;
}

int
vty_shell(vty_t *vty)
{
	return vty->type == VTY_SHELL ? 1 : 0;
}

int
vty_shell_serv(vty_t *vty)
{
	return vty->type == VTY_SHELL_SERV ? 1 : 0;
}

/* Install vty's own commands like `who' command. */
void
vty_init(void)
{
	/* For further configuration read, preserve current directory. */
	vty_save_cwd();

	vtyvec = vector_init(VECTOR_DEFAULT_SIZE);

	/* Initilize server thread vector. */
	Vvty_serv_thread = vector_init(VECTOR_DEFAULT_SIZE);

	/* Install basic node. */
	install_node(&vty_node, vty_config_write);

	install_element(VIEW_NODE, &config_who_cmd);
	install_element(VIEW_NODE, &show_history_cmd);
	install_element(ENABLE_NODE, &config_who_cmd);
	install_element(CONFIG_NODE, &line_vty_cmd);
	install_element(CONFIG_NODE, &service_advanced_vty_cmd);
	install_element(CONFIG_NODE, &no_service_advanced_vty_cmd);
	install_element(CONFIG_NODE, &show_history_cmd);
	install_element(ENABLE_NODE, &terminal_monitor_cmd);
	install_element(ENABLE_NODE, &terminal_no_monitor_cmd);
	install_element(ENABLE_NODE, &no_terminal_monitor_cmd);
	install_element(ENABLE_NODE, &show_history_cmd);

	install_default(VTY_NODE);
	install_element(VTY_NODE, &exec_timeout_min_cmd);
	install_element(VTY_NODE, &exec_timeout_sec_cmd);
	install_element(VTY_NODE, &no_exec_timeout_cmd);
	install_element(VTY_NODE, &vty_login_cmd);
	install_element(VTY_NODE, &no_vty_login_cmd);
}

void
vty_terminate(void)
{
	FREE_PTR(vty_cwd);

	if (vtyvec && Vvty_serv_thread) {
		vty_reset();
		vector_free(vtyvec);
		vector_free(Vvty_serv_thread);
	}
}
