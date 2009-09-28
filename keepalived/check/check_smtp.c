/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        SMTP CHECK. Check an SMTP-server.
 *
 * Authors:     Jeremy Rumpf, <jrumpf@heavyload.net>
 *              Alexandre Cassen, <acassen@linux-vs.org>
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
 * Copyright (C) 2001-2009 Alexandre Cassen, <acassen@freebox.fr>
 */

#include <ctype.h>

#include "check_smtp.h"
#include "check_api.h"
#include "logger.h"
#include "memory.h"
#include "ipwrapper.h"
#include "utils.h"
#include "parser.h"
#include "daemon.h"

int smtp_connect_thread(thread *);

/* module variables */
static smtp_host *default_host = NULL;

/*
 * Used as a callback from free_list() to free all
 * the list elements in smtp_checker->host before we
 * free smtp_checker itself.
 */
void
smtp_free_host(void *data)
{
        FREE(data);
}

/* Used as a callback from the checker api, queue_checker(),
 * to free up a checker entry and all its associated data.
 */
void
free_smtp_check(void *data)
{
  	smtp_checker *smtp_chk = CHECKER_DATA(data);
	free_list(smtp_chk->host);
	FREE(smtp_chk->helo_name);
	FREE(smtp_chk);
	FREE(data);
}

/*
 * Used as a callback from dump_list() to print out all
 * the list elements in smtp_checker->host.
 */
void
smtp_dump_host(void *data)
{
        smtp_host *smtp_hst = data;
        log_message(LOG_INFO, "   Checked ip = %s", inet_ntop2(smtp_hst->ip));
        log_message(LOG_INFO, "           port = %d", ntohs(smtp_hst->port));
	if (smtp_hst->bindto)
        	log_message(LOG_INFO, "           bindto = %s", inet_ntop2(smtp_hst->bindto));
}

/* 
 * Callback for whenever we've been requested to dump our
 * configuration.
 */
void
dump_smtp_check(void *data)
{
	smtp_checker *smtp_chk = CHECKER_DATA(data);
	log_message(LOG_INFO, "   Keepalive method = SMTP_CHECK");
        log_message(LOG_INFO, "           helo = %s", smtp_chk->helo_name);
        log_message(LOG_INFO, "           timeout = %ld", smtp_chk->timeout/TIMER_HZ);
        log_message(LOG_INFO, "           retry = %d", smtp_chk->retry);
        log_message(LOG_INFO, "           delay before retry = %ld", smtp_chk->db_retry/TIMER_HZ);
	dump_list(smtp_chk->host);
}

/* Allocates a default host structure */
smtp_host *
smtp_alloc_host(void)
{
	checker *chk = LIST_TAIL_DATA(checkers_queue);
	smtp_host *new;

	/* Allocate the new host data structure */
	new = (smtp_host *)MALLOC(sizeof(smtp_host));

	/* 
	 * By default we set the ip to connect to as the same ip as the current real server
	 * in the rs config. This might be overridden later on by a "connect_ip" keyword.
	 */
	new->ip = CHECKER_RIP(chk);
	new->port = htons(SMTP_DEFAULT_PORT);
	return new;
}

/* 
 * Callback for whenever an SMTP_CHECK keyword is encountered
 * in the config file. 
 */
void
smtp_check_handler(vector strvec)
{
	smtp_checker *smtp_chk = (smtp_checker *)MALLOC(sizeof(smtp_checker));

	/* 
	 * Set something sane for the default HELO banner
	 * May be overridden by a "helo_name" keyword later.
	 */
	smtp_chk->helo_name = (char *)MALLOC(strlen(SMTP_DEFAULT_HELO) + 1);
	memcpy(smtp_chk->helo_name, SMTP_DEFAULT_HELO, strlen(SMTP_DEFAULT_HELO) + 1);

	/* some other sane values */
	smtp_chk->timeout = 5 * TIMER_HZ;
	smtp_chk->db_retry = 1 * TIMER_HZ;
	smtp_chk->retry = 1;

	/*
	 * Have the checker queue code put our checker into the checkers_queue
	 * list.
	 *
	 * queue_checker(void (*free) (void *), void (*dump) (void *),
	 *               int (*launch) (struct _thread *),
	 *               void *data)
	 */
	queue_checker(free_smtp_check, dump_smtp_check, smtp_connect_thread,
		      smtp_chk);

	/* 
	 * Last, allocate/setup the list that will hold all the per host 
	 * configuration structures. We'll set a "default host", which
	 * is the same ip as the real server. If there are additional "host"
	 * sections in the config, the default will be deleted and overridden.
	 * If the default is still set by a previous "SMTP_CHECK" section,
	 * we must simply overwrite the old value:
	 * - it must not be reused, because it was probably located in a
	 *   different "real_server" section and
	 * - it must not be freed, because it is still referenced
	 *   by some other smtp_chk->host.
	 * This must come after queue_checker()!
	 */
	smtp_chk->host = alloc_list(smtp_free_host, smtp_dump_host);
	default_host = smtp_alloc_host();
	list_add(smtp_chk->host, default_host);
}

/* 
 * Callback for whenever the "host" keyword is encountered
 * in the config file. 
 */
void
smtp_host_handler(vector strvec)
{
        smtp_checker *smtp_chk = CHECKER_GET();

	/*
	 * If the default host is still allocated, delete it
	 * before we stick user defined hosts in the list.
	 */
	if (default_host) {
		list_del(smtp_chk->host, default_host);
		FREE(default_host);
		default_host = NULL;
	}

        /* add an empty host to the list, smtp_checker->host */
        list_add(smtp_chk->host, smtp_alloc_host());
}

/* "connect_ip" keyword */
void
smtp_ip_handler(vector strvec)
{
	smtp_checker *smtp_chk = CHECKER_GET();
	smtp_host *smtp_hst = LIST_TAIL_DATA(smtp_chk->host);
	inet_ston(VECTOR_SLOT(strvec, 1), &smtp_hst->ip);
}

/* "connect_port" keyword */
void
smtp_port_handler(vector strvec)
{
	smtp_checker *smtp_chk = CHECKER_GET();
	smtp_host *smtp_hst = LIST_TAIL_DATA(smtp_chk->host);
	smtp_hst->port = htons(CHECKER_VALUE_INT(strvec)); 
}

/* "helo_name" keyword */
void
smtp_helo_name_handler(vector strvec)
{
	smtp_checker *smtp_chk = CHECKER_GET();
	smtp_chk->helo_name = CHECKER_VALUE_STRING(strvec);
}

/* "connect_timeout" keyword */
void
smtp_timeout_handler(vector strvec)
{
	smtp_checker *smtp_chk = CHECKER_GET();
	smtp_chk->timeout = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

/* "retry" keyword */
void
smtp_retry_handler(vector strvec)
{
        smtp_checker *smtp_chk = CHECKER_GET();
	smtp_chk->retry = CHECKER_VALUE_INT(strvec);
}

/* "delay_before_retry" keyword */
void
smtp_db_retry_handler(vector strvec)
{
        smtp_checker *smtp_chk = CHECKER_GET();
	smtp_chk->db_retry = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
}

/* "bindto" keyword */
void
smtp_bindto_handler(vector strvec)
{
        smtp_checker *smtp_chk = CHECKER_GET();
	smtp_host *smtp_hst = LIST_TAIL_DATA(smtp_chk->host);
        inet_ston(VECTOR_SLOT(strvec, 1), &smtp_hst->bindto);
}

/* Config callback installer */
void
install_smtp_check_keyword(void)
{
        /* 
         * Notify the config log parser that we need to be notified via
	 * callbacks when the following keywords are encountered in the
	 * keepalive.conf file.
         */
	install_keyword("SMTP_CHECK", &smtp_check_handler);
	install_sublevel();
	install_keyword("helo_name", &smtp_helo_name_handler);
 	install_keyword("connect_timeout", &smtp_timeout_handler);
	install_keyword("delay_before_retry", &smtp_db_retry_handler);
	install_keyword("retry", &smtp_retry_handler);
	install_keyword("host", &smtp_host_handler);
	install_sublevel();
	install_keyword("connect_ip", &smtp_ip_handler);
	install_keyword("connect_port", &smtp_port_handler);
	install_keyword("bindto", &smtp_bindto_handler);
	install_sublevel_end();
	install_sublevel_end();
}

/*
 * Final handler. Determines if we need a retry or not. 
 * Also has to make a decision if we need to bring the resulting
 * service down in case of error.
 */
int
smtp_final(thread *thread_obj, int error, const char *format, ...)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	char error_buff[512];
	char smtp_buff[542];
	va_list varg_list;

	/* Error or no error we should always have to close the socket */
	close(thread_obj->u.fd);

	/* If we're here, an attempt HAS been made already for the current host */
	smtp_chk->attempts++;
	
	if (error) {
		/* Always syslog the error when the real server is up */
                if (svr_checker_up(chk->id, chk->rs)) {
			if (format != NULL) {
				memcpy(error_buff, "SMTP_CHECK ", 11);
				va_start(varg_list, format);
				vsnprintf(error_buff + 11, 512 - 11, format, varg_list);
				va_end(varg_list);
				error_buff[512 - 1] = '\0';

				log_message(LOG_INFO, error_buff);
			} else {
				log_message(LOG_INFO, "SMTP_CHECK Unknown error");
			}
		}

		/*
		 * If we still have retries left, try this host again by
		 * scheduling the main thread to check it again after the
		 * configured backoff delay. Otherwise down the RS.
		 */
		if (smtp_chk->attempts < smtp_chk->retry) {
			thread_add_timer(thread_obj->master, smtp_connect_thread, chk,
					 smtp_chk->db_retry);
			return 0;
		}

		/*
		 * No more retries, pull the real server from the virtual server.
		 * Only smtp_alert if it wasn't previously down. It should
		 * be noted that smtp_alert makes a copy of the string arguments, so
		 * we don't have to keep them statically allocated.
		 */
                if (svr_checker_up(chk->id, chk->rs)) {
			if (format != NULL) {
				snprintf(smtp_buff, 542, "=> CHECK failed on service : %s <=",
					 error_buff + 11);
			} else {
				snprintf(smtp_buff, 542, "=> CHECK failed on service <=");
			}

			smtp_buff[542 - 1] = '\0';
			smtp_alert(chk->rs, NULL, NULL, "DOWN", smtp_buff);
		}

		update_svr_checker_state(DOWN, chk->id, chk->vs, chk->rs);

		/* Reset everything back to the first host in the list */
		smtp_chk->attempts = 0;
		smtp_chk->host_ctr = 0;

		/* Reschedule the main thread using the configured delay loop */;
		thread_add_timer(thread_obj->master, smtp_connect_thread, chk, chk->vs->delay_loop);

		return 0;
	}	

	/*
	 * Ok this host was successful, increment to the next host in the list
	 * and reset the attempts counter. We'll then reschedule the main thread again.
	 * If host_ctr exceeds the number of hosts in the list, http_main_thread will
	 * take note and bring up the real server as well as inject the delay_loop.
	 */
	smtp_chk->attempts = 0;
	smtp_chk->host_ctr++;

	thread_add_timer(thread_obj->master, smtp_connect_thread, chk, 1);
	return 0;
}

/* 
 * Zeros out the rx/tx buffer
 */
void
smtp_clear_buff(thread *thread_obj)
{
        checker *chk = THREAD_ARG(thread_obj);
        smtp_checker *smtp_chk = CHECKER_ARG(chk);
	memset(smtp_chk->buff, 0, SMTP_BUFF_MAX);
	smtp_chk->buff_ctr = 0;
}

/*
 * One thing to note here is we do a very cheap check for a newline.
 * We could receive two lines (with two newline characters) in a
 * single packet, but we don't care. We are only looking at the
 * SMTP response codes at the beginning anyway.
 */
int
smtp_get_line_cb(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	smtp_host *smtp_hst = smtp_chk->host_ptr;
	int f, r, x;

        /* Handle read timeout */
        if (thread_obj->type == THREAD_READ_TIMEOUT) {
		smtp_final(thread_obj, 1, "Read timeout from server [%s:%d]",
			   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
		return 0;
	}

	/* wrap the buffer, if full, by clearing it */
	if (SMTP_BUFF_MAX - smtp_chk->buff_ctr <= 0) {
		log_message(LOG_INFO, "SMTP_CHECK Buffer overflow reading from server [%s:%d]. "
		       "Increase SMTP_BUFF_MAX in smtp_check.h",
		       inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
		smtp_clear_buff(thread_obj);
	}

	/* Set descriptor non blocking */
        f = fcntl(thread_obj->u.fd, F_GETFL, 0);
        fcntl(thread_obj->u.fd, F_SETFL, f | O_NONBLOCK);

        /* read the data */
        r = read(thread_obj->u.fd, smtp_chk->buff + smtp_chk->buff_ctr,
                 SMTP_BUFF_MAX - smtp_chk->buff_ctr);

	if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
		thread_add_read(thread_obj->master, smtp_get_line_cb, chk,
				thread_obj->u.fd, smtp_chk->timeout);
        	fcntl(thread_obj->u.fd, F_SETFL, f);
		return 0;
	} else if (r > 0)
		smtp_chk->buff_ctr += r;

        /* restore descriptor flags */
        fcntl(thread_obj->u.fd, F_SETFL, f);

	/* check if we have a newline, if so, callback */
	for (x = 0; x < SMTP_BUFF_MAX; x++) {
		if (smtp_chk->buff[x] == '\n') {
			smtp_chk->buff[SMTP_BUFF_MAX - 1] = '\0';
			
			DBG("SMTP_CHECK [%s:%d] < %s", inet_ntop2(smtp_hst->ip),
			    ntohs(smtp_hst->port), smtp_chk->buff);

			(smtp_chk->buff_cb)(thread_obj);

			return 0;
		}
	}

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (r <= 0) {
		smtp_final(thread_obj, 1, "Read failure from server [%s:%d]",
			   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
		return 0;
	}

	/*
	 * Last case, we haven't read enough data yet
	 * to pull a newline. Schedule ourselves for
	 * another round.
	 */
	thread_add_read(thread_obj->master, smtp_get_line_cb, chk,
			thread_obj->u.fd, smtp_chk->timeout);
	return 0;
}

/* 
 * Ok a caller has asked us to asyncronously schedule a single line
 * to be received from the server. They have also passed us a call back
 * function that we'll call once we have the newline. If something bad
 * happens, the caller assumes we'll pass the error off to smtp_final(),
 * which will either down the real server or schedule a retry. The
 * function smtp_get_line_cb is what does the dirty work since the
 * sceduler can only accept a single *thread argument.
 */
void
smtp_get_line(thread *thread_obj, int (*callback) (struct _thread *))
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);

	/* clear the buffer */
	smtp_clear_buff(thread_obj);

	/* set the callback */
	smtp_chk->buff_cb = callback;

	/* schedule the I/O with our helper function  */
	thread_add_read(thread_obj->master, smtp_get_line_cb, chk,
		thread_obj->u.fd, smtp_chk->timeout);
	return;
}

/*
 * The scheduler function that puts the data out on the wire.
 * All our data will fit into one packet, so we only check if
 * the current write would block or not. If it wants to block,
 * we'll return to the scheduler and try again later. 
 */
int
smtp_put_line_cb(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	smtp_host *smtp_hst = smtp_chk->host_ptr;
	int f, w;


        /* Handle read timeout */
        if (thread_obj->type == THREAD_WRITE_TIMEOUT) {
		smtp_final(thread_obj, 1, "Write timeout to server [%s:%d]",
			   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
		return 0;
	}

	/* Set descriptor non blocking */
        f = fcntl(thread_obj->u.fd, F_GETFL, 0);
        fcntl(thread_obj->u.fd, F_SETFL, f | O_NONBLOCK);

        /* write the data */
        w = write(thread_obj->u.fd, smtp_chk->buff, smtp_chk->buff_ctr);

	if (w == -1 && (errno == EAGAIN || errno == EINTR)) {
		thread_add_write(thread_obj->master, smtp_put_line_cb, chk,
				 thread_obj->u.fd, smtp_chk->timeout);
        	fcntl(thread_obj->u.fd, F_SETFL, f);
		return 0;
	}

        /* restore descriptor flags */
        fcntl(thread_obj->u.fd, F_SETFL, f);

	DBG("SMTP_CHECK [%s:%d] > %s", inet_ntop2(smtp_hst->ip),
	    ntohs(smtp_hst->port), smtp_chk->buff);

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (w <= 0) {
		smtp_final(thread_obj, 1, "Write failure to server [%s:%d]",
			   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
		return 0;
	}

	/* Execute the callback */
	(smtp_chk->buff_cb)(thread_obj);
	return 0;
}

/* 
 * This is the same as smtp_get_line() except that we're sending a
 * line of data instead of receiving one.
 */
void
smtp_put_line(thread *thread_obj, int (*callback) (struct _thread *))
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);

	smtp_chk->buff[SMTP_BUFF_MAX - 1] = '\0';
	smtp_chk->buff_ctr = strlen(smtp_chk->buff);

	/* set the callback */
	smtp_chk->buff_cb = callback;

	/* schedule the I/O with our helper function  */
	thread_add_write(thread_obj->master, smtp_put_line_cb, chk,
			 thread_obj->u.fd, smtp_chk->timeout);
	return;
}

/*
 * Ok, our goal here is to snag the status code out of the
 * buffer and return it as an integer. If it's not legible,
 * return -1.
 */
int
smtp_get_status(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	char *buff = smtp_chk->buff;

	/* First make sure they're all digits */	
	if (isdigit(buff[0]) && isdigit(buff[1]) &&
	    isdigit(buff[2])) {
		/* Truncate the string and convert */	
		buff[3] = '\0';
		return atoi(buff);
	}

	return -1;
}

/* 
 * We have a connected socket and are ready to begin 
 * the conversation. This function schedules itself to 
 * be called via callbacks and tracking state in 
 * smtp_chk->state. Upon first calling, smtp_chk->state 
 * should be set to SMTP_START.
 */
int
smtp_engine_thread(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	smtp_host *smtp_hst = smtp_chk->host_ptr;

	switch (smtp_chk->state) {

		/* First step, schedule to receive the greeting banner */
		case SMTP_START:
			/*
			 * Ok, if smtp_get_line schedules us back, we will
			 * have data to analyze. Otherwise, smtp_get_line
			 * will defer directly to smtp_final.
			 */
			smtp_chk->state = SMTP_HAVE_BANNER;
			smtp_get_line(thread_obj, smtp_engine_thread);
			return 0;
			break;

		/* Second step, analyze banner, send HELO */
		case SMTP_HAVE_BANNER:
			/* Check for "220 some.mailserver.com" in the greeting */
			if (smtp_get_status(thread_obj) != 220) {
				smtp_final(thread_obj, 1, "Bad greeting banner from server [%s:%d]",
					inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));

				return 0;
			}

			/*
			 * Schedule to send the HELO, smtp_put_line will
			 * defer directly to smtp_final on error.
			 */
			smtp_chk->state = SMTP_SENT_HELO;
			snprintf(smtp_chk->buff, SMTP_BUFF_MAX, "HELO %s\r\n",
				 smtp_chk->helo_name);
			smtp_put_line(thread_obj, smtp_engine_thread);
			return 0;
			break;

		/* Third step, schedule to read the HELO response */
		case SMTP_SENT_HELO:
			smtp_chk->state = SMTP_RECV_HELO;
			smtp_get_line(thread_obj, smtp_engine_thread);
			return 0;
			break;

		/* Fourth step, analyze HELO return, send QUIT */
		case SMTP_RECV_HELO:
			/* Check for "250 Please to meet you..." */
			if (smtp_get_status(thread_obj) != 250) {
				smtp_final(thread_obj, 1, "Bad HELO response from server [%s:%d]",
					inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));

				return 0;
			}

			smtp_chk->state = SMTP_SENT_QUIT;
			snprintf(smtp_chk->buff, SMTP_BUFF_MAX, "QUIT\r\n");
			smtp_put_line(thread_obj, smtp_engine_thread);
			return 0;
			break;

		/* Fifth step, schedule to receive QUIT confirmation */
		case SMTP_SENT_QUIT:
			smtp_chk->state = SMTP_RECV_QUIT;
			smtp_get_line(thread_obj, smtp_engine_thread);
			return 0;
			break;

		/* Sixth step, wrap up success to smtp_final */
		case SMTP_RECV_QUIT:
			smtp_final(thread_obj, 0, NULL);
			return 0;
			break;
	}

	/* We shouldn't be here */
	smtp_final(thread_obj, 1, "Unknown smtp engine state encountered");
	return 0;
}
		
/* 
 * Second step in the process. Here we'll see if the connection
 * to the host we're checking was successful or not.
 */
int
smtp_check_thread(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	smtp_host *smtp_hst = smtp_chk->host_ptr;
	int status;

	status = tcp_socket_state(thread_obj->u.fd, thread_obj, smtp_hst->ip,
				  smtp_hst->port, smtp_check_thread);
	switch (status) {
		case connect_error:
			smtp_final(thread_obj, 1, "Error connecting to server [%s:%d]",
				   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
			return 0;
			break;

		case connect_timeout:
			smtp_final(thread_obj, 1, "Connection timeout to server [%s:%d]",
				   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
			return 0;
			break;

		case connect_success:
			DBG("SMTP_CHECK Remote SMTP server [%s:%d] connected",
			    inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));

			/* Enter the engine at SMTP_START */
			smtp_chk->state = SMTP_START;
			smtp_engine_thread(thread_obj);
			return 0;
			break;
	}

	/* we shouldn't be here */		
	smtp_final(thread_obj, 1, "Unknown connection error to server [%s:%d]",
		   inet_ntop2(smtp_hst->ip), ntohs(smtp_hst->port));
	return 0;
}

/* 
 * This is the main thread, where all the action starts.
 * When the check daemon comes up, it goes down the checkers_queue
 * and launches a thread for each checker that got registered.
 * This is the callback/event function for that initial thread.
 *
 * It should be noted that we ARE responsible for sceduling 
 * ourselves to run again. It doesn't have to be right here,
 * but eventually has to happen.
 */
int
smtp_connect_thread(thread *thread_obj)
{
	checker *chk = THREAD_ARG(thread_obj);
	smtp_checker *smtp_chk = CHECKER_ARG(chk);
	smtp_host *smtp_hst;
	enum connect_result status;
	int sd;

	/* Let's review our data structures.
	 *
	 * Thread is the structure used by the sceduler
	 * for sceduling many types of events. thread->arg in this
	 * case points to a checker structure. The checker
	 * structure holds data about the vs and rs configurations
	 * as well as the delay loop, etc. Each real server 
         * defined in the keepalived.conf will more than likely have
	 * a checker structure assigned to it. Each checker structure
         * has a data element that is meant to hold per checker 
	 * configurations. So thread->arg(checker)->data points to
 	 * a smtp_checker structure. In the smtp_checker structure
	 * we hold global configuration data for the smtp check.
	 * Smtp_checker has a list of per host (smtp_host) configuration
	 * data in smtp_checker->host.
	 *
	 * So this whole thing looks like this:
	 * thread->arg(checker)->data(smtp_checker)->host(smtp_host)
	 * 
	 * To make life simple, we'll break the structures out so
	 * that "chk" always points to the current checker structure,
	 * "smtp_chk" points to the current smtp_checker structure, 
	 * and "smtp_hst" points to the current smtp_host structure.
	 */

	/*
	 * If we're disabled, we'll do nothing at all.
	 * But we still have to register ourselves again so
	 * we don't fall of the face of the earth.
	 */
	if (!CHECKER_ENABLED(chk)) {
		thread_add_timer(thread_obj->master, smtp_connect_thread, chk,
				 chk->vs->delay_loop);
		return 0;
	}

	/*
	 * Set the internal host pointer to the host that well be 
	 * working on. If it's NULL, we've successfully tested all hosts.
	 * We'll bring the service up (if it's not already), reset the host list,
	 * and insert the delay loop. When we get scheduled again the host list
	 * will be reset and we will continue on checking them one by one.
	 */
	if ((smtp_chk->host_ptr = list_element(smtp_chk->host, smtp_chk->host_ctr)) == NULL) {
		if (!svr_checker_up(chk->id, chk->rs)) {
			log_message(LOG_INFO, "Remote SMTP server [%s:%d] succeed on service.",
			       inet_ntop2(CHECKER_RIP(chk)), ntohs(CHECKER_RPORT(chk)));

			smtp_alert(chk->rs, NULL, NULL, "UP",
				   "=> CHECK succeed on service <=");
			update_svr_checker_state(UP, chk->id, chk->vs, chk->rs);
		}

		smtp_chk->attempts = 0;
		smtp_chk->host_ctr = 0;
		smtp_chk->host_ptr = list_element(smtp_chk->host, 0);

		thread_add_timer(thread_obj->master, smtp_connect_thread, chk, chk->vs->delay_loop);
		return 0;
	}

	smtp_hst = smtp_chk->host_ptr;

	/* Create the socket, failling here should be an oddity */
	if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		DBG("SMTP_CHECK connection failed to create socket.");
		thread_add_timer(thread_obj->master, smtp_connect_thread, chk,
				 chk->vs->delay_loop);
		return 0;
	}

	status = tcp_bind_connect(sd, smtp_hst->ip, smtp_hst->port, smtp_hst->bindto);

	/* handle tcp connection status & register callback the next setp in the process */
	tcp_connection_state(sd, status, thread_obj, smtp_check_thread, smtp_chk->timeout);
	return 0;
}
