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
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
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

int smtp_connect_thread(thread_t *);
int smtp_final(thread_t *thread, int error, const char *format, ...)
	 __attribute__ ((format (printf, 3, 4)));

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
  	smtp_checker_t *smtp_checker = CHECKER_DATA(data);
	free_list(smtp_checker->host);
	FREE(smtp_checker->helo_name);
	FREE(smtp_checker->default_co);
	FREE(smtp_checker);
	FREE(data);
}

/*
 * Used as a callback from dump_list() to print out all
 * the list elements in smtp_checker->host.
 */
void
smtp_dump_host(void *data)
{
	dump_conn_opts (data);
}

/* 
 * Callback for whenever we've been requested to dump our
 * configuration.
 */
void
dump_smtp_check(void *data)
{
	smtp_checker_t *smtp_checker = CHECKER_DATA(data);
	log_message(LOG_INFO, "   Keepalive method = SMTP_CHECK");
	log_message(LOG_INFO, "           helo = %s", smtp_checker->helo_name);
	log_message(LOG_INFO, "           retry = %d", smtp_checker->retry);
	log_message(LOG_INFO, "           delay before retry = %ld", smtp_checker->db_retry/TIMER_HZ);
	dump_list(smtp_checker->host);
}

/* Allocates a default host structure */
smtp_host_t *
smtp_alloc_host(void)
{
	smtp_host_t *new;
	smtp_checker_t *smtp_checker = CHECKER_GET();

	/* Allocate the new host data structure and copy default values */
	new = (smtp_host_t *)MALLOC(sizeof(smtp_host_t));
	memcpy(new, smtp_checker->default_co, sizeof(smtp_host_t));

	/*
	 * Overwrite the checker->co field to make the standard connect_opts
	 * keyword handlers modify the newly created co object.
	 */
	CHECKER_GET_CO() = new;
	return new;
}

/* 
 * Callback for whenever an SMTP_CHECK keyword is encountered
 * in the config file. 
 */
void
smtp_check_handler(vector_t *strvec)
{
	smtp_checker_t *smtp_checker = (smtp_checker_t *)MALLOC(sizeof(smtp_checker_t));

	/* 
	 * Set something sane for the default HELO banner
	 * May be overridden by a "helo_name" keyword later.
	 */
	smtp_checker->helo_name = (char *)MALLOC(strlen(SMTP_DEFAULT_HELO) + 1);
	memcpy(smtp_checker->helo_name, SMTP_DEFAULT_HELO, strlen(SMTP_DEFAULT_HELO) + 1);

	/* some other sane values */
	smtp_checker->db_retry = 1 * TIMER_HZ;
	smtp_checker->retry = 1;

	/*
	 * Back up checker->co pointer as it will be overwritten by any
	 * following host{} section
	 */
	smtp_checker->default_co = CHECKER_NEW_CO();

	/*
	 * Have the checker queue code put our checker into the checkers_queue
	 * list.
	 *
	 * queue_checker(void (*free) (void *), void (*dump) (void *),
	 *               int (*launch) (thread_t *),
	 *               void *data, conn_opts_t *)
	 */
	queue_checker(free_smtp_check, dump_smtp_check, smtp_connect_thread,
		      smtp_checker, smtp_checker->default_co);

	/*
	 * Last, allocate the list that will hold all the per host
	 * configuration structures. We already have the "default host"
	 * in our checker->co.
	 * If there are additional "host" sections in the config, they will
	 * be used instead of the default, but all the uninitialized options
	 * of those hosts will be set to the default's values.
	 */
	smtp_checker->host = alloc_list(smtp_free_host, smtp_dump_host);
}

void smtp_check_end_handler(void)
{
	smtp_checker_t *smtp_checker = CHECKER_GET();

	/*
	 * If there was no host{} section, add a single host to the list
	 * by duplicating the default co.
	 */
	if (LIST_ISEMPTY(smtp_checker->host))
		list_add(smtp_checker->host, smtp_alloc_host());
}

/* 
 * Callback for whenever the "host" keyword is encountered
 * in the config file. 
 */
void
smtp_host_handler(vector_t *strvec)
{
        smtp_checker_t *smtp_checker = CHECKER_GET();

        /* add an empty host to the list, smtp_checker->host */
        list_add(smtp_checker->host, smtp_alloc_host());
}

/* "helo_name" keyword */
void
smtp_helo_name_handler(vector_t *strvec)
{
	smtp_checker_t *smtp_checker = CHECKER_GET();
	smtp_checker->helo_name = CHECKER_VALUE_STRING(strvec);
}

/* "retry" keyword */
void
smtp_retry_handler(vector_t *strvec)
{
        smtp_checker_t *smtp_checker = CHECKER_GET();
	smtp_checker->retry = CHECKER_VALUE_INT(strvec);
}

/* "delay_before_retry" keyword */
void
smtp_db_retry_handler(vector_t *strvec)
{
        smtp_checker_t *smtp_checker = CHECKER_GET();
	smtp_checker->db_retry = CHECKER_VALUE_INT(strvec) * TIMER_HZ;
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

	install_keyword("warmup", &warmup_handler);
	install_keyword("delay_before_retry", &smtp_db_retry_handler);
	install_keyword("retry", &smtp_retry_handler);
	install_connect_keywords();

	/*
	 * The host list feature is deprecated. It makes config fussy by
	 * adding another nesting level and is excessive since it is possible
	 * to attach multiple checkers to a RS.
	 * So these keywords below are kept for compatibility with users'
	 * existing configs.
	 */
	install_keyword("host", &smtp_host_handler);
	install_sublevel();
	install_connect_keywords();
	install_sublevel_end();

	install_sublevel_end_handler(&smtp_check_end_handler);
	install_sublevel_end();
}

/*
 * Final handler. Determines if we need a retry or not. 
 * Also has to make a decision if we need to bring the resulting
 * service down in case of error.
 */
int
smtp_final(thread_t *thread, int error, const char *format, ...)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	char error_buff[512];
	char smtp_buff[542];
	va_list varg_list;

	/* Error or no error we should always have to close the socket */
	close(thread->u.fd);

	/* If we're here, an attempt HAS been made already for the current host */
	smtp_checker->attempts++;
	
	if (error) {
		/* Always syslog the error when the real server is up */
                if (svr_checker_up(checker->id, checker->rs)) {
			if (format != NULL) {
				/* prepend format with the "SMTP_CHECK " string */
				error_buff[0] = '\0';
				strncat(error_buff, "SMTP_CHECK ", sizeof(error_buff) - 1);
				strncat(error_buff, format, sizeof(error_buff) - 11 - 1);

				va_start(varg_list, format);
				vlog_message(LOG_INFO, error_buff, varg_list);
				va_end(varg_list);
			} else {
				log_message(LOG_INFO, "SMTP_CHECK Unknown error");
			}
		}

		/*
		 * If we still have retries left, try this host again by
		 * scheduling the main thread to check it again after the
		 * configured backoff delay. Otherwise down the RS.
		 */
		if (smtp_checker->attempts < smtp_checker->retry) {
			thread_add_timer(thread->master, smtp_connect_thread, checker,
					 smtp_checker->db_retry);
			return 0;
		}

		/*
		 * No more retries, pull the real server from the virtual server.
		 * Only smtp_alert if it wasn't previously down. It should
		 * be noted that smtp_alert makes a copy of the string arguments, so
		 * we don't have to keep them statically allocated.
		 */
                if (svr_checker_up(checker->id, checker->rs)) {
			if (format != NULL) {
				snprintf(smtp_buff, 542, "=> CHECK failed on service : %s <=",
					 error_buff + 11);
			} else {
				snprintf(smtp_buff, 542, "=> CHECK failed on service <=");
			}

			smtp_buff[542 - 1] = '\0';
			smtp_alert(checker->rs, NULL, NULL, "DOWN", smtp_buff);
			update_svr_checker_state(DOWN, checker->id, checker->vs, checker->rs);
		}

		/* Reset everything back to the first host in the list */
		smtp_checker->attempts = 0;
		smtp_checker->host_ctr = 0;

		/* Reschedule the main thread using the configured delay loop */;
		thread_add_timer(thread->master, smtp_connect_thread, checker, checker->vs->delay_loop);

		return 0;
	}	

	/*
	 * Ok this host was successful, increment to the next host in the list
	 * and reset the attempts counter. We'll then reschedule the main thread again.
	 * If host_ctr exceeds the number of hosts in the list, http_main_thread will
	 * take note and bring up the real server as well as inject the delay_loop.
	 */
	smtp_checker->attempts = 0;
	smtp_checker->host_ctr++;

	thread_add_timer(thread->master, smtp_connect_thread, checker, 1);
	return 0;
}

/* 
 * Zeros out the rx/tx buffer
 */
void
smtp_clear_buff(thread_t *thread)
{
        checker_t *checker = THREAD_ARG(thread);
        smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	memset(smtp_checker->buff, 0, SMTP_BUFF_MAX);
	smtp_checker->buff_ctr = 0;
}

/*
 * One thing to note here is we do a very cheap check for a newline.
 * We could receive two lines (with two newline characters) in a
 * single packet, but we don't care. We are only looking at the
 * SMTP response codes at the beginning anyway.
 */
int
smtp_get_line_cb(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;
	int f, r, x;

        /* Handle read timeout */
        if (thread->type == THREAD_READ_TIMEOUT) {
		smtp_final(thread, 1, "Read timeout from server %s"
				    , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* wrap the buffer, if full, by clearing it */
	if (SMTP_BUFF_MAX - smtp_checker->buff_ctr <= 0) {
		log_message(LOG_INFO, "SMTP_CHECK Buffer overflow reading from server %s. "
				      "Increase SMTP_BUFF_MAX in smtp_check.h"
				    , FMT_SMTP_RS(smtp_host));
		smtp_clear_buff(thread);
	}

	/* Set descriptor non blocking */
	f = fcntl(thread->u.fd, F_GETFL, 0);
	fcntl(thread->u.fd, F_SETFL, f | O_NONBLOCK);

	/* read the data */
	r = read(thread->u.fd, smtp_checker->buff + smtp_checker->buff_ctr,
		 SMTP_BUFF_MAX - smtp_checker->buff_ctr);

	if (r == -1 && (errno == EAGAIN || errno == EINTR)) {
		thread_add_read(thread->master, smtp_get_line_cb, checker,
				thread->u.fd, smtp_host->connection_to);
        	fcntl(thread->u.fd, F_SETFL, f);
		return 0;
	} else if (r > 0)
		smtp_checker->buff_ctr += r;

        /* restore descriptor flags */
        fcntl(thread->u.fd, F_SETFL, f);

	/* check if we have a newline, if so, callback */
	for (x = 0; x < SMTP_BUFF_MAX; x++) {
		if (smtp_checker->buff[x] == '\n') {
			smtp_checker->buff[SMTP_BUFF_MAX - 1] = '\0';

			DBG("SMTP_CHECK %s < %s"
			    , FMT_SMTP_RS(smtp_host)
			    , smtp_checker->buff);

			(smtp_checker->buff_cb)(thread);

			return 0;
		}
	}

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (r <= 0) {
		smtp_final(thread, 1, "Read failure from server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/*
	 * Last case, we haven't read enough data yet
	 * to pull a newline. Schedule ourselves for
	 * another round.
	 */
	thread_add_read(thread->master, smtp_get_line_cb, checker,
			thread->u.fd, smtp_host->connection_to);
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
smtp_get_line(thread_t *thread, int (*callback) (thread_t *))
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;

	/* clear the buffer */
	smtp_clear_buff(thread);

	/* set the callback */
	smtp_checker->buff_cb = callback;

	/* schedule the I/O with our helper function  */
	thread_add_read(thread->master, smtp_get_line_cb, checker,
		thread->u.fd, smtp_host->connection_to);
	return;
}

/*
 * The scheduler function that puts the data out on the wire.
 * All our data will fit into one packet, so we only check if
 * the current write would block or not. If it wants to block,
 * we'll return to the scheduler and try again later. 
 */
int
smtp_put_line_cb(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;
	int f, w;


        /* Handle read timeout */
        if (thread->type == THREAD_WRITE_TIMEOUT) {
		smtp_final(thread, 1, "Write timeout to server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* Set descriptor non blocking */
        f = fcntl(thread->u.fd, F_GETFL, 0);
        fcntl(thread->u.fd, F_SETFL, f | O_NONBLOCK);

        /* write the data */
        w = write(thread->u.fd, smtp_checker->buff, smtp_checker->buff_ctr);

	if (w == -1 && (errno == EAGAIN || errno == EINTR)) {
		thread_add_write(thread->master, smtp_put_line_cb, checker,
				 thread->u.fd, smtp_host->connection_to);
        	fcntl(thread->u.fd, F_SETFL, f);
		return 0;
	}

        /* restore descriptor flags */
        fcntl(thread->u.fd, F_SETFL, f);

	DBG("SMTP_CHECK %s > %s"
	    , FMT_SMTP_RS(smtp_host)
	    , smtp_checker->buff);

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (w <= 0) {
		smtp_final(thread, 1, "Write failure to server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* Execute the callback */
	(smtp_checker->buff_cb)(thread);
	return 0;
}

/* 
 * This is the same as smtp_get_line() except that we're sending a
 * line of data instead of receiving one.
 */
void
smtp_put_line(thread_t *thread, int (*callback) (thread_t *))
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;

	smtp_checker->buff[SMTP_BUFF_MAX - 1] = '\0';
	smtp_checker->buff_ctr = strlen(smtp_checker->buff);

	/* set the callback */
	smtp_checker->buff_cb = callback;

	/* schedule the I/O with our helper function  */
	thread_add_write(thread->master, smtp_put_line_cb, checker,
			 thread->u.fd, smtp_host->connection_to);
	return;
}

/*
 * Ok, our goal here is to snag the status code out of the
 * buffer and return it as an integer. If it's not legible,
 * return -1.
 */
int
smtp_get_status(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	char *buff = smtp_checker->buff;

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
 * smtp_checker->state. Upon first calling, smtp_checker->state 
 * should be set to SMTP_START.
 */
int
smtp_engine_thread(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;

	switch (smtp_checker->state) {

		/* First step, schedule to receive the greeting banner */
		case SMTP_START:
			/*
			 * Ok, if smtp_get_line schedules us back, we will
			 * have data to analyze. Otherwise, smtp_get_line
			 * will defer directly to smtp_final.
			 */
			smtp_checker->state = SMTP_HAVE_BANNER;
			smtp_get_line(thread, smtp_engine_thread);
			return 0;
			break;

		/* Second step, analyze banner, send HELO */
		case SMTP_HAVE_BANNER:
			/* Check for "220 some.mailserver.com" in the greeting */
			if (smtp_get_status(thread) != 220) {
				smtp_final(thread, 1, "Bad greeting banner from server %s"
						     , FMT_SMTP_RS(smtp_host));

				return 0;
			}

			/*
			 * Schedule to send the HELO, smtp_put_line will
			 * defer directly to smtp_final on error.
			 */
			smtp_checker->state = SMTP_SENT_HELO;
			snprintf(smtp_checker->buff, SMTP_BUFF_MAX, "HELO %s\r\n",
				 smtp_checker->helo_name);
			smtp_put_line(thread, smtp_engine_thread);
			return 0;
			break;

		/* Third step, schedule to read the HELO response */
		case SMTP_SENT_HELO:
			smtp_checker->state = SMTP_RECV_HELO;
			smtp_get_line(thread, smtp_engine_thread);
			return 0;
			break;

		/* Fourth step, analyze HELO return, send QUIT */
		case SMTP_RECV_HELO:
			/* Check for "250 Please to meet you..." */
			if (smtp_get_status(thread) != 250) {
				smtp_final(thread, 1, "Bad HELO response from server %s"
						     , FMT_SMTP_RS(smtp_host));

				return 0;
			}

			smtp_checker->state = SMTP_SENT_QUIT;
			snprintf(smtp_checker->buff, SMTP_BUFF_MAX, "QUIT\r\n");
			smtp_put_line(thread, smtp_engine_thread);
			return 0;
			break;

		/* Fifth step, schedule to receive QUIT confirmation */
		case SMTP_SENT_QUIT:
			smtp_checker->state = SMTP_RECV_QUIT;
			smtp_get_line(thread, smtp_engine_thread);
			return 0;
			break;

		/* Sixth step, wrap up success to smtp_final */
		case SMTP_RECV_QUIT:
			smtp_final(thread, 0, NULL);
			return 0;
			break;
	}

	/* We shouldn't be here */
	smtp_final(thread, 1, "Unknown smtp engine state encountered");
	return 0;
}
		
/* 
 * Second step in the process. Here we'll see if the connection
 * to the host we're checking was successful or not.
 */
int
smtp_check_thread(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host = smtp_checker->host_ptr;
	int status;

	status = tcp_socket_state(thread->u.fd, thread, smtp_check_thread);
	switch (status) {
		case connect_error:
			smtp_final(thread, 1, "Error connecting to server %s"
					     , FMT_SMTP_RS(smtp_host));
			return 0;
			break;

		case connect_timeout:
			smtp_final(thread, 1, "Connection timeout to server %s"
					     , FMT_SMTP_RS(smtp_host));
			return 0;
			break;

		case connect_success:
			DBG("SMTP_CHECK Remote SMTP server %s connected"
			    , FMT_SMTP_RS(smtp_host));

			/* Enter the engine at SMTP_START */
			smtp_checker->state = SMTP_START;
			smtp_engine_thread(thread);
			return 0;
			break;
	}

	/* we shouldn't be here */		
	smtp_final(thread, 1, "Unknown connection error to server %s"
			     , FMT_SMTP_RS(smtp_host));
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
smtp_connect_thread(thread_t *thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	smtp_host_t *smtp_host;
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
	 * that "checker" always points to the current checker structure,
	 * "smtp_checker" points to the current smtp_checker structure, 
	 * and "smtp_host" points to the current smtp_host structure.
	 */

	/*
	 * If we're disabled, we'll do nothing at all.
	 * But we still have to register ourselves again so
	 * we don't fall of the face of the earth.
	 */
	if (!CHECKER_ENABLED(checker)) {
		thread_add_timer(thread->master, smtp_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	/*
	 * Set the internal host pointer to the host that well be 
	 * working on. If it's NULL, we've successfully tested all hosts.
	 * We'll bring the service up (if it's not already), reset the host list,
	 * and insert the delay loop. When we get scheduled again the host list
	 * will be reset and we will continue on checking them one by one.
	 */
	if ((smtp_checker->host_ptr = list_element(smtp_checker->host, smtp_checker->host_ctr)) == NULL) {
		if (!svr_checker_up(checker->id, checker->rs)) {
			log_message(LOG_INFO, "Remote SMTP server %s succeed on service."
					    , FMT_CHK(checker));

			smtp_alert(checker->rs, NULL, NULL, "UP",
				   "=> CHECK succeed on service <=");
			update_svr_checker_state(UP, checker->id, checker->vs, checker->rs);
		}

		smtp_checker->attempts = 0;
		smtp_checker->host_ctr = 0;
		smtp_checker->host_ptr = list_element(smtp_checker->host, 0);

		thread_add_timer(thread->master, smtp_connect_thread, checker, checker->vs->delay_loop);
		return 0;
	}

	smtp_host = smtp_checker->host_ptr;

	/* Create the socket, failling here should be an oddity */
	if ((sd = socket(smtp_host->dst.ss_family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "SMTP_CHECK connection failed to create socket. Rescheduling.");
		thread_add_timer(thread->master, smtp_connect_thread, checker,
				 checker->vs->delay_loop);
		return 0;
	}

	status = tcp_bind_connect(sd, smtp_host);

	/* handle tcp connection status & register callback the next setp in the process */
	if(tcp_connection_state(sd, status, thread, smtp_check_thread, smtp_host->connection_to)) {
		close(sd);
		log_message(LOG_INFO, "SMTP_CHECK socket bind failed. Rescheduling.");
		thread_add_timer(thread->master, smtp_connect_thread, checker,
			checker->vs->delay_loop);
	}
 
	return 0;
}
