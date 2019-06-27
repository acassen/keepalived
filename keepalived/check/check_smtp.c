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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>

#include "check_smtp.h"
#include "logger.h"
#include "ipwrapper.h"
#include "utils.h"
#include "parser.h"
#if !HAVE_DECL_SOCK_CLOEXEC
#include "old_socket.h"
#endif
#include "layer4.h"
#include "smtp.h"
#ifdef THREAD_DUMP
#include "scheduler.h"
#endif

/* Specifying host blocks within the SMTP checker is deprecated, but currently
 * still supported. All code to support it is in WITH_HOST_ENTRIES conditional
 * compilation, so it is easy to remove all the code eventually. */
#define WITH_HOST_ENTRIES

#ifdef WITH_HOST_ENTRIES
static list host_list;
static conn_opts_t *sav_co;	/* Saved conn_opts while host{} block processed */
#endif
//*** default_co is pointless
static conn_opts_t* default_co;	/* Default conn_opts for SMTP_CHECK */

static int smtp_connect_thread(thread_ref_t);
static int smtp_start_check_thread(thread_ref_t);
static int smtp_engine_thread(thread_ref_t);

/* Used as a callback from the checker api, queue_checker(),
 * to free up a checker entry and all its associated data.
 */
static void
free_smtp_check(checker_t *checker)
{
	smtp_checker_t *smtp_checker = checker->data;

	FREE_PTR(checker->co);
	FREE_CONST(smtp_checker->helo_name);
	FREE(smtp_checker);
	FREE(checker);
}

/*
 * Callback for whenever we've been requested to dump our
 * configuration.
 */
static void
dump_smtp_check(FILE *fp, const checker_t *checker)
{
	const smtp_checker_t *smtp_checker = checker->data;

	conf_write(fp, "   Keepalive method = SMTP_CHECK");
	conf_write(fp, "   helo = %s", smtp_checker->helo_name);
	dump_checker_opts(fp, checker);
}

static bool
smtp_check_compare(const checker_t *old_c, const checker_t *new_c)
{
	const smtp_checker_t *old = old_c->data;
	const smtp_checker_t *new = new_c->data;

	if (strcmp(old->helo_name, new->helo_name) != 0)
		return false;
	if (!compare_conn_opts(old_c->co, new_c->co))
		return false;

	return true;
}

/*
 * Callback for whenever an SMTP_CHECK keyword is encountered
 * in the config file.
 */
static void
smtp_check_handler(__attribute__((unused)) const vector_t *strvec)
{
	smtp_checker_t *smtp_checker = (smtp_checker_t *)MALLOC(sizeof(smtp_checker_t));
	conn_opts_t *co;

#ifdef WITH_HOST_ENTRIES
	/* We keep a copy of the default settings for completing incomplete settings */
	host_list = alloc_list(free_list_element_simple, NULL);
#endif

	co = MALLOC(sizeof(conn_opts_t));
	co->connection_to = UINT_MAX;

	/* Have the checker queue code put our checker into the checkers_queue list. */
	queue_checker(free_smtp_check, dump_smtp_check, smtp_start_check_thread,
		      smtp_check_compare, smtp_checker, co, true);
}

static void
smtp_check_end_handler(void)
{
	checker_t *checker = CHECKER_GET_CURRENT();
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	checker_t *new_checker;
	smtp_checker_t *new_smtp_checker;
	element e, n;
	conn_opts_t *co;

	if (!smtp_checker->helo_name)
		smtp_checker->helo_name = STRDUP(SMTP_DEFAULT_HELO);

	/* If any connection component has been configured, we want to add it to the host list */
	if (checker->co->dst.ss_family != AF_UNSPEC ||
	    ((struct sockaddr_in *)&checker->co->dst)->sin_port ||
	    checker->co->bindto.ss_family != AF_UNSPEC ||
	    ((struct sockaddr_in *)&checker->co->bindto)->sin_port ||
	    checker->co->bind_if[0] ||
#ifdef _WITH_SO_MARK_
	    checker->co->fwmark ||
#endif
	    checker->co->connection_to) {
		/* Set any necessary defaults */
		if (checker->co->dst.ss_family == AF_UNSPEC) {
			if (((struct sockaddr_in *)&checker->co->dst)->sin_port) {
				uint16_t saved_port = ((struct sockaddr_in *)&checker->co->dst)->sin_port;
				checker->co->dst = default_co->dst;
				checker_set_dst_port(&checker->co->dst, saved_port);
			}
			else
				checker->co->dst = default_co->dst;
		}

		if (!check_conn_opts(checker->co)) {
			dequeue_new_checker();
			return;
		}
	}
	else
		FREE(checker->co);

	/* If there was no host{} section, add a single host to the list */
	if (!checker->co
#ifdef WITH_HOST_ENTRIES
			 && LIST_ISEMPTY(host_list)
#endif
						   ) {
		checker->co = default_co;
		default_co = NULL;
	} else {
#ifdef WITH_HOST_ENTRIES
		if (!checker->co) {
			checker->co = LIST_HEAD_DATA(host_list);
			list_extract(host_list, LIST_HEAD(host_list));
		}
#endif

		FREE(default_co);
	}

	/* Set the conection timeout if not set */
	virtual_server_t *vs = LIST_TAIL_DATA(check_data->vs);
	real_server_t *rs = LIST_TAIL_DATA(vs->rs);
	unsigned conn_to = rs->connection_to;
	if (conn_to == UINT_MAX)
		conn_to = vs->connection_to;

	if (checker->co->connection_to == UINT_MAX)
		checker->co->connection_to = conn_to;

#ifdef WITH_HOST_ENTRIES
	/* Create a new checker for each host on the host list */
	LIST_FOREACH_NEXT(host_list, co, e, n) {
		new_smtp_checker = MALLOC(sizeof(smtp_checker_t));
		*new_smtp_checker = *smtp_checker;

		if (co->connection_to == UINT_MAX)
			co->connection_to = conn_to;

		new_smtp_checker->helo_name = STRDUP(smtp_checker->helo_name);

		queue_checker(free_smtp_check, dump_smtp_check, smtp_start_check_thread,
			      smtp_check_compare, new_smtp_checker, NULL, true);

		new_checker = CHECKER_GET_CURRENT();
		*new_checker = *checker;
		new_checker->co = co;
		new_checker->data = new_smtp_checker;

		list_extract(host_list, e);
	}

	/* The list is now empty */
	free_list(&host_list);
#endif
}

#ifdef WITH_HOST_ENTRIES
/* Callback for "host" keyword */
static void
smtp_host_handler(__attribute__((unused)) const vector_t *strvec)
{
	checker_t *checker = CHECKER_GET_CURRENT();

	/* save the main conn_opts_t and set a new default for the host */
	sav_co = checker->co;
	checker->co = (conn_opts_t*)MALLOC(sizeof(conn_opts_t));
	*checker->co = *sav_co;

	log_message(LOG_INFO, "The SMTP_CHECK host block is deprecated. Please define additional checkers.");
}

static void
smtp_host_end_handler(void)
{
	checker_t *checker = CHECKER_GET_CURRENT();

	if (!check_conn_opts(checker->co))
		FREE(checker->co);
	else
		list_add(host_list, checker->co);

	checker->co = sav_co;
}
#endif

/* "helo_name" keyword */
static void
smtp_helo_name_handler(const vector_t *strvec)
{
	smtp_checker_t *smtp_checker = CHECKER_GET();

	if (vector_size(strvec) < 2) {
		report_config_error(CONFIG_GENERAL_ERROR, "SMTP_CHECK helo name missing");
		return;
	}

	if (smtp_checker->helo_name)
		FREE_CONST(smtp_checker->helo_name);

	smtp_checker->helo_name = set_value(strvec);
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

	install_checker_common_keywords(true);

	/*
	 * The host list feature is deprecated. It makes config fussy by
	 * adding another nesting level and is excessive since it is possible
	 * to attach multiple checkers to a RS.
	 * So these keywords below are kept for compatibility with users'
	 * existing configs.
	 */
	install_keyword("host", &smtp_host_handler);
	install_sublevel();
	install_checker_common_keywords(true);
	install_sublevel_end_handler(smtp_host_end_handler);
	install_sublevel_end();

	install_sublevel_end_handler(&smtp_check_end_handler);
	install_sublevel_end();
}

/*
 * Final handler. Determines if we need a retry or not.
 * Also has to make a decision if we need to bring the resulting
 * service down in case of error.
 */
static int __attribute__ ((format (printf, 2, 3)))
smtp_final(thread_ref_t thread, const char *format, ...)
{
	checker_t *checker = THREAD_ARG(thread);
	char error_buff[512];
	char smtp_buff[542];
	va_list varg_list;
	bool checker_was_up;
	bool rs_was_alive;

	/* Error or no error we should always have to close the socket */
	if (thread->type != THREAD_TIMER)
		thread_close_fd(thread);

	if (format) {
		/* Always syslog the error when the real server is up */
		if ((checker->is_up || !checker->has_run) &&
		    (global_data->checker_log_all_failures ||
		     checker->log_all_failures ||
		     checker->retry_it >= checker->retry)) {
			/* prepend format with the "SMTP_CHECK " string */
			strcpy_safe(error_buff, "SMTP_CHECK ");
			strncat(error_buff, format, sizeof(error_buff) - 11 - 1);

			va_start(varg_list, format);
			vlog_message(LOG_INFO, error_buff, varg_list);
			va_end(varg_list);
		}

		/*
		 * If we still have retries left, try this host again by
		 * scheduling the main thread to check it again after the
		 * configured backoff delay. Otherwise down the RS.
		 */
		if (++checker->retry_it <= checker->retry) {
			thread_add_timer(thread->master, smtp_connect_thread, checker,
					 checker->delay_before_retry);
			return 0;
		}

		/*
		 * No more retries, pull the real server from the virtual server.
		 * Only smtp_alert if it wasn't previously down. It should
		 * be noted that smtp_alert makes a copy of the string arguments, so
		 * we don't have to keep them statically allocated.
		 */
		if (checker->is_up || !checker->has_run) {
			checker_was_up = checker->is_up;
			rs_was_alive = checker->rs->alive;
			update_svr_checker_state(DOWN, checker);
			if (checker->rs->smtp_alert && checker_was_up &&
			    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails)) {
				if (format != NULL) {
					snprintf(error_buff, sizeof(error_buff), "=> CHECK failed on service : %s <=", format);
					va_start(varg_list, format);
					vsnprintf(smtp_buff, sizeof(smtp_buff), error_buff, varg_list);
					va_end(varg_list);
				} else
					strncpy(smtp_buff, "=> CHECK failed on service <=", sizeof(smtp_buff));

				smtp_buff[sizeof(smtp_buff) - 1] = '\0';
				smtp_alert(SMTP_MSG_RS, checker, NULL, smtp_buff);
			}
		}

		/* Reschedule the main thread using the configured delay loop */
		thread_add_timer(thread->master, smtp_start_check_thread, checker, checker->delay_loop);

		return 0;
	}

	/*
	 * Ok this host was successful, increment to the next host in the list
	 * and reset the retry_it counter. We'll then reschedule the main thread again.
	 * If host_ptr exceeds the end of the list, smtp_connect_main_thread will
	 * take note and bring up the real server as well as inject the delay_loop.
	 */
	checker->retry_it = 0;

	/*
	 * Set the internal host pointer to the host that we'll be
	 * working on. If it's NULL, we've successfully tested all hosts.
	 * We'll bring the service up (if it's not already), reset the host list,
	 * and insert the delay loop. When we get scheduled again the host list
	 * will be reset and we will continue on checking them one by one.
	 */
	if (!checker->is_up || !checker->has_run) {
		log_message(LOG_INFO, "Remote SMTP server %s succeed on service."
				    , FMT_CHK(checker));

		checker_was_up = checker->is_up;
		rs_was_alive = checker->rs->alive;
		update_svr_checker_state(UP, checker);
		if (checker->rs->smtp_alert && !checker_was_up &&
		    (rs_was_alive != checker->rs->alive || !global_data->no_checker_emails))
			smtp_alert(SMTP_MSG_RS, checker, NULL,
				   "=> CHECK succeed on service <=");
	}

	checker->has_run = true;

	thread_add_timer(thread->master, smtp_start_check_thread, checker, checker->delay_loop);

	return 0;
}

/*
 * One thing to note here is we do a very cheap check for a newline.
 * We could receive two lines (with two newline characters) in a
 * single packet, but we don't care. We are only looking at the
 * SMTP response codes at the beginning anyway.
 */
static int
smtp_get_line_cb(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	conn_opts_t *smtp_host = checker->co;
	ssize_t r;
	char *nl;

	/* Handle read timeout */
	if (thread->type == THREAD_READ_TIMEOUT) {
		smtp_final(thread, "Read timeout from server %s"
				    , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* wrap the buffer, if full, by clearing it */
	if (smtp_checker->buff_ctr >= SMTP_BUFF_MAX - 1) {
		log_message(LOG_INFO, "SMTP_CHECK Buffer overflow reading from server %s. "
				      "Increase SMTP_BUFF_MAX in check_smtp.h"
				    , FMT_SMTP_RS(smtp_host));
		smtp_checker->buff_ctr = 0;
	}

	/* read the data */
	r = read(thread->u.f.fd, smtp_checker->buff + smtp_checker->buff_ctr,
		 SMTP_BUFF_MAX - smtp_checker->buff_ctr - 1);

	if (r == -1 && (check_EAGAIN(errno) || check_EINTR(errno))) {
		thread_add_read(thread->master, smtp_get_line_cb, checker,
				thread->u.f.fd, smtp_host->connection_to, true);
		return 0;
	}

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (r <= 0) {
		smtp_final(thread, "Read failure from server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	smtp_checker->buff_ctr += (size_t)r;
	smtp_checker->buff[smtp_checker->buff_ctr] = '\0';

	/* check if we have a newline, if so, callback */
	if ((nl = strchr(smtp_checker->buff, '\n'))) {
		*nl = '\0';

		DBG("SMTP_CHECK %s < %s"
		    , FMT_SMTP_RS(smtp_host)
		    , smtp_checker->buff);

		smtp_engine_thread(thread);

		return 0;
	}

	/*
	 * Last case, we haven't read enough data yet
	 * to pull a newline. Schedule ourselves for
	 * another round.
	 */
	thread_add_read(thread->master, smtp_get_line_cb, checker,
			thread->u.f.fd, smtp_host->connection_to, true);
	return 0;
}

/*
 * Ok a caller has asked us to asyncronously schedule a single line
 * to be received from the server. They have also passed us a call back
 * function that we'll call once we have the newline. If something bad
 * happens, the caller assumes we'll pass the error off to smtp_final(),
 * which will either down the real server or schedule a retry. The
 * function smtp_get_line_cb is what does the dirty work since the
 * scheduler can only accept a single *thread argument.
 */
static void
smtp_get_line(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	conn_opts_t *smtp_host = checker->co;

	/* clear the buffer */
	smtp_checker->buff_ctr = 0;

	/* schedule the I/O with our helper function  */
	thread_add_read(thread->master, smtp_get_line_cb, checker,
		thread->u.f.fd, smtp_host->connection_to, true);
	thread_del_write(thread);
	return;
}

/*
 * The scheduler function that puts the data out on the wire.
 * All our data will fit into one packet, so we only check if
 * the current write would block or not. If it wants to block,
 * we'll return to the scheduler and try again later.
 */
static int
smtp_put_line_cb(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	conn_opts_t *smtp_host = checker->co;
	ssize_t w;

	/* Handle read timeout */
	if (thread->type == THREAD_WRITE_TIMEOUT) {
		smtp_final(thread, "Write timeout to server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* write the data */
	w = write(thread->u.f.fd, smtp_checker->buff, smtp_checker->buff_ctr);

	if (w == -1 && (check_EAGAIN(errno) || check_EINTR(errno))) {
		thread_add_write(thread->master, smtp_put_line_cb, checker,
				 thread->u.f.fd, smtp_host->connection_to, true);
		return 0;
	}

	DBG("SMTP_CHECK %s > %s"
	    , FMT_SMTP_RS(smtp_host)
	    , smtp_checker->buff);

	/*
	 * If the connection was closed or there was
	 * some sort of error, notify smtp_final()
	 */
	if (w <= 0) {
		smtp_final(thread, "Write failure to server %s"
				     , FMT_SMTP_RS(smtp_host));
		return 0;
	}

	/* Execute the callback */
	smtp_engine_thread(thread);
	return 0;
}

/*
 * This is the same as smtp_get_line() except that we're sending a
 * line of data instead of receiving one.
 */
static void
smtp_put_line(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);

	smtp_checker->buff_ctr = strlen(smtp_checker->buff);

	/* schedule the I/O with our helper function  */
	smtp_put_line_cb(thread);

	return;
}

/*
 * Ok, our goal here is to snag the status code out of the
 * buffer and return it as an integer. If it's not legible,
 * return -1.
 */
static int
smtp_get_status(smtp_checker_t *smtp_checker)
{
	char *buff = smtp_checker->buff;
	int status;
	char *endptr;

	status = strtoul(buff, &endptr, 10);
	if (endptr - buff != 3 ||
	    (*endptr && *endptr != ' '))
		return -1;

	return status;
}

/*
 * We have a connected socket and are ready to begin
 * the conversation. This function schedules itself to
 * be called via callbacks and tracking state in
 * smtp_checker->state. Upon first calling, smtp_checker->state
 * should be set to SMTP_START.
 */
static int
smtp_engine_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	conn_opts_t *smtp_host = checker->co;

	switch (smtp_checker->state) {

		/* First step, schedule to receive the greeting banner */
		case SMTP_START:
			/*
			 * Ok, if smtp_get_line schedules us back, we will
			 * have data to analyze. Otherwise, smtp_get_line
			 * will defer directly to smtp_final.
			 */
			smtp_checker->state = SMTP_HAVE_BANNER;
			smtp_get_line(thread);
			break;

		/* Second step, analyze banner, send HELO */
		case SMTP_HAVE_BANNER:
			/* Check for "220 some.mailserver.com" in the greeting */
			if (smtp_get_status(smtp_checker) != 220) {
				smtp_final(thread, "Bad greeting banner from server %s"
						     , FMT_SMTP_RS(smtp_host));
			} else {
				/*
				 * Schedule to send the HELO, smtp_put_line will
				 * defer directly to smtp_final on error.
				 */
				smtp_checker->state = SMTP_SENT_HELO;
				snprintf(smtp_checker->buff, SMTP_BUFF_MAX, "HELO %s\r\n",
					 smtp_checker->helo_name);
				smtp_put_line(thread);
			}
			break;

		/* Third step, schedule to read the HELO response */
		case SMTP_SENT_HELO:
			smtp_checker->state = SMTP_RECV_HELO;
			smtp_get_line(thread);
			break;

		/* Fourth step, analyze HELO return, send QUIT */
		case SMTP_RECV_HELO:
			/* Check for "250 Please to meet you..." */
			if (smtp_get_status(smtp_checker) != 250) {
				smtp_final(thread, "Bad HELO response from server %s"
						     , FMT_SMTP_RS(smtp_host));
			} else {
				smtp_checker->state = SMTP_SENT_QUIT;
				snprintf(smtp_checker->buff, SMTP_BUFF_MAX, "QUIT\r\n");
				smtp_put_line(thread);
			}
			break;

		/* Fifth step, schedule to receive QUIT confirmation */
		case SMTP_SENT_QUIT:
			smtp_checker->state = SMTP_RECV_QUIT;
			smtp_get_line(thread);
			break;

		/* Sixth step, wrap up success to smtp_final */
		case SMTP_RECV_QUIT:
			smtp_final(thread, NULL);
			break;

		default:
			/* We shouldn't be here */
			smtp_final(thread, "Unknown smtp engine state encountered");
			break;
	}

	return 0;
}

/*
 * Second step in the process. Here we'll see if the connection
 * to the host we're checking was successful or not.
 */
static int
smtp_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	smtp_checker_t *smtp_checker = CHECKER_ARG(checker);
	conn_opts_t *smtp_host = checker->co;
	int status;

	status = tcp_socket_state(thread, smtp_check_thread);
	switch (status) {
		case connect_error:
			smtp_final(thread, "Error connecting to server %s"
					     , FMT_SMTP_RS(smtp_host));
			break;

		case connect_timeout:
			smtp_final(thread, "Connection timeout to server %s"
					     , FMT_SMTP_RS(smtp_host));
			break;

		case connect_fail:
			smtp_final(thread, "Could not connect to server %s"
					     , FMT_SMTP_RS(smtp_host));
			break;

		case connect_success:
			DBG("SMTP_CHECK Remote SMTP server %s connected"
			    , FMT_SMTP_RS(smtp_host));

			/* Enter the engine at SMTP_START */
			smtp_checker->state = SMTP_START;
			smtp_engine_thread(thread);
			break;

		default:
			/* we shouldn't be here */
			smtp_final(thread, "Unknown connection error to server %s"
					     , FMT_SMTP_RS(smtp_host));
			break;
	}

	return 0;
}

/*
 * This is the main thread, where all the action starts.
 * When the check daemon comes up, it goes down the checkers_queue
 * and launches a thread for each checker that got registered.
 * This is the callback/event function for that initial thread.
 *
 * It should be noted that we ARE responsible for scheduling
 * ourselves to run again. It doesn't have to be right here,
 * but eventually has to happen.
 */
static int
smtp_connect_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);
	conn_opts_t *smtp_host;
	enum connect_result status;
	int sd;

	/* Let's review our data structures.
	 *
	 * Thread is the structure used by the sceduler
	 * for scheduling many types of events. thread->arg in this
	 * case points to a checker structure. The checker
	 * structure holds data about the vs and rs configurations
	 * as well as the delay loop, etc. Each real server
	 * defined in the keepalived.conf will more than likely have
	 * a checker structure assigned to it. Each checker structure
	 * has a data element that is meant to hold per checker
	 * configurations. So thread->arg(checker)->data points to
	 * a smtp_checker structure. In the smtp_checker structure
	 * we hold global configuration data for the smtp check.
	 *
	 * So this whole thing looks like this:
	 * thread->arg(checker)->data(smtp_checker)->host(smtp_host)
	 *
	 * To make life simple, we'll break the structures out so
	 * that "checker" always points to the current checker structure,
	 * "smtp_checker" points to the current smtp_checker structure.
	 */

	/*
	 * If we're disabled, we'll do nothing at all.
	 * But we still have to register ourselves again so
	 * we don't fall of the face of the earth.
	 */
	if (!checker->enabled) {
		thread_add_timer(thread->master, smtp_start_check_thread, checker,
				 checker->delay_loop);
		return 0;
	}

	smtp_host = checker->co;

	/* Create the socket, failing here should be an oddity */
	if ((sd = socket(smtp_host->dst.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_message(LOG_INFO, "SMTP_CHECK connection failed to create socket. Rescheduling.");
		thread_add_timer(thread->master, smtp_start_check_thread, checker,
				 checker->delay_loop);
		return 0;
	}

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(sd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on smtp socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(sd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on smtp socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_bind_connect(sd, smtp_host);

	/* handle tcp connection status & register callback the next step in the process */
	if(tcp_connection_state(sd, status, thread, smtp_check_thread, smtp_host->connection_to)) {
                if (status == connect_fail) {
                        close(sd);
                        smtp_final(thread, "Network unreachable for server %s - real server %s",
                                           inet_sockaddrtos(&checker->co->dst),
                                           inet_sockaddrtopair(&checker->rs->addr));
                } else {
			close(sd);
			log_message(LOG_INFO, "SMTP_CHECK socket bind failed. Rescheduling.");
			thread_add_timer(thread->master, smtp_start_check_thread, checker,
				checker->delay_loop);
		}
	}

	return 0;
}

static int
smtp_start_check_thread(thread_ref_t thread)
{
	checker_t *checker = THREAD_ARG(thread);

	checker->retry_it = 0;

	smtp_connect_thread(thread);

	return 0;
}

#ifdef THREAD_DUMP
void
register_check_smtp_addresses(void)
{
	register_thread_address("smtp_start_check_thread", smtp_start_check_thread);
	register_thread_address("smtp_check_thread", smtp_check_thread);
	register_thread_address("smtp_connect_thread", smtp_connect_thread);
	register_thread_address("smtp_get_line_cb", smtp_get_line_cb);
	register_thread_address("smtp_put_line_cb", smtp_put_line_cb);
}
#endif
