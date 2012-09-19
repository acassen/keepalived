/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        buffer.c include file.
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

#ifndef _BUFFER_H
#define _BUFFER_H

/* buffer definition */
typedef struct _buffer_data {
	struct _buffer_data	*next;

	size_t			cp;	/* Location to add new data. */
	size_t			sp;	/* Pointer to data not yet flushed. */
	unsigned char		data[];	/* Actual data stream (variable length).
					 * real dimension is buffer->size.
					 */
} buffer_data_t;

typedef struct _buffer {
	buffer_data_t		*head;
	buffer_data_t		*tail;

	size_t			size;	/* Size of each buffer_data chunk. */
} buffer_t;

typedef enum _buffer_status {
	BUFFER_ERROR = -1,		/* An I/O error occurred.
					 * The buffer should be destroyed and the
					 * file descriptor should be closed.
					 */
	BUFFER_EMPTY = 0,		/* The data was written successfully,
					 * and the buffer is now empty (there is
					 * no pending data waiting to be flushed).
					 */
	BUFFER_PENDING = 1		/* There is pending data in the buffer
					 * waiting to be flushed. Please try
					 * flushing the buffer when select
					 * indicates that the file descriptor
					 * is writeable.
					 */
} buffer_status_t;

/* Some defines */
#define BUFFER_SIZE_DEFAULT	4096

/* Some usefull macros */
#define ERRNO_IO_RETRY(EN) \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

/* Prototypes */
extern buffer_t *buffer_new(size_t);
extern void buffer_reset(buffer_t *);
extern void buffer_free(buffer_t *);
extern void buffer_put(buffer_t *, const void *, size_t);
extern void buffer_putc(buffer_t *, uint8_t);
extern void buffer_putstr(buffer_t *, const char *);
extern char *buffer_getstr(buffer_t *);
extern int buffer_empty(buffer_t *);
extern buffer_status_t buffer_write(buffer_t *, int fd,
                                    const void *, size_t);
extern buffer_status_t buffer_flush_available(buffer_t *, int fd);
extern buffer_status_t buffer_flush_all(buffer_t *, int fd);
extern buffer_status_t buffer_flush_window(buffer_t *, int fd, int width,
                                           int height, int erase, int no_more);

#endif
