/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Buffer structure manipulation.
 *		This code is coming from quagga.net.
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
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/uio.h>

#include "buffer.h"
#include "memory.h"

/* Create a new buffer. Memory will be allocated in chunks of the given
 * size.  If the argument is 0, the library will supply a reasonable
 * default size suitable for buffering socket I/O.
 */
buffer_t *
buffer_new(size_t size)
{
	buffer_t *b;

	b = (buffer_t *) MALLOC(sizeof(buffer_t));

	if (size) {
		b->size = size;
	} else {
		static size_t default_size;
		if (!default_size) {
			long pgsz = sysconf(_SC_PAGESIZE);
			default_size = ((((BUFFER_SIZE_DEFAULT-1)/pgsz)+1)*pgsz);
		}
		b->size = default_size;
	}

	return b;
}

/* Free all data in the buffer. */
void
buffer_free(buffer_t *b)
{
	buffer_reset(b);
	FREE(b);
}

/* Combine all accumulated (and unflushed) data inside the buffer into a
 * single NUL-terminated string allocated using XMALLOC(MTYPE_TMP).  Note
 * that this function does not alter the state of the buffer, so the data
 * is still inside waiting to be flushed.
 */
char *
buffer_getstr(buffer_t *b)
{
	size_t totlen = 0;
	buffer_data_t *data;
	char *s, *p;

	for (data = b->head; data; data = data->next)
		totlen += data->cp - data->sp;

	if (!(s = (char *) MALLOC(totlen+1)))
		return NULL;

	p = s;
	for (data = b->head; data; data = data->next) {
		memcpy(p, data->data + data->sp, data->cp - data->sp);
		p += data->cp - data->sp;
	}
	*p = '\0';

	return s;
}

/* Returns 1 if there is no pending data in the buffer.
 * Otherwise returns 0.
 */
int
buffer_empty(buffer_t *b)
{
	return (b->head == NULL);
}

/* Clear and free all allocated data. */
void
buffer_reset(buffer_t *b)
{
	buffer_data_t *data, *next;

	for (data = b->head; data; data = next) {
		next = data->next;
		FREE(data);
	}

	b->head = b->tail = NULL;
}

/* Add buffer_data to the end of buffer. */
static buffer_data_t *
buffer_add(buffer_t *b)
{
	buffer_data_t *d;

	d = (buffer_data_t *) MALLOC(offsetof(buffer_data_t, data[b->size]));
	d->cp = d->sp = 0;
	d->next = NULL;

	if (b->tail)
		b->tail->next = d;
	else
		b->head = d;
	b->tail = d;

	return d;
}

/* Add the given data to the end of the buffer. */
void
buffer_put(buffer_t *b, const void *p, size_t size)
{
	buffer_data_t *data = b->tail;
	const char *ptr = p;

	/* We use even last one byte of data buffer. */
	while (size) {
		size_t chunk;

		/* If there is no data buffer add it. */
		if (data == NULL || data->cp == b->size)
			data = buffer_add(b);

		chunk = ((size <= (b->size - data->cp)) ? size : (b->size - data->cp));
		memcpy((data->data + data->cp), ptr, chunk);
		size -= chunk;
		ptr += chunk;
		data->cp += chunk;
	}
}

/* Add a single character to the end of the buffer. */
void
buffer_putc(buffer_t *b, uint8_t c)
{
	buffer_put(b, &c, 1);
}

/* Add a NUL-terminated string to the end of the buffer. */
void
buffer_putstr(buffer_t *b, const char *c)
{
	buffer_put(b, c, strlen(c));
}

/* Call buffer_flush_available repeatedly until either all data has been
 * flushed, or an I/O error has been encountered, or the operation would
 * block.
 */
buffer_status_t
buffer_flush_all(buffer_t *b, int fd)
{
 	buffer_status_t ret;
	buffer_data_t *head;
	size_t head_sp;

	if (!b->head)
		return BUFFER_EMPTY;

	/* Flush all data. */
	head_sp = (head = b->head)->sp;
	while ((ret = buffer_flush_available(b, fd)) == BUFFER_PENDING) {
		if ((b->head == head) && (head_sp == head->sp) && (errno != EINTR)) {
			/* No data was flushed, so kernel buffer must be full. */
			return ret;
		}

		head_sp = (head = b->head)->sp;
	}

	return ret;
}

/* Attempt to write enough data to the given fd to fill a window of the
 * given width and height (and remove the data written from the buffer).
 *
 * If !no_more, then a message saying " --More-- " is appended.
 * If erase is true, then first overwrite the previous " --More-- " message
 * with spaces.
 *
 * Any write error (including EAGAIN or EINTR) will cause this function
 * to return -1 (because the logic for handling the erase and more features
 * is too complicated to retry the write later).
 */
buffer_status_t
buffer_flush_window(buffer_t *b, int fd, int width, int height,
                    int erase_flag, int no_more_flag)
{
	int nbytes = 0, iov_alloc, iov_index, column;
	struct iovec *iov;
	struct iovec small_iov[3];
	char more[] = " --More-- ";
	char erase[] = { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
			 ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08};
	buffer_data_t *data;

	if (!b->head)
		return BUFFER_EMPTY;

	if (height < 1) {
		height = 1;
	} else if (height >= 2) {
		height--;
	}

	if (width < 1) {
		width = 1;
	}

	/* For erase and more data add two to b's buffer_data count.*/
	if (b->head->next == NULL) {
		iov_alloc = sizeof(small_iov)/sizeof(small_iov[0]);
		iov = small_iov;
	} else {
		iov_alloc = ((height*(width+2))/b->size)+10;
		iov = (struct iovec *) MALLOC(iov_alloc*sizeof(*iov));
	}
	iov_index = 0;

	/* Previously print out is performed. */
	if (erase_flag) {
		iov[iov_index].iov_base = erase;
		iov[iov_index].iov_len = sizeof erase;
		iov_index++;
	}

	/* Output data. */
	column = 1;  /* Column position of next character displayed. */
	for (data = b->head; data && (height > 0); data = data->next) {
		size_t cp;

		cp = data->sp;
		while ((cp < data->cp) && (height > 0)) {
			/* Calculate lines remaining and column position after displaying
			 * this character. */
			if (data->data[cp] == '\r') {
				column = 1;
			} else if ((data->data[cp] == '\n') || (column == width)) {
				column = 1;
				height--;
			} else {
				column++;
			}
			cp++;
		}

		iov[iov_index].iov_base = (char *)(data->data + data->sp);
		iov[iov_index++].iov_len = cp-data->sp;
		data->sp = cp;

        	/* This should not ordinarily happen. */
		if (iov_index == iov_alloc) {
			iov_alloc *= 2;
			if (iov != small_iov) {
				iov = REALLOC(iov, iov_alloc*sizeof(*iov));
			} else {
				/* This should absolutely never occur. */
				iov = MALLOC(iov_alloc*sizeof(*iov));
				memcpy(iov, small_iov, sizeof(small_iov));
			}
		}
	}

	/* In case of `more' display need. */
	if (b->tail && (b->tail->sp < b->tail->cp) && !no_more_flag) {
		iov[iov_index].iov_base = more;
		iov[iov_index].iov_len = sizeof more;
		iov_index++;
	}


#ifdef IOV_MAX
	/* IOV_MAX are normally defined in <sys/uio.h> , Posix.1g.
	 * example: Solaris2.6 are defined IOV_MAX size at 16.
	 */
	{
		struct iovec *c_iov = iov;

		while (iov_index > 0) {
			int iov_size;

			iov_size = ((iov_index > IOV_MAX) ? IOV_MAX : iov_index);
			if ((nbytes = writev(fd, c_iov, iov_size)) < 0) {
				break;
			}

			/* move pointer io-vector */
			c_iov += iov_size;
			iov_index -= iov_size;
		}
	}
#endif /* IOV_MAX */

	/* Free printed buffer data. */
	while (b->head && (b->head->sp == b->head->cp)) {
		buffer_data_t *del;
		if (!(b->head = (del = b->head)->next))
			b->tail = NULL;
		FREE(del);
	}

	if (iov != small_iov)
		FREE(iov);

	return (nbytes < 0) ? BUFFER_ERROR :
			      (b->head ? BUFFER_PENDING : BUFFER_EMPTY);
}

/* This function (unlike other buffer_flush* functions above) is designed
 * to work with non-blocking sockets.  It does not attempt to write out
 * all of the queued data, just a "big" chunk.  It returns 0 if it was
 * able to empty out the buffers completely, 1 if more flushing is
 * required later, or -1 on a fatal write error.
 */
buffer_status_t
buffer_flush_available(buffer_t *b, int fd)
{
/* These are just reasonable values to make sure a significant amount of
 * data is written.  There's no need to go crazy and try to write it all
 * in one shot. */
#ifdef IOV_MAX
#define MAX_CHUNKS ((IOV_MAX >= 16) ? 16 : IOV_MAX)
#else
#define MAX_CHUNKS 16
#endif
#define MAX_FLUSH 131072

	buffer_data_t *d;
	size_t written;
	struct iovec iov[MAX_CHUNKS];
	size_t iovcnt = 0, nbytes = 0;

	for (d = b->head; d && (iovcnt < MAX_CHUNKS) && (nbytes < MAX_FLUSH);
	     d = d->next, iovcnt++) {
		iov[iovcnt].iov_base = d->data+d->sp;
		nbytes += (iov[iovcnt].iov_len = d->cp-d->sp);
	}

	/* No data to flush: should we issue a warning message? */
	if (!nbytes)
		return BUFFER_EMPTY;

	/* only place where written should be sign compared */
	if ((ssize_t)(written = writev(fd,iov,iovcnt)) < 0) {
		/* Calling code should try again later. */
		if (ERRNO_IO_RETRY(errno))
			return BUFFER_PENDING;
		return BUFFER_ERROR;
	}

	/* Free printed buffer data. */
	while (written > 0) {
		buffer_data_t *d;
		if (!(d = b->head))
			break;
		if (written < d->cp-d->sp) {
			d->sp += written;
			return BUFFER_PENDING;
		}

		written -= (d->cp-d->sp);
		if (!(b->head = d->next))
			b->tail = NULL;
		FREE(d);
	}

	return b->head ? BUFFER_PENDING : BUFFER_EMPTY;

#undef MAX_CHUNKS
#undef MAX_FLUSH
}

/* Try to write this data to the file descriptor.
 * Any data that cannot be written immediately is added to
 * the buffer queue.
 */
buffer_status_t
buffer_write(buffer_t *b, int fd, const void *p, size_t size)
{
	ssize_t nbytes;
	size_t written;

	/* Buffer is not empty, so do not attempt to write the new data. */
	if (b->head) {
		nbytes = 0;
	} else if ((nbytes = write(fd, p, size)) < 0) {
		if (ERRNO_IO_RETRY(errno)) {
			nbytes = 0;
		} else {
			return BUFFER_ERROR;
		}
	}

	/* Add any remaining data to the buffer. */
	written = nbytes;
	if (written < size) {
		buffer_put(b, ((const char *)p)+written, size-written);
	}

	return b->head ? BUFFER_PENDING : BUFFER_EMPTY;
}
