# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2017-2017 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

noinst_LIBRARIES	= libbfd.a

libbfd_a_SOURCES = \
	bfd.c bfd_data.c bfd_parser.c bfd_daemon.c bfd_scheduler.c \
	bfd_event.c

AM_CPPFLAGS		+= -I$(srcdir)/../include -I$(srcdir)/../../lib

EXTRA_libbfd_a_SOURCES =
libbfd_a_LIBADD =

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
