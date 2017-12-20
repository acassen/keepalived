# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

bin_PROGRAMS		= genhash
AM_CPPFLAGS		+= -I$(srcdir)/../lib

genhash_SOURCES		= main.c sock.c layer4.c http.c ssl.c
genhash_LDADD		= ../lib/liblib.a $(KA_LIBS) $(GENHASH_LIBS)

noinst_HEADERS		= $(srcdir)/include/*.h

EXTRA_DIST		= AUTHOR

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
