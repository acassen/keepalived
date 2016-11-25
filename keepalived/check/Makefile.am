# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

noinst_LIBRARIES	= libcheck.a

libcheck_a_SOURCES = \
	check_daemon.c check_data.c check_parser.c \
	check_api.c check_tcp.c check_http.c check_ssl.c \
	check_smtp.c check_misc.c check_dns.c ipwrapper.c \
	ipvswrapper.c libipvs.c

AM_CPPFLAGS		+= -I$(srcdir)/../include -I$(srcdir)/../../lib

EXTRA_libcheck_a_SOURCES =
libcheck_a_LIBADD =

if SNMP_CHECKER
  libcheck_a_LIBADD	+= check_snmp.o
  EXTRA_libcheck_a_SOURCES += check_snmp.c
endif

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
