# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2018 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= -I $(top_srcdir)/keepalived/include -I $(top_srcdir)/lib
AM_CPPFLAGS		+= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

noinst_LIBRARIES	= libcheck.a

libcheck_a_SOURCES = \
	check_daemon.c check_data.c check_parser.c \
	check_api.c check_tcp.c check_http.c check_ssl.c check_genhash.c \
	check_smtp.c check_misc.c check_dns.c check_print.c \
	ipwrapper.c ipvswrapper.c libipvs.c check_udp.c check_ping.c \
	check_file.c

EXTRA_libcheck_a_SOURCES =
libcheck_a_LIBADD =

if SNMP_CHECKER
  libcheck_a_LIBADD	+= check_snmp.o
  EXTRA_libcheck_a_SOURCES += check_snmp.c
endif

if NFTABLES
  libcheck_a_LIBADD      += check_nftables.o
  EXTRA_libcheck_a_SOURCES += check_nftables.c
endif

if WITH_BFD
  libcheck_a_LIBADD	+= check_bfd.o
  EXTRA_libcheck_a_SOURCES += check_bfd.c
endif

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
