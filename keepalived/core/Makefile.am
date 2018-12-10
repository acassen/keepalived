# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS) -DLOCAL_STATE_DIR=\"@localstatedir@\"
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

noinst_LIBRARIES	= libcore.a

libcore_a_SOURCES	= main.c daemon.c pidfile.c layer4.c smtp.c \
			  global_data.c global_parser.c keepalived_netlink.c

AM_CPPFLAGS		+= -I$(srcdir)/../include -I$(srcdir)/../../lib

libcore_a_LIBADD =
EXTRA_libcore_a_SOURCES =

if SNMP
  libcore_a_LIBADD	+= snmp.o
  EXTRA_libcore_a_SOURCES += snmp.c
endif

if WITH_NAMESPACES
  libcore_a_LIBADD	+= namespaces.o
  EXTRA_libcore_a_SOURCES += namespaces.c
endif

if LIBNL_DYNAMIC
  libcore_a_LIBADD	+= libnl_link.o
  EXTRA_libcore_a_SOURCES += libnl_link.c
endif

if CN_PROC
  libcore_a_LIBADD	+= track_process.o
  EXTRA_libcore_a_SOURCES += track_process.c
endif

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
