# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2020 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= -I $(top_srcdir)/keepalived/include -I $(top_srcdir)/lib
AM_CPPFLAGS		+= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS) -DLOCAL_STATE_DIR=\"@localstatedir@\"
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

noinst_LIBRARIES	= libcore.a

libcore_a_SOURCES	= main.c daemon.c pidfile.c layer4.c smtp.c \
			  global_data.c global_parser.c keepalived_netlink.c \
			  namespaces.c

libcore_a_LIBADD =
EXTRA_libcore_a_SOURCES =

if SNMP
  libcore_a_LIBADD	+= snmp.o
  EXTRA_libcore_a_SOURCES += snmp.c
endif

if NFTABLES
  libcore_a_LIBADD      += nftables.o
  EXTRA_libcore_a_SOURCES += nftables.c
endif

if LIBNL_DYNAMIC
  libcore_a_LIBADD	+= libnl_link.o
  EXTRA_libcore_a_SOURCES += libnl_link.c
endif

if TRACK_PROCESS
  libcore_a_LIBADD	+= track_process.o
  EXTRA_libcore_a_SOURCES += track_process.c
endif

if !ONE_PROCESS_DEBUG
  libcore_a_LIBADD	+= reload_monitor.o config_notify.o
  EXTRA_libcore_a_SOURCES += reload_monitor.c config_notify.c
endif

if WITH_SANITIZER
  libcore_a_LIBADD	+= sanitizer.o
  EXTRA_libcore_a_SOURCES += sanitizer.c
endif

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@
