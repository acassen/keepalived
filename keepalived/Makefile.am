# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

sbin_PROGRAMS		= keepalived
keepalived_SOURCES	= main.c

noinst_HEADERS		= $(srcdir)/include/*.h

AM_CPPFLAGS		+= -I$(srcdir)/include -I $(top_srcdir)/lib

if WITH_IPVS
  IPVS_SUBDIR		= check
  IPVS_LIB		= check/libcheck.a
endif

if WITH_VRRP
  VRRP_SUBDIR		= vrrp
  VRRP_LIB		= vrrp/libvrrp.a
endif

if WITH_DBUS
  DBUS_SUBDIR		= dbus
endif

SUBDIRS			= core $(VRRP_SUBDIR) $(IPVS_SUBDIR) $(DBUS_SUBDIR)

EXTRA_DIST		= keepalived.service etc

keepalived_LDADD	= core/libcore.a $(IPVS_LIB) $(VRRP_LIB) core/libcore.a ../lib/liblib.a $(KA_LIBS)

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

sysconfigdir		= $(sysconfdir)/sysconfig
sysconfig_DATA		= etc/sysconfig/keepalived

configdir		= $(sysconfdir)/@PACKAGE@
config_DATA		= etc/keepalived/keepalived.conf

if INIT_SYSV
initdir			= $(sysconfdir)/rc.d/init.d
init_DATA		= etc/init.d/keepalived
endif

if INIT_SYSTEMD
systemdsystemunit_DATA	= keepalived.service
endif

if INIT_UPSTART
initdir			= $(sysconfdir)/init
init_DATA		= etc/init/keepalived.conf
endif
