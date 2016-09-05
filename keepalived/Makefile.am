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

SUBDIRS			= core $(VRRP_SUBDIR) $(IPVS_SUBDIR)

EXTRA_DIST		= keepalived.service etc

keepalived_LDADD	= core/libcore.a $(IPVS_LIB) $(VRRP_LIB) core/libcore.a ../lib/liblib.a $(KA_LIBS)

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

sysconfigdir		= $(sysconfdir)/sysconfig
sysconfig_DATA		= etc/init.d/keepalived.sysconfig

configdir		= $(sysconfdir)/@PACKAGE@
config_DATA		= etc/keepalived/keepalived.conf

initdir			= $(sysconfdir)/rc.d/init.d
init_DATA		= etc/init.d/keepalived.init

systemddir		= $(prefix)/lib/systemd/system
systemd_DATA		= keepalived.service

install-data-hook:
	mv $(DESTDIR)/$(sysconfdir)/rc.d/init.d/keepalived.init $(DESTDIR)/$(sysconfdir)/rc.d/init.d/keepalived
	mv $(DESTDIR)/$(sysconfdir)/sysconfig/keepalived.sysconfig $(DESTDIR)/$(sysconfdir)/sysconfig/keepalived
