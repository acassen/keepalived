# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@sbindir[@]|$(sbindir)|g' \
	 -e 's|@localstatedir[@]|$(localstatedir)|g' \
	 -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	 -e 's|@PID_DIR[@]|$(PID_DIR)|g' \
	 -e 's|@SNMP_SERVICE[@]|$(SNMP_SERVICE)|g'

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

if WITH_BFD
  BFD_SUBDIR		= bfd
  BFD_LIB		= bfd/libbfd.a
endif

keepalived.service: Makefile
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.service: $(srcdir)/keepalived.service.in

SUBDIRS			= core $(VRRP_SUBDIR) $(IPVS_SUBDIR) $(DBUS_SUBDIR) $(BFD_SUBDIR) etc

EXTRA_DIST		= keepalived.service.in

keepalived_LDADD	= core/libcore.a $(IPVS_LIB) $(VRRP_LIB) $(BFD_LIB) core/libcore.a ../lib/liblib.a $(KA_LIBS)

MOSTLYCLEANFILES	= keepalived.service

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

sysconfigdir		= $(sysconfdir)/sysconfig
sysconfig_DATA		= etc/sysconfig/keepalived

configdir		= $(sysconfdir)/@PACKAGE@
config_DATA		= etc/keepalived/keepalived.conf

if INIT_SYSTEMD
systemdsystemunit_DATA	= keepalived.service
endif

if INIT_OPENRC
initdir			= $(sysconfdir)/init.d
init_DATA		= etc/openrc/keepalived
endif
