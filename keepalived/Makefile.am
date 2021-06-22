# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

AM_CPPFLAGS		= -I $(top_srcdir)/keepalived/include -I $(top_srcdir)/lib
AM_CPPFLAGS		+= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@sbindir[@]|$(sbindir)|g' \
	 -e 's|@localstatedir[@]|$(localstatedir)|g' \
	 -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	 -e 's|@RUN_DIR[@]|$(RUN_DIR)|g' \
	 -e 's|@SNMP_SERVICE[@]|$(SNMP_SERVICE)|g' \
	 -e 's|@SYSTEMD_SERVICE_TYPE[@]|$(SYSTEMD_SERVICE_TYPE)|g' \
	 -e 's|@SYSTEMD_EXEC_START_OPTIONS[@]|$(SYSTEMD_EXEC_START_OPTIONS)|g'

sbin_PROGRAMS		= keepalived
keepalived_SOURCES	= main.c

noinst_HEADERS		= $(srcdir)/include/*.h

TRACKER_SUBDIR		= trackers
TRACKER_LIB		= trackers/libtracker.a

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

if INIT_SYSTEMD
keepalived.service: $(srcdir)/Makefile.am
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.service: $(srcdir)/keepalived.service.in
endif

SUBDIRS			= core $(VRRP_SUBDIR) $(IPVS_SUBDIR) $(DBUS_SUBDIR) $(BFD_SUBDIR) $(TRACKER_SUBDIR) etc

EXTRA_DIST		= keepalived.service.in

keepalived_LDADD	= core/libcore.a $(IPVS_LIB) $(VRRP_LIB) $(BFD_LIB) core/libcore.a $(TRACKER_LIB) ../lib/liblib.a $(KA_LIBS)

MOSTLYCLEANFILES	= keepalived.service

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

if INIT_SYSTEMD
systemdsystemunit_DATA	= keepalived.service
endif

if INIT_OPENRC
initdir			= $(sysconfdir)/init.d
init_DATA		= etc/openrc/keepalived
endif

if WITH_IPVS
install-exec-hook:
	@( \
	d=`echo $(bindir) | sed -e "s:^/::"`; \
	s=`echo $(sbindir) | sed -e "s:^/::"`; \
	\
	while [ 1 ]; do \
		d1=`echo $$d | sed -e "s:/.*::"`; \
		s1=`echo $$s | sed -e "s:/.*::"`; \
		if [ $$d1 != $$s1 ]; then \
			break; \
		fi; \
		d=`echo $$d | sed -e "s:^[^/]*/::"`; \
		s=`echo $$s | sed -e "s:^[^/]*/::"`; \
		if [ -z $$d ]; then break; fi; \
		if [ -z $$s ]; then break; fi; \
	done; \
	\
	d=`echo /$$d/ | sed -e "s:/[^/.]*/:/../:g" -e "s:/[^/.]*/:/../:g" -e "s:^/::"`; \
	\
	$(MKDIR_P) $(DESTDIR)/$(bindir); \
	$(LN_S) $$d$$s/keepalived $(DESTDIR)/$(bindir)/genhash; \
	)
endif
