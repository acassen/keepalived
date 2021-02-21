# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

EXTRA_DIST		= keepalived.suse.init.in keepalived keepalived.rh.init.in

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@sbindir[@]|$(sbindir)|g' \
	 -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	 -e 's|@localstatedir[@]|$(localstatedir)|g'

if INIT_SUSE
keepalived.suse.init: $(srcdir)/Makefile.am
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.suse.init: $(srcdir)/keepalived.suse.init.in
endif

if INIT_SYSV
if REDHAT
keepalived.rh.init: $(srcdir)/Makefile.am
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.rh.init: $(srcdir)/keepalived.rh.init.in
endif
endif

if INIT_SYSV
if REDHAT
rhdir			= $(sysconfdir)/rc.d/init.d
rh_DATA			= keepalived.rh.init
else
initdir			= $(sysconfdir)/rc.d/init.d
init_DATA		= keepalived
endif
endif

if INIT_SUSE
susedir			= $(sysconfdir)/init
suse_DATA		= keepalived.suse.init
endif

MOSTLYCLEANFILES	= keepalived.suse.init keepalived.rh.init
