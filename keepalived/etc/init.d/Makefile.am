# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

EXTRA_DIST		= keepalived.suse.init.in keepalived keepalived.rh.init

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@sbindir[@]|$(sbindir)|g' \
	 -e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	 -e 's|@localstatedir[@]|$(localstatedir)|g'

keepalived.suse.init: Makefile
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.suse.init: $(srcdir)/keepalived.suse.init.in

if INIT_SYSV
initdir			= $(sysconfdir)/rc.d/init.d
init_DATA		= keepalived
endif

if INIT_SUSE
susedir			= $(sysconfdir)/init
suse_DATA		= keepalived.suse.init
endif

MOSTLYCLEANFILES	= keepalived.suse.init
