# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

EXTRA_DIST		= keepalived.conf.in

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@sbindir[@]|$(sbindir)|g' \
	 -e 's|@sysconfdir[@]|$(sysconfdir)|g'

keepalived.conf: Makefile
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.conf: $(srcdir)/keepalived.conf.in

if INIT_UPSTART
initdir			= $(sysconfdir)/init
init_DATA		= keepalived.conf
endif

MOSTLYCLEANFILES	= keepalived.conf
