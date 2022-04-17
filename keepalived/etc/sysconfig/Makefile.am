# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2021-2021 Alexandre Cassen, <acassen@gmail.com>

edit = echo "  EDIT     $@"; \
	@SED@ \
	 -e 's|@KEEPALIVED_RUNTIME_OPTIONS[@]|$(KEEPALIVED_RUNTIME_OPTIONS)|g'


keepalived: $(srcdir)/keepalived.in $(builddir)/Makefile
	@rm -f $@ $@.tmp
	@$(edit) '$(srcdir)/$@.in' >$@

EXTRA_DIST		= keepalived.in

sysconfigdir		= $(sysconfdir)/sysconfig
sysconfig_DATA		= keepalived

MOSTLYCLEANFILES	= keepalived
