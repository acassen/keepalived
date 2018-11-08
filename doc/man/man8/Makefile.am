# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@DEFAULT_CONFIG_FILE[@]|$(DEFAULT_CONFIG_FILE)|g'

dist_man8_MANS  = keepalived.8

keepalived.8: Makefile
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.8: $(srcdir)/keepalived.8.in

EXTRA_DIST		= keepalived.8.in

MOSTLYCLEANFILES	= keepalived.8
