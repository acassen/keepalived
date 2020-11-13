# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>

DATE=`date --date=\"\`git log -n 1 -- $@.in | grep Date: | sed -e \"s/  */ /g\" | cut -d' ' -f 4,3,6\`\" +\"%Y-%m-%d\"`

edit = echo "  EDIT     $@"; \
	sed \
	 -e "s|@DATE[@]|$(DATE)|g"

dist_man5_MANS  = keepalived.conf.5

keepalived.conf.5: Makefile
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.conf.5: $(srcdir)/keepalived.conf.5.in

EXTRA_DIST		= keepalived.conf.5.in

MOSTLYCLEANFILES	= keepalived.conf.5
