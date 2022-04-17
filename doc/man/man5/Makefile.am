# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>

DATE=`date -u --date=@\"\`git log -n 1 --format=%ct -- $@.in 2>/dev/null || date --reference=$(srcdir)/$@.in +%s\`\" +\"%Y-%m-%d\"`

edit = echo "  EDIT     $@"; \
	@SED@ \
	 -e "s|@DATE[@]|$(DATE)|g" \
	 -e 's|@RUN_DIR_ROOT[@]|$(RUN_DIR_ROOT)|g' \
	 -e 's|@KA_TMP_DIR[@]|$(KA_TMP_DIR)|g'

dist_man5_MANS  = keepalived.conf.5

keepalived.conf.5: $(builddir)/Makefile $(top_builddir)/lib/config.h $(srcdir)/Makefile.am
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.conf.5: $(srcdir)/keepalived.conf.5.in

EXTRA_DIST		= keepalived.conf.5.in

MOSTLYCLEANFILES	= keepalived.conf.5
