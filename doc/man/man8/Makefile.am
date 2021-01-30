# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

DATE=`date -u --date=@\"\`git log -n 1 --format=%ct -- $@.in 2>/dev/null || date --reference=$@.in +%s\`\" +\"%Y-%m-%d\"`

edit = echo "  EDIT     $@"; \
	sed \
	 -e 's|@DEFAULT_CONFIG_FILE[@]|$(DEFAULT_CONFIG_FILE)|g' \
	 -e "s|@DATE[@]|$(DATE)|g" \
	 -e 's|@RUN_DIR_ROOT[@]|$(RUN_DIR_ROOT)|g' \
	 -e 's|@KA_TMP_DIR[@]|$(KA_TMP_DIR)|g'

dist_man8_MANS  = keepalived.8

keepalived.8: Makefile.am
	@$(edit) '$(srcdir)/$@.in' >$@

keepalived.8: $(srcdir)/keepalived.8.in

EXTRA_DIST		= keepalived.8.in

MOSTLYCLEANFILES	= keepalived.8
