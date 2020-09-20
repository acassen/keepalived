# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2020-2020 Alexandre Cassen, <acassen@gmail.com>

cp = echo "  CP       $@"; \
      cp

@DEFAULT_CONFIG_FILENAME@: $(srcdir)/keepalived.conf.in
	@$(cp)  '$<' $@

EXTRA_DIST		= keepalived.conf.in

configdir		= @DEFAULT_CONFIG_DIR@
config_DATA		= @DEFAULT_CONFIG_FILENAME@

MOSTLYCLEANFILES	= @DEFAULT_CONFIG_FILENAME@
