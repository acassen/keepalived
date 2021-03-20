# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>

.PHONY:	all debug profile

all debug profile: $(top_builddir)/bin/keepalived $(top_builddir)/bin/genhash

$(top_builddir)/bin/keepalived: $(top_builddir)/keepalived/keepalived
	@$(MKDIR_P) $(top_builddir)/bin
	@(if test -f $(top_builddir)/keepalived/keepalived; then \
		if test -z "$(DEBUG_LDFLAGS)$(DEBUG_CFLAGS)$(DEBUG_CPPFLAGS)"; then \
			@STRIP@ -o $(top_builddir)/bin/keepalived $(top_builddir)/keepalived/keepalived; \
		else \
			cp -p $(top_builddir)/keepalived/keepalived $(top_builddir)/bin; \
		fi; \
	else \
		rm -f $(top_builddir)/bin/keepalived; \
	fi)

$(top_builddir)/bin/genhash: $(top_builddir)/tools/genhash
	@$(MKDIR_P) $(top_builddir)/bin
	@(if test -f $(top_builddir)/tools/genhash; then \
		cp -p $(top_builddir)/tools/genhash $(top_builddir)/bin; \
	else \
		rm -f $(top_builddir)/bin/genhash; \
	fi)

clean-local:
	rm -f $(top_builddir)/bin/keepalived $(top_builddir)/bin/genhash
