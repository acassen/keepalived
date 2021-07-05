# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>

.PHONY:	all debug profile

all debug profile: $(top_builddir)/bin/keepalived

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
if WITH_IPVS
	@(if test -f $(top_builddir)/keepalived/keepalived; then \
		rm -f $(top_builddir)/bin/genhash; \
		$(LN_S) keepalived $(top_builddir)/bin/genhash; \
	else \
		rm -f $(top_builddir)/bin/genhash; \
	fi)
endif

clean-local:
if WITH_IPVS
	rm -f $(top_builddir)/bin/genhash
endif
	rm -f $(top_builddir)/bin/keepalived
