# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@gmail.com>

GIT_COMMIT_FILE		= git-commit.h

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)
BUILT_SOURCES		= $(GIT_COMMIT_FILE)

noinst_LIBRARIES	= liblib.a

liblib_a_SOURCES	= memory.c utils.c notify.c timer.c scheduler.c \
	vector.c list.c html.c parser.c signals.c logger.c rttables.c \
	bitops.h timer.h scheduler.h rttables.h vector.h parser.h \
	signals.h notify.h logger.h list.h memory.h html.h utils.h

liblib_a_LIBADD		=
EXTRA_liblib_a_SOURCES	=

if ! SOCK_NONBLOCK
  liblib_a_LIBADD	+= old_socket.o
  EXTRA_liblib_a_SOURCES += old_socket.c old_socket.h
endif

EXTRA_DIST		= $(GIT_COMMIT_FILE)

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

.PHONY: $(GIT_COMMIT_FILE)

$(GIT_COMMIT_FILE):
	@if [ ! -f $(srcdir)/$(GIT_COMMIT_FILE) -a ! -f $(builddir)/$(GIT_COMMIT_FILE) ]; then \
		>$(builddir)/$(GIT_COMMIT_FILE); \
	fi; \
	if [ -x `type -p git` ]; then \
		cd $(srcdir); \
		git rev-parse --is-inside-work-tree >/dev/null 2>&1; \
		if [ $$? -eq 0 ]; then \
			GIT_REV=`git describe --tags`; \
			echo $${GIT_REV} | grep -qE -- "-[1-9][0-9]*-g[0-9a-f]{7}$$"; \
			if [ $$? -eq 0 ]; then \
				if [ "`git status --porcelain | wc -l`" -ne 0 ]; then EXTRA="+"; else EXTRA=""; fi ; \
				echo "#define GIT_COMMIT \"$${GIT_REV}$${EXTRA}\"" >$(abs_builddir)/$(GIT_COMMIT_FILE).new; \
				diff -q $(abs_builddir)/$(GIT_COMMIT_FILE) $(abs_builddir)/$(GIT_COMMIT_FILE).new 2>/dev/null >/dev/null; \
				if [ $$? -eq 0 ]; then \
					rm $(abs_builddir)/$(GIT_COMMIT_FILE).new; \
				else \
					mv $(abs_builddir)/$(GIT_COMMIT_FILE).new $(abs_builddir)/$(GIT_COMMIT_FILE); \
				fi; \
			fi; \
		fi; \
		cd $(abs_builddir); \
	fi
