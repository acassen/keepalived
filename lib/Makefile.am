# Makefile.am
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>

GIT_COMMIT_FILE		= git-commit.h

AM_CPPFLAGS		= $(KA_CPPFLAGS) $(DEBUG_CPPFLAGS)
AM_CFLAGS		= $(KA_CFLAGS) $(DEBUG_CFLAGS)
AM_LDFLAGS		= $(KA_LDFLAGS) $(DEBUG_LDFLAGS)
# AM_LIBS		= $(KA_LIBS)
# AM_LIBTOOLFLAGS	= $(KA_LIBTOOLFLAGS)
BUILT_SOURCES		= $(GIT_COMMIT_FILE)

noinst_LIBRARIES	= liblib.a

liblib_a_SOURCES	= memory.c utils.c notify.c timer.c scheduler.c \
			  vector.c list.c html.c parser.c signals.c logger.c \
			  list_head.c rbtree.c process.c json_writer.c \
			  bitops.h timer.h scheduler.h vector.h parser.h \
			  signals.h notify.h logger.h list.h memory.h html.h utils.h \
			  keepalived_magic.h list_head.h rbtree.h process.h \
			  rbtree_augmented.h assert_debug.h json_writer.h \
			  warnings.h container.h

liblib_a_LIBADD		=
EXTRA_liblib_a_SOURCES	=

if WITH_VRRP
  liblib_a_LIBADD	+= rttables.o
  EXTRA_liblib_a_SOURCES += rttables.c rttables.h
endif

if ! SOCK_NONBLOCK
  liblib_a_LIBADD	+= old_socket.o
  EXTRA_liblib_a_SOURCES += old_socket.c old_socket.h
endif

if ASSERTS
  liblib_a_LIBADD	+= assert.o
  EXTRA_liblib_a_SOURCES += assert.c old_socket.h
endif

EXTRA_DIST		= $(GIT_COMMIT_FILE)

MAINTAINERCLEANFILES	= @MAINTAINERCLEANFILES@

CLEANFILES		= $(GIT_COMMIT_FILE)

FORCE:

# The git commit file will contain the git version and date of last commit,
# unless this is a tagged version, in which case the git commit is omitted.
# If there have been any local modifications, '+' is appended to the git
# version.
# The one file that needs to be ignored is deletion of snap/snapcraft.yaml,
# since in a snapcraft build that file is deleted
# (see https://bugs.launchpad.net/snapcraft/+bug/1662388).
$(GIT_COMMIT_FILE): FORCE
	@if [ ! -f $(srcdir)/$@ -a ! -f $@ ]; then \
		echo '#define GIT_DATE	"unknown"' >$@; \
		echo "#define GIT_YEAR	\"`date +%Y`\"" >>$@; \
	fi; \
	if [ -x `type -p git` ]; then \
		cd $(srcdir); \
		git rev-parse --is-inside-work-tree >/dev/null 2>&1; \
		if [ $$? -eq 0 ]; then \
			GIT_REV=`git describe --tags`; \
			GIT_TIMESTAMP=`git log -1 --format=%ct`; \
			GIT_DATE=`date -d "1970-01-01 UTC $${GIT_TIMESTAMP} seconds" +"%m/%d,%Y"`; \
			if test -n "$${GIT_DATE}"; then \
				GIT_YEAR=`date -d "1970-01-01 UTC $${GIT_TIMESTAMP} seconds" +"%Y"`; \
			else \
				GIT_DATE=`git log -1 --date=iso | grep Date: | sed -e "s/^[^ ]* *\(....\)-\(..\)-\(..\).*/\2\/\3,\1/"`; \
				GIT_YEAR=`echo $${GIT_DATE} | sed -e "s/.*,//"`; \
			fi; \
			if [ "`git status --porcelain | \
			       grep -v '^??' | \
			       grep -v "^ D snap/snapcraft.yaml" | \
			       wc -l`" -ne 0 ]; then \
				EXTRA="+"; \
			else \
				EXTRA=""; \
			fi; \
			echo $${GIT_REV} | grep -qE -- "-[1-9][0-9]*-g[0-9a-f]{7,}$$"; \
			if [ $$? -eq 0 -o -n "$${EXTRA}" ]; then \
				echo "#define GIT_COMMIT \"$${GIT_REV}$${EXTRA}\"" >$(abs_builddir)/$@.new; \
			fi; \
			echo "#define GIT_DATE \"$${GIT_DATE}\"" >>$(abs_builddir)/$@.new; \
			echo "#define GIT_YEAR \"$${GIT_YEAR}\"" >>$(abs_builddir)/$@.new; \
			diff -q $(abs_builddir)/$@ $(abs_builddir)/$@.new 2>/dev/null >/dev/null; \
			if [ $$? -eq 0 ]; then \
				rm $(abs_builddir)/$@.new; \
			else \
				mv $(abs_builddir)/$@.new $(abs_builddir)/$@; \
			fi; \
		fi; \
		cd $(abs_builddir); \
	fi
