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
			  vector.c html.c parser.c signals.c logger.c \
			  list_head.c rbtree.c process.c json_writer.c \
			  bitops.h timer.h scheduler.h vector.h parser.h \
			  signals.h notify.h logger.h memory.h html.h utils.h \
			  keepalived_magic.h list_head.h rbtree.h process.h \
			  rbtree_augmented.h assert_debug.h json_writer.h \
			  warnings.h container.h align.h

liblib_a_LIBADD		=
EXTRA_liblib_a_SOURCES	=

if WITH_VRRP
  liblib_a_LIBADD	+= rttables.o
  EXTRA_liblib_a_SOURCES += rttables.c rttables.h
endif

if ASSERTS
  liblib_a_LIBADD	+= assert.o
  EXTRA_liblib_a_SOURCES += assert.c
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
#
# Note: date -d "1970-01-01 UTC" fails using Busybox date
#
$(GIT_COMMIT_FILE): FORCE
	@if [ ! -f $(srcdir)/$@ ]; then \
		LATEST_FILE=`ls -t \`find $(srcdir)/.. -type f -name Makefile.am -o -name configure.ac -o -name '*.[ch]' | grep -v "lib/config.h" | grep -v "lib/config_warnings.h" | grep -v "lib/git-commit.h" | grep -v "/test/"\` | head -1`; \
		LATEST_FILE_DATE=`date -u --reference=$${LATEST_FILE} "+%m/%d,%Y"`; \
		echo "/* Dates are UTC */" >$(abs_builddir)/$@; \
		echo "#define GIT_DATE	\"$${LATEST_FILE_DATE}\"" >>$(abs_builddir)/$@; \
		echo "#define GIT_YEAR	\"`echo $${LATEST_FILE_DATE} | sed -e "s/.*,//"`\"" >>$(abs_builddir)/$@; \
	fi; \
	if [ -x `type -p git` ]; then \
		cd $(srcdir); \
		git rev-parse --is-inside-work-tree >/dev/null 2>&1; \
		res=$$?; \
		if [ $$res -eq 0 ]; then \
			# Check the git root is our parent directory \
			GIT_ROOT_REL=`git rev-parse --show-cdup`; \
			if [ $$GIT_ROOT_REL != "../" ]; then \
				res=1; \
			fi; \
		fi; \
		if [ $$res -eq 0 ]; then \
			GIT_REV=`git describe --tags`; \
			GIT_TIMESTAMP=`git log -1 --format=%ct`; \
			date -d "1970-01-01 UTC" >/dev/null 2>&1 ; \
			if test $$? -eq 0; then \
				SECONDS_STR="UTC $${GIT_TIMESTAMP} seconds"; \
			else \
				SECONDS_STR="0:0:$${GIT_TIMESTAMP}"; \
			fi; \
			GIT_DATE=`date -u +"%m/%d,%Y" -d "1970-01-01 $${SECONDS_STR}"`; \
			if test -n "$${GIT_DATE}"; then \
				GIT_YEAR=`date -u +"%Y" -d "1970-01-01 $${SECONDS_STR}"`; \
			else \
				GIT_DATE=`git log -1 --date=iso | grep Date: | sed -e "s/^[^ ]* *\(....\)-\(..\)-\(..\).*/\2\/\3,\1/"`; \
				GIT_YEAR=`echo $${GIT_DATE} | sed -e "s/.*,//"`; \
			fi; \
			if [ "`git status --porcelain | \
			       grep -v '^??' | \
			       grep -v "^ D snap/snapcraft.yaml" | \
			       grep -v "^ D snap/hooks/install" | \
			       grep -v "^ D snap/hooks/post-refresh" | \
			       wc -l`" -ne 0 ]; then \
				EXTRA="+"; \
			else \
				EXTRA=""; \
			fi; \
			echo "/* Dates are UTC */" >$(abs_builddir)/$@.new; \
			echo $${GIT_REV} | grep -qE -- "-[1-9][0-9]*-g[0-9a-f]{7,}$$"; \
			if [ $$? -eq 0 -o -n "$${EXTRA}" ]; then \
				echo "#define GIT_COMMIT \"$${GIT_REV}$${EXTRA}\"" >>$(abs_builddir)/$@.new; \
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
