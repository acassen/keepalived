#
# Keepalived OpenSource project.
#
# Configuration template file for keepalived.
# autoconf will generate & check deps for proper compilation
#
# Copyright (C) 2001-2018 Alexandre Cassen, <acassen@linux-vs.org>

AC_DEFUN([add_to_var], [$1="$$1 $2"])
AC_DEFUN([add_to_var_ind], [eval $1=\"\$$1 $2\"]) dnl "

AC_DEFUN([add_to_var_ind_unique],
  ADD_NEW=
  [ eval var=\$$1
    for item in $2; do
      echo " $var " | $GREP -q " $item "
      if test $? -ne 0; then
	add_to_var([ADD_NEW], [$item])
      fi
    done
    add_to_var_ind([$1], [$ADD_NEW])
  ])

AC_DEFUN([add_pkg_config],
  [ if test -n "$2"; then
      KA_PKG_PFX=$2
    else
      KA_PKG_PFX=KA
    fi
    add_to_var_ind_unique([${KA_PKG_PFX}_CPPFLAGS], [`$PKG_CONFIG --cflags-only-I $1`])
    add_to_var_ind_unique([${KA_PKG_PFX}_CFLAGS], [`$PKG_CONFIG --cflags-only-other $1`])

    if test .$3 = .remove-requires; then
      REQUIRES=`$PKG_CONFIG --print-requires $1`
      var=`$PKG_CONFIG --libs-only-l $1`
      for r in $REQUIRES; do
	REQ_LIBS=`$PKG_CONFIG --libs-only-l $r`
	for l in $REQ_LIBS; do
	  var=`echo " $var " | sed -e "s: $l : :g"`
	done
      done
      var=`echo $var | sed -e "s:^ *::" -e "s:  *$::"`
      eval ${KA_PKG_PFX}_LIBS="\"$var\""

      var=`echo $var | sed -e "s/-l//g"`
      eval ${KA_PKG_PFX}_LIB_NAMES="\"$var\""
    else
      add_to_var_ind_unique([${KA_PKG_PFX}_LIBS], [`$PKG_CONFIG --libs $1`])
    fi
  ])

AC_DEFUN([add_pkg_config_without_libs],
  [ if test -n "$2"; then
      KA_PKG_PFX=$2
    else
      KA_PKG_PFX=KA
    fi
    add_to_var_ind_unique([${KA_PKG_PFX}_CPPFLAGS], [$($PKG_CONFIG --cflags-only-I $1)])
    add_to_var_ind_unique([${KA_PKG_PFX}_CFLAGS], [$($PKG_CONFIG --cflags-only-other $1)])
  ])

AC_DEFUN([add_config_opt], [add_to_var([CONFIG_OPTIONS], [$1])])

AC_DEFUN([add_system_opt], [add_to_var([SYSTEM_OPTIONS], [$1])])

AC_DEFUN([get_lib_name],
  [
    if test $LDD = :; then
      AC_MSG_ERROR([ldd is required for dynamic run-time linking support])
    fi

    SAV_LIBS="$LIBS"
    LIBS="$LIBS -l$1"
    AC_LINK_IFELSE([AC_LANG_SOURCE([[
      extern void $2(void);
      int main(void)
      {
	$2();
	return 0;
      }
    ]])], [
      LIB_DETAILS=`$LDD ./conftest$EXEEXT | grep $1.so | sed -e "s/^[[ \t]]*//"`
      LIB_NAME=`echo $LIB_DETAILS | sed -e "s/ .*//"`
    ],[
    ])
    LIBS="$SAV_LIBS"
  ])

# AS_VAR_COPY was introduced in autoconf 2.63b.
# Remove the following definition once require autoconf >= 2.64.
m4_ifndef([AS_VAR_COPY],
[m4_define([AS_VAR_COPY],
[AS_LITERAL_IF([$1[]$2], [$1=$$2], [eval $1=\$$2])])])

dnl ----[ Process this file with autoconf to produce a configure script ]----
AC_PREREQ([2.63])
AC_INIT([Keepalived], [2.2.2], [keepalived-users@groups.io], [], [http://www.keepalived.org/])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror -Woverride foreign])

AC_CONFIG_SRCDIR([keepalived/core/main.c])

AC_CONFIG_HEADERS([lib/config.h lib/config_warnings.h])

AH_TOP(
  [
#ifndef _CONFIG_H
#define _CONFIG_H
  ])
AH_BOTTOM(
  [
#include "config_warnings.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#endif])

AC_CONFIG_FILES([Makefile keepalived/Makefile lib/Makefile keepalived/core/Makefile keepalived.spec \
		 keepalived/check/Makefile keepalived/vrrp/Makefile \
		 keepalived/bfd/Makefile doc/Makefile bin_install/Makefile keepalived/dbus/Makefile \
		 keepalived/etc/Makefile keepalived/etc/init/Makefile keepalived/etc/init.d/Makefile \
		 keepalived/etc/sysconfig/Makefile keepalived/etc/keepalived/Makefile \
		 keepalived/trackers/Makefile \
		 doc/man/man8/Makefile doc/man/man5/Makefile doc/man/man1/Makefile])


MAINTAINERCLEANFILES="*~ *.orig *.rej core core.*"
AC_SUBST(MAINTAINERCLEANFILES)
CONFIG_OPTIONS=
SYSTEM_OPTIONS=

AM_SILENT_RULES([yes])

PKG_PROG_PKG_CONFIG

dnl ----[ Keepalived specific configure options ]----
AC_ARG_ENABLE(lvs-syncd,
  [AS_HELP_STRING([--disable-lvs-syncd], [do not use LVS synchronization daemon])])
AC_ARG_ENABLE(lvs,
  [AS_HELP_STRING([--disable-lvs], [do not use the LVS framework])])
AC_ARG_ENABLE(lvs-64bit-stats,
  [AS_HELP_STRING([--disable-lvs-64bit-stats], [do not use the LVS 64-bit stats])])
AC_ARG_ENABLE(vrrp,
  [AS_HELP_STRING([--disable-vrrp], [do not use the VRRP framework])])
AC_ARG_ENABLE(bfd,
  [AS_HELP_STRING([--enable-bfd], [use the BFD framework])])
AC_ARG_WITH(kernel-dir,
  [AS_HELP_STRING([--with-kernel-dir=DIR], [path to linux kernel source directory])],
  [AS_HELP_STRING([kernel_src_path="$withval"],], [[kernel_src_path=""])])
AC_ARG_ENABLE(fwmark,
  [AS_HELP_STRING([--disable-fwmark], [compile without SO_MARK support])])
AC_ARG_ENABLE(snmp,
  [AS_HELP_STRING([--enable-snmp], [compile with SNMP support])])
AC_ARG_ENABLE(snmp-vrrp,
  [AS_HELP_STRING([--enable-snmp-vrrp], [compile with SNMP vrrp support])])
AC_ARG_ENABLE(snmp-keepalived,
  [AS_HELP_STRING([--enable-snmp-keepalived], [obsolete - use --enable-snmp-vrrp])])
AC_ARG_ENABLE(snmp-checker,
  [AS_HELP_STRING([--enable-snmp-checker], [compile with SNMP checker support])])
AC_ARG_ENABLE(snmp-rfc,
  [AS_HELP_STRING([--enable-snmp-rfc], [compile with SNMP RFC2787 (VRRPv2) and SNMP RFC6527 (VRRPv3) support])])
AC_ARG_ENABLE(snmp-rfcv2,
  [AS_HELP_STRING([--enable-snmp-rfcv2], [compile with SNMP RFC2787 (VRRPv2) support])])
AC_ARG_ENABLE(snmp-rfcv3,
  [AS_HELP_STRING([--enable-snmp-rfcv3], [compile with SNMP RFC6527 (VRRPv3) support])])
AC_ARG_ENABLE(snmp-reply-v3-for-v2,
  [AS_HELP_STRING([--disable-snmp-reply-v3-for-v2], [disable RFC6527 responses for VRRPv2 instances])])
AC_ARG_ENABLE(dbus,
  [AS_HELP_STRING([--enable-dbus], [compile with dbus support])])
AC_ARG_ENABLE(dbus-create-instance,
  [AS_HELP_STRING([--enable-dbus-create-instance], [compile with dbus support for creating instances])])
AC_ARG_ENABLE(regex,
  [AS_HELP_STRING([--enable-regex], [build with HTTP_GET regex checking])])
AC_ARG_ENABLE(vmac,
  [AS_HELP_STRING([--disable-vmac], [build without VMAC support])])
AC_ARG_ENABLE(regex-timers,
  [AS_HELP_STRING([--enable-regex-timers], [build with HTTP_GET regex timers])])
AC_ARG_ENABLE(json,
  [AS_HELP_STRING([--enable-json], [compile with signal to dump configuration and stats as json])])
AC_ARG_WITH(init,
  [AS_HELP_STRING([--with-init=(upstart|systemd|SYSV|SUSE|openrc)], [specify init type])],
  [init_type="$withval"], [init_type=""])
AC_ARG_ENABLE(vrrp-auth,
  [AS_HELP_STRING([--disable-vrrp-auth], [compile without VRRP authentication])])
AC_ARG_ENABLE(checksum_compat,
  [AS_HELP_STRING([--disable-checksum-compat], [compile without v1.3.6 and earlier VRRPv3 unicast checksum compatibility])])
AC_ARG_ENABLE(routes,
  [AS_HELP_STRING([--disable-routes], [compile without ip rules/routes])])
AC_ARG_ENABLE(linkbeat,
  [AS_HELP_STRING([--disable-linkbeat], [build without linkbeat support])])
AC_ARG_ENABLE(gnu-std-paths,
  [AS_HELP_STRING([--enable-gnu-std-paths], [use GNU standard paths for pid files etc])])
AC_ARG_ENABLE(dynamic-linking,
  [AS_HELP_STRING([--enable-dynamic-linking], [compile with/without dynamically linked libiptc/libipset/libnl])])
AC_ARG_ENABLE(iptables,
  [AS_HELP_STRING([--disable-iptables], [compile without iptables support])],
  [], [IPTABLES_SILENT=Yes])
AC_ARG_ENABLE(libiptc-dynamic,
  [AS_HELP_STRING([--enable-libiptc-dynamic], [compile with libiptc dynamically linked])])
AC_ARG_ENABLE(libipset-dynamic,
  [AS_HELP_STRING([--disable-libipset-dynamic], [compile with libipset statically linked])])
AC_ARG_ENABLE(libnl-dynamic,
  [AS_HELP_STRING([--enable-libnl-dynamic], [compile with libnl dynamically linked])])
AC_ARG_ENABLE(libipset,
  [AS_HELP_STRING([--disable-libipset], [compile without libipset])])
AC_ARG_ENABLE(nftables,
  [AS_HELP_STRING([--disable-nftables], [build without nftables support])],
  [], [NFTABLES_SILENT=Yes])
AC_ARG_ENABLE(libnl,
  [AS_HELP_STRING([--disable-libnl], [compile without libnl])])
AC_ARG_ENABLE(track-process,
  [AS_HELP_STRING([--disable-track-process], [build without track-process functionality])])
AC_ARG_ENABLE(systemd,
  [AS_HELP_STRING([--disable-systemd], [build without systemd integration])])
AC_ARG_WITH(run-dir,
  [AS_HELP_STRING([--with-run-dir=PATH_TO_RUN], [specify directory where /run is located])],
  [RUN_DIR_SPECIFIED=Y], [RUN_DIR_SPECIFIED=N])
AC_ARG_WITH(tmp-dir,
  [AS_HELP_STRING([--with-tmp-dir=PATH_TO_TMP], [specify directory where run-time temporary files are to be located])],
  [TMP_DIR_SPECIFIED=Y], [TMP_DIR_SPECIFIED=N])
AC_ARG_ENABLE(strict-config-checks,
  [AS_HELP_STRING([--enable-strict-config-checks], [build with strict configuration checking])])
AC_ARG_ENABLE(hardening,
  [AS_HELP_STRING([--disable-hardening], [do not build with security hardening])])
AC_ARG_ENABLE(optimise,
  [AS_HELP_STRING([--enable-optimise], [compiler optimisation level])], [], [enable_optimise=not-specified])
AC_ARG_ENABLE(warnings,
  [AS_HELP_STRING([--enable-warnings[[=WARNINGS]]], [additional compiler warnings, disable for reduced set])], [], [enable_warnings=yes])
AC_ARG_ENABLE(extra-warnings,
  [AS_HELP_STRING([--enable-extra-warnings], [extra compiler warnings that will probably produce many warnings])])
AC_ARG_ENABLE(mem-check,
  [AS_HELP_STRING([--enable-mem-check], [compile with memory alloc checking])])
AC_ARG_ENABLE(mem-check-log,
  [AS_HELP_STRING([--enable-mem-check-log], [compile with memory alloc checking writing to syslog])])
AC_ARG_ENABLE(timer-check,
  [AS_HELP_STRING([--enable-timer-check], [compile with set time logging])])
AC_ARG_ENABLE(debug,
  [AS_HELP_STRING([--enable-debug], [compile with most debugging options])])
AC_ARG_ENABLE(netlink-timers,
  [AS_HELP_STRING([--enable-netlink-timers], [compile with netlink command timers])])
AC_ARG_ENABLE(smtp-alert-debug,
  [AS_HELP_STRING([--enable-smtp-alert-debug], [compile with smtp-alert debugging])])
AC_ARG_ENABLE(stacktrace,
  [AS_HELP_STRING([--enable-stacktrace], [compile with stacktrace support])])
AC_ARG_ENABLE(perf,
  [AS_HELP_STRING([--enable-perf], [compile with perf performance data recording support for vrrp process])])
AC_ARG_ENABLE(log-file,
  [AS_HELP_STRING([--enable-log-file], [enable logging to file (-g)])])
AC_ARG_ENABLE(dump-threads,
  [AS_HELP_STRING([--enable-dump-threads], [compile with thread dumping support])])
AC_ARG_ENABLE(epoll-debug,
  [AS_HELP_STRING([--enable-epoll-debug], [compile with epoll_wait() debugging support])])
AC_ARG_ENABLE(epoll-thread-dump,
  [AS_HELP_STRING([--enable-epoll-thread-dump], [compile with epoll thread dumping support])])
AC_ARG_ENABLE(regex-debug,
  [AS_HELP_STRING([--enable-regex-debug], [compile with regex debugging support])])
AC_ARG_ENABLE(tsm-debug,
  [AS_HELP_STRING([--enable-tsm-debug], [compile with TSM debugging support])])
AC_ARG_ENABLE(vrrp-fd-debug,
  [AS_HELP_STRING([--enable-vrrp-fd-debug], [compile with vrrp fd debugging support])])
AC_ARG_ENABLE(recvmsg-debug,
  [AS_HELP_STRING([--enable-recvmsg-debug], [compile with recvmsg() debugging support])])
AC_ARG_ENABLE(eintr-debug,
  [AS_HELP_STRING([--enable-eintr-debug], [compile with EINTR debugging support, set to check/not check for EINTR])])
AC_ARG_ENABLE(track-process-debug,
  [AS_HELP_STRING([--enable-track-process-debug], [compile with track process debugging support, set to log all process connector events])])
AC_ARG_ENABLE(parser-debug,
  [AS_HELP_STRING([--enable-parser-debug], [compile with parser debugging support])])
AC_ARG_ENABLE(checksum-debug,
  [AS_HELP_STRING([--enable-checksum-debug], [compile with checksum debugging support])])
AC_ARG_ENABLE(checker-debug,
  [AS_HELP_STRING([--enable-checker-debug], [compile with checker debugging support])])
AC_ARG_ENABLE(smtp-connect-debug,
  [AS_HELP_STRING([--enable-smtp-connect-debug], [compile with smtp connect debugging support])])
AC_ARG_ENABLE(mem-err-debug,
  [AS_HELP_STRING([--enable-mem-err-debug], [compile with MALLOC/FREE error debugging support])])
AC_ARG_ENABLE(script-debug,
  [AS_HELP_STRING([--enable-script-debug], [compile with script termination debugging support])])
AC_ARG_ENABLE(one-process-debug,
  [AS_HELP_STRING([--enable-one-process-debug], [compile with all functionality running in a single process])])
AC_ARG_ENABLE(dump-keywords,
  [AS_HELP_STRING([--enable-dump-keywords], [compile with keyword dumping support])])
AC_ARG_ENABLE(network-timestamp,
  [AS_HELP_STRING([--enable-network-timestamp], [compile with network timestamp debugging support])])
AC_ARG_ENABLE(asserts,
  [AS_HELP_STRING([--enable-asserts], [compile with assert() enabled])])
AC_ARG_WITH(fixed-if-type,
  [AS_HELP_STRING([--with-fixed-if-type=TYPE], [treat interface type TYPE as unchangeable])])
AC_ARG_WITH(default-config-file,
  AS_HELP_STRING([--with-default-config-file=FILE], [Default configuration file]),
  [default_config_file="$withval"], [default_config_file=""])
AC_ARG_WITH(default-runtime-options,
  AS_HELP_STRING([--with-default-runtime-options=OPTIONS], [Default runtime options]),
  [default_runtime_options="$withval"], [default_runtime_options="-D"])
AC_ARG_ENABLE(profile,
  [AS_HELP_STRING([--enable-profile], [compile with profiling flags])])
AC_ARG_ENABLE(strict-cast-align,
  [AS_HELP_STRING([--enable-strict-cast-align], [compile with strict cast alignment warnings])])
AC_ARG_ENABLE(cast-align-checks,
  [AS_HELP_STRING([--enable-cast-align-checks], [runtime cast alignment checks])])
AC_ARG_ENABLE(cast-via-void,
  [AS_HELP_STRING([--enable-cast-via-void], [enable pointer cast via void * (default if warns without)])]
[AS_HELP_STRING([--disable-cast-via-void], [disable pointer cast via void * (default if does not warn without)])])
AC_ARG_ENABLE(conversion-checks,
  [AS_HELP_STRING([--enable-conversion-checks], [compile with conversion warnings if sensible])])
AC_ARG_ENABLE(force-conversion-checks,
  [AS_HELP_STRING([--enable-force-conversion-checks], [compile with conversion warnings])])
AC_ARG_ENABLE(Werror,
  [AS_HELP_STRING([--enable-Werror], [compile with warnings being errors])])

AC_ARG_WITH([systemdsystemunitdir],
	AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])])

# Set the kernel headers path
if test -n "$kernel_src_path"; then
  if test ! -d $kernel_src_path/include; then
    AC_MSG_ERROR([kernel source path $kernel_src_path/include does not exist])
  fi
  if test ! -d $kernel_src_path/include/linux; then
    AC_MSG_ERROR([kernel source path $kernel_src_path/include does not appear to include linux header files])
  fi
  if test -d $kernel_src_path/include/uapi/linux; then
    AC_MSG_ERROR([kernel source path $kernel_src_path appears to be an unprocessed kernel source tree])
  fi
  kernelinc="-isystem $kernel_src_path/include"
elif test ! -d /usr/include/linux -a \
	    -d /usr/src/linux/include; then
  kernelinc="-isystem /usr/src/linux/include"
else
  kernelinc=
fi

CPPFLAGS="$kernelinc $CPPFLAGS"

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_GREP
AC_PROG_LN_S
AC_PROG_SED
AC_CHECK_TOOL(STRIP,strip)
AC_CHECK_TOOL(LDD,ldd)

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
ARFLAGS=cr
AC_SUBST(ARFLAGS)

# Default settings
ENABLE_LOG_FILE_APPEND=No

# AC_PROG_LIBTOOL

#
# save the configure arguments
#
args=`echo $ac_configure_args | $SED -e "s/'//g"`
AC_DEFINE_UNQUOTED(KEEPALIVED_CONFIGURE_OPTIONS,"$args", [configure options specified])

# Save the CPPFLAGS, CFLAGS, LDFLAGS and LDLIBS settings for make time
KA_CPPFLAGS="$kernelinc -D_GNU_SOURCE $CPPFLAGS"
KA_CFLAGS="-g $CFLAGS"
KA_LDFLAGS=$LDFLAGS
KA_LIBS=$LDLIBS

NEED_LIBDL=No
#KA_LIBTOOLFLAGS =

# Set up the compiler warnings we want
dnl -- Unused warnings - traditional
MAX_FRAME_SIZE=5120
WARNINGS_BASIC="all extra unused strict-prototypes"
WARNINGS_STD="absolute-value address-of-packed-member alloca alloc-zero array-bounds=2 attribute-alias bad-function-cast cast-align cast-qual chkp date-time disabled-optimization double-promotion duplicated-branches duplicated-cond float-conversion float-equal format-overflow format-security format-signedness format-truncation frame-larger-than=$MAX_FRAME_SIZE implicit-fallthrough=3 init-self inline jump-misses-init logical-op missing-declarations missing-field-initializers missing-prototypes nested-externs normalized null-dereference old-style-definition overlength-strings pointer-arith redundant-decls shadow shift-overflow=2 stack-protector strict-overflow=4 strict-prototypes stringop-overflow=2 suggest-attribute=cold suggest-attribute=const suggest-attribute=format suggest-attribute=malloc suggest-attribute=noreturn suggest-attribute=pure sync-nand trampolines undef uninitialized unknown-pragmas unsuffixed-float-constants unused-const-variable=2 unused-macros variadic-macros write-strings"
WARNINGS_EXTRA="aggregate-return cast-align=strict conversion format-nonliteral format-overflow=2 format-truncation=2 padded pedantic sign-conversion stack-usage=$MAX_FRAME_SIZE strict-overflow=5 stringop-overflow=3 stringop-overflow=4 switch-enum system-headers traditional-conversion"

# We want _GNU_SOURCE defined always
add_to_var([CPPFLAGS], [-D_GNU_SOURCE])

# fpclassify() needs -lm
add_to_var([KA_LIBS], [-lm])

# Some sanity checks on configure options
AS_IF([test .$enable_vrrp = .no],
    AS_IF([test .$IPTABLES_SILENT == .Yes], [enable_iptables=no])

    AS_IF([test .$enable_perf != .], [AC_MSG_ERROR([enable-perf requires vrrp])])
    AS_IF([test $with_fixed_if_type], [AC_MSG_ERROR([with-fixed-if-type requires vrrp])])
    AS_IF([test .$enable_vrrp_fd_debug != .], [AC_MSG_ERROR([enable-vrrp-fd-debug requires vrrp])])
    AS_IF([test .$enable_tsm_debug != .], [AC_MSG_ERROR([enable-tsm-debug requires vrrp])])
    AS_IF([test .$enable_recvmsg_debug != .], [AC_MSG_ERROR([enable-recvmsg-debug requires vrrp])])
    AS_IF([test .$enable_json != .], [AC_MSG_ERROR([enable-json requires vrrp])])
    AS_IF([test .$enable_snmp_vrrp != .], [AC_MSG_ERROR([enable-snmp-vrrp requires vrrp])])
    AS_IF([test .$enable_snmp_keepalived != .], [AC_MSG_ERROR([enable-snmp-keepalived requires vrrp])])
    AS_IF([test .$enable_snmp_rfc != .], [AC_MSG_ERROR([enable-snmp-rfc requires vrrp])])
    AS_IF([test .$enable_snmp_rfcv2 != .], [AC_MSG_ERROR([enable-snmp-rfcv2 requires vrrp])])
    AS_IF([test .$enable_snmp_rfcv3 != .], [AC_MSG_ERROR([enable-snmp-rfcv3 requires vrrp])])
    AS_IF([test .$enable_dbus != .], [AC_MSG_ERROR([enable-dbus requires vrrp])])
    AS_IF([test .$enable_vrrp_auth != .], [AC_MSG_ERROR([disable-vrrp-auth requires vrrp])])
    AS_IF([test .$enable_checksum_compat != .], [AC_MSG_ERROR([disable-checksum-compat requires vrrp])])
    AS_IF([test .$enable_routes != .], [AC_MSG_ERROR([disable-routes requires vrrp])])
    AS_IF([test .$enable_linkbeat != .], [AC_MSG_ERROR([disable-linkbeat requires vrrp])])
    AS_IF([test .$enable_bfd != .], [AC_MSG_ERROR([enable-bfd requires vrrp])])
    AS_IF([test .$enable_iptables != .no], [AC_MSG_ERROR([enable-iptables requires vrrp])])
    AS_IF([test .$enable_track_process != .], [AC_MSG_ERROR([enable-track-process requires vrrp])])
    AS_IF([test .$enable_network_timestamp != .], [AC_MSG_ERROR([enable-network-timestamp requires vrrp])])
    AS_IF([test .$enable_netlink_timers != .], [AC_MSG_ERROR([enable-netlink-timers requires vrrp])])
  )
AS_IF([test .$enable_iptables = .no],
    AS_IF([test .$enable_libipset != .], [AC_MSG_ERROR([disable-libipset requires vrrp and iptables])])
  )
AS_IF([test .$enable_libipset = .no],
    AS_IF([test .$enable_libipset_dynamic != .], [AC_MSG_ERROR([disable-libipset-dynamic requires ipsets])])
  )
AS_IF([test .$enable_snmp_rfc != .yes -a .$enable_snmp_rfcv3 != yes],
    AS_IF([test .$enable_snmp_reply_v3_for_v2 != .], [AC_MSG_ERROR([enable-snmp-reply-v3-for-v2 requires enable-snmp-rfcv3 or enable-snmp-rfc])])
  )
AS_IF([test .$enable_dbus != .yes],
    AS_IF([test .$enable_dbus_create_instance != .], [AC_MSG_ERROR([enable-dbus-create-instance requires enable-dbus])])
  )
AS_IF([test .$enable_lvs = .no],
    AS_IF([test .$enable_regex != .], [AC_MSG_ERROR([enable-regex requires lvs])])
    AS_IF([test .$enable_libnl != .], [AC_MSG_ERROR([disable-libnl requires lvs])])
    AS_IF([test .$enable_lvs_syncd != .], [AC_MSG_ERROR([disable-lvs-syncd requires lvs])])
    AS_IF([test .$enable_lvs_64bit_stats != .], [AC_MSG_ERROR([disable-lvs-64bit-stats requires lvs])])
    AS_IF([test .$enable_fwmark != .], [AC_MSG_ERROR([enable-fwmark requires lvs])])
    AS_IF([test .$enable_checker_debug != .], [AC_MSG_ERROR([enable-checker-debug requires lvs])])
  )
AS_IF([test .$enable_libnl = .no],
    AS_IF([test .$enable_libnl_dynamic != .], [AC_MSG_ERROR([enable-libnl-dynamic requires lvs and libnl])])
  )
AS_IF([test .$enable_regex != .yes],
    AS_IF([test .$enable_regex_timers != .], [AC_MSG_ERROR([enable-regex-timers requires enable-regex])])
    AS_IF([test .$enable_regex_debug != .], [AC_MSG_ERROR([enable-regex-debug requires enable-regex])])
  )
AS_IF([test .$enable_track_process = .no],
    AS_IF([test .$enable_track_process_debug != .], [AC_MSG_ERROR([enable-track-process-debug incompatible with disable-track-process])])
  )
AS_IF([test .$enable_mem_check != .yes],
    AS_IF([test .$enable_mem_err_debug != .], [AC_MSG_ERROR([enable-mem-err-debug requires --enable-mem-check])])
  )

# --enable-debug enables most debugging if not explicitly disabled, but NOT one-process-debug
AS_IF([test .$enable_debug = .yes],
  [
    # If we are debugging, we want to be able to write logs to files
    AS_IF([test .$enable_log_file = .], [enable_log_file=yes])

    AS_IF([test .$enable_asserts = .], [enable_asserts=yes])
    AS_IF([test .$enable_epoll_debug = .], [enable_epoll_debug=yes])
    AS_IF([test .$enable_epoll_thread_dump = .], [enable_epoll_thread_dump=yes])
    AS_IF([test .$enable_eintr_debug = .], [enable_eintr_debug=yes])
    AS_IF([test .$enable_parser_debug = .], [enable_parser_debug=yes])
    AS_IF([test .$enable_timer_check = .], [enable_timer_check=yes])
    AS_IF([test .$enable_smtp_alert_debug = .], [enable_smtp_alert_debug=yes])
    AS_IF([test .$enable_smtp_connect_debug = .], [enable_smtp_connect_debug=yes])
    AS_IF([test .$enable_dump_keywords = .], [enable_dump_keywords=yes])
    AS_IF([test .$enable_script_debug = .], [enable_script_debug=yes])

    AS_IF([test .$enable_vrrp != .no],
      [
	AS_IF([test .$enable_vrrp_fd_debug = .], [enable_vrrp_fd_debug=yes])
	AS_IF([test .$enable_tsm_debug = .], [enable_tsm_debug=yes])
	AS_IF([test .$enable_recvmsg_debug = .], [enable_recvmsg_debug=yes])
	AS_IF([test .$enable_track_process_debug = .], [enable_track_process_debug=yes])
	AS_IF([test .$enable_checksum_debug = .], [enable_checksum_debug=yes])
	AS_IF([test .$enable_netlink_timers = .], [enable_netlink_timers=yes])
	AS_IF([test .$enable_network_timestamp = .], [enable_network_timestamp=yes])
      ])

    AS_IF([test .$enable_lvs != .no],
      [
	AS_IF([test .$enable_checker_debug = .], [enable_checker_debug=yes])
	AS_IF([test .$enable_regex = .yes],
	  [
	    AS_IF([test .$enable_regex_timers = .], [enable_regex_timers=yes])
	    AS_IF([test .$enable_regex_debug = .], [enable_regex_debug=yes])
	  ])
      ])

    AS_IF([test .$enable_mem_check = .yes],
      [
	AS_IF([test .$enable_mem_err_debug = .], [enable_mem_err_debug=yes])
      ])
  ])

dnl -- Do we want -Wcast-align=strict?
AS_IF([test .$enable_strict_cast_align = .yes],
      [WARNINGS_STD=$(echo $WARNINGS_STD | sed -e "s/cast-align /cast-align=strict /")])

dnl -- check if we are using LTO. There is a GCC bug which means that when addattr_l()
dnl -- is inlined, GCC (up to at least v11.1.1) ignores RELAX_STRINGOP_OVERFLOW and issues
dnl -- -Wstringop-overflow warnings
dnl -- I haven't been able to produce a test case to demonstrate this GCC bug, so we can't
dnl -- test it here, nor have I been able to report a bug upstream to GCC.
AC_MSG_CHECKING([if using Link Time Optimisation])
echo " $CFLAGS " | grep -q -- " -flto=auto "
AS_IF([test $? -eq 0],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([LTO_NOINLINE], [ __attribute__((noinline)) ], [Define to not inline if using LTO])
  ], [
    AC_MSG_RESULT([no])
    AC_DEFINE([LTO_NOINLINE], [], [Define to not inline if using LTO])
  ])

dnl -- ulibc/glibc differences
AC_MSG_CHECKING([msghdr.msg_controllen is size_t])
SAV_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <sys/socket.h>
  #include <stdio.h>

  int main(int argc, char**argv)
  {
    struct msghdr msgh = { .msg_controllen = 0 };

    printf("%zu", msgh.msg_controllen);
  }
  ]])],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([PRI_MSG_CONTROLLEN], [ "zu" ], [Define to zu if msghdr.msg_controllen is size_t, else u])
  ],
  [
    AC_MSG_RESULT([no])
    AC_DEFINE([PRI_MSG_CONTROLLEN], [ "u" ], [Define to zu if msghdr.msg_controllen is size_t, else u])
  ])
CFLAGS=$SAV_CFLAGS

dnl -- Check for diagnostic pragmas in functions - GCC 4.6.0
AC_MSG_CHECKING([diagnostic pragmas in functions])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  int main(int argc, char**argv)
  {
_Pragma("GCC diagnostic warning \"-Wall\"")
  }
  ]])],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_FUNCTION_DIAGNOSTIC_PRAGMAS_], [ 1 ], [Define to 1 if can have _Pragma GCC diagnostic in functions])
  ],
  [
    AC_MSG_RESULT([no])
  ])
AM_CONDITIONAL([DEBUG], [test .$enable_debug = .yes])

dnl -- Check for diagnostic push/pop pragmas - GCC 4.6.0
AC_MSG_CHECKING([diagnostic push/pop pragmas])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  int main(int argc, char**argv)
  {
_Pragma("GCC diagnostic push")
  }
  ]])],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_DIAGNOSTIC_PUSH_POP_PRAGMAS_], [ 1 ], [Define to 1 if can have _Pragma GCC diagnostic push/pop])
  ],
  [
    AC_MSG_RESULT([no])
  ])

dnl - Set up warnings list
AS_IF([test ".$enable_warnings" = .no],
      [WARNINGS_ENABLED=$WARNINGS_BASIC],
      [WARNINGS_ENABLED="$WARNINGS_BASIC $WARNINGS_STD"
       AS_IF([test ".$enable_warnings" != .yes],
	     [WARN_LIST=`echo $enable_warnings | sed -e "s/-W//g"`
	      add_to_var([WARNINGS_ENABLED], ["$WARN_LIST"])
	     ])
      ]
     )
AS_IF([test .$enable_extra_warnings = .yes],
      [add_to_var([WARNINGS_ENABLED], ["$WARNINGS_EXTRA"])])

if test "$enable_conversion_checks" = yes; then
  # Check if we can sensibly enable -Wconversion
  AC_MSG_CHECKING([for usable -Wconversion])
  SAV_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS -Wconversion -O2 -Wp,-D_FORTIFY_SOURCE=2 -Werror"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <sys/types.h>
    #include <sys/select.h>
    #include <stdint.h>
    #include <stdbool.h>
    #include <sys/socket.h>
    #include <linux/rtnetlink.h>

    #define VAL	255

    static void
    fun(uint8_t val)
    {
    }

    int main(int argc, char**argv)
    {
      fd_set set;
      uint8_t	val = 42;
      unsigned u;
      bool b;
      size_t size = 17;
      char c[2];
      char *c_ptr = c;
      struct rtattr rta;
      struct rtattr *rta_p = &rta;

      FD_SET(argc+1, &set);

      fun(argc == VAL ? VAL : val);

      //      vrrp->lower_prio_no_advert = vrrp->strict_mode ? true : global_data->vrrp_lower_prio_no_advert;
      u = u ? true : b;

      size = RTA_LENGTH(size);
      c_ptr = RTA_DATA(c_ptr);
      rta_p = RTA_NEXT(rta_p, size);

      val = (u < 256 ) ? u & 0xff : 0;
    }
    ]])],
    [
      AC_MSG_RESULT([yes])
      add_to_var([WARNINGS_ENABLED], [conversion])
    ],
    [
      AC_MSG_RESULT([no])
      AC_MSG_WARN([-Wconversion is not sensible with this compiler. Use --enable-force-conversion-checks to override.])
    ])
  CFLAGS="$SAV_CFLAGS"
elif test "$enable_force_conversion_checks" = yes; then
  add_to_var([WARNINGS_ENABLED], [conversion])
fi

if test "$enable_Werror" = yes; then
  add_to_var([WARNINGS_ENABLED], [error])
fi

CONFIG_WARNINGS=lib/config_warnings.h.in

# Save (or restore) lib/config_warnings.h.in
AS_IF([test ! -f ${CONFIG_WARNINGS}.sav],
      [cp -p ${CONFIG_WARNINGS} ${CONFIG_WARNINGS}.sav],
      [cp -p ${CONFIG_WARNINGS}.sav ${CONFIG_WARNINGS}])

SAV_CFLAGS="$CFLAGS"
for WARN in $WARNINGS_ENABLED
do
  AC_MSG_CHECKING([for -W$WARN])
  CFLAGS="$SAV_CFLAGS -W$WARN"

  WARN_VAR=_HAVE_WARNING_`echo $WARN | tr "a-z=-" "A-Z__"`_
  LOCAL_WARN_VAR=HAVE_WARNING_`echo $WARN | sed -e "s/=.*//" | tr "a-z-" "A-Z_"`
  grep -q "^#undef $WARN_VAR$" $CONFIG_WARNINGS
  AS_IF([test $? -ne 0],
	[echo -e "\n/* Define to 1 if -W$WARN in use */\n#undef $WARN_VAR" >>$CONFIG_WARNINGS]
       )

  test `echo $WARN | grep "=[[0-9]][[0-9]]*$"`
  AS_IF([test $? -eq 0],
	[ WARN_SHORT=`echo $WARN | sed -e 's/=[[0-9]][[0-9]]*$//'`
	  WARN_VAR_SHORT=_HAVE_WARNING_`echo $WARN_SHORT | tr "a-z=-" "A-Z__"`_
	  grep -q "^#undef $WARN_VAR_SHORT$" $CONFIG_WARNINGS
	  AS_IF([test $? -ne 0],
		[echo -e "\n/* Define to 1 if -W$WARN_SHORT in use */\n#undef $WARN_VAR_SHORT" >>$CONFIG_WARNINGS]
	       )
	],
	[ unset WARN_VAR_SHORT ]
       )

  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    int main(int argc, char**argv)
    {
    }
    ]])],
    [
      # gcc 9 removed -Wchkp and doesn't error if it is specified,
      # but rather outputs:
      #  warning: switch '-Wchkp' is no longer supported
      # so check for the warning.
      touch conftest.err
      grep -q "is no longer supported" conftest.err
      AS_IF([test $? -ne 0],
       [
	AC_MSG_RESULT([yes])
	eval $LOCAL_WARN_VAR=yes
	add_to_var([KA_CFLAGS], [-W$WARN])
	AC_DEFINE_UNQUOTED([$WARN_VAR], [ 1 ])
	AS_IF([test -z "$WARN_VAR_SHORT"], [],
	      [AC_DEFINE_UNQUOTED([$WARN_VAR_SHORT], [ 1 ])]
	     )
       ],
       [
	AC_MSG_RESULT([no])
	eval $LOCAL_WARN_VAR=no
       ])
    ],
    [
      AC_MSG_RESULT([no])
      eval $LOCAL_WARN_VAR=no
    ])
done
AS_IF([test .$HAVE_WARNING_STRICT_OVERFLOW = .yes],
      [
	# The following is not supported in gcc 5.4.0
	CFLAGS="$CFLAGS -Werror"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	  _Pragma("GCC diagnostic warning \"-Wstrict-overflow=1\"")
	  int main(int argc, char**argv)
	  {
	  }
	  ]])],
	  [AC_DEFINE([_HAVE_PRAGMA_WARN_STRICT_OVERFLOW_1_], [ 1 ], [Define to 1 if _Pragma("GCC diagnostic warning \"-Wstrict-overflow=1\"") supported])
	  ])
      ]
     )
CFLAGS="$SAV_CFLAGS"

dnl ---- [ Do we want stricter configuration checking? ] ----
STRICT_CONFIG=No
if test "$enable_strict_config_checks" = yes; then
  AC_DEFINE([_STRICT_CONFIG_], [ 1 ], [Define to 1 if want stricter configuration checking])
  STRICT_CONFIG=Yes
  add_config_opt([STRICT_CONFIG])
fi
AM_CONDITIONAL([WITH_STRICT_CONFIG_CHECKS], [test $STRICT_CONFIG = Yes])

if test "$enable_hardening" != no; then
  AC_MSG_CHECKING([for PIE support])
  SAV_CFLAGS="$CFLAGS"
  SAV_LDFLAGS="$LDFLAGS"
  CFLAGS="$CFLAGS -fPIE"
  if test "${enable_profile}" = yes; then
    # RHEL 7 and others have a problem with profiling with PIE
    CFLAGS="$CFLAGS -pg"
  fi
  LDFLAGS="$LDFLAGS -pie"
  AC_LINK_IFELSE([AC_LANG_SOURCE([[
    int main(int argc, char **argv)
    {
      int i = 0;
    }
    ]])],
    AC_MSG_RESULT([yes])
      add_to_var([KA_CFLAGS], [-fPIE])
      add_to_var([KA_LDFLAGS], [-pie]),
    AC_MSG_RESULT([no]))
  CFLAGS=$SAV_CFLAGS
  LDFLAGS=$SAV_LDFLAGS

  for FLAG in \
	  "-Wformat -Werror=format-security" \
	  "-Wp,-D_FORTIFY_SOURCE=2" \
	  "-fexceptions" \
	  "-fstack-protector-strong" \
	  "--param=ssp-buffer-size=4" \
	  "-grecord-gcc-switches"
  do
    AC_MSG_CHECKING([for $FLAG support])
    CFLAGS="$CFLAGS $FLAG"
    AC_COMPILE_IFELSE(
      [AC_LANG_SOURCE([[ ]])],
      [AC_MSG_RESULT([yes])]
	add_to_var([KA_CFLAGS], [$FLAG]),
      [AC_MSG_RESULT([no])])
    CFLAGS=$SAV_CFLAGS
  done

  WL_FLAGS=
  for FLAG in \
	  "-z,relro" \
	  "-z,now"
  do
    AC_MSG_CHECKING([for -Wl,$FLAG support])
    LDFLAGS="$LDFLAGS -Wl,$FLAG"
    AC_LINK_IFELSE(
      [AC_LANG_SOURCE([[
      int main(int argc, char **argv)
      {
	int i = 0;
      }
      ]])],
      [
	AC_MSG_RESULT([yes])
	WL_FLAGS="$WL_FLAGS -Wl,$FLAG"
      ],
      [AC_MSG_RESULT([no])]
    )
    CFLAGS=$SAV_CFLAGS
    LDFLAGS=$SAV_LDFLAGS
  done
  if test -n "$WL_FLAGS"; then
    add_to_var([KA_LDFLAGS], [$WL_FLAGS])
  fi
fi

# enable-optimise
AS_IF([test "$enable_optimise" = yes -o "$enable_optimise" = not-specified], [optimise_level=2], [optimise_level=$enable_optimise])
AS_IF([test "$enable_optimise" = no], [optimise_level=0])
AS_IF([test "$optimise_level" -eq 0],
  [
    echo $KA_CFLAGS | $GREP -q -- "-D_FORTIFY_SOURCE=[[^0]]"
    AS_IF([test $? -eq 0], [AC_MSG_WARN([--disable-optimise requires --disable-hardening])])
  ])
FLAG="-O$optimise_level"
AC_MSG_CHECKING([for $FLAG support])
SAV_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS $FLAG"
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE([[ ]])],
  [AC_MSG_RESULT([yes])]
    add_to_var([KA_CFLAGS], [$FLAG]),
  [
    AC_MSG_RESULT([no])
    AS_IF([test "$enable_optimise" != not-specified], [AC_MSG_ERROR([Invalid optimisation level specified])])
  ])
CFLAGS=$SAV_CFLAGS

AC_SUBST(KA_CPPFLAGS)
AC_SUBST(KA_CFLAGS)
AC_SUBST(KA_LDFLAGS)
AC_SUBST(KA_LIBS)
# AC_SUBST(KA_LIBTOOLFLAGS)

# Check if unaligned memory access is supported (for ARM not supported prior to ARMv6 processors)
AC_MSG_CHECKING([for unaligned memory access])
AC_RUN_IFELSE(
  [
    AC_LANG_PROGRAM(
      [[
	#include <limits.h>
	#include <endian.h>

	#if __BYTE_ORDER == __BIG_ENDIAN
	#if ULONG_MAX == 0xffffffffffffffffUL
	#define CHK_VAL       0x1234567890abcdefUL
	#elif ULONG_MAX == 0xffffffffUL
	#define CHK_VAL       0x12345678UL
	#else
	#define CHK_VAL       0x1234UL
	#endif
	#elif __BYTE_ORDER == __LITTLE_ENDIAN
	#if ULONG_MAX == 0xffffffffffffffffUL
	#define CHK_VAL       0xefcdab9078563412UL
	#elif ULONG_MAX == 0xffffffffUL
	#define CHK_VAL       0x78563412UL
	#else
	#define CHK_VAL       0x3412UL
	#endif
	#else
	#error Neither big nor little endian - unsupported
	#endif
      ]],
      [[
	unsigned long arr[2] = { 0, 0 };
	unsigned char *p = (unsigned char *)arr + 1;
	unsigned i;

	*(unsigned long *)p = CHK_VAL;

	return !!(arr[0] == CHK_VAL || p[0] != 0x12 || p[1] != 0x34 || p[2] != 0x56);
      ]]
    )
  ],
  [AC_MSG_RESULT([yes])],
  [
    AC_MSG_RESULT([no])
    AC_DEFINE([_NO_UNALIGNED_ACCESS_], [ 1 ], [Define to 1 if unaligned memory access not supported])
  ],
  [
    AC_MSG_RESULT([unknown])
    AC_MSG_WARN([Cannot determine if unaligned access supported. Assuming yes.])
  ]
 )

# Check if unaligned memory access creates warnings
AC_MSG_CHECKING([for unaligned memory access causes warnings])
UNALIGNED_ACCESS_WARNED=0
SAV_CFLAGS="$CFLAGS"
CFLAGS=$(echo $KA_CFLAGS | sed -e "s/.*\(-Wcast-align[[^ ]]*\) .*/\1/")
CFLAGS="$CFLAGS -Werror"
AC_COMPILE_IFELSE(
  [
    AC_LANG_PROGRAM(
      [],
      [[
        char c;
	int i = *(int *)&c;
      ]]
    )
  ],
  [AC_MSG_RESULT([no])],
  [
    AC_MSG_RESULT([yes])
    UNALIGNED_ACCESS_WARNED=1
  ],
  [
    AC_MSG_RESULT([unknown])
    AC_MSG_WARN([Cannot determine if unaligned access supported. Assuming yes.])
  ]
 )
CFLAGS="$SAV_CFLAGS"

dnl - Do we want/need to cat via a void *?
AS_IF([test .$enable_cast_via_void = .no],
  [],
  [
    AS_IF([test .$enable_cast_via_void = .yes -o $UNALIGNED_ACCESS_WARNED -eq 1],
      AC_DEFINE([CAST_VIA_VOID], [ 1 ], [Define to 1 to cast via void *]))
  ]
)

dnl -- Runtime check cast alignments?
AS_IF([test .$enable_cast_align_checks = .yes],
      AC_DEFINE([CHECK_CAST_ALIGN], [ 1 ], [Define to 1 to do runtime cast alignment checks]))

# Checks for libraries.
dnl clock_gettime() required -lt before glibc 2.17
AC_MSG_CHECKING([for clock_gettime() requires -lrt])
AC_LINK_IFELSE([AC_LANG_SOURCE([[
  #include <time.h>
  int main(int argc, char **argv)
  {
    int i;
    struct timespec ts;

    i = clock_gettime(CLOCK_MONOTONIC, &ts);
  }
  ]])],
  [AC_MSG_RESULT([no])],
  [
    SAV_LIBS="$LIBS"
    LIBS="$LIBS -lrt"
    AC_LINK_IFELSE([AC_LANG_SOURCE([[
      #include <time.h>
      int main(int argc, char **argv)
      {
	int i;
	struct timespec ts;

	i = clock_gettime(CLOCK_MONOTONIC, &ts);
      }
      ]])],
      [AC_MSG_RESULT([yes])]
	add_to_var([KA_LIBS], [-lrt]),
      [AC_MSG_ERROR([clock_gettime() not supported])])
    LIBS=$SAV_LIBS
  ])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/prctl.h sys/socket.h sys/time.h syslog.h unistd.h],
  [], [AC_MSG_ERROR([Missing/unusable system header file <$ac_header>])])

# check for kernel headers
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"

dnl -- linux/errqueue.h need sys/time.h before Linux < v5.1
AC_MSG_CHECKING([linux/errqueue.h needs sys/time.h])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <fcntl.h>
  #include <linux/errqueue.h>

  int main(int argc, char**argv)
  {
  }
  ]])],
  [
    AC_MSG_RESULT([no])
  ],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([ERRQUEUE_NEEDS_SYS_TIME], [ 1 ], [Define to 1 if linux/errqueue.h needs sys/time.h])
  ])

AC_CHECK_HEADERS([asm/types.h linux/ethtool.h linux/icmpv6.h linux/if_ether.h linux/if_packet.h linux/ip.h linux/sockios.h linux/types.h],
  [], [AC_MSG_ERROR([Missing/unusable kernel header file <$ac_header>])])
AC_CHECK_HEADERS([linux/fib_rules.h linux/if_addr.h linux/if_link.h],
  [], [AC_MSG_ERROR([Missing/unusable kernel header file <$ac_header>])],
  [[$NETLINK_EXTRA_INCLUDE]])
AC_CHECK_HEADERS([linux/if_arp.h],
  [], [AC_MSG_ERROR([Missing/unusable <$ac_header>])],
  [[#include <sys/socket.h>]])
CPPFLAGS="$SAV_CPPFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_C_CONST

# Checks for library functions.
AC_FUNC_FORK
# We don't want the following two, since autoconf, if malloc(0) returns NULL, refines malloc as rpl_malloc
# and we have to provide our own rpl_malloc() and likewise rpl_realloc() functions.
# keepalived doesn't do 0 length malloc()s so it is not an issue.
# We add malloc and realloc to AC_CHECK_FUNCS instead.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
dnl - dup3 since Linux 2.6.27 and glibc 2.9
AC_CHECK_FUNCS([dup2 dup3 getcwd gettimeofday malloc memmove memset realloc select setenv socket strcasecmp strchr strdup strerror strpbrk strstr strtol strtoul uname])
dnl - vsyslog() Not defined by Posix, but available in glibc and musl
AC_CHECK_FUNCS([vsyslog], [add_system_opt([VSYSLOG])])

dnl - memfd_create() - since Linux 3.17 and glibc 2.27
dnl - memfd_create() appeared in the kernel long before it appeared in
dnl -   glibc so we use the raw syscall if it is available
AC_CHECK_FUNCS([memfd_create], [add_system_opt([MEMFD_CREATE])])
AS_IF([test "x$ac_cv_func_memfd_create" != xyes],
  [
    AC_CHECK_DECLS([__NR_memfd_create],
      [AC_DEFINE([USE_MEMFD_CREATE_SYSCALL], [ 1 ], [Use syscall for memfd_create])], [],
      [[#include <sys/syscall.h>]])
  ])

dnl - Since Linux 3.17
AC_CHECK_DECLS([O_TMPFILE], [], [], [[#include <fcntl.h>]])

# glibc uses unsigned int as 3rd parameter to __assert_fail(), musl uses int.
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <assert.h>
  #include <stdlib.h>

  void __assert_fail(const char * a, const char *b, unsigned int l, const char *c)
  {
    exit(a[0] + b[0] + c[0] + l == 0);
  }
  ]])],
  [LINE_type="unsigned int"], [LINE_type="int"])
AC_DEFINE_UNQUOTED([LINE_type], [ $LINE_type ], [The type of parameter __line passed to __assert_fail()])

dnl Check if libc supports __always_inline
dnl See glibc sys/cdefs.h definition of __always_inline and comment
SAV_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -Wattributes -Werror"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <stdlib.h>
  static __always_inline int
  test_func(int val)
  {
    return val;
  }

  int
  main(int argc, char **argv)
  {
    int val = test_func(3);
    return val;
  }
  ]])],
  [],
  [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    static __inline __attribute__ ((__always_inline__)) int
    test_func(int val)
    {
      return val;
    }

    int
    main(int argc, char **argv)
    {
      int val = test_func(3);
      return val;
    }
    ]])],
    [AC_DEFINE([__always_inline], [__inline __attribute__ ((__always_inline__))], [Define  __always_inline if libc does not define it])],
    [AC_DEFINE([__always_inline], [inline], [Define __always_inline if libc does not define it])]
  )])
CFLAGS="$SAV_CFLAGS"

dnl - Do we want to override dynamic/static linking?
AS_IF([test "$enable_dynamic_linking"],
  [
    AS_IF([test .$enable_vrrp != .no],
      [
	enable_libiptc_dynamic=$enable_dynamic_linking
	enable_libipset_dynamic=$enable_dynamic_linking
      ])
    AS_IF([test .$enable_lvs != .no],
      [
	enable_libnl_dynamic=$enable_dynamic_linking
      ])
  ])

# check for missing definition - added in glibc 2.8
AC_CHECK_DECLS([ETHERTYPE_IPV6], [],
  [
    AC_DEFINE([ETHERTYPE_IPV6], [0x86dd], [Defined here if not found in <net/ethernet.h>.])
  ],
  [[#include <net/ethernet.h>]])

dnl ----[ Checks for openssl ]----
# check for openssl headers
NEED_EVP=no
NEED_SSL=no
if test "$enable_vrrp" != no -a \
	"$enable_vrrp_auth" != no; then
  NEED_EVP=yes
fi
if test "$enable_lvs" != no; then
  NEED_EVP=yes
  NEED_SSL=yes
fi
AC_CHECK_HEADERS([openssl/ssl.h openssl/err.h], [],
  [
    if test $NEED_SSL = yes; then
      AC_MSG_ERROR([
  !!! OpenSSL is not properly installed on your system. !!!
  !!! Can not include OpenSSL headers files.            !!!])
    fi
    NEED_SSL=no
    break
  ])
AC_CHECK_HEADERS([openssl/md5.h openssl/evp.h], [],
  [
    if test $NEED_EVP = yes; then
      AC_MSG_ERROR([
  !!! OpenSSL is not properly installed on your system. !!!
  !!! Can not include OpenSSL EVP headers files.        !!!])
    fi
    NEED_EVP=no
    break
  ])
unset LIBS

$PKG_CONFIG --exists openssl
if test $? -eq 0; then
  add_pkg_config([openssl], [OPENSSL])
else
  OPENSSL_LIBS="-lssl -lcrypto"
fi

EXTRA_LIBS=`echo $OPENSSL_LIBS | sed -e "s/-lcrypto//"`
AC_CHECK_LIB(crypto, EVP_DigestInit_ex, [],
  [
    if test $NEED_EVP = yes; then
      AC_MSG_ERROR([OpenSSL EVP libraries are required])
    fi
  ], [$EXTRA_LIBS])
if test $NEED_EVP = yes; then
  add_to_var([KA_LIBS], [$LIBS])
fi
unset LIBS

EXTRA_LIBS=`echo $OPENSSL_LIBS | sed -e "s/-lssl//"`
AC_CHECK_LIB(ssl, SSL_CTX_new, [],
  [
    if test $NEED_SSL = yes; then
      AC_MSG_ERROR([OpenSSL libraries are required])
    fi
  ], [$EXTRA_LIBS])
if test $NEED_SSL = yes; then
  add_to_var([KA_LIBS], [$LIBS])
fi
unset LIBS

# Introduced in OpenSSL ver 0.9.9
LIBS=$OPENSSL_LIBS
AC_MSG_CHECKING([SSL_set_tlsext_host_name() - may be a definition])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <openssl/ssl.h>
    int main(void)
    {
      request_t req;
      SSL_set_tlsext_host_name(req.ssl, "SSL");
    }
  ]])], [
    AC_MSG_RESULT([no])
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_SSL_SET_TLSEXT_HOST_NAME_], [ 1 ], [Define to 1 if have SSL_set_tlsext_host_name()])
])

# SSL_CTX_set_verify_depth() introduced OpenSSL v0.9.5a
AC_CHECK_FUNCS([SSL_CTX_set_verify_depth])

# SSL_set0_rbio(), SSL_set0_wbio() OPENSSL_init_crypto() and TLS_method() introduced OpenSSL v1.1.0
AC_CHECK_FUNCS([SSL_set0_rbio OPENSSL_init_crypto TLS_method])

# In OpenSSL v1.1.1 the call to SSL_CTX_new() fails if OPENSSL_init_crypto() has been called with
# OPENSSL_INIT_NO_LOAD_CONFIG. It does not fail in v1.1.0h and v1.1.1b.
AS_IF([test .$ac_cv_func_OPENSSL_init_crypto = .yes],
      [
	AS_IF([test .$ac_cv_func_TLS_method = .yes], [method_func=TLS_method], [method_func=SSLv23_method])
	AC_RUN_IFELSE(
	  [AC_LANG_PROGRAM(
	    [[#include <openssl/ssl.h>]],
	    [[
	      const SSL_METHOD *meth;
	      SSL_CTX *ctx;

	      if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
		return 1;

	      /* Initialize SSL context */
	      meth = $method_func();
	      if (!(ctx = SSL_CTX_new(meth)))
		return 1;
	      return 0;
	    ]])],
	  [openssl_init_no_load_bug=0],
	  [openssl_init_no_load_bug=1],
	  [
	    AC_MSG_WARN([Cannot determine if need to OPENSSL_init_crypto() problem. Assuming yes for safety.])
	    openssl_init_no_load_bug=1
	  ]
	)
	AS_IF([test $openssl_init_no_load_bug -eq 1],
	      [AC_DEFINE([HAVE_OPENSSL_INIT_NO_LOAD_CONFIG_BUG], [ 1 ], [Define to 1 if OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG) bug)])])
      ])
unset LIBS

dnl ----[ Check for IPv4 devconf netlink support ]----
IPV4_DEVCONF=No
if test .$enable_vrrp != .no; then
  dnl ----[Check have IPV4_DEVCONF defines - since Linux 3.11]----
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"
  IPV4_DEVCONF=Yes
  AC_CHECK_DECLS([
    IPV4_DEVCONF_ARP_IGNORE,
    IPV4_DEVCONF_ACCEPT_LOCAL,
    IPV4_DEVCONF_RP_FILTER,
    IPV4_DEVCONF_ARPFILTER],
    [],
    [
      IPV4_DEVCONF=No
      break
    ],
    [[#include <linux/ip.h>]])
  if test $IPV4_DEVCONF = Yes; then
    AC_DEFINE([_HAVE_IPV4_DEVCONF_], [ 1 ], [Define to 1 if have IPv4 netlink device configuration])
    add_system_opt([IPV4_DEVCONF])
  fi
  AC_CHECK_HEADERS([linux/rtnetlink.h], [], [AC_MSG_ERROR([Unusable linux/rtnetlink.h])], [$RTNETLINK_EXTRA_INCLUDE])
  CPPFLAGS="$SAV_CPPFLAGS"
fi

dnl ----[ Checks for libraries ]----
NETLINK_VER=0
IPVS_USE_NL=No
if test .$enable_lvs != .no -a .${enable_libnl} != .no; then
  $PKG_CONFIG --exists libnl-3.0
  if test $? -eq 0; then
    add_pkg_config([libnl-3.0], [NL3], [remove-requires])
    AC_CHECK_LIB($NL3_LIB_NAMES, nl_socket_alloc,
      [
	NETLINK_VER=3

	AC_DEFINE([_HAVE_LIBNL3_], [ 1 ], [Define to 1 if using libnl-3])
	add_system_opt([LIBNL3])
	if test .$enable_libnl_dynamic = .yes; then
	  add_system_opt([LIBNL_DYNAMIC])
	  add_pkg_config_without_libs([libnl-3.0])
	  AC_DEFINE([_LIBNL_DYNAMIC_], [ 1 ], [Define to 1 if building with libnl dynamic linking])
	  NEED_LIBDL=Yes
	  get_lib_name([$NL3_LIB_NAMES], [nl_socket_alloc])
	  AC_DEFINE_UNQUOTED([NL3_LIB_NAME], [ "$LIB_NAME" ], [Define the nl-3 library name])
	else
	  add_pkg_config([libnl-3.0])
	fi

	add_pkg_config([libnl-genl-3.0], [GENL], [remove-requires])
	AC_CHECK_LIB($GENL_LIB_NAMES, genl_connect, [],
	  [AC_MSG_ERROR([libnl-3 is installed but not libnl-gen-3. Please, install libnl-gen-3/libnl-genl-3.])],
	  [$NL3_LIBS])
	IPVS_USE_NL=Yes
	if test .$enable_libnl_dynamic = .yes; then
	  add_pkg_config_without_libs([libnl-genl-3.0])
	  get_lib_name([$GENL_LIB_NAMES], [genl_connect])
	  AC_DEFINE_UNQUOTED([NL3_GENL_LIB_NAME], [ "$LIB_NAME" ], [Define the nl-genl-3.0 library name])
	else
	  add_pkg_config([libnl-genl-3.0])
	fi
      ], [])
  fi

  if test $NETLINK_VER -eq 0; then
    AC_CHECK_LIB(nl, nl_socket_modify_cb,
      [
	IPVS_USE_NL=Yes
	NETLINK_VER=1
	AC_DEFINE([_HAVE_LIBNL1_], [ 1 ], [Define to 1 if using libnl-1])
	add_system_opt([LIBNL1])
	if test .$enable_libnl_dynamic = .yes; then
	  add_pkg_config_without_libs([libnl-1])
	  add_config_opt([LIBNL_DYNAMIC])
	  AC_DEFINE([_LIBNL_DYNAMIC_], [ 1 ], [Define to 1 if building with libnl dynamic linking])
	  NEED_LIBDL=Yes
	  get_lib_name([nl], [nl_socket_modify_cb])
	  AC_DEFINE_UNQUOTED([NL_LIB_NAME], [ "$LIB_NAME" ], [Define the nl library name])
	else
	  add_pkg_config([libnl-1])
	fi
      ],
      [AC_MSG_WARN([keepalived will be built without libnl support.])
    ])
  fi

  if test $NETLINK_VER -ne 0; then
    SAV_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $kernel_inc $NL3_CPPFLAGS"
    AC_CHECK_HEADERS([netlink/netlink.h], [], [AC_MSG_ERROR([netlink headers missing])])
    AC_CHECK_HEADERS([netlink/genl/ctrl.h netlink/genl/genl.h], [], [AC_MSG_ERROR([netlink genl headers missing])])
    CPPFLAGS="$SAV_CPPFLAGS"
  fi
fi
AM_CONDITIONAL([LIBNL1], [test $NETLINK_VER -eq 1])
AM_CONDITIONAL([LIBNL3], [test $NETLINK_VER -eq 3])
AM_CONDITIONAL([LIBNL_DYNAMIC], [test .$enable_lvs != .no -a .$enable_libnl_dynamic = .yes -a $NETLINK_VER -ne 0])
unset LIBS

AC_CHECK_LIB(magic, magic_open,
  [
    AC_DEFINE([_HAVE_LIBMAGIC_], [ 1 ], [Define to 1 if have magic library])
    add_to_var([KA_LIBS], [-lmagic])
  ])
unset LIBS

dnl -- Check for the following variables introduced at various times into Linux
dnl --RTAX_QUICKACK		dnl -- Linux 3.11
dnl --FRA_SUPPRESS_PREFIXLEN	dnl -- Linux 3.12
dnl --FRA_SUPPRESS_IFGROUP	dnl -- Linux 3.12
dnl --RTAX_CC_ALGO		dnl -- Linux 4.0
dnl --RTA_VIA			dnl -- Linux 4.1
dnl --RTA_NEWDST		dnl -- Linux 4.1
dnl --RTA_PREF			dnl -- Linux 4.1
dnl --FRA_TUN_ID		dnl -- Linux 4.3
dnl --RTA_ENCAP			dnl -- Linux 4.3
dnl --RTEXT_FILTER_SKIP_STATS	dnl -- Linux 4.4
dnl --RTA_EXPIRES		dnl -- Linux 4.5
dnl --FRA_L3MDEV		dnl -- Linux 4.8
dnl --FRA_UID_RANGE		dnl -- Linux 4.10
dnl --RTAX_FASTOPEN_NO_COOKIE	dnl -- Linux 4.15
dnl --FRA_PROTOCOL		dnl -- Linux 4.17
dnl --FRA_IP_PROTO		dnl -- Linux 4.17
dnl --FRA_SPORT_RANGE		dnl -- Linux 4.17
dnl --FRA_DPORT_RANGE		dnl -- Linux 4.17
dnl --RTA_TTL_PROPAGATE		dnl -- Linux 4.12
AC_CHECK_DECLS([RTA_ENCAP, RTA_EXPIRES, RTA_NEWDST, RTA_PREF, FRA_SUPPRESS_PREFIXLEN, FRA_SUPPRESS_IFGROUP, FRA_TUN_ID, RTAX_CC_ALGO, RTAX_QUICKACK, RTEXT_FILTER_SKIP_STATS, FRA_L3MDEV, FRA_UID_RANGE, RTAX_FASTOPEN_NO_COOKIE, RTA_VIA, FRA_PROTOCOL, FRA_IP_PROTO, FRA_SPORT_RANGE, FRA_DPORT_RANGE, RTA_TTL_PROPAGATE], [], [],
  [[$RTNETLINK_EXTRA_INCLUDES
    #include <linux/rtnetlink.h>
    #include <sys/socket.h>
    #include <linux/fib_rules.h>]])
for flag in RTA_ENCAP RTA_EXPIRES RTA_NEWDST RTA_PREF FRA_SUPPRESS_PREFIXLEN FRA_SUPPRESS_IFGROUP FRA_TUN_ID RTAX_CC_ALGO RTAX_QUICKACK RTEXT_FILTER_SKIP_STATS FRA_L3MDEV FRA_UID_RANGE RTAX_FASTOPEN_NO_COOKIE RTA_VIA FRA_PROTOCOL FRA_IP_PROTO FRA_SPORT_RANGE FRA_DPORT_RANGE RTA_TTL_PROPAGATE; do
  AS_VAR_COPY([decl_var], [ac_cv_have_decl_$flag])
  if test ${decl_var} = yes; then
    add_system_opt[${flag}]
  fi
done

dnl - Introduced in Linux 3.14
AC_CHECK_DECLS([IFA_FLAGS], [], [], [[#include <linux/if_addr.h>]])
for flag in IFA_FLAGS; do
  AS_VAR_COPY([decl_var], [ac_cv_have_decl_$flag])
  if test ${decl_var} = yes; then
    add_system_opt[${flag}]
  fi
done

dnl -- RedHat backported ENCAP_IP and ENCAP_IP6 without MPLS and ILA
AS_IF([test $ac_cv_have_decl_RTA_ENCAP = yes],
  [
    AC_CHECK_DECLS([LWTUNNEL_ENCAP_MPLS, LWTUNNEL_ENCAP_ILA], [], [],
      [[#include <linux/lwtunnel.h>]])
    for flag in LWTUNNEL_ENCAP_MPLS LWTUNNEL_ENCAP_ILA; do
      AS_VAR_COPY([decl_var], [ac_cv_have_decl_$flag])
      if test ${decl_var} = yes; then
	add_system_opt([${flag}])
      fi
    done
  ])

dnl ----[Check for iptables libraries]----
USE_IPTABLES=No
USE_LIBIPSET=No
AS_IF([test .$enable_iptables != .no],
  [
    USE_IPTABLES=Yes
    SAV_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $kernelinc"
    AC_CHECK_HEADERS([libiptc/libip6tc.h libiptc/libiptc.h libiptc/libxtc.h], [],
      [
	USE_IPTABLES=No
	break
      ])
    CPPFLAGS="$SAV_CPPFLAGS"

    if test $USE_IPTABLES = Yes; then
      PKG_CONFIG_IP4TC=Yes
      $PKG_CONFIG --exists libip4tc
      AS_IF([test $? -eq 0],
	[
	  add_pkg_config([--static libip4tc], [IP4TC], [remove-requires])
	  add_pkg_config([--static libip6tc], [IP6TC], [remove-requires])
	  IPTC_LIBS="$IP4TC_LIBS $IP6TC_LIBS"
	  IPTC_LIB_NAMES="$IP4TC_LIB_NAMES $IP6TC_LIB_NAMES"
	],
	[
	  PKG_CONFIG_IP4TC=No
	  add_pkg_config([--static libiptc], [IPTC], [remove-requires])
	])

      SAV_CPPFLAGS="$CPPFLAGS"
      CPPFLAGS="$CPPFLAGS $kernelinc"

      AC_SEARCH_LIBS(iptc_init, $IPTC_LIB_NAMES,
	[
	  if test .${enable_libiptc_dynamic} != .yes; then
	    AS_IF([test $PKG_CONFIG_IP4TC = Yes],
	      [
	        add_pkg_config([--static libip4tc])
	        add_pkg_config([--static libip6tc])
	      ],
	      [add_pkg_config([--static libiptc])])

	    dnl - Older versions of libiptc produced a requirement for -liptc, but we don't need it
	    KA_LIBS=`echo $KA_LIBS | sed -e "s/ -liptc//"`
	    dnl - Even older versions of libiptc don't produce any requirement other than -liptc
	    IPTC_LIBS=`echo $IPTC_LIBS | sed -e "s/ *-L[[^ ]]*  */ /" -e "s/ *-liptc */ /" -e "s/^  *$//"`
	    if test ".$IPTC_LIBS" = .; then
	      KA_LIBS="$KA_LIBS -lip4tc -lip6tc"
	    fi
	  else
	    AS_IF([test $PKG_CONFIG_IP4TC = Yes],
	      [
	        add_pkg_config_without_libs([libip4tc])
	        add_pkg_config_without_libs([libip6tc])
	      ],
	      [
	        add_pkg_config_without_libs([libiptc])
	      ])
	    add_config_opt([LIBIPTC_DYNAMIC])
	    AC_DEFINE([_LIBIPTC_DYNAMIC_], [ 1 ], [Define to 1 if building with libiptc dynamic linking])
	    NEED_LIBDL=Yes
	    AC_SEARCH_LIBS(ip6tc_init, $IPTC_LIB_NAMES)
	    IP4TC_NAME=`echo $ac_cv_search_iptc_init | sed -e "s/-l//"`
	    IP6TC_NAME=`echo $ac_cv_search_ip6tc_init | sed -e "s/-l//"`
	    get_lib_name([$IP4TC_NAME], [iptc_init])
	    AC_DEFINE_UNQUOTED([IP4TC_LIB_NAME], [ "$LIB_NAME" ], [Define the ip4tc library name])
	    get_lib_name([$IP6TC_NAME], [ip6tc_init])
	    AC_DEFINE_UNQUOTED([IP6TC_LIB_NAME], [ "$LIB_NAME" ], [Define the ip6tc library name])
	    LIBIPTC_DYNAMIC=Yes
	  fi
	],
	[USE_IPTABLES=No])
      CPPFLAGS="$SAV_CPPFLAGS"
    fi

    if test $USE_IPTABLES = Yes; then
      dnl ----[Check for ipset libraries]----
      SAV_CPPFLAGS="$CPPFLAGS"
      CPPFLAGS="$CPPFLAGS $kernelinc"
      if test "${enable_libipset}" != no; then
	$PKG_CONFIG --exists libipset
	if test $? -eq 0; then
	  add_pkg_config([libipset], [IPSET], [remove-requires])
	else
	  IPSET_LIBS="-lipset"
	  IPSET_LIB_NAMES=ipset
	fi
	SAV_LIBS=$LIBS

	AC_SEARCH_LIBS(ipset_session_init, $IPSET_LIB_NAMES,
	  [
	    USE_LIBIPSET=Yes
	    AC_CHECK_HEADERS([libipset/data.h libipset/linux_ip_set.h libipset/session.h libipset/types.h], [],
	      [
		USE_LIBIPSET=No
		break
	      ])

	    if test $USE_LIBIPSET = Yes; then
	      AC_DEFINE([_HAVE_LIBIPSET_], [ 1 ], [Define to 1 if have ipset library])
	      $PKG_CONFIG --exists libipset
	      if test $? -eq 0; then
		if test .${enable_libipset_dynamic} = .no; then
		  add_pkg_config([libipset])
		else
		  add_pkg_config_without_libs([libipset])
		fi
	      elif test .${enable_libipset_dynamic} = .no; then
		add_to_var([KA_LIBS], [$ac_cv_search_ipset_session_init])
	      fi
	      if test .${enable_libipset_dynamic} != .no; then
		AC_DEFINE([_LIBIPSET_DYNAMIC_], [ 1 ], [Define to 1 if building with libipset dynamic linking])
		add_config_opt([LIBIPSET_DYNAMIC])
		NEED_LIBDL=Yes
		LIBIPSET_NAME=`echo $ac_cv_search_ipset_session_init | sed -e "s/-l//"`
		get_lib_name([$LIBIPSET_NAME], [ipset_session_init])
		AC_DEFINE_UNQUOTED([IPSET_LIB_NAME], [ "$LIB_NAME" ], [Define the ipset library name])
	      else
		add_config_opt([LIBIPSET])
	      fi

	      dnl -- xt_set_info_match_v4 declared since Linux 3.19
	      AC_CHECK_MEMBER([struct xt_set_info_match_v4.match_set.index], [AC_DEFINE([HAVE_XT_SET_INFO_MATCH_V4], [ 1 ], [Define to 1 if have struct xt_set_info_match_v4])], [],
		[#include <linux/netfilter/xt_set.h>])
	    fi

	    if test $USE_LIBIPSET = Yes; then
	      dnl -- Debian Buster has ipset v6.38, Bullseye v7.10.
	      dnl -- Ubuntu 16.04 has ipset v6.29.
	      dnl -- All other distros appear to have moved to ipset v7.
	      AC_MSG_CHECKING([for libipset version 7 or later])
	      AC_COMPILE_IFELSE([AC_LANG_SOURCE(
		[[
		  #include <libipset/session.h>

		  void test_func(void)
		  {
		    ipset_session_init(NULL, NULL);
		  }
		]])],
		[
		  AC_MSG_RESULT([yes])
		],
		[
		  AC_MSG_RESULT([no])
		  AC_DEFINE([LIBIPSET_PRE_V7_COMPAT], [ 1 ], [Define to 1 if libipset library version prior to v7])
		  add_system_opt[LIBIPSET_PRE_V7]
		])
	    fi
	  ])
	LIBS="$SAV_LIBS"
      fi
      CPPFLAGS="$SAV_CPPFLAGS"
    fi
    if test $USE_IPTABLES = Yes; then
      AC_DEFINE([_WITH_IPTABLES_], [ 1 ], [Define to 1 if want iptables support])
      add_system_opt([IPTABLES])
    fi
  ])
AM_CONDITIONAL([LIBIPSET], [test $USE_LIBIPSET = Yes])
AM_CONDITIONAL([IPTABLES], [test $USE_IPTABLES = Yes])
AM_CONDITIONAL([LIBIPTC_DYNAMIC], [test $USE_IPTABLES = Yes -a .$LIBIPTC_DYNAMIC = .Yes])
AM_CONDITIONAL([LIBIPSET_DYNAMIC], [test $USE_LIBIPSET = Yes -a .${enable_libipset_dynamic} != .no])
unset LIBS

dnl ----[Check for nftables libraries]----
USE_NFTABLES=No
if test .${enable_nftables} != .no; then
  USE_NFTABLES=Yes
  dnl -- linux/netfilter/nf_tables.h since Linux 3.13
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"
  AC_CHECK_DECL([NFTA_TABLE_MAX], [],
   [
     AS_IF([test .${enable_nftables} = .yes], [AC_MSG_ERROR([nftables header files missing/not useable])])
     USE_NFTABLES=No
   ],
   [#include <linux/netfilter/nf_tables.h>])

  if test $USE_NFTABLES = Yes; then
    $PKG_CONFIG --exists libnftnl
    if test $? -ne 0; then
      USE_NFTABLES=No
      AC_MSG_WARN([libnftnl missing])
    fi
    $PKG_CONFIG --exists libmnl
    if test $? -ne 0; then
      USE_NFTABLES=No
      AC_MSG_WARN([libmnl missing])
    fi

    if test $USE_NFTABLES = Yes; then
      # nft prior to version 0.8.3 does not support type ifname in sets. We can't check the version of
      #  nft, but we can check the version of libnftnl. nft v0.8.3 required libnftnl v1.0.9, but so did
      #  nft v0.8.2. So play safe, and require the next version.
      LIBNFTNL_VERSION=`printf "0x%2.2x%2.2x%2.2xU" \`pkg-config --modversion libnftnl | sed -e "s/\./ /g"\``
      AC_DEFINE_UNQUOTED([LIBNFTNL_VERSION], [ $LIBNFTNL_VERSION ], [libnftnl version in hex])

      add_pkg_config([libnftnl])
      add_pkg_config([libmnl])
      AC_DEFINE([_WITH_NFTABLES_], [ 1 ], [Define to 1 if want nftables support])
      add_config_opt([NFTABLES])
      AC_MSG_CHECKING([whether NFTNL_EXPR_LOOKUP_FLAGS and NFT_LOOKUP_F_INV are defined])
      AC_LINK_IFELSE([AC_LANG_SOURCE([[
	#include <stdio.h>	// libnftnl/expr.h requires this
	#include <libnftnl/expr.h>
	#include <linux/netfilter/nf_tables.h>
	int main(void)
	{
	  int i = NFTNL_EXPR_LOOKUP_FLAGS | NFT_LOOKUP_F_INV;
	  return 0;
	}
	]])], [
	  AC_MSG_RESULT(yes)
	  AC_DEFINE([HAVE_NFTNL_EXPR_LOOKUP_FLAG_INV], [ 1 ], [Define to 1 if NFTNL_EXPR_LOOKUP_FLAGS and NFT_LOOKUP_F_INV defined])
	],[
	  AC_MSG_RESULT(no)
	])
      # nft dup from Linux 4.3
      AC_CHECK_DECLS([NFTA_DUP_MAX], [], [],
        [#include <linux/netfilter/nf_tables.h>])

      # NFT_USERDATA_MAXLEN since Linux 3.15. Check nftnl_udata_buf_alloc for libnftnl support of userdata
      USE_NFT_USERDATA=Yes
      AC_CHECK_DECLS([NFT_USERDATA_MAXLEN, nftnl_udata_buf_alloc],
	[], [USE_NFT_USERDATA=No],
	[
	  #include <linux/netfilter/nf_tables.h>
	  #include <libnftnl/udata.h>
	]
      )

      AS_IF([test $USE_NFT_USERDATA = Yes],
	[
	  AC_DEFINE([HAVE_NFTNL_UDATA], [ 1 ], [Define to 1 if have nftnl udata support])
          AC_CHECK_DECLS([nftnl_udata_put_u32],
	    [], [],
	    [
	      #include <linux/netfilter/nf_tables.h>
	      #include <libnftnl/udata.h>
	    ])
	])

      # NFTNL_SET_DESC_CONCAT since Linux 5.6 and libnftnl 1.1.6, nft 0.9.4 - ranges in concatenations
      # NFTNL_SET_ELEM_KEY_END since Linux 5.6 and libnftnl 1.1.6, nft 0.9.4
      NFT_RANGE_CONCATS_OK=1
      AC_CHECK_DECLS([NFTNL_SET_DESC_CONCAT, NFTNL_SET_ELEM_KEY_END], [], [NFT_RANGE_CONCATS_OK=0], [[#include <libnftnl/set.h>]])
      AS_IF([test $NFT_RANGE_CONCATS_OK -eq 1],
	    [AC_DEFINE([NFT_RANGE_CONCATS], [ 1 ], [Define to 1 if can use concats with ranges in nftables])])

      # NFTA_SET_EXPR since Linux 5.7, libnftnl 1.1.7, nft 0.9.5 - counters on set elements
      AC_CHECK_DECLS([NFTNL_SET_EXPR], [], [], [[#include <libnftnl/set.h>]])
    fi
  fi
  CPPFLAGS="$SAV_CPPFLAGS"
fi
AM_CONDITIONAL([NFTABLES], [test $USE_NFTABLES = Yes])
unset LIBS

AS_IF([test $USE_IPTABLES = Yes -o $USE_NFTABLES = Yes], [AC_DEFINE([_WITH_FIREWALL_], [ 1 ], [Define to 1 if using iptables or nftables])])
AM_CONDITIONAL([FIREWALL], [test $USE_IPTABLES = Yes -o $USE_NFTABLES = Yes])

dnl ----[Check if have linux/if.h and net/if.h namespace collision]----
# Including <linux/if.h> and <net/if.h> can cause a namespace collision.
# Later versions of the headers are OK if linux/if.h is included second
AC_MSG_CHECKING([for linux/if.h and net/if.h namespace collision])
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <linux/if.h>
    #include <net/if.h>
  ]])],
  [
    AC_MSG_RESULT([no])
  ],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_NET_LINUX_IF_H_COLLISION_], [ 1 ], [Define to 1 if have linux/if.h followed by net/if.h namespace collision])
    add_system_opt([NET_LINUX_IF_H_COLLISION])
  ])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[Check if linux/if_ether.h then netinet/in.h then linux/if.h namespace collision]----
# This issue was resolved in Linux 4.15.7/4.16
AC_MSG_CHECKING([for linux/if_ether.h then netinet/in.h then linux/if.h namespace collision])
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <linux/if_ether.h>
    #include <netinet/in.h>
    #include <linux/in.h>
  ]])],
  [
    AC_MSG_RESULT([no])
  ],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_LINUX_IF_ETHER_H_COLLISION_], [ 1 ], [Define to 1 if have linux/if_ether.h then netinet/in.h then linux/in.h namespace collision])
    add_system_opt([NET_LINUX_IF_ETHER_H_COLLISION])
  ])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[Check if have linux/if_ether.h and netinet/if_ether.h namespace collision]----
# Including <linux/if_ether.h> and <netinet/if_ether.h> causes a namespace collision
# with musl libc, but the collision only occurs if linux/ip_ether.h is included
# before netinet/if_ether.h. The problem is that we want to include them in that
# order.
AC_MSG_CHECKING([for linux/if_ether.h then netinet/if_ether.h namespace collision])
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <linux/if_ether.h>
    #include <netinet/if_ether.h>
  ]])],
  [
    AC_MSG_RESULT([no])
  ],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_NETINET_LINUX_IF_ETHER_H_COLLISION_], [ 1 ], [Define to 1 if have linux/if_ether.h then netinet/if_ether.h namespace collision])
    add_system_opt([NETINET_LINUX_IF_ETHER_H_COLLISION])
  ])
CPPFLAGS="$SAV_CPPFLAGS"

# Linux 4.5 to 4.5.4 has <libiptc/libiptc.h> indirectly including <net/if.h>
# and <linux/if.h> which causes a namespace collision.
AC_MSG_CHECKING([for libiptc/libiptc.h linux/if.h and net/if.h namespace collision])
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <libiptc/libiptc.h>
  ]])],
  [
    AC_MSG_RESULT([no])
  ],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([_HAVE_LIBIPTC_LINUX_NET_IF_H_COLLISION_], [ 1 ], [Define to 1 if have libiptc/libiptc.h linux/if.h and net/if.h namespace collision])
    add_system_opt([LIBIPTC_LINUX_NET_IF_H_COLLISION])
  ])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Checks for LVS, VRRP and BFD support ]----
IPVS_SYNCD_ATTRIBUTES=No
IPVS_64BIT_STATS=No
WITH_REGEX=No
ENABLE_REGEX_DEBUG=No
if test "$enable_lvs" != no; then
  IPVS_SUPPORT=Yes
  add_config_opt([LVS])
  AC_DEFINE([_WITH_LVS_], [ 1 ], [Define to 1 if have IPVS support])

  if test $IPVS_USE_NL = Yes; then
    AC_DEFINE([LIBIPVS_USE_NL], [ 1 ], [Define to 1 if libipvs can use netlink])
    add_system_opt([LIBIPVS_NETLINK])
  fi

  dnl ----[ IPVS syncd options ]---
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"

  dnl -- Since Linux 3.18
  AC_CHECK_DECLS([IPVS_DEST_ATTR_ADDR_FAMILY], [add_system_opt([IPVS_DEST_ATTR_ADDR_FAMILY])], [], [#include <linux/ip_vs.h>])

  dnl -- Since Linux 4.3
  IPVS_SYNCD_ATTRIBUTES=Yes
  AC_CHECK_DECLS([
    IPVS_DAEMON_ATTR_SYNC_MAXLEN,
    IPVS_DAEMON_ATTR_MCAST_GROUP,
    IPVS_DAEMON_ATTR_MCAST_GROUP6,
    IPVS_DAEMON_ATTR_MCAST_PORT,
    IPVS_DAEMON_ATTR_MCAST_TTL], [],
    [
      IPVS_SYNCD_ATTRIBUTES=No
      break
    ],
    [[#include <linux/ip_vs.h>]])

  if test $IPVS_SYNCD_ATTRIBUTES = Yes; then
    AC_DEFINE([_HAVE_IPVS_SYNCD_ATTRIBUTES_], [ 1 ], [Define to 1 if have IPVS syncd attributes])
    add_system_opt([IPVS_SYNCD_ATTRIBUTES])
  fi

  dnl ----[ IPVS 64-bit stats ]----
  dnl -- Since Linux 4.1
  if test "$enable_lvs_64bit_stats" != "no"; then
    IPVS_64BIT_STATS=Yes
    AC_CHECK_DECLS([
      IPVS_SVC_ATTR_STATS64,
      IPVS_DEST_ATTR_STATS64], [],
      [
	IPVS_64BIT_STATS=No
	break
      ],
      [[#include <linux/ip_vs.h>]])
    if test $IPVS_64BIT_STATS = Yes; then
      AC_DEFINE([_WITH_LVS_64BIT_STATS_], [ 1 ], [Define to 1 if have IPVS 64 bit stats])
      add_system_opt([IPVS_64BIT_STATS])
    fi
  fi

  dnl ----[ IPVS tunnel type ]----
  dnl -- Since Linux 5.2
  AC_CHECK_DECLS([IPVS_DEST_ATTR_TUN_TYPE],
    [
      AC_DEFINE([_HAVE_IPVS_TUN_TYPE_], [ 1 ], [Define to 1 if have IPVS tunnel type])
      add_system_opt([IPVS_TUN_TYPE])
    ], [],
    [[#include <linux/ip_vs.h>]])

  dnl -- Since Linux 5.3
  AC_CHECK_DECLS([IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM],
    [
      AC_DEFINE([_HAVE_IPVS_TUN_CSUM_], [ 1 ], [Define to 1 if have IPVS tunnel checksum options])
      add_system_opt([IPVS_TUN_CSUM])
    ], [],
    [[#include <linux/ip_vs.h>]])

  dnl -- Since Linux 5.3
  AC_CHECK_DECLS([IP_VS_CONN_F_TUNNEL_TYPE_GRE],
    [
      AC_DEFINE([_HAVE_IPVS_TUN_GRE_], [ 1 ], [Define to 1 if have IPVS gre tunnel])
      add_system_opt([IPVS_TUN_GRE])
    ], [],
    [[#include <linux/ip_vs.h>]])

  CPPFLAGS="$SAV_CPPFLAGS"

  dnl ----[ Is HTTP_GET regex checking wanted? ]----
  AS_IF([test "$enable_regex" = yes],
    [
      dnl -- Check pcre library has 8-bit support
      $PKG_CONFIG --exists libpcre2-8
      HAVE_PCRE2=$?
      AS_IF([test $HAVE_PCRE2 -ne 0], [AC_MSG_ERROR([cannot find 8-bit pcre library])])
      AC_MSG_CHECKING([for pcre.h])
      AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	#define PCRE2_CODE_UNIT_WIDTH 8
	#include <pcre2.h>
	]])],
	[
	  AC_MSG_RESULT([yes])
	  WITH_REGEX=Yes
	  add_pkg_config([libpcre2-8])
	  AC_DEFINE([_WITH_REGEX_CHECK_], [ 1 ], [Define to 1 to build with HTTP_GET regex checking])
	  add_config_opt([REGEX])
	],
	[
	  AC_MSG_RESULT([no])
	  AC_MSG_ERROR([pcre2.h is missing])
	])
      if test "$enable_regex_timers" = yes; then
	AC_DEFINE([_WITH_REGEX_TIMERS_], [ 1 ], [Define to 1 to include regex timers])
      fi

      if test "${enable_regex_debug}" = yes; then
	AC_DEFINE([_REGEX_DEBUG_], [ 1 ], [Define to 1 to build with regex debugging support])
	ENABLE_REGEX_DEBUG=Yes
	add_config_opt([REGEX_DEBUG])
      fi
    ])
else
  IPVS_SUPPORT=No
fi
AM_CONDITIONAL([WITH_IPVS], [test $IPVS_SUPPORT = Yes])
AM_CONDITIONAL([WITH_REGEX], [test $WITH_REGEX = Yes])

dnl ----[ Checks for kernel netlink support ]----
VRRP_SUPPORT=No
VRRP_AUTH_SUPPORT=No
MACVLAN_SUPPORT=No
ENABLE_JSON=No
BFD_SUPPORT=No
HAVE_CN_PROC=No
WITH_TRACK_PROCESS=No
if test "$enable_vrrp" != no; then
  VRRP_SUPPORT=Yes
  AC_DEFINE([_WITH_VRRP_], [ 1 ], [Define to 1 if have VRRP support])
  add_config_opt([VRRP])

  dnl ----[ check for VRRP authentication support ]----
  if test "${enable_vrrp_auth}" != no; then
    VRRP_AUTH_SUPPORT=Yes
    AC_DEFINE([_WITH_VRRP_AUTH_], [ 1 ], [Define to 1 if want ARRP authentication support])
    add_config_opt([VRRP_AUTH])
  fi

  dnl ----[ Checks for kernel VMAC support ]----
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"
  MACVLAN_SUPPORT=No
  if test "${enable_vmac}" != no; then
    MACVLAN_SUPPORT=Yes
    AC_DEFINE([_HAVE_VRRP_VMAC_], [ 1 ], [Define to 1 if have MAC VLAN support])
    add_config_opt([VRRP_VMAC])

    dnl ----[ Checks for kernel IPVLAN support ]----
    IPVLAN_SUPPORT=Yes
    dnl -- Since Linux 3.19
    AC_CHECK_DECLS([IFLA_IPVLAN_MODE], [],
      [
        IPVLAN_SUPPORT=No
        break
      ], [[
        #include <sys/socket.h>
        #include <linux/if_link.h>
      ]])
    if test $IPVLAN_SUPPORT = Yes; then
      dnl - IPVLAN_MODE_L3S since Linux 4.9, IFLA_IPVLAN_FLAGS since Linux 4.15
      AC_CHECK_DECLS([IPVLAN_MODE_L3S, IFLA_IPVLAN_FLAGS], [], [],
        [[
          #include <linux/if_link.h>
        ]])
      AC_DEFINE([_HAVE_VRRP_IPVLAN_], [ 1 ], [Define to 1 if have IP VLAN support])
      add_system_opt([VRRP_IPVLAN])
    fi

    dnl ----[ Check for IFLA_LINK_NETNSID support ]---- since Linux v4.0
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
      #include <linux/if_link.h>
      int main(void) { int var = IFLA_LINK_NETNSID; }
      ]])],
      [
        AC_DEFINE([HAVE_IFLA_LINK_NETNSID], [ 1 ], [Define to 1 if IFLA_LINK_NETNSID supported])
        add_system_opt([IFLA_LINK_NETNSID])
      ])
  fi
  CPPFLAGS="$SAV_CPPFLAGS"

  dnl ----[ JSON output or not ? ]----
  if test "${enable_json}" = yes; then
    ENABLE_JSON=Yes
    AC_DEFINE([_WITH_JSON_], [ 1 ], [Define to 1 to build with JSON output support])
    add_config_opt([JSON])
  fi

  dnl ----[ BFD support ? ]----
  if test "${enable_bfd}" = yes; then
    BFD_SUPPORT=Yes
    AC_DEFINE([_WITH_BFD_], [ 1 ], [Define to 1 if have BFD support])
    add_config_opt([BFD])
  fi

  AS_IF([test .$enable_track_process != .no],
    [
      WITH_TRACK_PROCESS=Yes
      AC_DEFINE([_WITH_TRACK_PROCESS_], [ 1 ], [Define to 1 if track-process not disabled])
    ],
    [add_config_opt([DISABLE_TRACK_PROCESS])])
fi
AM_CONDITIONAL([WITH_VRRP], [test $VRRP_SUPPORT = Yes])
AM_CONDITIONAL([VRRP_AUTH], [test $VRRP_AUTH_SUPPORT = Yes])
AM_CONDITIONAL([VMAC], [test $MACVLAN_SUPPORT = Yes])
AM_CONDITIONAL([WITH_JSON], [test $ENABLE_JSON = Yes])
AM_CONDITIONAL([WITH_BFD], [test $BFD_SUPPORT = Yes])
AM_CONDITIONAL([TRACK_PROCESS], [test $WITH_TRACK_PROCESS = Yes])

if test ${IPVS_SUPPORT} = No -a ${VRRP_SUPPORT} = No; then
  AC_MSG_ERROR([keepalived MUST be compiled with at least one of LVS or VRRP framework])
fi

dnl ----[ Check for GLOB_BRACE support ]----
AC_CHECK_DECLS([GLOB_BRACE], [add_system_opt([GLOB_BRACE])], [], [[#include <glob.h>]])

dnl ----[ Check for GLOB_ALTDIRFUNC support ]----
AC_CHECK_DECLS([GLOB_ALTDIRFUNC], [add_system_opt([GLOB_ALTDIRFUNC])], [], [[#include <glob.h>]])

dnl ----[ Check for timegm() support ]----
AC_MSG_CHECKING([for timegm()])
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$KA_CPPFLAGS $kernel_inc"
AC_LINK_IFELSE([AC_LANG_SOURCE([[
    #include <time.h>
    int main(void)
    {
      timegm(NULL);
      return 0;
    }
  ]])], [
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_TIMEGM], [ 1 ], [Define to 1 if have timegm()])
  ],[
    AC_MSG_RESULT(no)
  ])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Do we want v1.3.6 and earlier VRRPv3 unicast checksum compatibility support ]----
UNICAST_CHKSUM_COMPAT_SUPPORT=No
if test .$enable_checksum_compat != .no; then
  UNICAST_CHKSUM_COMPAT_SUPPORT=Yes
  AC_DEFINE([_WITH_UNICAST_CHKSUM_COMPAT_], [ 1 ], [Define to 1 to enable v1.3.6 and earlier VRRPv3 unicast checksum compatibility])
  add_config_opt([OLD_CHKSUM_COMPAT])
fi

dnl ----[ Check if linkbeat wanted ]----
AS_IF([test .$enable_linkbeat = .no],
  [
    LINKBEAT_SUPPORT=No
    add_config_opt([NO_LINKBEAT])
  ],
  [
    LINKBEAT_SUPPORT=Yes
    AC_DEFINE([_WITH_LINKBEAT_], [ 1 ], [Define to 1 if have linkbeat support])
  ])

dnl ----[ Checks for kernel IFLA_INET6_ADDR_GEN_MODE support ]----
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
if test ${MACVLAN_SUPPORT} = Yes; then
  # Introduced in Linux 3.17
  AC_CHECK_DECLS([IFLA_INET6_ADDR_GEN_MODE],
    [
      add_system_opt([INET6_ADDR_GEN_MODE])
    ], [], [[
      #include <linux/if_link.h>
    ]])
fi
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Checks for kernel IFLA_VRF_... support ]----
if test ${MACVLAN_SUPPORT} = Yes; then
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"

  # Introduced in Linux 4.3
  AC_CHECK_DECLS([IFLA_VRF_MAX],
    [
      add_system_opt([VRF])
      AC_DEFINE([_HAVE_VRF_], [ 1 ], [Define to 1 if have kernel VRF support])
    ], [], [[
      #include <linux/if_link.h>
    ]])
  CPPFLAGS="$SAV_CPPFLAGS"
fi

dnl ----[ Checks for SNMP support ]----
SNMP_SUPPORT=No
SNMP_KEEPALIVED_SUPPORT=No
SNMP_VRRP_SUPPORT=No
SNMP_RFC_SUPPORT=No
SNMP_RFCV2_SUPPORT=No
SNMP_RFCV3_SUPPORT=No
SNMP_CHECKER_SUPPORT=No
SNMP_V3_FOR_V2=No
if test "$enable_snmp_keepalived" = yes; then
  AC_MSG_WARN([--enable-snmp-keepalived is obsolete. Use --enable-snmp-vrrp.])
  enable_snmp_vrrp=$enable_snmp_keepalived
fi
if test "$enable_snmp" = yes -o \
	"$enable_snmp_vrrp" = yes -o \
	"$enable_snmp_checker" = yes -o \
	"$enable_snmp_rfc" = yes -o \
	"$enable_snmp_rfcv2" = yes -o \
	"$enable_snmp_rfcv3" = yes; then
  AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], [no])
  if test "$NETSNMP_CONFIG" = no; then
    AC_MSG_ERROR([*** unable to find net-snmp-config])
  fi

  # Despite the net-snmp-config documentation for the --*-libs and --base-cflags
  # options documention suggesting they provide the libraries and -I options
  # respectively, they actually include all the other # LDFLAGS and CFLAGS options
  # used when net-snmp was built. Since net-snmp is likely to have been built using
  # the distro's package builder, this can include quite a large number of
  # compiler/linker flags that we don't really want.
  # RedHat has a patch that stops the additional compile options being emitted with
  # --cflags and --base-cflags, however it doesn't have a patch to do similarly for
  # the --*-libs options. This means that the --cflags options do not include the
  # -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1, whereas the --*-libs options
  # do include -specs=/usr/lib/rpm/redhat/redhat-hardened-ld. The result of this is
  # -pie is specified for the linker, but -fpie is not specified for the compiler.
  # It turns out that this does not cause a problem on x86_64, but building on s390x
  # fails to link due to this mismatch.
  # See https://bugzilla.redhat.com/show_bug.cgi?id=1921988 for further details.
  NETSNMP_LIBS_AGENT=`${NETSNMP_CONFIG} --netsnmp-agent-libs`
  NETSNMP_LIBS_EXT=`${NETSNMP_CONFIG} --external-libs`
  NETSNMP_CFLAGS=`${NETSNMP_CONFIG} --base-cflags`
  NETSNMP_CPPFLAGS="-DNETSNMP_NO_INLINE"

  echo $NETSNMP_LIBS_EXT | $GREP -q -- -specs=
  AS_IF([ test $? -eq 0 ], [ HAVE_LD_SPECS=1 ], [ HAVE_LD_SPECS=0 ])
  echo $NETSNMP_CFLAGS | $GREP -q -- -specs=
  AS_IF([ test $? -eq 0 ], [ HAVE_CC_SPECS=1 ], [ HAVE_CC_SPECS=0 ])
  AS_IF([ test \( $HAVE_LD_SPECS -eq 1 -a $HAVE_CC_SPECS -eq 0 \)],
    [NETSNMP_LIBS_EXT=`echo $NETSNMP_LIBS_EXT | tr " " "\n" | grep "^-[lL]"`])

  NETSNMP_LIBS="$NETSNMP_LIBS_AGENT $NETSNMP_LIBS_EXT"

  # net-snmp-config can add -I/usr/include, so remove it
  NETSNMP_CFLAGS=`echo $NETSNMP_CFLAGS " " | sed -e "s:-I */usr/include ::"`

  # net-snmp-config adds compiler and linker options that were set at the time
  # net-snmp was built, and this can include spec files that may not exist
  # on the system building keepalived. We need to check if any spec files
  # are specified, and if they do not exist on this system, then remove them
  # from NETSNMP_LIBS or NETSNMP_CFLAGS.
  # For further information, see https://bugzilla.redhat.com/show_bug.cgi?id=1544527
  # and the other bugs referred to in it.
  for spec in `echo $NETSNMP_LIBS | sed -e "s? ?\n?g" | grep "^-specs="`; do
    SPEC_FILE=`echo $spec | sed -e "s?^-specs=??"`
    if test ! -f $SPEC_FILE; then
      NETSNMP_LIBS=`echo $NETSNMP_LIBS | sed -e "s? *$spec *? ?"`
      AC_MSG_WARN([Removing $spec from NETSNMP_LIBS since spec file not installed])
    fi
  done
  for spec in `echo $NETSNMP_CFLAGS | sed -e "s? ?\n?g" | grep "^-specs="`; do
    SPEC_FILE=`echo $spec | sed -e "s?^-specs=??"`
    if test ! -f $SPEC_FILE; then
      NETSNMP_CFLAGS=`echo $NETSNMP_CFLAGS | sed -e "s? *$spec *? ?"`
      AC_MSG_WARN([Removing $spec from NETSNMP_CFLAGS since spec file not installed])
    fi
  done

  SAV_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS ${NETSNMP_CFLAGS}"
  SAV_LIBS="$LIBS"
  LIBS="$LIBS ${NETSNMP_LIBS}"
  AC_MSG_CHECKING([whether C compiler supports flag "${NETSNMP_CFLAGS} ${NETSNMP_LIBS}" from Net-SNMP])
  AC_LINK_IFELSE([AC_LANG_SOURCE([[
      int main(void)
      {
	return 0;
      }
    ]])], [
      AC_MSG_RESULT(yes)
    ],[
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([*** incorrect CFLAGS from net-snmp-config])
    ])

  # Do we have subagent support?
  AC_CHECK_FUNCS([netsnmp_enable_subagent], [],
      [AC_MSG_ERROR([*** no subagent support in net-snmp])])

  # check for net-snmp headers
  # Some ancient distributions may miss <net-snmp/agent/util_funcs.h> header
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernel_inc $NETSNMP_CFLAGS"
  AC_CHECK_HEADERS(net-snmp/agent/agent_sysORTable.h net-snmp/agent/snmp_vars.h net-snmp/agent/util_funcs.h,[],
    [AC_MSG_ERROR([missing net-snmp headers])],[[
      #include <net-snmp/net-snmp-config.h>
      #include <net-snmp/net-snmp-includes.h>
      #include <net-snmp/agent/net-snmp-agent-includes.h>
    ]])

  SNMP_SUPPORT=Yes

  # NETSNMP_CFLAGS can have CPPFLAGS options, so separate them
  NETSNMP_CPPFLAGS_XTRA=`echo " $NETSNMP_CFLAGS " | sed -e "s/ /  /g" -e "s/ -[[^IDU]] *-/ -/g" -e "s/ -[[^IDU]] *[[^-]][[^ ]]* / /g" -e "s/  */ /g"`
  NETSNMP_CFLAGS=`echo " $NETSNMP_CFLAGS " | sed -e "s/ /  /g" -e "s/ -[[IDU]] *[[^ ]]* / /g" -e "s/  */ /g"`
  add_to_var([KA_CFLAGS], [$NETSNMP_CFLAGS])
  add_to_var([KA_CPPFLAGS], [$NETSNMP_CPPFLAGS $NETSNMP_CPPFLAGS_XTRA])

  # NETSNMP_LIBS may have some LDFLAGS options, so separate them
  NETSNMP_LDFLAGS_XTRA=`echo " $NETSNMP_LIBS " | sed -e "s/ /  /g" -e "s/ -l *[[^ ]]* /  /g" -e "s/  */ /g" -e "s/ -/ @-/g" | tr "@" "\n" | sed -e "s/^  *//" -e "s/  *$//" | sort -u | tr "\n" " "`
  NETSNMP_LIBS=`echo " $NETSNMP_LIBS " | sed -e "s/ /  /g" -e "s/ \(-l *[[^ ]]*\) /@\1@/g" | tr "@" "\n" | grep  "^-l" | tr "\n" " " | sed -e "s/  */ /g"`
  add_to_var([KA_LDFLAGS], [$NETSNMP_LDFLAGS $NETSNMP_LDFLAGS_XTRA])
  add_to_var([KA_LIBS], [$NETSNMP_LIBS])

  if test "$enable_snmp_rfc" = yes; then
    SNMP_RFCV2_SUPPORT=Yes
    SNMP_RFCV3_SUPPORT=Yes
  else
    if test "$enable_snmp_rfcv2" = yes; then
      SNMP_RFCV2_SUPPORT=Yes
    fi
    if test "$enable_snmp_rfcv3" = yes; then
      SNMP_RFCV3_SUPPORT=Yes
    fi
  fi
  if test ${SNMP_RFCV2_SUPPORT} = Yes -o \
	  ${SNMP_RFCV3_SUPPORT} = Yes; then
    if test ${VRRP_SUPPORT} != Yes; then
      AC_MSG_ERROR([RFC SNMP support requires VRRP])
    fi
    SNMP_RFC_SUPPORT=Yes
  fi
  if test ${SNMP_RFCV3_SUPPORT} = Yes -a \
	  "$enable_snmp_reply_v3_for_v2" != no; then
    AC_DEFINE([_SNMP_REPLY_V3_FOR_V2_], [ 1 ], [Define to 1 to have keepalived send RFC6527 SNMP responses for VRRPv2 instances])
    SNMP_V3_FOR_V2=Yes
    add_config_opt([SNMP_V3_FOR_V2])
  fi

  if test "$enable_snmp" = yes; then
    if test ${VRRP_SUPPORT} = Yes; then
      SNMP_VRRP_SUPPORT=Yes
    fi
    if test ${IPVS_SUPPORT} = Yes; then
      SNMP_CHECKER_SUPPORT=Yes
    fi
  else
    if test "$enable_snmp_vrrp" = yes; then
      SNMP_VRRP_SUPPORT=Yes
    fi
    if test "$enable_snmp_checker" = yes; then
      SNMP_CHECKER_SUPPORT=Yes
    fi
  fi
  if test ${VRRP_SUPPORT} != Yes -a \
	  ${SNMP_VRRP_SUPPORT} = Yes; then
    AC_MSG_ERROR([VRRP SNMP support requires VRRP])
  fi
  if test ${IPVS_SUPPORT} = No -a \
	  ${SNMP_CHECKER_SUPPORT} = Yes; then
    AC_MSG_ERROR([CHECKER SNMP support requires checker])
  fi

  if test ${SNMP_VRRP_SUPPORT} = Yes -o \
	  ${SNMP_CHECKER_SUPPORT} = Yes; then
    SNMP_KEEPALIVED_SUPPORT=Yes
  fi

  CPPFLAGS="$SAV_CPPFLAGS"
  CFLAGS="$SAV_CFLAGS"
  LIBS="$SAV_LIBS"
fi

dnl ----[What SNMP support is required]----
if test $SNMP_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_], [ 1 ], [Define to 1 to have SNMP support])
fi
if test $SNMP_KEEPALIVED_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_KEEPALIVED_], [ 1 ], [Define to 1 to have keepalived SNMP support])
fi
if test $SNMP_VRRP_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_VRRP_], [ 1 ], [Define to 1 to have keepalived SNMP VRRP support])
  add_config_opt([SNMP_VRRP])
fi
if test $SNMP_CHECKER_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_CHECKER_], [ 1 ], [Define to 1 to have keepalived SNMP checker support])
  add_config_opt([SNMP_CHECKER])
fi
if test $SNMP_RFC_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFC_], [ 1 ], [Define to 1 to have RFC SNMP support])
fi
if test $SNMP_RFCV2_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFCV2_], [ 1 ], [Define to 1 to have RFCv2 SNMP support])
  add_config_opt([SNMP_RFCV2])
fi
if test $SNMP_RFCV3_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFCV3_], [ 1 ], [Define to 1 to have RFCv3 SNMP support])
  add_config_opt([SNMP_RFCV3])
fi
AM_CONDITIONAL([SNMP], [test $SNMP_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_KEEPALIVED], [test $SNMP_KEEPALIVED_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_VRRP], [test $SNMP_VRRP_SUPPORT = Yes -o $SNMP_RFC_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_CHECKER], [test $SNMP_CHECKER_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFC], [test $SNMP_RFCV2_SUPPORT = Yes -o $SNMP_RFCV3_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFCV2], [test $SNMP_RFCV2_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFCV3], [test $SNMP_RFCV3_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_REPLY_V3_FOR_V2], [test $SNMP_V3_FOR_V2 = Yes])
AS_IF([test $SNMP_SUPPORT = Yes], [SNMP_SERVICE=snmpd.service], [SNMP_SERVICE=])
AC_SUBST([SNMP_SERVICE])

dnl ----[ Check for Dbus support ]----
DBUS_SUPPORT=No
DBUS_CREATE_INSTANCE=No
if test "$enable_dbus" = yes; then
  AC_CHECK_LIB(gio-2.0, g_bus_own_name,
    [
      add_pkg_config([gio-2.0])
      DBUS_SUPPORT=Yes
      AC_DEFINE([_WITH_DBUS_], [ 1 ], [Define to 1 to have DBUS support])
      add_config_opt([DBUS])

      dnl -- g_type_init() not needed and deprecated since glib 2.36
      SAV_CFLAGS=$CFLAGS
      CFLAGS="$($PKG_CONFIG --cflags gio-2.0)"
      SAV_LIBS=$LIBS
      LIBS="$($PKG_CONFIG --libs gio-2.0)"
      AC_RUN_IFELSE(
	[
	  AC_LANG_PROGRAM(
	    [[#include <gio/gio.h>]],
	    [[return !g_thread_functions_for_glib_use.mutex_lock;]])],
	[need_g_type_init=0],
	[need_g_type_init=1],
	[
	  AC_MSG_WARN([Cannot determine if need to call g_type_init(). Assuming yes for safety.])
	  need_g_type_init=1
	])
      if test $need_g_type_init -eq 1; then
	AC_DEFINE([DBUS_NEED_G_TYPE_INIT], [ 1 ], [Define to 1 if need to call g_type_init()])
      fi
      LIBS=$SAV_LIBS
      CFLAGS=$SAV_CFLAGS
      if test "$enable_dbus_create_instance" = yes; then
	AC_DEFINE([_WITH_DBUS_CREATE_INSTANCE_], [ 1 ], [Define to 1 to have DBus create instance support])
	DBUS_CREATE_INSTANCE=Yes
	add_config_opt([DBUS_CREATE_INSTANCE])
	AC_MSG_WARN([DBus create instance functionality is dangerous - why do you want it?])
      fi
    ],
    [AC_MSG_ERROR([DBUS support requested but libgio-2.0 not found.])])
  unset LIBS
fi
AM_CONDITIONAL([WITH_DBUS], [test $DBUS_SUPPORT = Yes])
AM_CONDITIONAL([DBUS_CREATE_INSTANCE], [test $DBUS_CREATE_INSTANCE = Yes])

dnl ----[ check for SO_MARK support ]----
dnl -- Since Linux 2.6.25
SO_MARK_SUPPORT=No
if test "${enable_fwmark}" != no; then
  AC_CHECK_DECLS([SO_MARK],
    [
      SO_MARK_SUPPORT=Yes
      AC_DEFINE([_WITH_SO_MARK_], [ 1 ], [Define to 1 if have SO_MARK])
      add_system_opt([SO_MARK])
    ], [],
    [[#include <sys/socket.h>]])
fi

dnl -- Do we want GNU standard paths (moves .pid files)
GNU_STD_PATHS=No
if test "${enable_gnu_std_paths}" = "yes"; then
  AC_DEFINE([GNU_STD_PATHS], [ 1 ], [set to enforce GNU standard paths, for .pid files etc])
  RUN_DIR=$localstatedir
elif test $RUN_DIR_SPECIFIED = Y -a .${with_run_dir} != .no; then
  AS_IF([test `expr substr ${with_run_dir} 1 1` != /], [AC_MSG_ERROR([run-dir must be absolute path])])
  # Remove any trailing /run and / - someone will include then sometime
  RUN_DIR=`echo ${with_run_dir} | sed -e "s:/run/*$::" -e "s:/*$::"`
elif test -d /run; then
  RUN_DIR=
else
  RUN_DIR=/var
fi
AC_DEFINE_UNQUOTED([RUN_DIR_ROOT], [ "${RUN_DIR}" ], [Parent directory of /run])
AC_SUBST([RUN_DIR_ROOT], [${RUN_DIR}])

if test $TMP_DIR_SPECIFIED = Y; then
  AS_IF([test `expr substr ${with_tmp_dir} 1 1` != /], [AC_MSG_ERROR([tmp-dir must be absolute path])])
  # Remove any trailing / - someone will include it sometime
  KA_TMP_DIR=`echo ${with_tmp_dir} | sed -e "s:/*$::"`
else
  KA_TMP_DIR=/tmp
fi
KA_TMP_DIR_LEN=`expr length $KA_TMP_DIR`
AC_DEFINE_UNQUOTED([KA_TMP_DIR], [ "${KA_TMP_DIR}" ], [Location for temporary files])
AC_DEFINE_UNQUOTED([KA_TMP_DIR_LEN], [ ${KA_TMP_DIR_LEN} ], [Length of KA_TMP_DIR])
AC_SUBST([KA_TMP_DIR], [${KA_TMP_DIR}])

dnl - Check type of rlim_t for printf() - this check needs to be late on
dnl - since _FILE_OFFSET_BITS (set when using netsnmp) alters sizeof(rlim_t)
SAV_CFLAGS="$CFLAGS"
CFLAGS="-Wformat -Werror=format $SAV_CPPFLAGS $KA_CPPFLAGS"
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <stdio.h>
  #include <sys/resource.h>
  int
  main(int argc, char **argv)
  {
    rlim_t val = 23U;
    printf("%lu %d %p", val, argc, argv);

    return 0;
  }
  ]])],
  [AC_DEFINE([PRI_rlim_t], ["lu"], [Define printf format specifier for rlim_t])],
  [AC_DEFINE([PRI_rlim_t], ["llu"], [Define printf format specifier for rlim_t])],
  )
CFLAGS="$SAV_CFLAGS"

dnl ---[ check for sphinx-build executable ]----
if test -z "$SPHINXBUILD"; then
  SPHINXBUILDNAME=sphinx-build
else
  SPHINXBUILDNAME=${SPHINXBUILD}
fi
AC_SUBST(SPHINXBUILDNAME)
AC_CHECK_PROG([HAVE_SPHINX_BUILD], [$SPHINXBUILDNAME], [Yes], [No])
AM_CONDITIONAL([BUILD_DOCS], [test $HAVE_SPHINX_BUILD = Yes])

dnl ----[ Memory alloc check or not ? ]----
MEM_CHECK=No
MEM_CHECK_LOG=No
if test "${enable_mem_check}" = "yes"; then
  MEM_CHECK=Yes
  AC_DEFINE([_MEM_CHECK_], [ 1 ], [Define to 1 to build with malloc/free checks])
  add_config_opt([MEM_CHECK])
  if test "${enable_mem_check_log}" = "yes"; then
    MEM_CHECK_LOG=Yes
    AC_DEFINE([_MEM_CHECK_LOG_], [ 1 ], [Define to 1 to log malloc/free checks to syslog])
    add_config_opt([MEM_CHECK_LOG])
  fi
fi

dnl ----[ Log calls to set_time or not ? ]----
TIMER_CHECK=No
if test "${enable_timer_check}" = "yes"; then
  TIMER_CHECK=Yes
  AC_DEFINE([_TIMER_CHECK_], [ 1 ], [Define to 1 to build with set time logging])
  add_config_opt([TIMER_CHECK])
fi

dnl ----[ Debug in one process or not ? ]----
if test "${enable_one_process_debug}" = yes; then
  AC_DEFINE([_ONE_PROCESS_DEBUG_], [ 1 ], [Define to 1 to build with debugging support])
  ENABLE_ONE_PROCESS_DEBUG=Yes
  add_config_opt([ONE_PROCESS_DEBUG])
else
  ENABLE_ONE_PROCESS_DEBUG=No
fi
AM_CONDITIONAL([ONE_PROCESS_DEBUG], [test $ENABLE_ONE_PROCESS_DEBUG = Yes])

dnl ----[ Netlink command timers or not ? ]----
if test "${enable_netlink_timers}" = yes; then
  AC_DEFINE([_NETLINK_TIMERS_], [ 1 ], [Define to 1 to build with netlink command timers support])
  ENABLE_NETLINK_TIMERS=Yes
  add_config_opt([NETLINK_TIMERS])
else
  ENABLE_NETLINK_TIMERS=No
fi

dnl ----[ smtp-alert debugging or not ? ]----
if test "${enable_smtp_alert_debug}" = yes; then
  AC_DEFINE([_SMTP_ALERT_DEBUG_], [ 1 ], [Define to 1 to build with smtp-alert debugging support])
  ENABLE_SMTP_ALERT_DEBUG=Yes
  add_config_opt([SMTP_ALERT_DEBUG])
  ENABLE_LOG_FILE_APPEND=Yes
else
  ENABLE_SMTP_ALERT_DEBUG=No
fi

dnl ----[ Stacktrace support or not ? ]----
if test "${enable_stacktrace}" = yes; then
  AC_DEFINE([_WITH_STACKTRACE_], [ 1 ], [Define to 1 to build with stacktrace support])
  ENABLE_STACKTRACE=Yes
  add_config_opt([STACKTRACE])
  add_to_var([KA_LDFLAGS], [-rdynamic])
else
  ENABLE_STACKTRACE=No
fi

dnl ----[ Thread dumping support or not ? ]----
if test "${enable_dump_threads}" = yes; then
  AC_DEFINE([_WITH_DUMP_THREADS_], [ 1 ], [Define to 1 to build with thread dumping support])
  ENABLE_DUMP_THREADS=Yes
  add_config_opt([DUMP_THREADS])
else
  ENABLE_DUMP_THREADS=No
fi

dnl ----[ epoll() debugging support or not ? ]----
if test "${enable_epoll_debug}" = yes; then
  AC_DEFINE([_EPOLL_DEBUG_], [ 1 ], [Define to 1 to build with epoll_wait() debugging support])
  ENABLE_EPOLL_DEBUG=Yes
  add_config_opt([EPOLL_DEBUG])
else
  ENABLE_EPOLL_DEBUG=No
fi

dnl ----[ epoll() thread dumping support or not ? ]----
if test "${enable_epoll_thread_dump}" = yes; then
  AC_DEFINE([_EPOLL_THREAD_DUMP_], [ 1 ], [Define to 1 to build with epoll thread dumping support])
  ENABLE_EPOLL_THREAD_DUMP=Yes
  add_config_opt([EPOLL_THREAD_DUMP])
else
  ENABLE_EPOLL_THREAD_DUMP=No
fi

if test $ENABLE_EPOLL_THREAD_DUMP = Yes -o $ENABLE_DUMP_THREADS = Yes -o $ENABLE_EPOLL_DEBUG = Yes; then
  AC_DEFINE([THREAD_DUMP], [ 1 ], [Define to 1 to build with thread dumping support])
fi

dnl ----[ TSM debugging support or not ? ]----
if test "${enable_tsm_debug}" = yes; then
  AC_DEFINE([_TSM_DEBUG_], [ 1 ], [Define to 1 to build with TSM debugging support])
  ENABLE_TSM_DEBUG=Yes
  add_config_opt([TSM_DEBUG])
else
  ENABLE_TSM_DEBUG=No
fi

dnl ----[ VRRP FD debugging support or not ? ]----
if test "${enable_vrrp_fd_debug}" = yes; then
  AC_DEFINE([_VRRP_FD_DEBUG_], [ 1 ], [Define to 1 to build with vrrp fd debugging support])
  ENABLE_VRRP_FD_DEBUG=Yes
  add_config_opt([VRRP_FD_DEBUG])
else
  ENABLE_VRRP_FD_DEBUG=No
fi

dnl ----[ network timestamp support or not ? ]----
if test "${enable_network_timestamp}" = yes; then
  AC_DEFINE([_NETWORK_TIMESTAMP_], [ 1 ], [Define to 1 to build with network timestamp support])
  ENABLE_NETWORK_TIMESTAMP=Yes
  add_config_opt([NETWORK_TIMESTAMP])
else
  ENABLE_NETWORK_TIMESTAMP=No
fi

dnl ----[ asserts enabled or not ? ]----
if test "${enable_asserts}" = yes; then
  AC_DEFINE([_ENABLE_ASSERT_], [ 1 ], [Define to 1 to enable asserts])
  ENABLE_ASSERT=Yes
  add_config_opt([ASSERT])
else
  ENABLE_ASSERT=No
fi
AM_CONDITIONAL([ASSERTS], [test $ENABLE_ASSERT = Yes])

dnl ----[ Specify interface type to be unchangeable ]----
if test "${with_fixed_if_type}"; then
  if test "${with_fixed_if_type}" = yes -o ${with_fixed_if_type} = no; then
    AC_MSG_ERROR([An interface type must be specified with --with-fixed-if-type])
  fi
  AC_DEFINE_UNQUOTED([_FIXED_IF_TYPE_], [ "${with_fixed_if_type}" ], [Consider ${with_fixed_if_type} interfaces to be unchangeable])
  FIXED_IF_TYPE=${with_fixed_if_type}
  add_config_opt([FIXED_IF_TYPE=${with_fixed_if_type}])
else
  FIXED_IF_TYPE=
fi

dnl ----[ Profiling or not ? ]----
WITH_PROFILING=No
if test "${enable_profile}" = yes; then
  WITH_PROFILING=Yes
  add_config_opt([PROFILING])
  add_to_var([KA_CFLAGS], [-pg])
fi
AM_CONDITIONAL([PROFILE], [test $WITH_PROFILING = Yes])

dnl ----[ perf support or not? keepalived provides runtime options ]----
if test "${enable_perf}" = yes; then
  AC_DEFINE([_WITH_PERF_], [ 1 ], [Define to 1 to build with perf support])
  ENABLE_PERF=Yes
  add_config_opt([PERF])
  add_to_var([KA_CFLAGS], [-pg])
else
  ENABLE_PERF=No
fi

if test "${enable_log_file}" = yes; then
  AC_DEFINE([ENABLE_LOG_TO_FILE], [ 1 ], [Define if enabling logging to files])
  ENABLE_LOG_FILE_APPEND=Yes
  add_config_opt([FILE_LOGGING])
fi

if test "${ENABLE_LOG_FILE_APPEND}" = Yes; then
  AC_DEFINE([ENABLE_LOG_FILE_APPEND], [ 1 ], [Define if appending to log files is allowed])
  add_config_opt([LOG_FILE_APPEND])
fi

dnl ----[ Do we want RECVMSG debugging code]----
ENABLE_RECVMSG_DEBUG=No
AS_IF([test .$enable_recvmsg_debug = .yes],
  [
    AC_DEFINE([_RECVMSG_DEBUG_], [ 1 ], [Define to add VRRP recvmsg() debugging code])
    add_config_opt([RECVMSG_DEBUG])
    ENABLE_RECVMSG_DEBUG=Yes
  ])

dnl ----[ Do we need to check for EINTR, or enable EINTR debugging code]----
ENABLE_EINTR_DEBUG=No
AS_IF([test .$enable_eintr_debug = .yes],
  [
    AC_DEFINE([_EINTR_DEBUG_], [ 1 ], [Define to test for and log errno == EINTR when no asynchronous signal handlers])
    add_config_opt([EINTR_DEBUG])
    ENABLE_EINTR_DEBUG=Yes
  ],
  [
    AS_IF([test .$enable_eintr_debug = .check],
      [
	AC_DEFINE([CHECK_EINTR], [ 1 ], [Define if need to check for EINTR errno])
	add_config_opt([EINTR_CHECK])
      ])
  ])

dnl ----[ Do we enable script debugging code]----
ENABLE_SCRIPT_DEBUG=No
AS_IF([test .$enable_script_debug = .yes],
  [
    AC_DEFINE([_SCRIPT_DEBUG_], [ 1 ], [Define to enable script debugging support])
    add_config_opt([SCRIPT_DEBUG])
    ENABLE_SCRIPT_DEBUG=Yes
  ])

dnl ----[ Do we want to enable track process debugging code]----
ENABLE_TRACK_PROCESS_DEBUG=No
AS_IF([test .$enable_track_process != .no],
  [
    AS_IF([test .$enable_track_process_debug = .yes],
      [
	AC_DEFINE([_TRACK_PROCESS_DEBUG_], [ 1 ], [Define to enable logging all process connector events])
	add_config_opt([TRACK_PROCESS_DEBUG])
	ENABLE_TRACK_PROCESS_DEBUG=Yes
      ])
  ])

dnl ----[ Do we want to enable parser debugging code]----
ENABLE_PARSER_DEBUG=No
AS_IF([test .$enable_parser_debug = .yes],
  [
    AC_DEFINE([_PARSER_DEBUG_], [ 1 ], [Define to enable parser debugging])
    add_config_opt([PARSER_DEBUG])
    ENABLE_PARSER_DEBUG=Yes
  ])

dnl ----[ Do we want to enable checksum debugging code]----
ENABLE_CHECKSUM_DEBUG=No
AS_IF([test .$enable_checksum_debug = .yes],
  [
    AC_DEFINE([_CHECKSUM_DEBUG_], [ 1 ], [Define to enable checksum debugging])
    add_config_opt([CHECKSUM_DEBUG])
    ENABLE_CHECKSUM_DEBUG=Yes
  ])

dnl ----[ Do we want to enable checker debugging code]----
ENABLE_CHECKER_DEBUG=No
AS_IF([test .$enable_checker_debug = .yes],
  [
    AC_DEFINE([_CHECKER_DEBUG_], [ 1 ], [Define to enable checker debugging])
    add_config_opt([CHECKER_DEBUG])
    ENABLE_CHECKER_DEBUG=Yes
  ])

dnl ----[ Do we want to enable SMTP connect debugging code]----
ENABLE_SMTP_CONNECT_DEBUG=No
AS_IF([test .$enable_smtp_connect_debug = .yes],
  [
    AC_DEFINE([_SMTP_CONNECT_DEBUG_], [ 1 ], [Define to enable SMTP connection debugging])
    add_config_opt([SMTP_CONNECT_DEBUG])
    ENABLE_SMTP_CONNECT_DEBUG=Yes
  ])

dnl ----[ Do we want to enable memory alloc/free error debugging code]----
ENABLE_MEM_ERR_DEBUG=No
AS_IF([test .$enable_mem_err_debug = .yes],
  [
    AC_DEFINE([_MEM_ERR_DEBUG_], [ 1 ], [Define to enable memory alloc/free error debugging])
    add_config_opt([MEM_ERR_DEBUG])
    ENABLE_MEM_ERR_DEBUG=Yes
  ])

dnl ----[ Do we want to enable dump keywords code]----
AS_IF([test .$enable_dump_keywords = .yes],
  [
    AC_DEFINE([_DUMP_KEYWORDS_], [ 1 ], [Define to enable keyword dumping])
    add_config_opt([DUMP_KEYWORDS])
  ])

if test "${NEED_LIBDL}" = Yes; then
  add_to_var([KA_LIBS], [-ldl])
fi

dnl ----[ Determine if we are using pthreads ]----
echo " $KA_LIBS" | grep -qE -- " -l?pthread "
if test $? -eq 0 ;then
  AC_DEFINE([_WITH_PTHREADS_], [ 1 ], [Define to 1 if using pthreads])
fi

dnl ----[ Check if rpmbuild supports --build-in-place ]----
RPM_NO_BIP=1
AC_CHECK_PROG([HAVE_RPM], [rpm], [Yes], [No])
if test $HAVE_RPM = Yes; then
  AC_CHECK_PROG([HAVE_RPMBUILD], [rpmbuild], [Yes], [No])
  RPM_SRC_DIR=`rpm --eval "%{_sourcedir}"`
  if ! test -d $RPM_SRC_DIR; then
    HAVE_RPMBUILD=No
  fi
  if test $HAVE_RPMBUILD = Yes; then
    rpmbuild --help | grep -q -- --build-in-place
    RPM_NO_BIP=$?
  fi
fi
AM_CONDITIONAL([RPM], [test $HAVE_RPM = Yes])
AM_CONDITIONAL([RPM_BIP], [test $RPM_NO_BIP -eq 0])

dnl ----[ Determine system init type]----
INIT_TYPE=
AS_IF(
  [test -n "$init_type"], [INIT_TYPE=$init_type],
  [test -n "$with_systemdsystemunitdir"], [INIT_TYPE=systemd],
  [
    /sbin/init --version 2>/dev/null | grep -q upstart
    AS_IF(
      [test $? -eq 0], [INIT_TYPE=upstart],
      [
	init_path=`which systemctl 2>/dev/null`
	AS_IF([test \( $? -eq 0 -a -x "$init_path" \)],
	  [
	    systemctl | grep -q -- "-\.mount"
	    AS_IF([test $? -eq 0], [INIT_TYPE=systemd])
	  ])
	AS_IF([test \( -z "$INIT_TYPE" -a -f /etc/init.d/networking \)],
	  [
	    init_path=`which openrc-run 2>/dev/null`
	    AS_IF([test \( $? -eq 0 -a -x "$init_path" \)],
	      [
		head -1 /etc/init.d/networking | grep -q "^#! */.*/openrc-run$"
		AS_IF([test $? -eq 0], [INIT_TYPE=openrc])
	      ])
	  ])
	AS_IF([test -z "$INIT_TYPE"],
	  [
	    for f in /etc/init.d/cron* /etc/init.d/*syslog*; do
	      INIT_TYPE=SYSV
	      break
	    done
	  ])
      ])
  ])
AS_IF([test \( .$INIT_TYPE = .systemd -a -z "$with_systemdsystemunitdir" \)], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AS_IF([test .$INIT_TYPE != .], [add_config_opt([INIT=$INIT_TYPE])])

USE_SYSTEMD_NOTIFY=No
SYSTEMD_SERVICE_TYPE=forking
SYSTEMD_EXEC_START_OPTIONS=
AS_IF([test .$INIT_TYPE = .systemd],
  [
    dnl ----[Check for systemd libraries]----
    AS_IF([test .${enable_systemd} != .no],
     [
      $PKG_CONFIG --exists libsystemd
      AS_IF([test $? -eq 0],
       [
	USE_SYSTEMD_NOTIFY=Yes
	add_pkg_config([libsystemd])
	AC_DEFINE([_USE_SYSTEMD_NOTIFY_], [ 1 ], [Define to 1 if want systemd notify support])
	add_config_opt([SYSTEMD_NOTIFY])
	SYSTEMD_SERVICE_TYPE="notify\\nNotifyAccess=all"
	SYSTEMD_EXEC_START_OPTIONS+="--dont-fork"
       ],
       [
	AS_IF([test .${enable_systemd} = .yes], [AC_MSG_WARN([libsystemd missing])])
       ])
     ])
    AC_SUBST([SYSTEMD_SERVICE_TYPE])
  ])
AM_CONDITIONAL([WITH_SYSTEMD_NOTIFY], [test $USE_SYSTEMD_NOTIFY = Yes])
AC_SUBST([SYSTEMD_EXEC_START_OPTIONS])

dnl ----[Default runtime options (in /etc/sysconfig/keepalived)]----
AC_SUBST([KEEPALIVED_RUNTIME_OPTIONS], ["$default_runtime_options"])

dnl ----[Default keepalived configuration file]----
AS_IF([test $default_config_file],
  [
    AS_IF([test $default_config_file = yes -o $default_config_file = no],
	  [AC_MSG_ERROR([A filename must be specified for default-config-file])])
    CONFIG_FILE=$default_config_file
    add_config_opt([DEFAULT_CONFIG_FILE=${default_config_file}])
  ],
  [default_config_file="\$(sysconfdir)/$PACKAGE/$PACKAGE.conf"])
dir=`echo $default_config_file | $SED -e "s|/[[^/]]*$||"`
name=`echo $default_config_file | $SED -e "s|.*/||"`
AC_SUBST([DEFAULT_CONFIG_FILE], [$default_config_file])
AC_SUBST([DEFAULT_CONFIG_DIR], [${dir}])
AC_SUBST([DEFAULT_CONFIG_FILENAME], [${name}])
# Change any make $(...) variable to the matching shell variable and substitute
default_config_file=`echo $default_config_file | $SED -e "s|\\\$(\(.*\))|\\\${\1}|"`
eval dcf=`echo $default_config_file`
# Remove a leading ${prefix} since that is not part of the real file name
dcf=`echo $dcf | $SED -e "s|^\\\${prefix}||"`
AC_DEFINE_UNQUOTED([DEFAULT_CONFIG_FILE], ["$dcf"], [The default configuration file])

if test -z "$INIT_TYPE"; then
  INIT_TYPE=undetected
elif test $INIT_TYPE = systemd; then
  AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi

AM_CONDITIONAL([INIT_UPSTART], [test $INIT_TYPE = upstart])
AM_CONDITIONAL([INIT_SYSTEMD], [test $INIT_TYPE = systemd])
AM_CONDITIONAL([INIT_SYSV], [test $INIT_TYPE = SYSV])
AM_CONDITIONAL([INIT_OPENRC], [test $INIT_TYPE = openrc])
AM_CONDITIONAL([INIT_SUSE], [test $INIT_TYPE = SUSE])

AC_DEFINE_UNQUOTED([CONFIGURATION_OPTIONS], ["$CONFIG_OPTIONS"], [The configuration options from which the package is built])
AC_DEFINE_UNQUOTED([SYSTEM_OPTIONS], ["$SYSTEM_OPTIONS"], [The system options from which the package is built])

if test $NETLINK_VER -eq 0; then
	NETLINK_VER=None
fi

dnl ----[ Process output target ]----
echo

# Tidy up some strings
KA_CPPFLAGS=`echo $KA_CPPFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_CFLAGS=`echo $KA_CFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_LDFLAGS=`echo $KA_LDFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_LIBS=`echo $KA_LIBS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`

# Tidy up some strings
KA_CPPFLAGS=`echo $KA_CPPFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_CFLAGS=`echo $KA_CFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_LDFLAGS=`echo $KA_LDFLAGS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`
KA_LIBS=`echo $KA_LIBS | sed -e "s/  */ /g" -e "s/^ //" -e "s/ $//"`

AC_OUTPUT

# Restore lib/config_warnings.h.in
mv ${CONFIG_WARNINGS}.sav ${CONFIG_WARNINGS}

dnl ----[ Display current configuration ]----
cat <<EOF;

Keepalived configuration
------------------------
Keepalived version       : ${VERSION}
Compiler                 : ${CC} `${CC} --version | head -1`
Preprocessor flags       : ${KA_CPPFLAGS}
Compiler flags           : ${KA_CFLAGS}
EOF

dnl ----[ display optional vars  ]----
if test -n "$KA_LDFLAGS$KA_LIBS"; then
  echo "Linker flags             : $KA_LDFLAGS"
  echo "Extra Lib                : $KA_LIBS"
fi

echo "Use IPVS Framework       : ${IPVS_SUPPORT}"
if test ${IPVS_SUPPORT} = Yes; then
  echo "IPVS use libnl           : ${IPVS_USE_NL}"
  echo "IPVS syncd attributes    : ${IPVS_SYNCD_ATTRIBUTES}"
  echo "IPVS 64 bit stats        : ${IPVS_64BIT_STATS}"
  echo "HTTP_GET regex support   : ${WITH_REGEX}"
fi
echo "fwmark socket support    : ${SO_MARK_SUPPORT}"
echo "Use VRRP Framework       : ${VRRP_SUPPORT}"
if test ${VRRP_SUPPORT} = Yes; then
  echo "Use VRRP VMAC            : ${MACVLAN_SUPPORT}"
  echo "Use VRRP authentication  : ${VRRP_AUTH_SUPPORT}"
  echo "With track_process       : ${WITH_TRACK_PROCESS}"
  echo "With linkbeat            : ${LINKBEAT_SUPPORT}"
fi
echo "Use BFD Framework        : ${BFD_SUPPORT}"
echo "SNMP vrrp support        : ${SNMP_VRRP_SUPPORT}"
echo "SNMP checker support     : ${SNMP_CHECKER_SUPPORT}"
echo "SNMP RFCv2 support       : ${SNMP_RFCV2_SUPPORT}"
echo "SNMP RFCv3 support       : ${SNMP_RFCV3_SUPPORT}"
if test ${SNMP_RFCV3_SUPPORT} = Yes; then
  echo "SNMP send V3 for V2      : ${SNMP_V3_FOR_V2}"
fi
echo "DBUS support             : ${DBUS_SUPPORT}"
if test ${DBUS_SUPPORT} = Yes; then
  echo "DBUS create instance     : ${DBUS_CREATE_INSTANCE}"
fi
echo "Use JSON output          : ${ENABLE_JSON}"
echo "libnl version            : ${NETLINK_VER}"
echo "Use IPv4 devconf         : ${IPV4_DEVCONF}"
echo "Use iptables             : ${USE_IPTABLES}"
if test .$USE_IPTABLES = .Yes; then
  echo "Use libipset             : ${USE_LIBIPSET}"
fi
echo "Use nftables             : ${USE_NFTABLES}"
echo "init type                : ${INIT_TYPE}"
echo "systemd notify           : ${USE_SYSTEMD_NOTIFY}"
echo "Strict config checks     : ${STRICT_CONFIG}"
echo "Build documentation      : ${HAVE_SPHINX_BUILD}"
if test ${ENABLE_STACKTRACE} = Yes; then
  echo "Stacktrace support       : Yes"
fi
if test ${ENABLE_PERF} = Yes; then
  echo "Perf support             : Yes"
fi
if test ${MEM_CHECK} = Yes; then
  echo "Memory alloc check       : Yes"
  echo "Memory alloc check log   : ${MEM_CHECK_LOG}"
fi
if test ${TIMER_CHECK} = Yes; then
  echo "Set time logging         : Yes"
fi
if test ${ENABLE_DUMP_THREADS} = Yes; then
  echo "Thread debugging         : Yes"
fi
if test ${ENABLE_EPOLL_DEBUG} = Yes; then
  echo "epoll_wait() debugging   : Yes"
fi
if test ${ENABLE_EPOLL_THREAD_DUMP} = Yes; then
  echo "epoll thread dumping     : Yes"
fi
if test ${ENABLE_REGEX_DEBUG} = Yes; then
  echo "regex debugging          : Yes"
fi
if test ${ENABLE_TSM_DEBUG} = Yes; then
  echo "TSM debugging            : Yes"
fi
if test ${ENABLE_VRRP_FD_DEBUG} = Yes; then
  echo "VRRP_FD debugging        : Yes"
fi
if test ${ENABLE_NETWORK_TIMESTAMP} = Yes; then
  echo "network timestamping     : Yes"
fi
if test ${ENABLE_ASSERT} = Yes; then
  echo "asserts enabled          : Yes"
fi
if test ${ENABLE_ONE_PROCESS_DEBUG} = Yes; then
  echo "Use one process debuging : Yes"
fi
if test ${ENABLE_NETLINK_TIMERS} = Yes; then
  echo "Netlink command timers   : Yes"
fi
if test ${ENABLE_SMTP_ALERT_DEBUG} = Yes; then
  echo "smtp-alert debugging     : Yes"
fi
if test ${ENABLE_RECVMSG_DEBUG} = Yes; then
  echo "RECVMSG debugging        : Yes"
fi
if test ${ENABLE_EINTR_DEBUG} = Yes; then
  echo "EINTR debugging          : Yes"
fi
if test ${ENABLE_SCRIPT_DEBUG} = Yes; then
  echo "Script debugging         : Yes"
fi
if test ${ENABLE_TRACK_PROCESS_DEBUG} = Yes; then
  echo "track process debugging  : Yes"
fi
if test ${ENABLE_PARSER_DEBUG} = Yes; then
  echo "Parser debugging         : Yes"
fi
if test ${ENABLE_CHECKSUM_DEBUG} = Yes; then
  echo "Checksum debugging       : Yes"
fi
if test ${ENABLE_CHECKER_DEBUG} = Yes; then
  echo "checker debugging        : Yes"
fi
if test ${ENABLE_SMTP_CONNECT_DEBUG} = Yes; then
  echo "SMTP connect debugging   : Yes"
fi
if test ${ENABLE_MEM_ERR_DEBUG} = Yes; then
  echo "memory alloc error debug : Yes"
fi
if test "${FIXED_IF_TYPE}"; then
  echo "Fixed interface type     : ${FIXED_IF_TYPE}"
fi
if test "${CONFIG_FILE}"; then
  echo "Default config file      : ${CONFIG_FILE}"
fi
if test "${default_runtime_options}"; then
  echo "Default runtime options  : ${default_runtime_options}"
fi

dnl ----[ end configure ]---

if test ${IPVS_SUPPORT} = Yes -a ${IPVS_USE_NL} = No; then
  echo
  echo "*** WARNING - this build will not support IPVS with IPv6. Please install libnl/libnl-3 dev libraries to support IPv6 with IPVS."
  echo
fi

if test ${ENABLE_ONE_PROCESS_DEBUG} = Yes; then
  echo
  echo "*** WARNING --enable-one-process-debug is only for debugging purposes and isn't expected to work properly"
  echo
fi
