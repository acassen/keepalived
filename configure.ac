#
# Keepalived OpenSource project.
#
# Configuration template file for keepalived.
# autoconf will generate & check deps for proper compilation
#
# Copyright (C) 2001-2016 Alexandre Cassen, <acassen@linux-vs.org>

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
  [ if test $# -ge 2; then
      KA_PKG_PFX=$2
    else
      KA_PKG_PFX=KA
    fi
    add_to_var_ind_unique([${KA_PKG_PFX}_CPPFLAGS], [$($PKG_CONFIG --cflags-only-I $1)])
    add_to_var_ind_unique([${KA_PKG_PFX}_CFLAGS], [$($PKG_CONFIG --cflags-only-other $1)])
    add_to_var_ind_unique([${KA_PKG_PFX}_LIBS], [$($PKG_CONFIG --libs $1)])
  ])

AC_DEFUN([add_build_opt], [add_to_var([BUILD_OPTIONS], [$1])])

dnl ----[ Process this file with autoconf to produce a configure script ]----
AC_PREREQ([2.65])
AC_INIT([Keepalived], [1.3.2], [keepalived-devel@lists.sourceforge.net], [], [http://www.keepalived.org/])
AM_INIT_AUTOMAKE([-Wall -Werror -Woverride foreign])

AC_CONFIG_SRCDIR([keepalived/core/main.c])

AC_CONFIG_HEADERS([lib/config.h])
AH_TOP(
  [
#ifndef _CONFIG_H
#define _CONFIG_H
  ])
AH_BOTTOM(
  [
#endif
  ])

AC_CONFIG_FILES([Makefile keepalived/Makefile lib/Makefile keepalived/core/Makefile keepalived.spec \
		 genhash/Makefile keepalived/check/Makefile keepalived/vrrp/Makefile doc/Makefile \
		 bin_install/Makefile keepalived/dbus/Makefile])

MAINTAINERCLEANFILES="*~ *.orig *.rej core core.*"
AC_SUBST(MAINTAINERCLEANFILES)
BUILD_OPTIONS=

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
  [AS_HELP_STRING([--enable-snmp-rfcv3], [compile with SNMP RFC6257 (VRRPv3) support])])
AC_ARG_ENABLE(snmp-reply-v3-for-v2,
  [AS_HELP_STRING([--disable-snmp-reply-v3-for-v2], [disable RFC6257 responses for VRRPv2 instances])])
AC_ARG_ENABLE(dbus,
  [AS_HELP_STRING([--enable-dbus], [compile with dbus support])])
AC_ARG_ENABLE(dbus-create-instance,
  [AS_HELP_STRING([--enable-dbus-create-instance], [compile with dbus support for creating instances])])
AC_ARG_ENABLE(sha1,
  [AS_HELP_STRING([--enable-sha1], [compile with SHA1 support])])
AC_ARG_ENABLE(vrrp-auth,
  [AS_HELP_STRING([--disable-vrrp-auth], [compile without VRRP authentication])])
AC_ARG_ENABLE(routes,
  [AS_HELP_STRING([--disable-routes], [compile without ip rules/routes])])
AC_ARG_ENABLE(libiptc,
  [AS_HELP_STRING([--disable-libiptc], [compile without libiptc])])
AC_ARG_ENABLE(libipset,
  [AS_HELP_STRING([--disable-libipset], [compile without libipset])])
AC_ARG_ENABLE(mem-check,
  [AS_HELP_STRING([--enable-mem-check], [compile with memory alloc checking])])
AC_ARG_ENABLE(mem-check-log,
  [AS_HELP_STRING([--enable-mem-check-log], [compile with memory alloc checking wriging to syslog])])
AC_ARG_ENABLE(debug,
  [AS_HELP_STRING([--enable-debug], [compile with debugging flags])])
AC_ARG_ENABLE(stacktrace,
  [AS_HELP_STRING([--enable-stracktrace], [compile with stacktrace support])])
AC_ARG_ENABLE(profile,
  [AS_HELP_STRING([--enable-profile], [compile with profiling flags])])
AC_ARG_ENABLE(conversion-checks,
  [AS_HELP_STRING([--enable-conversion-checks], [compile with conversion warnings if sensible])])
AC_ARG_ENABLE(force-conversion-checks,
  [AS_HELP_STRING([--enable-force-conversion-checks], [compile with conversion warnings])])
AC_ARG_ENABLE(Werror,
  [AS_HELP_STRING([--enable-Werror], [compile with warnings being errors])])

AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])

# Set the kernel headers path
if test -n "$kernel_src_path"; then
  kernelinc="-I$kernel_src_path/include"
elif test ! -d /usr/include/linux -a \
            -d /usr/src/linux/include; then
  kernelinc="-I/usr/src/linux/include"
else
  kernelinc=
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PROG_GREP
AC_PROG_LN_S
AC_PROG_SED
AC_CHECK_TOOL(STRIP,strip)

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
ARFLAGS=cr
AC_SUBST(ARFLAGS)

KA_CPPFLAGS="$kernelinc"
KA_CFLAGS="-Wall -Wunused -Wstrict-prototypes -Wextra -g -O2"
KA_LDFLAGS=
KA_LIBS="-ldl"
#KA_LIBTOOLFLAGS = 

if test "$enable_conversion_checks" = yes; then
  # Check if we can sensibly enable -Wconversion
  AC_MSG_CHECKING([for usable -Wconversion])
  SAV_CFLAGS="$CFLAGS"
  CFLAGS="-Wconversion -O2  -Wp,-D_FORTIFY_SOURCE=2  -Werror"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <sys/types.h>
    #include <sys/select.h>
    #include <stdint.h>
    #include <stdbool.h>
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
      KA_CFLAGS="$KA_CFLAGS -Wconversion"
    ],
    [
      AC_MSG_RESULT([no])
      AC_MSG_WARN([-Wconversion is not sensible with this compiler. Use --enable-force-conversion-checks to override.])
    ])
  CFLAGS="$SAV_CFLAGS"
elif test "$enable_force_conversion_checks" = yes; then
  KA_CFLAGS="$KA_CFLAGS -Wconversion"
fi

if test "$enable_Werror" = yes; then
  KA_CFLAGS="$KA_CFLAGS -Werror"
fi

AC_SUBST(KA_CPPFLAGS)
AC_SUBST(KA_CFLAGS)
AC_SUBST(KA_LDFLAGS)
AC_SUBST(KA_LIBS)
# AC_SUBST(KA_LIBTOOLFLAGS)

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h],
  [], [AC_MSG_ERROR([Missing/unusable system header file <$ac_header>])])

# check for kernel headers
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
dnl -- <linux/netlink.h> needed <sys/socket.h> until Linux 3.1
dnl -- using AC_CHECK_HEADER causes a horrible error message for the user
NETLINK_EXTRA_INCLUDE=
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
  #include <linux/netlink.h>
  ]])], [],
  [AC_CHECK_HEADER([linux/netlink.h],
    [
      AC_DEFINE([NETLINK_H_NEEDS_SYS_SOCKET_H], [ 1 ], [Define to 1 if <linux/netlink.h> needs <sys/socket.h>])
      NETLINK_EXTRA_INCLUDE="#include <sys/socket.h>"
    ], [AC_MSG_ERROR([Missing/unusable kernel header file <linux/netlink.h>])],
    [[#include <sys/socket.h>]])])

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
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 getcwd gettimeofday memmove memset select setenv socket strcasecmp strchr strdup strerror strpbrk strstr strtol strtoul uname])
dnl - pipe2() since Linux 2.6.27 and glibc 2.9.
AC_CHECK_FUNCS([pipe2], [add_build_opt([PIPE2])])

# check for missing definition - added in glibc 2.8
AC_CHECK_DECLS([ETHERTYPE_IPV6], [],
  [
    AC_DEFINE([ETHERTYPE_IPV6], [0x86dd], [Defined here if not found in <net/ethernet.h>.])
  ],
  [[#include <net/ethernet.h>]])

BUILD_GENHASH=Yes
dnl ----[ Checks for openssl ]----
# check for openssl headers
NEED_MD5=no
NEED_SSL=no
if test "$enable_vrrp" != no -a \
        "$enable_vrrp_auth" != no; then
  NEED_MD5=yes
fi
if test "$enable_lvs" != no; then
  NEED_MD5=yes
  NEED_SSL=yes
fi
AC_CHECK_HEADERS([openssl/ssl.h openssl/err.h], [],
  [
    if test $NEED_SSL = yes; then
      AC_MSG_ERROR([
  !!! OpenSSL is not properly installed on your system. !!!
  !!! Can not include OpenSSL headers files.            !!!])
    fi
    BUILD_GENHASH=No
    NEED_SSL=no
    break
  ])
AC_CHECK_HEADERS([openssl/md5.h], [],
  [
    if test $NEED_MD5 = yes; then
      AC_MSG_ERROR([
  !!! OpenSSL is not properly installed on your system. !!!
  !!! Can not include OpenSSL MD5 headers files.        !!!])
    fi
    BUILD_GENHASH=No
    NEED_MD5=no
    break
  ])
AC_CHECK_LIB(crypto, MD5_Init, [],
  [
    if test $NEED_MD5 = yes; then
      AC_MSG_ERROR([OpenSSL libraries are required])
    fi
    BUILD_GENHASH=No
  ])
AC_CHECK_LIB(ssl, SSL_CTX_new, [],
  [
    if test $NEED_SSL = yes; then
      AC_MSG_ERROR([OpenSSL libraries are required])
    fi
    BUILD_GENHASH=No
  ])
add_to_var([KA_LIBS], [$LIBS])

if test $BUILD_GENHASH = Yes; then
  GENHASH_LIBS=
  AC_SUBST([GENHASH_LIBS])
  add_to_var([GENHASH_LIBS], [$LIBS])
else
  AC_MSG_NOTICE([Unable to build genhash due to missing openssl headers/libraries])
fi
AM_CONDITIONAL([BUILD_GENHASH], [test $BUILD_GENHASH = Yes])

dnl ----[ Checks for libraries ]----
NETLINK_VER=None
IPVS_USE_NL=No
AC_CHECK_LIB(nl-3, nl_socket_alloc,
  [
    NETLINK_VER=3
    AC_DEFINE([_HAVE_LIBNL3_], [ 1 ], [Define to 1 if using libnl-3])
    add_build_opt([LIBNL3])
    add_pkg_config([libnl-3.0])

    AC_CHECK_LIB(nl-genl-3, genl_connect, [],
      [AC_MSG_ERROR([libnl-3 is installed but not libnl-gen-3. Please, install libnl-gen-3/libnl-genl-3.])])
    IPVS_USE_NL=Yes
    add_pkg_config([libnl-genl-3.0])

    AC_CHECK_LIB(nl-route-3, nl_rtgen_request, [],
      [AC_MSG_ERROR([libnl-3 is installed but not libnl-route-3. Please, install libnl-route-3.])])
    NL3_CFLAGS="$($PKG_CONFIG --cflags libnl-route-3.0)"
    add_pkg_config([libnl-route-3.0])
  ],
  [
    AC_CHECK_LIB(nl, nl_socket_modify_cb,
      [
        IPVS_USE_NL=Yes
        NETLINK_VER=1
        AC_DEFINE([_HAVE_LIBNL1_], [ 1 ], [Define to 1 if using libnl-1])
        add_pkg_config([libnl-1])
        add_build_opt([LIBNL1])
        AC_DEFINE([FALLBACK_LIBNL1], [ 1 ], [Define to 1 if using libnl-1])
        add_build_opt([FALLBACK_LIBNL1])
      ],
      [
        AC_MSG_WARN([keepalived will be built without libnl support.])
      ])
  ])

if test $NETLINK_VER != None; then
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"
  AC_CHECK_HEADERS(libnfnetlink/libnfnetlink.h,,AC_MSG_ERROR([
    !!! Please install libnfnetlink headers.              !!!]))
  if test $NETLINK_VER = 3; then
    CPPFLAGS="$CPPFLAGS $NL3_CFLAGS"
    AC_CHECK_HEADERS([netlink/route/link.h netlink/route/link/inet.h], [], [AC_MSG_ERROR([libnl-3 headers missing])])
  fi

  AC_CHECK_HEADERS([linux/rtnetlink.h], [], [AC_MSG_ERROR([Unusable link/rtnetlink.h])], [$NETLINK_EXTRA_INCLUDE])
  AC_CHECK_HEADERS([libnfnetlink/libnfnetlink.h netlink/genl/ctrl.h netlink/genl/genl.h netlink/netlink.h], [], [AC_MSG_ERROR([netlink headers missing])])

  CPPFLAGS="$SAV_CPPFLAGS"
fi
AM_CONDITIONAL([LIBNL1], [test $NETLINK_VER -eq 1])
AM_CONDITIONAL([LIBNL3], [test $NETLINK_VER -eq 3])

dnl -- Check for the following variables introduced at various times into Linux
dnl --FRA_OIFNAME		dnl -- Linux 2.6.33
dnl --RTAX_QUICKACK		dnl -- Linux 3.11
dnl --FRA_SUPPRESS_PREFIXLEN	dnl -- Linux 3.12
dnl --FRA_SUPPRESS_IFGROUP	dnl -- Linux 3.12
dnl --RTAX_CC_ALGO		dnl -- Linux 4.0
dnl --RTA_VIA			dnl -- Linux 4.1
dnl --RTA_NEWDST		dnl -- Linux 4.1
dnl --RTA_PREF			dnl -- Linux 4.1
dnl --FRA_TUN_ID		dnl -- Linux 4.3
dnl --RTA_ENCAP			dnl -- Linux 4.3
dnl --RTA_EXPIRES		dnl -- Linux 4.5
AC_CHECK_DECLS([RTA_ENCAP, RTA_EXPIRES, RTA_NEWDST, RTA_PREF, FRA_SUPPRESS_PREFIXLEN, FRA_SUPPRESS_IFGROUP, FRA_TUN_ID, RTAX_CC_ALGO, RTAX_QUICKACK], [], [],
  [[#include <linux/rtnetlink.h>
    #include <sys/socket.h>
    #include <linux/fib_rules.h>]])
dnl - following only needed for for flag loop
AC_CHECK_DECLS([RTA_VIA, FRA_OIFNAME], [], [],
  [[#include <linux/rtnetlink.h>
    #include <sys/socket.h>
    #include <linux/fib_rules.h>]])
for flag in RTA_ENCAP RTA_EXPIRES RTA_NEWDST RTA_PREF RTA_VIA FRA_OIFNAME FRA_SUPPRESS_PREFIXLEN FRA_SUPPRESS_IFGROUP FRA_TUN_ID RTAX_CC_ALGO RTAX_QUICKACK; do
  AS_VAR_COPY([decl_var], [ac_cv_have_decl_$flag])
  if test ${decl_var} = yes; then
    add_build_opt[${flag}]
  fi
done

dnl ----[Check if have net/if.h and netlink/route/link.h namespace collision]----
dnl -- Resolved in libnl3-3.2.26 (release 30/3/2015)
if test $NETLINK_VER = 3; then
  AC_MSG_CHECKING([for net/if.h and libnl3/netlink/route/link.h namespace collision])
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $NL3_CFLAGS"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
      #include <net/if.h>
      #include <netlink/route/link.h>
    ]])], [
      AC_MSG_RESULT([no])
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([_HAVE_IF_H_LINK_H_COLLISION_], [ 1 ], [Define to 1 if <net/if.h> and <netlink/route/link.h> namespace collision])
      add_build_opt([IF_H_LINK_H_COLLISION])
    ])
  CPPFLAGS="$SAV_CPPFLAGS"

  dnl ----[Check have IPV4_DEVCONF defines - since Linux 3.11]----
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPP_FLAGS $kernelinc"
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
  CPPFLAGS="$SAV_CPPFLAGS"
else
  IPV4_DEVCONF=No
fi
if test $IPV4_DEVCONF = Yes; then
  AC_DEFINE([_HAVE_IPV4_DEVCONF_], [ 1 ], [Define to 1 if have IPv4 netlink device configuration])
  add_build_opt([IPV4_DEVCONF])
fi

dnl ----[Check for iptables libraries]----
USE_LIBIPTC=No
USE_LIBIPSET=No
if test .${enable_libiptc} != .no; then
  USE_LIBIPTC=Yes
  dnl -- linux/netfilter/x_tables.h since Linux 2.6.16
  AC_CHECK_HEADERS([linux/netfilter/x_tables.h xtables.h libiptc/libip6tc.h libiptc/libiptc.h libiptc/libxtc.h], [],
    [
      USE_LIBIPTC=No
      break
    ])
  if test $USE_LIBIPTC = Yes; then
    add_pkg_config([--static libiptc], [IPTC])
    LIBS="$IPTC_LIBS"
    SAV_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $kernelinc"
    AC_CHECK_LIB(iptc, iptc_init,
      [
        add_pkg_config([--static libiptc])
        AC_DEFINE([_HAVE_LIBIPTC_], [ 1 ], [Define to 1 if have iptables libraries])
      ],
      [USE_LIBIPTC=No])
  CPPFLAGS="$SAV_CPPFLAGS"
  fi

  if test $USE_LIBIPTC = Yes; then
    add_build_opt([LIBIPTC])

    dnl ----[Check for ipset libraries]----
    SAV_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $kernelinc"
    if test "${enable_libipset}" != no; then
      $PKG_CONFIG --exists libipset
      if test $? -eq 0; then
        add_pkg_config([libipset], [IPSET])
      else
        IPSET_LIBS="-lipset"
      fi
      SAV_LIBS=$LIBS
      LIBS="$IPTC_LIBS $IPSET_LIBS"

      AC_CHECK_LIB(ipset, ipset_session_init,
        [
          USE_LIBIPSET=Yes
          AC_CHECK_HEADERS([libipset/data.h libipset/linux_ip_set.h libipset/session.h libipset/types.h], [],
            [
              USE_LIBIPSET=No
              break
            ])
  
          if test $USE_LIBIPSET = Yes; then
            AC_CHECK_LIB(xtables, xtables_insmod, [], [USE_LIBIPSET=No])
          fi

          if test $USE_LIBIPSET = Yes; then
            dnl -- Need to include <libipset/linux_ip_set.h> for <linux/netfilter/xt_set.h> prior to Linux 3.4
            EXTRA_INCLUDE=
            AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
              #include <linux/netfilter/xt_set.h>
              ]])], [],
              [AC_CHECK_HEADER([linux/netfilter/xt_set.h],
                [
                  AC_DEFINE([XT_SET_H_NEEDS_LINUX_IP_SET_H], [ 1 ], [Define to 1 if <linux/netfilter/xt_set.h> needs <libipset/linux_ip_set.h>])
                  EXTRA_INCLUDE="#include <libipset/linux_ip_set.h>"
                ], [AC_MSG_ERROR([Missing/unusable kernel header file <linux/netfilter/xt_set.h>])],
                [[#include <libipset/linux_ip_set.h>]])])
            AC_CHECK_HEADERS([linux/netfilter/xt_set.h], [], [USE_LIBIPSET=No], [$EXTRA_INCLUDE])
  
            AC_DEFINE([_HAVE_LIBIPSET_], [ 1 ], [Define to 1 if have ipset library])
            add_build_opt([LIBIPSET])
            $PKG_CONFIG --exists libipset
            if test $? -eq 0; then
              dnl -- libipset is dynamically linked, so we don't want -lipset
              add_to_var_ind_unique([KA_CPPFLAGS], [$IPSET_CPPFLAGS])
              add_to_var_ind_unique([KA_CFLAGS], [$IPSET_CFLAGS])
            fi
            add_pkg_config([xtables])

            dnl -- xt_set_info_match_v1 declared since Linux 3.1
            AC_CHECK_MEMBER([struct xt_set_info_match_v1.match_set.index], [AC_DEFINE([HAVE_XT_SET_INFO_MATCH_V1], [ 1 ], [Define to 1 if have struct xt_set_info_match_v1])], [],
              [
                $EXTRA_INCLUDE
                #include <linux/netfilter/xt_set.h>
              ])
  
            dnl - ipset type iface introduced in Linux 3.1
            AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
              #include <linux/netfilter/ipset/ip_set.h>
              int main(void) { int var = IPSET_ATTR_IFACE; }
              ]])],
              [AC_DEFINE([HAVE_IPSET_ATTR_IFACE], [ 1 ], [Define to 1 if ipset supports iface type])])
          fi
        ])
      LIBS="$SAV_LIBS"
    fi

    dnl -- XT_EXTENSION_MAXNAMELEN not defined until Linux 2.6.35
    AC_CHECK_DECL([XT_EXTENSION_MAXNAMELEN], [],
      [AC_DEFINE([XT_EXTENSION_MAXNAMELEN], [ (XT_FUNCTION_MAXNAMELEN - 1) ], [Define if <linux/netfilter/x_tables.h> doesnt define it])],
      [#include <linux/netfilter/x_tables.h>])

    CPPFLAGS="$SAV_CPPFLAGS"
  fi
fi
AM_CONDITIONAL([LIBIPTC], [test $USE_LIBIPTC = Yes])
AM_CONDITIONAL([LIBIPSET], [test $USE_LIBIPSET = Yes])
unset LIBS

dnl ----[Check if have linux/if.h and net/if.h namespace collision]----
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
    AC_DEFINE([_HAVE_LINUX_NET_IF_H_COLLISION_], [ 1 ], [Define to 1 if have libiptc/libiptc.h linux/if.h and net/if.h namespace collision])
    add_build_opt([LINUX_NET_IF_H_COLLISION])
  ])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Checks for LVS and VRRP support ]----
IPVS_SYNCD_ATTRIBUTES=No
IPVS_64BIT_STATS=No
if test "$enable_lvs" != no; then
  IPVS_SUPPORT=Yes
  add_build_opt([LVS])
  AC_DEFINE([_WITH_LVS_], [ 1 ], [Define to 1 if have IPVS support])

  dnl -- <linux/ip_vs.h> exists from 2.6.27; prior to that <net/ip_vs.h> is used
  AC_CHECK_HEADERS([linux/ip_vs.h],
    [
      dnl -- From 2.6.35 (but CentOS has it in 2.6.32)
      AC_CHECK_DECLS([IP_VS_SVC_F_ONEPACKET], [], [],
        [[#include <linux/ip_vs.h>]])
    ])

  if test $IPVS_USE_NL = Yes; then
    AC_DEFINE([LIBIPVS_USE_NL], [ 1 ], [Define to 1 if libipvs can use netlink])
    add_build_opt([LIBIPVS_NETLINK])
  fi

  dnl ----[ IPVS syncd options ]---
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"

  dnl -- Since Linux 3.18
  AC_CHECK_DECLS([IPVS_DEST_ATTR_ADDR_FAMILY], [add_build_opt([IPVS_DEST_ATTR_ADDR_FAMILY])], [], [#include <linux/ip_vs.h>])

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

  dnl -- Since Linux 4.3
  if test $IPVS_SYNCD_ATTRIBUTES = Yes; then
    AC_DEFINE([_HAVE_IPVS_SYNCD_ATTRIBUTES_], [ 1 ], [Define to 1 if have IPVS syncd attributes])
    add_build_opt([IPVS_SYNCD_ATTRIBUTES])
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
      add_build_opt([IPVS_64BIT_STATS])
    fi
  fi
  CPPFLAGS="$SAV_CPPFLAGS"
else
  IPVS_SUPPORT=No
fi
AM_CONDITIONAL([WITH_IPVS], [test $IPVS_SUPPORT = Yes])

dnl ----[ Checks for kernel netlink support ]----
VRRP_SUPPORT=No
VRRP_AUTH_SUPPORT=No
MACVLAN_SUPPORT=No
if test "$enable_vrrp" != no; then
  VRRP_SUPPORT=Yes
  AC_DEFINE([_WITH_VRRP_], [ 1 ], [Define to 1 if have VRRP support])
  add_build_opt([VRRP])

  dnl ----[ check for VRRP authentication support ]----
  if test "${enable_vrrp_auth}" != no; then
    VRRP_AUTH_SUPPORT=Yes
    AC_DEFINE([_WITH_VRRP_AUTH_], [ 1 ], [Define to 1 if want ARRP authentication support])
    add_build_opt([VRRP_AUTH])
  fi

  dnl ----[ Checks for kernel VMAC support ]----
  SAV_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $kernelinc"
  MACVLAN_SUPPORT=Yes
  dnl -- Since Linux 2.6.33
  AC_CHECK_DECLS([
      IFLA_MACVLAN_MODE,
      MACVLAN_MODE_PRIVATE], [],
    [
      MACVLAN_SUPPORT=No
      break
    ], [[
      #include <sys/socket.h>
      #include <linux/if_link.h>
    ]])
  if test $MACVLAN_SUPPORT = Yes; then
    AC_DEFINE([_HAVE_VRRP_VMAC_], [ 1 ], [Define to 1 if have MAC VLAN support])
    add_build_opt([VRRP_VMAC])
  fi
  CPPFLAGS="$SAV_CPPFLAGS"
fi
AM_CONDITIONAL([WITH_VRRP], [test $VRRP_SUPPORT = Yes])
AM_CONDITIONAL([VRRP_AUTH], [test $VRRP_AUTH_SUPPORT = Yes])
AM_CONDITIONAL([VMAC], [test $MACVLAN_SUPPORT = Yes])

if test ${IPVS_SUPPORT} = No -a ${VRRP_SUPPORT} = No; then
  AC_MSG_ERROR([keepalived MUST be compiled with at least one of LVS or VRRP framework])
fi

dnl ----[ Checks for glibc SOCK_NONBLOCK support ]----
# Introduced in Linux 2.6.27 and glibc 2.9
AC_CHECK_DECLS([SOCK_NONBLOCK], [add_build_opt([SOCK_NONBLOCK])], [],[[#include <sys/socket.h>]])
AM_CONDITIONAL([SOCK_NONBLOCK], [test $ac_cv_have_decl_SOCK_NONBLOCK = yes])

dnl ----[ Checks for glibc SOCK_CLOEXEC support ]----
# Introduced in Linux 2.6.27 and glibc 2.9
AC_CHECK_DECLS([SOCK_CLOEXEC], [add_build_opt([SOCK_CLOEXEC])], [],[[#include <sys/socket.h>]])

dnl ----[ Checks for pe support ]----
# Introduced in Linux 2.6.37
AC_CHECK_DECL([IPVS_SVC_ATTR_PE_NAME],
   [
     AC_DEFINE([_HAVE_PE_NAME_], [ 1 ], [Define to 1 if have pe selection support])
   ],
   [], [[#include <linux/ip_vs.h>]])

dnl ----[ Checks for FIB routing support ]----
# Introduced in Linux 2.6.19
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
AC_CHECK_DECL([FRA_SRC],
  [
    FIB_ROUTING_SUPPORT=Yes
    AC_DEFINE([_HAVE_FIB_ROUTING_], [ 1 ], [Define to 1 if have FIB routing support])
    add_build_opt([FIB_ROUTING])
  ],
  [
    FIB_ROUTING_SUPPORT=No
  ],[[#include <sys/socket.h>
      #include <linux/fib_rules.h>]])
AM_CONDITIONAL([FIB_ROUTING], [test $FIB_ROUTING_SUPPORT = Yes])
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Checks for kernel IFLA_INET6_ADDR_GEN_MODE support ]----
SAV_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $kernelinc"
if test ${MACVLAN_SUPPORT} = Yes; then
  # Introduced in Linux 3.17
  AC_CHECK_DECLS([IFLA_INET6_ADDR_GEN_MODE],
    [
      add_build_opt([INET6_ADDR_GEN_MODE])
    ], [], [[
      #include <linux/if_link.h>
    ]])
fi
CPPFLAGS="$SAV_CPPFLAGS"

dnl ----[ Checks for SNMP support ]----
SNMP_SUPPORT=No
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
  NETSNMP_LIBS_AGENT=`${NETSNMP_CONFIG} --netsnmp-agent-libs`
  NETSNMP_LIBS_EXT=`${NETSNMP_CONFIG} --external-libs`
  NETSNMP_LIBS="$NETSNMP_LIBS_AGENT $NETSNMP_LIBS_EXT"
  NETSNMP_CFLAGS="`${NETSNMP_CONFIG} --base-cflags` -DNETSNMP_NO_INLINE"

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
  CPPFLAGS="$CPPFLAGS $NETSNMP_CFLAGS"
  AC_CHECK_HEADERS(net-snmp/agent/agent_sysORTable.h net-snmp/agent/snmp_vars.h net-snmp/agent/util_funcs.h,[],
    [AC_MSG_ERROR([missing net-snmp headers])],[[
      #include <net-snmp/net-snmp-config.h>
      #include <net-snmp/net-snmp-includes.h>
      #include <net-snmp/agent/net-snmp-agent-includes.h>
    ]])

  SNMP_SUPPORT=Yes
  add_to_var([KA_CFLAGS], [$NETSNMP_CFLAGS])
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
    AC_DEFINE([_SNMP_REPLY_V3_FOR_V2_], [ 1 ], [Define to 1 to have keepalived send RFC6257 SNMP responses for VRRPv2 instances])
    SNMP_V3_FOR_V2=Yes
    add_build_opt([SNMP_V3_FOR_V2])
  fi

  if test "$enable_snmp" = yes; then
    SNMP_VRRP_SUPPORT=Yes
    SNMP_CHECKER_SUPPORT=Yes
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
    AC_MSG_ERROR([KEEPALIVED SNMP support requires VRRP])
  fi
  if test ${IPVS_SUPPORT} = No -a \
          ${SNMP_CHECKER_SUPPORT} = Yes; then
    AC_MSG_ERROR([CHECKER SNMP support requires checker])
  fi

  CPPFLAGS="$SAV_CPPFLAGS"
  CFLAGS="$SAV_CFLAGS"
  LIBS="$SAV_LIBS"
fi

dnl ----[What SNMP support is required]----
if test $SNMP_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_], [ 1 ], [Define to 1 to have keepalived SNMP support])
  add_build_opt([SNMP])
fi
if test $SNMP_VRRP_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_KEEPALIVED_], [ 1 ], [Define to 1 to have keepalived SNMP VRRP support])
  add_build_opt([SNMP_KEEPALIVED])
fi
if test $SNMP_CHECKER_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_CHECKER_], [ 1 ], [Define to 1 to have keepalived SNMP checker support])
  add_build_opt([SNMP_CHECKER])
fi
if test $SNMP_RFC_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFC_], [ 1 ], [Define to 1 to have RFC SNMP support])
  add_build_opt([SNMP_RFC])
fi
if test $SNMP_RFCV2_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFCV2_], [ 1 ], [Define to 1 to have RFCv2 SNMP support])
  add_build_opt([SNMP_RFCV2])
fi
if test $SNMP_RFCV3_SUPPORT = Yes; then
  AC_DEFINE([_WITH_SNMP_RFCV3_], [ 1 ], [Define to 1 to have RFCv3 SNMP support])
  add_build_opt([SNMP_RFCV3])
fi
AM_CONDITIONAL([SNMP], [test $SNMP_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_VRRP], [test $SNMP_VRRP_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_CHECKER], [test $SNMP_CHECKER_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFC], [test $SNMP_RFC_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFCV2], [test $SNMP_RFCV2_SUPPORT = Yes])
AM_CONDITIONAL([SNMP_RFCV3], [test $SNMP_RFCV3_SUPPORT = Yes])

dnl ----[ Check for Dbus support ]----
DBUS_SUPPORT=No
DBUS_CREATE_INSTANCE=No
if test "$enable_dbus" = yes; then
  AC_CHECK_LIB(gio-2.0, g_bus_own_name,
    [
      add_pkg_config([gio-2.0])
      DBUS_SUPPORT=Yes
      AC_DEFINE([_WITH_DBUS_], [ 1 ], [Define to 1 to have DBUS support])
      add_build_opt([DBUS])

      dnl -- g_type_init() not needed and deprecated since glib 2.36
      CFLAGS="$($PKG_CONFIG --cflags gio-2.0)"
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
      LIBS=
      CFLAGS=
      if test "$enable_dbus_create_instance" = yes; then
        AC_DEFINE([_WITH_DBUS_CREATE_INSTANCE_], [ 1 ], [Define to 1 to have DBus create instance support])
        DBUS_CREATE_INSTANCE=Yes
        add_build_opt([DBUS_CREATE_INSTANCE])
        AC_MSG_WARN([DBus create instance functionality is dangerous - why do you want it?])
      fi
    ],
    [AC_MSG_ERROR([DBUS support requested but libgio-2.0 not found.])])
fi
AM_CONDITIONAL([WITH_DBUS], [test $DBUS_SUPPORT = Yes])
AM_CONDITIONAL([DBUS_CREATE_INSTANCE], [test $DBUS_CREATE_INSTANCE = Yes])

dnl ----[ SHA1 or not ? ]----
SHA1_SUPPORT=No
if test "${enable_sha1}" = yes; then
  AC_CHECK_HEADERS(openssl/sha.h,,AC_MSG_ERROR([unable to find openssl/sha.h]))
  AC_CHECK_LIB(crypto, SHA1_Init,,AC_MSG_ERROR([SHA1 in OpenSSL required]))
  SHA1_SUPPORT=Yes
  AC_DEFINE([_WITH_SHA1_], [ 1 ], [Define to 1 to have SHA1 support])
fi
AM_CONDITIONAL([WITH_SHA1], [test $SHA1_SUPPORT = Yes])

dnl ----[ check for SO_MARK support ]----
SO_MARK_SUPPORT=No
if test "${enable_fwmark}" != no; then
  AC_CHECK_DECLS([SO_MARK],
    [
      SO_MARK_SUPPORT=Yes
      AC_DEFINE([_WITH_SO_MARK_], [ 1 ], [Define to 1 if have SO_MARK])
      add_build_opt([SO_MARK])
    ], [],
    [[#include <sys/socket.h>]])
fi

dnl ---[ check for setns() ]----
dnl -- CLONE_NEWNET defined from Linux 3.0
SAV_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -D_GNU_SOURCE"
AC_CHECK_DECLS([CLONE_NEWNET], [], [], [[#include <sched.h>]])
dnl -- From glibc 2.14. Otherwise use setns syscall, since Linux 2.4.x
AC_CHECK_FUNCS([setns])
CFLAGS="$SAV_CFLAGS"
AM_CONDITIONAL([WITH_NAMESPACES], [test $ac_cv_have_decl_CLONE_NEWNET = yes])

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
  add_build_opt([MEM_CHECK])
  if test "${enable_mem_check_log}" = "yes"; then
    MEM_CHECK_LOG=Yes
    AC_DEFINE([_MEM_CHECK_LOG_], [ 1 ], [Define to 1 to log malloc/free checks to syslog])
    add_build_opt([MEM_CHECK_LOG])
  fi
fi

dnl ----[ Debug or not ? ]----
if test "${enable_debug}" = yes; then
  AC_DEFINE([_DEBUG_], [ 1 ], [Define to 1 to build with debugging support])
  ENABLE_DEBUG=Yes
  add_build_opt([DEBUG])
else
  ENABLE_DEBUG=No
fi
AM_CONDITIONAL([DEBUG], [test $ENABLE_DEBUG = Yes])

dnl ----[ Stacktrace support or not ? ]----
if test "${enable_stacktrace}" = yes; then
  AC_DEFINE([_WITH_STACKTRACE_], [ 1 ], [Define to 1 to build with stacktrace support])
  ENABLE_STACKTRACE=Yes
  add_build_opt([STACKTRACE])
  add_to_var([KA_LDFLAGS], [-rdynamic])
else
  ENABLE_STACKTRACE=No
fi

dnl ----[ Profiling or not ? ]----
WITH_PROFILING=No
if test "${enable_profile}" = yes; then
  WITH_PROFILING=Yes
  add_to_var([KA_CFLAGS], [-pg])
fi
AM_CONDITIONAL([PROFILE], [test $WITH_PROFILING = Yes])

dnl ----[ Determine system init type]----
INIT_TYPE=
/sbin/init --version 2>/dev/null | grep -q upstart
if test $? -eq 0; then
        INIT_TYPE=upstart
else
	if test \( `which systemctl` -a -x `which systemctl` \); then
		systemctl | grep -q -- "-\.mount"
		if test $? -eq 0; then
			AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
			INIT_TYPE=systemd
		fi
	fi
	if test \( -z "$INIT_TYPE" -a -f /etc/init.d/cron -a ! -h /etc/init.d/cron \); then
		INIT_TYPE=SYSV
	fi
fi
if test -z $INIT_TYPE; then INIT_TYPE=undetected; fi
AM_CONDITIONAL([INIT_UPSTART], [test $INIT_TYPE = upstart])
AM_CONDITIONAL([INIT_SYSTEMD], [test $INIT_TYPE = systemd])
AM_CONDITIONAL([INIT_SYSV], [test $INIT_TYPE = SYSV])

echo $INIT_TYPE
VERSION_DATE=`date +%m/%d,%Y`
VERSION_YEAR=`date +%Y`

AC_DEFINE_UNQUOTED([VERSION_DATE], ["$VERSION_DATE"], [Date of build configuration])
AC_DEFINE_UNQUOTED([COPYRIGHT_YEAR], ["$VERSION_YEAR"], [Year of build configuration])
AC_DEFINE_UNQUOTED([CONFIGURATION_OPTIONS], ["$BUILD_OPTIONS"], [The configuration and build options from which the package is built])

dnl ----[ Process output target ]----
echo

AC_OUTPUT

dnl ----[ Display current configuration ]----
cat <<EOF;

Keepalived configuration
------------------------
Keepalived version       : ${VERSION}
Compiler                 : ${CC}
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
fi
echo "fwmark socket support    : ${SO_MARK_SUPPORT}"
echo "Use VRRP Framework       : ${VRRP_SUPPORT}"
if test ${VRRP_SUPPORT} = Yes; then
  echo "Use VRRP VMAC            : ${MACVLAN_SUPPORT}"
  echo "Use VRRP authentication  : ${VRRP_AUTH_SUPPORT}"
  echo "With ip rules/routes     : ${FIB_ROUTING_SUPPORT}"
fi
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
echo "SHA1 support             : ${SHA1_SUPPORT}"
echo "Use Debug flags          : ${ENABLE_DEBUG}"
echo "Stacktrace support       : ${ENABLE_STACKTRACE}"
echo "Memory alloc check       : ${MEM_CHECK}"
if test ${MEM_CHECK} = Yes; then
  echo "Memory alloc check log   : ${MEM_CHECK_LOG}"
fi
echo "libnl version            : ${NETLINK_VER}"
echo "Use IPv4 devconf         : ${IPV4_DEVCONF}"
echo "Use libiptc              : ${USE_LIBIPTC}"
echo "Use libipset             : ${USE_LIBIPSET}"
echo "init type                : ${INIT_TYPE}"
echo "Build genhash            : ${BUILD_GENHASH}"
echo "Build documentation      : ${HAVE_SPHINX_BUILD}"

dnl ----[ end configure ]---
