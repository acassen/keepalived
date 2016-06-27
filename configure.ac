#
# Keepalived OpenSource project.
#
# Configuration template file for keepalived.
# autoconf will generate & check deps for proper compilation
#
# Copyright (C) 2001-2009 Alexandre Cassen, <acassen@linux-vs.org>

dnl ----[ Process this file with autoconf to produce a configure script ]----
AC_INIT(keepalived/core/main.c)
VERSION=`cat VERSION`
VERSION_DATE=`date +%m/%d,%Y`
VERSION_YEAR=`date +%Y`
OUTPUT_TARGET="Makefile genhash/Makefile keepalived/core/Makefile lib/config.h keepalived.spec"

dnl ----[ Checks for programs ]----
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_TOOL(STRIP,strip)

dnl ----[ Keepalived specific configure options ]----
AC_ARG_ENABLE(lvs-syncd,
  [  --disable-lvs-syncd     do not use LVS synchronization daemon])
AC_ARG_ENABLE(lvs,
  [  --disable-lvs           do not use the LVS framework])
AC_ARG_ENABLE(vrrp,
  [  --disable-vrrp          do not use the VRRP framework])
AC_ARG_WITH(kernel-dir,
  [  --with-kernel-dir=DIR   path to linux kernel source directory],
  [kernelinc="$withval/include" kernelpath="$withval"],
  [kernelinc="/usr/src/linux/include" kernelpath="/usr/src/linux"])
AC_ARG_WITH(kernel-version,
  [  --with-kernel-version=VER forced value for linux kernel version (VER=2.4|2.6)],
  [kernelversion="$withval"], [kernelversion=""])
AC_ARG_ENABLE(fwmark,
  [  --disable-fwmark        compile without SO_MARK support])
AC_ARG_ENABLE(snmp,
  [  --enable-snmp           compile with SNMP support])
AC_ARG_ENABLE(snmp-keepalived,
  [  --enable-snmp-keepalived compile with SNMP keepalived support])
AC_ARG_ENABLE(snmp-checker,
  [  --enable-snmp-checker   compile with SNMP checker support])
AC_ARG_ENABLE(snmp-rfc,
  [  --enable-snmp-rfc       compile with SNMP RFC2787 (VRRPv2) and SNMP RFC6527 (VRRPv3) support])
AC_ARG_ENABLE(snmp-rfcv2,
  [  --enable-snmp-rfcv2     compile with SNMP RFC2787 (VRRPv2) support])
AC_ARG_ENABLE(snmp-rfcv3,
  [  --enable-snmp-rfcv3     compile with SNMP RFC6257 (VRRPv3) support])
AC_ARG_ENABLE(sha1,
  [  --enable-sha1           compile with SHA1 support])
AC_ARG_ENABLE(vrrp-auth,
  [  --disable-vrrp-auth     compile without VRRP authentication])
AC_ARG_ENABLE(libiptc,
  [  --disable-libiptc       compile without libiptc])
AC_ARG_ENABLE(libipset,
  [  --disable-libipset      compile without libipset])
AC_ARG_ENABLE(mem-check,
  [  --enable-mem-check      compile with memory alloc checking])
AC_ARG_ENABLE(mem-check-log,
  [  --enable-mem-check-log  compile with memory alloc checking writing to syslog])
AC_ARG_ENABLE(debug,
  [  --enable-debug          compile with debugging flags])
AC_ARG_ENABLE(profile,
  [  --enable-profile        compile with profiling flags])

dnl ----[ Checks for header files ]----
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(fcntl.h syslog.h unistd.h sys/ioctl.h sys/time.h linux/netfilter/x_tables.h)
dnl [do we really need this ?] AC_CHECK_HEADERS(linux/netlink.h linux/rtnetlink.h)
AC_CHECK_HEADERS(openssl/ssl.h openssl/md5.h openssl/err.h,,AC_MSG_ERROR([
  !!! OpenSSL is not properly installed on your system. !!!
  !!! Can not include OpenSSL headers files.            !!!]))
AC_CHECK_DECL([ETHERTYPE_IPV6],[],[CFLAGS="$CFLAGS -DETHERTYPE_IPV6=0x86dd"],
  [[@%:@include <net/ethernet.h>]])

dnl ----[ Checks for libraries ]----
AC_CHECK_LIB(crypt, crypt,,AC_MSG_ERROR([crypt() function is required]))
AC_CHECK_LIB(crypto, MD5_Init,,AC_MSG_ERROR([OpenSSL libraries are required]))
AC_CHECK_LIB(ssl, SSL_CTX_new,,AC_MSG_ERROR([OpenSSL libraries are required]))

USE_NL3="_WITHOUT_LIBNL_"
AC_CHECK_LIB(nl-3, nl_socket_alloc,
  [
    AC_CHECK_LIB(nl-genl-3, genl_connect,
      [
        IPVS_USE_NL="LIBIPVS_USE_NL"
        CFLAGS="$CFLAGS $(pkg-config --cflags libnl-genl-3.0)"
        LIBS="$LIBS $(pkg-config --libs libnl-genl-3.0)"
      ],
      [
        AC_MSG_ERROR([libnl-3 is installed but not libnl-gen-3. Please, install libnl-gen-3.])
      ])
    AC_CHECK_LIB(nl-route-3, nl_rtgen_request,
      [
        USE_NL3="_HAVE_LIBNL3_"
        CFLAGS="$CFLAGS $(pkg-config --cflags libnl-route-3.0)"
        LIBS="$LIBS $(pkg-config --libs libnl-route-3.0)"
      ])
  ],
  [
    AC_CHECK_LIB(nl, nl_socket_modify_cb,
      [
        IPVS_USE_NL="LIBIPVS_USE_NL"
        USE_NL3="_HAVE_LIBNL1_"
        CFLAGS="$CFLAGS -DFALLBACK_LIBNL1"
        LIBS="$LIBS $(pkg-config --libs libnl-1)"
      ],
      [
        IPVS_USE_NL="LIBIPVS_DONTUSE_NL"
        AC_MSG_WARN([keepalived will be built without libnl support.])
      ])
  ])

AC_SUBST(USE_NL3)

if test "$USE_NL3" != "_WITHOUT_LIBNL_"; then
  AC_CHECK_HEADERS(libnfnetlink/libnfnetlink.h,,AC_MSG_ERROR([
    !!! Please install libnfnetlink headers.              !!!]))
fi

dnl ----[Check if have linux/if.h and netlink/route/link.h namespace collision]----
IF_H_LINK_H_COLLISION="_WITHOUT_IF_H_LINK_H_COLLISION_"
if test "${USE_NL3}" = "_HAVE_LIBNL3_"; then
  AC_MSG_CHECKING([for linux/if.h and netlink/route/link.h namespace collision])
  AC_TRY_COMPILE([
      #include <net/if.h>
      #include <netlink/route/link.h>
    ], [
    ], [], [
      IF_H_LINK_H_COLLISION=_HAVE_IF_H_LINK_H_COLLISION_
    ]);
  if test "$IF_H_LINK_H_COLLISION" = "_HAVE_IF_H_LINK_H_COLLISION_"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi

AC_SUBST(IF_H_LINK_H_COLLISION)

dnl ----[Check if have linux/if.h and net/if.h namespace collision]----
# Linux 4.5 caused <libiptc/libiptc.h> to indirectly include <net/if.h> and <linux/if.h>
# which causes a namespace collision.
# This issue was resolved in Linux 4.5.5 and 4.6
LINUX_NET_IF_H_COLLISION="_WITHOUT_LINUX_NET_IF_H_COLLISION_"
AC_MSG_CHECKING([for libiptc/libiptc.h linux/if.h and net/if.h namespace collision])
AC_TRY_COMPILE([
    #include <libiptc/libiptc.h>
  ], [
  ], [], [
    LINUX_NET_IF_H_COLLISION=_HAVE_LINUX_NET_IF_H_COLLISION_
  ]);
if test "$LINUX_NET_IF_H_COLLISION" = "_HAVE_LINUX_NET_IF_H_COLLISION_"; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_SUBST(LINUX_NET_IF_H_COLLISION)

dnl ----[Check have IPV4_DEVCONF defines]----
IPV4_DEVCONF="_WITHOUT_IPV4_DEVCONF_"
if test "${USE_NL3}" = "_HAVE_LIBNL3_"; then
  AC_MSG_CHECKING([for IPV4_DEVCONF defines])
  AC_TRY_COMPILE([
      #include <linux/ip.h>
      int devconf;
    ], [
      devconf = IPV4_DEVCONF_ARP_IGNORE;
      devconf = IPV4_DEVCONF_ACCEPT_LOCAL;
      devconf = IPV4_DEVCONF_RP_FILTER;
      devconf = IPV4_DEVCONF_ARPFILTER;
    ], [
      IPV4_DEVCONF_SUPPORT=yes
    ], []);
  if test "$IPV4_DEVCONF_SUPPORT" = "yes"; then
    IPV4_DEVCONF="_HAVE_IPV4_DEVCONF_"
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi

AC_SUBST(IPV4_DEVCONF)

dnl ----[Check for iptables libraries]----
USE_LIBIPTC=_WITHOUT_LIBIPTC_
if test "${enable_libiptc}" != "no"; then
  SAV_LIBS=$LIBS
  LIBS="$LIBS $(pkg-config --libs --static libiptc)"
  AC_CHECK_LIB(iptc, iptc_init,
    [
      USE_LIBIPTC="_HAVE_LIBIPTC_"
      SAV_LIBS=$LIBS
    ])
  LIBS=$SAV_LIBS
fi

AC_SUBST(USE_LIBIPTC)

dnl ----[Check for ipset libraries]----
USE_LIBIPSET=_WITHOUT_LIBIPSET_
if test "${USE_LIBIPTC}" = "_HAVE_LIBIPTC_"; then
  if test "${enable_libipset}" != "no"; then
    SAV_LIBS=$LIBS
    LIBS="$LIBS -lipset -lxtables"
    AC_CHECK_LIB(ipset, ipset_session_init,
      [
	AC_TRY_COMPILE([
	    #include <linux/netfilter/xt_set.h>
	    ip_set_id_t id;
	  ], [
	  ], [
	    IPSET_HEADERS_OK=yes
	  ], [
	    IPSET_HEADERS_OK=no
	  ]);

	if test "$IPSET_HEADERS_OK" = "yes"; then
          USE_LIBIPSET="_HAVE_LIBIPSET_"
          SAV_LIBS=$LIBS
	fi
      ],
      [])
    LIBS=$SAV_LIBS
  fi
fi

AC_SUBST(USE_LIBIPSET)

dnl ----[ Kernel version check ]----
CPPFLAGS="$CPPFLAGS -I$kernelinc"
AC_MSG_CHECKING([for kernel version])
AC_TRY_RUN([
    #include <stdlib.h>
    #include <stdio.h>
    #include <linux/version.h>
    #if !defined(UTS_RELEASE) && !defined(LINUX_VERSION_CODE)
    #include <linux/utsrelease.h>
    #endif
    int main (void) {
      FILE *fp = fopen ("linuxinfo", "w");
      if (!fp) return 1;
    #if defined(UTS_RELEASE)
      fprintf (fp, "%s\n", UTS_RELEASE);
    #elif defined(LINUX_VERSION_CODE)
      fprintf (fp, "%d.%d.%d\n", LINUX_VERSION_CODE >> 16, (LINUX_VERSION_CODE >> 8) & 0xFF, LINUX_VERSION_CODE & 0xFF);
    #else
      fprintf (fp, "0.0.0\n"); /* Let''s fail gently */
    #endif
      fclose (fp);
      return 0;
    }
  ], [
    LINUX_MAJOR=`cat linuxinfo | cut -d'.' -f1`
    LINUX_MINOR=`cat linuxinfo | cut -d'.' -f2`
    LINUX_PATCH=`cat linuxinfo | cut -d'.' -f3`
  ], [
    LINUX_MAJOR="0"
    LINUX_MINOR="0"
    LINUX_PATCH="0"
  ], [
    LINUX_MAJOR="0"
    LINUX_MINOR="0"
    LINUX_PATCH="0"
  ])
  rm -f linuxinfo

  if test "$kernelversion" = "2.4"; then
    KERN="_KRNL_2_4_"
    AC_MSG_RESULT([2.4])
  elif test "$kernelversion" = "2.6"; then
    KERN="_KRNL_2_6_"
    AC_MSG_RESULT([2.6])
  else
    AC_MSG_RESULT([$LINUX_MAJOR.$LINUX_MINOR.$LINUX_PATCH])
    if test "$LINUX_MAJOR" = "2" && test "$LINUX_MINOR" = "6"; then
      KERN="_KRNL_2_6_"
    elif test "$LINUX_MAJOR" = "2" && test "$LINUX_MINOR" = "4"; then
      KERN="_KRNL_2_4_"
    else
      KERN="_KRNL_2_6_"
    fi
    if test "$LINUX_MAJOR" = "0" -a "$LINUX_MINOR" = "0" -a "$LINUX_PATCH" = "0"; then
      AC_MSG_WARN([Cannot determine Linux Kernel version.])
    fi
  fi

AC_SUBST(KERN)

dnl ----[ Checks for LVS and VRRP support ]----
IPVS_SUPPORT="_WITHOUT_LVS_"
if test "$enable_lvs" != "no"; then
  if test "$KERN" = "_KRNL_2_6_"; then
    IPVS_SUPPORT="_WITH_LVS_"
  else
    AC_CHECK_HEADER([net/ip_vs.h],
      [IPVS_SUPPORT="_WITH_LVS_"],
      [
        IPVS_SUPPORT="_WITHOUT_LVS_"
        AC_MSG_WARN([keepalived will be built without LVS support.])
      ])
  fi
fi

if test "$IPVS_SUPPORT" = "_WITHOUT_LVS_" -a "$enable_vrrp" = "no"; then
  AC_MSG_ERROR([keepalived MUST be compiled at least with LVS or VRRP framework])
fi

dnl ----[ IPVS syncd support probe ]---
IPVS_SYNCD="_WITHOUT_IPVS_SYNCD_"
if test "$IPVS_SUPPORT" = "_WITH_LVS_"; then
  AC_MSG_CHECKING([for IPVS syncd support])
  if test "$KERN" = "_KRNL_2_6_"; then
    IPVS_SYNCD="_HAVE_IPVS_SYNCD_"
  elif test "_KRNL_2_4_"; then
    IPVS_SYNCD="_HAVE_IPVS_SYNCD_"
  else
    IPVS_SYNCD="_WITHOUT_IPVS_SYNCD_"
  fi

  if test "${IPVS_SUPPORT}" = "_WITHOUT_LVS_" -o "$enable_lvs_syncd" = "no"; then
    IPVS_SYNCD="_WITHOUT_IPVS_SYNCD_"
  fi

  if test "$IPVS_SYNCD" = "_HAVE_IPVS_SYNCD_"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi

AC_SUBST(IPVS_SYNCD)

dnl ----[ Checks for kernel netlink support ]----
VRRP_SUPPORT="_WITHOUT_VRRP_"
if test "$enable_vrrp" != "no"; then
  VRRP_SUPPORT="_WITH_VRRP_"
fi

dnl ----[ Checks for glibc SOCK_NONBLOCK support ]----
# Introduced in Linux 2.6.23
AC_MSG_CHECKING([for SOCK_NONBLOCK support])
AC_TRY_COMPILE([
    #include <sys/socket.h>
    int flags;
  ], [
    flags = SOCK_NONBLOCK;
  ], [
    SOCK_NONBLOCK_SUPPORT=yes
  ], []);

  if test "$SOCK_NONBLOCK_SUPPORT" = "yes"; then
    SOCK_NONBLOCK_SUPPORT="_HAVE_SOCK_NONBLOCK_"
    AC_MSG_RESULT([yes])
  else
    SOCK_NONBLOCK_SUPPORT="_WITHOUT_SOCK_NONBLOCK_"
    AC_MSG_RESULT([no])
  fi

AC_SUBST(SOCK_NONBLOCK_SUPPORT)

dnl ----[ Checks for glibc SOCK_CLOEXEC support ]----
# Introduced in Linux 2.6.23
AC_MSG_CHECKING([for SOCK_CLOEXEC support])
AC_TRY_COMPILE([
    #include <sys/socket.h>
    int flags;
  ], [
    flags = SOCK_CLOEXEC;
  ], [
    SOCK_CLOEXEC_SUPPORT=yes
  ], []);

  if test "$SOCK_CLOEXEC_SUPPORT" = "yes"; then
    SOCK_CLOEXEC_SUPPORT="_HAVE_SOCK_CLOEXEC_"
    AC_MSG_RESULT([yes])
  else
    SOCK_CLOEXEC_SUPPORT="_WITHOUT_SOCK_CLOEXEC_"
    AC_MSG_RESULT([no])
  fi

AC_SUBST(SOCK_CLOEXEC_SUPPORT)

dnl ----[ Checks for FIB routing support ]----
# Introduced in Linux 2.6.19
AC_MSG_CHECKING([for SOCK_CLOEXEC support])
AC_TRY_COMPILE([
    #include <linux/fib_rules.h>
    int type;
  ], [
    type = FRA_SRC;
  ], [
    FIB_ROUTING_SUPPORT=yes
  ], []);

  if test "$FIB_ROUTING_SUPPORT" = "yes"; then
    FIB_ROUTING_SUPPORT="_HAVE_FIB_ROUTING_"
    AC_MSG_RESULT([yes])
  else
    FIB_ROUTING_SUPPORT="_WITHOUT_FIB_ROUTING_"
    AC_MSG_RESULT([no])
  fi

AC_SUBST(FIB_ROUTING_SUPPORT)

dnl ----[ Checks for kernel VMAC support ]----
CPPFLAGS="$CPPFLAGS -I$kernelinc"
AC_MSG_CHECKING([for kernel macvlan support])
AC_TRY_COMPILE([
    #include <sys/socket.h>
    #include <linux/if_link.h>
    int macvlan;
  ], [
    macvlan = IFLA_MACVLAN_MODE;
    macvlan = MACVLAN_MODE_PRIVATE;
  ], [
    MACVLAN_SUPPORT=yes
  ], []);

  if test "$MACVLAN_SUPPORT" = "yes"; then
    VRRP_VMAC="_HAVE_VRRP_VMAC_"
    AC_MSG_RESULT([yes])
  else
    VRRP_VMAC="_WITHOUT_VRRP_VMAC_"
    AC_MSG_RESULT([no])
  fi

AC_SUBST(VRRP_VMAC)

if test "${VRRP_VMAC}" = "_HAVE_VRRP_VMAC_"; then
  dnl ----[ Checks for kernel INET6_ADDR_GEN_MODE support ]----
  CPPFLAGS="$CPPFLAGS -I$kernelinc"
  AC_MSG_CHECKING([for kernel inet6_addr_gen_mode support])
  AC_TRY_COMPILE([
      #include <linux/if_link.h>
      int gen_mode;
    ], [
      gen_mode = IFLA_INET6_ADDR_GEN_MODE;
      gen_mode++;
    ], [
      GEN_MODE_SUPPORT=yes
    ], []);

    if test "$GEN_MODE_SUPPORT" = "yes"; then
      ADDR_GEN_MODE="_HAVE_ADDR_GEN_MODE_"
      AC_MSG_RESULT([yes])
    else
      ADDR_GEN_MODE="_WITHOUT_ADDR_GEN_MODE_"
      AC_MSG_RESULT([no])
    fi
else
  ADDR_GEN_MODE="_WITHOUT_ADDR_GEN_MODE_"
fi

AC_SUBST(ADDR_GEN_MODE)

dnl ----[ Checks for SNMP support ]----
SNMP_SUPPORT="_WITHOUT_SNMP_"
SNMP_KEEPALIVED_SUPPORT="_WITHOUT_SNMP_KEEPALIVED_"
SNMP_RFC_SUPPORT="_WITHOUT_SNMP_RFC_"
SNMP_RFCV2_SUPPORT="_WITHOUT_SNMP_RFCV2_"
SNMP_RFCV3_SUPPORT="_WITHOUT_SNMP_RFCV3_"
SNMP_CHECKER_SUPPORT="_WITHOUT_SNMP_CHECKER_"

if test "$enable_snmp" = "yes" -o \
	"$enable_snmp_rfc" = "yes" -o \
	"$enable_snmp_rfcv2" = "yes" -o \
	"$enable_snmp_rfcv3" = "yes" -o \
	"$enable_snmp_keepalived" = "yes" -o \
	"$enable_snmp_checker" = "yes" ; then
  AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], [no])
  if test x"$NETSNMP_CONFIG" = x"no"; then
    AC_MSG_ERROR([*** unable to find net-snmp-config])
  fi
  NETSNMP_LIBS=`${NETSNMP_CONFIG} --agent-libs`
  NETSNMP_CFLAGS="`${NETSNMP_CONFIG} --base-cflags` -DNETSNMP_NO_INLINE"

  CFLAGS="$CFLAGS ${NETSNMP_CFLAGS}"
  LIBS="$LIBS ${NETSNMP_LIBS}"
  AC_MSG_CHECKING([whether C compiler supports flag "${NETSNMP_CFLAGS} ${NETSNMP_LIBS}" from Net-SNMP])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])],[AC_MSG_RESULT(yes)],[
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([*** incorrect CFLAGS from net-snmp-config])])

  # Do we have subagent support?
  AC_CHECK_FUNCS([netsnmp_enable_subagent], [:],
      [AC_MSG_ERROR([*** no subagent support in net-snmp])])

  # Do we have a usable <net-snmp/agent/util_funcs.h> header?
  # Some ancien distributions may miss this header.
  AC_CHECK_HEADERS([net-snmp/agent/util_funcs.h],,,[
@%:@include <net-snmp/net-snmp-config.h>
@%:@include <net-snmp/net-snmp-includes.h>
@%:@include <net-snmp/library/snmp_transport.h>
@%:@include <net-snmp/agent/net-snmp-agent-includes.h>
@%:@include <net-snmp/agent/snmp_vars.h>
  ])

  SNMP_SUPPORT="_WITH_SNMP_"
  if test "$enable_snmp_rfc" = "yes"; then
    SNMP_RFCV2_SUPPORT="_WITH_SNMP_RFCV2_"
    SNMP_RFCV3_SUPPORT="_WITH_SNMP_RFCV3_"
  else
    if test "$enable_snmp_rfcv2" = "yes"; then
      SNMP_RFCV2_SUPPORT="_WITH_SNMP_RFCV2_"
    fi
    if test "$enable_snmp_rfcv3" = "yes"; then
      SNMP_RFCV3_SUPPORT="_WITH_SNMP_RFCV3_"
    fi
  fi
  if test "${SNMP_RFCV2_SUPPORT}" = "_WITH_SNMP_RFCV2_" -o \
          "${SNMP_RFCV3_SUPPORT}" = "_WITH_SNMP_RFCV3_"; then
      SNMP_RFC_SUPPORT="_WITH_SNMP_RFC_"
  fi

  if test "$enable_snmp" = "yes"; then
    SNMP_KEEPALIVED_SUPPORT="_WITH_SNMP_KEEPALIVED_"
    SNMP_CHECKER_SUPPORT="_WITH_SNMP_CHECKER_"
  else
    if test "$enable_snmp_keepalived" = "yes"; then
      SNMP_KEEPALIVED_SUPPORT="_WITH_SNMP_KEEPALIVED_"
    fi
    if test "$enable_snmp_checker" = "yes"; then
      SNMP_CHECKER_SUPPORT="_WITH_SNMP_CHECKER_"
    fi
  fi
fi

AC_SUBST(SNMP_SUPPORT)
AC_SUBST(SNMP_KEEPALIVED_SUPPORT)
AC_SUBST(SNMP_CHECKER_SUPPORT)
AC_SUBST(SNMP_RFC_SUPPORT)
AC_SUBST(SNMP_RFCV2_SUPPORT)
AC_SUBST(SNMP_RFCV3_SUPPORT)

dnl ----[ SHA1 or not ? ]----
SHA1_SUPPORT="_WITHOUT_SHA1_"
if test "${enable_sha1}" = "yes"; then
  CFLAGS="$CFLAGS -DFEAT_SHA1"
  AC_CHECK_HEADERS(openssl/sha.h,,AC_MSG_ERROR([unable to find openssl/sha.h]))
  AC_CHECK_LIB(crypto, SHA1_Init,,AC_MSG_ERROR([SHA1 in OpenSSL required]))
  SHA1_SUPPORT="_WITH_SHA1_"
fi

AC_SUBST(SHA1_SUPPORT)

dnl ----[ check for SO_MARK support ]----
SO_MARK_SUPPORT="_WITHOUT_SO_MARK_"
if test "${enable_fwmark}" != "no"; then
  AC_MSG_CHECKING([for SO_MARK support])
  AC_TRY_COMPILE([
      #include <sys/socket.h>
      int flag;
    ], [
      flag = SO_MARK;
    ], [
      SO_MARK_SUPPORT="_WITH_SO_MARK_"
    ], [
    ]);
  if test "$SO_MARK_SUPPORT" = "_WITH_SO_MARK_"; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi

AC_SUBST(SO_MARK_SUPPORT)


dnl ----[ Debug or not ? ]----
if test "${enable_debug}" = "yes"; then
  DFLAGS="-D_DEBUG_"
  AC_SUBST(DFLAGS)
fi

dnl ----[ Memory alloc check or not ? ]----
MEM_CHECK_LOG=_NO_MEM_CHECK_LOG_
if test "${enable_mem_check}" = "yes"; then
  MEM_CHECK=_MEM_CHECK_
  if test "${enable_mem_check_log}" = "yes"; then
    MEM_CHECK_LOG=_MEM_CHECK_LOG_
  fi
else
  MEM_CHECK=_NO_MEM_CHECK_
fi
AC_SUBST(MEM_CHECK)
AC_SUBST(MEM_CHECK_LOG)

dnl ----[ check for VRRP authentication support ]----
VRRP_AUTH_SUPPORT="_WITHOUT_VRRP_AUTH_"
if test "$enable_vrrp" != "no"; then
  if test "${enable_vrrp_auth}" != "no"; then
    VRRP_AUTH_SUPPORT="_WITH_VRRP_AUTH_"
  fi
fi

AC_SUBST(VRRP_AUTH_SUPPORT)


dnl ----[ Profiling or not ? ]----
if test "${enable_profile}" = "yes"; then
  CFLAGS="$CFLAGS -pg"
fi

AC_SUBST(VERSION)
AC_SUBST(VERSION_DATE)
AC_SUBST(VERSION_YEAR)
AC_SUBST(IPVS_SUPPORT)
AC_SUBST(IPVS_USE_NL)
AC_SUBST(VRRP_SUPPORT)

APP_DEFS="-D${KERN} -D${IPVS_SUPPORT} -D${IPVS_SYNCD} -D${VRRP_SUPPORT} -D${VRRP_VMAC} -D${ADDR_GEN_MODE} -D${SNMP_SUPPORT} -D${SNMP_KEEPALIVED_SUPPORT} -D${SNMP_CHECKER_SUPPORT} -D${SNMP_RFC_SUPPORT} -D${SNMP_RFCV2_SUPPORT} -D${SNMP_RFCV3_SUPPORT} -D${IPVS_USE_NL} -D${USE_NL3} -D${VRRP_AUTH_SUPPORT} -D${SO_MARK_SUPPORT} -D${USE_LIBIPTC} -D${USE_LIBIPSET} -D${IPV4_DEVCONF} -D${IF_H_LINK_H_COLLISION} -D${LINUX_NET_IF_H_COLLISION} -D${SOCK_NONBLOCK_SUPPORT} -D${SOCK_CLOEXEC_SUPPORT} -D${FIB_ROUTING_SUPPORT} -D${MEM_CHECK} -D${MEM_CHECK_LOG} ${DFLAGS}"
BUILD_OPTS=`echo ${APP_DEFS} | sed -e 's/ "$//' -e 's/.*"//' -e 's/-D//g' -e 's/_ / /g' -e 's/ _/ /g' -e 's/^_//' -e 's/_$//'`
AC_SUBST(APP_DEFS)
AC_SUBST(BUILD_OPTS)

dnl ----[ Checks for typedefs, structures, and compiler characteristics ]----
AC_C_CONST
AC_TYPE_PID_T
AC_HEADER_TIME

dnl ----[ Checks for library functions ]----
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(gettimeofday select socket strerror strtol uname pipe2)

dnl ----[ Process output target ]----
OUTPUT_TARGET="$OUTPUT_TARGET keepalived/Makefile lib/Makefile"
if test "${VRRP_SUPPORT}" = "_WITH_VRRP_"; then
  OUTPUT_TARGET="$OUTPUT_TARGET keepalived/vrrp/Makefile"
fi
if test "$IPVS_SUPPORT" = "_WITH_LVS_"; then
  OUTPUT_TARGET="$OUTPUT_TARGET keepalived/check/Makefile"
  if test "$KERN" = "_KRNL_2_6_"; then
    OUTPUT_TARGET="$OUTPUT_TARGET keepalived/libipvs-2.6/Makefile"
  elif test "$KERN" = "_KRNL_2_4_"; then
    OUTPUT_TARGET="$OUTPUT_TARGET keepalived/libipvs-2.4/Makefile"
  fi
fi
AC_OUTPUT($OUTPUT_TARGET)


dnl ----[ Display current configuration ]----
cat <<EOF;

Keepalived configuration
------------------------
Keepalived version       : ${VERSION}
Compiler                 : ${CC}
Compiler flags           : ${CFLAGS}
EOF

dnl ----[ display optional vars  ]----
if test -n "$LIBS"; then
  echo "Extra Lib                : $LIBS"
fi

if test "${IPVS_SUPPORT}" = "_WITH_LVS_"; then
  echo "Use IPVS Framework       : Yes"
  if test "${IPVS_SYNCD}" = "_HAVE_IPVS_SYNCD_"; then
    echo "IPVS sync daemon support : Yes"
  elif test "${IPVS_SYNCD}" = "_WITHOUT_IPVS_SYNCD_"; then
    echo "IPVS sync daemon support : No"
  fi
  if test "${IPVS_USE_NL}" = "LIBIPVS_USE_NL"; then
    echo "IPVS use libnl           : Yes"
  else
    echo "IPVS use libnl           : No"
  fi
else
  echo "Use IPVS Framework       : No"
  echo "IPVS sync daemon support : No"
fi

if test "${SO_MARK_SUPPORT}" = "_WITH_SO_MARK_"; then
  echo "fwmark socket support    : Yes"
else
  echo "fwmark socket support    : No"
fi

if test "${VRRP_SUPPORT}" = "_WITH_VRRP_"; then
  echo "Use VRRP Framework       : Yes"
  if test "${VRRP_VMAC}" = "_HAVE_VRRP_VMAC_"; then
    echo "Use VRRP VMAC            : Yes"
  else
    echo "Use VRRP VMAC            : No"
  fi
  if test "${VRRP_AUTH_SUPPORT}" = "_WITH_VRRP_AUTH_"; then
    echo "Use VRRP authentication  : Yes"
  else
    echo "Use VRRP authentication  : No"
  fi
else
  echo "Use VRRP Framework       : No"
fi
if test "${SNMP_KEEPALIVED_SUPPORT}" = "_WITH_SNMP_KEEPALIVED_"; then
  echo "SNMP keepalived support  : Yes"
else
  echo "SNMP keepalived support  : No"
fi
if test "${SNMP_CHECKER_SUPPORT}" = "_WITH_SNMP_CHECKER_"; then
  echo "SNMP checker support     : Yes"
else
  echo "SNMP checker support     : No"
fi
if test "${SNMP_RFCV2_SUPPORT}" = "_WITH_SNMP_RFCV2_"; then
  echo "SNMP RFCv2 support       : Yes"
else
  echo "SNMP RFCv2 support       : No"
fi
if test "${SNMP_RFCV3_SUPPORT}" = "_WITH_SNMP_RFCV3_"; then
  echo "SNMP RFCv3 support       : Yes"
else
  echo "SNMP RFCv3 support       : No"
fi
if test "${SHA1_SUPPORT}" = "_WITH_SHA1_"; then
  echo "SHA1 support             : Yes"
else
  echo "SHA1 support             : No"
fi
if test "${DFLAGS}" = "-D_DEBUG_"; then
  echo "Use Debug flags          : Yes"
else
  echo "Use Debug flags          : No"
fi
if test "${MEM_CHECK}" = "_MEM_CHECK_"; then
  echo "Memory alloc check       : Yes"
  if test "${MEM_CHECK_LOG}" = "_MEM_CHECK_LOG_"; then
    echo "Memory alloc check log   : Yes"
  else
    echo "Memory alloc check log   : No"
  fi
else
  echo "Memory alloc check       : No"
fi
if test "${USE_NL3}" = "_HAVE_LIBNL3_"; then
  echo "libnl version            : 3"
elif test "${USE_NL3}" = "_HAVE_LIBNL1_"; then
  echo "libnl version            : 1"
else
  echo "libnl version            : None"
fi
if test "${IPV4_DEVCONF}" = "_HAVE_IPV4_DEVCONF_"; then
  echo "Use IPv4 devconf         : Yes"
else
  echo "Use IPv4 devconf         : No"
fi
if test "${USE_LIBIPTC}" = "_HAVE_LIBIPTC_"; then
  echo "Use libiptc              : Yes"
else
  echo "Use libiptc              : No"
fi
if test "${USE_LIBIPSET}" = "_HAVE_LIBIPSET_"; then
  echo "Use libipset             : Yes"
else
  echo "Use libipset             : No"
fi
dnl ----[ end configure ]---
