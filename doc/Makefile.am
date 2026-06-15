# Makefile.am
#
# Keepalived OpenSource project.

SUBDIRS		= man/man8 man/man5
if WITH_IPVS
SUBDIRS		+= man/man1
endif

EXTRA_DIST	= samples keepalived.conf.SYNOPSIS NOTE_vrrp_vmac.txt KEEPALIVED-MIB.txt VRRP-MIB.txt VRRPv3-MIB.txt

sampledir	= @SAMPLES_DIR@
sample_DATA	= @srcdir@/samples/*

mibsdir		= @datarootdir@/snmp/mibs
mibs_DATA	=
if SNMP_KEEPALIVED
mibs_DATA	+= KEEPALIVED-MIB.txt
endif
if SNMP_RFCV2
mibs_DATA	+= VRRP-MIB.txt
endif
if SNMP_RFCV3
mibs_DATA	+= VRRPv3-MIB.txt
endif

dist-hook:
	rm -rf `find $(distdir)/doc -type d -name ".git*"`
