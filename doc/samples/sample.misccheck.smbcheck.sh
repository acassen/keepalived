#!/bin/sh
# remove it as smbcheck.sh and put it the location you want

SAMBA_BIN=`which smbclient 2> /dev/null`

if [ -z "$SAMBA_BIN" ] ; then
	exit 2
fi

if [ -z "$1" ] ; then
	echo "Usage: $0 <ip address>"
	exit 2
fi

($SAMBA_BIN -N -L $1 -W CENTRALB -U nobody) \
 | egrep '^Domain=\[[A-Za-z0-9_-]+\]' > /dev/null 2>&1

