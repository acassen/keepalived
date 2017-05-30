#!/bin/sh
# Henrique Mecking <henriquemecking@gmail.com>
# 05.02.2013
# remove it as psqlcheck.sh and put it the location you want
#
# $1 == ip address

psql -U postgres -h $1 -l > /dev/null
if [ $? -eq 0 ]; then
	exit 0
else
	exit 1
fi
