#!/bin/bash

# To use this script, copy it to directory /etc/keepalived/scripts
# and add the following to the keepalived configuration file in the
# global_defs section:
#     vrrp_notify_fifo /tmp/notify_fifo
# This script will then need to be executed.
# 
# As an alternative to executing this script manually, add the following
# in the global_defs section of the config:
#     vrrp_notify_fifo_script /etc/keepalived/scripts/sample_notify_fifo.sh
# If this approach is used, comment out the lines 'mkfifo $FIFO' and trap ...
# below, since keepalived can create the FIFO.

FIFO=/tmp/notify_fifo
CREATED_FIFO=0

trap "{ [[ $CREATED_FIFO -eq 1 ]] && rm -f $FIFO; exit 0; }" HUP INT QUIT USR1 USR2 PIPE TERM

[[ ! -p $FIFO ]] && mkfifo $FIFO && CREATED_FIFO=1

# If keepalived terminates, the FIFO will be closed, so
# read the FIFO in a loop. It keepalived hasn't opened the
# FIFO, the script will be blocked until it has been opened.
while [ 1 ]
do
	[[ ! -p $FIFO ]] && echo FIFO $FIFO missing && exit 1

	while read line; do
		set $line
		TYPE=$1
		VRRP_INST=${2//\"/}
		STATE=$3
		PRIORITY=$4

		# Now take whatever action is required
		echo $TYPE $VRRP_INST $STATE $PRIORITY >>/tmp/fifo.log
	done < $FIFO
done
