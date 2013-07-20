#!/bin/bash

LANG=C
#set -eu

: ${GENHASH:=$(which genhash 2>/dev/null)}
: ${GENHASH:=../bin/genhash}
: ${TESTFILE:=$(basename "$0")}
: ${ITERNUM:=500}
: ${LIMITERR:=10}
: ${SHOWERR:=0}

trap kill_server EXIT

kill_server() { pkill -f -u $(id -u) SimpleHTTPServer;}

die() {
	echo "$*"
	exit 1
}

do_test() {
	test -x "${GENHASH}" || die "genhash required (tried ${GENHASH})"
	which md5sum &>/dev/null || die "md5sum required"
	which python &>/dev/null || die "python required"
	md5=$(md5sum "${TESTFILE}" | cut -d' ' -f1)
	echo "Test TESTFILE=${TESTFILE} with MD5SUM=${md5}"
	echo "Using GENHASH=${GENHASH}"
	python -m SimpleHTTPServer &
	echo "Waiting for Python SimpleHTTPServer..."
	slept=0
	while netstat -tln 2>/dev/null | grep -qv 8000 && test $slept -lt 3; do
		let slept+=1
		sleep 1;
	done
	echo "Python SimpleHTTPServer started"
	e=0
	for ((i=0;i<${ITERNUM};i++)); do
		gotmd5=$(${GENHASH} -s 127.0.0.1 -p 8000 -u "/${TESTFILE}" |
			 tail -n2 | cut -d' ' -f3)
		test "${gotmd5}" = "${md5}" && echo -n '.' \
		  || { let e+=1 && echo -e "\n${gotmd5}";}
		test ${e} -ge ${LIMITERR} && break
	done
	echo -e "\n--- ${e} ---"
	test ${e} -eq 0
}

kill_server
test ${SHOWERR} -ne 0 && do_test || do_test 2>/dev/null
