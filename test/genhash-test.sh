#!/bin/bash

LANG=C
#set -eu

: ${GENHASH:=$(which genhash 2>/dev/null)}
: ${GENHASH:=../bin/genhash}
: ${TESTFILE:=$(basename "$0")}
: ${HASH:=MD5}
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
	which python &>/dev/null || die "python required"
	case "${HASH}" in
	"MD5")
		which md5sum &>/dev/null || die "md5sum required"
		digest=$(md5sum "${TESTFILE}" | cut -d' ' -f1)
		;;
	"SHA1")
		which sha1sum &>/dev/null || die "sha1sum required"
		digest=$(sha1sum "${TESTFILE}" | cut -d' ' -f1)
		;;
	*)
		die "unsupported hash ${HASH}"
		;;
	esac
	echo "Test TESTFILE=${TESTFILE} with MD5SUM=${digest}"
	echo "Using GENHASH=${GENHASH} and HASH=${HASH}"
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
		gotdigest=$(${GENHASH} -H ${HASH} -s 127.0.0.1 -p 8000 \
			    -u "/${TESTFILE}" | tail -n2 | cut -d' ' -f3)
		test "${gotdigest}" = "${digest}" && echo -n '.' \
		  || { let e+=1 && echo -e "\n${gotdigest}";}
		test ${e} -ge ${LIMITERR} && break
	done
	echo -e "\n--- ${e} ---"
	test ${e} -eq 0
}

kill_server
test ${SHOWERR} -ne 0 && do_test || do_test 2>/dev/null
