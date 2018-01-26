#!/bin/bash

GIT_ROOT=$(git rev-parse --show-toplevel)
WORKING_DIR=$(dirname $0)

grep -E "Linux  *[0-9]+\.[0-9]*" $(find $GIT_ROOT -name "*.[ch]" -o -name Makefile.am) $GIT_ROOT/configure.ac | \
	sed -re "s/.*(Linux +[0-9])/\1/" -e "s/^Linux +([0-9.]*).*/\1/" -e "s/\.$//" | \
	sort -Vu | \
	sed -re "s/(^[0-9]+\.[0-9]+)$/\1.0/" -e "s/^/KERNEL_VERSION(/" -e "s/$/),/" -e "s/\./,/g" \
	>${WORKING_DIR}/kernel_vers_nos.h

gcc -o ${WORKING_DIR}/kernel_vers ${WORKING_DIR}/kernel_vers.c

${WORKING_DIR}/kernel_vers $*
