# Makefile to make libipvsc.

CC	= gcc
CFLAGS	= -g -O2  -I/usr/src/linux/include -Wall -Wunused

export OBJS += libipvs.a

all: libipvs.a

libipvs.a: libipvs.a(libipvs.o)

libipvsc.o: libipvs.h

clean:
	rm -f *.a *.o *~

distclean: clean
	rm -f Makefile
