# Makefile to make libipvsc.

CC	= gcc
COPTS   = -g -O
CFLAGS	= -Wall -Wunused $(COPTS) -I/usr/src/linux/include

libipvs.a: libipvs.a(libipvs.o)

libipvsc.o: libipvs.h

clean:
	rm -f *.a *.o *~
