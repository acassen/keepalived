# Makefile to make libipfwc.

CC	= gcc
CFLAGS	= -g -O2 -Wall -Wunused

export OBJS += libipfwc.a

all: libipfwc.a

libipfwc.a: libipfwc.a(libipfwc.o)

libipfwc.o: libipfwc.h ipfwc_kernel_headers.h

clean:
	rm -f *.a *.o *~

distclean: clean
	rm -f Makefile
