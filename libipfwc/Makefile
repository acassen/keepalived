# Makefile to make libipfwc.

CC	= gcc
COPTS   = -g -O
CFLAGS	= -Wall -Wunused $(COPTS)

libipfwc.a: libipfwc.a(libipfwc.o)

libipfwc.o: libipfwc.h ipfwc_kernel_headers.h

clean:
	rm -f *.a *.o *~
