CC	= gcc
COPTS   = -g -O
CFLAGS	= -Wall -Wunused $(COPTS)

libnetlink.a: libnetlink.a(libnetlink.o ll_map.o)

libnetlink.o: libnetlink.h
ll_map.o: ll_map.h

clean:
	rm -f *.a *.o *~
