# Makefile
# Alexandre Cassen <acassen@linux-vs.org>

EXEC= keepalived
CC= gcc

# To compile with debug messages uncomment the following line
CFLAGS= -g -Wall -D DEBUG
#CFLAGS= -g -Wall
DEFS=

LIB=	libipfwc/libipfwc.a \
	libnetlink/libnetlink.a

#DEFS= main.h scheduler.h cfreader.h layer4.h check_tcp.h check_http.h md5.h smtp.h
OBJECTS= main.o \
	utils.o \
	scheduler.o \
	cfreader.o \
	layer4.o \
	check_tcp.o \
	check_http.o \
	md5.o \
	ipwrapper.o \
	ipvswrapper.o \
	ipfwwrapper.o \
	pidfile.o \
	smtp.o \
	vrrp.o \
	vrrp_iproute.o \
	vrrp_ipaddress.o \
	vrrp_ipsecah.o

INCLUDE= -I/usr/src/linux/include

.c.o:	
	$(CC) -o $@ $(CFLAGS) $(INCLUDE) -c $*.c

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS) $(DEFS) $(LIB)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS) $(LIB)

libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a

libnetlink/libnetlink.a:
	cd libnetlink/ && $(MAKE) libnetlink.a

subclean:
	cd libipfwc/ && $(MAKE) clean
	cd libnetlink/ && $(MAKE) clean

clean: subclean
	rm -f core *.o $(EXEC)

install:
	install -m 700 keepalived /usr/sbin/
	install -m 755 etc/rc.d/init.d/keepalived.init /etc/rc.d/init.d/
	mkdir /etc/keepalived
	install -m 644 etc/keepalived/keepalived.conf /etc/keepalived/

