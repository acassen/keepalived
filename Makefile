# Makefile
# Alexandre Cassen <acassen@linux-vs.org>

EXEC = keepalived
CC = gcc

KERNEL := _KRNL_2_$(shell uname -r | cut -d'.' -f2)_

# To compile with debug messages uncomment the following line
CFLAGS= -g -O6 -Wall -Wunused -Wstrict-prototypes -D_DEBUG_ -D$(KERNEL)
# CFLAGS= -g -Wall -O6 -D$(KERNEL) $(SSL)
DEFS=

SSL := -lssl -lcrypto
LIB := $(LIB) $(SSL) -lpopt

ifeq ($(KERNEL),_KRNL_2_2_)
  LIB := $(LIB) libipfwc/libipfwc.a
endif

DEFS= main.h \
	memory.h \
        scheduler.h \
        cfreader.h \
        layer4.h \
        check_tcp.h \
        check_http.h \
        check_ssl.h \
        check_misc.h \
	vrrp.h \
	vrrp_scheduler.h \
	vrrp_netlink.h \
	vrrp_ipaddress.h \
	vrrp_ipsecah.h \
        smtp.h

OBJECTS := main.o \
	memory.o \
	utils.o \
	scheduler.o \
	cfreader.o \
	layer4.o \
	check_tcp.o \
	check_http.o \
        check_ssl.o \
	check_misc.o \
	ipwrapper.o \
	ipvswrapper.o
ifeq ($(KERNEL),_KRNL_2_2_)
  OBJECTS := $(OBJECTS) ipfwwrapper.o
endif
OBJECTS := $(OBJECTS) \
	pidfile.o \
	smtp.o \
	vrrp.o \
	vrrp_scheduler.o \
	vrrp_netlink.o \
	vrrp_ipaddress.o \
	vrrp_ipsecah.o

INCLUDE= -I/usr/src/linux/include

.c.o:	
	$(CC) -o $@ $(CFLAGS) $(INCLUDE) -c $*.c

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

debug:	$(EXEC)
	@echo""
	@echo "Make complete"

$(EXEC):	$(OBJECTS) $(DEFS) $(LIB)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS) $(LIB)

ifeq ($(KERNEL),_KRNL_2_2_)
libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a
endif

subclean:
ifeq ($(KERNEL),_KRNL_2_2_)
	cd libipfwc/ && $(MAKE) clean
endif

clean: subclean
	rm -f core *.o $(EXEC)

install:
	install -m 700 keepalived /usr/sbin/
	install -m 755 etc/rc.d/init.d/keepalived.init /etc/rc.d/init.d/
	mkdir /etc/keepalived
	install -m 644 etc/keepalived/keepalived.conf /etc/keepalived/
	mkdir /etc/keepalived/samples
	install -m 644 samples/* /etc/keepalived/samples/

