# Makefile
# Alexandre Cassen <acassen@linux-vs.org>

EXEC= keepalived
CC= gcc

KERNEL := KERNEL_2_$(shell uname -r | cut -d'.' -f2)

# To compile with debug messages uncomment the following line
CFLAGS= -g -Wall -Wunused -DDEBUG -D$(KERNEL)
#CFLAGS= -g -Wall -D$(KERNEL)
DEFS=

ifeq ($(KERNEL),KERNEL_2_2)
  LIB := $(LIB) libipfwc/libipfwc.a
endif

DEFS= main.h \
        scheduler.h \
        cfreader.h \
        layer4.h \
        check_tcp.h \
        check_http.h \
        check_misc.h \
        md5.h \
	vrrp.h \
	vrrp_scheduler.h \
	vrrp_netlink.h \
	vrrp_ipaddress.h \
	vrrp_ipsecah.h \
        smtp.h

OBJECTS := main.o \
	utils.o \
	scheduler.o \
	cfreader.o \
	layer4.o \
	check_tcp.o \
	check_http.o \
	check_misc.o \
	md5.o \
	ipwrapper.o \
	ipvswrapper.o
ifeq ($(KERNEL),KERNEL_2_2)
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

$(EXEC):	$(OBJECTS) $(DEFS) $(LIB)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS) $(LIB)

ifeq ($(KERNEL),KERNEL_2_2)
libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a
endif

subclean:
ifeq ($(KERNEL),KERNEL_2_2)
	cd libipfwc/ && $(MAKE) clean
endif

clean: subclean
	rm -f core *.o $(EXEC)

install:
	install -m 700 keepalived /usr/sbin/
	install -m 755 etc/rc.d/init.d/keepalived.init /etc/rc.d/init.d/
	mkdir /etc/keepalived
	install -m 644 etc/keepalived/keepalived.conf /etc/keepalived/

