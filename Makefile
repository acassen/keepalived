# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= keepalived
CC= gcc
#CFLAGS= -Wall -Wunused
CFLAGS= 
DEFS= md5.h iputils.h utils.h pidfile.h cfreader.h icmpcheck.h tcpcheck.h httpget.h smtpwrapper.h ipvswrapper.h libipfwc/libipfwc.h libipfwc/ipfwc_kernel_headers.h ipfwwrapper.h keepalived.h
OBJECTS= md5.o iputils.o utils.o pidfile.o cfreader.o icmpcheck.o tcpcheck.o httpget.o smtpwrapper.o ipvswrapper.o ipfwwrapper.o libipfwc/libipfwc.a keepalived.o
INCLUDE= -I/usr/src/linux/include

.c.o:	
	$(CC) -o $@ $(CFLAGS) $(INCLUDE) -c $*.c

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS) $(DEFS)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS)

libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a

subclean:
	cd libipfwc/ && $(MAKE) clean

clean: subclean
	rm -f core *.o $(EXEC)

install:	
	install -m 700 keepalived /usr/sbin/
	install -m 755 etc/rc.d/init.d/keepalived.init /etc/rc.d/init.d/
	mkdir /etc/keepalived
	mkdir /etc/keepalived/log
	touch /etc/keepalived/log/keepalived.log
	install -m 644 etc/keepalived/keepalived.conf /etc/keepalived/
