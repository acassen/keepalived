# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= keepalived
CC= gcc
#CFLAGS= -Wall -Wunused -lmd
CFLAGS= -lmd
DEFS= iputils.h utils.h cfreader.h icmpcheck.h tcpcheck.h httpget.h ipvswrapper.h keepalived.h
OBJECTS= iputils.o utils.o cfreader.o icmpcheck.o tcpcheck.o httpget.o ipvswrapper.o keepalived.o
INCLUDE= -I/usr/src/linux/include

.c.o:	
#	$(CC) -o $@ $(CFLAGS) $(INCLUDE) -c $*.c
	$(CC) -o $@ $(INCLUDE) -DDEBUG -c $*.c

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS) $(DEFS)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS)

clean:
	rm -f core *.o $(EXEC) 

install:
	cp -av keepalived /usr/sbin/
	cp -av etc/* /etc/
