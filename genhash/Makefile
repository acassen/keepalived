# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= genhash
CC= gcc
CFLAGS= -Wall
DEFS= genhash.h md5.h
OBJECTS= md5.o genhash.o
INCLUDE= -I/usr/src/linux/include
.c.o:	
	$(CC) -o $@ $(CFLAGS) $(INCLUDE) -c $*.c

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC):	$(OBJECTS) $(DEFS)
	$(CC) -o $(EXEC) $(CFLAGS) $(OBJECTS)

clean:
	rm -f core *.o $(EXEC)

install:	
	install -m 755 genhash /usr/bin/
