# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= genhash
CC= gcc
CFLAGS= -Wall
DEFS= genhash.h md5.h
OBJECTS= md5.o genhash.o
.c.o:	
	$(CC) -o $@ $(CFLAGS) -c $*.c

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
