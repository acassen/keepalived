# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= genhash
CC= gcc
CFLAGS= -Wall -lmd
DEFS= genhash.h
OBJECTS= genhash.o
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
	cp -av genhash /usr/bin
