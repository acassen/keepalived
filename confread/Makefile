# Makefile
# Alexandre Cassen <Alexandre.Cassen@wanadoo.fr>

EXEC= confreader
CC= gcc
#CFLAGS= -Wall -Wunused
CFLAGS= 
DEFS= main.h cfreader.h
OBJECTS= main.o cfreader.o utils.o
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
