# Generated automatically from Makefile.in by configure.
# Makefile
#
# Keepalived OpenSource project.
#
# Copyright (C) 2001, 2002 Alexandre Cassen, <acassen@linux-vs.org>

EXEC = genhash

prefix = /usr/local
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin

CC = gcc
CFLAGS = -g -O2 -Wall -Wunused -Wstrict-prototypes
LDFLAGS = -lpopt -lssl -lcrypto  

OBJS = main.o client.o common.o

all:	$(EXEC)
	strip $(EXEC)
	@echo ""
	@echo "Make complete"

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

clean:
	rm -f core *.o $(EXEC)

clean-dist:
	rm -f $(bindir)/$(EXEC)

install:	
	install -m 755 $(EXEC) $(bindir)/
