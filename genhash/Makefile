# Makefile
# Alexandre Cassen <acassen@linux-vs.org>

EXEC = genhash

CC = gcc
CFLAGS = -Wall -Wunused -Wstrict-prototypes -g -O2
#LD = -lssl -lcrypto -dynamic -lpopt
LD = -lssl -lcrypto -lpopt

OBJS = main.o client.o common.o

all:	genhash
	strip genhash
	@echo ""
	@echo "Make complete"
$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $(EXEC) $(LD)
clean:
	rm -f core *.o $(EXEC)
install:	
	install -m 755 genhash /usr/bin/
