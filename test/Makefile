CFLAGS = -O2 -g

PROGS=tcp_server tcp_client regex_partial_test auth_hmac_test snmp_epoll_test

all: $(PROGS)

tcp_server: tcp_server.c

tcp_client:	tcp_client.c
	gcc -o tcp_client tcp_client.c -lreadline

regex_partial_test:	regex_partial_test.c
	gcc $(CFLAGS) -o regex_partial_test regex_partial_test.c -lpcre2-8

auth_hmac_test:	auth_hmac_test.c ../keepalived/vrrp/libvrrp.a ../lib/liblib.a
	gcc $(CFLAGS) -Wall -o auth_hmac_test auth_hmac_test.c \
		-I../lib -I../keepalived/include \
		../keepalived/vrrp/libvrrp.a ../lib/liblib.a -lcrypto -lsystemd -lkmod -lnetsnmp -lnetsnmpagent


# Requires a library configured with --enable-snmp.
snmp_epoll_test: snmp_epoll_test.c ../lib/liblib.a
	echo CPPFLAGS=$(CPPFLAGS) CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS) LDLIBS=$(LDLIBS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o $@ $< \
		-I../lib ../lib/liblib.a -lcrypto -lm $(LDLIBS) -lkmod -lsystemd

clean:
	$(RM) $(PROGS)
