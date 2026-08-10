CFLAGS = -O2 -g

all: tcp_server tcp_client regex_partial_test auth_hmac_test failover_pool_test

tcp_server: tcp_server.c

tcp_client:	tcp_client.c
	gcc -o tcp_client tcp_client.c -lreadline

regex_partial_test:	regex_partial_test.c
	gcc $(CFLAGS) -o regex_partial_test regex_partial_test.c -lpcre2-8

auth_hmac_test:	auth_hmac_test.c ../keepalived/vrrp/libvrrp.a ../lib/liblib.a
	gcc $(CFLAGS) -Wall -o auth_hmac_test auth_hmac_test.c \
		-I../lib -I../keepalived/include \
		../keepalived/vrrp/libvrrp.a ../lib/liblib.a -lcrypto -lsystemd

failover_pool_test:	failover_pool_test.c ../keepalived/check/ipwrapper.c ../lib/liblib.a
	gcc $(CFLAGS) -Wall -o failover_pool_test failover_pool_test.c \
		../keepalived/check/ipwrapper.c \
		-I../lib -I../keepalived/include \
		../lib/liblib.a -lcrypto
