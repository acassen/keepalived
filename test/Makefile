CFLAGS = -O2 -g

all: tcp_server tcp_client regex_partial_test

tcp_server: tcp_server.c

tcp_client:	tcp_client.c
	gcc -o tcp_client tcp_client.c -lreadline

regex_partial_test:	regex_partial_test.c
	gcc $(CFLAGS) -o regex_partial_test regex_partial_test.c -lpcre2-8
