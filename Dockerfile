FROM alpine:3.5
MAINTAINER Bertrand Gouny <bertrand.gouny@osixia.net>

# add keepalived sources to /tmp/keepalived-sources
ADD . /tmp/keepalived-sources

# Add keepalived default script user to make sure their IDs get assigned consistently,
# regardless of whatever dependencies get added
RUN addgroup -S keepalived_script && adduser -D -S -G keepalived_script keepalived_script

# 1. install required libraries and tools
# 2. compile and install keepalived
# 3. remove keepalived sources and unnecessary libraries and tools
RUN apk --no-cache add \
       gcc \
       ipset \
       ipset-dev \
       iptables \
       iptables-dev \
       libnfnetlink \
       libnfnetlink-dev \
       libnl3 \
       libnl3-dev \
       make \
       musl-dev \
       openssl \
       openssl-dev \
       autoconf \

    && cd /tmp/keepalived-sources \
    && ./configure --disable-dynamic-linking \
    && make && make install \
    && cd - \

    && rm -rf /tmp/keepalived-sources \
    && apk --no-cache del \
	gcc \
	ipset-dev \
	iptables-dev \
	libnfnetlink-dev \
	libnl3-dev \
	make \
	musl-dev \
	openssl-dev \
	autoconf

ADD docker/keepalived.conf /usr/local/etc/keepalived/keepalived.conf

# set keepalived as image entrypoint with --dont-fork and --log-console (to make it docker friendly)
# define /usr/local/etc/keepalived/keepalived.conf as the configuration file to use
ENTRYPOINT ["/usr/local/sbin/keepalived","--dont-fork","--log-console", "-f","/usr/local/etc/keepalived/keepalived.conf"]

# example command to customise keepalived daemon:
# CMD ["--log-detail","--dump-conf"]
