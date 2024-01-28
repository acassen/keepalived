#!/bin/bash

# For testing. Either have --ssl and -S in first and second commands, or omit both

# To run: 	ip netns exec high ncat -l -p 443 -e $(pwd)/test/ncat_resp.sh -k --ssl
# To test:	ip netns exec low keepalived/keepalived -T  -p 443 -s 10.200.30.211 -u /loadbalancer -P 1.1 -v -S

${0%/*}/tcp_server -Z -W / -w /loadbalancer.html fred -P -gG
