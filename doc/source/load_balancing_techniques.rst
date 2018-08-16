#########################
Load Balancing Techniques
#########################

Virtual Server via NAT
**********************

NAT Routing is used when the Load-Balancer (or LVS Router) has two Network
Interface Cards (NICs), one assigned an outside-facing IP address and the
other, a private, inside-facing IP address.  In this method, the Load-Balancer
receives requests from users on the public network and uses network address
translation (NAT) to forward those requests to the real servers located on the
private network.  The replies are also translated in the reverse direction,
when the real servers reply to the users’ requests.

As a result, an advantage is that the real servers are protected from the
public network as they are hidden behind the Load-Balancer.  Another advantage
is IP address preservation, as the private network can use private address
ranges.

The main disadvantage is that the Load-Balancer becomes a bottleneck.  It has
to serve not only requests but also replies to and from the public users,
while also forwarding to and from the private real servers.

Virtual Server via Tunneling
****************************

In Tunneling mode, the Load-Balancer sends requests to real servers through IP tunnel
in the former, and the Load-Balancer sends request to real servers via network
address translation in the latter.

The main advantage of this method is scalability, Load-Balancer will forward
incoming request to farm nodes, latter nodes will then respond directly to the
client requests without having to proxy through Load-Balancer. It offers you
a way to locate nodes in different networking segments.

The main disadvantage is the cost you will put into it to finally get a working
env since it is deeply dependent upon your network architecture.

Virtual Server via Direct Routing
*********************************

In Direct Routing, users issue requests to the VIP on the Load-Balancer.  The
Load-Balancer uses its predefined scheduling (distribution) algorithm and
forwards the requests to the appropriate real server.  Unlike using NAT
Routing, the real servers respond directly to the public users, bypassing the
need to route through the Load-Balancer.

The main advantage with this routing method is scalability, as the
Load-Balancer does not have the additional responsibility of routing outgoing
packets from the real servers to the public users.

The disadvantage to this routing method lies in its ARP limitation. In order
for the real servers to directly respond to the public users’ requests, each
real server must use the VIP as its source address when sending replies.
As a result, the VIP and MAC address combination are shared amongst the
Load-Balancer itself as well as each of the real servers that can lead to
situations where the real servers receive the requests directly, bypassing
the Load-Balancer on incoming requests.  There are methods available to
solve this problem at the expense of added configuration complexity and
manageability.
