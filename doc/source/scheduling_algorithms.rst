##########################
IPVS Scheduling Algorithms
##########################

The following scheduling algorithms are supported by the IPVS kernel code. (heavily stolen from LVS website).

Round Robin (rr)
****************

The round-robin scheduling algorithm sends each incoming request to the next server in its list. Thus in a three server cluster (servers A, B, and C) request 1 would go to server A, request 2 would go to server B, request 3 would go to server C, and request 4 would go to server A, thus completing the cycling or 'round-robin' of servers. It treats all real servers as equals regardless of the number of incoming connections or response time each server is experiencing. Virtual Server provides a few advantages over traditional round-robin DNS. Round-robin DNS resolves a single domain to the different IP addresses, the scheduling granularity is host-based, and the caching of DNS queries hinders the basic algorithm, these factors lead to significant dynamic load imbalances among the real servers. The scheduling granularity of Virtual Server is network connection-based, and it is much superior to round-robin DNS due to the fine scheduling granularity.

Weighted Round Robin (wrr)
**************************

The weighted round-robin scheduling is designed to better handle servers with different processing capacities. Each server can be assigned a weight, an integer value that indicates the processing capacity. Servers with higher weights receive new connections first than those with less weights, and servers with higher weights get more connections than those with less weights and servers with equal weights get equal connections. For example, the real servers, A, B, and C, have the weights, 4, 3, 2 respectively, a good scheduling sequence will be AABABCABC in a scheduling period (mod sum(Wi)). In the implementation of the weighted round-robin scheduling, a scheduling sequence will be generated according to the server weights after the rules of Virtual Server are modified. The network connections are directed to the different real servers based on the scheduling sequence in a round-robin manner.

The weighted round-robin scheduling is better than the round-robin scheduling, when the processing capacity of real servers is different. However, it may lead to dynamic load imbalance among the real servers if the load of the requests vary highly. In short, there is the possibility that a majority of requests requiring large responses may be directed to the same real server.

Actually, the round-robin scheduling is a special instance of the weighted round-robin scheduling, in which all the weights are equal.

Least Connection (lc)
*********************

The least-connection scheduling algorithm directs network connections to the server with the least number of established connections. This is one of the dynamic scheduling algorithms; because it needs to count live connections for each server dynamically. For a Virtual Server that is managing a collection of servers with similar performance, least-connection scheduling is good to smooth distribution when the load of requests varies a lot. Virtual Server will direct requests to the real server with the fewest active connections.

At a first glance, it might seem that least-connection scheduling can also perform well even when there are servers of various processing capacities, because the faster server will get more network connections. In fact, it cannot perform very well because of the TCP's TIME_WAIT state. The TCP's TIME_WAIT is usually 2 minutes, during this 2 minutes a busy website often receives thousands of connections, for example, the server A is twice as powerful as the server B, the server A is processing thousands of requests and keeping them in the TCP's TIME_WAIT state, but server B is crawling to get its thousands of connections finished. So, the least-connection scheduling cannot get load well balanced among servers with various processing capacities.

Weighted Least Connection (wlc)
*******************************

The weighted least-connection scheduling is a superset of the least-connection scheduling, in which you can assign a performance weight to each real server. The servers with a higher weight value will receive a larger percentage of live connections at any one time. The Virtual Server Administrator can assign a weight to each real server, and network connections are scheduled to each server in which the percentage of the current number of live connections for each server is a ratio to its weight. The default weight is one.

The weighted least-connections scheduling works as follows:

    Supposing there are n real servers, each server i has weight Wi (i=1,..,n), and alive connections Ci (i=1,..,n), ALL_CONNECTIONS is the sum of Ci (i=1,..,n), the next network connection will be directed to the server j, in which

        (Cj/ALL_CONNECTIONS)/Wj = min { (Ci/ALL_CONNECTIONS)/Wi } (i=1,..,n)

    Since the ALL_CONNECTIONS is a constant in this lookup, there is no need to divide Ci by ALL_CONNECTIONS, it can be optimized as

        Cj/Wj = min { Ci/Wi } (i=1,..,n)

The weighted least-connection scheduling algorithm requires additional division than the least-connection. In a hope to minimize the overhead of scheduling when servers have the same processing capacity, both the least-connection scheduling and the weighted least-connection scheduling algorithms are implemented.

Locality-Based Least Connection (lblc)
**************************************

The locality-based least-connection scheduling algorithm is for destination IP load balancing. It is usually used in cache cluster. This algorithm usually directs packet destined for an IP address to its server if the server is alive and under load. If the server is overloaded (its active connection numbers is larger than its weight) and there is a server in its half load, then allocate the weighted least-connection server to this IP address.

Locality-Based Least Connection with Replication (lblcr)
********************************************************

The locality-based least-connection with replication scheduling algorithm is also for destination IP load balancing. It is usually used in cache cluster. It differs from the LBLC scheduling as follows: the load balancer maintains mappings from a target to a set of server nodes that can serve the target. Requests for a target are assigned to the least-connection node in the target's server set. If all the node in the server set are over loaded, it picks up a least-connection node in the cluster and adds it in the sever set for the target. If the server set has not been modified for the specified time, the most loaded node is removed from the server set, in order to avoid high degree of replication.

Destination Hashing (dh)
************************

The destination hashing scheduling algorithm assigns network connections to the servers through looking up a statically assigned hash table by their destination IP addresses.

Source Hashing (sh)
*******************

The source hashing scheduling algorithm assigns network connections to the servers through looking up a statically assigned hash table by their source IP addresses.

Shortest Expected Delay (sed)
*****************************

The shortest expected delay scheduling algorithm assigns network connections to the server with the shortest expected delay. The expected delay that the job will experience is (Ci + 1) / Ui if sent to the ith server, in which Ci is the number of connections on the ith server and Ui is the fixed service rate (weight) of the ith server.

Never Queue (nq)
****************

The never queue scheduling algorithm adopts a two-speed model. When there is an idle server available, the job will be sent to the idle server, instead of waiting for a fast one. When there is no idle server available, the job will be sent to the server that minimizes its expected delay (The Shortest Expected Delay scheduling algorithm).

Overflow-Connection (ovf)
*************************

The Overflow connection scheduling algorithm implements "overflow" loadbalancing according to a number of active connections, will keep all connections to the node with the highest weight and overflow to the next node if the number of connections exceeds the node's weight. Note that this scheduler might not be suitable for UDP because it only uses active connections
