=======
genhash
=======

:Date: 2021-07-05

NAME
====

genhash - md5 hash generation tool for remote web pages

SYNOPSIS
========

**keepalived --genhash [options] [-s server-address] [-p port] [-u
url]**

DESCRIPTION
===========

**genhash** is a tool used for generating md5sum hashes of remote web
pages. **genhash** can use HTTP or HTTPS to connect to the web page. The
output by this utility includes the HTTP header, page data, and the
md5sum of the data. This md5sum can then be used within the
**keepalived(8)** program, for monitoring HTTP and HTTPS services.

OPTIONS
=======

**--use-ssl, -S**
   Use SSL to connect to the server.

**--server <host>, -s**
   Specify the ip address to connect to.

**--port <port>, -p**
   Specify the port to connect to.

**--url <url>, -u**
   Specify the path to the file you want to generate the hash of.

**--use-virtualhost <host>, -V**
   Specify the virtual host to send along with the HTTP headers.

**--protocol <protocol_version>, -P**
   Specify the HTTP protocol version to use. protocol_version can be
   1.0, 1.1 or 1.0c. 1.0c means protocol version 1.0 but with a
   "Connection: close" line; this is included in version 1.1 by default.

**--timeout <timeout>, -t**
   Specify the connection timeout in seconds.

**--fwmark <mark>, -m**
   Set the specified firewall mark on the socket

**--verbose, -v**
   Be verbose with the output.

**--help, -h**
   Display the program help screen and exit.

SEE ALSO
========

**keepalived**\ (8), **keepalived.conf**\ (5)

AUTHOR
======

| 
| **genhash** was written by Alexandre Cassen <acassen@linux-vs.org>.

This man page was contributed by Andres Salomon <dilinger@voxel.net> for
the Debian GNU/Linux system (but may be used by others).
