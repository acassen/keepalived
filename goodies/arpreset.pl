#!/usr/bin/perl -w

###################################################################
# arpreset 0.2
# Copyright (C) 2005  Steve Milton (milton AT isomedia.com)
#
# Utility for deleting a single ARP entry from a cisco router.
# Script adapted from description on Cisco tech article.
#   http://www.cisco.com/warp/public/477/SNMP/clear_arp.shtml
#
# The Cisco router needs to have a read/write community setup
# for the utility to work.  I recommend using the following
# IOS commands to setup a restricted community that can only
# work with the MAC table.  You will need ENABLE level access
# to the router to execute these commands.
#
#    access-list 50 permit 123.123.123.123
#    access-list 50 permit 123.123.123.124
#    access-list 50 deny any
#    snmp-server view arpchange ipNetToMediaEntry.4 included
#    snmp-server community blahblah view arpchange RW 50
#
# Set the access-list permit to the IP addresses of the systems
# you want to be able to make changes to the MAC table.  Set
# the community name (above blahblah) to something random and
# password-like.
###################################################################
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
###################################################################

use strict;
use Getopt::Long;
&Getopt::Long::config('auto_abbrev');

my ($router,$community,$address,$help,$check);
$router=$community=$address=$help=$check="";

my $status = GetOptions("router:s" => \$router,
                        "community:s" => \$community,
                        "address:s" => \$address,
			"help" => \$help,
			"check" => \$check);

if (($status == 0) or $help) {
    &PrintUsage;
    exit 1;
}

if (!$router or !$community or !$address) {
    &PrintUsage;
    exit 1;
}

# OID for the ARP table entries
my $ciscoOID = ".1.3.6.1.2.1.4.22.1.4";
my $target = "";

# Walk the SNMP ARP table on the router to locate the target address
open(GET, "/usr/bin/snmpwalk -v1 -c $community $router $ciscoOID |");
while(<GET>) {
    if (/^(.*?\.$address)\s/) {
	$target = $1;
	print $_;
    }
}
close(GET);
if ($target and !$check) {
    print "-- changed to --\n";
    # set the target address to "invalid"
    system("/usr/bin/snmpset -v1 -c $community $router $target i 2");
} elsif (!$check) {
    print "No target OID located.";
    exit 1;
}
exit;

sub PrintUsage {
    print "arpreset 0.2\nCopyright (c) 2005 by Steve Milton\narpreset comes with ABSOLUTELY NO WARRANTY\n\n";
    print "Usage: arpreset --router=routeraddress --community=rwcommunity --address=ipaddress\n";
    print "       arpreset --help\n";
    print "\nWhere ipaddress is the IP address in the Cisco router that you want to invalidate\nfrom the MAC address cache.\n";
    print "\nYou can add --check to the command to make it NOT update the router, but check for\nthe entry only.\n";
    exit;
}
