#!/usr/bin/env python3

#####
#
# This script will generate a sample configuration for Keepalived.
# The configuration is as follows:
# Each vlan contains a VRRPv2 instance with a private IPv4 address
# and a VRRPv3 instance with a Local Address.
# Each instance tracks a file located in keepalived_offset_folder.
#
# Author: Damien Clabaut <damien.clabaut@corp.ovh.com>
#
#####

import jinja2

# Configuration
# First vlan of the range
first_vlan = 2

# Last vlan of the range, must not be higher than 255
last_vlan = 100

# Path to the folder containing files tracked by each instance
keepalived_offset_folder = "/etc/keepalived_offset/"

# Path to the output file
output_file = "keepalived.conf"

# Underlying interface.
# For this configuration to work you need vlan subinterfaces.
# For example, if the value below is bond0, you need to have
# interfaces bond0.2 to bond0.<last_vlan>
interface = "bond0"

class Vlan:
    def __init__(self, name, ip4addr, ip4net, ip6addr):
        self.name = name
        self.ip4addr = ip4addr
        self.ip4net = ip4net
        self.ip6addr = ip6addr


vlans = []
for vlan_id in range(first_vlan, last_vlan + 1):
    ip4addr = "10.0." + str(vlan_id) + ".254"
    ip4net = "10.0." + str(vlan_id) + ".0/24"
    ip6addr = "fd00:42:ffff:" + format(vlan_id, '02x') + ":ff:ff:ff:ff/64"
    new_vlan = Vlan(vlan_id, ip4addr, ip4net, ip6addr)
    vlans.append(new_vlan)

to_return = ""
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
vrrpconf = templateEnv.get_template('template_vrrp_instance').render(
                vlans=vlans, track_files=keepalived_offset_folder,
                interface=interface
                ) + "\n"

output_file = open(output_file, "w")
output_file.write(vrrpconf)
output_file.close()
