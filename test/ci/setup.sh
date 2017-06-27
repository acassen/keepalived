#!/bin/sh

# kernel version
#uname -a

# compiler version
#gcc -v

# Distro
#cat /etc/*release

# Packages installed
#sudo apt list --installed

# Install development libraries
sudo apt -qq install libsnmp-dev iptables-dev libipset-dev libnfnetlink-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev

# Update kernel headers to match kernel
CURDIR=$(pwd)
cd /tmp
KER_VER=$(sudo apt list --installed | grep "^linux-image-[0-9]" | sed -e "s/.*,now //" -e "s/~.*//")
wget http://security.ubuntu.com/ubuntu/pool/main/l/linux/linux-libc-dev_${KER_VER}_amd64.deb
sudo dpkg --install linux-libc-dev_${KER_VER}_amd64.deb
rm linux-libc-dev_${KER_VER}_amd64.deb
cd $CURDIR
