#!/bin/sh

nic=$1
IPADDR=$(tail -n 20 /var/db/dhclient.leases.$nic | grep '-m' '1' 'fixed-address' | awk '{print $2}' | sed -e 's/;//')
NETMASK=$(tail -n 20 /var/db/dhclient.leases.$nic | grep '-m' '1' 'subnet-mask' | awk '{print $3}' | sed -e 's/;//')
GATEWAY=$(tail -n 20 /var/db/dhclient.leases.$nic | grep '-m' '1' 'routers' | awk '{print $3}' | sed -e 's/;//')
echo $IPADDR,$NETMASK,$GATEWAY