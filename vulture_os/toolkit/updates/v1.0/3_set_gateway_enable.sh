#!/bin/sh

if [ -f /etc/rc.conf.d/routing ] ; then
    # Set gateway_enable & ipv6_gateway_enable to YES in /etc/rc.conf.d/routing
    /usr/bin/sed -i '' "s/gateway_enable=.*/gateway_enable=\"YES\"/" /etc/rc.conf.d/routing
    /usr/bin/sed -i '' "s/ipv6_gateway_enable=.*/ipv6_gateway_enable=\"YES\"/" /etc/rc.conf.d/routing
fi
