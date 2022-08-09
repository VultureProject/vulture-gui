#!/bin/sh

if /usr/local/sbin/vm switch list | grep -q "public"; then
    echo "Removing legacy VM interface 'vm-public'"
    /usr/local/sbin/vm switch destroy public
fi

if /usr/bin/grep -qF "tap0" /etc/rc.conf.d/network; then
    echo "Removing legacy tap0 configuration"
    /usr/sbin/sysrc -f /etc/rc.conf.d/network cloned_interfaces-="tap0"
    /usr/sbin/sysrc -xf /etc/rc.conf.d/network ifconfig_tap0
fi

if /sbin/ifconfig | /usr/bin/grep -qE "^tap0:"; then
    echo "Removing legacy tap0 interface"
    /sbin/ifconfig tap0 destroy
fi

echo "Reloading dnsmasq"
/usr/sbin/service dnsmasq reload || /usr/sbin/service dnsmasq restart
