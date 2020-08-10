#!/bin/sh

config=$1
destination=`basename $2`
loop=$3

echo $destination

if [ "$loop" ==  "0" ]; then

    if [ "$destination" == "network" ]; then

        if [ -f "/usr/local/etc/cloned.intf" ]; then
            vlan_nic=" `/bin/cat /usr/local/etc/cloned.intf`"
        else
            vlan_nic=""
        fi

        echo "ifconfig_lo0=\"inet 127.0.0.1 netmask 255.255.255.0\"" >  /etc/rc.conf.d/network
        echo "ifconfig_lo0_ipv6=\"inet6 ::1 prefixlen 128\"" >> /etc/rc.conf.d/network
        echo "ifconfig_lo0_alias0=\"inet6 fd00::201 prefixlen 128\"" >> /etc/rc.conf.d/network
        echo "#Declare LACP and VLAN interfaces (eg: 'lagg0 vlan100 vlan200') in /usr/local/etc/cloned.intf" >> /etc/rc.conf.d/network 
        echo -n "cloned_interfaces=\"lo1 lo2 lo3 lo4 lo5 lo6${vlan_nic}" >> /etc/rc.conf.d/network
        if ! /usr/local/sbin/vm switch info public ; then
            echo " tap0\"" >> /etc/rc.conf.d/network
            echo "ifconfig_tap0=\"inet 192.168.1.1 netmask 255.255.255.0\"" >> /etc/rc.conf.d/network
        else
            echo "\"" >> /etc/rc.conf.d/network
        fi
        echo $config | sed -e 's/_EOL/\
/g' >> /etc/rc.conf.d/$destination
    else
echo $config | sed -e 's/_EOL/\
/g' > /etc/rc.conf.d/$destination
    fi
else
    echo $config | sed -e 's/_EOL/\
/g' >> /etc/rc.conf.d/$destination
fi
