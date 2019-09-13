#!/bin/sh

if ! /usr/sbin/jls -j apache 2> /dev/null | /usr/bin/grep "apache" ; then
    /bin/echo "Jail apache not existing. Quitting."
    return
fi

/bin/echo "[-] Installing liblognorm in apache jail ..."

if [ -f /etc/rc.conf.proxy ]; then
    . /etc/rc.conf.proxy
    export http_proxy=${http_proxy}
    export https_proxy=${https_proxy}
    export ftp_proxy=${ftp_proxy}
fi

/usr/sbin/pkg -j apache install -y liblognorm

/bin/echo "[+] Done."