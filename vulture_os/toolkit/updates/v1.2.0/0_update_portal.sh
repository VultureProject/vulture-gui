#!/bin/sh

if [ -f /etc/rc.conf.proxy ]; then
    . /etc/rc.conf.proxy
    export http_proxy=${http_proxy}
    export https_proxy=${https_proxy}
    export ftp_proxy=${ftp_proxy}
fi

if [ -d /zroot/portal ] ; then
    /usr/sbin/pkg -j portal install -y tiff || echo "[!] Failed to install tiff in portal - Please make 'pkg -j portal install -y tiff' to solve the issue."
    /usr/sbin/pkg -j portal install -y libxcb || echo "[!] Failed to install tiff in portal - Please make 'pkg -j portal install -y libxcb' to solve the issue."
fi
