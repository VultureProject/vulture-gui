#!/bin/sh

if [ -d /zroot/portal ] ; then
    /usr/sbin/pkg -j portal install -y tiff || echo "[!] Failed to install tiff in portal - Please make 'pkg -j portal install -y tiff' to solve the issue."
    /usr/sbin/pkg -j portal install -y libxcb || echo "[!] Failed to install tiff in portal - Please make 'pkg -j portal install -y libxcb' to solve the issue."
fi
