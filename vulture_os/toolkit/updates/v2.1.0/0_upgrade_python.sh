#!/bin/sh

if [ -d /zroot/apache ] ; then
    /usr/sbin/pkg -j apache remove -y python38 ap24-py38-mod_wsgi
    /usr/sbin/pkg -j apache install -y lang/python www/mod_wsgi4
fi
if [ -d /zroot/portal ] ; then
    /usr/sbin/pkg -j portal remove -y python38 ap24-py38-mod_wsgi
    /usr/sbin/pkg -j portal install -y lang/python www/mod_wsgi4
fi
