#!/usr/bin/env sh

if [ -f "/usr/local/etc/haproxy.d/haproxy_internals.cfg" ]; then
    /bin/mv /usr/local/etc/haproxy.d/haproxy_internals.cfg /usr/local/etc/haproxy.d/00_haproxy_internals.cfg
    /bin/echo "Haproxy internals configuration file renamed"
fi
