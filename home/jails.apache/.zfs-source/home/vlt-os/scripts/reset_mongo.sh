#!/bin/sh
if [ -d /zroot/mongodb/var ]; then
    rm -rf /zroot/mongodb/var/db/mongodb/*
fi
if [ -d /zroot/mongodb/root/var ]; then
    rm -rf /zroot/mongodb/root/var/db/mongodb/*
fi