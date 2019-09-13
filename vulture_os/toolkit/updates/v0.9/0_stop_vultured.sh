#!/bin/sh

/bin/kill -9 $(/bin/cat /var/run/vulture/vultured.pid)

/bin/echo "[!] Please start vultured at the end of the update [!]"
