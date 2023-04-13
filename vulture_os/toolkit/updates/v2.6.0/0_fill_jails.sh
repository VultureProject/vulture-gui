#!/usr/bin/env sh

if [ -d "/.jail_system/" ]; then
    /bin/echo "Updating jails' files..."

    OLD_LINKS="etc/defaults etc/newsyslog.conf etc/mail etc/syslog.conf etc/rc etc/rc.d etc/pkg etc/mtree etc/rc.subr etc/network.subr etc/rc.shutdown"
    COPY_LIST=".cshrc .profile COPYRIGHT etc media mnt net proc root tmp var usr/obj usr/tests"

    for jail in apache portal mongodb redis rsyslog haproxy; do
        /bin/echo $jail

        for old_link in $OLD_LINKS; do
            # Only delete the file if it is a link
            /usr/bin/find "/zroot/${jail}/${old_link}" -type l -delete
        done

        for file in ${COPY_LIST}; do
            if [ -f "/.jail_system/${file}" ]; then
                    /bin/cp -nRP "/.jail_system/${file}" "/zroot/${jail}/${file}"
            fi
            if [ -d "/.jail_system/${file}" ]; then
                    /bin/cp -nRP "/.jail_system/${file}/" "/zroot/${jail}/${file}"
            fi
        done
    done

fi
