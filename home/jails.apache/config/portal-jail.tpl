portal {                                                            #PORTALJAIL
        host.hostname = "portal";                                   #PORTALJAIL
        ip4.addr = "lo6|127.0.0.7";                                 #PORTALJAIL
        ip6.addr = "lo6|fd00::207";                                 #PORTALJAIL
        allow.raw_sockets = 0;                                      #PORTALJAIL
        exec.clean;                                                 #PORTALJAIL
        exec.system_user = "root";                                  #PORTALJAIL
        exec.jail_user = "root";                                    #PORTALJAIL
        exec.start += "/bin/sh /etc/rc";                            #PORTALJAIL
        exec.stop = "/bin/sh /etc/rc.shutdown";                     #PORTALJAIL
        exec.consolelog = "/var/log/jail_portal_console.log";       #PORTALJAIL
        allow.set_hostname = 0;                                     #PORTALJAIL
        allow.sysvipc = 0;                                          #PORTALJAIL
        enforce_statfs = "2";                                       #PORTALJAIL
	    devfs_ruleset = "4";    #devfsrules_jail                    #PORTALJAIL
    	mount.devfs;                                                #PORTALJAIL
}                                                                   #PORTALJAIL
