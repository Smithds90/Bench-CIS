#!/usr/bin/env bash


pkg info
c=N;read -p "Couch: Do you want to update packages?[y/N]" c; if [ $c == 'Y' -o $c == 'y' ]; then pkg upgrade; fi


freebsd-version -ku
echo Couch: For updating OS version and patches use following commands: freebsd-update fetch; freebsd-update upgrade -r [release]; freebsd-update install
read -p "Next" a


sed 's/sendmail_enable=/#sendmail_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "sendmail_enable=\"NO\"" >> /etc/rc.conf
sed 's/sendmail_submit_enable=/#sendmail_submit_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "sendmail_submit_enable=\"NO\"" >> /etc/rc.conf
sed 's/sendmail_outbound_enable=/#sendmail_outbound_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "sendmail_outbound_enable=\"NO\"" >> /etc/rc.conf
sed 's/sendmail_msp_queue_enable=/#sendmail_msp_queue_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "sendmail_msp_queue_enable=\"NO\"" >> /etc/rc.conf


sed 's/named_enable=/#named_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "named_enable=\"NO\"" >> /etc/rc.conf


sed 's/rpc_lockd_enable=/#rpc_lockd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "rpc_lockd_enable=\"NO\"" >> /etc/rc.conf
sed 's/rpc_statd_enable=/#rpc_statd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "rpc_statd_enable=\"NO\"" >> /etc/rc.conf
sed 's/rpcbind_enable=/#rpcbind_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "rpcbind_enable=\"NO\"" >> /etc/rc.conf


sed 's/nis_server_enable=/#nis_server_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nis_server_enable=\"NO\"" >> /etc/rc.conf
sed 's/nis_ypxfrd_enable=/#nis_ypxfrd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nis_ypxfrd_enable=\"NO\"" >> /etc/rc.conf
sed 's/nis_yppasswdd_enable=/#nis_yppasswdd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nis_yppasswdd_enable=\"NO\"" >> /etc/rc.conf
sed 's/rpc_ypupdated_enable=/#rpc_ypupdated_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "rpc_ypupdated_enable=\"NO\"" >> /etc/rc.conf


sed 's/nis_client_enable=/#nis_client_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nis_client_enable=\"NO\"" >> /etc/rc.conf
sed 's/nis_ypset_enable=/#nis_ypset_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nis_ypset_enable=\"NO\"" >> /etc/rc.conf


sed 's/nfs_server_enable=/#nfs_server_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nfs_server_enable=\"NO\"" >> /etc/rc.conf
sed 's/mountd_enabl=/#mountd_enabl=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "mountd_enabl=\"NO\"" >> /etc/rc.conf


sed 's/nfs_client_enable=/#nfs_client_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nfs_client_enable=\"NO\"" >> /etc/rc.conf


sed 's/nfs_reserved_port_only=/#nfs_reserved_port_only=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "nfs_reserved_port_only=\"YES\"" >> /etc/rc.conf


sed 's/weak_mountd_authentication=/#weak_mountd_authentication=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "weak_mountd_authentication=\"NO\"" >> /etc/rc.conf


sed 's/lpd_enable=/#lpd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "lpd_enable=\"NO\"" >> /etc/rc.conf


sed 's/autofs_enable=/#autofs_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "autofs_enable=\"NO\"" >> /etc/rc.conf


sed 's/apache22_enable=/#apache22_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "apache22_enable=\"NO\"" >> /etc/rc.conf
sed 's/apache24_enable=/#apache24_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "apache24_enable=\"NO\"" >> /etc/rc.conf


echo Couch: Add permitted IPs to /etc/hosts.allow
read -p "Next" a
sed 's/inetd_enable=/#inetd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "inetd_enable=\"YES\"" >> /etc/rc.conf
sed 's/inetd_flags=/#inetd_flags=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "inetd_flags=\"-Wwl -C60\"" >> /etc/rc.conf
echo "ALL : ALL : deny" >> /etc/hosts.allow
chmod 644 /etc/hosts.allow


sed 's/^telnet/#telnet/g' /etc/inetd.conf > /etc/inetd.conf.tmp
cp /etc/inetd.conf.tmp /etc/inetd.conf


echo Couch: All needed NFS exports must have their write or read-only permissions specified, as well as the clients authorized to remotely mount the directories exported.This must be done by changing the referring lines in /etc/exports to follow the example: share -ro IP1 IP2
read -p "Next" a


c=N;read -p "Couch: Do you want to disable SNMP?[y/N]" c; if [ $c == 'Y' -o $c == 'y' ]; then sed 's/snmpd_enable=/#snmpd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp; cp /etc/rc.conf.tmp /etc/rc.conf; echo "snmpd_enable=\"NO\"" >> /etc/rc.conf; fi


sed 's/\(r[ow]community\s\+public\)/#\1/g' /usr/local/share/snmp/snmpd.conf > /usr/local/share/snmp/snmpd.conf.tmp
cp /usr/local/share/snmp/snmpd.conf.tmp /usr/local/share/snmp/snmpd.conf
sed 's/\(r[ow]community\s\+private\)/#\1/g' /usr/local/share/snmp/snmpd.conf > /usr/local/share/snmp/snmpd.conf.tmp
cp /usr/local/share/snmp/snmpd.conf.tmp /usr/local/share/snmp/snmpd.conf


echo Couch: If use SNMPv2 restrict hosts that can access SNMP service in /usr/local/share/snmp/snmpd.conf, example: rwcommunity [community_name] 10.10.10.0/24
read -p "Next" a


grep ^[^#] /etc/rc.conf
grep ^[^#] /etc/defaults/rc.conf
echo Couch: Search for enabled uneccessary services and disable them.
read -p "Next" a


sed 's/kern.coredump=[123456789]/#kern.coredump=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "kern.coredump=0" || echo "kern.coredump=0" >> /etc/sysctl.conf


sed 's/kern.securelevel=[023456789]/#kern.securelevel=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "kern.securelevel=1" || echo "kern.securelevel=1" >> /etc/sysctl.conf


sed 's/security.bsd.see_other_uids=[123456789]/#security.bsd.see_other_uids=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "security.bsd.see_other_uids=0" || echo "security.bsd.see_other_uids=0" >> /etc/sysctl.conf


sed 's/security.bsd.see_other_gids=[123456789]/#security.bsd.see_other_gids=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "security.bsd.see_other_gids=0" || echo "security.bsd.see_other_gids=0" >> /etc/sysctl.conf


sed 's/net.inet.ip.sourceroute=[123456789]/#net.inet.ip.sourceroute=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip.sourceroute=0" || echo "net.inet.ip.sourceroute=0" >> /etc/sysctl.conf
sed 's/net.inet.ip.accept_sourceroute=[123456789]/#net.inet.ip.accept_sourceroute=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip.accept_sourceroute=0" || echo "net.inet.ip.accept_sourceroute=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.bmcastecho=[123456789]/#net.inet.icmp.bmcastecho=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.bmcastecho=0" || echo "net.inet.icmp.bmcastecho=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.bmcastecho=[123456789]/#net.inet.icmp.bmcastecho=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.bmcastecho=0" || echo "net.inet.icmp.bmcastecho=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.maskrepl=[123456789]/#net.inet.icmp.maskrepl=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.maskrepl=0" || echo "net.inet.icmp.maskrepl=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.maskrepl=[123456789]/#net.inet.icmp.maskrepl=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.maskrepl=0" || echo "net.inet.icmp.maskrepl=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.bmcastecho=[123456789]/#net.inet.icmp.bmcastecho=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.bmcastecho=0" || echo "net.inet.icmp.bmcastecho=0" >> /etc/sysctl.conf


sed 's/net.inet.icmp.bmcastecho=[123456789]/#net.inet.icmp.bmcastecho=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.icmp.bmcastecho=0" || echo "net.inet.icmp.bmcastecho=0" >> /etc/sysctl.conf


sed 's/net.inet.ip.redirect=[123456789]/#net.inet.ip.redirect=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip.redirect=0" || echo "net.inet.ip.redirect=0" >> /etc/sysctl.conf
sed 's/net.inet.ip6.redirect=[123456789]/#net.inet.ip6.redirect=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip6.redirect=0" || echo "net.inet.ip6.redirect=0" >> /etc/sysctl.conf


sed 's/net.inet.ip.redirect=[123456789]/#net.inet.ip.redirect=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip.redirect=0" || echo "net.inet.ip.redirect=0" >> /etc/sysctl.conf
sed 's/net.inet.ip6.redirect=[123456789]/#net.inet.ip6.redirect=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.ip6.redirect=0" || echo "net.inet.ip6.redirect=0" >> /etc/sysctl.conf


sed 's/kern.ipc.somaxconn=/#kern.ipc.somaxconn=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
echo "kern.ipc.somaxconn=1024" >> /etc/sysctl.conf


sed 's/routed_enabled=/#routed_enabled=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "routed_enabled=\"NO\"" >> /etc/rc.conf


sed 's/net.inet.tcp.syncookies=[023456789]/#net.inet.tcp.syncookies=/g' /etc/sysctl.conf > /etc/sysctl.conf.tmp
cp /etc/sysctl.conf.tmp /etc/sysctl.conf
grep ^[^#] /etc/sysctl.conf | grep "net.inet.tcp.syncookies=1" || echo "net.inet.tcp.syncookies=1" >> /etc/sysctl.conf


echo Couch: All the services in /etc/inetd.conf file should be disabled, unless they are necessary. This can be done by commenting out the line relating to the service. Services like telnet and ftp must be replaced by SSH.
read -p "Next" a


echo Couch: The DNS servers listed in /etc/resolv.conf file must be those managed locally by the internal.
read -p "Next" a


echo > /etc/hosts.equiv
echo > /home/*/.netrc
echo > /home/*/.rhosts
echo > /root/.netrc
echo > /root/.rhosts
chmod 000 /etc/hosts.equiv
chmod 000 /home/*/.netrc
chmod 000 /home/*/.rhosts
chmod 000 /root/.netrc
chmod 000 /root/.rhosts


grep "incsec:Security Configuration Standard" /etc/security/audit_class || sed "s;0xffffffffffffffff;#0xffffffffffffffff;g" /etc/security/audit_class > /etc/security/audit_class.tmp && cp /etc/security/audit_class.tmp /etc/security/audit_class && printf "0x0100000000000000:incsec:Security Configuration Standard\n0xffffffffffffffff:all:all classes (meta-class)\n" >> /etc/security/audit_class


grep ^[^#] /etc/security/audit_event | grep AUE_ACCEPT | grep incsec || awk '{if (match($0, /^.*:AUE_ACCEPT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_CONNECT | grep incsec || awk '{if (match($0, /^.*:AUE_CONNECT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SOCKACCEPT | grep incsec || awk '{if (match($0, /^.*:AUE_SOCKACCEPT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SOCKCONNECT | grep incsec || awk '{if (match($0, /^.*:AUE_SOCKCONNECT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_inetd_connect | grep incsec || awk '{if (match($0, /^.*:AUE_inetd_connect:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


grep ^[^#] /etc/security/audit_event | grep AUE_CHMOD | grep incsec || awk '{if (match($0, /^.*:AUE_CHMOD:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_CHOWN | grep incsec || awk '{if (match($0, /^.*:AUE_CHOWN:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHOWN | grep incsec || awk '{if (match($0, /^.*:AUE_FCHOWN:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHMOD | grep incsec || awk '{if (match($0, /^.*:AUE_FCHMOD:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_LCHOWN | grep incsec || awk '{if (match($0, /^.*:AUE_LCHOWN:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_ACLSET | grep incsec || awk '{if (match($0, /^.*:AUE_ACLSET:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FACLSET | grep incsec || awk '{if (match($0, /^.*:AUE_FACLSET:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


grep ^[^#] /etc/security/audit_event | grep AUE_CHROOT | grep incsec || awk '{if (match($0, /^.*:AUE_CHROOT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETREUID | grep incsec || awk '{if (match($0, /^.*:AUE_SETREUID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETREGID | grep incsec || awk '{if (match($0, /^.*:AUE_SETREGID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHROOT | grep incsec || awk '{if (match($0, /^.*:AUE_FCHROOT:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_PFEXEC | grep incsec || awk '{if (match($0, /^.*:AUE_PFEXEC:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETUID | grep incsec || awk '{if (match($0, /^.*:AUE_SETUID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_NICE | grep incsec || awk '{if (match($0, /^.*:AUE_NICE:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETGID | grep incsec || awk '{if (match($0, /^.*:AUE_SETGID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_PRIOCNTLSYS | grep incsec || awk '{if (match($0, /^.*:AUE_PRIOCNTLSYS:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETEGID | grep incsec || awk '{if (match($0, /^.*:AUE_SETEGID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETEUID | grep incsec || awk '{if (match($0, /^.*:AUE_SETEUID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETPPRIV | grep incsec || awk '{if (match($0, /^.*:AUE_SETPPRIV:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETSID | grep incsec || awk '{if (match($0, /^.*:AUE_SETSID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETPGID | grep incsec || awk '{if (match($0, /^.*:AUE_SETPGID:.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


sed 's/dir:/#dir:/g' /etc/security/audit_control > /etc/security/audit_control.tmp
cp /etc/security/audit_control.tmp /etc/security/audit_control
echo "dir:/var/audit" >> /etc/security/audit_control
sed 's/flags:/#flags:/g' /etc/security/audit_control > /etc/security/audit_control.tmp
cp /etc/security/audit_control.tmp /etc/security/audit_control
echo "flags:lo,aa,ad,ex,fw,fc,fd,incsec" >> /etc/security/audit_control
sed 's/minfree:/#minfree:/g' /etc/security/audit_control > /etc/security/audit_control.tmp
cp /etc/security/audit_control.tmp /etc/security/audit_control
echo "minfree:5" >> /etc/security/audit_control
sed 's/naflags:/#naflags:/g' /etc/security/audit_control > /etc/security/audit_control.tmp
cp /etc/security/audit_control.tmp /etc/security/audit_control
echo "naflags:lo,aa" >> /etc/security/audit_control
sed 's/policy:/#policy:/g' /etc/security/audit_control > /etc/security/audit_control.tmp
cp /etc/security/audit_control.tmp /etc/security/audit_control
echo "policy:cnt,argv" >> /etc/security/audit_control
audit -s
grep "^0 0 * * * /usr/sbin/audit -n" /etc/crontab || echo "0 0 * * * /usr/sbin/audit -n" >> /etc/crontab


sed 's/auditd_enable=/#auditd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "auditd_enable=\"YES\"" >> /etc/rc.conf
service auditd start


grep "^daemon.debug\t\t\t\t/var/log/daemon.log" /etc/syslog.conf || printf "daemon.debug\t\t\t\t/var/log/daemon.log\n" >> /etc/syslog.conf
touch /var/log/daemon.log
chown root:wheel /var/log/daemon.log
chmod 600 /var/log/daemon.log


touch /var/account/acct
accton /var/account/acct
sed 's/accounting_enable=/#accounting_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "accounting_enable=\"YES\"" >> /etc/rc.conf


sed 's/syslogd_enable=/#syslogd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "syslogd_enable=\"YES\"" >> /etc/rc.conf
service syslogd start


echo Couch: Configure rules in /etc/syslog.conf
read -p "Next" a


grep "^auth.notice /var/log/authlog" /etc/syslog.conf || echo "auth.notice /var/log/authlog" >> /etc/syslog.conf
touch /var/log/authlog
chown root:wheel /var/log/authlog
chmod 600 /var/log/authlog


sed 's/syslogd_flags=/#syslogd_flags=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "syslogd_flags=\"-s\"" >> /etc/rc.conf


chown -R root /var/account
chmod -R go-rwx /var/account
chown -R root /var/log
chmod -R go-rwx /var/log
chmod 640 /var/log/utx.log
chmod 640 /var/log/utx.lastlogin
chown -R root /var/audit
chmod -R go-rwx /var/audit


grep "^flags:" /etc/security/audit_control | grep "lo" || (sed 's/\(flags:.*\)$/\1,lo/g' /etc/security/audit_control > /etc/security/audit_control.tmp; cp /etc/security/audit_control.tmp /etc/security/audit_control)


grep "^flags:" /etc/security/audit_control | grep "lo" || (sed 's/\(flags:.*\)$/\1,lo/g' /etc/security/audit_control > /etc/security/audit_control.tmp; cp /etc/security/audit_control.tmp /etc/security/audit_control)


grep "^flags:" /etc/security/audit_control | grep "lo" || (sed 's/\(flags:.*\)$/\1,lo/g' /etc/security/audit_control > /etc/security/audit_control.tmp; cp /etc/security/audit_control.tmp /etc/security/audit_control)


grep "^flags:" /etc/security/audit_control | grep "lo" || (sed 's/\(flags:.*\)$/\1,lo/g' /etc/security/audit_control > /etc/security/audit_control.tmp; cp /etc/security/audit_control.tmp /etc/security/audit_control)


grep "^flags:" /etc/security/audit_control | grep "ad" || (sed 's/\(flags:.*\)$/\1,ad/g' /etc/security/audit_control > /etc/security/audit_control.tmp; cp /etc/security/audit_control.tmp /etc/security/audit_control)


sed -i .preFile -e 's/644/600/g; s/640/600/g' /etc/newsyslog.conf &&\
awk '($1 == "/var/log/utx.log") { $4 = "644" }; \
($1 == "/var/log/lastlog") { $4 = "644" } { print }' \
/etc/newsyslog.conf > /etc/newsyslog.conf.new &&\
mv /etc/newsyslog.conf.new /etc/newsyslog.conf
for file in `ls /etc/newsyslog.conf.d/`; do sed -i .preFile -e 's/644/600/g; s/640/600/g' /etc/newsyslog.conf.d/$file; awk '($1 == "/var/log/utx.log") { $4 = "644" }; ($1 == "/var/log/lastlog") { $4 = "644" } { print }' $file > $file.new; mv /etc/newsyslog.conf.d/$file.new /etc/newsyslog.conf.d/$file; done


sed 's/ntpd_enable=/#ntpd_enable=/g' /etc/rc.conf > /etc/rc.conf.tmp
cp /etc/rc.conf.tmp /etc/rc.conf
echo "ntpd_enable=\"YES\"" >> /etc/rc.conf
service ntpd start
read -p "Enter first NTP-server:" ntp_serv_1
read -p "Enter second NTP-server:" ntp_serv_2
grep "^server $ntp_serv_1" /etc/ntp.conf || echo "server 0 $ntp_serv_1" > /etc/ntp.conf
grep "^server $ntp_serv_2" /etc/ntp.conf || echo "server 1 $ntp_serv_2" >> /etc/ntp.conf
grep "^restrict 127.0.0.1" /etc/ntp.conf || echo "restrict 127.0.0.1" >> /etc/ntp.conf
grep "^restrict 127.127.1.0" /etc/ntp.conf || echo "restrict 127.127.1.0" >> /etc/ntp.conf
grep "^restrict -6 ::1" /etc/ntp.conf || echo "restrict -6 ::1" >> /etc/ntp.conf
grep "^restrict $ntp_serv_1 nomodify nopeer noquery notrap" /etc/ntp.conf || echo "restrict $ntp_serv_1 nomodify nopeer noquery notrap" >> /etc/ntp.conf
grep "^restrict $ntp_serv_2 nomodify nopeer noquery notrap" /etc/ntp.conf || echo "restrict $ntp_serv_2 nomodify nopeer noquery notrap" >> /etc/ntp.conf
grep "^restrict default ignore" /etc/ntp.conf || echo "restrict default ignore" >> /etc/ntp.conf
grep "^restrict -6 default ignore" /etc/ntp.conf || echo "restrict -6 default ignore" >> /etc/ntp.conf
grep "^driftfile /var/ntp/ntp.drift" /etc/ntp.conf || echo "driftfile /var/ntp/ntp.drift" >> /etc/ntp.conf
chown root:wheel /etc/ntp.conf
chmod 600 /etc/ntp.conf


chown root:wheel /etc/passwd /etc/master.passwd /etc/group /etc/pwd.db /etc/spwd.db
chmod 644 /etc/passwd /etc/group /etc/pwd.db
chmod 600 /etc/master.passwd /etc/spwd.db


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type d \( -perm -0002 -a ! -perm -1000 \)`; do chmod +t $line;done


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print`; do chmod o-w $line;done


find  / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print
echo Couch: Consider the output and disable SUID/SGID permissions where they are not needed
read -p "Next" a


grep ^[^#] /etc/passwd | awk -F: "{ print \$1 \" \" \$3 \" \" \$6 }" | while read nuser nuid ndir; do if [ $nuid -gt 1000 -a -d "$ndir" -a $nuser != "nfsnobody" ] ; then nowner=$(stat -f "%u" "$ndir"); if [ "$nowner" != "$nuser" -a "$nowner" != "$nuid" ]; then chown $nuser $ndir; fi; fi; done


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \( -nouser -o -nogroup \)`; do chown root:wheel $line; chmod go-w $line; done


awk '($4 == "dialup") { $5 = "off" } { print }' /etc/ttys > /etc/ttys.new
mv /etc/ttys.new /etc/ttys


awk '($1 == "console") { $5 = "insecure" } { print }' /etc/ttys > /etc/ttys.new
mv /etc/ttys.new /etc/ttys


find /etc/ /usr/local/etc/rc.d/ | xargs grep ^[^#] | egrep "umask[ =]"
echo Couch: Change umask to 022 or stronger
read -p "Next" a


sed -i .preFile -e 's/nologin/deny/g' /etc/pam.d/rsh /etc/pam.d/rexecd


pkg delete -r wrapper-\*
sed -i .preFile -e '/xdm -nodaemon/s/off/on/' /etc/ttys


sed -e '/^:/s/$/ -nolisten tcp/' </usr/X11R6/lib/X11/xdm/Xservers >/etc/X11/xdm/Xservers


z=$IFS
IFS=$'\n'
for line in `grep ^[^#] /etc/pam.conf /etc/pam.d/* 2>/dev/null | grep -i pam_rhosts`; do q=`echo $line | cut -d: -f1`; w=`echo $line | cut -d: -f2`; sed "s;$w;#$w;g" $q > $q.tmp; cp $q.tmp $q; done
IFS=$z


echo Couch: Set login-backoff=1 in default profile in /etc/login.conf
read -p "Next" a
cap_mkdb /etc/login.conf


echo 'root' > /var/cron/allow
echo 'root' > /var/at/allow
chown root:wheel /var/cron/allow /var/at/allow
chmod 400 /var/cron/allow /var/at/allow
chmod 0640 /etc/crontab


sed 's/PATH=/#PATH=/g' /etc/crontab > /etc/crontab.tmp
cp /etc/crontab.tmp /etc/crontab
echo "PATH=/usr/bin" >> /etc/crontab


chmod 700 /var/cron/tabs


sed 's/[[:space:]]secure/ insecure/g' /etc/ttys > /etc/ttys.tmp
cp /etc/ttys.tmp /etc/ttys


echo Couch: FreeBSD doesn\'t include system tools for locking accounts after sequence of failed login. To enforce this policy for example fail2ban may be used.
read -p "Next" a


#read -p "Enter boot password:" boot_pass
#sed 's/password=/#password=/g' /boot/defaults/loader.conf > /boot/loader.conf.tmp
#cp /boot/defaults/loader.conf.tmp /boot/defaults/loader.conf
#echo "password=$boot_pass" >> /boot/defaults/loader.conf
chmod 700 /boot/defaults/loader.conf


chown root:wheel /usr/bin/gcc /usr/bin/cc
chmod 500 /usr/bin/gcc /usr/bin/cc


echo Couch: Create wheel group and include the common users used by administrators in it, editing /etc/group file.
read -p "Next" a
chown root:wheel /usr/bin/su
chmod 4750 /usr/bin/su


echo Couch: Remove all unnecessary aliases from the /etc/aliases file. Entries with commands specified as aliases, like used for uudecode and decode, must be removed.
read -p "Next" a


echo Couch: Change /etc/mail/aliases to indicate a valid internal email address as root alias.
read -p "Next" a


sed "s;TMOUT=;#TMOUT=;g" /etc/profile > /etc/profile.tmp
cp /etc/profile.tmp /etc/profile
echo "TMOUT=900" >> /etc/profile
grep ^[^#] /etc/profile | grep "readonly TMOUT" || echo "readonly TMOUT" >> /etc/profile


grep ^[^#] /usr/local/etc/sudoers | grep "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /usr/local/etc/sudoers


echo Couch: Add string \":passwordtime=90d:\\\" to the default profile in /etc/login.conf.
read -p "Next" a
cap_mkdb /etc/login.conf


echo "defaultLgroup=" > /etc/adduser.conf
echo "defaultclass=default" >> /etc/adduser.conf
echo "defaultgroups=" >> /etc/adduser.conf
echo "passwdtype=yes" >> /etc/adduser.conf
echo "homeprefix=/home" >> /etc/adduser.conf
echo "defaultshell=/bin/csh" >> /etc/adduser.conf
echo "disableflag=" >> /etc/adduser.conf
echo "upwexpire=90d" >> /etc/adduser.conf
echo "uexpire=" >> /etc/adduser.conf


pw deluser toor


grep ^[^#] /etc/pam.d/passwd | grep "password        requisite       pam_passwdqc.so         min=disabled,disabled,disabled,8,8 similar=deny retry=3 enforce=users" || echo "password        requisite       pam_passwdqc.so         min=disabled,disabled,disabled,8,8 similar=deny retry=3 enforce=users" >> /etc/pam.d/passwd


sed "s;umask=[0-9]*;umask=077;g" /etc/profile > /etc/profile.tmp
cp /etc/profile.tmp /etc/profile
sed "s;umask=[0-9]*;umask=077;g" /etc/csh.login > /etc/csh.login.tmp
cp /etc/csh.login.tmp /etc/csh.login
sed "s;umask=[0-9]*;umask=077;g" /etc/csh.cshrc > /etc/csh.cshrc.tmp
cp /etc/csh.cshrc.tmp /etc/csh.cshrc
sed "s;umask=[0-9]*;umask=077;g" /etc/login.conf > /etc/login.conf.tmp
cp /etc/login.conf.tmp /etc/login.conf


sed -i .preFile -e 's/#[[:space:]]mesg[[:space:]]y/mesg n/g' /etc/profile
sed -i .preFile -e 's/#[[:space:]]mesg[[:space:]]y/mesg n/g' /etc/csh.login


echo Couch: FreeBSD doesn\'t include system tools for locking accounts after inactivity period. Cron job may be used to search and lock out such accounts.
read -p "Next" a


echo "Authorized users only. All activity may be monitored and reported. Use of this system implies the acceptance of such monitoring." > /etc/motd
chmod 644 /etc/motd


sed 's/im=.*:/im=\\r\\n:/g' /etc/gettytab > /etc/gettytab.tmp
cp /etc/gettytab.tmp /etc/gettytab


rm -f /etc/ftpwelcome


for user in $(grep "^[^#]" /etc/passwd | awk -F ":" "( \$3 <= 1000 && \$3 != 0 ) { print \$1 }"); do pw lock $user; done


for user in `grep ^[^#] /etc/master.passwd 2>/dev/null | awk -F ":" '( $2 == "" ) { print $1 }'`; do pw lock $user; done


for user in `awk -F: '( $3 == 0 && $1 != "root") { print $1 }' /etc/passwd`; do rmuser $user; done


echo Couch: Set passwd_format=sha512 in all profiles in /etc/login.conf.
read -p "Next" a


if [ "`/bin/echo $PATH | /usr/bin/grep :: `" != "" ]; then /bin/echo "Error: Empty Directory in PATH (::)"; fi; if [ "`/bin/echo $PATH | /usr/bin/grep :$`" != "" ]; then /bin/echo "Error: Trailing : in PATH"; fi; p=`/bin/echo $PATH | /usr/bin/sed -e "s/::/:/" -e "s/:$//" -e "s/:/ /g"`; set -- $p; while [ "$1" != "" ]; do /bin/echo $1; if [ "$1" == "." ]; then /bin/echo "Error: PATH contains ."; shift; continue; fi; if [ -d $1 ]; then dirperm=`/bin/ls -ldH $1 | /usr/bin/cut -f1 -d" "`; /bin/echo "$dirperm"; if [ `/bin/echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then /bin/echo "Error: Group Write permissions on directory $1"; fi; if [ `/bin/echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then /bin/echo "Error: Other Write permissions set on directory $1"; fi; dirown=$(/bin/ls -ldH $1 | /usr/bin/awk "{print \$3}"); /bin/echo "$dirown"; if [ "$dirown" != "root" ]; then /bin/echo "Error: $1 is not owned by root"; fi; else /bin/echo "Error: $1 is not a directory"; fi; shift; done
echo Couch: If some errors are returned correct root PATH
read -p "Next" a


for dir in $( awk -F: " ( \$3 > 1000 && \$3 != 65534 ) { print \$6 }" /etc/passwd ); do for each in `find ${dir} -type d -prune \( -perm -g+w -o -perm -o+w \)`; do chmod go-w $each; done; done


for dir in $(grep ^[^#] /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: "( \$7 != \"/usr/sbin/nologin\" && \$7 != \"/bin/false\" && \$7 != \"/sbin/nologin\" ) { print \$6}"); do for file in $dir/.[A-Za-z0-9]*; do if [ ! -h "$file" -a -f "$file" ]; then fileperm=`ls -ld $file | cut -f1 -d" "`; if [ `echo $fileperm | cut -c6 ` != "-" ]; then chmod g-w $file; fi; if [ `echo $fileperm | cut -c9 ` != "-" ]; then chmod o-w $file; fi; fi; done; done


for dir in `grep ^[^#] /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | cut -d: -f6`; do chmod go-rwx $dir/.netrc; done;


for dir in `grep ^[^#] /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | cut -d: -f6`; do mv $dir/.rhosts $dir/.couch_rhosts; done;


for i in $( grep ^[^#] /etc/passwd | cut -s -d: -f4 | sort -u ); do egrep "^.*?:[^:]*:$i:" /etc/group; if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi; done
echo Couch: If some groups are returned, remove users with this groups, or change group for these users, or create such groups
read -p "Next" a


echo Couch: Users with unassigned home directory:
grep ^[^#] /etc/passwd | awk -F: "{ print \$1 \" \" \$3 \" \" \$6 }" | while read user uid dir; do if test $uid -gt 1000 -a -z $dir ; then echo "The home directory ($dir) for user $user is not assigned"; fi; done
echo Couch: If some are returned create and assign home directory for these users
read -p "Next" a


grep ^[^#] /etc/passwd | awk -F: "{ print \$1 \" \" \$3 \" \" \$6 }" | while read user uid dir; do if [ $uid -gt 1000 -a ! -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then mkdir $dir; fi; done


echo Couch: Users with common UID:
grep ^[^#] /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then users=$( awk -F: "(\$3 == n) { print \$1 }" n=$2 /etc/passwd | xargs ); echo "Duplicate UID ($2): ${users}"; fi; done
echo Couch: If some are returned, correct UIDs
read -p "Next" a


echo Couch: Groups with common GID:
grep ^[^#] /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then grps=$( awk -F: "(\$3 == n) { print \$1 }" n=$2 /etc/group | xargs ); echo "Duplicate GID ($2): ${grps}"; fi; done
echo Couch: If some are returned, correct GIDs
read -p "Next" a


echo Couch: Users with common username:
grep ^[^#] /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then uids=$( awk -F: "(\$1 == n) { print \$3 }" n=$2 /etc/passwd | xargs ); echo "Duplicate User Name ($2): ${uids}"; fi; done
echo Couch: If some are returned, correct usernames
read -p "Next" a


echo Couch: Groups with common groupname:
grep ^[^#] /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then gids=$( awk -F: "(\$1 == n) { print \$3 }" n=$2 /etc/group | xargs ); echo "Duplicate Group Name ($2): ${gids}"; fi; done
echo Couch: If some are returned, correct groupnames
read -p "Next" a


for dir in `grep ^[^#] /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | cut -d: -f6`; do mv $dir/.netrc $dir/.couch_netrc; done;


for dir in `grep ^[^#] /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | cut -d: -f6`; do mv $dir/.forward $dir/.couch_forward; done;


find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -acl -ls
echo Couch: Remove extended ACLs is some are returned
read -p "Next" a


for user in `grep ^[^#] /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/sbin/nologin") {print $1}'`; do chsh -s /sbin/nologin $user; done


chown root:wheel /usr/sbin/devctl
chmod 550 /usr/sbin/devctl



