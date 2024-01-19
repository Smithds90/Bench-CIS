#!/usr/bin/env bash


pkg info
pkg update -n
c=N;read -p "Couch: Do you want to update packages?[y/N]" c; if [ $c == 'Y' -o $c == 'y' ]; then pkg update; fi


pkg info entire | grep FMRI: | awk "{ print \$2 }"
echo Couch: Update operating system software to manufacters supported version
read -p "Next" a


svcadm disable svc:/application/graphical-login/gdm:default


svccfg -v -s svc:/network/smtp:sendmail setprop config/local_only=true 
svcadm refresh sendmail
svcadm restart sendmail


svcadm disable svc:/network/rpc/keyserv


svcadm disable svc:/network/nis/server
svcadm disable svc:/network/nis/domain


svcadm disable svc:/network/nis/client


svcadm disable svc:/network/security/ktkt_warn


svcadm disable svc:/network/rpc/gss


svcadm disable svc:/system/filesystem/rmvolmgr 
svcadm disable svc:/network/rpc/smserver


svcadm disable svc:/system/filesystem/autofs


svcadm disable svc:/network/http:apache22
svcadm disable svc:/network/http:apache24


echo Couch: Redact /etc/hosts.allow file to permit IP-addresses and network access to this hosts
read -p "Next" a
echo "ALL: ALL" >/etc/hosts.deny
inetadm -M tcp_wrappers=TRUE
svccfg -s rpc/bind setprop config/enable_tcpwrappers=true
svcadm refresh rpc/bind


svcadm disable svc:/network/telnet


echo Couch:All needed NFS exports must have their write or read-only permissions specified, as well as the clients authorized to remotely mount the directories exported.This must be done by changing the referring lines in /etc/dfs/dfstab to follow the example below: share -F nfs -o ro=IP1:IP2 /exported_dir
read -p "Next" a


sed 's/\(r[ow]community\s\+public\)/#\1/g' /etc/net-snmp/snmp/snmpd.conf > /etc/net-snmp/snmp/snmpd.conf.tmp
cp /etc/net-snmp/snmp/snmpd.conf.tmp /etc/net-snmp/snmp/snmpd.conf
sed 's/\(r[ow]community\s\+private\)/#\1/g' /etc/net-snmp/snmp/snmpd.conf > /etc/net-snmp/snmp/snmpd.conf.tmp
cp /etc/net-snmp/snmp/snmpd.conf.tmp /etc/net-snmp/snmp/snmpd.conf


echo Couch: Include the managers directive and add the hosts that will have access to the SNMP communities in /etc/net-snmp/snmp/snmpd.conf
read -p "Next" a


echo Couch: Unnecessary services must be disabled from the current process state with the following commmand: pkill [process]. The startup files in /etc/rc3.d and /etc/rc2.d directories relating to the unnecessary services must be moved to new names starting with "S" 
read -p "Next" a


chmod 700 /var/share/cores
coreadm -g /var/share/cores/core_%n_%f_%u_%g_%t_%p -e log -e global -e global-setid -d process -d proc-setid


sed 's/set\s+sys:coredumpsize/#set sys:coredumpsize/g' /etc/system > /etc/system.tmp
cp /etc/system.tmp /etc/system
echo "set sys:coredumpsize = 0" >> /etc/system


sed 's/set\s+noexec_user_stack/#set\+noexec_user_stack/g' /etc/system > /etc/system.tmp
cp /etc/system.tmp /etc/system
echo "set noexec_user_stack=1" >> /etc/system
sed 's/set\s+noexec_user_stack_log/#set noexec_user_stack_log/g' /etc/system > /etc/system.tmp
cp /etc/system.tmp /etc/system
echo "set noexec_user_stack_log=1" >> /etc/system


cd /etc/default
awk '/TCP_STRONG_ISS=/ { $1 = "TCP_STRONG_ISS=2" }; { print }' inetinit > inetinit.temp
mv inetinit.temp inetinit
ipadm set-prop -p _strong_iss=2 tcp


ipadm set-prop -p _forward_src_routed=0 ipv4
ipadm set-prop -p _forward_src_routed=0 ipv6


ipadm set-prop -p _forward_directed_broadcasts=0 ip


ipadm set-prop -p _respond_to_timestamp=0 ip


ipadm set-prop -p _respond_to_timestamp_broadcast=0 ip


ipadm set-prop -p _respond_to_address_mask_broadcast=0 ip


ipadm set-prop -p _respond_to_echo_broadcast=0 ip


ipadm set-prop -p _respond_to_echo_multicast=0 ipv4
ipadm set-prop -p _respond_to_echo_multicast=0 ipv6


ipadm set-prop -p _ignore_redirect=1 ipv4
ipadm set-prop -p _ignore_redirect=1 ipv6


ipadm set-prop -p _strict_dst_multihoming=1 ipv4
ipadm set-prop -p _strict_dst_multihoming=1 ipv6


ipadm set-prop -p send_redirects=off ipv4
ipadm set-prop -p send_redirects=off ipv6


ipadm set-prop -p _rev_src_routes=0 tcp


ipadm set-prop -p _conn_req_max_q0=4096 tcp


ipadm set-prop -p _conn_req_max_q=1024 tcp


routeadm -d ipv4-forwarding -d ipv4-routing
routeadm -d ipv6-forwarding -d ipv6-routing
routeadm -u


ndd -set /dev/tcp tcp_sack_permitted 2
grep "^ndd -set /dev/tcp tcp_sack_permitted 2" /etc/rc3.d/S99net || echo "ndd -set /dev/tcp tcp_sack_permitted 2" >> /etc/rc3.d/S99net


echo Couch: All the services in /etc/inetd.conf file should be disabled, unless they are necessary. This can be done by commenting out the line relating to the service. Services like telnet and ftp must be replaced by SSH.
read -p "Next" a


echo Couch: Change the line starting inetd in /etc/rc2.d/S**inetsvc to: /usr/sbin/inetd -s -t
read -p "Next" a
pkill inetd
svcs -xv inetd


grep ^[^#] /etc/resolv.conf 2>/dev/null | grep nameserver
echo Couch: Ensure that DNS servers in /etc/resolv.conf are those managed locally by the internal
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


grep "incsec:Security Configuration Standard" /etc/security/audit_class || sed "s;0xffffffffffffffff:all:all classes (meta-class);#0xffffffffffffffff:all:all classes (meta-class);g" /etc/security/audit_class > /etc/security/audit_class.tmp && cp /etc/security/audit_class.tmp /etc/security/audit_class && echo "0x0100000000000000:incsec:Security Configuration Standard\n0xffffffffffffffff:all:all classes (meta-class)" >> /etc/security/audit_class


grep ^[^#] /etc/security/audit_event | grep AUE_ACCEPT | grep incsec || gawk '{if (match($0, /^.*:AUE_ACCEPT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_CONNECT | grep incsec || gawk '{if (match($0, /^.*:AUE_CONNECT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SOCKACCEPT | grep incsec || gawk '{if (match($0, /^.*:AUE_SOCKACCEPT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SOCKCONNECT | grep incsec || gawk '{if (match($0, /^.*:AUE_SOCKCONNECT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_inetd_connect | grep incsec || gawk '{if (match($0, /^.*:AUE_inetd_connect::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


grep ^[^#] /etc/security/audit_event | grep AUE_CHMOD | grep incsec || gawk '{if (match($0, /^.*:AUE_CHMOD::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_CHOWN | grep incsec || gawk '{if (match($0, /^.*:AUE_CHOWN::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHOWN | grep incsec || gawk '{if (match($0, /^.*:AUE_FCHOWN::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHMOD | grep incsec || gawk '{if (match($0, /^.*:AUE_FCHMOD::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_LCHOWN | grep incsec || gawk '{if (match($0, /^.*:AUE_LCHOWN::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_ACLSET | grep incsec || gawk '{if (match($0, /^.*:AUE_ACLSET::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FACLSET | grep incsec || gawk '{if (match($0, /^.*:AUE_FACLSET::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


grep ^[^#] /etc/security/audit_event | grep AUE_CHROOT | grep incsec || gawk '{if (match($0, /^.*:AUE_CHROOT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETREUID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETREUID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETREGID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETREGID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_FCHROOT | grep incsec || gawk '{if (match($0, /^.*:AUE_FCHROOT::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_PFEXEC | grep incsec || gawk '{if (match($0, /^.*:AUE_PFEXEC::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETUID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETUID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_NICE | grep incsec || gawk '{if (match($0, /^.*:AUE_NICE::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETGID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETGID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_PRIOCNTLSYS | grep incsec || gawk '{if (match($0, /^.*:AUE_PRIOCNTLSYS::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETEGID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETEGID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETEUID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETEUID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETPPRIV | grep incsec || gawk '{if (match($0, /^.*:AUE_SETPPRIV::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETSID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETSID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event
grep ^[^#] /etc/security/audit_event | grep AUE_SETPGID | grep incsec || gawk '{if (match($0, /^.*:AUE_SETPGID::.*/)) print $0",incsec"; else print $0}' /etc/security/audit_event > /etc/security/audit_event.tmp && cp /etc/security/audit_event.tmp /etc/security/audit_event


auditconfig -conf 
auditconfig -setflags lo,ad,ft,ex,am,as,ua,aa,fc,fd,incsec 
auditconfig -setnaflags lo  
auditconfig -setpolicy cnt,argv,zonename 
auditconfig -setplugin audit_binfile active p_minfree=5 
audit -s 
rolemod -K audit_flags=lo,ad,ft,ex,am,as,ua,aa,fc,fd,incsec:no root 
grep "^0 0 * * * /usr/sbin/audit -n" /var/spool/cron/crontabs/root || echo "0 0 * * * /usr/sbin/audit -n" >> /var/spool/cron/crontabs/root
chown root:root /var/share/audit 
chmod 750 /var/share/audit


/sbin/init.d/syslogd start


echo Couch: Configure rules in /etc/syslog.conf
read -p "Next" a


grep "^auth.notice /var/log/authlog" /etc/syslog.conf || echo "auth.notice /var/log/authlog" >> /etc/syslog.conf
touch /var/log/authlog
chown root root /var/log/authlog
chmod 600 /var/log/authlog


sed "s;LOG_FROM_REMOTE;#LOG_FROM_REMOTE;g" /etc/default/syslogd > /etc/default/syslogd.tmp
cp /etc/default/syslogd.tmp /etc/default/syslogd
echo "LOG_FROM_REMOTE=NO" >> /etc/default/syslogd


chown -R root /var/share
chmod -R go-rwx /var/share
chown -R root /var/adm
chmod -R go-rwx /var/adm
chmod 640 /var/adm/utmpx
chmod 640 /var/adm/wtmpx
chown -R root /var/log
chmod -R go-rwx /var/log
chown -R root /var/audit
chmod -R go-rwx /var/audit


sed "s;SYSLOG;#SYSLOG;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "SYSLOG=YES" >> /etc/default/login


sed "s;SYSLOG_FAILED_LOGINS;#SYSLOG_FAILED_LOGINS;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "SYSLOG_FAILED_LOGINS=0" >> /etc/default/login


sed "s;SYSLOG;#SYSLOG;g" /etc/default/su > /etc/default/su.tmp
cp /etc/default/su.tmp /etc/default/su
echo "SYSLOG=YES" >> /etc/default/su


sed "s;CONSOLE=;#CONSOLE=;g" /etc/default/su > /etc/default/su.tmp
cp /etc/default/su.tmp /etc/default/su
echo "CONSOLE=/dev/console" >> /etc/default/su


sed "s;CRONLOG;#CRONLOG;g" /etc/default/cron > /etc/default/cron.tmp
cp /etc/default/cron.tmp /etc/default/cron
echo "CRONLOG=YES" >> /etc/default/cron


read -p "Enter first NTP-server:" ntp_serv_1
read -p "Enter second NTP-server:" ntp_serv_2
grep "^server 0 $ntp_serv_1" /etc/inet/ntp.conf || echo "server 0 $ntp_serv_1" > /etc/inet/ntp.conf
grep "^server 1 $ntp_serv_2" /etc/inet/ntp.conf || echo "server 1 $ntp_serv_2" >> /etc/inet/ntp.conf
grep "^restrict 127.0.0.1" /etc/inet/ntp.conf || echo "restrict 127.0.0.1" >> /etc/inet/ntp.conf
grep "^restrict 127.127.1.0" /etc/inet/ntp.conf || echo "restrict 127.127.1.0" >> /etc/inet/ntp.conf
grep "^restrict -6 ::1" /etc/inet/ntp.conf || echo "restrict -6 ::1" >> /etc/inet/ntp.conf
grep "^restrict $ntp_serv_1 nomodify nopeer noquery notrap" /etc/inet/ntp.conf || echo "restrict $ntp_serv_1 nomodify nopeer noquery notrap" >> /etc/inet/ntp.conf
grep "^restrict $ntp_serv_2 nomodify nopeer noquery notrap" /etc/inet/ntp.conf || echo "restrict $ntp_serv_2 nomodify nopeer noquery notrap" >> /etc/inet/ntp.conf
grep "^restrict default ignore" /etc/inet/ntp.conf || echo "restrict default ignore" >> /etc/inet/ntp.conf
grep "^restrict -6 default ignore" /etc/inet/ntp.conf || echo "restrict -6 default ignore" >> /etc/inet/ntp.conf
grep "^driftfile /var/ntp/ntp.drift" /etc/inet/ntp.conf || echo "driftfile /var/ntp/ntp.drift" >> /etc/inet/ntp.conf
chown root:root /etc/inet/ntp.conf
chmod 600 /etc/inet/ntp.conf


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type d \( -perm -0002 -a ! -perm -1000 \)`; do chmod +t $line;done


svcadm disable svc:/system/console-login:terma 
svcadm disable svc:/system/console-login:termb


sed "s;ENABLE_NOBODY_KEYS=;#ENABLE_NOBODY_KEYS=;g" /etc/default/keyserv > /etc/default/keyserv.tmp
cp /etc/default/keyserv.tmp /etc/default/keyserv
echo "ENABLE_NOBODY_KEYS=NO" >> /etc/default/keyserv


z=$IFS
IFS=$'\n'
for line in `grep ^[^#] /etc/pam.conf /etc/pam.d/* | grep -i pam_rhosts_auth`; do q=`echo $line | cut -d: -f1`; w=`echo $line | cut -d: -f2`; sed "s;$w;#$w;g" $q > $q.tmp; cp $q.tmp $q; done
IFS=$z


getent passwd | cut -f1 -d":" > /etc/ftpd/ftpusers
echo Couch: Remove users for whom are permitted to use ftp from /etc/ftpd/ftpusers file
read -p "Next" a


sed "s;SLEEPTIME=;#SLEEPTIME=;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "SLEEPTIME=4" >> /etc/default/login


sed "s;gdm-autologin;#gdm-autologin;g" /etc/pam.conf > /etc/pam.conf.tmp
cp /etc/pam.conf.tmp /etc/pam.conf
echo > /etc/pam.d/gdm-autologin


cd /usr/share/X11/app-defaults 
cp XScreenSaver XScreenSaver.orig 
awk '/^\*timeout:/ { $2 = "0:10:00" } /^\*lockTimeout:/ { $2 = "0:00:00" } /^\*lock:/ { $2 = "True" } { print }' xScreenSaver > xScreenSaver.File 
mv xScreenSaver.File xScreenSaver


cd /etc/cron.d 
mv cron.deny cron.deny.old_couch 
mv at.deny at.deny.old_couch
echo root > cron.allow 
cp /dev/null at.allow 
chown root:root cron.allow at.allow 
chmod 400 cron.allow at.allow


sed "s;PATH=;#PATH=;g" /etc/default/cron > /etc/default/cron.tmp
cp /etc/default/cron.tmp /etc/default/cron
echo "PATH=/usr/bin" >> /etc/default/cron


chmod 700 /etc/cron.d


sed "s;CONSOLE=;#CONSOLE=;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "CONSOLE=/dev/console" >> /etc/default/login


sed "s;RETRIES=;#RETRIES=;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "RETRIES=5" >> /etc/default/login
sed "s;LOCK_AFTER_RETRIES=;#LOCK_AFTER_RETRIES=;g" /etc/security/policy.conf > /etc/security/policy.conf.tmp
cp /etc/security/policy.conf.tmp /etc/security/policy.conf
echo "LOCK_AFTER_RETRIES=YES" >> /etc/security/policy.conf
svcadm restart svc:/system/name-service/cache


echo Couch: After next commands the administrator will be prompted for a password. This password will be required to authorize any future command issued at boot-level on the system \(the ok or \> prompt\) except for the normal multi-user boot command \(i.e., the system will be able to reboot unattended\). Write down the password and store it in a sealed envelope in a secure location \(note that locked desk drawers are typically not secure\). If the password is lost or forgotten, simply log into the system and run the command: eeprom security-mode=none. This will erase the forgotten password. If the password is lost or forgotten and this action cannot be completed, then the EEPROM must be replaced to gain access to the system. To set a new password, run the command: eeprom security-mode=command
read -p "Next" a
eeprom security-mode=command
eeprom security-badlogins=0


echo Couch:
echo Perform the following to implement the recommended state:
echo /boot/grub/bin/grub 
echo grub\> md5crypt 
echo Password: [enter desired boot loader password] 
echo Encrypted: 
echo grub\> [enter control-C ]
chmod 600 /rpool/boot/grub/menu.lst
read -p "Next" a
echo Add the following line to the menu.lst file above the entries added by bootadm: password --md5 [enter md5 password string generated above]
read -p "Next" a
echo Finally, add the keyword lock to the Solaris failsafe boot entry as in the following example \(as well as to any other entries that you want to protect\): 
echo title Solaris failsafe 
echo lock
read -p "Next" a


sed "s;KEYBOARD_ABORT=;#KEYBOARD_ABORT=;g" /etc/default/kbd > /etc/default/kbd.tmp
cp /etc/default/kbd.tmp /etc/default/kbd
echo "KEYBOARD_ABORT=disable" >> /etc/default/kbd


chown root:root /usr/bin/gcc /usr/bin/cc
chmod 700 /usr/bin/gcc /usr/bin/cc


echo Couch: Create wheel group and include the common users used by administrators in it, editing /etc/group file.
read -p "Next" a
chown root:wheel /usr/bin/su 
chmod 4750 /usr/bin/su


echo Couch: Remove all unnecessary aliases from the /etc/aliases file. Entries with commands specified as aliases, like used for uudecode and decode, must be removed.
read -p "Next" a


echo Couch: Change /etc/mail/aliases to indicate a valid internal email address as root alias.
read -p "Next" a


sed "s;^\*;#*;g" /usr/dt/config/Xaccess > /usr/dt/config/Xaccess.tmp
cp /usr/dt/config/Xaccess.tmp /usr/dt/config/Xaccess


sed "s;TMOUT=;#TMOUT=;g" /etc/profile > /etc/profile.tmp
cp /etc/profile.tmp /etc/profile
echo "TMOUT=900" >> /etc/profile
grep ^[^#] /etc/profile | grep "readonly TMOUT" || echo "readonly TMOUT" >> /etc/profile


sed "s;TIMEOUT=;#TIMEOUT=;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "TIMEOUT=15" >> /etc/default/login


grep ^[^#] /etc/sudoers | grep "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


logins -ox | awk -F: '($1 == "root" || $8 == "LK" || $8 == "NL") { next } ; { $cmd = "passwd" } ; ($11 > 91) { $cmd = $cmd " -x 91" } ($10 < 7) { $cmd = $cmd " -n 7" } ($12 < 7) { $cmd = $cmd " -w 7" } ($cmd != "passwd") { print $cmd " " $1 }' > /etc/Preupd_accounts 
/sbin/sh /etc/Preupd_accounts 
rm -f /etc/Preupd_accounts 
cd /etc/default 
grep -v WEEKS passwd > passwd.preFile 
echo "MAXWEEKS=13\nMINWEEKS=1\nWARNWEEKS=1" >> passwd.preFile 
mv passwd.preFile passwd


cd /etc/default
awk '/PASSLENGTH=/ { $1 = "PASSLENGTH=8" }; /NAMECHECK=/ { $1 = "NAMECHECK=YES" }; /HISTORY=/ { $1 = "HISTORY=5" }; /MINDIFF=/ { $1 = "MINDIFF=3" }; /WHITESPACE=/ { $1 = "WHITESPACE=YES" }; /DICTIONDBDIR=/ { $1 = "DICTIONDBDIR=/var/passwd" }; /DICTIONLIST=/ { $1 = "DICTIONLIST=/usr/share/lib/dict/words" }; { print }' passwd > passwd.preFile
mv passwd.preFile passwd


sed "s;UMASK=;#UMASK=;g" /etc/default/login > /etc/default/login.tmp
cp /etc/default/login.tmp /etc/default/login
echo "UMASK=027" >> /etc/default/login


cd /etc
if [ "`grep '^Umask' proftpd.conf`" ]; then awk '/^Umask/ { $2 = "027" } { print }' proftpd.conf > proftpd.conf.preFile; mv proftpd.conf.preFile proftpd.conf; else echo "Umask 027" >> proftpd.conf; fi


cd /etc
for file in profile .login csh.login ; do if [ "`grep mesg $file`" ]; then awk '$1 == "mesg" { $2 = "n" } { print }' $file > $file.preFile; mv $file.preFile $file; else echo mesg n >> $file; fi; done


useradd -D -f 90
for u in `logins -ox | awk -F: "( \\$1 != \"root\" ) { print \\$1 }"`; do usermod -f 90 $u; done


echo "Authorized users only. All activity may be monitored and reported." > /etc/motd
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue


echo Couch: Edit the /etc/gdm/Init/Default file to add the following content before the last line of the file: /usr/bin/zenity --text-info --width=800 --height=300 --title=\"Security Message\" --filename=/etc/issue
read -p "Next" a


grep "^DisplayConnect /etc/issue" /etc/proftpd.conf || echo "DisplayConnect /etc/issue" >> /etc/proftpd.conf
svcadm restart ftp


sed "s;BANNER=;#BANNER=;g" /etc/default/telnetd > /etc/default/telnetd.tmp
cp /etc/default/telnetd.tmp /etc/default/telnetd
echo "BANNER=" >> /etc/default/telnetd


echo BANNER=\"\" > /etc/default/ftpd


z=$IFS
IFS=$'\n'
for line in `/usr/sbin/consadm -p`; do /usr/sbin/consadm -d $line; done
IFS=$z


pkg fix


for user in aiuser dhcpserv dladm ftp gdm netadm netcfg noaccess nobody nobody4 openldap pkg5srv svctag unknown webservd xvm adm bin daemon lp mysql nuucp postgres smmsp sys upnp uucp zfssnap; do passwd -d $user; passwd -N $user; done


for user in `logins -p`; do passwd -l $user; done


for user in `logins -o | awk -F: '(\$2 == 0) { print \$1 }'`; do if [ "$user" != "root" ]; then userdel $user; fi; done


if [ "`/bin/echo $PATH | /usr/bin/grep :: `" != "" ]; then /bin/echo "Empty Directory in PATH (::)"; fi;  if [ "`/bin/echo $PATH | /usr/bin/grep :$`" != "" ]; then /bin/echo "Error: Trailing : in PATH"; fi; p=`/bin/echo $PATH | /usr/bin/sed -e "s/::/:/" -e "s/:\$//" -e "s/:/ /g"`; set -- $p; while [ "$1" != "" ]; do if [ "$1" == "." ]; then /bin/echo "Error: PATH contains ."; shift; continue; fi; if [ -d $1 ]; then dirperm=`/bin/ls -ldH $1 | /usr/bin/cut -f1 -d" "`; if [ `/bin/echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then /bin/echo "Error: Group Write permissions on directory $1"; fi; if [ `/bin/echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then /bin/echo "Error: Other Write permissions set on directory $1"; fi; dirown=`/bin/ls -ldH $1 | /usr/bin/awk "{print \\$3}"`; if [ "$dirown" != "root" ]; then /bin/echo "Error: $1 in not owned by root"; fi; else /bin/echo "Error: $1 is not a directory"; fi; shift; done
echo Couch: If some errors are returned correct root PATH
read -p "Next" a


for dir in `logins -ox | awk -F: "(\\$8 == "PS") { print \\$6 }"`; do chmod g-r,o-rwx $dir; done;


for dir in `logins -ox | awk -F: "(\\$8 == "PS") { print \\$6 }"`; do chmod g-r,o-rwx $dir/.*; done;


for dir in `logins -ox | awk -F: "(\\$8 == "PS") { print \\$6 }"`; do chmod go-rwx $dir/.netrc; done;


rm -f /home/*/.rhosts
rm -f /root/.rhosts


echo Couch: Groups existing in passwd but not included in /etc/groups:
logins -xo | awk -F: "(\$3 == \"\") { print \$1 }"
echo Couch: If some groups are returned, remove users with this groups, or change group for these users, or create such groups
read -p "Next" a


echo Couch: Users with unassigned home directory:
logins -xo | while read line; do user=`echo ${line} | awk -F: "{ print \\$1 }"`; home=`echo ${line} | awk -F: "{ print \\$6 }"`; if [ -z "${home}" ]; then echo ${user}; fi; done
echo Couch: If some are returned create and assign home directory for these users
read -p "Next" a


logins -xo | while read line; do user=`echo ${line} | awk -F: "{ print \\$1 }"`; home=`echo ${line} | awk -F: "{ print \\$6 }"`; if [ ! -d "${home}" -a $user != "uucp" -a $user != "nuucp" ]; then a=`grep ${user} /etc/passwd | cut -d: -f6`; mkdir $a; fi; done


logins -xo | awk -F: "(\$8 == "PS") { print }" | while read line; do user=`echo ${line} | awk -F: "{ print \\$1 }"`; home=`echo ${line} | awk -F: "{ print \\$6 }"`; for line in `find ${home} -type d -prune ! -user ${user}`; do chown ${user} ${home}; done; done


echo Couch: Users with common UID:
logins -d
echo Couch: If some are returned, correct UIDs
read -p "Next" a


echo Couch: Groups with common GID:
getent group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set - $x; if [ $1 -gt 1 ]; then grps=`getent group | nawk -F: "(\\$3 == n) { print \\$1 }" n=\$2 | xargs`; echo "Duplicate GID ($2): ${grps}"; fi; done
echo Couch: If some are returned, correct GIDs
read -p "Next" a


echo Couch: Users with common username:
getent passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set - $x; if [ $1 -gt 1 ]; then gids=`getent passwd | nawk -F: "(\\$1 == n) { print \\$3 }" n=\$2 | xargs`; echo "Duplicate User Name ($2): ${gids}"; fi; done
echo Couch: If some are returned, correct usernames
read -p "Next" a


echo Couch: Groups with common groupname:
getent group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set - $x; if [ $1 -gt 1 ]; then gids=`getent group | nawk -F: "(\\$1 == n) { print \\$3 }" n=$2 | xargs`; echo "Duplicate Group Name ($2): ${gids}"; fi; done
echo Couch: If some are returned, correct groupnames
read -p "Next" a


rm -f /home/*/.netrc
rm -f /root/.netrc


rm -f /home/*/.forward
rm -f /root/.forward


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print`; do chmod o-w $line; done


find  / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print
echo Couch: Consider the output and disable SUID/SGID permissions where they are not needed
read -p "Next" a


for line in `find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \( -nouser -o -nogroup \)`; do chown root:root $line; done


find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -xattr -ls
echo Couch: Remove extended ACLs is some are returned
read -p "Next" a


for line in `grep ^[^#] /etc/passwd | awk -F: '(\$1!="root" && \$1!="sync" && \$1!="shutdown" && \$1!="halt" && \$3<100 && \$7!="/usr/sbin/nologin" && \$7!="/bin/false" && \$7!="/sbin/nologin") {print}' | cut -f1 -d:`; do usermod -s /bin/false $line; done


poweradm set suspend-enable=false
poweradm update


svcadm disable svc:/network/inetd



