#!/usr/bin/env bash


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /tmp. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /tmp


grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /tmp


rep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /tmp


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var


grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /var


grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /var


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var/tmp


grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /var/tmp


grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /var/tmp


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var/log


grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /var/log


grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /var/log


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log/audit. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /var/log/audit


grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var/log/audit


grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /var/log/audit


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /home . 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /home


grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /home


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nodev  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep noexec  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nosuid  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /dev/shm


grep "/media" /etc/fstab  | grep ^[^#] | grep nodev || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nodev $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep noexec || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,noexec $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep nosuid || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nosuid $each; done


df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t


modprobe -r cramfs 2>&1 | grep builtin && (echo "Module cramfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* cramfs .*\)"#\1"g' /etc/modprobe.d/$each; done;echo install cramfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r squashfs 2>&1 | grep builtin && (echo "Module squashfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* squashfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install squashfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r udf 2>&1 | grep builtin && (echo "Module udf is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* udf .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install udf /bin/true >> /etc/modprobe.d/disabled_modules.conf)


if [[ -z $(grep -E -i '\svfat\s' /etc/fstab) ]]; then modprobe -r vfat 2>&1 | grep builtin && (echo "Module vfat is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* vfat .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install vfat /bin/true >> /etc/modprobe.d/disabled_modules.conf); else echo "Vfat is used and must be disabled manually if is not required"; read -p "Next" a; fi


systemctl --now disable autofs


echo "[Manual]" 'Configure your package manager repositories according to site policy.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Repositories are configured in the /etc/apt/sources.list and /etc/apt/sources.list.d/*.list files. Ensure that every configured repository includes pointer to public key for signing verification as the second field in the line. Configuration for public keys is located in the /etc/apt/vendors.list and /etc/apt/vendors.list.d/*.list files.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Use your package manager to update all packages on the system according to site policy. 
Notes:  Site policy may mandate a testing period before install onto production systems for available updates.'
read -n 1 -p "Press Enter to continue..."


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
chown root:root "$grubdir/grub.cfg"
chown root:root "$grubdir/user.cfg"
chown root:root "$grubdir/grubenv"


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
chmod og-rwx "$grubdir/grub.cfg"
chmod og-rwx "$grubdir/user.cfg"
chmod og-rwx "$grubdir/grubenv"


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
if [[ -z $(grep '^set superusers' "$grubdir"/*.cfg) ]] || [[ -z $(grep '^password' "$grubdir"/*.cfg) ]]; then echo "Configuring password for grub"; grub-mkpasswd-pbkdf2; read -p "Enter username for grub authentication:" user; read -p "Enter generated above encrypted password for grub authentication:" pass; if [[ "$pass" =~ ^grub\.pbkdf2\.sha512\. ]]; then echo "set superusers=\"$user\"" >> /etc/grub.d/40_custom; echo "password_pbkdf2 $user $pass" >> /etc/grub.d/40_custom; update-grub; chmod og-rwx "$grubdir/grub.cfg"; chmod og-rwx "$grubdir/user.cfg"; chmod og-rwx "$grubdir/grubenv"; else echo "Couch: Password format is not correct, password was not set"; fi; fi


echo "[Manual]" 'Run the following command and follow the prompts to set a password for the root user: 
# passwd root'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(sysctl kernel.core_pattern | grep 'systemd-coredump') ]]; then 
  sed -ri 's/^(\s*Storage\s*=)/## \1/i' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /run/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf.d/*.conf;
  echo 'Storage=none' >> /etc/systemd/coredump.conf;
  sed -ri 's/^(\s*ProcessSizeMax\s*=)/## \1/i' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /run/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf.d/*.conf;
  echo 'ProcessSizeMax=0' >> /etc/systemd/coredump.conf;
else 
  sed -ri "s;^(\s*\*\s+hard\s+core\s+[1-9]);## \1;" /etc/security/limits.conf /etc/security/limits.d/*;
  [[ -n $(grep -E "^\s*\*\s+hard\s+core\s+0(\s|$)" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null) ]] || echo '* hard core 0' >> /etc/security/limits.conf;
  sed -i 's/^\(\s*fs\.suid_dumpable\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null;
  [[ -n $(grep -E "^\s*fs\.suid_dumpable\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/44-couch.conf;
  sysctl -w fs.suid_dumpable=0;
fi


echo "[Manual]" 'On 32 bit systems install a kernel with PAE support, no installation is required on 64 bit systems. If necessary configure your bootloader to load the new kernel and reboot the system. 
You may need to enable NX or XD support in your bios. 
Notes: Ensure your system supports the XD or NX bit and has PAE support before implementing this recommendation as this may prevent it from booting if these are not supported by your hardware. To check whether or not the CPU supports the nx feature, check /proc/cpuinfo for the nx flag:
# cat proc/cpuinfo | grep nx | uniq'
read -n 1 -p "Press Enter to continue..."


sed -i 's/^\(\s*kernel\.randomize_va_space\s*=\s*[013456789]\)/#\1/' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*kernel\.randomize_va_space\s*=\s*2(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/44-couch.conf
sysctl -w kernel.randomize_va_space=2


prelink -ua
apt-get remove prelink


modprobe -r usb-storage 2>&1 | grep builtin && (echo "Module usb-storage is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* usb-storage .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install usb-storage /bin/true >> /etc/modprobe.d/disabled_modules.conf)


apt-get -y install sudo


[[ -n $(grep -Ei '^\s*Defaults\s+([^#]+\s)?use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null) ]] || echo "Defaults use_pty" >> /etc/sudoers


[[ -n $(grep -Ei '^\s*Defaults\s+([^#]+\s)?logfile=".' /etc/sudoers /etc/sudoers.d/* 2>/dev/null) ]] || echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers


apt-get remove telnet-server


apt-get remove telnet


apt-get remove rsh-server


apt-get remove rsh


apt-get remove ypbind


apt-get remove ypserv


apt-get remove tftp


apt-get remove tftp-server


apt-get remove talk


apt-get remove talk-server


systemctl --now mask rsyncd 2>/dev/null


apt-get remove xinetd


chkconfig chargen-dgram off


chkconfig chargen-stream off


chkconfig daytime-dgram off


chkconfig daytime-stream off


chkconfig discard-dgram off
chkconfig discard-stream off


chkconfig echo-dgram off


chkconfig echo-stream off


chkconfig time-dgram off
chkconfig time-stream off


chkconfig tcpmux-server off


echo "[Manual]" 'Review enabled services and disable all unnecessary services:
# systemctl status'
read -n 1 -p "Press Enter to continue..."


chmod go-rwx /usr/bin/gcc
chmod go-rwx /usr/bin/cc


sed -i 's/^\s*umask /#umask /g' /etc/init.d/functions
echo umask 027 >> /etc/init.d/functions


apt-get remove xorg-x11-server-common


systemctl --now disable avahi-daemon


systemctl --now disable cups


systemctl --now disable dhcpd


read -p "Do you want to chrony or ntp for time synchronization?[CHRONY][ntp]" timeserv; if [ "$timeserv" == "ntp" ]; then apt-get -y install ntp; systemctl enable ntpd; systemctl start ntpd; else apt-get -y install chrony; systemctl enable chronyd; systemctl start chronyd; fi


if [[ -n $(systemctl is-enabled ntpd 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^\s*server\s*$ntp_server" /etc/ntp.conf || echo "server $ntp_server" >> /etc/ntp.conf; egrep "^\s*restrict\s*-4\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -4 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; egrep "^\s*restrict\s*-6\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -6 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; grep ^OPTIONS=\" /etc/sysconfig/ntpd && sed -i '/^OPTIONS=/s/"$/ -u ntp:ntp"/g' /etc/sysconfig/ntpd; grep ^OPTIONS=\" /etc/sysconfig/ntpd || echo OPTIONS=\"-u ntp:ntp\" >> /etc/sysconfig/ntpd; else echo "Not applicable - ntpd.service is not enabled"; fi


if [[ -n $(systemctl is-enabled chronyd 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^\s*server\s+$ntp_server" /etc/chrony.conf || echo "server $ntp_server" >> /etc/chrony.conf; grep ^OPTIONS=\" /etc/sysconfig/chronyd && sed -i '/^OPTIONS=/s/"$/ -u chrony"/g' /etc/sysconfig/chronyd; egrep ^OPTIONS=\" /etc/sysconfig/chronyd || echo OPTIONS=\"-u chrony\" >> /etc/sysconfig/chronyd; else echo "Not applicable - chronyd.service is not enabled"; fi


systemctl --now disable slapd


systemctl --now disable nfs 
systemctl --now disable nfs-server 
systemctl --now disable rpcbind


echo "[Manual]" 'All export NFS necessary must be with the respective
restrictions of writing, and limited to the IPs of the authorized
customers in the etc/exports:
/directory archive/client1(ro), client2(rw)'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]nfs[[:space:]]" /etc/fstab | grep ^[^#] | grep -v "nosuid" && sed -i 's;^\(.*\snfs\s\+[a-zA-Z0-9,]\+\)\(\s\+.*\)$;\1,nosuid\2;g' /etc/fstab


apt-get remove bind


apt-get remove vsftpd


apt-get remove httpd
apt-get remove lighttpd
apt-get remove nginx


apt-get remove dovecot
apt-get remove cyrus-imapd


apt-get remove samba


apt-get remove squid


apt-get remove net-snmp


sed -i 's/^\s*\(r[ow]community\s\+public\)/#\1/g' /etc/snmp/*.conf
sed -i 's/^\s*\(r[ow]community\s\+private\)/#\1/g' /etc/snmp/*.conf


if [ -e /etc/postfix/main.cf ]; then sed -i 's/^\s*inet_interfaces/#inet_interfaces/g' /etc/postfix/main.cf; echo inet_interfaces = loopback-only >> /etc/postfix/main.cf; systemctl restart postfix; fi


apt-get remove openldap-clients


apt-get remove ftp


apt-get remove dnsmasq


systemctl disable ahttpd
systemctl stop ahttpd


sed -i "s/^\(\s*net\.ipv4\.ip_forward\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.ip_forward\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.route.flush=1
sed -i "s/^\(\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/44-couch.conf
if [ -e /proc/sys/net/ipv6/conf/all/forwarding ]; then /sbin/sysctl -w net.ipv6.conf.all.forwarding=0; /sbin/sysctl -w net.ipv6.route.flush=1; fi


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 
/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0 
/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.secure_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.secure_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.secure_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.secure_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0 
/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.log_martians\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.log_martians\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.log_martians=1 
/sbin/sysctl -w net.ipv4.conf.default.log_martians=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1 
/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.tcp_syncookies\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.tcp_syncookies\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.tcp_syncookies=1
/sbin/sysctl -w net.ipv4.route.flush=1


module_fix()
{
if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install \/bin\/(true|false)'; then echo -e " - setting module: \"$l_mname\" to be un-loadable"; echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf; fi
if lsmod | grep "$l_mname" > /dev/null 2>&1; then echo -e " - unloading module \"$l_mname\""; modprobe -r "$l_mname"; fi
if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then echo -e " - deny listing \"$l_mname\""; echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf; fi
}
if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then 
  l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u);
  for l_mname in $l_dname; do module_fix; done;
fi


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_ra\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_ra\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_ra\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_ra\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.route.flush=1


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv6.route.flush=1


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_source_route=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv6.route.flush=1


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+ipv6\.disable=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+ipv6\.disable=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+ipv6\.disable=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1ipv6.disable=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='ipv6.disable=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+ipv6\.disable=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+ipv6\.disable=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+ipv6\.disable=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1ipv6.disable=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='ipv6.disable=1'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


modprobe -r dccp 2>&1 | grep builtin && (echo "Module dccp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* dccp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install dccp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r sctp 2>&1 | grep builtin && (echo "Module sctp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* sctp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install sctp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r rds 2>&1 | grep builtin && (echo "Module rds is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* rds .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install rds /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r tipc 2>&1 | grep builtin && (echo "Module tipc is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* tipc .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install tipc /bin/true >> /etc/modprobe.d/disabled_modules.conf)


echo "[Manual]" 'The DNS servers listed in
/etc/resolv.conf file must be those managed locally by the internal administrators.'
read -n 1 -p "Press Enter to continue..."


systemctl enable auditd
systemctl start auditd


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+audit=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+audit=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+audit=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1audit=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='audit=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+audit=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+audit=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+audit=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1audit=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='audit=1'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if echo "$line" | egrep "^[^#]*\s+audit_backlog_limit=([1-7][0-9]{3}|[0-9]{1,3}|80[0-9]{2}|81[0-8][0-9]|819[01])(\s|\"|')"; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
  done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+audit_backlog_limit=([1-7][0-9]{3}|[0-9]{1,3}|80[0-9]{2}|81[0-8][0-9]|819[01]))+(\s|\"|')/\3/g" /etc/sysconfig/grub2;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=[^#]*audit_backlog_limit=/b; s/^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$/\1audit_backlog_limit=8192 \2/" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='audit_backlog_limit=8192'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if echo "$line" | egrep "^[^#]*\s+audit_backlog_limit=([1-7][0-9]{3}|[0-9]{1,3}|80[0-9]{2}|81[0-8][0-9]|819[01])(\s|\"|')"; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
  done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+audit_backlog_limit=([1-7][0-9]{3}|[0-9]{1,3}|80[0-9]{2}|81[0-8][0-9]|819[01]))+(\s|\"|')/\3/g" /etc/sysconfig/grub2;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=[^#]*audit_backlog_limit=/b; s/^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$/\1audit_backlog_limit=8192 \2/" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='audit_backlog_limit=8192'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


sed -i 's/^\s*max_log_file\s*=\s*.*$/max_log_file = 50/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file\s*=\s*50\s*$" /etc/audit/auditd.conf || echo "max_log_file = 50" >> /etc/audit/auditd.conf


sed -i 's/^\s*space_left_action\s*=.*$/space_left_action = email/g' /etc/audit/auditd.conf
egrep "^\s*space_left_action\s*=\s*email\s*$" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i 's/^\s*action_mail_acct\s*=.*$/action_mail_acct = root/g' /etc/audit/auditd.conf
egrep "^\s*action_mail_acct\s*=\s*root\s*$" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf


echo "[Manual]" 'Configure max_log_file_action in /etc/audit/auditd.conf as prescribed in your organization, example keep_logs or rotate or leave default.'
read -n 1 -p "Press Enter to continue..."


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || ( egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/etc/group\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/passwd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/gshadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/shadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/security/opasswd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*exit,always\s*-F\s*arch=b64\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/etc/selinux/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/usr/share/selinux/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/share/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/var/log/lastlog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/lastlog -p wa -k logins " /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/run/faillock/\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/run/faillock/ -p wa -k logins" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/var/run/utmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/run/utmp -p wa -k session" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/wtmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/wtmp -p wa -k session" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/btmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/btmp -p wa -k session" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=500 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=500 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while read -r line; do egrep "^-a\s*always,exit\s*-F\s*path=${line}\s*-F\s*perm=x\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*privileged" /etc/audit/rules.d/audit.rules || (audit_num=$(cat /etc/audit/rules.d/audit.rules | wc -l); sed -i "${audit_num}i-a always,exit -F path=${line} -F perm=x -F auid\>=500 -F auid!=4294967295 -k privileged" /etc/audit/rules.d/audit.rules); done;
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi;


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=500 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules)) 
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*mount\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S mount -F auid\>=500 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=500 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=500 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid\>=500 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=500\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=500 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/etc/sudoers\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/sudoers.d/\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers.d/ -p wa -k scope" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/var/log/sudo.log\s*-p\s*wa\s*-k\s*actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/sudo.log -p wa -k actions" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
uname -i 2>&1 | grep 64 || (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
for file in `find /var/log -type f`; do \
if [[ "$file" =~ ^/var/log/journal/ ]]; then \
if [[ $(egrep "^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs;-w /var/log/journal -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/journal -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
elif [[ "$file" =~ ^.*/postgresql-[^/]*\.log$ ]]; then \
pref=$(dirname "$file"); if [[ $(egrep "^-w\s+$pref\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^-w\s+$pref\s[^#]*-k\s+access-logs;-w $pref -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $pref -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
elif ! [[ "$file" =~ ^.*([0-9]|old|back|gz)$ ]]; then \
if [[ $(egrep "^-w\s+$file\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^-w\s+$file\s[^#]*-k\s+access-logs;-w $file -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
fi; done

# special files
if [[ $(egrep "^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs;-w /var/log/journal -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/journal -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi
if [[ $(egrep "^\s*-w\s+/var/log/sudo.log\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^\s*-w\s+/var/log/sudo.log\s[^#]*-k\s+access-logs;-w /var/log/sudo.log -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/sudo.log -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi

restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
for file in `find /etc/pam.d -type f`; do egrep "^-w\s*$file\s*-p\s*wa\s*-k\s*change-auth-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p wa -k change-auth-cfg" /etc/audit/rules.d/audit.rules); done
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


[ ! -s /etc/audit/rules.d/audit.rules ] && echo "# couch" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s*/etc/audit/auditd.conf\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/auditd.conf -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/rules.d/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/rules.d/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


tail -n 1 /etc/audit/rules.d/audit.rules | egrep "^-e\s+2" || (sed -i "s;^-e\s\+;#-e ;g" /etc/audit/rules.d/audit.rules; echo "-e 2" >> /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


echo "[Manual]" 'Edit the /etc/logrotate.d/syslog file to include appropriate existing system logs. Example: 
/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {'
read -n 1 -p "Press Enter to continue..."


for f in `ls /etc/logrotate.conf /etc/logrotate.d/*`; do i=0; rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $line | egrep -i "/utmp|/wtmp|/btmp" && i=1; if [ "$i" == "0" ]; then echo $line | grep "{" && k=0; echo $line | grep "}" && if [ "$k" == "0" ]; then echo "create 0600 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 600 ;' >> $f.couch_tmp; else echo $line | grep "{" && k=0; echo $line | grep "}" && i=0&& if [ "$k" == "0" ]; then echo "create 0640 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 640 ;' >> $f.couch_tmp; fi; done < $f; yes | cp $f.couch_tmp $f; rm --interactive=never $f.couch_tmp; done


egrep "^Defaults\s+syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" /etc/sudoers || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


echo "[Manual]" 'By default the systemd-journald service does not have an [Install] section and thus cannot be enabled / disabled. It is meant to be referenced as Requires or Wants by other unit files. As such, if the status of systemd-journald is not static, investigate why.'
read -n 1 -p "Press Enter to continue..."


[[ -n $(sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Compress\s*=" | tail -n 1 | egrep "^\s*Compress\s*=\s*yes(\s|#|$)") ]] || (sed -i "s/^\s*Compress\s/## Compress/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nCompress=yes\n/' /etc/systemd/journald.conf)


[[ -n $(sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Storage\s*=" | tail -n 1 | egrep "^\s*Storage\s*=\s*persistent(\s|#|$)") ]] || (sed -i "s/^\s*Storage\s/## Storage/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nStorage=persistent\n/' /etc/systemd/journald.conf)


echo "[Manual]" 'Review /etc/systemd/journald.conf and verify logs are rotated according to site policy. The settings should be carefully understood as there are specific edge cases and prioritisation of parameters. The specific parameters for log rotation are: 
SystemMaxUse= 
SystemKeepFree= 
RuntimeMaxUse= 
RuntimeKeepFree= 
MaxFileSec=
The MaxFileSec is especially recommended to change besause of too long default 1 month.

Default:
  SystemMaxUse= 10% of the size of the respective file system, but not more than 4G
  SystemKeepFree= 15% of the size of the respective file system, but not more than 4G
  RuntimeMaxUse= 10% of the size of the respective file system, but not more than 4G
  RuntimeKeepFree= 15% of the size of the respective file system, but not more than 4G
  MaxFileSec=1month'
read -n 1 -p "Press Enter to continue..."


apt-get install systemd-journal-remote


echo "[Manual]" 'Edit the /etc/systemd/journal-upload.conf file and ensure the following lines are set per your environment: 
URL=192.168.50.42 
ServerKeyFile=/etc/ssl/private/journal-upload.pem 
ServerCertificateFile=/etc/ssl/certs/journal-upload.pem 
TrustedCertificateFile=/etc/ssl/ca/trusted.pem
Restart the service: 
# systemctl restart systemd-journal-upload'
read -n 1 -p "Press Enter to continue..."


systemctl --now enable systemd-journal-upload.service


read -p "Is this host designated central logging server (for journald service)?[y][N]" logserver;
if ! [[ "$logserver" =~ ^[[:space:]]*[yY] ]]; then systemctl --now disable systemd-journal-remote.socket; fi


find /var/log -type f ! -name wtmp ! -name btmp ! -name lastlog | xargs chmod g-wx,o-rwx
chmod ug-x,o-wx /var/log/lastlog 2>/dev/null
chmod ug-x,o-rwx /var/log/btmp 2>/dev/null
chmod ug-x,o-wx /var/log/wtmp 2>/dev/null


systemctl --now enable crond


chown root:root /etc/crontab
chmod og-rwx /etc/crontab


chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly


chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily


chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly


chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly


chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d


rm /etc/cron.deny 
rm /etc/at.deny 
touch /etc/cron.allow 
touch /etc/at.allow
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow 
chown root:root /etc/cron.allow 
chown root:root /etc/at.allow


read -p "Do you want to restrict cron access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/cron.allow; fi
read -p "Do you want to restrict at access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/at.allow; fi


control tcb-hash-prefix | egrep '(bcrypt_2b|bcrypt_2y|bcrypt_2a|yescrypt|scrypt|gost_yescrypt|sha512)' || control tcb-hash-prefix gost_yescrypt


touch /etc/passwdqc.conf;
grep -P '^\s*min=disabled,disabled,disabled,([89]|\d\d+),' /etc/passwdqc.conf || (sed -ri 's/^(\s*min=)/## \1/' /etc/passwdqc.conf; echo "min=disabled,disabled,disabled,8,8" >> /etc/passwdqc.conf);

PTF=/etc/pam.d;
for FN in system-auth-local-only; do 
  target_file="${PTF}/${FN}";
  grep -E '^\s*password\s+[^#]+\s+pam_passwdqc\.so\s+config=/etc/passwdqc\.conf' "$target_file" || sed -ri '0,/^\s*password\s+/s/^\s*password\s+/password        required        pam_passwdqc.so config=/etc/passwdqc.conf\n&/' "$target_file";
done;


touch /etc/security/faillock.conf;
grep -P '^\s*deny\s*=\s*[1-5](\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*deny\s*=)/## \1/' /etc/security/faillock.conf; echo "deny = 5" >> /etc/security/faillock.conf);
grep -P '^\s*unlock_time\s*=\s*(7[2-9]\d\d|[89]\d\d\d|\d{5,}|0)(\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*unlock_time\s*=)/## \1/' /etc/security/faillock.conf; echo "unlock_time = 7200" >> /etc/security/faillock.conf);

PTF=/etc/pam.d;
for FN in system-auth-local-only system-auth-use_first_pass-local-only; do 
  target_file="${PTF}/${FN}";
  sed -ri 's/^(\s*auth\s+[^#]+\s+pam_faillock\.so(\s+\S+)*)\s+deny=([06-9]|[0-9][0-9]+)((\s+\S+)*)$/\1\4/' "$target_file";
  sed -ri 's/^(\s*auth\s+[^#]+\s+pam_faillock\.so(\s+\S+)*)\s+unlock_time=([1-6][0-9]{3}|[0-9]{1,3})((\s+\S+)*)$/\1\4/' "$target_file";
  sed -ri 's/^(\s*auth\s+)[^#]+(\s+pam_tcb\.so\s.*)$/\1[success=1 default=bad]\2/' "$target_file";
  grep -E '^\s*auth\s+[^#]+\s+pam_faillock\.so\s+authfail' "$target_file" || sed -ri '0,/^\s*auth\s+[^#]+\s+pam_tcb\.so/s/^\s*auth\s+[^#]+\s+pam_tcb\.so.*$/&\nauth            [default=die]           pam_faillock.so authfail/' "$target_file";
  grep -E '^\s*auth\s+[^#]+\s+pam_faillock\.so\s+authsucc' "$target_file" || sed -ri '0,/^\s*auth\s+[^#]+\s+pam_faillock\.so\s+authfail/s/^^\s*auth\s+[^#]+\s+pam_faillock\.so\s+authfail.*$/&\nauth            sufficient              pam_faillock.so authsucc/' "$target_file";  
done;


PTF=/etc/pam.d/su; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_wheel\.so' $PTF) ]] && sed -ri '0,/^\s*auth\s+sufficient\s+pam_rootok\.so/s/^\s*auth\s+sufficient\s+pam_rootok\.so.*$/&\nauth           required        pam_wheel.so debug use_uid group=wheel/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_wheel\.so.*\s+use_uid(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_wheel\.so.*)$/\1 use_uid/' $PTF || true;


rm -f /etc/hosts.equiv


sed -i "s;^\(\s*PASS_MAX_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MAX_DAYS 90" >> /etc/login.defs


sed -i "s;^\(\s*PASS_MIN_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs


sed -i "s;^\(\s*PASS_WARN_AGE\s\);#\1;g" /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs


awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/^\/dev\/null$/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 }' /etc/passwd | while read user; do usermod -s /dev/null $user; done
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | while read -r username; do if passwd -S "$username" | egrep '^(Password set|Empty password)'; then usermod -L "$username"; fi; done


usermod -g 0 root


sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/bashrc
sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/profile /etc/profile.d/*.sh
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/bashrc || echo umask 077 >> /etc/bashrc
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/profile /etc/profile.d/*.sh || echo umask 077 >> /etc/profile.d/cis.sh


useradd -D -f 30


echo "[Manual]" 'Remove unnecessary aliases from the /etc/aliases file. Entries like uudecode and decode must be removed, as well as entries that refer to automated scripts.'
read -n 1 -p "Press Enter to continue..."


read -p "Enter timeout in seconds (default is 900):" idle_timeout;
if [ -z "$idle_timeout" ]; then idle_timeout=900; fi

sed -i 's/TMOUT=[0-9]\+/TMOUT='"${idle_timeout}"'/g' /etc/bashrc /etc/profile /etc/profile.d/*.sh
sed -i 's/\(if\s\+\[\s\+!\s\+"$(\s*readonly\s\+-p\s*|\s*egrep\s\+"declare\s\+-\[a-z\]+\s\+TMOUT="\s*)"\s\+\]\s*;\s*then\s\+\)\?readonly\s\+TMOUT\(=[0-9]\+\)\?\(\s*;\s*export\s\+TMOUT\s*\)\?\(\s*;\s*fi\)\?/if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'\3; fi/g' /etc/bashrc /etc/profile /etc/profile.d/*.sh
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/bashrc || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/bashrc
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/profile.d/couch.sh
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/bashrc || echo "export TMOUT" >> /etc/bashrc
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo "export TMOUT" >> /etc/profile.d/couch.sh
if [ -n "$ENV" ]; then \
sed -i 's/TMOUT=[0-9]\+/TMOUT='"${idle_timeout}"'/g' "$ENV";
sed -i 's/\(if\s\+\[\s\+!\s\+"$(\s*readonly\s\+-p\s*|\s*egrep\s\+"declare\s\+-\[a-z\]+\s\+TMOUT="\s*)"\s\+\]\s*;\s*then\s\+\)\?readonly\s\+TMOUT\(=[0-9]\+\)\?\(\s*;\s*export\s\+TMOUT\s*\)\?\(\s*;\s*fi\)\?/if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'\3; fi/g' "$ENV";
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" "$ENV" || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> "$ENV";
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" "$ENV" || echo "export TMOUT" >> "$ENV";
fi

idle_minutes=$(expr ${idle_timeout} / 60)
if [ -e "/bin/csh" -o -e "/bin/tcsh" ]; then egrep "^[^#]*set\s+-r\s+autologout\s+${idle_minutes}(\s|;|#|$)" /etc/csh.cshrc || echo "( set autologout | & grep 'read-only' ) || set -r autologout ${idle_minutes}" >> /etc/csh.cshrc; fi


chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net


echo "Authorized users only. All activity may be monitored and reported." > /etc/motd
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net


echo "Authorized users only. All activity may be monitored and reported." > /etc/motd
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net


echo "[Manual]" 'Investigate the results to ensure any discrepancies found are understood and support proper secure operation of the system with command:
rpm -Va --nomtime --nosize --nomd5 --nolinkto
Rerun the command until output is clean or risk is mitigated or accepted.'
read -n 1 -p "Press Enter to continue..."


/bin/chmod u-x,go-wx /etc/passwd


/bin/chmod u-wx,go-rwx /etc/shadow


/bin/chmod u-wx,go-rwx /etc/gshadow


/bin/chmod u-x,go-wx /etc/group


/bin/chown root:root /etc/passwd


/bin/chown root:root /etc/shadow


/bin/chown root:root /etc/gshadow


/bin/chown root:root /etc/group


chown root:root /etc/passwd- 
chmod u-x,go-wx /etc/passwd-


chown root:root /etc/shadow-
chmod ugo-rwx /etc/shadow-


chown root:root /etc/group-
chmod u-x,go-wx /etc/group-


chown root:root /etc/gshadow-
chmod ugo-rwx /etc/gshadow-


p=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f -perm -0002 2>/dev/null);
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chmod o-w "$each"; done;
IFS=$couch_ifs


p=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -nouser 2>/dev/null);
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chown root "$each"; chmod go-rwx "$each"; done;
IFS=$couch_ifs


p=$(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -nogroup 2>/dev/null);
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chown :root "$each"; chmod go-rwx "$each"; done
IFS=$couch_ifs


echo "[Manual]" 'Ensure that no rogue set-UID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the the integrity of these binaries as described below: 
# rpm -V `rpm -qf /usr/bin/sudo`
.......T /usr/bin/sudo
SM5....T /usr/bin/sudoedit'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that no rogue set-GID programs have been introduced into the system.
Audit section and confirm the the integrity of these binaries as described below: 
# /bin/rpm -V `/bin/rpm -qf sudo`'
read -n 1 -p "Press Enter to continue..."


cat /etc/shadow | awk -F: '( $2 == "" ) {system("passwd -l "$1); print "User "$1" has been locked because of empty password"}'


sed -i 's/^+/#+/g' /etc/passwd


sed -i 's/^+/#+/g' /etc/shadow


sed -i 's/^+/#+/g' /etc/group


echo "[Manual]" 'Delete any other entries that are displayed except root:
# awk -F: '\''($3 == 0) { print $1 }'\'' /etc/passwd'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Correct or justify any items discovered with the script:
#!/bin/bash
RPCV="$(sudo -Hiu root env | grep '\''^PATH'\'' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root'\''s path contains a empty directory (::)"
echo "$RPCV" | grep -q ":$" && echo "root'\''s path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do 
if [ -d "$x" ]; then 
ls -ldH "$x" | awk '\''$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'\''
else echo "$x is not a directory"
fi
done'
read -n 1 -p "Press Enter to continue..."


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/dev/null" && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do chmod g-w "$dir"; chmod o-rwx "$dir"; done


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/dev/null" && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do for file in `ls -d "$dir"/.[A-Za-z0-9]* 2>/dev/null`; do chmod -R go-w "$file"; done; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then chmod go-rwx "$dir/.netrc";fi; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.rhosts" -a -f "$dir/.rhosts" ]; then mv "$dir/.rhosts" "$dir/.rhosts.old"; fi; done


echo "[Manual]" 'Analyze the output of the script and perform the appropriate action to correct any discrepancies found:
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:[^:]*:$i:" /etc/group
if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi
done'
read -n 1 -p "Press Enter to continue..."


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then mkdir "$dir"; chown $user "$dir"; chmod g-w "$dir"; chmod o-rwx "$dir"; fi; done


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then chown $user "$dir"; fi; fi; done


q=0
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read -r x ; do [ -z "${x}" ] && break; set -- $x; if [ "$1" -gt 1 ]; then q=1; users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs); echo "Duplicate UID ($2): ${users}"; fi; done
if [ "$q" -eq 1 ]; then echo "Change UID or remove excess users"; read -p "Next" a; fi


q=0
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; grps=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`; echo "Duplicate GID ($2): ${grps}"; fi; done
if [ $q -eq 1 ]; then echo "Change GID or remove excess groups"; read -p "Next" a; fi


q=0
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`; echo "Duplicate User Name ($2): ${uids}"; fi; done
if [ $q -eq 1 ]; then echo "Change username or remove excess users"; read -p "Next" a; fi


q=0
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; gids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`; echo "Duplicate Group Name ($2): ${gids}"; fi; done
if [ $q -eq 1 ]; then echo "Change group name or remove excess groups"; read -p "Next" a; fi


couch_ifs="$IFS";IFS=$'\n';
for dir in $(awk -F: '{ print $6 }' /etc/passwd); do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then read -p "Do you want to remove $dir/.netrc file?[YES][no]" co_ans; if [[ "$co_ans" =~ [Nn][oO]? ]]; then chmod go-rwx "$dir/.netrc"; else rm -f "$dir/.netrc"; fi; fi; done
IFS="$couch_ifs"


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then mv "$dir/.forward" "$dir/.forward.old";fi; done


echo "[Manual]" 'Remove all users from the shadow group, and change the primary group of any users with shadow as their primary group.'
read -n 1 -p "Press Enter to continue..."


sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd


chown root:shadow /etc/tcb
chmod g-w,o-rwx /etc/tcb


find -L /etc/tcb -mindepth 1 -perm /027 -print 2>/dev/null | xargs -d$'\n' -I {} chmod g-w,o-rwx '{}'
find -L /etc/tcb -mindepth 1 ! -group auth -print 2>/dev/null | xargs -d$'\n' -I {} chown :auth '{}'


sed -i 's/^\(\s*kernel\.dmesg_restrict\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.dmesg_restrict\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.dmesg_restrict=1


sed -i 's/^\(\s*kernel\.kptr_restrict\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.kptr_restrict\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kptr_restrict=2


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+init_on_alloc=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+init_on_alloc=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+init_on_alloc=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1init_on_alloc=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='init_on_alloc=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+init_on_alloc=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+init_on_alloc=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+init_on_alloc=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1init_on_alloc=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='init_on_alloc=1'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


if [[ -n $(egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2) ]]; then egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | egrep '^[^#]*\s+slab_nomerge' || (sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+slab_nomerge)+(\s|\"|')/\2/g" /etc/sysconfig/grub2; sed -ri "s;^(GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1slab_nomerge \2;g" /etc/sysconfig/grub2); else echo "GRUB_CMDLINE_LINUX_DEFAULT='slab_nomerge'" >> /etc/sysconfig/grub2; fi;
if [[ -n $(egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2) ]]; then egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | egrep '^[^#]*\s+slab_nomerge' || (sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+slab_nomerge)+(\s|\"|')/\2/g" /etc/sysconfig/grub2; ; sed -ri "s;^(GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1slab_nomerge \2;g" /etc/sysconfig/grub2); else echo "GRUB_CMDLINE_LINUX='slab_nomerge'" >> /etc/sysconfig/grub2; fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu=force(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+iommu=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1iommu=force \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='iommu=force'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu=force(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+iommu=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1iommu=force \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='iommu=force'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu\.strict=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu\.strict=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+iommu\.strict=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1iommu.strict=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='iommu.strict=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu\.strict=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu\.strict=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+iommu\.strict=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1iommu.strict=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='iommu.strict=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu\.passthrough=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu\.passthrough=0(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+iommu\.passthrough=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1iommu.passthrough=0 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='iommu.passthrough=0'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+iommu\.passthrough=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+iommu\.passthrough=0(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+iommu\.passthrough=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1iommu.passthrough=0 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='iommu.passthrough=0'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+randomize_kstack_offset=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+randomize_kstack_offset=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+randomize_kstack_offset=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1randomize_kstack_offset=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='randomize_kstack_offset=1'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+randomize_kstack_offset=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+randomize_kstack_offset=1(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+randomize_kstack_offset=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1randomize_kstack_offset=1 \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='randomize_kstack_offset=1'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+mitigations=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+mitigations=auto,nosmt(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+mitigations=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1mitigations=auto,nosmt \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='mitigations=auto,nosmt'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+mitigations=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+mitigations=auto,nosmt(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+mitigations=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1mitigations=auto,nosmt \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='mitigations=auto,nosmt'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*net\.core\.bpf_jit_harden\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*net\.core\.bpf_jit_hardens*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'net.core.bpf_jit_harden = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w net.core.bpf_jit_harden=2


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+vsyscall=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+vsyscall=none(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+vsyscall=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1vsyscall=none \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='vsyscall=none'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+vsyscall=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+vsyscall=none(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+vsyscall=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1vsyscall=none \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='vsyscall=none'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.perf_event_paranoid\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.perf_event_paranoid\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.perf_event_paranoid = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.perf_event_paranoid=3


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+debugfs=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+debugfs=no-mount(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+debugfs=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1debugfs=no-mount \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='debugfs=no-mount'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+debugfs=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+debugfs=no-mount(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+debugfs=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1debugfs=no-mount \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='debugfs=no-mount'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.kexec_load_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.kexec_load_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kexec_load_disabled=1


sed -i 's/^\(\s*user\.max_user_namespaces\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*user\.max_user_namespaces\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'user.max_user_namespaces = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w user.max_user_namespaces=0


sed -i 's/^\(\s*kernel\.unprivileged_bpf_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.unprivileged_bpf_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.unprivileged_bpf_disabled=1


sed -i 's/^\(\s*vm\.unprivileged_userfaultfd\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*vm\.unprivileged_userfaultfd\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'vm.unprivileged_userfaultfd = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w vm.unprivileged_userfaultfd=0


sed -i 's/^\(\s*dev\.tty\.ldisc_autoload\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*dev\.tty\.ldisc_autoload\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'dev.tty.ldisc_autoload = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w dev.tty.ldisc_autoload=0


if egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+tsx=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+tsx=off(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX_DEFAULT\s*=/s/(\s+tsx=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX_DEFAULT=[\"'])(.*)$;\1tsx=off \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX_DEFAULT='tsx=off'" >> /etc/sysconfig/grub2; 
fi;
if egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2; then   
  egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/sysconfig/grub2 | while read -r line; do
    if [[ -n $(echo "$line" | egrep '^[^#]*\s+tsx=') ]] && [[ -z $(echo "$line" | egrep "^[^#]*\s+tsx=off(\s|\"|')") ]]; then printf '%s\n' '0?^\s*GRUB_CMDLINE_LINUX\s*=?a' "## $line" . x | ex /etc/sysconfig/grub2; fi;
    done;
  sed -ri "/^\s*GRUB_CMDLINE_LINUX\s*=/s/(\s+tsx=[^\s\"']+)+(\s|\"|')/\2/g" /etc/sysconfig/grub2;
  sed -ri "s;^(\s*GRUB_CMDLINE_LINUX=[\"'])(.*)$;\1tsx=off \2;" /etc/sysconfig/grub2;
else 
  echo "GRUB_CMDLINE_LINUX='tsx=off'" >> /etc/sysconfig/grub2; 
fi;
grub-mkconfig -o /boot/grub/grub.cfg; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -ri 's/^(\s*vm\.mmap_min_addr\s*=\s*[1-3]?[0-9]{1,3})/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*vm\.mmap_min_addr\s*=\s*([4-9][0-9]{3}|[0-9]{5,})\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || (echo 'vm.mmap_min_addr = 4096' >> /etc/sysctl.d/FSTEC.conf; sysctl -w vm.mmap_min_addr=4096)


sed -i 's/^\(\s*kernel\.yama\.ptrace_scope\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.yama\.ptrace_scope\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.yama.ptrace_scope = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.yama.ptrace_scope=3


sed -i 's/^\(\s*fs\.protected_symlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_symlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_symlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_symlinks=1


sed -i 's/^\(\s*fs\.protected_hardlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_hardlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_hardlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_hardlinks=1


sed -i 's/^\(\s*fs\.protected_fifos\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_fifos\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_fifos = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_fifos=2


sed -i 's/^\(\s*fs\.protected_regular\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_regular\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/net/sysctl.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_regular = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_regular=2


df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f -perm -4000 -print | xargs -d$'\n' -I {} chmod go-w "{}"


df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f -perm -2000 -print | xargs -d$'\n' -I {} chmod o-w "{}"


ROOT_PATH="$(sudo -Hiu root env | grep '^PATH=' | cut -d= -f2)"; IFS=':' read -ra DIRS <<< "$ROOT_PATH"; for dir in "${DIRS[@]}"; do find -L "$dir" -type f \( -perm /0111 -a -perm /0022 \) -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-w '{}'; done


find -L /lib /lib64 -type f -perm /0022 -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-w '{}'


chmod -R og-w /etc/init.d/ /etc/rc.d/ /etc/rc0.d/ /etc/rc1.d/ /etc/rc2.d/ /etc/rc3.d/ /etc/rc4.d/ /etc/rc5.d/ /etc/rc6.d/ /etc/rcS.d/ /etc/inittab 2>/dev/null || true;
chown -R root /etc/init.d/ /etc/rc.d/ /etc/rc0.d/ /etc/rc1.d/ /etc/rc2.d/ /etc/rc3.d/ /etc/rc4.d/ /etc/rc5.d/ /etc/rc6.d/ /etc/rcS.d/ /etc/inittab 2>/dev/null || true;


find -L /etc/systemd/system.control/ /run/systemd/system.control/ /run/systemd/transient/ /run/systemd/generator.early/ /etc/systemd/system/ /etc/systemd/system.attached/ /run/systemd/system/ /run/systemd/system.attached/ /run/systemd/generator/ /usr/local/lib/systemd/system /usr/lib/systemd/system/ /run/systemd/generator.late/ /etc/xdg/systemd/user/ /etc/systemd/user/ /run/systemd/user/ /usr/local/share/systemd/user/ /usr/share/systemd/user/ /usr/local/lib/systemd/user/ /usr/lib/systemd/user/ -perm /0022 \( ! -type c -a ! -type b \) 2>/dev/null | xargs -d$'\n' -I {} chmod go-w "{}"
find -L /etc/systemd/system.control/ /run/systemd/system.control/ /run/systemd/transient/ /run/systemd/generator.early/ /etc/systemd/system/ /etc/systemd/system.attached/ /run/systemd/system/ /run/systemd/system.attached/ /run/systemd/generator/ /usr/local/lib/systemd/system /usr/lib/systemd/system/ /run/systemd/generator.late/ /etc/xdg/systemd/user/ /etc/systemd/user/ /run/systemd/user/ /usr/local/share/systemd/user/ /usr/share/systemd/user/ /usr/local/lib/systemd/user/ /usr/lib/systemd/user/ ! -user root \( ! -type c -a ! -type b \) 2>/dev/null | xargs -d$'\n' -I {} chown root "{}"


SECURE_PATH="$(sudo env | grep '^PATH=' | cut -d= -f2)";
IFS=':' read -ra DIRS <<< "$SECURE_PATH";
for dir in "${DIRS[@]}"; do
  find -L "$dir" -type f -perm /0111 -perm /0022 | xargs -d$'\n' -I {} chmod go-w '{}';
  find -L "$dir" -type f -perm /0111 ! -user root | xargs -d$'\n' -I {} chown root '{}';
  find -L "$dir" -type d -perm /0022 | xargs -d$'\n' -I {} chmod go-w '{}';
  find -L "$dir" -type d ! -user root | xargs -d$'\n' -I {} chown root '{}';
done


find /proc -name exe -print 2>/dev/null | xargs readlink -e | sort -u | while read -r procfile; do chmod go-w "$procfile" 2>/dev/null; ldd "$procfile" 2>/dev/null | sed -r 's#^(.*=>)?\s+([^(]*)\s+\(.*$#\2#' | while read -r filename; do [[ -e "$filename" ]] && chmod go-w "$filename" 2>/dev/null; done; done


find -L /var/spool/cron/ -type f -perm /0022 -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-w '{}';
find -L /var/spool/cron/ -type d -perm /0022 ! \( -name cron -a -perm -1000 -a ! -perm -0002 \) -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-w '{}';


for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null  | grep -v '^#' | awk '{$1=$2=$3=$4=$5=""; print $0}' | grep -oE '("[^"]+"|[^[:space:]"'\'']+)' | tr -d '"' | while read -r line; do filename=$(which --skip-alias --skip-functions -- "$line" 2>/dev/null); [[ -x "$filename" ]] && chmod go-w "$filename"; done; done


echo "[Manual]" 'Review the /etc/sudoers configuration file and comment out lines which provide excessive access if any.'
read -n 1 -p "Press Enter to continue..."



