#!/usr/bin/env bash


echo "[Manual]" 'Configure /etc/fstab with separate partition for /tmp. Example:
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
OR
Run the following commands to enable systemd /tmp mounting.
Run the following command to create the file /etc/systemd/system/tmp.mount if it doesn'\''t exist:
# [ ! -f /etc/systemd/system/tmp.mount ] && cp -v /usr/lib/systemd/system/tmp.mount /etc/systemd/system/
Edit /etc/systemd/system/tmp.mount to configure the /tmp mount:
[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid
Run the following command to reload the systemd daemon:
# systemctl daemon-reload
Run the following command to unmask and start tmp.mount:
# systemctl unmask tmp.mount
# systemctl enable tmp.mount

/tmp utilizing tmpfs can be resized using the size={size} parameter on the Options line on the tmp.mount file'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nodev" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nodev/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nodev" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nosuid" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nosuid/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nosuid" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*noexec" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,noexec/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=noexec" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]/var/tmp[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var/tmp


grep "[[:space:]]/var/tmp[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /var/tmp


grep "[[:space:]]/var/tmp[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || sed -i 's"^\(.*\s/var/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /var/tmp


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log/audit. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /home . 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]/home[[:space:]]" /etc/fstab | grep nodev  | grep ^[^#] || sed -i 's"^\(.*\s/home\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /home


grep "/media" /etc/fstab  | grep ^[^#] | grep nodev || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nodev $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep noexec || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,noexec $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep nosuid || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nosuid $each; done


grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep nodev  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /dev/shm


grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep nosuid  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /dev/shm


grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep "[[:space:]]/dev/shm[[:space:]]" /etc/fstab | grep noexec  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /dev/shm


df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t


modprobe -r cramfs 2>&1 | grep builtin && (echo "Module cramfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* cramfs .*\)"#\1"g' /etc/modprobe.d/$each; done;echo install cramfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r freevxfs 2>&1 | grep builtin && (echo "Module freevxfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* freevxfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install freevxfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r jffs2 2>&1 | grep builtin && (echo "Module jffs2 is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* jffs2 .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install jffs2 /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfs 2>&1 | grep builtin && (echo "Module hfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfsplus 2>&1 | grep builtin && (echo "Module hfsplus is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfsplus .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfsplus /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r squashfs 2>&1 | grep builtin && (echo "Module squashfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* squashfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install squashfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r udf 2>&1 | grep builtin && (echo "Module udf is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* udf .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install udf /bin/true >> /etc/modprobe.d/disabled_modules.conf)


if [[ -z $(grep -E -i '\svfat\s' /etc/fstab) ]]; then modprobe -r vfat 2>&1 | grep builtin && (echo "Module vfat is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* vfat .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install vfat /bin/true >> /etc/modprobe.d/disabled_modules.conf); else echo "Vfat is used and must be disabled manually if is not required"; read -p "Next" a; fi


systemctl disable autofs


echo "[Manual]" 'Update your package manager GPG keys in accordance with site policy.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/(^|\s|;)gpgcheck\s*=\s*[023456789]+($|\s|;)/\1gpgcheck=1\2/g' /etc/yum.conf
sed -ri 's/(^|\s|;)gpgcheck\s*=\s*[023456789]+($|\s|;)/\1gpgcheck=1\2/g' /etc/yum.repos.d/*.repo
egrep "^\s*gpgcheck\s*=\s*1\s*(#|$)" /etc/yum.conf || echo gpgcheck=1 >> /etc/yum.conf


yum check-update --security | grep "No packages needed for security" || (read -p "Do you want to upgrade packages with security problems now?[yes][NO]" update; if [ "$update" == "yes" ]; then yum update --security; fi )


echo "[Manual]" 'Address unexpected discrepancies identified in the audit step:
# rpm -qVa | awk '\''$2 != "c" { print $0}'\'''
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure your package manager repositories according to site policy.'
read -n 1 -p "Press Enter to continue..."


yum -y install aide
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'


(crontab -u root -l 2>/dev/null | egrep -i "^[0-9]+\s+[0-9]+\s+\*\s+\*\s+\*\s+/usr/sbin/aide.*\s+--check") || (crontab -u root -l 2>/dev/null; echo "0 5 * * * /usr/sbin/aide --check") | sort - | uniq - | crontab -u root -


yum -y install libselinux


sed -i 's/selinux=0//g' /etc/default/grub
sed -i 's/enforcing=0//g' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg; chown root:root /boot/grub2/grub.cfg; chmod og-rwx /boot/grub2/grub.cfg


egrep "^\s*SELINUX=enforcing" /etc/selinux/config || (sed -i 's/^\s*SELINUX=/#SELINUX=/g' /etc/selinux/config; echo SELINUX=enforcing >> /etc/selinux/config)


egrep "^\s*SELINUXTYPE=targeted" /etc/selinux/config || (sed -i 's/^\s*SELINUXTYPE=/#SELINUXTYPE=/g' /etc/selinux/config; echo SELINUXTYPE=targeted >> /etc/selinux/config)


yum erase setroubleshoot


yum erase mcstrans


ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ":" " " | awk '{ print $NF }' && (echo "Investigate any unconfined daemons. They may need to have an existing security context assigned to them or a policy built for them."; read -p "Next" a)


chown root:root /boot/grub2/grub.cfg
chown root:root /boot/grub2/user.cfg


chmod og-rwx /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/user.cfg


grub2-setpassword
grub2-mkconfig -o /boot/grub2/grub.cfg; chown root:root /boot/grub2/grub.cfg; chmod og-rwx /boot/grub2/grub.cfg


egrep 'ExecStart\s*=\s*-/bin/sh\s+-c\s+"(/usr)?/sbin/sulogin;\s*/usr/bin/systemctl\s+--fail\s+--no-block\s+default"' /usr/lib/systemd/system/rescue.service || ( sed -i "s;\(^\s*ExecStart.*/sbin/sulogin\);#\1;g" /usr/lib/systemd/system/rescue.service; echo 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/rescue.service)
egrep 'ExecStart\s*=\s*-/bin/sh\s+-c\s+"(/usr)?/sbin/sulogin;\s*/usr/bin/systemctl\s+--fail\s+--no-block\s+default"' /usr/lib/systemd/system/emergency.service || (sed -i "s;\(^\s*ExecStart.*/sbin/sulogin\);#\1;g" /usr/lib/systemd/system/emergency.service; echo 'ExecStart=-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/emergency.service)


if [[ -n $(sysctl kernel.core_pattern | grep 'systemd-coredump') ]]; then 
  sed -ri 's/^(\s*Storage\s*=)/## \1/i' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /run/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf.d/*.conf;
  echo 'Storage=none' >> /etc/systemd/coredump.conf;
  sed -ri 's/^(\s*ProcessSizeMax\s*=)/## \1/i' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf /run/systemd/coredump.conf.d/*.conf /usr/lib/systemd/coredump.conf.d/*.conf;
  echo 'ProcessSizeMax=0' >> /etc/systemd/coredump.conf;
else 
  sed -ri "s;^(\s*\*\s+hard\s+core\s+[1-9]);## \1;" /etc/security/limits.conf /etc/security/limits.d/*;
  [[ -n $(grep -E "^\s*\*\s+hard\s+core\s+0(\s|$)" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null) ]] || echo '* hard core 0' >> /etc/security/limits.conf;
  sed -i 's/^\(\s*fs\.suid_dumpable\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null;
  [[ -n $(grep -E "^\s*fs\.suid_dumpable\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/44-couch.conf;
  sysctl -w fs.suid_dumpable=0;
fi


echo "[Manual]" 'On 32 bit systems install a kernel with PAE support, no installation is required on 64 bit systems. If necessary configure your bootloader to load the new kernel and reboot the system. 
You may need to enable NX or XD support in your bios. 
Notes: Ensure your system supports the XD or NX bit and has PAE support before implementing this recommendation as this may prevent it from booting if these are not supported by your hardware. To check whether or not the CPU supports the nx feature, check /proc/cpuinfo for the nx flag:
# cat proc/cpuinfo | grep nx | uniq'
read -n 1 -p "Press Enter to continue..."


sed -i 's/^\(\s*kernel\.randomize_va_space\s*=\s*[013456789]\)/#\1/' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*kernel\.randomize_va_space\s*=\s*2(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/44-couch.conf
sysctl -w kernel.randomize_va_space=2


prelink -ua
yum remove prelink


echo "[Manual]" 'Obtain and install the latest update of the RHEL software.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run the following command to connect to the Red Hat Subscription Manager: 
# subscription-manager register'
read -n 1 -p "Press Enter to continue..."


chkconfig rhnsd off


yum erase telnet-server


yum erase telnet


yum erase rsh-server


yum erase rsh


yum erase ypbind


yum erase ypserv


yum erase tftp


yum erase tftp-server


yum erase talk


yum erase talk-server


yum erase rsync


yum erase xinetd


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
# service --status-all'
read -n 1 -p "Press Enter to continue..."


chmod go-rwx /usr/bin/gcc
chmod go-rwx /usr/bin/cc


sed -i 's/^\s*umask /#umask /g' /etc/sysconfig/init
echo umask 027 >> /etc/sysconfig/init


yum remove xorg-x11*


systemctl disable avahi-daemon


systemctl disable cups


systemctl disable dhcpd


read -p "Do you want to chrony or ntp for time synchronization?[CHRONY][ntp]" timeserv; if [ "$timeserv" == "ntp" ]; then yum -y install ntp; systemctl enable ntpd; systemctl start ntpd; else yum -y install chrony; systemctl enable chronyd; systemctl start chronyd; fi


if [[ -n $(systemctl is-enabled ntpd 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^\s*server\s*$ntp_server" /etc/ntp.conf || echo "server $ntp_server" >> /etc/ntp.conf; egrep "^\s*restrict\s*-4\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -4 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; egrep "^\s*restrict\s*-6\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -6 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; grep ^OPTIONS=\" /etc/sysconfig/ntpd && sed -i '/^OPTIONS=/s/"$/ -u ntp:ntp"/g' /etc/sysconfig/ntpd; grep ^OPTIONS=\" /etc/sysconfig/ntpd || echo OPTIONS=\"-u ntp:ntp\" >> /etc/sysconfig/ntpd; else echo "Not applicable - ntpd.service is not enabled"; fi


if [[ -n $(systemctl is-enabled chronyd 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^\s*server\s+$ntp_server" /etc/chrony.conf || echo "server $ntp_server" >> /etc/chrony.conf; grep ^OPTIONS=\" /etc/sysconfig/chronyd && sed -i '/^OPTIONS=/s/"$/ -u chrony"/g' /etc/sysconfig/chronyd; egrep ^OPTIONS=\" /etc/sysconfig/chronyd || echo OPTIONS=\"-u chrony\" >> /etc/sysconfig/chronyd; else echo "Not applicable - chronyd.service is not enabled"; fi


systemctl disable slapd


systemctl disable nfs
systemctl disable nfs-server
systemctl disable rpcbind


echo "[Manual]" 'All export NFS necessary must be with the respective
restrictions of writing, and limited to the IPs of the authorized
customers in the etc/exports:
/directory archive/client1(ro), client2(rw)'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]nfs[[:space:]]" /etc/fstab | grep ^[^#] | grep -v "nosuid" && sed -i 's;^\(.*\snfs\s\+[a-zA-Z0-9,]\+\)\(\s\+.*\)$;\1,nosuid\2;g' /etc/fstab


yum erase bind


yum erase vsftpd


yum erase httpd


yum erase dovecot


yum erase samba


yum erase squid


yum erase net-snmp


sed -i 's/^\s*\(r[ow]community\s\+public\)/#\1/g' /etc/snmp/*.conf
sed -i 's/^\s*\(r[ow]community\s\+private\)/#\1/g' /etc/snmp/*.conf


sed -i 's/^\s*inet_interfaces/#inet_interfaces/g' /etc/postfix/main.cf
echo inet_interfaces = loopback-only >> /etc/postfix/main.cf
systemctl restart postfix


sed -i "s/^\(\s*net\.ipv4\.ip_forward\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.ip_forward\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.route.flush=1
sed -i "s/^\(\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.forwarding=0
/sbin/sysctl -w net.ipv6.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 
/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0 
/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.secure_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.secure_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.secure_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.secure_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0 
/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.log_martians\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.log_martians\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.log_martians=1 
/sbin/sysctl -w net.ipv4.conf.default.log_martians=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1 
/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
/sbin/sysctl -w net.ipv4.route.flush=1


sed -i "s/^\(\s*net\.ipv4\.tcp_syncookies\s*=\s*[023456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.tcp_syncookies\s*=\s*1(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.tcp_syncookies=1
/sbin/sysctl -w net.ipv4.route.flush=1


nmcli nm wifi off 2>/dev/null || nmcli radio wifi off
for each in `ifconfig | egrep "(wlan|wlp)" | cut -f1 -d" "`; do ip link $each down; done


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_ra\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_ra\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_ra\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_ra\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.route.flush=1


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_redirects\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_redirects\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv6.route.flush=1


grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | grep "ipv6.disable=1" || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1ipv6.disable=1 \2;g' /etc/default/grub
grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"ipv6.disable=1\" >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg; chown root:root /boot/grub2/grub.cfg; chmod og-rwx /boot/grub2/grub.cfg


yum -y install tcp_wrappers


echo "[Manual]" 'Create /etc/hosts.allow:
# echo "ALL: <net>/<mask>, <net>/<mask>, …" >/etc/hosts.allow
where each <net>/<mask> combination  (for example, "192.168.1.0/255.255.255.0") represents one network block in use by your organization that requires access to this system.'
read -n 1 -p "Press Enter to continue..."


[ -e /etc/hosts.allow ] || > /etc/hosts.allow
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow


read -p 'Do you want to configure /etc/hosts.deny now ("ALL: ALL" will be added to hosts.deny and access to host may be lost if /etc/hosts.allow is not configured properly)?[yes][NO]' update; if [ "$update" == "yes" ]; then echo "ALL: ALL" >> /etc/hosts.deny; fi


chown root:root /etc/hosts.deny 
chmod u-x,go-wx /etc/hosts.deny


modprobe -r dccp 2>&1 | grep builtin && (echo "Module dccp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* dccp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install dccp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r sctp 2>&1 | grep builtin && (echo "Module sctp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* sctp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install sctp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r rds 2>&1 | grep builtin && (echo "Module rds is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* rds .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install rds /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r tipc 2>&1 | grep builtin && (echo "Module tipc is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* tipc .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install tipc /bin/true >> /etc/modprobe.d/disabled_modules.conf)


echo "[Manual]" 'The DNS servers listed in
/etc/resolv.conf file must be those managed locally by the internal administrators.'
read -n 1 -p "Press Enter to continue..."


yum -y install rsyslog


systemctl enable rsyslog


echo "[Manual]" 'Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment.
Example:
auth,user.* /var/log/messages kern.* /var/log/kern.log
daemon.* /var/log/daemon.log syslog.* /var/log/syslog lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log  # Execute the following command to restart rsyslogd # pkill -HUP rsyslogd'
read -n 1 -p "Press Enter to continue..."


egrep "^\\\$FileCreateMode\s+0?[0246][04]0" /etc/rsyslog.conf /etc/rsyslog.d/* || echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
pkill -HUP rsyslogd


for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | grep -Ei '(^|\s)file=".+"'); do if [[ "$each" =~ ^[^#]*[Ff]ile=\"(.*)\" ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done
for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "^.+\..+\s+-?/.+$" | grep -v -i IncludeConfig); do if [[ "$each" =~ ^-?(/[^:;]+)[^:]*$ ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done


grep "^\*\.\*[[:space:]]*@@" /etc/rsyslog.conf || (read -p "Enter IP address or domain name of central logging server for syslog:" logserv; echo "*.* @@$logserv" >> /etc/rsyslog.conf; pkill -HUP rsyslogd)


read -p "Is this host designated central logging server?[y][N]" logserver;
if [[ "$logserver" != "y" && "$logserver" != "Y" ]]; then sed -i "s;^\s*\(\$ModLoad\s\+\(imtcp\|/[^#]*imtcp\)\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; sed -i "s;^\s*\(\$InputTCPServerRun\s\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; systemctl restart rsyslog; fi


sed -i 's/^\s*max_log_file\s*=\s*.*$/max_log_file = 50/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file\s*=\s*50\s*$" /etc/audit/auditd.conf || echo "max_log_file = 50" >> /etc/audit/auditd.conf


sed -i 's/^\s*space_left_action\s*=.*$/space_left_action = email/g' /etc/audit/auditd.conf
egrep "^\s*space_left_action\s*=\s*email\s*$" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i 's/^\s*action_mail_acct\s*=.*$/action_mail_acct = root/g' /etc/audit/auditd.conf
egrep "^\s*action_mail_acct\s*=\s*root\s*$" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf


sed -i 's/^\s*max_log_file_action\s*=.*$/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file_action\s*=\s*keep_logs\s*$" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf


systemctl enable auditd
systemctl start auditd


egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub && sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1audit=1 \2;g' /etc/default/grub
egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"audit=1\" >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg; chown root:root /boot/grub2/grub.cfg; chmod og-rwx /boot/grub2/grub.cfg


lscpu 2>&1 | grep "Architecture" | grep 64 || ( egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/group\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/passwd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/gshadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/shadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/security/opasswd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network-scripts/\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*exit,always\s*-F\s*arch=b64\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network-scripts/\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/selinux/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/usr/share/selinux/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/share/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/log/lastlog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/lastlog -p wa -k logins " /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/run/faillock/\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/run/faillock/ -p wa -k logins" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/run/utmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/run/utmp -p wa -k session" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/wtmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/wtmp -p wa -k session" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/btmp\s*-p\s*wa\s*-k\s*session" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/btmp -p wa -k session" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while read -r line; do egrep "^-a\s*always,exit\s*-F\s*path=${line}\s*-F\s*perm=x\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*privileged" /etc/audit/rules.d/audit.rules || (audit_num=$(cat /etc/audit/rules.d/audit.rules | wc -l); sed -i "${audit_num}i-a always,exit -F path=${line} -F perm=x -F auid\>=1000 -F auid!=4294967295 -k privileged" /etc/audit/rules.d/audit.rules); done;
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi;


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/sudoers\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/sudoers.d/\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers.d/ -p wa -k scope" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/log/sudo.log\s*-p\s*wa\s*-k\s*actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/sudo.log -p wa -k actions" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


for file in `find /var/log -type f`; do \
if [[ "$file" =~ ^/var/log/journal/ ]]; then \
if [[ $(egrep "^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs;-w /var/log/journal -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/journal -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
elif [[ "$file" =~ ^.*/postgresql-[^/]*\.log$ ]]; then \
pref=$(dirname "$file"); if [[ $(egrep "^-w\s+$pref\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^-w\s+$pref\s[^#]*-k\s+access-logs;-w $pref -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $pref -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
elif ! [[ "$file" =~ ^.*([0-9]|old|back|gz)$ ]]; then \
if [[ $(egrep "^-w\s+$file\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^-w\s+$file\s[^#]*-k\s+access-logs;-w $file -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi;
fi; done
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


for file in `find /etc/pam.d -type f`; do egrep "^-w\s*$file\s*-p\s*wa\s*-k\s*change-auth-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p wa -k change-auth-cfg" /etc/audit/rules.d/audit.rules); done
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/audit/auditd.conf\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/auditd.conf -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/rules.d/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/rules.d/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


grep "^\s*[^#]" /etc/audit/rules.d/audit.rules | tail -1 | egrep "^-e\s+2" || (sed -i "s;^-e\s\+;#-e ;g" /etc/audit/rules.d/audit.rules; echo "-e 2" >> /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


echo "[Manual]" 'Edit the /etc/logrotate.d/syslog file to include appropriate system logs:
/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {'
read -n 1 -p "Press Enter to continue..."


for f in `ls /etc/logrotate.conf /etc/logrotate.d/*`; do i=0; rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $line | egrep -i "/utmp|/wtmp|/btmp" && i=1; if [ "$i" == "0" ]; then echo $line | grep "{" && k=0; echo $line | grep "}" && if [ "$k" == "0" ]; then echo "create 0600 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 600 ;' >> $f.couch_tmp; else echo $line | grep "{" && k=0; echo $line | grep "}" && i=0&& if [ "$k" == "0" ]; then echo "create 0640 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 640 ;' >> $f.couch_tmp; fi; done < $f; yes | cp $f.couch_tmp $f; rm --interactive=never $f.couch_tmp; done


egrep "^Defaults\s+syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" /etc/sudoers || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


find /var/log -type f ! -name wtmp ! -name btmp ! -name lastlog | xargs chmod g-wx,o-rwx
chmod ug-x,o-wx /var/log/lastlog 2>/dev/null
chmod ug-x,o-rwx /var/log/btmp 2>/dev/null
chmod ug-x,o-wx /var/log/wtmp 2>/dev/null


systemctl enable crond


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


/bin/rm /etc/cron.deny
/bin/rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow


read -p "Do you want to restrict cron access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/cron.allow; fi
read -p "Do you want to restrict at access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/at.allow; fi


for FN in system-auth password-auth; do target_file="/etc/pam.d/${FN}"; sed -ri '/^\s*password\s+(\S+\s+)+pam_unix\.so/s/(\ssha[0-9]+|yescrypt)(\s|$)/\2/g' "$target_file"; sed -ri 's/^\s*(password\s+(\S+\s+)+pam_unix\.so\s*)(.*)$/\1 sha512 \3/' "$target_file"; done


rpm -q libpwquality || yum -y install libpwquality;
for FN in system-auth password-auth; do 
  target_file="/etc/pam.d/${FN}";
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so(\s|$)' "$target_file" || sed -ri '0,/^\s*password\s+sufficient\s/s/^\s*password\s+sufficient\s/password requisite pam_pwquality.so retry=3\n&/' "$target_file"; 
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so[^#]*\s+try_first_pass(\s|#|$)' "$target_file" || sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality\.so\s*)(.*)$/\1 try_first_pass \2/' "$target_file"; 
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so[^#]*\s+retry=[123](\s|#|$)' "$target_file" || (sed -ri '/pam_pwquality\.so/s/\sretry=\S+//g' "$target_file"; sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s*)(.*)$/\1 retry=3 \2/' "$target_file"); 
done;
grep -E '^\s*minlen\s*=\s*[0-7](\s|$)' /etc/security/pwquality.conf && sed -ri 's/^(\s*minlen\s*=\s*[0-7])(\s|$)/## \1\2/' /etc/security/pwquality.conf
grep -E '^\s*dcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*dcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*dcredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo dcredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ucredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ucredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ucredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo ucredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ocredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ocredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ocredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo ocredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*lcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*lcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*lcredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo lcredit=-1 >> /etc/security/pwquality.conf)


if [[ -n $(grep ^[^#] /etc/pam.d/system-auth /etc/pam.d/password-auth | grep 'pam_tally2.so') ]] && [[ -z $(grep ^[^#] /etc/pam.d/system-auth /etc/pam.d/password-auth | grep 'pam_faillock.so') ]]; then 
  for FN in system-auth password-auth; do 
    target_file="/etc/pam.d/$FN"; 
    grep -E '^\s*auth\s+required\s+pam_tally2\.so' "$target_file" || sed -ri '0,/^\s*auth\s+sufficient\s/s/^\s*auth\s+sufficient\s/auth required pam_tally2.so onerr=fail silent deny=5 unlock_time=7200\n&/' "$target_file"; 
    grep -E '^\s*auth\s+required\s+pam_tally2\.so[^#]*\s+deny=[1-5](\s|#|$)' "$target_file" || (sed -ri '/^\s*auth\s+required\s+pam_tally2\.so/s/\sdeny=\S+//g' "$target_file"; sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so\s*)(.*)$/\1 deny=5 \2/' "$target_file"); 
    grep -E '^\s*auth\s+required\s+pam_tally2\.so[^#]*\s+unlock_time=(7[2-9]|[89][0-9]|[1-9][0-9]{2,})[0-9]{2}(\s|#|$)' "$target_file" || (sed -ri '/^\s*auth\s+required\s+pam_tally2\.so/s/\sunlock_time=\S+//g' "$target_file"; sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so\s*)(.*)$/\1 unlock_time=7200 \2/' "$target_file"); 
    grep -E '^\s*account\s+required\s+pam_tally2\.so' "$target_file" || sed -ri '0,/^\s*account\s+\S+\s+pam_unix\.so/s/^\s*account\s+\S+\s+pam_unix\.so/account required pam_tally2.so\n&/' "$target_file"; 
  done;
else
  for FN in system-auth password-auth; do 
    target_file="/etc/pam.d/${FN}";
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+preauth(\s|$)' "$target_file" || (rm -f "$FN.couch_tmp" 2>/dev/null; i=0; while read -r line || [[ -n "$line" ]]; do if [[ "$i" -eq "0" ]]&&[[ $(echo "$line" | egrep -i "^\s*auth\s+sufficient") ]]; then echo "auth required pam_faillock.so preauth silent" >> "$FN.couch_tmp"; i=1; fi; echo "$line" >> "$FN.couch_tmp"; done < "$target_file"; yes | cp "$FN.couch_tmp" "$target_file"; rm -f "$FN.couch_tmp" 2>/dev/null); 
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+authfail(\s|$)' "$target_file" || printf '%s\n' '0?^\s*auth\s\+sufficient\s?a' 'auth required pam_faillock.so authfail' . x | ex "$target_file";
    sed -ri '/pam_faillock.so/s/deny=\S+/deny=5/g' "$target_file"; 
    sed -ri '/pam_faillock.so/s/unlock_time=\S+/unlock_time=7200/g' "$target_file"; 
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+preauth\s[^#]*deny=\S+' "$target_file" || sed -ri 's/^\s*(auth\s+required\s+pam_faillock\.so\s+preauth)(.*[^{}])?(\{.*\}|#.*|)?$/\1 deny=5 \2\3/' "$target_file"; 
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+preauth\s[^#]*unlock_time=\S+' "$target_file" || sed -ri 's/^\s*(auth\s+required\s+pam_faillock\.so\s+preauth)(.*[^{}])?(\{.*\}|#.*|)?$/\1 unlock_time=7200 \2\3/' "$target_file"; 
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+authfail\s[^#]*deny=\S+' "$target_file" || sed -ri 's/^\s*(auth\s+required\s+pam_faillock\.so\s+authfail)(.*[^{}])?(\{.*\}|#.*|)?$/\1 deny=5 \2\3/' "$target_file"; 
    grep -E '^\s*auth\s+required\s+pam_faillock.so\s+authfail\s[^#]*unlock_time=\S+' "$target_file" || sed -ri 's/^\s*(auth\s+required\s+pam_faillock\.so\s+authfail)(.*[^{}])?(\{.*\}|#.*|)?$/\1 unlock_time=7200 \2\3/' "$target_file"; 
    grep -E '^\s*account\s+required\s+pam_faillock\.so' "$target_file" || sed -ri '0,/^\s*account\s+\S+\s+pam_unix\.so/s/^\s*account\s+\S+\s+pam_unix\.so/account required pam_faillock.so\n&/' "$target_file"; 
  done;
fi;


for FN in system-auth password-auth; do 
  PTF="/etc/pam.d/$FN"; 
  grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so' "$PTF" || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password required pam_pwhistory.so remember=5\n&/' "$PTF"; 
  grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so[^#]*\sremember=([5-9]|[1-9][0-9]+)' "$PTF" || (sed -ri '/^\s*password\s+(requisite|required)\s+pam_pwhistory\.so/s/\sremember=\S+//g' "$PTF"; sed -ri 's/^\s*(password\s+(requisite|required)\s+pam_pwhistory\.so\s*)(.*)$/\1 remember=5 \3/' "$PTF"); 
done;


cp /etc/securetty /etc/securetty.old
egrep "^(tty[0-9]+|console)$" /etc/securetty.old > /etc/securetty


PTF=/etc/pam.d/su; 
grep -E '^\s*auth\s+required\s+pam_wheel\.so' $PTF || sed -ri '0,/^\s*auth\s+sufficient\s+pam_rootok\.so/s/^\s*auth\s+sufficient\s+pam_rootok\.so.*$/&\nauth required pam_wheel.so use_uid/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_wheel\.so.*\s+use_uid(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_wheel\.so.*)$/\1 use_uid/' $PTF || true;


rm -f /etc/hosts.equiv


sed -i "s;^\(\s*PASS_MAX_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MAX_DAYS 90" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do if [[ -n $(echo "__technology_accounts__" | grep -E "(^|;)$x(;|$)") ]]; then chage --maxdays 365 $x; else chage --maxdays 90 $x; fi; done


sed -i "s;^\(\s*PASS_MIN_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --mindays 1 $x; done


sed -i "s;^\(\s*PASS_WARN_AGE\s\);#\1;g" /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --warndays 7 $x; done


egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/sbin/nologin") {system("usermod -s /usr/sbin/nologin "$1)}'


usermod -g 0 root


sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/bashrc
sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/profile /etc/profile.d/*.sh
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/bashrc || echo umask 077 >> /etc/bashrc
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/profile /etc/profile.d/*.sh || echo umask 077 >> /etc/profile.d/cis.sh


useradd -D -f 30
for x in `cut -d: -f1 /etc/passwd`; do chage --inactive 30 $x; done


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


chown root:root /etc/motd
chmod 644 /etc/motd


chown root:root /etc/issue
chmod 644 /etc/issue


chown root:root /etc/issue.net
chmod 644 /etc/issue.net


if [ -e /etc/dconf ]; then egrep "^\s*user-db:user" /etc/dconf/profile/gdm || echo "user-db:user" >> /etc/dconf/profile/gdm; egrep "^\s*system-db:gdm" /etc/dconf/profile/gdm || echo "system-db:gdm" >> /etc/dconf/profile/gdm; egrep "^\s*file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm || echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >> /etc/dconf/profile/gdm; if [ ! -e /etc/dconf/db/gdm.d ]; then mkdir /etc/dconf/db/gdm.d; fi; egrep "^\s*\[org/gnome/login-screen\]" /etc/dconf/db/gdm.d/* || echo "[org/gnome/login-screen]" >> /etc/dconf/db/gdm.d/01-banner-message; egrep "^\s*banner-message-enable\s*=\s*true" /etc/dconf/db/gdm.d/*  || echo "banner-message-enable=true" >> /etc/dconf/db/gdm.d/01-banner-message; egrep "^\s*banner-message-text\s*=" /etc/dconf/db/gdm.d/* | egrep -i "authorized\s+(users|access|uses)\s+only\.\s*all\s+activity\s+may\s+be\s+(monitored\s+and\s+reported|logged\s+and\s+monitored)" || ( sed -i "s/banner-message-text\s*=/#banner-message-text=/g" /etc/dconf/db/gdm.d/*; echo "banner-message-text='Authorized access only. All activity may be logged and monitored'" >> /etc/dconf/db/gdm.d/01-banner-message); dconf update; fi


echo "[Manual]" 'Correct any discrepancies found and rerun the command until output is clean or risk is mitigated or accepted:
rpm -Va --nomtime --nosize --nomd5 --nolinkto'
read -n 1 -p "Press Enter to continue..."


/bin/chmod u-x,go-wx /etc/passwd


/bin/chmod go-rwx,u-wx /etc/shadow


/bin/chmod go-rwx,u-wx /etc/gshadow


/bin/chmod u-x,go-wx /etc/group


/bin/chown root:root /etc/passwd


/bin/chown root:root /etc/shadow


/bin/chown root:root /etc/gshadow


/bin/chown root:root /etc/group


chown root:root /etc/passwd-
chmod go-rwx /etc/passwd-


chown root:root /etc/shadow-
chmod go-rwx /etc/shadow-


chown root:root /etc/group-
chmod go-rwx /etc/group-


chown root:root /etc/gshadow-
chmod go-rwx /etc/gshadow-


p=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f -perm -0002 2>/dev/null`;
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chmod o-w "$each"; done;
IFS=$couch_ifs


p=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -nouser 2>/dev/null`;
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chown root "$each"; chmod go-rwx "$each"; done;
IFS=$couch_ifs


p=`df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -nogroup 2>/dev/null`;
couch_ifs=$IFS;IFS=$'\n';
for each in $p; do chown :root "$each"; chmod go-rwx "$each"; done
IFS=$couch_ifs


echo "[Manual]" 'Ensure that no rogue set-UID programs have been introduced into the system. Review the files returned by the action in the Audit section:
#!/bin/bash
df --local -P | awk {'\''if (NR!=1) print $6'\''} | xargs -I '\''{}'\'' find '\''{}'\'' -xdev -type f -perm -4000 -print
 and confirm the the integrity of these binaries as described below:
# rpm -V `rpm -qf /usr/bin/sudo`
.......T /usr/bin/sudo
SM5....T /usr/bin/sudoedit'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that no rogue set-GID programs have been introduced into the system
#!/bin/bash
# df --local -P | awk {'\''if (NR!=1) print $6'\''} | xargs -I '\''{}'\'' find '\''{}'\'' -xdev -type f -perm -2000 -print
# /bin/rpm -V `/bin/rpm -qf sudo`'
read -n 1 -p "Press Enter to continue..."


cat /etc/shadow | awk -F: '( $2 == "" ) {system("passwd -l "$1); print "User "$1" has been locked because of empty password"}'


sed -i 's/^+/#+/g' /etc/passwd


sed -i 's/^+/#+/g' /etc/shadow


sed -i 's/^+/#+/g' /etc/group


echo "[Manual]" 'Delete any other entries that are displayed except root:
# cat /etc/passwd | awk -F: '\''($3 == 0) { print $1 }'\'''
read -n 1 -p "Press Enter to continue..."


if [ "`/bin/echo $PATH | /bin/grep :: `" != "" ]; then /bin/echo "Warning: Empty Directory in PATH (::)"; fi; echo _#[; if [ "`/bin/echo $PATH | /bin/grep :$`" != "" ]; then /bin/echo "Warning: Trailing : in PATH"; fi; echo _#[; p=`/bin/echo $PATH | /bin/sed -e "s/::/:/" -e "s/:\$//" -e "s/:/ /g"`; set -- $p; while [ "$1" != "" ]; do /bin/echo $1; if [ "$1" == "." ]; then /bin/echo "Warning: PATH contains ."; shift; continue; fi; if [ -d $1 ]; then dirperm=`/bin/ls -ldH $1 | /usr/bin/cut -f1 -d" "`; /bin/echo "$dirperm"; if [ `/bin/echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then /bin/echo "Warning: Group Write permissions on directory $1"; fi; if [ `/bin/echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then /bin/echo "Warning: Other Write permissions set on directory $1"; fi; dirown=`/bin/ls -ldH $1 | /usr/bin/cut -d" " -f3`; /bin/echo "Owner: $dirown"; if [ "$dirown" != "root" ]; then /bin/echo "Warning: $1 is not owned by root"; fi; else /bin/echo "Warning: $1 is not a directory"; fi; shift; done
echo "Correct returned warnings"
read -p "Next" a


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do chmod g-w "$dir"; chmod o-rwx "$dir"; done


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do for file in `ls -d "$dir"/.[A-Za-z0-9]* 2>/dev/null`; do chmod -R go-w "$file"; done; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then chmod go-rwx "$dir/.netrc";fi; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.rhosts" -a -f "$dir/.rhosts" ]; then mv "$dir/.rhosts" "$dir/.rhosts.old"; fi; done


q=0
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group; if [ $? -ne 0 ]; then q=1; echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi; done
if [ $q -eq 1 ]; then echo "Create returned groups or change these groups in /etc/passwd"; read -p "Next" a; fi


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then mkdir "$dir"; chown $user "$dir"; chmod g-w "$dir"; chmod o-rwx "$dir"; fi; done


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then chown $user "$dir"; fi; fi; done


q=0
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`; echo "Duplicate UID ($2): ${users}"; fi; done
if [ $q -eq 1 ]; then echo "Change UID or remove excess users"; read -p "Next" a; fi


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


c_min_uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}');
grep -Ev "^\+" /etc/passwd | awk -F: -v N=$c_min_uid '($1!="root" && $3 < N) {system("usermod -L "$1)}'


sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd



