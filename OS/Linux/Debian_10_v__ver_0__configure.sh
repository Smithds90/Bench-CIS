#!/usr/bin/env bash


apt-get update &>/dev/null;apt-get --just-print upgrade
apt-get --just-print upgrade | grep "The following packages will be upgraded" && (read -p "Do you want to upgrade packages now?[yes][NO]" update; if [ "$update" == "yes" ]; then apt-get upgrade; fi )


echo "[Manual]" 'Configure your package manager repositories according to site policy.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Update your package manager GPG keys in accordance with site policy.'
read -n 1 -p "Press Enter to continue..."


if [[ -z $(grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#') && -z $(systemctl is-enabled tmp.mount 2>/dev/null | grep enabled) ]]; then if [[ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]]; then sed -e '0,/^\s*\[Mount\]/d' /etc/systemd/system/local-fs.target.wants/tmp.mount | egrep "^\s*Where\s*=\s*/tmp(\s|#|$|;)" || printf "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,noexec\n" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; else cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/; fi; systemctl daemon-reload; systemctl --now enable tmp.mount; fi


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nodev" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nodev/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nodev" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi
if [ -e /etc/systemd/system/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nodev" /etc/systemd/system/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nodev/" /etc/systemd/system/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/tmp.mount || echo "Options=nodev" >> /etc/systemd/system/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nosuid" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nosuid/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nosuid" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi
if [ -e /etc/systemd/system/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nosuid" /etc/systemd/system/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nosuid/" /etc/systemd/system/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/tmp.mount || echo "Options=nosuid" >> /etc/systemd/system/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || (sed -i 's"^\(.*\s/tmp\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*noexec" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,noexec/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=noexec" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi
if [ -e /etc/systemd/system/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*noexec" /etc/systemd/system/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,noexec/" /etc/systemd/system/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/tmp.mount || echo "Options=noexec" >> /etc/systemd/system/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


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


grep "[[:space:]]/home[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/home\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
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


modprobe -r freevxfs 2>&1 | grep builtin && (echo "Module freevxfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* freevxfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install freevxfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r jffs2 2>&1 | grep builtin && (echo "Module jffs2 is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* jffs2 .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install jffs2 /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfs 2>&1 | grep builtin && (echo "Module hfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfsplus 2>&1 | grep builtin && (echo "Module hfsplus is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfsplus .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfsplus /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r squashfs 2>&1 | grep builtin && (echo "Module squashfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* squashfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install squashfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r udf 2>&1 | grep builtin && (echo "Module udf is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* udf .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install udf /bin/true >> /etc/modprobe.d/disabled_modules.conf)


systemctl --now mask autofs


if [[ -z $(grep -E -i '\svfat\s' /etc/fstab) ]]; then modprobe -r vfat 2>&1 | grep builtin && (echo "Module vfat is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* vfat .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install vfat /bin/true >> /etc/modprobe.d/disabled_modules.conf); else echo "Vfat is used and must be disabled manually if is not required"; read -p "Next" a; fi


modprobe -r usb-storage 2>&1 | grep builtin && (echo "Module usb-storage is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* usb-storage .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install usb-storage /bin/true >> /etc/modprobe.d/disabled_modules.conf)


chown root:root /boot/grub/grub.cfg


chmod og-rwx /boot/grub/grub.cfg


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
if [[ -z $(grep '^set superusers' "$grubdir"/*.cfg) ]] || [[ -z $(grep '^password' "$grubdir"/*.cfg) ]]; then echo "Configuring password for grub"; grub-mkpasswd-pbkdf2; read -p "Enter username for grub authentication:" user; read -p "Enter generated above encrypted password for grub authentication:" pass; if [[ "$pass" =~ ^grub\.pbkdf2\.sha512\. ]]; then echo "set superusers=\"$user\"" >> /etc/grub.d/40_custom; echo "password_pbkdf2 $user $pass" >> /etc/grub.d/40_custom; update-grub; chmod og-rwx "$grubdir/grub.cfg"; chmod og-rwx "$grubdir/user.cfg"; chmod og-rwx "$grubdir/grubenv"; else echo "Couch: Password format is not correct, password was not set"; fi; fi


passwd -S root | cut -f2 -d" " | egrep "(NP|L)" && passwd root


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


/usr/sbin/prelink -ua
apt-get purge prelink


apt-get -y install apparmor; apt-get -y install apparmor-utils


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*apparmor=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1apparmor=1 \2;g' /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*security=apparmor(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1security=apparmor \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


apt-get -y install apparmor apparmor-profiles apparmor-utils
grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*apparmor=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1apparmor=1 \2;g' /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*security=apparmor(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1security=apparmor \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"
aa-enforce /etc/apparmor.d/*


systemctl disable rsync


systemctl disable nis


apt-get remove nis
apt-get purge nis


apt-get remove rsh-client rsh-redone-client


apt-get remove talk


apt-get remove telnet


apt-get remove xinetd
apt-get purge xinetd


apt-get remove openbsd-inetd


echo "[Manual]" 'Run the following command to remove the package containing the service:
# apt purge <package_name>
OR If required packages have a dependency:
Run the following command to stop and mask the service:
# systemctl --now mask <service_name>'
read -n 1 -p "Press Enter to continue..."


chmod go-rwx /usr/bin/gcc
chmod go-rwx /usr/bin/cc


read -p "Do you want to use systemd-timesyncd (default), chrony or ntp for time synchronization?[SYSTEMD-TIMESYNCD][chrony][ntp]" timeserv; if [ "$timeserv" == "ntp" ]; then apt-get -y install ntp; systemctl enable ntp; systemctl start ntp; elif [ "$timeserv" == "chrony" ]; then apt-get -y install chrony; systemctl enable chrony; systemctl start chrony; else systemctl enable systemd-timesyncd; systemctl start systemd-timesyncd; fi


if [[ -n $(systemctl is-enabled ntp 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^\s*server\s*$ntp_server" /etc/ntp.conf || echo "server $ntp_server" >> /etc/ntp.conf; egrep "^\s*restrict\s*-4\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -4 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; egrep "^\s*restrict\s*-6\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -6 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; egrep "^\s*RUNASUSER=ntp" /etc/init.d/ntp || (sed -i 's;^\(\s*RUNASUSER.*\)$;#\1;g' /etc/init.d/ntp; echo RUNASUSER=ntp >> /etc/init.d/ntp); else echo "Not applicable - ntp.service is not enabled"; fi


if [[ -n $(systemctl is-enabled chrony 2>/dev/null | grep enabled) ]]; then grep -Ei "^(server|pool)\s+[a-z0-9]" /etc/chrony/chrony.conf || (read -p "Enter ntp server address:" ntp_server; echo "server $ntp_server" >> /etc/chrony/chrony.conf); grep -Ei "^\s*user\s+_chrony" /etc/chrony/chrony.conf || (sed -ri "s/^\s*user\s/## user /" /etc/chrony/chrony.conf; echo "user _chrony" >> /etc/chrony/chrony.conf); else echo "Not applicable - chrony.service is not enabled"; fi


apt-get remove xserver-xorg*


systemctl disable avahi-daemon


systemctl disable cups


systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6


systemctl disable slapd


apt-get remove ldap-utils


systemctl disable nfs-server
systemctl disable rpcbind


systemctl disable bind9


systemctl disable vsftpd


systemctl disable apache2


systemctl --now disable dovecot
systemctl disable exim4


systemctl disable smbd


systemctl disable squid


systemctl disable snmpd


sed -i 's/\s*dc_local_interfaces=/#dc_local_interfaces=/g' /etc/exim4/update-exim4.conf.conf
echo "dc_local_interfaces='127.0.0.1; ::1'" >> /etc/exim4/update-exim4.conf.conf
sed -i 's/\s*dc_eximconfig_configtype=/#dc_eximconfig_configtype=/g' /etc/exim4/update-exim4.conf.conf
echo "dc_eximconfig_configtype='local'" >> /etc/exim4/update-exim4.conf.conf
update-exim4.conf
service exim4 reload


echo "[Manual]" 'All export NFS necessary must be with the respective
restrictions of writing, and limited to the IPs of the authorized
customers in the etc/exports:
/directory archive/client1(ro), client2(rw)'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]nfs[[:space:]]" /etc/fstab | grep ^[^#] | grep -v "nosuid" && sed -i 's;^\(.*\snfs\s\+[a-zA-Z0-9,]\+\)\(\s\+.*\)$;\1,nosuid\2;g' /etc/fstab


sed -i 's/^\s*\(r[ow]community\s\+public\)/#\1/g' /etc/snmp/snmpd.conf
sed -i 's/^\s*\(r[ow]community\s\+private\)/#\1/g' /etc/snmp/snmpd.conf


if [[ -n $(systemctl is-enabled systemd-timesyncd 2>/dev/null | grep enabled) ]]; then read -p "Enter ntp server address:" ntp_server; egrep "^(ntp|fallbackntp)\s*=\s*$ntp_server" /etc/systemd/timesyncd.conf || (sed -i 's/^ntp\s*=\s*/# ntp=/gI' /etc/systemd/timesyncd.conf; echo "NTP=$ntp_server" >> /etc/systemd/timesyncd.conf; systemctl restart systemd-timesyncd); else echo "Not applicable - systemd-timesyncd.service is not enabled"; fi


sed -i "s/^\(\s*net\.ipv4\.ip_forward\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.ip_forward\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.route.flush=1


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


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.forwarding=0
/sbin/sysctl -w net.ipv6.route.flush=1


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


sed -i "s/^\(\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
sed -i "s/^\(\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
[[ -n $(egrep "^\s*net\.ipv6\.conf\.default\.accept_source_route\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv6.conf.all.accept_source_route=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv6.route.flush=1


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*ipv6.disable=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1ipv6.disable=1 \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


apt-get -y install tcpd


echo "[Manual]" 'Run the following command to create /etc/hosts.allow: 
# echo "ALL: <net>/<mask>, <net>/<mask>, ..." >/etc/hosts.allow 
where each <net>/<mask> combination (for example, "192.168.1.0/255.255.255.0") 
represents one network block in use by your organization that requires access to this 
system. 
Notes: 
Contents of the /etc/hosts.allow file will vary depending on your network configuration.'
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


nmcli nm wifi off 2>/dev/null || nmcli radio wifi off
ip link show up | grep -B 1 'link/ieee802.11' | grep -E "^[^ ]" | cut -f2 -d: | while read -r each; do ip link $each down; done


echo "[Manual]" 'The DNS servers listed in
/etc/resolv.conf file must be those managed locally by the internal administrators.'
read -n 1 -p "Press Enter to continue..."


apt-get -y install auditd
systemctl enable auditd
systemctl start auditd


sed -i 's/^\s*max_log_file\s*=\s*.*$/max_log_file = 50/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file\s*=\s*50\s*$" /etc/audit/auditd.conf || echo "max_log_file = 50" >> /etc/audit/auditd.conf


sed -i 's/^\s*space_left_action\s*=.*$/space_left_action = email/g' /etc/audit/auditd.conf
egrep "^\s*space_left_action\s*=\s*email\s*$" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i 's/^\s*action_mail_acct\s*=.*$/action_mail_acct = root/g' /etc/audit/auditd.conf
egrep "^\s*action_mail_acct\s*=\s*root\s*$" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf


sed -i 's/^\s*max_log_file_action\s*=.*$/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file_action\s*=\s*keep_logs\s*$" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*audit=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1audit=1 \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*audit_backlog_limit=(819[2-9]|8[2-9][0-9]{2}|9[0-9]{3}|[1-9][0-9]{4,})(\s|")' /etc/default/grub || (sed -ri 's/\saudit_backlog_limit=[0-9]+//g' /etc/default/grub; sed -ri 's/^(GRUB_CMDLINE_LINUX=")(.*)$/\1audit_backlog_limit=8192 \2/' /etc/default/grub)
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


lscpu 2>&1 | grep "Architecture" | grep 64 || ( egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/group\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/passwd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/gshadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/shadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/security/opasswd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*exit,always\s*-F\s*arch=b64\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/apparmor/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/apparmor/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/apparmor.d/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/apparmor.d/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/log/faillog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/faillog -p wa -k logins" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/lastlog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/lastlog -p wa -k logins" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/tallylog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/tallylog -p wa -k logins" /etc/audit/rules.d/audit.rules)
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


apt-get -y install rsyslog


systemctl enable rsyslog


echo "[Manual]" 'Edit the following lines in the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files as appropriate for your environment. Example: 
*.emerg :omusrmsg:* 
mail.* -/var/log/mail 
mail.info -/var/log/mail.info 
mail.warning -/var/log/mail.warn 
mail.err /var/log/mail.err 
news.crit -/var/log/news/news.crit 
news.err -/var/log/news/news.err 
news.notice -/var/log/news/news.notice 
*.=warning;*.=err -/var/log/warn 
*.crit /var/log/warn 
*.*;mail.none;news.none -/var/log/messages 
local0,local1.* -/var/log/localmessages 
local2,local3.* -/var/log/localmessages 
local4,local5.* -/var/log/localmessages 
local6,local7.* -/var/log/localmessages 
Run the following command to reload the rsyslogd configuration: 
# systemctl reload rsyslog'
read -n 1 -p "Press Enter to continue..."


egrep "^\\\$FileCreateMode\s+0?[0246][04]0" /etc/rsyslog.conf || echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf


grep "^\*\.\*[[:space:]]*@@" /etc/rsyslog.conf || (read -p "Enter IP address or domain name of central logging server for syslog:" logserv; echo "*.* @@$logserv" >> /etc/rsyslog.conf; pkill -HUP rsyslogd)


read -p "Is this host designated central logging server?[y][N]" logserver;
if [[ "$logserver" != "y" && "$logserver" != "Y" ]]; then sed -i "s;^\s*\(\$ModLoad\s\+\(imtcp\|/[^#]*imtcp\)\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; sed -i "s;^\s*\(\$InputTCPServerRun\s\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; pkill -HUP rsyslogd; fi


apt install aide aide-common
echo "Configure AIDE as appropriate for your environment"
read -p "Ready" a
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db


(crontab -u root -l 2>/dev/null | egrep -i "^[0-9]+\s+[0-9]+\s+\*\s+\*\s+\*\s+/usr/bin/aide.*\s+--check") || (crontab -u root -l 2>/dev/null; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check") | sort - | uniq - | crontab -u root -


find /var/log -type f ! -name wtmp ! -name wtmp.* ! -name btmp ! -name btmp.* ! -name lastlog ! -name lastlog.* | xargs -d$'\n' -I {} chmod g-wx,o-rwx '{}'
chmod ug-x,o-wx /var/log/lastlog 2>/dev/null
chmod ug-x,o-rwx /var/log/btmp 2>/dev/null
chmod ug-x,o-wx /var/log/wtmp 2>/dev/null


echo "[Manual]" 'Edit /etc/logrotate.conf and /etc/logrotate.d/* to ensure logs are rotated according 
to site policy. 
Notes: 
If no maxage setting is set for logrotate a situation can occur where logrotate is interrupted 
and fails to delete rotated logfiles. It is recommended to set this to a value greater than the 
longest any log file should exist on your system to ensure that any such logfile is removed 
but standard rotation settings are not overridden.'
read -n 1 -p "Press Enter to continue..."


for f in `ls /etc/logrotate.conf /etc/logrotate.d/*`; do i=0; rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $line | egrep -i "/utmp|/wtmp|/btmp" && i=1; if [ "$i" == "0" ]; then echo $line | grep "{" && k=0; echo $line | grep "}" && if [ "$k" == "0" ]; then echo "create 0600 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 600 ;' >> $f.couch_tmp; else echo $line | grep "{" && k=0; echo $line | grep "}" && i=0&& if [ "$k" == "0" ]; then echo "create 0640 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 640 ;' >> $f.couch_tmp; fi; done < $f; yes | cp $f.couch_tmp $f; rm --interactive=never $f.couch_tmp; done


egrep "^Defaults\s+syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" /etc/sudoers || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*ForwardToSyslog\s*=" | tail -n 1 | egrep "^\s*ForwardToSyslog\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*ForwardToSyslog\s/## ForwardToSyslog /g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nForwardToSyslog=yes\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Compress\s*=" | tail -n 1 | egrep "^\s*Compress\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*Compress\s/## Compress/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nCompress=yes\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Storage\s*=" | tail -n 1 | egrep "^\s*Storage\s*=\s*persistent(\s|#|$)" || ( sed -i "s/^\s*Storage\s/## Storage/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nStorage=persistent\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | grep -Ei '(^|\s)file=".+"'); do if [[ "$each" =~ ^[^#]*[Ff]ile=\"(.*)\" ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done
for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "^.+\..+\s+-?/.+$" | grep -v -i IncludeConfig); do if [[ "$each" =~ ^-?(/[^:;]+)[^:]*$ ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done


systemctl enable cron


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


dpkg -s libpam-pwquality 1>/dev/null 2>/dev/null || apt-get -y install libpam-pwquality
PTF=/etc/pam.d/common-password; 
grep -E '^\s*password\s+requisite\s+pam_pwquality\.so' $PTF || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password requisite pam_pwquality.so retry=3\n&/' $PTF; 
[[ -z $(grep -E '^\s*password\s+requisite\s+pam_pwquality\.so.*\s+try_first_pass(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality\.so.*)$/\1 try_first_pass/' $PTF; 
[[ -z $(grep -E '^\s*password\s+requisite\s+pam_pwquality\.so.*\s+retry=[123](\s|#|$)' $PTF) ]] && (sed -ri '/pam_pwquality\.so/s/\sretry=\S+//g' $PTF; sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so.*)$/\1 retry=3/' $PTF);
grep -E '^\s*minlen\s*=\s*[0-7](\s|$)' /etc/security/pwquality.conf && sed -ri 's/^(\s*minlen\s*=\s*[0-7])(\s|$)/## \1/' /etc/security/pwquality.conf
grep -E '^\s*dcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*dcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*dcredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo dcredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ucredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ucredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ucredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo ucredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ocredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ocredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ocredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo ocredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*lcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*lcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*lcredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo lcredit=-1 >> /etc/security/pwquality.conf)


PTF=/etc/pam.d/common-auth; 
grep -E '^\s*auth\s+required\s+pam_tally2\.so' $PTF || sed -ri '0,/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s/auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=7200\n&/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_tally2\.so.*\s+onerr=fail(\s|#|$)' $PTF) ]] && (sed -ri '/^\s*auth\s+required\s+pam_tally2\.so/s/\sonerr=\S+//g' $PTF; sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so.*)$/\1 onerr=fail/' $PTF); 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_tally2\.so.*\s+audit(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so.*)$/\1 audit/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_tally2\.so.*\s+silent(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so.*)$/\1 silent/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_tally2\.so.*\s+deny=[1-5](\s|#|$)' $PTF) ]] && (sed -ri '/^\s*auth\s+required\s+pam_tally2\.so/s/\sdeny=\S+//g' $PTF; sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so.*)$/\1 deny=5/' $PTF); 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_tally2\.so.*\s+unlock_time=(7[2-9]|[89][0-9]|[1-9][0-9]{2,})[0-9]{2}(\s|#|$)' $PTF) ]] && (sed -ri '/^\s*auth\s+required\s+pam_tally2\.so/s/\sunlock_time=\S+//g' $PTF; sed -ri 's/^\s*(auth\s+required\s+pam_tally2\.so.*)$/\1 unlock_time=7200/' $PTF); 
grep -E '^\s*account\s+required\s+pam_tally2\.so' /etc/pam.d/common-account || sed -ri '0,/^\s*account\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*account\s+(sufficient|\[success=([0-9]+|ok).*)\s/account required pam_tally2.so\n&/' /etc/pam.d/common-account;


PTF=/etc/pam.d/common-password;
grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so' $PTF || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password required pam_pwhistory.so remember=5\n&/' $PTF; 
[[ -z $(grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so.*\sremember=([5-9]|[1-9][0-9]+)' $PTF) ]] && (sed -ri '/^\s*password\s+(requisite|required)\s+pam_pwhistory\.so/s/\sremember=\S+//g' $PTF; sed -ri 's/^\s*(password\s+(requisite|required)\s+pam_pwhistory\.so.*)$/\1 remember=5/' $PTF) || true


PTF=/etc/pam.d/common-password;
sed -ri '/^\s*password\s+(\S+\s+)+pam_unix\.so/s/\ssha[0-9]+(\s|$)/\1/g' $PTF; sed -ri 's/^\s*(password\s+(\S+\s+)+pam_unix\.so)(.*)$/\1 sha512\3/' $PTF;


cp /etc/securetty /etc/securetty.old
egrep "^(tty[0-9]+|console)$" /etc/securetty.old > /etc/securetty


PTF=/etc/pam.d/su; 
grep -E '^\s*auth\s+required\s+pam_wheel\.so' $PTF || sed -ri '0,/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s+pam_rootok\.so/s/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s+pam_rootok\.so.*$/&\nauth required pam_wheel.so use_uid/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_wheel\.so.*\s+use_uid(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_wheel\.so.*)$/\1 use_uid/' $PTF || true;


rm -f /etc/hosts.equiv


sed -i 's/^\s*PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs
echo PASS_MAX_DAYS 90 >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do if [[ -n $(echo "__technology_accounts__" | grep -E "(^|;)$x(;|$)") ]]; then chage --maxdays 365 $x; else chage --maxdays 90 $x; fi; done


sed -i "s;^\(\s*PASS_MIN_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --mindays 1 $x; done


sed -i 's/^\s*PASS_WARN_AGE/#PASS_WARN_AGE/g' /etc/login.defs
echo PASS_WARN_AGE 7 >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --warndays 7 $x; done


useradd -D -f 30
egrep -v "^\+" /etc/shadow | awk -F: '($2!="" && $2!="*" && $2!="!") {system("chage --inactive 30 "$1)}'


egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/sbin/nologin") {system("usermod -s /usr/sbin/nologin "$1)}'


usermod -g 0 root


sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/bash.bashrc
sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/profile /etc/profile.d/*.sh
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/bash.bashrc || echo umask 077 >> /etc/bash.bashrc
egrep "^\s*umask\s+[0-7]?[0-7]?77" /etc/profile /etc/profile.d/*.sh || echo umask 077 >> /etc/profile.d/cis.sh


read -p "Enter timeout in seconds (default is 900):" idle_timeout;
if [ -z "$idle_timeout" ]; then idle_timeout=900; fi

sed -i "s/TMOUT=[0-9]\+/TMOUT=${idle_timeout}/g" /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
sed -i 's/\(if\s\+\[\s\+!\s\+"$(\s*readonly\s\+-p\s*|\s*egrep\s\+"declare\s\+-\[a-z\]+\s\+TMOUT="\s*)"\s\+\]\s*;\s*then\s\+\)\?readonly\s\+TMOUT\(=[0-9]\+\)\?\(\s*;\s*export\s\+TMOUT\s*\)\?\(\s*;\s*fi\)\?/if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'\3; fi/g' /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/bash.bashrc || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/bash.bashrc
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/profile.d/couch.sh
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/bash.bashrc || echo "export TMOUT" >> /etc/bash.bashrc
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo "export TMOUT" >> /etc/profile.d/couch.sh


echo "[Manual]" 'Remove unnecessary aliases from the /etc/aliases file. Entries like uudecode and decode must be removed, as well as entries that refer to automated scripts.'
read -n 1 -p "Press Enter to continue..."


apt -y install sudo


grep -Ei '^\s*Defaults\s+([^#]+\s)?use_pty' /etc/sudoers /etc/sudoers.d/* || echo "Defaults use_pty" >> /etc/sudoers


grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/* || (read -p "Enter path for sudo log file: [default /var/log/sudo.log]" c_sudo_log_path;
if [ -z "$c_sudo_log_path" ]; then c_sudo_log_path=/var/log/sudo.log; fi; echo "Defaults logfile=\"${c_sudo_log_path}\"" >> /etc/sudoers)


echo "Authorized users only. All activity may be monitored and reported." > /etc/motd


echo "Authorized users only. All activity may be monitored and reported." > /etc/issue


echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net


chown root:root /etc/motd
chmod 644 /etc/motd


chown root:root /etc/issue
chmod 644 /etc/issue


chown root:root /etc/issue.net
chmod 644 /etc/issue.net


if [ -e /etc/gdm3 ]; then egrep "^\s*\[org/gnome/login-screen\]" /etc/gdm3/greeter.dconf-defaults || printf "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized users only. All activity may be monitored and reported.'\n" >> /etc/gdm3/greeter.dconf-defaults; egrep "^\s*banner-message-enable\s*=\s*true" /etc/gdm3/greeter.dconf-defaults  || sed -i 's;\(^\s*[org/gnome/login-screen].*$\);\1\nbanner-message-enable=true;' /etc/gdm3/greeter.dconf-defaults; egrep "^\s*banner-message-text\s*=" /etc/gdm3/greeter.dconf-defaults | grep "Authorized access only. All activity may be logged and monitored" || sed -i "s;\(^\s*[org/gnome/login-screen].*$\);\1\nbanner-message-text='Authorized access only. All activity may be logged and monitored';" /etc/gdm3/greeter.dconf-defaults; fi


echo "[Manual]" 'Correct any discrepancies found and rerun the audit until output is clean or risk is mitigated or accepted:
dpkg --verify
Notes: 
Since packages and important files may change with new updates and releases, it is 
recommended to verify everything, not just a finite list of files. This can be a time 
consuming task and results may depend on site policy therefore it is not a scorable 
benchmark item, but is provided for those interested in additional security measures. 
Some of the recommendations of this benchmark alter the state of files audited by this 
recommendation. The audit command will alert for all changes to a file permissions even if 
the new state is more secure than the default.'
read -n 1 -p "Press Enter to continue..."


/bin/chown root:root /etc/passwd


/bin/chmod u-x,go-wx /etc/passwd


/bin/chown root:shadow /etc/shadow


/bin/chmod o-rwx,g-rw /etc/shadow


/bin/chown root:root /etc/group


/bin/chmod u-x,go-wx /etc/group


/bin/chown root:shadow /etc/gshadow


/bin/chmod o-rwx,g-rw /etc/gshadow


/bin/chown root:root /etc/passwd-


chmod u-x,go-wx /etc/passwd-


/bin/chown root:shadow /etc/shadow-


/bin/chmod o-rwx,g-rw /etc/shadow-


/bin/chown root:root /etc/group-


/bin/chmod u-x,go-wx /etc/group-


/bin/chown root:shadow /etc/gshadow-


/bin/chmod o-rwx,g-rw /etc/gshadow-


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


echo "[Manual]" 'Ensure that no rogue SUID programs have been introduced into the system. Review the files returned by the action in the Audit section:
# df --local -P | awk {'\''if (NR!=1) print $6'\''} | xargs -I '\''{}'\'' find '\''{}'\'' -xdev -type f -perm -4000 
 and confirm the integrity of these binaries.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that no rogue SGID programs have been introduced into the system. Review the files returned by the action in the Audit section:
# df --local -P | awk {'\''if (NR!=1) print $6'\''} | xargs -I '\''{}'\'' find '\''{}'\'' -xdev -type f -perm -2000 
 and confirm the integrity of these binaries.'
read -n 1 -p "Press Enter to continue..."


cat /etc/shadow | awk -F: '( $2 == "" ) {system("passwd -l "$1); print "User "$1" has been locked because of empty password"}'


sed -i 's/^+/#+/g' /etc/passwd


sed -i 's/^+/#+/g' /etc/shadow


sed -i 's/^+/#+/g' /etc/group


echo "[Manual]" 'Remove any users other than root with UID 0 or assign them a new UID if appropriate.'
read -n 1 -p "Press Enter to continue..."


if [ "`/bin/echo $PATH | /bin/grep :: `" != "" ]; then /bin/echo "Warning: Empty Directory in PATH (::)"; fi; echo _#[; if [ "`/bin/echo $PATH | /bin/grep :$`" != "" ]; then /bin/echo "Warning: Trailing : in PATH"; fi; echo _#[; p=`/bin/echo $PATH | /bin/sed -e "s/::/:/" -e "s/:\$//" -e "s/:/ /g"`; set -- $p; while [ "$1" != "" ]; do /bin/echo $1; if [ "$1" == "." ]; then /bin/echo "Warning: PATH contains ."; shift; continue; fi; if [ -d $1 ]; then dirperm=`/bin/ls -ldH $1 | /usr/bin/cut -f1 -d" "`; /bin/echo "$dirperm"; if [ `/bin/echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then /bin/echo "Warning: Group Write permissions on directory $1"; fi; if [ `/bin/echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then /bin/echo "Warning: Other Write permissions set on directory $1"; fi; dirown=`/bin/ls -ldH $1 | /usr/bin/cut -d" " -f3`; /bin/echo "Owner: $dirown"; if [ "$dirown" != "root" ]; then /bin/echo "Warning: $1 is not owned by root"; fi; else /bin/echo "Warning: $1 is not a directory"; fi; shift; done
echo "Correct returned warnings"
read -p "Next" a


grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then mkdir "$dir"; chown $user "$dir"; chmod go-rwx "$dir"; fi; done


cat /etc/passwd | egrep -v "^(halt:|sync:|shutdown:)" | awk -F: '( $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do chmod g-w "$dir"; chmod o-rwx "$dir"; done


cat /etc/passwd | egrep -v '^(halt|sync|shutdown|nfsnobody|nobody):' | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7!="/sbin/nologin") { print $1 " " $6 }' | while read user dir; do if [ -d "$dir" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then chown $user "$dir"; fi; fi; done


cat /etc/passwd | egrep -v "^(halt:|sync:|shutdown:)" | awk -F: '( $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do for file in `ls -d "$dir"/.[A-Za-z0-9]* 2>/dev/null`; do chmod -R go-w "$file"; done; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then mv "$dir/.forward" "$dir/.forward.old";fi; done


couch_ifs="$IFS";IFS=$'\n';
for dir in $(awk -F: '{ print $6 }' /etc/passwd); do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then read -p "Do you want to remove $dir/.netrc file?[YES][no]" co_ans; if [[ "$co_ans" =~ [Nn][oO]? ]]; then chmod go-rwx "$dir/.netrc"; else rm -f "$dir/.netrc"; fi; fi; done
IFS="$couch_ifs"


cat /etc/passwd | awk -F: '{print $6}' | while read dir; do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then chmod go-rwx "$dir/.netrc";fi; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.rhosts" -a -f "$dir/.rhosts" ]; then mv "$dir/.rhosts" "$dir/.rhosts.old"; fi; done


q=0
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do grep -q -P "^.*?:[^:]*:$i:" /etc/group; if [ $? -ne 0 ]; then q=1; echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi; done
if [ $q -eq 1 ]; then echo "If some groups are returned, create returned groups or change these groups in /etc/passwd"; read -p "Next" a; fi


q=0
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`; echo "Duplicate UID ($2): ${users}"; fi; done
if [ $q -eq 1 ]; then echo "If some users are returned, change UID or remove excess users"; read -p "Next" a; fi


q=0
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break; set -- $x; if [ $1 -gt 1 ]; then q=1; grps=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`; echo "Duplicate GID ($2): ${grps}"; fi; done
if [ $q -eq 1 ]; then echo "If some groups are returned, change GID or remove excess groups"; read -p "Next" a; fi


q=0
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x; do q=1; echo "Duplicate login name ${x} in /etc/passwd"; done
if [ $q -eq 1 ]; then echo "If some users are returned, change username or remove excess users"; read -p "Next" a; fi


q=0
cut -d: -f1 /etc/group | sort | uniq -d | while read x; do q=1; echo "Duplicate group name ${x} in /etc/group"; done
if [ $q -eq 1 ]; then echo "If some groups are returned, change group name or remove excess groups"; read -p "Next" a; fi


echo "[Manual]" 'Remove all users from the shadow group, and change the primary group of any users with 
shadow as their primary group.'
read -n 1 -p "Press Enter to continue..."


awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do usermod -L "$user"; done


sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd


sed -i 's/^\(\s*kernel\.dmesg_restrict\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.dmesg_restrict\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.dmesg_restrict=1


sed -i 's/^\(\s*kernel\.kptr_restrict\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.kptr_restrict\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kptr_restrict=2


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*init_on_alloc=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1init_on_alloc=1 \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*slab_nomerge(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1slab_nomerge \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*iommu=force(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1iommu=force \2;g' /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*iommu.strict=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1iommu.strict=1 \2;g' /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*iommu.passthrough=0(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1iommu.passthrough=0 \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*randomize_kstack_offset=1(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1randomize_kstack_offset=1 \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*mitigations=auto,nosmt(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1mitigations=auto,nosmt \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*net\.core\.bpf_jit_harden\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*net\.core\.bpf_jit_hardens*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'net.core.bpf_jit_harden = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w net.core.bpf_jit_harden=2


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*vsyscall=none(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1vsyscall=none \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.perf_event_paranoid\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.perf_event_paranoid\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.perf_event_paranoid = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.perf_event_paranoid=3


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*debugfs=off(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1debugfs=off \2;g' /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*debugfs=no-mount(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1debugfs=no-mount \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.kexec_load_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.kexec_load_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kexec_load_disabled=1


sed -i 's/^\(\s*user\.max_user_namespaces\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*user\.max_user_namespaces\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'user.max_user_namespaces = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w user.max_user_namespaces=0


sed -i 's/^\(\s*kernel\.unprivileged_bpf_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.unprivileged_bpf_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.unprivileged_bpf_disabled=1


sed -i 's/^\(\s*vm\.unprivileged_userfaultfd\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*vm\.unprivileged_userfaultfd\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'vm.unprivileged_userfaultfd = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w vm.unprivileged_userfaultfd=0


sed -i 's/^\(\s*dev\.tty\.ldisc_autoload\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*dev\.tty\.ldisc_autoload\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'dev.tty.ldisc_autoload = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w dev.tty.ldisc_autoload=0


grep -E '^\s*GRUB_CMDLINE_LINUX\s*=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX=""' >> /etc/default/grub
grep -E '^\s*GRUB_CMDLINE_LINUX\s*="([^"]+\s)*tsx=off(\s|")' /etc/default/grub || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1tsx=off \2;g' /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg
echo "Reboot is needed to apply configuration changes"


sed -ri 's/^(\s*vm\.mmap_min_addr\s*=\s*[1-3]?[0-9]{1,3})/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*vm\.mmap_min_addr\s*=\s*([4-9][0-9]{3}|[0-9]{5,})\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || (echo 'vm.mmap_min_addr = 4096' >> /etc/sysctl.d/FSTEC.conf; sysctl -w vm.mmap_min_addr=4096)


sed -i 's/^\(\s*kernel\.yama\.ptrace_scope\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*kernel\.yama\.ptrace_scope\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'kernel.yama.ptrace_scope = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.yama.ptrace_scope=3


sed -i 's/^\(\s*fs\.protected_symlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*fs\.protected_symlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'fs.protected_symlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_symlinks=1


sed -i 's/^\(\s*fs\.protected_hardlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*fs\.protected_hardlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'fs.protected_hardlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_hardlinks=1


sed -i 's/^\(\s*fs\.protected_fifos\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*fs\.protected_fifos\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'fs.protected_fifos = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_fifos=2


sed -i 's/^\(\s*fs\.protected_regular\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
grep -E "^\s*fs\.protected_regular\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null || echo 'fs.protected_regular = 2' >> /etc/sysctl.d/FSTEC.conf
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
find -L /var/spool/cron/ -type d -perm /0022 ! \( -name crontabs -a -perm -1000 -a ! -perm -0002 \) -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-w '{}';


for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null  | grep -v '^#' | awk '{$1=$2=$3=$4=$5=""; print $0}' | grep -oE '("[^"]+"|[^[:space:]"'\'']+)' | tr -d '"' | while read -r line; do filename=$(which --skip-alias --skip-functions -- "$line" 2>/dev/null); [[ -x "$filename" ]] && chmod go-w "$filename"; done; done


echo "[Manual]" 'Review the /etc/sudoers configuration file and comment out lines which provide excessive access if any.'
read -n 1 -p "Press Enter to continue..."



