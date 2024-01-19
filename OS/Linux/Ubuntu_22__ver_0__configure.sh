#!/usr/bin/env bash


apt update &>/dev/null; apt -s upgrade
apt -s upgrade | grep "The following packages will be upgraded" && (read -p "Do you want to upgrade packages now?[yes][NO]" update; if [ "$update" == "yes" ]; then apt -y upgrade; fi)


echo "[Manual]" 'Configure your package manager repositories according to site policy.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Update your package manager GPG keys in accordance with site policy.'
read -n 1 -p "Press Enter to continue..."


if [[ -z $(grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#') && -z $(systemctl is-enabled tmp.mount 2>/dev/null | grep enabled) ]]; then if [[ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]]; then sed -e '0,/^\s*\[Mount\]/d' /etc/systemd/system/local-fs.target.wants/tmp.mount | egrep "^\s*Where\s*=\s*/tmp(\s|#|$|;)" || printf "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,noexec\n" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; else cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/; fi; systemctl daemon-reload; systemctl --now enable tmp.mount; fi


grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || (sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nodev" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nodev/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nodev" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#] || (sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nosuid" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nosuid/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nosuid" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#] || (sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /tmp)
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*noexec" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,noexec/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=noexec" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#] || sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /var


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


echo "[Manual]" 'Edit /etc/fstab and add or edit the following line:
tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0
Run the following command to remount /dev/shm:
# mount -o remount,noexec,nodev,nosuid /dev/shm'
read -n 1 -p "Press Enter to continue..."


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nodev  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nosuid  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep noexec  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /dev/shm


grep "/media" /etc/fstab  | grep ^[^#] | grep nodev || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nodev $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep nosuid || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,nosuid $each; done


grep "/media" /etc/fstab  | grep ^[^#] | grep noexec || sed -i 's"^\(.*\s[a-zA-Z0-9/_-]*/media[a-zA-Z0-9/_-]*\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
for each in `grep "/media" /etc/fstab  | grep ^[^#] | sed 's;\s\+; ;g' | cut -f2 -d' '`; do mount -o remount,noexec $each; done


df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t


modprobe -r cramfs 2>&1 | grep builtin && (echo "Module cramfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* cramfs .*\)"#\1"g' /etc/modprobe.d/$each; done;echo install cramfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r freevxfs 2>&1 | grep builtin && (echo "Module freevxfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* freevxfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install freevxfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r jffs2 2>&1 | grep builtin && (echo "Module jffs2 is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* jffs2 .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install jffs2 /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfs 2>&1 | grep builtin && (echo "Module hfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r hfsplus 2>&1 | grep builtin && (echo "Module hfsplus is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* hfsplus .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install hfsplus /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r squashfs 2>&1 | grep builtin && (echo "Module squashfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* squashfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install squashfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r udf 2>&1 | grep builtin && (echo "Module udf is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* udf .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install udf /bin/true >> /etc/modprobe.d/disabled_modules.conf)


systemctl --now mask autofs


if [[ -z $(grep -E -i '\svfat\s' /etc/fstab) ]]; then modprobe -r vfat 2>&1 | grep builtin && (echo "Module vfat is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* vfat .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install vfat /bin/true >> /etc/modprobe.d/disabled_modules.conf); else echo "Vfat is used and must be disabled manually if is not required"; read -p "Next" a; fi


modprobe -r usb-storage 2>&1 | grep builtin && (echo "Module usb-storage is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* usb-storage .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install usb-storage /bin/true >> /etc/modprobe.d/disabled_modules.conf)


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
chown root:root "$grubdir/grub.cfg"
chown root:root "$grubdir/user.cfg"
chown root:root "$grubdir/grubenv"


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
chmod og-rwx "$grubdir/grub.cfg"
chmod og-rwx "$grubdir/user.cfg"
chmod og-rwx "$grubdir/grubenv"


grubdir=$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")
if [[ -z $(grep '^set superusers' "$grubdir"/*.cfg) ]] || [[ -z $(grep '^password' "$grubdir"/*.cfg) ]]; then echo "Configuring password for grub"; grub-mkpasswd-pbkdf2; read -p "Enter username for grub authentication:" user; read -p "Enter generated above encrypted password for grub authentication:" pass; echo "set superusers=\"$user\"" >> /etc/grub.d/40_custom; echo "password_pbkdf2 $user $pass" >> /etc/grub.d/40_custom; update-grub; chmod og-rwx "$grubdir/grub.cfg"; chmod og-rwx "$grubdir/user.cfg"; chmod og-rwx "$grubdir/grubenv"; fi


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
apt purge prelink


apt -y install apparmor apparmor-utils


egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub && sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1apparmor=1 security=apparmor \2;g' /etc/default/grub
egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\" >> /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


aa-enforce /etc/apparmor.d/*
apparmor_status | grep "0 processes are unconfined" || (echo "Create or activate profile for unconfined processes and restart them"; read -p "Next" a)


systemctl stop apport.service
systemctl --now disable apport.service


sed -i 's;^\(\s*chargen.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*chargen" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*daytime.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*daytime" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*discard.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*discard" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*echo.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*echo" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*time.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*time" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*shell.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*
sed -i 's;^\(\s*login.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*
sed -i 's;^\(\s*exec.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*rsh" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*rlogin" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*rexec" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*talk.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*
sed -i 's;^\(\s*ntalk.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*talk" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*telnet.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*telnet" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


sed -i 's;^\(\s*tftp.*\)$;#\1;g' /etc/inetd.conf /etc/inetd.d/*

for each in `ls /etc/xinetd.conf /etc/xinetd.d/*`; do \
rm --interactive=never $each.couch_tmp; \
i=0; \
while read -r line || [[ -n "$line" ]]; do \
echo $line | egrep -i "service\s*tftp" && i=1;\
if [ "$i" == "0" ]; then echo $line >> $each.couch_tmp;\
else echo $line | grep '}' && i=0; echo $line | sed 's;disable.*$;disable = yes;g' >> $each.couch_tmp; fi; \
done < $each; \
cp $each.couch_tmp $each; rm --interactive=never $each.couch_tmp; \
done


apt purge xinetd


apt purge openbsd-inetd


read -p "Do you want to use systemd-timesyncd (default), chrony or ntp for time synchronization?[SYSTEMD-TIMESYNCD][chrony][ntp]" timeserv; if [ "$timeserv" == "ntp" ]; then apt-get -y install ntp; systemctl enable ntp; systemctl start ntp; elif [ "$timeserv" == "chrony" ]; then apt-get -y install chrony; systemctl enable chrony; systemctl start chrony; else systemctl enable systemd-timesyncd; systemctl start systemd-timesyncd; fi


if [[ -n $(systemctl is-enabled ntp 2>/dev/null | grep enabled) ]]; then grep -Ei "^(server|pool)\s+[a-z0-9]" /etc/ntp.conf || (read -p "Enter ntp server address:" ntp_server; echo "server $ntp_server" >> /etc/ntp.conf); grep -Ei "^\s*restrict\s+-4\s+default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf; grep -Ei "^\s*restrict\s+-6\s+default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf; grep -Ei "^\s*RUNASUSER\s*=\s*ntp" /etc/init.d/ntp || (sed -ri 's/^(\s*RUNASUSER\s*=)/## \1/' /etc/init.d/ntp; echo "RUNASUSER=ntp" >> /etc/init.d/ntp); else echo "Not applicable - ntp.service is not enabled"; fi


if [[ -n $(systemctl is-enabled chrony 2>/dev/null | grep enabled) ]]; then grep -Ei "^(server|pool)\s+[a-z0-9]" /etc/chrony/chrony.conf || (read -p "Enter ntp server address:" ntp_server; echo "server $ntp_server" >> /etc/chrony/chrony.conf); grep -Ei "^\s*user\s+_chrony" /etc/chrony/chrony.conf || (sed -ri "s/^\s*user\s/## user /" /etc/chrony/chrony.conf; echo "user _chrony" >> /etc/chrony/chrony.conf); else echo "Not applicable - chrony.service is not enabled"; fi


c_cons=no;
dpkg -l xserver-xorg* && (read -p "Attention! Do you really want to purge xserver-xorg* packages?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge xserver-xorg*; fi)


systemctl stop avahi-daaemon.service;
systemctl stop avahi-daemon.socket;
c_cons=no;
dpkg -s avahi-daemon && (read -p "Attention! Do you really want to purge avahi-daemon?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge avahi-daemon; fi)


c_cons=no;
dpkg -s cups && (read -p "Attention! Do you really want to purge cups?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge cups; fi)


c_cons=no;
dpkg -s isc-dhcp-server && (read -p "Attention! Do you really want to purge isc-dhcp-server?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge isc-dhcp-server; fi)
c_cons=no;
dpkg -s isc-dhcp-server6 && (read -p "Attention! Do you really want to purge isc-dhcp-server6?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge isc-dhcp-server6; fi)


c_cons=no;
dpkg -s slapd && (read -p "Attention! Do you really want to purge slapd?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge slapd; fi)


c_cons=no;
dpkg -s nfs-kernel-server && (read -p "Attention! Do you really want to purge nfs-kernel-server?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge nfs-kernel-server; fi)


c_cons=no;
dpkg -s bind9 && (read -p "Attention! Do you really want to purge bind9?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge bind9; fi)


c_cons=no;
dpkg -s vsftpd && (read -p "Attention! Do you really want to purge vsftpd?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge vsftpd; fi)


c_cons=no;
dpkg -s apache2 && (read -p "Attention! Do you really want to purge apache2?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge apache2; fi)


c_cons=no;
dpkg -s dovecot-imapd && (read -p "Attention! Do you really want to purge dovecot-imapd?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge dovecot-imapd; fi)
c_cons=no;
dpkg -s dovecot-pop3d && (read -p "Attention! Do you really want to purge dovecot-pop3d?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge dovecot-pop3d; fi)


c_cons=no;
dpkg -s samba && (read -p "Attention! Do you really want to purge samba?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge samba; fi)


c_cons=no;
dpkg -s squid && (read -p "Attention! Do you really want to purge squid?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge squid; fi)


c_cons=no;
dpkg -s snmpd && (read -p "Attention! Do you want to purge snmpd?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge snmpd; fi)


if [ -e /etc/postfix ]; then c_cons=no; read -p "Do you want to reconfigure Postfix for local-only use?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then 
sed -i 's/^\s*inet_interfaces/#  inet_interfaces/g' /etc/postfix/main.cf;
echo inet_interfaces = loopback-only >> /etc/postfix/main.cf;
systemctl restart postfix;
fi;
fi

if [ -e /etc/exim4 ]; then c_cons=no; read -p "Do you want to reconfigure Exim for local-only use?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then 
sed -i 's/^\s*dc_eximconfig_configtype/## dc_eximconfig_configtype/' /etc/exim4/update-exim4.conf.conf;
echo "dc_eximconfig_configtype='local'" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_readhost/## dc_readhost/' /etc/exim4/update-exim4.conf.conf;
echo "dc_readhost=''" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_relay_domains/## dc_relay_domains/' /etc/exim4/update-exim4.conf.conf;
echo "dc_relay_domains=''" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_minimaldns/## dc_minimaldns/' /etc/exim4/update-exim4.conf.conf;
echo "dc_minimaldns='false'" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_relay_nets/## dc_relay_nets/' /etc/exim4/update-exim4.conf.conf;
echo "dc_relay_nets=''" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_smarthost/## dc_smarthost/' /etc/exim4/update-exim4.conf.conf;
echo "dc_smarthost=''" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_use_split_config/## dc_use_split_config/' /etc/exim4/update-exim4.conf.conf;
echo "dc_use_split_config='false'" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_hide_mailname/## dc_hide_mailname/' /etc/exim4/update-exim4.conf.conf;
echo "dc_hide_mailname=''" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_mailname_in_oh/## dc_mailname_in_oh/' /etc/exim4/update-exim4.conf.conf;
echo "dc_mailname_in_oh='true'" >> /etc/exim4/update-exim4.conf.conf;
sed -i 's/^\s*dc_localdelivery/## dc_localdelivery/' /etc/exim4/update-exim4.conf.conf;
echo "dc_localdelivery='mail_spool'" >> /etc/exim4/update-exim4.conf.conf;
fi;
fi


c_cons=no;
dpkg -s rsync && (read -p "Attention! Do you really want to purge rsync?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge rsync; fi)


c_cons=no;
dpkg -s nis && (read -p "Attention! Do you want to purge nis?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge nis; fi)


c_cons=no;
dpkg -s ypbind-mt && (read -p "Attention! Do you want to purge nis-client?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge ypbind-mt; fi)


apt-get -y purge rsh-client rsh-redone-client


apt-get -y purge talk


apt-get -y purge telnet


apt-get -y purge ldap-utils


echo "[Manual]" 'Run the following command to remove the package containing the service:
# apt purge <package_name>
OR If required packages have a dependency:
Run the following command to stop and mask the service:
# systemctl --now mask <service_name>'
read -n 1 -p "Press Enter to continue..."


chmod go-rwx /usr/bin/gcc /usr/bin/cc


echo "[Manual]" 'All export NFS necessary must be with the respective
restrictions of writing, and limited to the IPs of the authorized
customers in the etc/exports:
/directory archive/client1(ro), client2(rw)'
read -n 1 -p "Press Enter to continue..."


grep "[[:space:]]nfs[[:space:]]" /etc/fstab | grep ^[^#] | grep -v "nosuid" && sed -i 's;^\(.*\snfs\s\+[a-zA-Z0-9,]\+\)\(\s\+.*\)$;\1,nosuid\2;g' /etc/fstab


sed -i 's/^\(\s*r[ow]community\s\+public\)/#\1/g' /etc/snmp/snmpd.conf
sed -i 's/^\(\s*r[ow]community\s\+private\)/#\1/g' /etc/snmp/snmpd.conf


echo "[Manual]" 'If timesyncd is enabled:
# systemctl status systemd-timesyncd
Edit the file /etc/systemd/timesyncd.conf and add/modify the following lines:
NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org
#Servers listed should be In Accordence With Local Policy
FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org
#Servers listed should be In Accordence With Local Policy
RootDistanceMaxSec=1
#should be In Accordence With Local Policy
Run the following commands to restart systemd-timesyncd.service:
# systemctl restart systemd-timesyncd.service
# timedatectl set-ntp true'
read -n 1 -p "Press Enter to continue..."


c_cons=no;
dpkg -s rpcbind && (read -p "Do you want to purge rpcbind?[yes][NO]" c_cons; if [ "$c_cons" == "yes" ]; then apt purge rpcbind; fi)


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


grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub | grep "ipv6.disable=1" || sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1ipv6.disable=1 \2;g' /etc/default/grub
grep "^GRUB_CMDLINE_LINUX=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"ipv6.disable=1\" >> /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


apt-get -y install tcpd


echo "[Manual]" 'Run the following command to create /etc/hosts.allow: 
# echo "ALL: <net>/<mask>, <net>/<mask>, ..." >/etc/hosts.allow 
where each <net>/<mask> combination (for example, "192.168.1.0/255.255.255.0") represents one network block in use by your organization that requires access to this system. Contents of the /etc/hosts.allow file will vary depending on your network configuration.'
read -n 1 -p "Press Enter to continue..."


update=NO;
read -p 'Do you want to configure /etc/hosts.deny now ("ALL: ALL" will be added to hosts.deny and access to host may be lost if /etc/hosts.allow is not configured properly)?[yes][NO]' update; if [ "$update" == "yes" ]; then echo "ALL: ALL" >> /etc/hosts.deny; fi


chown root:root /etc/hosts.allow 
chmod 644 /etc/hosts.allow


chown root:root /etc/hosts.deny 
chmod u-x,go-wx /etc/hosts.deny


modprobe -r dccp 2>&1 | grep builtin && (echo "Module dccp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* dccp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install dccp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r sctp 2>&1 | grep builtin && (echo "Module sctp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* sctp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install sctp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r rds 2>&1 | grep builtin && (echo "Module rds is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* rds .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install rds /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r tipc 2>&1 | grep builtin && (echo "Module tipc is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* tipc .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install tipc /bin/true >> /etc/modprobe.d/disabled_modules.conf)


if command -v nmcli >/dev/null 2>&1 ; then nmcli radio all off; else if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then drivers=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver)"; done | sort -u); for dm in $drivers; do echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf; done; fi; fi


echo "[Manual]" 'The DNS servers listed in
/etc/resolv.conf file must be those managed locally by the internal administrators.'
read -n 1 -p "Press Enter to continue..."


rm -f /etc/hosts.equiv


sed -i 's/^\s*max_log_file\s*=\s*.*$/max_log_file = 50/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file\s*=\s*50\s*$" /etc/audit/auditd.conf || echo "max_log_file = 50" >> /etc/audit/auditd.conf


sed -i 's/^\s*space_left_action\s*=.*$/space_left_action = email/g' /etc/audit/auditd.conf
egrep "^\s*space_left_action\s*=\s*email\s*$" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i 's/^\s*action_mail_acct\s*=.*$/action_mail_acct = root/g' /etc/audit/auditd.conf
egrep "^\s*action_mail_acct\s*=\s*root\s*$" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf


sed -i 's/^\s*max_log_file_action\s*=.*$/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file_action\s*=\s*keep_logs\s*$" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf


apt -y install auditd
systemctl --now enable auditd


egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub && sed -i 's;^\(GRUB_CMDLINE_LINUX="\)\(.*\)$;\1audit=1 \2;g' /etc/default/grub
egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"audit=1\" >> /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub | grep -E -v "audit_backlog_limit=(819[2-9]|8[2-9][0-9]{2}|9[0-9]{3}|[1-9][0-9]{4,})" && (sed -ri 's/\saudit_backlog_limit=[0-9]+//g' /etc/default/grub; sed -ri 's/^(GRUB_CMDLINE_LINUX=")(.*)$/\1audit_backlog_limit=8192 \2/' /etc/default/grub)
egrep "^\s*GRUB_CMDLINE_LINUX\s*=" /etc/default/grub || echo GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\" >> /etc/default/grub
update-grub; chown root:root /boot/grub/grub.cfg; chmod og-rwx /boot/grub/grub.cfg


lscpu 2>&1 | grep "Architecture" | grep 64 || ( egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/group\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/passwd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/gshadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/shadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/security/opasswd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


lscpu 2>&1 | grep "Architecture" | grep 64 || (egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/networks\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/networks -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
lscpu 2>&1 | grep "Architecture" | grep 64 && (egrep "^-a\s*exit,always\s*-F\s*arch=b64\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/networks\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/networks -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/selinux/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s+/usr/share/selinux/\s+-p\s+wa\s+-k\s+MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/share/selinux/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/apparmor/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/apparmor/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/apparmor.d/\s*-p\s*wa\s*-k\s*MAC-policy" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/apparmor.d/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/log/faillog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/faillog -p wa -k logins" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/var/log/lastlog\s*-p\s*wa\s*-k\s*logins" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/lastlog -p wa -k logins" /etc/audit/rules.d/audit.rules)
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


uname -i 2>&1 | grep 64 || (egrep "^-a\s+(exit,always|always,exit)\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=4294967295 -k actions" /etc/audit/rules.d/audit.rules)) 
uname -i 2>&1 | grep 64 && (egrep "^-a\s+(exit,always|always,exit)\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=4294967295 -k actions" /etc/audit/rules.d/audit.rules); egrep "^-a\s+(exit,always|always,exit)\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=4294967295 -k actions" /etc/audit/rules.d/audit.rules))
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

# special files
if [[ $(egrep "^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs" /etc/audit/rules.d/audit.rules) ]]; then sed -ri "s;^\s*-w\s+/var/log/journal\s[^#]*-k\s+access-logs;-w /var/log/journal -p rwa -k access-logs;" /etc/audit/rules.d/audit.rules; else audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/journal -p rwa -k access-logs" /etc/audit/rules.d/audit.rules; fi

restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


for file in `find /etc/pam.d -type f`; do egrep "^-w\s*$file\s*-p\s*wa\s*-k\s*change-auth-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p wa -k change-auth-cfg" /etc/audit/rules.d/audit.rules); done
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/audit/auditd.conf\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/auditd.conf -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/rules.d/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/rules.d/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


grep "^\s*[^#]" /etc/audit/rules.d/audit.rules | tail -1 | egrep "^-e\s+2" || (sed -i "s;^-e\s\+;#-e ;g" /etc/audit/rules.d/audit.rules; echo "-e 2" >> /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


dpkg -s rsyslog || apt -y install rsyslog
systemctl --now enable rsyslog


echo "[Manual]" 'Edit the following lines in the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files as 
appropriate for your environment: 
*.emerg :omusrmsg:* 
auth,authpriv.* /var/log/auth.log
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
# systemctl restart rsyslog'
read -n 1 -p "Press Enter to continue..."


sed -ri "s/^\s*\\\$FileCreateMode\s+[0-9]+/\$FileCreateMode 0640/" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
egrep "^\s*\\\$FileCreateMode\s+0?[0246][04]0" /etc/rsyslog.conf /etc/rsyslog.d/*.conf || echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf


grep "^\*\.\*[[:space:]]*@@" /etc/rsyslog.conf || (read -p "Enter IP address or domain name of central logging server for syslog:" logserv; echo "*.* @@$logserv" >> /etc/rsyslog.conf; pkill -HUP rsyslogd)


read -p "Is this host designated central logging server?[y][N]" logserver;
if [[ "$logserver" != "y" && "$logserver" != "Y" ]]; then sed -i "s;^\s*\(\$ModLoad\s\+\(imtcp\|/[^#]*imtcp\)\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; sed -i "s;^\s*\(\$InputTCPServerRun\s\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; systemctl restart rsyslog; fi


find /var/log -type f ! -name wtmp ! -name wtmp.* ! -name btmp ! -name btmp.* ! -name lastlog ! -name lastlog.* | xargs -d$'\n' -I {} chmod g-wx,o-rwx '{}'
chmod ug-x,o-wx /var/log/lastlog 2>/dev/null
chmod ug-x,o-rwx /var/log/btmp 2>/dev/null
chmod ug-x,o-wx /var/log/wtmp 2>/dev/null


apt install aide aide-common
echo "Configure AIDE as appropriate for your environment"
read -p "Ready" a
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db


(crontab -u root -l 2>/dev/null | egrep -i "^[0-9]+\s+[0-9]+\s+\*\s+\*\s+\*\s+/usr/bin/aide.*\s+--check") || (crontab -u root -l 2>/dev/null; echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check") | sort - | uniq - | crontab -u root -


read -ra qqq <<< "/var/log/auth.log /var/log/boot.log /var/log/kern.log /var/log/mail.log /var/log/syslog /var/log/dpkg.log"
for i in "${qqq[@]}"; do grep $i /etc/logrotate.conf /etc/logrotate.d/* || echo -e "$i {\ncreate 0600 root\nrotate 4\nweekly\nmissingok\nnotifempty\ncompress\ndelaycompress\npostrotate\nreload rsyslog >/dev/null 2>&1 || true\nendscript\n}\n" >> /etc/logrotate.conf; done


for f in `ls /etc/logrotate.conf /etc/logrotate.d/*`; do i=0; rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $line | egrep -i "/utmp|/wtmp|/btmp" && i=1; if [ "$i" == "0" ]; then echo $line | grep "{" && k=0; echo $line | grep "}" && if [ "$k" == "0" ]; then echo "create 0600 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 600 ;' >> $f.couch_tmp; else echo $line | grep "{" && k=0; echo $line | grep "}" && i=0&& if [ "$k" == "0" ]; then echo "create 0640 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 640 ;' >> $f.couch_tmp; fi; done < $f; yes | cp $f.couch_tmp $f; rm --interactive=never $f.couch_tmp; done


egrep "^\s*Defaults\s+syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" /etc/sudoers || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*ForwardToSyslog\s*=" | tail -n 1 | egrep "^\s*ForwardToSyslog\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*ForwardToSyslog\s/## ForwardToSyslog /g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nForwardToSyslog=yes\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Compress\s*=" | tail -n 1 | egrep "^\s*Compress\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*Compress\s/## Compress/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nCompress=yes\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Storage\s*=" | tail -n 1 | egrep "^\s*Storage\s*=\s*persistent(\s|#|$)" || ( sed -i "s/^\s*Storage\s/## Storage/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nStorage=persistent\n/' /etc/systemd/journald.conf; systemctl restart systemd-journald)


for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | grep -Ei '(^|\s)file=".+"'); do if [[ "$each" =~ ^[^#]*[Ff]ile=\"(.*)\" ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done
for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "^.+\..+\s+-?/.+$" | grep -v -i IncludeConfig); do if [[ "$each" =~ ^-?(/[^:;]+)[^:]*$ ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done


systemctl --now enable cron


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


read -p "Do you want to restrict cron access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/cron.allow; fi
read -p "Do you want to restrict at access to root only?[yes][NO]" update; if [ "$update" == "yes" ]; then echo root > /etc/at.allow; fi


rm /etc/cron.deny
rm /etc/at.deny
if [ ! -e "/etc/cron.allow" ]; then echo root > /etc/cron.allow; fi
if [ ! -e "/etc/at.allow" ]; then echo root > /etc/at.allow; fi
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow


dpkg -s libpam-pwquality 1>/dev/null 2>/dev/null || apt-get -y install libpam-pwquality
PTF=/etc/pam.d/common-password; 
grep -E '^\s*password\s+requisite\s+pam_pwquality\.so' $PTF || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password requisite pam_pwquality.so retry=3\n&/' $PTF; 
[[ -z $(grep -E '^\s*password\s+requisite\s+pam_pwquality\.so.*\s+retry=[123](\s|#|$)' $PTF) ]] && (sed -ri '/pam_pwquality\.so/s/\sretry=\S+//g' $PTF; sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so.*)$/\1 retry=3/' $PTF);
grep -E '^\s*minlen\s*=\s*[0-7](\s|$)' /etc/security/pwquality.conf && sed -ri 's/^(\s*minlen\s*=\s*[0-7])(\s|$)/## \1/' /etc/security/pwquality.conf
grep -E '^\s*dcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*dcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*dcredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo dcredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ucredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ucredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ucredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo ucredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ocredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ocredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ocredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo ocredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*lcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*lcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*lcredit\s*=)(\s|$)/## \1/' /etc/security/pwquality.conf; echo lcredit=-1 >> /etc/security/pwquality.conf)


for FN in common-auth; do 
  target_file="/etc/pam.d/${FN}";
  grep -E '^\s*auth\s+required\s+pam_faillock.so\s+preauth(\s|$)' "$target_file" || (rm -f "$FN.couch_tmp" 2>/dev/null; i=0; while read -r line || [[ -n "$line" ]]; do if [[ "$i" -eq "0" ]]&&[[ $(echo "$line" | egrep -i '^\s*auth\s[^#]*\s+pam_unix\.so(\s|#|$)') ]]; then echo "auth required pam_faillock.so preauth silent" >> "$FN.couch_tmp"; i=1; fi; echo "$line" >> "$FN.couch_tmp"; done < "$target_file"; yes | cp "$FN.couch_tmp" "$target_file"; rm -f "$FN.couch_tmp" 2>/dev/null);
  grep -E '^\s*auth\s+[^#]*\s+pam_faillock.so\s+authfail(\s|$)' "$target_file" || (rm -f "$FN.couch_tmp" 2>/dev/null; i=0; while read -r line || [[ -n "$line" ]]; do echo "$line" >> "$FN.couch_tmp"; if [[ "$i" -eq "0" ]]&&[[ $(echo "$line" | egrep -i '^\s*auth\s[^#]*\s+pam_unix\.so(\s|#|$)') ]]; then echo 'auth [default=die] pam_faillock.so authfail' >> "$FN.couch_tmp"; echo 'auth sufficient pam_faillock.so authsucc' >> "$FN.couch_tmp"; i=1; fi; done < "$target_file"; yes | cp "$FN.couch_tmp" "$target_file"; rm -f "$FN.couch_tmp" 2>/dev/null);
done;
grep -P '^\s*account\s+required\s+pam_faillock\.so(\s|$)' /etc/pam.d/common-account || echo 'account required pam_faillock.so' >> /etc/pam.d/common-account;
touch /etc/security/faillock.conf;
grep -P '^\s*deny\s*=\s*[1-5](\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*deny\s*=)/## \1/' /etc/security/faillock.conf; echo "deny = 5" >> /etc/security/faillock.conf);
grep -P '^\s*unlock_time\s*=\s*(7[2-9]\d\d|[89]\d\d\d|\d{5,}|0)(\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*unlock_time\s*=)/## \1/' /etc/security/faillock.conf; echo "unlock_time = 7200" >> /etc/security/faillock.conf);


PTF=/etc/pam.d/common-password;
grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so' $PTF || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password required pam_pwhistory.so remember=5\n&/' $PTF; 
[[ -z $(grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so.*\sremember=([5-9]|[1-9][0-9]+)' $PTF) ]] && (sed -ri '/^\s*password\s+(requisite|required)\s+pam_pwhistory\.so/s/\sremember=\S+//g' $PTF; sed -ri 's/^\s*(password\s+(requisite|required)\s+pam_pwhistory\.so.*)$/\1 remember=5/' $PTF) || true


echo "[Manual]" 'NOTE: Pay special attention to the configuration. Incorrect configuration can cause system lock outs. This is example configuration. You configuration may differ based on previous changes to the files. 
PAM 
Edit the /etc/pam.d/common-password file and ensure that no hashing algorithm option for pam_unix.so is set. Example:
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass remember=5
Login definitions 
Edit /etc/login.defs and ensure that ENCRYPT_METHOD is set to yescrypt:
ENCRYPT_METHOD yescrypt
Also the SHA512 is strong enough algorithm. If the SHA512 is configured to encrypt passwords, the system is compliant.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If some users have passwords with out of date hashing algorithms, administrator can force password changing for them to update used hashing algorithm (new password will be hashed with the configured in the system algorithm):
# passwd --expire <users>'
read -n 1 -p "Press Enter to continue..."


sed -i 's/^\s*PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs
echo PASS_MAX_DAYS 90 >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do if [[ -n $(echo "__technology_accounts__" | grep -E "(^|;)$x(;|$)") ]]; then chage --maxdays 365 $x; else chage --maxdays 90 $x; fi; done


sed -i "s;^\(\s*PASS_MIN_DAYS\s\);#\1;g" /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --mindays 1 $x; done


sed -i "s;^\(\s*PASS_WARN_AGE\s\);#\1;g" /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs
for x in `cut -d: -f1 /etc/passwd`; do chage --warndays 7 $x; done


useradd -D -f 30
egrep -v "^\+" /etc/shadow | awk -F: '($2!="" && $2!="*" && $2!="!") {system("chage --inactive 30 "$1)}'


awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done


usermod -g 0 root


sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/bash.bashrc
sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' /etc/profile /etc/profile.d/*.sh

PTF=/etc/pam.d/common-session;
grep -E '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so' $PTF || sed -ri '0,/^\s*session\s+(\S+\s+)+pam_unix\.so.*$/s/^\s*session\s+(\S+\s+)+pam_unix\.so.*$/session optional pam_umask.so\n&/' $PTF;

sed -i "s;^\(\s*UMASK\s\);## \1;g" /etc/login.defs
echo "UMASK 077" >> /etc/login.defs


read -p "Enter timeout in seconds (default is 900):" idle_timeout;
if [ -z "$idle_timeout" ]; then idle_timeout=900; fi

sed -i 's/TMOUT=[0-9]\+/TMOUT='"${idle_timeout}"'/g' /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
sed -i 's/\(if\s\+\[\s\+!\s\+"$(\s*readonly\s\+-p\s*|\s*egrep\s\+"declare\s\+-\[a-z\]+\s\+TMOUT="\s*)"\s\+\]\s*;\s*then\s\+\)\?readonly\s\+TMOUT\(=[0-9]\+\)\?\(\s*;\s*export\s\+TMOUT\s*\)\?\(\s*;\s*fi\)\?/if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'\3; fi/g' /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/bash.bashrc || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/bash.bashrc 
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> /etc/profile.d/couch.sh
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/bash.bashrc || echo "export TMOUT" >> /etc/bash.bashrc
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" /etc/profile /etc/profile.d/*.sh || echo "export TMOUT" >> /etc/profile.d/couch.sh
if [ -n "$ENV" ]; then \
sed -i 's/TMOUT=[0-9]\+/TMOUT='"${idle_timeout}"'/g' "$ENV";
sed -i 's/\(if\s\+\[\s\+!\s\+"$(\s*readonly\s\+-p\s*|\s*egrep\s\+"declare\s\+-\[a-z\]+\s\+TMOUT="\s*)"\s\+\]\s*;\s*then\s\+\)\?readonly\s\+TMOUT\(=[0-9]\+\)\?\(\s*;\s*export\s\+TMOUT\s*\)\?\(\s*;\s*fi\)\?/if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'\3; fi/g' "$ENV";
egrep "^[^#]*readonly\s+TMOUT=${idle_timeout}(\s|;|#|$)" "$ENV" || echo 'if [ ! "$(readonly -p | egrep "declare -[a-z]+ TMOUT=")" ]; then readonly TMOUT='"${idle_timeout}"'; fi' >> "$ENV";
egrep "^[^#]*export\s+TMOUT(\s|;|#|$)" "$ENV" || echo "export TMOUT" >> "$ENV";
fi

idle_minutes=$(expr ${idle_timeout} / 60)
if [ -e "/bin/csh" -o -e "/bin/tcsh" ]; then egrep "^[^#]*set\s+-r\s+autologout\s+${idle_minutes}(\s|;|#|$)" /etc/csh.cshrc || echo "( set autologout | & grep 'read-only' ) || set -r autologout ${idle_minutes}" >> /etc/csh.cshrc; fi


PTF=/etc/pam.d/su; 
grep -E '^\s*auth\s+required\s+pam_wheel\.so' $PTF || sed -ri '0,/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s+pam_rootok\.so/s/^\s*auth\s+(sufficient|\[success=([0-9]+|ok).*)\s+pam_rootok\.so.*$/&\nauth required pam_wheel.so use_uid/' $PTF; 
[[ -z $(grep -E '^\s*auth\s+required\s+pam_wheel\.so.*\s+use_uid(\s|#|$)' $PTF) ]] && sed -ri 's/^\s*(auth\s+required\s+pam_wheel\.so.*)$/\1 use_uid/' $PTF || true;


echo "[Manual]" 'Remove unnecessary aliases from the /etc/aliases file. Entries like uudecode and decode must be removed, as well as entries that refer to automated scripts.'
read -n 1 -p "Press Enter to continue..."


apt -y install sudo


grep -Ei '^\s*Defaults\s+([^#]+\s)?use_pty' /etc/sudoers /etc/sudoers.d/* || echo "Defaults use_pty" >> /etc/sudoers


grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/* || (read -p "Enter path for sudo log file: [default /var/log/sudo.log]" c_sudo_log_path;
if [ -z "$c_sudo_log_path" ]; then c_sudo_log_path=/var/log/sudo.log; fi; echo "Defaults logfile=\"${c_sudo_log_path}\"" >> /etc/sudoers)


echo "Authorized users only. All activity may be monitored and reported." > /etc/motd


echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue


echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net


chown root:root /etc/motd
chmod u-x,go-wx /etc/motd


chown root:root /etc/issue
chmod u-x,go-wx /etc/issue


chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net


if [ -e /etc/gdm3 ]; then egrep "^\s*\[org/gnome/login-screen\]" /etc/gdm3/greeter.dconf-defaults || printf "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'\ndisable-user-list=true\n" >> /etc/gdm3/greeter.dconf-defaults; egrep "^\s*banner-message-enable\s*=\s*true" /etc/gdm3/greeter.dconf-defaults  || sed -i 's;\(^\s*[org/gnome/login-screen].*$\);\1\nbanner-message-enable=true;' /etc/gdm3/greeter.dconf-defaults; egrep "^\s*banner-message-text\s*=" /etc/gdm3/greeter.dconf-defaults | grep "Authorized access only. All activity may be logged and monitored" || sed -i "s;\(^\s*[org/gnome/login-screen].*$\);\1\nbanner-message-text='Authorized access only. All activity may be logged and monitored';" /etc/gdm3/greeter.dconf-defaults; egrep "^\s*disable-user-list\s*=\s*true" /etc/gdm3/greeter.dconf-defaults  || sed -i 's;\(^\s*[org/gnome/login-screen].*$\);\1\ndisable-user-list=true;' /etc/gdm3/greeter.dconf-defaults; dpkg-reconfigure gdm3; fi


echo "[Manual]" 'Correct any discrepancies found and rerun the audit until output is clean or risk is mitigated or accepted:
# dpkg --verify

Notes: Since packages and important files may change with new updates and releases, it is recommended to verify everything, not just a finite list of files. This can be a time consuming task and results may depend on site policy therefore it is not a scorable benchmark item, but is provided for those interested in additional security measures. Some of the recommendations of this benchmark alter the state of files audited by this recommendation. The audit command will alert for all changes to a file permissions even if the new state is more secure than the default.'
read -n 1 -p "Press Enter to continue..."


/bin/chown root:root /etc/passwd


/bin/chmod u-x,go-wx /etc/passwd


/bin/chown root:shadow /etc/shadow


/bin/chmod o-rwx,g-wx /etc/shadow


/bin/chown root:root /etc/group


/bin/chmod u-x,go-wx /etc/group


/bin/chown root:shadow /etc/gshadow


/bin/chmod u-x,g-wx,o-rwx /etc/gshadow


/bin/chown root:root /etc/passwd-


/bin/chmod u-x,go-wx /etc/passwd-


/bin/chown root:shadow /etc/shadow-


/bin/chmod u-x,g-wx,o-rwx /etc/shadow-


/bin/chown root:root /etc/group-


/bin/chmod u-x,go-wx /etc/group-


chown root:shadow /etc/gshadow-


/bin/chmod o-rwx,g-wx /etc/gshadow-


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


cat /etc/shadow | awk -F: '( "$2" == "" ) {system("passwd -l "$1); print "User $1 has been locked because of empty password"}'


cat /etc/shadow | awk -F: '( $2 == "" ) {system("passwd -l "$1); print "User "$1" has been locked because of empty password"}'


sed -i "s;^+;#+;g" /etc/passwd


sed -i "s;^+;#+;g" /etc/shadow


sed -i "s;^+;#+;g" /etc/group


p=`cat /etc/passwd | awk -F: '( $3 == 0 && $1 != "root" ) { print "Remove user "$1" or assign to him a new UID"}'`
if [ -n "$p" ]; then echo $p; read -p "Next" a; fi


q=0
if [ "`/bin/echo $PATH | /bin/grep :: `" != "" ]; then /bin/echo "Warning:Empty Directory in PATH (::)"; q=1; fi; if [ "`/bin/echo $PATH | /bin/grep :$`" != "" ]; then /bin/echo "Warning:Trailing : in PATH"; q=1; fi; p=`/bin/echo $PATH | /bin/sed -e "s/::/:/" -e "s/:\$//" -e "s/:/ /g"`; set -- $p; while [ "$1" != "" ]; do /bin/echo "Directory:$1"; if [ "$1" == "." ]; then /bin/echo "Warning:PATH contains ."; q=1; shift; continue; fi; if [ -d $1 ]; then dirperm=`/bin/ls -ldH $1 | /usr/bin/cut -f1 -d" "`; /bin/echo "Directory rights:$dirperm"; if [ `/bin/echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then /bin/echo "Warning:Group Write permissions on directory $1"; q=1; fi; if [ `/bin/echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then /bin/echo "Warning:Other Write permissions set on directory $1"; q=1; fi; dirown=`/bin/ls -ldH $1 | /usr/bin/cut -d" " -f3`; /bin/echo "Owner:$dirown"; if [ "$dirown" != "root" ]; then /bin/echo "Warning:$1 is not owned by root"; q=1; fi; else /bin/echo "Warning:$1 is not a directory"; q=1; fi; shift; done
if [ "$q" == "1" ]; then echo "Correct returned warnings"; read -p "Next" a; fi


grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do if [ ! -d "$dir" ]; then mkdir "$dir"; chown $user "$dir"; chmod go-rwx "$dir"; fi; done


cat /etc/passwd | egrep -v "^(halt:|sync:|shutdown:)" | awk -F: '( $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do chmod g-w "$dir"; chmod o-rwx "$dir"; done


cat /etc/passwd | egrep -v '^(halt|sync|shutdown|nfsnobody|nobody):' | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7!="/sbin/nologin") { print $1 " " $6 }' | while read user dir; do if [ -d "$dir" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then chown $user "$dir"; fi; fi; done


cat /etc/passwd | egrep -v "^(halt:|sync:|shutdown:)" | awk -F: '( $7 != "'"$(which nologin)"'" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do for file in `ls -d "$dir"/.[A-Za-z0-9]* 2>/dev/null`; do chmod -R go-w "$file"; done; done


cat /etc/passwd | awk -F: '{print $6}' | while read dir; do if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then mv "$dir/.forward" "$dir/.forward.old"; fi; done


couch_ifs="$IFS";IFS=$'\n';
for dir in $(awk -F: '{ print $6 }' /etc/passwd); do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then read -p "Do you want to remove $dir/.netrc file?[YES][no]" co_ans; if [[ "$co_ans" =~ [Nn][oO]? ]]; then chmod go-rwx "$dir/.netrc"; else rm -f "$dir/.netrc"; fi; fi; done
IFS="$couch_ifs"


cat /etc/passwd | awk -F: '{print $6}' | while read dir; do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then chmod go-rwx "$dir/.netrc";fi; done


cat /etc/passwd | awk -F: '{print $6}' | while read dir; do if [ ! -h "$dir/.rhosts" -a -f "$dir/.rhosts" ]; then mv "$dir/.rhosts" "$dir/.rhosts.old"; fi; done


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


p="$(cat /etc/group | awk -F: '( $1 == "shadow" && $4 != "" ) { print "Remove all users from the shadow group, and change the primary group of any users with shadow as their primary group."}')"
if [ -n "$p" ]; then echo $p; read -p "Next" a; fi


awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do usermod -L "$user"; done


sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd



