#!/usr/bin/env bash


echo "[Manual]" 'Configure /etc/fstab with separate partition for /tmp. Example:
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
OR
Run the following commands to enable systemd /tmp mounting.
Run the following command to create the file /etc/systemd/system/tmp.mount if it doesn'\''t exist:
# [ ! -f /etc/systemd/system/tmp.mount ] && cp -v /usr/lib/systemd/system/tmp.mount /etc/systemd/system/
Edit the [Mount] section in /etc/systemd/system/tmp.mount to configure the /tmp mount:
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


if [[ -n $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /tmp; fi
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nodev" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nodev/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nodev" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


if [[ -n $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /tmp; fi
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*nosuid" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,nosuid/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=nosuid" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


if [[ -n $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/tmp/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /tmp; fi
if [ -e /etc/systemd/system/local-fs.target.wants/tmp.mount ]; then grep -Ei "^\s*Options=[^#]*noexec" /etc/systemd/system/local-fs.target.wants/tmp.mount || sed -i --follow-symlinks "s/^\(\s*[oO]ptions=\S*\)/\1,noexec/" /etc/systemd/system/local-fs.target.wants/tmp.mount; grep -Ei "^\s*Options=" /etc/systemd/system/local-fs.target.wants/tmp.mount || echo "Options=noexec" >> /etc/systemd/system/local-fs.target.wants/tmp.mount; systemctl daemon-reload; systemctl restart tmp.mount; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /var; fi


if [[ -n $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /var; fi


if [[ -n $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /var; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /var/tmp; fi


if [[ -n $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /var/tmp; fi


if [[ -n $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/tmp/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/tmp/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /var/tmp; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /var/log; fi


if [[ -n $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /var/log; fi


if [[ -n $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /var/log; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /var/log/audit. 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep noexec | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab; mount -o remount,noexec /var/log/audit; fi


if [[ -n $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /var/log/audit; fi


if [[ -n $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/var/log/audit/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/var/log/audit/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /var/log/audit; fi


echo "[Manual]" 'For new installations, during installation create a custom partition setup and specify a separate partition for /home . 
For systems that were previously installed use the Logical Volume Manager (LVM) to create partitions and configure /etc/fstab as appropriate.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep nodev | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab; mount -o remount,nodev /home; fi


if [[ -n $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep nosuid | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab; mount -o remount,nosuid /home; fi


rpm -q quota || dnf install -y quota; 
if [[ -n $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep usrquota | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,usrquota\2"g' /etc/fstab; mount -o remount /home; quotacheck -cugv /home; restorecon /home/aquota.user; quotaon -vug /home; fi


rpm -q quota || dnf install -y quota; 
if [[ -n $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep ^[^#]) ]] && [[ -z $(grep -E "[[:space:]]/home/?[[:space:]]" /etc/fstab | grep grpquota | grep ^[^#]) ]]; then sed -i 's"^\(.*\s/home/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,grpquota\2"g' /etc/fstab; mount -o remount /home; quotacheck -cugv /home; restorecon /home/aquota.group; quotaon -vug /home; fi


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nodev  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nodev\2"g' /etc/fstab
mount -o remount,nodev /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep noexec  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm/?\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,noexec\2"g' /etc/fstab
mount -o remount,noexec /dev/shm


grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep ^[^#] || echo -e "tmpfs\t/dev/shm\ttmpfs\tdefaults,noexec,nodev,nosuid\t0\t0" >> /etc/fstab
grep -E "[[:space:]]/dev/shm/?[[:space:]]" /etc/fstab | grep nosuid  | grep ^[^#] || sed -i 's"^\(.*\s/dev/shm\s\+\w\+\s\+[a-zA-Z0-9,]\+\)\(\s.*\)$"\1,nosuid\2"g' /etc/fstab
mount -o remount,nosuid /dev/shm


grep ^[^#] /etc/fstab | while read -r _ mountpoint _ options; do if [[ "$mountpoint" == */media* ]] && [[ "$options" != *nodev* ]]; then sed -i "s#^\(.*\s${mountpoint}\s\+\w\+\s\+[^[:space:]]\+\)\(\s.*\)\$#\1,nodev\2#g" /etc/fstab; fi; done


grep ^[^#] /etc/fstab | while read -r _ mountpoint _ options; do if [[ "$mountpoint" == */media* ]] && [[ "$options" != *noexec* ]]; then sed -i "s#^\(.*\s${mountpoint}\s\+\w\+\s\+[^[:space:]]\+\)\(\s.*\)\$#\1,noexec\2#g" /etc/fstab; fi; done


grep ^[^#] /etc/fstab | while read -r _ mountpoint _ options; do if [[ "$mountpoint" == */media* ]] && [[ "$options" != *nosuid* ]]; then sed -i "s#^\(.*\s${mountpoint}\s\+\w\+\s\+[^[:space:]]\+\)\(\s.*\)\$#\1,nosuid\2#g" /etc/fstab; fi; done


df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t


modprobe -r cramfs 2>&1 | grep builtin && (echo "Module cramfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* cramfs .*\)"#\1"g' /etc/modprobe.d/$each; done;echo install cramfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r squashfs 2>&1 | grep builtin && (echo "Module squashfs is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* squashfs .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install squashfs /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r udf 2>&1 | grep builtin && (echo "Module udf is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* udf .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install udf /bin/true >> /etc/modprobe.d/disabled_modules.conf)


if [[ -z $(grep -E -i '\svfat\s' /etc/fstab) ]]; then modprobe -r vfat 2>&1 | grep builtin && (echo "Module vfat is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* vfat .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install vfat /bin/true >> /etc/modprobe.d/disabled_modules.conf); else echo "Vfat is used and must be disabled manually if is not required"; read -p "Next" a; fi


systemctl --now disable autofs


echo "[Manual]" 'Update your package manager GPG keys in accordance with site policy.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/(^|\s|;)gpgcheck\s*=\s*\S+($|\s)/\1gpgcheck=1\2/g' /etc/dnf/dnf.conf
sed -ri 's/(^|\s|;)gpgcheck\s*=\s*\S+($|\s)/\1gpgcheck=1\2/g' /etc/yum.repos.d/*
grep -E "^\s*gpgcheck\s*=\s*1\s*($|\s)" /etc/dnf/dnf.conf || sed -ri 's;^(\s*\[main\].*)$;\1\ngpgcheck=1;' /etc/dnf/dnf.conf


sed -ri 's/^(\s*repo_gpgcheck\s*=\s*0)/## \1/' /etc/dnf/dnf.conf
grep -E "^\s*repo_gpgcheck\s*=\s*1\s*($|\s)" /etc/dnf/dnf.conf || sed -ri 's;^(\s*\[main\].*)$;\1\nrepo_gpgcheck=1;' /etc/dnf/dnf.conf


echo "[Manual]" 'To display information about not installed packages from security advisories use:
# dnf --refresh -q updateinfo list sec
To install updates use your package manager to update all packages on the system according to site policy. The following command will install all available in configured repositories updates:
# dnf update
If some security updates are not available in configured repositories, they can be found in central repository on https://repo.almalinux.org or on info site https://almalinux.pkgs.org.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Address unexpected discrepancies identified in the audit step.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure your package manager repositories according to site policy.'
read -n 1 -p "Press Enter to continue..."


dnf -y install aide
echo "Initializing AIDE database..."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz


(crontab -u root -l 2>/dev/null | egrep -i "^[0-9]+\s+[0-9]+\s+\*\s+\*\s+\*\s+/usr/sbin/aide.*\s+--check") || (crontab -u root -l 2>/dev/null; echo "0 5 * * * /usr/sbin/aide --check") | sort - | uniq - | crontab -u root -


dnf -y install libselinux


grubby --update-kernel ALL --remove-args 'selinux=0 enforcing=0'


grep -Ei "^\s*SELINUX=enforcing" /etc/selinux/config || (sed -i 's/^\s*SELINUX=/#SELINUX=/g' /etc/selinux/config; echo SELINUX=enforcing >> /etc/selinux/config)


grep -Ei "^\s*SELINUXTYPE=(targeted|mls)" /etc/selinux/config || (sed -i 's/^\s*SELINUXTYPE=/#SELINUXTYPE=/g' /etc/selinux/config; echo SELINUXTYPE=targeted >> /etc/selinux/config)


dnf remove setroubleshoot


dnf remove mcstrans


echo "[Manual]" 'Investigate any unconfined processes found during the audit action. They may need to have an existing security context assigned to them or a policy built for them.'
read -n 1 -p "Press Enter to continue..."


chown -R root:root /boot/grub2
if [ -e /boot/efi ]; then chmod -R root:root /boot/efi; fi


chmod -R og-rwx /boot/grub2
if [ -e /boot/efi ]; then chmod -R og-rwx /boot/efi; fi


echo "[Manual]" 'Create an encrypted password with grub2-setpassword : 
# grub2-setpassword
Enter password: <password>
Confirm password: <password>'
read -n 1 -p "Press Enter to continue..."


[[ -n $(grep -Er 'ExecStart\s*=\s*-/usr/lib/systemd/systemd-sulogin-shell\s+rescue' /usr/lib/systemd/system/rescue.service /etc/systemd/system/rescue.service.d 2>/dev/null) ]] || ( sed -i "s;\(^\s*ExecStart.*\srescue\);#\1;g" /usr/lib/systemd/system/rescue.service /etc/systemd/system/rescue.service.d 2>/dev/null; sed -ri 's;^(\s*\[Service\].*)$;\1\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue' /usr/lib/systemd/system/rescue.service)


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
dnf remove prelink


echo "[Manual]" 'Obtain and install the latest update of the AlmaLinux software.'
read -n 1 -p "Press Enter to continue..."


modprobe -r usb-storage 2>&1 | grep builtin && (echo "Module usb-storage is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* usb-storage .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install usb-storage /bin/true >> /etc/modprobe.d/disabled_modules.conf)


dnf -y install sudo


[[ -n $(grep -Ei '^\s*Defaults\s+([^#]+\s)?use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null) ]] || echo "Defaults use_pty" >> /etc/sudoers


[[ -n $(grep -Ei '^\s*Defaults\s+([^#]+\s)?logfile=".' /etc/sudoers /etc/sudoers.d/* 2>/dev/null) ]] || echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers


echo "[Manual]" 'Note: If passwords are not being used for authentication, this is not applicable.
Ensure the operating system requires users to supply a password for privilege escalation.
Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:
# grep -r "^[^#].*NOPASSWD" /etc/sudoers*
Based on the outcome, use visudo -f <PATH TO FILE> to remove any lines with occurrences of NOPASSWD tags in the file.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure the operating system to require users to reauthenticate for privilege escalation.
Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:
# grep -r "^[^#].*\!authenticate" /etc/sudoers*
Based on the outcome , use visudo -f <PATH TO FILE> to remove any occurrences of !authenticate tags in the file(s).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If the currently configured timeout is larger than 15 minutes or disabled (-1), check the file with timeout configuration:
# grep -rP "^[^#].*timestamp_timeout" /etc/sudoers*
Edit the file(s) with visudo -f <PATH TO FILE> and modify the entry timestamp_timeout= to 15 minutes or less as per your site policy. The value is in minutes. This particular entry may appear on its own, or on the same line as env_reset. Example 1:
Defaults env_reset, timestamp_timeout=15
Example 2:
Defaults timestamp_timeout=15
Defaults env_reset'
read -n 1 -p "Press Enter to continue..."


if [[ -z $(grep -iP '^\h*(FIPS|FUTURE)' /etc/crypto-policies/config) ]]; then read -p "Do you want to set the system-wide crypto policy to FIPS mode (manual reboot will be needed to enable configuration), FUTURE mode or DEFAULT mode?[fips][future][DEFAULT]" update; if [ "${update,,}" == "fips" ]; then fips-mode-setup --enable; elif [ "${update,,}" == "future" ]; then update-crypto-policies --set FUTURE; else update-crypto-policies --set DEFAULT; fi; update-crypto-policies; fi


if [[ -z $(grep -iP '^\h*(FIPS|FUTURE)' /etc/crypto-policies/config) ]]; then read -p "Do you want to set the system-wide crypto policy to FIPS mode (manual reboot will be needed to enable configuration) or FUTURE mode?[fips][future][CANCEL]" update; if [ "${update,,}" == "fips" ]; then fips-mode-setup --enable; update-crypto-policies; fi; if [ "${update,,}" == "future" ]; then update-crypto-policies --set FUTURE; update-crypto-policies; fi; fi


dnf remove telnet-server


dnf remove telnet


dnf remove rsh-server


dnf remove rsh


dnf remove ypbind


dnf remove ypserv


dnf remove tftp


dnf remove tftp-server


dnf remove talk


dnf remove talk-server


systemctl --now mask rsyncd 2>/dev/null


echo "[Manual]" 'Review enabled services and disable all unnecessary services:
# systemctl status *'
read -n 1 -p "Press Enter to continue..."


chmod go-rwx /usr/bin/gcc
chmod go-rwx /usr/bin/cc


dnf remove xorg-x11-server-common


systemctl --now disable avahi-daemon


systemctl --now disable cups


systemctl --now disable dhcpd


read -p "Do you want to chrony or ntp for time synchronization?[CHRONY][ntp]" timeserv; if [ "$timeserv" == "ntp" ]; then yum -y install ntp; systemctl enable ntpd; systemctl start ntpd; else yum -y install chrony; systemctl enable chronyd; systemctl start chronyd; fi


if [[ -n $(systemctl is-enabled ntpd 2>/dev/null | grep enabled) ]]; then if [[ -z $(grep -P "^\s*server\s+\S" /etc/ntp.conf) ]]; then read -p "Enter ntp server address:" ntp_server; echo "server $ntp_server" >> /etc/ntp.conf; fi; egrep "^\s*restrict\s*-4\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -4 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; egrep "^\s*restrict\s*-6\s*default" /etc/ntp.conf | grep kod | grep nomodify | grep notrap | grep nopeer | grep noquery || echo restrict -6 default kod nomodify notrap nopeer noquery >> /etc/ntp.conf; grep ^OPTIONS=\" /etc/sysconfig/ntpd && sed -i '/^OPTIONS=/s/"$/ -u ntp:ntp"/g' /etc/sysconfig/ntpd; grep ^OPTIONS=\" /etc/sysconfig/ntpd || echo OPTIONS=\"-u ntp:ntp\" >> /etc/sysconfig/ntpd; else echo "Not applicable - ntpd.service is not enabled"; fi


if [[ -n $(systemctl is-enabled chronyd 2>/dev/null | grep enabled) ]]; then if [[ -z $(grep -P "^\s*server\s+\S" /etc/chrony.conf) ]]; then read -p "Enter ntp server address:" ntp_server; echo "server $ntp_server" >> /etc/chrony.conf; fi; grep ^OPTIONS=\" /etc/sysconfig/chronyd && sed -i '/^OPTIONS=/s/"$/ -u chrony"/g' /etc/sysconfig/chronyd; egrep ^OPTIONS=\" /etc/sysconfig/chronyd || echo OPTIONS=\"-u chrony\" >> /etc/sysconfig/chronyd; else echo "Not applicable - chronyd.service is not enabled"; fi


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


dnf remove bind


dnf remove vsftpd


dnf remove httpd
dnf remove lighttpd
dnf remove nginx


dnf remove dovecot
dnf remove cyrus-imapd


dnf remove samba


dnf remove squid


dnf remove net-snmp


sed -i 's/^\s*\(r[ow]community\s\+public\)/#\1/g' /etc/snmp/*.conf
sed -i 's/^\s*\(r[ow]community\s\+private\)/#\1/g' /etc/snmp/*.conf


if [ -e /etc/postfix/main.cf ]; then sed -i 's/^\s*inet_interfaces/#inet_interfaces/g' /etc/postfix/main.cf; echo inet_interfaces = loopback-only >> /etc/postfix/main.cf; systemctl restart postfix; fi


dnf remove openldap-clients


dnf remove ftp


dnf remove dnsmasq


sed -i "s/^\(\s*net\.ipv4\.ip_forward\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv4\.ip_forward\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/44-couch.conf
/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.route.flush=1
sed -i "s/^\(\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*[123456789]\)/#\1/" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(egrep "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*0(\s|$)" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/44-couch.conf
if [ -e /proc/sys/net/ipv6/conf/all/forwarding ]; then /sbin/sysctl -w net.ipv6.conf.all.forwarding=0; /sbin/sysctl -w net.ipv6.route.flush=1; fi


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


grubby --update-kernel ALL --args 'ipv6.disable=1'


modprobe -r dccp 2>&1 | grep builtin && (echo "Module dccp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* dccp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install dccp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r sctp 2>&1 | grep builtin && (echo "Module sctp is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* sctp .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install sctp /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r rds 2>&1 | grep builtin && (echo "Module rds is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* rds .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install rds /bin/true >> /etc/modprobe.d/disabled_modules.conf)


modprobe -r tipc 2>&1 | grep builtin && (echo "Module tipc is built-in, you need to recompile kernel to disable it"; read -p "Next" a) || (for each in `ls /etc/modprobe.d/`; do sed -i 's"\(.* tipc .*\)"#\1"g' /etc/modprobe.d/$each; done; echo install tipc /bin/true >> /etc/modprobe.d/disabled_modules.conf)


echo "[Manual]" 'The DNS servers listed in
/etc/resolv.conf file must be those managed locally by the internal administrators.'
read -n 1 -p "Press Enter to continue..."


dnf -y install rsyslog


systemctl --now enable rsyslog


echo "[Manual]" 'Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment.
Example: 
auth,user.* /var/log/messages
kern.* /var/log/kern.log 
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
Execute the following command to restart rsyslogd
# systemctl restart rsyslog'
read -n 1 -p "Press Enter to continue..."


[[ -n $(grep -E "^\\\$FileCreateMode\s+0?[0246][04]0" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null) ]] || echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
systemctl restart rsyslog


for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | grep -Ei '(^|\s)file=".+"'); do if [[ "$each" =~ ^[^#]*[Ff]ile=\"(.*)\" ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done
for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "^.+\..+\s+-?/.+$" | grep -v -i IncludeConfig); do if [[ "$each" =~ ^-?(/[^:;]+)[^:]*$ ]]; then [ -e "${BASH_REMATCH[1]}" ] || (mkdir -p "$(dirname "${BASH_REMATCH[1]}")"; touch "${BASH_REMATCH[1]}"); echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" && chmod 640 "${BASH_REMATCH[1]}"; echo "${BASH_REMATCH[1]}" | egrep "(utmp|wtmp)" || chmod 600 "${BASH_REMATCH[1]}"; fi; done


if [[ -z $(grep "^\*\.\*[[:space:]]*@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null) ]]; then read -p "Enter IP address or domain name of central logging server for syslog:" logserv; echo "*.* @@$logserv" >> /etc/rsyslog.conf; systemctl restart rsyslog; fi


read -p "Is this host designated central logging server?[y][N]" logserver;
if [[ "$logserver" != "y" && "$logserver" != "Y" ]]; then sed -i "s;^\s*\(\$ModLoad\s\+\(imtcp\|/[^#]*imtcp\)\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; sed -i "s;^\s*\(\$InputTCPServerRun\s\);## \1;g" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; systemctl restart rsyslog; fi


sed -i 's/^\s*max_log_file\s*=\s*.*$/max_log_file = 50/g' /etc/audit/auditd.conf
egrep "^\s*max_log_file\s*=\s*50\s*$" /etc/audit/auditd.conf || echo "max_log_file = 50" >> /etc/audit/auditd.conf


sed -i 's/^\s*space_left_action\s*=.*$/space_left_action = email/g' /etc/audit/auditd.conf
egrep "^\s*space_left_action\s*=\s*email\s*$" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
sed -i 's/^\s*action_mail_acct\s*=.*$/action_mail_acct = root/g' /etc/audit/auditd.conf
egrep "^\s*action_mail_acct\s*=\s*root\s*$" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf


echo "[Manual]" 'Configure max_log_file_action in /etc/audit/auditd.conf as prescribed in your organization, example keep_logs or rotate or leave default.'
read -n 1 -p "Press Enter to continue..."


systemctl enable auditd
systemctl start auditd


grubby --update-kernel ALL --args 'audit=1'


uname -i 2>&1 | grep 64 || ( egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*adjtimex\s*-S\s*settimeofday\s*-S\s*stime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*clock_settime\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/localtime\s*-p\s*wa\s*-k\s*time-change" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/group\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/passwd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/gshadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/shadow\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/security/opasswd\s*-p\s*wa\s*-k\s*identity" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


uname -i 2>&1 | grep 64 || (egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*exit,always\s*-F\s*arch=b64\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-a\s*exit,always\s*-F\s*arch=b32\s*-S\s*sethostname\s*-S\s*setdomainname\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/issue.net\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/hosts\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules);egrep "^-w\s*/etc/sysconfig/network\s*-p\s*wa\s*-k\s*system-locale" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules))
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


uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chmod\s*-S\s*fchmod\s*-S\s*fchmodat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*chown\s*-S\s*fchown\s*-S\s*fchownat\s*-S\s*lchown\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*setxattr\s*-S\s*lsetxattr\s*-S\s*fsetxattr\s*-S\s*removexattr\s*-S\s*lremovexattr\s*-S\s*fremovexattr\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*perm_mod" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid\>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EACCES\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*creat\s*-S\s*open\s*-S\s*openat\s*-S\s*truncate\s*-S\s*ftruncate\s*-F\s*exit=-EPERM\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*access" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid\>=1000 -F auid!=4294967295 -k access" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


df --local -P | awk '{if (NR!=1) print $6}' | xargs -I "{}" find "{}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | while read -r line; do egrep "^-a\s*always,exit\s*-F\s*path=${line}\s*-F\s*perm=x\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*privileged" /etc/audit/rules.d/audit.rules || (audit_num=$(cat /etc/audit/rules.d/audit.rules | wc -l); sed -i "${audit_num}i-a always,exit -F path=${line} -F perm=x -F auid\>=1000 -F auid!=4294967295 -k privileged" /etc/audit/rules.d/audit.rules); done;
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi;


uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules)) 
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules);egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*mount\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*mounts" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S mount -F auid\>=1000 -F auid!=4294967295 -k mounts" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


uname -i 2>&1 | grep 64 || (egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*unlink\s*-S\s*unlinkat\s*-S\s*rename\s*-S\s*renameat\s*-F\s*auid>=1000\s*-F\s*auid!=4294967295\s*-k\s*delete" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid\>=1000 -F auid!=4294967295 -k delete" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/sudoers\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/sudoers.d/\s*-p\s*wa\s*-k\s*scope" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sudoers.d/ -p wa -k scope" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/var/log/sudo.log\s*-p\s*wa\s*-k\s*actions" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/log/sudo.log -p wa -k actions" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


uname -i 2>&1 | grep 64 || (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b32\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
uname -i 2>&1 | grep 64 && (egrep "^-w\s*/sbin/insmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/insmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/rmmod\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/rmmod -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-w\s*/sbin/modprobe\s*-p\s*x\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /sbin/modprobe -p x -k modules" /etc/audit/rules.d/audit.rules); egrep "^-a\s*always,exit\s*-F\s*arch=b64\s*-S\s*init_module\s*-S\s*delete_module\s*-k\s*modules" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/rules.d/audit.rules))
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


find /var/log -type f | while read -r file; do \
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


find /etc/pam.d -type f | while read -r file; do egrep "^-w\s*$file\s*-p\s*wa\s*-k\s*change-auth-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w $file -p wa -k change-auth-cfg" /etc/audit/rules.d/audit.rules); done
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


egrep "^-w\s*/etc/audit/auditd.conf\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/auditd.conf -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
egrep "^-w\s*/etc/audit/rules.d/audit.rules\s*-p\s*wa\s*-k\s*change-audit-cfg" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/audit/rules.d/audit.rules -p wa -k change-audit-cfg" /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


tail -n 1 /etc/audit/rules.d/audit.rules | egrep "^-e\s+2" || (sed -i "s;^-e\s\+;#-e ;g" /etc/audit/rules.d/audit.rules; echo "-e 2" >> /etc/audit/rules.d/audit.rules)
restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi


grubby --update-kernel ALL --args 'audit_backlog_limit=8192'


echo "[Manual]" 'Edit the /etc/logrotate.d/syslog file to include appropriate system logs: 
/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron /var/log/dnf.log {'
read -n 1 -p "Press Enter to continue..."


for f in `ls /etc/logrotate.conf /etc/logrotate.d/*`; do i=0; rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $line | egrep -i "/utmp|/wtmp|/btmp" && i=1; if [ "$i" == "0" ]; then echo $line | grep "{" && k=0; echo $line | grep "}" && if [ "$k" == "0" ]; then echo "create 0600 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 600 ;' >> $f.couch_tmp; else echo $line | grep "{" && k=0; echo $line | grep "}" && i=0&& if [ "$k" == "0" ]; then echo "create 0640 root" >> $f.couch_tmp; fi; echo $line | grep "create[[:space:]][0-9]" && k=1; echo $line | sed 's;create\s\+[0-9]\+\s;create 640 ;' >> $f.couch_tmp; fi; done < $f; yes | cp $f.couch_tmp $f; rm --interactive=never $f.couch_tmp; done


egrep "^Defaults\s+syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" /etc/sudoers || echo "Defaults syslog=authpriv,syslog_goodpri=info,syslog_badpri=info" >> /etc/sudoers


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*ForwardToSyslog\s*=" | tail -n 1 | egrep "^\s*ForwardToSyslog\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*ForwardToSyslog\s/## ForwardToSyslog /g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nForwardToSyslog=yes\n/' /etc/systemd/journald.conf)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Compress\s*=" | tail -n 1 | egrep "^\s*Compress\s*=\s*yes(\s|#|$)" || ( sed -i "s/^\s*Compress\s/## Compress/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nCompress=yes\n/' /etc/systemd/journald.conf)


sed -e '0,/^\s*\[Journal\]/d' /etc/systemd/journald.conf | egrep "^\s*Storage\s*=" | tail -n 1 | egrep "^\s*Storage\s*=\s*persistent(\s|#|$)" || ( sed -i "s/^\s*Storage\s/## Storage/g" /etc/systemd/journald.conf; sed -i 's/\(^\s*\[Journal\].*$\)/\1\nStorage=persistent\n/' /etc/systemd/journald.conf)


find /var/log -type f ! -name wtmp ! -name wtmp.* ! -name btmp ! -name btmp.* ! -name lastlog ! -name lastlog.* | xargs -d$'\n' -I {} chmod g-wx,o-rwx '{}'
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


if authselect check; then
  current_profile=$(authselect current | grep '^Profile ID:' | cut -f2 -d: | xargs);
  current_options=$(authselect current | grep '^- ' | while read -r opt; do printf " ${opt#- }"; done);
  if [[ ! "$current_profile" =~ ^custom/.* ]]; then
    if ! authselect show "custom/${current_profile}-couch" 1>/dev/null; then authselect create-profile "${current_profile}-couch" --base-on="${current_profile}"; fi; 
    current_profile="custom/${current_profile}-couch";
    authselect select "${current_profile}" ${current_options};
  fi;
  PTF="/etc/authselect/${current_profile}";
else 
  PTF=/etc/pam.d;
fi;
for FN in system-auth password-auth; do target_file="${PTF}/${FN}"; sed -ri '/^\s*password\s+(\S+\s+)+pam_unix\.so/s/(\ssha[0-9]+|yescrypt)(\s|$)/\2/g' "$target_file"; sed -ri 's/^\s*(password\s+(\S+\s+)+pam_unix\.so\s*)(.*)$/\1 sha512 \3/' "$target_file"; done; 
if authselect check; then authselect apply-changes; fi;
if [[ -z $(grep -Ei '^\s*crypt_style\s*=' /etc/libuser.conf | head -n 1 | grep -Ei '^\s*crypt_style\s*=\s*sha512\b') ]]; then sed -ri 's/^(\s*crypt_style\s*=)/## \1/' /etc/libuser.conf; sed -ri 's;^(\s*\[defaults\].*)$;\1\ncrypt_style = sha512;' /etc/libuser.conf; fi
if [[ -z $(grep -Ei '^\s*ENCRYPT_METHOD\s' /etc/login.defs | head -n 1 | grep -Ei '^\s*ENCRYPT_METHOD\s+SHA512\b') ]]; then sed -ri 's/^(\s*ENCRYPT_METHOD\s)/## \1/' /etc/login.defs; echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs; fi


rpm -q libpwquality || yum -y install libpwquality;
if authselect check; then
  current_profile=$(authselect current | grep '^Profile ID:' | cut -f2 -d: | xargs);
  current_options=$(authselect current | grep '^- ' | while read -r opt; do printf " ${opt#- }"; done);
  if [[ ! "$current_profile" =~ ^custom/.* ]]; then
    if ! authselect show "custom/${current_profile}-couch" 1>/dev/null; then authselect create-profile "${current_profile}-couch" --base-on="${current_profile}"; fi; 
    current_profile="custom/${current_profile}-couch";
    authselect select "${current_profile}" ${current_options};
  fi;
  PTF="/etc/authselect/${current_profile}";
else 
  PTF=/etc/pam.d;
fi;
for FN in system-auth password-auth; do 
  target_file="${PTF}/${FN}";
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so(\s|$)' "$target_file" || sed -ri '0,/^\s*password\s+sufficient\s/s/^\s*password\s+sufficient\s/password requisite pam_pwquality.so retry=3\n&/' "$target_file"; 
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so[^#]*\s+try_first_pass(\s|#|$)' "$target_file" || sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality\.so\s*)(.*)$/\1 try_first_pass \2/' "$target_file"; 
  grep -E '^\s*password\s+requisite\s+pam_pwquality\.so[^#]*\s+retry=[123](\s|#|$)' "$target_file" || (sed -ri '/pam_pwquality\.so/s/\sretry=\S+//g' "$target_file"; sed -ri 's/^\s*(password\s+requisite\s+pam_pwquality.so\s*)(.*)$/\1 retry=3 \2/' "$target_file"); 
done;
if authselect check; then authselect apply-changes; fi;
grep -E '^\s*minlen\s*=\s*[0-7](\s|$)' /etc/security/pwquality.conf && sed -ri 's/^(\s*minlen\s*=\s*[0-7])(\s|$)/## \1\2/' /etc/security/pwquality.conf
grep -E '^\s*dcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*dcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*dcredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo dcredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ucredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ucredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ucredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo ucredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*ocredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*ocredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*ocredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo ocredit=-1 >> /etc/security/pwquality.conf)
grep -E '^\s*lcredit\s*=' /etc/security/pwquality.conf | tail -n 1 | grep -E '^\s*lcredit\s*=\s*-[1-9]' || (sed -ri 's/^(\s*lcredit\s*=.*$)/## \1/' /etc/security/pwquality.conf; echo lcredit=-1 >> /etc/security/pwquality.conf)


if authselect check; then
  current_profile=$(authselect current | grep '^Profile ID:' | cut -f2 -d: | xargs);
  current_options=$(authselect current | grep '^- ' | while read -r opt; do printf " ${opt#- }"; done);
  if [[ ! "$current_profile" =~ ^custom/.* ]]; then
    if ! authselect show "custom/${current_profile}-couch" 1>/dev/null; then authselect create-profile "${current_profile}-couch" --base-on="${current_profile}"; fi; 
    current_profile="custom/${current_profile}-couch";
    authselect select "${current_profile}" ${current_options};
  fi;
  if authselect list-features "$current_profile" | grep '^with-faillock$'; then authselect enable-feature with-faillock; fi; 
  PTF="/etc/authselect/${current_profile}";
else 
  PTF=/etc/pam.d;
fi;
for FN in system-auth password-auth; do 
  target_file="${PTF}/${FN}";
  grep -E '^\s*auth\s+required\s+pam_faillock.so\s+preauth(\s|$)' "$target_file" || (rm -f "$FN.couch_tmp" 2>/dev/null; i=0; while read -r line || [[ -n "$line" ]]; do if [[ "$i" -eq "0" ]]&&[[ $(echo "$line" | egrep -i "^\s*auth\s+sufficient") ]]; then echo "auth required pam_faillock.so preauth silent" >> "$FN.couch_tmp"; i=1; fi; echo "$line" >> "$FN.couch_tmp"; done < "$target_file"; yes | cp "$FN.couch_tmp" "$target_file"; rm -f "$FN.couch_tmp" 2>/dev/null); 
  grep -E '^\s*auth\s+required\s+pam_faillock.so\s+authfail(\s|$)' "$target_file" || printf '%s\n' '0?^\s*auth\s\+sufficient\s?a' 'auth required pam_faillock.so authfail' . x | ex "$target_file";
  touch /etc/security/faillock.conf;
  grep -P '^\s*deny\s*=\s*[1-5](\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*deny\s*=)/## \1/' /etc/security/faillock.conf; echo "deny = 5" >> /etc/security/faillock.conf);
  grep -P '^\s*unlock_time\s*=\s*(7[2-9]\d\d|[89]\d\d\d|\d{5,}|0)(\s|$)' /etc/security/faillock.conf || (sed -ri 's/^(\s*unlock_time\s*=)/## \1/' /etc/security/faillock.conf; echo "unlock_time = 7200" >> /etc/security/faillock.conf);
done;
if authselect check; then authselect apply-changes; fi


if authselect check; then
  current_profile=$(authselect current | grep '^Profile ID:' | cut -f2 -d: | xargs);
  current_options=$(authselect current | grep '^- ' | while read -r opt; do printf " ${opt#- }"; done);
  if [[ ! "$current_profile" =~ ^custom/.* ]]; then
    if ! authselect show "custom/${current_profile}-couch" 1>/dev/null; then authselect create-profile "${current_profile}-couch" --base-on="${current_profile}"; fi; 
    current_profile="custom/${current_profile}-couch";
    authselect select "${current_profile}" ${current_options};
  fi;
  PTF="/etc/authselect/${current_profile}/system-auth";
else 
  PTF=/etc/pam.d/system-auth;
fi;
grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so' "$PTF" || sed -ri '0,/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/s/^\s*password\s+(sufficient|\[success=([0-9]+|ok).*)\s/password required pam_pwhistory.so remember=5\n&/' "$PTF"; 
grep -E '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so[^#]*\sremember=([5-9]|[1-9][0-9]+)' "$PTF" || (sed -ri '/^\s*password\s+(requisite|required)\s+pam_pwhistory\.so/s/\sremember=\S+//g' "$PTF"; sed -ri 's/^\s*(password\s+(requisite|required)\s+pam_pwhistory\.so\s*)(.*)$/\1 remember=5 \3/' "$PTF");
if authselect check; then authselect apply-changes; fi


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


awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 }' /etc/passwd | while read user; do usermod -s $(which nologin) $user; done
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read user; do usermod -L $user; done


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


if rpm -q gdm 1>/dev/null; then egrep "^\s*user-db:user" /etc/dconf/profile/gdm || echo "user-db:user" >> /etc/dconf/profile/gdm; egrep "^\s*system-db:gdm" /etc/dconf/profile/gdm || echo "system-db:gdm" >> /etc/dconf/profile/gdm; egrep "^\s*file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm || echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >> /etc/dconf/profile/gdm; if [ ! -e /etc/dconf/db/gdm.d ]; then mkdir /etc/dconf/db/gdm.d; fi; egrep "^\s*\[org/gnome/login-screen\]" /etc/dconf/db/gdm.d/* || echo "[org/gnome/login-screen]" >> /etc/dconf/db/gdm.d/01-banner-message; egrep "^\s*banner-message-enable\s*=\s*true" /etc/dconf/db/gdm.d/*  || echo "banner-message-enable=true" >> /etc/dconf/db/gdm.d/01-banner-message; egrep "^\s*banner-message-text\s*=" /etc/dconf/db/gdm.d/* | egrep -i "authorized\s+(users|access|uses)\s+only\.\s*all\s+activity\s+may\s+be\s+(monitored\s+and\s+reported|logged\s+and\s+monitored)" || ( sed -i "s/banner-message-text\s*=/#banner-message-text=/g" /etc/dconf/db/gdm.d/*; echo "banner-message-text='Authorized access only. All activity may be logged and monitored'" >> /etc/dconf/db/gdm.d/01-banner-message); dconf update; fi


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


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do chmod g-w "$dir"; chmod o-rwx "$dir"; done


cat /etc/passwd | egrep -v "^(root:|halt:|sync:|shutdown:)" | awk -F: '( $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin") { print $6}' | while read dir; do for file in `ls -d "$dir"/.[A-Za-z0-9]* 2>/dev/null`; do chmod -R go-w "$file"; done; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then chmod go-rwx "$dir/.netrc";fi; done


cat /etc/passwd | awk -F: "{print \$6}" | while read dir; do if [ ! -h "$dir/.rhosts" -a -f "$dir/.rhosts" ]; then mv "$dir/.rhosts" "$dir/.rhosts.old"; fi; done


echo "[Manual]" 'Analyze the output of the script and perform the appropriate action to correct any discrepancies found:
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:[^:]*:$i:" /etc/group
if [ $? -ne 0 ]; then echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"; fi
done'
read -n 1 -p "Press Enter to continue..."


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then mkdir "$dir"; chown $user "$dir"; chmod g-w "$dir"; chmod o-rwx "$dir"; fi; done


cat /etc/passwd | awk -F: '{ print $1" "$3" "$6 }' | while read user uid dir; do if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" -a $user != "nobody" ]; then owner=$(stat -L -c "%U" "$dir"); if [ "$owner" != "$user" ]; then chown $user "$dir"; fi; fi; done


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


c_min_uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}');
grep -Ev "^\+" /etc/passwd | awk -F: -v N=$c_min_uid '($1!="root" && $3 < N) {system("usermod -L "$1)}'


sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd


sed -i 's/^\(\s*kernel\.dmesg_restrict\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.dmesg_restrict\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.dmesg_restrict=1


sed -i 's/^\(\s*kernel\.kptr_restrict\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.kptr_restrict\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kptr_restrict=2


grubby --update-kernel ALL --args 'init_on_alloc=1' && echo "Reboot is needed to apply configuration changes"


grubby --update-kernel ALL --args 'slab_nomerge' && echo "Reboot is needed to apply configuration changes"


grubby --update-kernel ALL --args 'iommu=force iommu.strict=1 iommu.passthrough=0' && echo "Reboot is needed to apply configuration changes"


grubby --update-kernel ALL --args 'randomize_kstack_offset=1' && echo "Reboot is needed to apply configuration changes"


grubby --update-kernel ALL --args 'mitigations=auto,nosmt' && echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*net\.core\.bpf_jit_harden\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*net\.core\.bpf_jit_hardens*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'net.core.bpf_jit_harden = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w net.core.bpf_jit_harden=2


grubby --update-kernel ALL --args 'vsyscall=none' && echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.perf_event_paranoid\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.perf_event_paranoid\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.perf_event_paranoid = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.perf_event_paranoid=3


grubby --update-kernel ALL --args 'debugfs=no-mount' && echo "Reboot is needed to apply configuration changes"


sed -i 's/^\(\s*kernel\.kexec_load_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.kexec_load_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.kexec_load_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.kexec_load_disabled=1


sed -i 's/^\(\s*user\.max_user_namespaces\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*user\.max_user_namespaces\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'user.max_user_namespaces = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w user.max_user_namespaces=0


sed -i 's/^\(\s*kernel\.unprivileged_bpf_disabled\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.unprivileged_bpf_disabled\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.unprivileged_bpf_disabled = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.unprivileged_bpf_disabled=1


sed -i 's/^\(\s*vm\.unprivileged_userfaultfd\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*vm\.unprivileged_userfaultfd\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'vm.unprivileged_userfaultfd = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w vm.unprivileged_userfaultfd=0


sed -i 's/^\(\s*dev\.tty\.ldisc_autoload\s*=\s*[123456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*dev\.tty\.ldisc_autoload\s*=\s*0\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'dev.tty.ldisc_autoload = 0' >> /etc/sysctl.d/FSTEC.conf
sysctl -w dev.tty.ldisc_autoload=0


grubby --update-kernel ALL --args 'tsx=off' && echo "Reboot is needed to apply configuration changes"


sed -ri 's/^(\s*vm\.mmap_min_addr\s*=\s*[1-3]?[0-9]{1,3})/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*vm\.mmap_min_addr\s*=\s*([4-9][0-9]{3}|[0-9]{5,})\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || (echo 'vm.mmap_min_addr = 4096' >> /etc/sysctl.d/FSTEC.conf; sysctl -w vm.mmap_min_addr=4096)


sed -i 's/^\(\s*kernel\.yama\.ptrace_scope\s*=\s*[012456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*kernel\.yama\.ptrace_scope\s*=\s*3\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'kernel.yama.ptrace_scope = 3' >> /etc/sysctl.d/FSTEC.conf
sysctl -w kernel.yama.ptrace_scope=3


sed -i 's/^\(\s*fs\.protected_symlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_symlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_symlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_symlinks=1


sed -i 's/^\(\s*fs\.protected_hardlinks\s*=\s*[023456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_hardlinks\s*=\s*1\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_hardlinks = 1' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_hardlinks=1


sed -i 's/^\(\s*fs\.protected_fifos\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_fifos\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_fifos = 2' >> /etc/sysctl.d/FSTEC.conf
sysctl -w fs.protected_fifos=2


sed -i 's/^\(\s*fs\.protected_regular\s*=\s*[013456789]\)/#\1/g' /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null
[[ -n $(grep -E "^\s*fs\.protected_regular\s*=\s*2\s*$" /etc/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2>/dev/null) ]] || echo 'fs.protected_regular = 2' >> /etc/sysctl.d/FSTEC.conf
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



