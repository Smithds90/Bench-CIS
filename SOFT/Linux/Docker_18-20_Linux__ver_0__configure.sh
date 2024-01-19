#!/usr/bin/env bash

couch_docker_conffile=$(ps -ef | grep "do[c]kerd.*--config-file=" 1>/dev/null && ps -ef | grep "do[c]kerd.*\s--config-file=" | sed -r 's/.*\s--config-file=("[^"]*"|[^"]\S*).*/\1/' || echo "/etc/docker/daemon.json")


echo "[Manual]" 'You should monitor versions of Docker releases and make sure your software is updated as required.
Note: You should be aware that third-party products that use Docker may require older major versions of Docker to be supported, and this should be reviewed in line with the general IT security policy of your organization, particularly where security vulnerabilities in older versions have been publicly disclosed.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For new installations, you should create a separate partition for the /var/lib/docker mount point. For systems which have already been installed, you should use the Logical Volume Manager (LVM) within Linux to create a new partition.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should remove any untrusted users from the docker group. Additionally, you should not create a mapping of sensitive directories from the host to container volumes.'
read -n 1 -p "Press Enter to continue..."


if [[ -e /usr/bin/dockerd ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/dockerd\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/dockerd -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/dockerd\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/dockerd -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /var/lib/docker ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/var/lib/docker\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/lib/docker -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/var/lib/docker\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /var/lib/docker -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /etc/docker ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/etc/docker\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/docker -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/etc/docker\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/docker -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" && -e "$c_file" ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+${c_file}\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w ${c_file} -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+${c_file}\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w ${c_file} -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


c_file=$(systemctl show -p FragmentPath docker.socket | cut -f2 -d=); if [[ -n "$c_file" && -e "$c_file" ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+${c_file}\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w ${c_file} -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+${c_file}\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w ${c_file} -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /etc/default/docker ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/etc/default/docker\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/default/docker -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/etc/default/docker\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/default/docker -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /etc/sysconfig/docker ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/etc/sysconfig/docker\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/docker -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/etc/sysconfig/docker\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/sysconfig/docker -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /etc/docker/daemon.json ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/etc/docker/daemon.json\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/docker/daemon.json -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/etc/docker/daemon.json\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/docker/daemon.json -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /usr/bin/containerd ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/containerd\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/containerd\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /usr/bin/runc ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/runc\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/runc -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/runc\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/runc -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /run/containerd ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/run/containerd\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /run/containerd -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/run/containerd\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /run/containerd -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /etc/containerd/config.toml ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/etc/containerd/config.toml\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/containerd/config.toml -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/etc/containerd/config.toml\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /etc/containerd/config.toml -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /usr/bin/containerd-shim ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/containerd-shim\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/containerd-shim\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /usr/bin/containerd-shim-runc-v1 ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/containerd-shim-runc-v1\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim-runc-v1 -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/containerd-shim-runc-v1\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim-runc-v1 -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ -e /usr/bin/containerd-shim-runc-v2 ]]; then if [[ -e /etc/audit/rules.d/audit.rules ]]; then grep -E "^\s*-w\s+/usr/bin/containerd-shim-runc-v2\s" /etc/audit/rules.d/audit.rules || (audit_num=`cat /etc/audit/rules.d/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim-runc-v2 -k docker" /etc/audit/rules.d/audit.rules); restart="no"; read -p "Do you want to restart auditd service for updating audit.rules now (also reboot is needed if auditd rules are configured as immutable)?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service auditd restart; fi; else grep -E "^\s*-w\s+/usr/bin/containerd-shim-runc-v2\s" /etc/audit/audit.rules || (audit_num=`cat /etc/audit/audit.rules | wc -l`; sed -i "${audit_num}i-w /usr/bin/containerd-shim-runc-v2 -k docker" /etc/audit/audit.rules); pkill -HUP -P 1 auditd || true; echo "Reboot is needed if auditd rules are configured as immutable"; read -p "Next" a; fi; fi


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"icc": false\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"icc"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"icc"\s*:[^,]*/"icc": false/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "icc": false,\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--icc(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--icc(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"log-level": "info"\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"log-level"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"log-level"\s*:[^,]*/"log-level": "info"/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "log-level": "info",\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--log-level(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--log-level(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"iptables": true\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"iptables"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"iptables"\s*:[^,]*/"iptables": true/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "iptables": true,\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--iptables(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--iptables(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


echo "[Manual]" 'You should ensure that no insecure registries are in use.

Default: Docker assumes all, except local, registries are secure.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(docker info --format 'Storage Driver: {{ .Driver }}' | grep -E "^\s*Storage\s+Driver\s*:\s*aufs\s*$") ]]; then read -p "Do you want to change aufs storage driver to another now?[yes][NO]" c_change; if [ "$c_change" == "yes" ]; then read -p "Enter new storage driver name [default is overlay2]: " c_driver; [[ -z "$c_driver" ]] && c_driver=overlay2; 
if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi;
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"storage-driver": "%s"\n}\n' "$c_driver" >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"storage-driver"\s*:' "$couch_docker_conffile") ]]; then sed -ri "s/\"storage-driver\"\s*:[^,]*/\"storage-driver\": \"${c_driver}\"/g" "$couch_docker_conffile"; else sed -ri "0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  \"storage-driver\": \"${c_driver}\",\n\1/" "$couch_docker_conffile"; fi; fi;
service docker restart;
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--storage-driver(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--storage-driver(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi;
fi;
fi


echo "[Manual]" 'If Docker daemon is available remotely over a TCP port follow the steps mentioned in the Docker documentation or other references to configure TLS certificates and authentication for its network service.
Note: You would need to manage and guard certificates and keys for the Docker daemon and Docker clients.

Default: TLS authentication is not configured.'
read -n 1 -p "Press Enter to continue..."


if [[ -z $(ps -ef | grep "do[c]kerd" | grep -E "\s--default-ulimit\s+nproc=") && -z $(sed -e '0,/(^|{|,)\s*"default-ulimits"\s*:/d' "$couch_docker_conffile" | egrep "(^|{|,)\s*"nproc"\s*:") ]]; then
read -p "Enter soft nproc limit?[default is 1024]" c_nproc_soft; [[ -z "$c_nproc_soft" ]] && c_nproc_soft=1024; 
read -p "Enter hard nproc limit?[default is 2048]" c_nproc_hard; [[ -z "$c_nproc_hard" ]] && c_nproc_hard=2048;
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then sed -ri "s/^(\s*ExecStart\s*=.*)(#|$)/\1 --default-ulimit nproc=${c_nproc_soft}:${c_nproc_hard} \2/" "$c_file"; systemctl daemon-reload; systemctl restart docker.service; fi; fi;
if [[ -z $(ps -ef | grep "do[c]kerd" | grep -E "\s--default-ulimit\s+nofile=") && -z $(sed -e '0,/(^|{|,)\s*"default-ulimits"\s*:/d' "$couch_docker_conffile" | egrep "(^|{|,)\s*"nofile"\s*:") ]]; then
read -p "Enter soft nofile limit?[default is 100]" c_nofile_soft; [[ -z "$c_nofile_soft" ]] && c_nofile_soft=100; 
read -p "Enter hard nofile limit?[default is 200]" c_nofile_hard; [[ -z "$c_nofile_hard" ]] && c_nofile_hard=200;
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then sed -ri "s/^(\s*ExecStart\s*=.*)(#|$)/\1 --default-ulimit nofile=${c_nofile_soft}:${c_nofile_hard} \2/" "$c_file"; systemctl daemon-reload; systemctl restart docker.service; fi; fi


if [[ -z $(docker info --format '{{ .SecurityOptions }}' | grep -E "(\[|\s|,)name=userns(\]|\s|,)") ]]; then read -p "Do you want to enable user namespace remapping now?[yes][NO]" c_change; if [[ "$c_change" == "yes" ]]; then
touch /etc/subuid /etc/subgid;
if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi;
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"userns-remap": "default"\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"userns-remap"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"userns-remap"\s*:[^,]*/"userns-remap": "default"/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "userns-remap": "default",\n\1/' "$couch_docker_conffile"; fi; fi;
service docker restart;
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--userns-remap(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--userns-remap(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi;
fi;
fi


echo "[Manual]" 'The default setting is in line with good security practice and can be left in situ.
If you wish to specifically set a non-default cgroup, pass the --cgroup-parent parameter to the Docker daemon when starting it. 
For example, 
dockerd --cgroup-parent=/foobar

By default, docker daemon uses /docker for fs cgroup driver and system.slice for systemd cgroup driver.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Do not set --storage-opt dm.basesize until needed.

The default base device size is 10G.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Step 1: Install/Create an authorization plugin. 
Step 2: Configure the authorization policy as desired. 
Step 3: Start the docker daemon as below: 
dockerd --authorization-plugin=<PLUGIN_ID>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Step 1: Set up the desired log driver following its documentation. 
Step 2: Start the docker daemon using that logging driver. 
For example: 
dockerd --log-driver=syslog --log-opt syslog-address=tcp://xxx.xxx.xxx.xxx

By default, container logs are maintained as json files'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(docker info 2>/dev/null | grep -E "^\s*Swarm\s*:\s*inactive") ]]; then if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi; if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"live-restore": true\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"live-restore"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"live-restore"\s*:[^,]*/"live-restore": true/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "live-restore": true,\n\1/' "$couch_docker_conffile"; fi; fi; service docker restart; c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--live-restore(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--live-restore(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi; fi


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"userland-proxy": false\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"userland-proxy"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"userland-proxy"\s*:[^,]*/"userland-proxy": false/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "userland-proxy": false,\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--userland-proxy(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--userland-proxy(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


echo "[Manual]" 'A reduced set of system calls reduces the total kernel surface exposed to the application and therefore improves application security. 
By default, Docker'\''s default seccomp profile is applied. If this is adequate for your environment, no action is necessary. Alternatively, if you choose to apply your own seccomp profile, use the --seccomp-profile flag at daemon start or put it in the daemon runtime parameters file. 
dockerd --seccomp-profile </path/to/seccomp/profile>

Note. A misconfigured seccomp profile could possibly interrupt your container environment. Docker-default blocked calls have been carefully scrutinized and address some critical vulnerabilities/issues within container environments (for example, kernel key ring calls).'
read -n 1 -p "Press Enter to continue..."


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"experimental": false\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"experimental"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"experimental"\s*:[^,]*/"experimental": false/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "experimental": false,\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--experimental(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--experimental(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"no-new-privileges": true\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"no-new-privileges"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"no-new-privileges"\s*:[^,]*/"no-new-privileges": true/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "no-new-privileges": true,\n\1/' "$couch_docker_conffile"; fi; fi
service docker restart
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); if [[ -n "$c_file" ]]; then grep -E "\s--no-new-privileges(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--no-new-privileges(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi


c_path=$(systemctl show -p FragmentPath docker.service | cut -d= -f2); if [ -n "$c_path" ]; then chown root:root "$c_path"; fi


c_path=$(systemctl show -p FragmentPath docker.service | cut -d= -f2); if [ -n "$c_path" ]; then chmod u-x,go-wx "$c_path"; fi


c_path=$(systemctl show -p FragmentPath docker.socket | cut -d= -f2); if [ -n "$c_path" ]; then chown root:root "$c_path"; fi


c_path=$(systemctl show -p FragmentPath docker.socket | cut -d= -f2); if [ -n "$c_path" ]; then chmod u-x,go-wx "$c_path"; fi


chown root:root /etc/docker


chmod go-w /etc/docker


chown root:root /etc/docker/certs.d/*/*


chmod ugo-wx /etc/docker/certs.d/*/*


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlscacert=" | sed -r 's/.*\s--tlscacert=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlscacert"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlscacert"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chown root:root "$c_path"; fi


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlscacert=" | sed -r 's/.*\s--tlscacert=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlscacert"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlscacert"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chmod ugo-wx "$c_path"; fi


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlscert=" | sed -r 's/.*\s--tlscert=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlscert"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlscert"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chown root:root "$c_path"; fi


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlscert=" | sed -r 's/.*\s--tlscert=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlscert"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlscert"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chmod ugo-wx "$c_path"; fi


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlskey=" | sed -r 's/.*\s--tlskey=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlskey"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlskey"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chown root:root "$c_path"; fi


c_path=$(ps -ef | grep "do[c]kerd.*\s--tlskey=" | sed -r 's/.*\s--tlskey=("[^"]*"|[^"]\S*).*/\1/'); if [ -z "$c_path" ]; then c_path=$(grep '"tlskey"' $couch_docker_conffile 2>/dev/null | sed -r 's/^.*"tlskey"\s*:\s*"([^"]*)".*$/\1/'); fi; if [ -n "$c_path" ]; then chmod u-wx,go-rwx "$c_path"; fi


chown root:docker /var/run/docker.sock


chmod u-x,go-rwx /var/run/docker.sock


chown root:root "$couch_docker_conffile"


chmod u-x,go-wx "$couch_docker_conffile"


chown root:root /etc/default/docker


chown root:root /etc/sysconfig/docker


chmod u-x,go-wx /etc/sysconfig/docker


chmod u-x,go-wx /etc/default/docker


chown root:root /run/containerd/containerd.sock


chmod u-x,go-rwx /run/containerd/containerd.sock


echo "[Manual]" 'You should ensure that the Dockerfile for each container image contains the information below: 
USER <username or ID> 
In this case, the user name or ID refers to the user that was found in the container base image. If there is no specific user created in the container base image, then make use of the useradd command to add a specific user before the USER instruction in the Dockerfile. For example, add the below lines in the Dockerfile to create a user in the container: 
RUN useradd -d /home/username -m -s /bin/bash username
USER username 

Note: If there are users in the image that are not needed, you should consider deleting them. After deleting those users, commit the image and then generate new instances of the containers. Alternatively, if it is not possible to set the USER directive in the Dockerfile, a script running as part of the CMD or ENTRYPOINT sections of the Dockerfile should be used to ensure that the container process switches to a non-root user.
Running as a non-root user can present challenges where you wish to bind mount volumes from the underlying host. In this case, care should be taken to ensure that the user running the contained process can read and write to the bound directory, according to their requirements.

By default, containers are run with root privileges and also run as the root user inside the container.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'The following procedures are useful for establishing trust for a specific image. 
 · Configure and use Docker Content trust. 
 · View the history of each Docker image to evaluate its risk, dependent on the sensitivity of the application you wish to deploy using it. 
 · Scan Docker images for vulnerabilities at regular intervals.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not install anything within the container that is not required. 
You should consider using a minimal base image rather than the standard Redhat/Centos/Debian images if you can. Some of the options available include BusyBox and Alpine. 
Not only can this trim your image size considerably, but there would also be fewer pieces of software which could contain vectors for attack.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Images should be re-built ensuring that the latest version of the base images are used, to keep the operating system patch level at an appropriate level. Once the images have been re-built, containers should be re-started making use of the updated images.

By default, containers and images are not updated automatically to address missing operating system security patches.'
read -n 1 -p "Press Enter to continue..."


sed -ri 's/(^|\s|;)DOCKER_CONTENT_TRUST=[0-9]*/\1DOCKER_CONTENT_TRUST=1/g' /etc/profile /etc/profile.d/*.sh
egrep "^([^#]+;)?\s*export\s+DOCKER_CONTENT_TRUST=1(\s|;|$)" /etc/profile /etc/profile.d/*.sh || echo "export DOCKER_CONTENT_TRUST=1" >> /etc/profile.d/cis.sh
if [[ -e /etc/bashrc ]]; then sed -ri 's/(^|\s|;)DOCKER_CONTENT_TRUST=[0-9]*/\1DOCKER_CONTENT_TRUST=1/g' /etc/bashrc; egrep "^([^#]+;)?\s*export\s+DOCKER_CONTENT_TRUST=1(\s|;|$)" /etc/bashrc || echo "export DOCKER_CONTENT_TRUST=1" >> /etc/bashrc; fi
if [[ -e /etc/bash.bashrc ]]; then sed -ri 's/(^|\s|;)DOCKER_CONTENT_TRUST=[0-9]*/\1DOCKER_CONTENT_TRUST=1/g' /etc/bash.bashrc; egrep "^([^#]+;)?\s*export\s+DOCKER_CONTENT_TRUST=1(\s|;|$)" /etc/bash.bashrc || echo "export DOCKER_CONTENT_TRUST=1" >> /etc/bash.bashrc; fi


echo "[Manual]" 'You should follow the Docker documentation and rebuild your container images to include the HEALTHCHECK instruction.

By default, HEALTHCHECK is not set.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should use update instructions together with install instructions and version pinning for packages while installing them. This prevent caching and force the extraction of the required versions. 
Alternatively, you could use the --no-cache flag during the docker build process to avoid using cached layers.

By default, Docker does not enforce any restrictions on using update instructions.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should allow setuid and setgid permissions only on executables which require them. 
You could remove these permissions at build time by adding the following command in your Dockerfile, preferably towards the end of the Dockerfile, as example: 
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true
Note! The above command would break all executables that depend on setuid or setgid permissions including legitimate ones. You should therefore be careful to modify the command to suit your requirements so that it does not reduce the permissions of legitimate programs excessively.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should use COPY rather than ADD instructions in Dockerfiles.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Do not store any kind of secrets within Dockerfiles. Where secrets are required during the build process, make use of a secrets management tool, such as the buildkit builder included with Docker.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should use a secure package distribution mechanism of your choice to ensure the authenticity of software packages.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If AppArmor is applicable for your Linux OS, you should enable it. 
1: Verify AppArmor is installed. 
2: Create or import a AppArmor profile for Docker containers. 
3: Enable enforcement of the policy. 
4: Start your Docker container using the customized AppArmor profile. For example: 
docker run --interactive --tty --security-opt="apparmor:PROFILENAME" ubuntu /bin/bash 
Alternatively, Docker'\''s default AppArmor policy can be used.

By default, the docker-default AppArmor profile is applied to running containers. This profile can be found at /etc/apparmor.d/docker.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $(sestatus | grep -iE "selinux\s+status\s*:\s*enabled") ]]; then read -p "This script enables selinux on daemon level. Containers configuration must be provided while starting them. [Ok]" a; 
if [[ ! -e "$couch_docker_conffile" ]]; then touch "$couch_docker_conffile"; chmod 644 "$couch_docker_conffile"; chown root:root "$couch_docker_conffile"; fi;
if [[ -z $(grep '{' "$couch_docker_conffile") ]]; then printf '{\n"selinux-enabled": true\n}\n' >> "$couch_docker_conffile"; else if [[ -n $(grep -E '"selinux-enabled"\s*:' "$couch_docker_conffile") ]]; then sed -ri 's/"selinux-enabled"\s*:[^,]*/"selinux-enabled": true/g' "$couch_docker_conffile"; else sed -ri '0,/^\s*\{\s*(\S.*)$/s/^\s*\{(.*$)/{\n  "selinux-enabled": true,\n\1/' "$couch_docker_conffile"; fi; fi;
service docker restart;
c_file=$(systemctl show -p FragmentPath docker.service | cut -f2 -d=); 
if [[ -n "$c_file" ]]; then grep -E "\s--selinux-enabled(=|\s)" "$c_file" && (sed -ri 's/^(\s*ExecStart\s*=.*)\s--selinux-enabled(=\S+)?(.*$)/\1\3/' "$c_file"; systemctl daemon-reload; systemctl restart docker.service) || true; fi;
fi


echo "[Manual]" 'You should execute the command below to add required capabilities: 
docker run --cap-add={"Capability 1","Capability 2"} <Run arguments> <Container Image Name or ID> <Command> 
You should execute the command below to remove unneeded capabilities: 
docker run --cap-drop={"Capability 1","Capability 2"} <Run arguments> <Container Image Name or ID> <Command> 
Alternatively, you could remove all the currently configured capabilities and then restore only the ones you specifically use: 
docker run --cap-drop=all --cap-add={"Capability 1","Capability 2"} <Run arguments> <Container Image Name or ID> <Command>
Specifically, ensure that the NET_RAW capability is removed if not required.

By default, the capabilities below are applied to containers: 
AUDIT_WRITE 
CHOWN 
DAC_OVERRIDE 
FOWNER 
FSETID 
KILL 
MKNOD 
NET_BIND_SERVICE 
NET_RAW 
SETFCAP 
SETGID 
SETPCAP 
SETUID 
SYS_CHROOT'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not run containers with the --privileged flag. For example, do not start a container using the command like below: 
docker run --interactive --tty --privileged centos /bin/bash

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not mount directories which are security sensitive on the host within containers, especially in read-write mode.

By default, no sensitive host directories are mounted within containers.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Uninstall the SSH daemon from the container and use docker exec to enter a container on the remote host. 
docker exec --interactive --tty $INSTANCE_ID sh 
OR 
docker attach $INSTANCE_ID

SSH server is running by default only in some container types.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not map container ports to privileged host ports when starting a container. You should also, ensure that there is no such container to host privileged port mapping declarations in the Dockerfile.

Note: There might be certain cases where you want to map privileged ports, because if you forbid it, then the corresponding application has to run outside of a container. For example: HTTP and HTTPS load balancers have to bind 80/tcp and 443/tcp respectively. Forbidding to map privileged ports effectively forbids from running those in a container, and mandates using an external load balancer. In such cases, those containers instances should be marked as exceptions for this recommendation.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should ensure that the Dockerfile for each container image only exposes needed ports. 
You can also completely ignore the list of ports defined in the Dockerfile by NOT using -P (UPPERCASE) or the --publish-all flag when starting the container. Instead, use the -p (lowercase) or --publish flag to explicitly define the ports that you need for a particular 
container instance. For example: 
docker run --interactive --tty --publish 5000 --publish 5001 --publish 5002 centos /bin/bash

By default, all the ports that are listed in the Dockerfile under the EXPOSE instruction for an image are opened when a container is run with the -P or --publish-all flags.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not pass the --net=host option when starting any container.

By default, containers connect to the Docker bridge when starting and do not run in the context of the host'\''s network stack.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should run the container with only as much memory as it requires by using the --memory argument. 
For example, you could run a container using the command below: 
docker run --interactive --tty --memory 256m centos /bin/bash 
In the example above, the container is started with a memory limit of 256 MB. 
Note that the output of the command below returns values in scientific notation if memory limits are in place. 
docker inspect --format='\''{{.Config.Memory}}'\'' 7c5a2d4c7fe0 
For example, if the memory limit is set to 256 MB for a container instance, the output of the command above would be 2.68435456e+08 and NOT 256m. You should convert this value using a scientific calculator.

By default, all containers on a Docker host share their resources equally and no memory limits are enforced.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should manage the CPU runtime between your containers dependent on their priority within your organization. To do so start the container using the --cpu-shares argument. 
For example, you could run a container as below: 
docker run --interactive --tty --cpu-shares 512 centos /bin/bash 
In the example above, the container is started with CPU shares of 50% of what other containers use. So if the other container has CPU shares of 80%, this container will have CPU shares of 40%. 
Every new container will have 1024 shares of CPU by default. However, this value is shown as 0 if you run the command mentioned in the audit section. 
Alternatively: 
1: Navigate to the /sys/fs/cgroup/cpu/system.slice/ directory. 
2: Check your container instance ID using docker ps. 
3: Inside the above directory (in step 1), you could have a directory called, for example: docker-<Instance ID>.scope. Navigate to this directory. 
4: You will find a file named cpu.shares. Execute cat cpu.shares. This will always give you the CPU share value based on the system. Even if there are no CPU shares configured using the -c or --cpu-shares argument in the docker run command, this file will have a value of 1024. 
If you set one container'\''s CPU shares to 512 it will receive half of the CPU time compared to the other containers. So if you take 1024 as 100% you can then derive the number that you should set for respective CPU shares. For example, use 512 if you want to set it to 50% and 256 if you want to set it 25%.

By default, all containers on a Docker host share their resources equally. No CPU shares are enforced.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should add a --read-only flag at a container'\''s runtime to enforce the container'\''s root filesystem being mounted as read only. 
docker run <Run arguments> --read-only <Container Image Name or ID> <Command> 
Enabling the --read-only option at a container'\''s runtime should be used by administrators to force a container'\''s executable processes to only write container data to explicit storage locations during its lifetime. 
Examples of explicit storage locations during a container'\''s runtime include, but are not limited to: 
1: Using the --tmpfs option to mount a temporary file system for non-persistent data writes. Example: 
docker run --interactive --tty --read-only --tmpfs "/run" --tmpfs "/tmp" centos /bin/bash 
2: Enabling Docker rw mounts at a container'\''s runtime to persist container data directly on the Docker host filesystem. Example:
docker run --interactive --tty --read-only -v /opt/app/data:/run/app/data:rw centos /bin/bash 
3: Utilizing the Docker shared-storage volume plugin for Docker data volume to persist container data. Example:
docker volume create -d convoy --opt o=size=20GB my-named-volume 
docker run --interactive --tty --read-only -v my-named-volume:/run/app/data centos /bin/bash 
3: Transmitting container data outside of the Docker controlled area during the container'\''s runtime for container data in order to ensure that it is persistent. Examples include hosted databases, network file shares and APIs.

Note! Enabling --read-only at container runtime may break some container OS packages if a data writing strategy is not defined. 

By default, a container has its root filesystem writeable, allowing all container processes to write files owned by the container'\''s actual runtime user.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should bind the container port to a specific host interface on the desired host port. For example:
docker run --detach --publish 10.2.3.4:49153:80 nginx 
In the example above, the container port 80 is bound to the host port on 49153 and would accept incoming connection only from the 10.2.3.4 external interface.

By default, Docker exposes the container ports on 0.0.0.0, the wildcard IP address that will match any possible incoming network interface on the host machine.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If you wish a container to be automatically restarted, you can use --restart=on-failure:5 (set to 5 or less) option as on example: 
docker run --detach --restart=on-failure:5 nginx

By default, containers are not configured with restart policies.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not start a container with the --pid=host argument. For example, do not start a container with the --pid=host option like: 
docker run --interactive --tty --pid=host centos /bin/bash

By default, all containers have the PID namespace enabled and the therefore the host'\''s process namespace is not shared with its containers.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not start a container with the --ipc=host argument. For example, do not start a container with option --ipc=host like: 
docker run --interactive --tty --ipc=host centos /bin/bash

By default, all containers have their IPC namespace enabled and host IPC namespace is not shared with any container.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not directly expose host devices to containers. If you do need to expose host devices to containers, you should use granular permissions as appropriate to your organization: 
For example, do not start a container using the command like: 
docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rwm --device=/dev/temp_sda:/dev/temp_sda:rwm centos bash 
You should only share the host device using appropriate permissions, examples: 
docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rw --device=/dev/temp_sda:/dev/temp_sda:r centos bash

By default, host devices are not exposed to containers. If you do not provide sharing permissions and choose to expose a host device to a container, the host device is be exposed with read, write and mknod permissions.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should only override the default ulimit settings if needed in a specific case. For example, to override default ulimit settings start a container like: 
docker run --ulimit nofile=1024:1024 --interactive --tty centos /bin/bash

Default: Container instances inherit the default ulimit settings set at the Docker daemon level.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Do not mount volumes in shared mode propagation. For example, do not start a container like: 
docker run <Run arguments> --volume=/hostPath:/containerPath:shared <Container Image Name or ID> <Command>

By default, the container mounts are private.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not start a container with the --uts=host argument. For example, do not start a container using the command like: 
docker run --rm --interactive --tty --uts=host rhel7.2

By default, all containers have the UTS namespace enabled and the host UTS namespace is not shared with any containers.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'By default, seccomp profiles are enabled. You do not need to do anything unless you want to modify and use a modified seccomp profile.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not use the --privileged option in docker exec commands.

By default, the docker exec command runs without the --privileged option.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not use the --user=root option in docker exec commands.

By default, the docker exec command runs without the --user option.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not use the --cgroup-parent option within the docker run command unless strictly required.

By default, containers run under docker cgroup.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should start your container with the option --security-opt=no-new-privileges like: 
docker run --rm -it --security-opt=no-new-privileges ubuntu bash

By default, new privileges are not restricted.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should run the container using the --health-cmd parameter. For example: 
docker run -d --health-cmd='\''stat /etc/passwd || exit 1'\'' nginx

By default, health checks are not carried out at container runtime.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should use proper version pinning mechanisms (the "latest" tag which is assigned by default is still vulnerable to caching attacks) to avoid extracting cached older versions. Version pinning mechanisms should be used for base images, packages, and entire images. You can customize version pinning rules according to your requirements.

By default, Docker commands extract the local copy unless version pinning mechanisms are used or the local cache is cleared.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Use --pids-limit flag with an appropriate value when launching the container. For example: 
docker run -it --pids-limit 100 <Image_ID> 
In the above example, the number of processes allowed to run at any given time is set to 100. After a limit of 100 concurrently running processes is reached, Docker would restrict any new process creation.

Note. The PIDs cgroup limit works only for kernel versions 4.3 and higher.

The Default value for --pids-limit is 0 which means there is no restriction on the number of forks.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should follow the Docker documentation and set up a user-defined network. Containers should not be run in the default bridge network.

By default, Docker runs containers within the default docker0 bridge.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should not share user namespaces between host and containers. For example, you should not run the command with options like: 
docker run --rm -it --userns=host ubuntu bash

By default, the host user namespace is shared with containers unless user namespace support is enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should ensure that no containers mount docker.sock as a volume.

By default, docker.sock is not mounted inside containers.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should keep only the images that you actually need and establish a workflow to remove old or stale images from the host. Additionally, you should use features such as pull-by-digest to get specific images from the registry. 
You can follow the steps below to find unused images on the system so they can be deleted. 
Step 1 Make a list of all image IDs that are currently instantiated by executing the command below: 
docker images --quiet | xargs docker inspect --format '\''{{ .Id }}: Image={{ .Config.Image }}'\'' 
Step 2: List all the images present on the system by executing the command below: 
docker images --all
Step 3: Compare the list of image IDs created from Step 1 and Step 2 to find out images which are currently not being instantiated. 
Step 4: Decide if you want to keep the images that are not currently in use. If they are not needed, delete them by executing the following command: 
docker rmi $IMAGE_ID 
Alternatively, the docker system prune command can be used to remove dangling images which are not tagged or, if necessary, all images that are not currently used by a running container when used with the -a option.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should periodically check your container inventory on each host and clean up containers which are not in active use with the command below:
docker container prune'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If swarm mode has been enabled on a system in error, you should run the command below: 
docker swarm leave

By default, Docker swarm mode is not enabled.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If an excessive number of managers is configured, the excess nodes can be demoted to workers using the following command: 
docker node demote <ID> 
Where is the node ID value of the manager to be demoted.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Resolving this issues requires re-initialization of the swarm, specifying a specific interface for the --listen-addr parameter.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should create overlay networks the with --opt encrypted flag.

By default, data exchanged in overlay networks in Docker swarm mode is not encrypted.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should follow the docker secret documentation and use it to manage secrets effectively.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If you are initializing a swarm, use the command below. 
docker swarm init --autolock 
If you want to set --autolock on an existing swarm manager node, use the following command. 
docker swarm update --autolock

Note! A swarm in auto-lock mode will not recover from a restart without manual intervention from an administrator to enter the unlock key. This may not always be desirable, and should be reviewed at a policy level.

By default, the swarm manager does not run in auto-lock mode.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should run the command below to rotate the keys. 
docker swarm unlock-key --rotate 
Additionally, to facilitate auditing of this recommendation, you should maintain key rotation records and ensure that you establish a pre-defined frequency for key rotation.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should run the command to set the desired expiry time on the node certificate (90 days or less). For example: 
docker swarm update --cert-expiry 48h

By default, node certificates are rotated automatically every 90 days.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'You should initialize the swarm with dedicated interfaces for management and data planes respectively. For example, 
docker swarm init --advertise-addr=192.168.0.1 --data-path-addr=17.1.0.3
This requires two network interfaces per node.

By default, data plane traffic is not separated from management plane traffic.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Swarm CA certificate should be rotated once a year or more frequently. The following command may be used:
docker swarm ca --rotate

By default, root CA certificates are not rotated.'
read -n 1 -p "Press Enter to continue..."



