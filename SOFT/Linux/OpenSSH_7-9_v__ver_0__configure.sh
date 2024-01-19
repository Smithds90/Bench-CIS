#!/usr/bin/env bash

ssh_cf=$(cd /etc/ssh; files=( /etc/ssh/sshd_config ); couch_a=$(grep -i "^\s*include\s" "/etc/ssh/sshd_config"); while (echo "$couch_a" | grep -i "^\s*include\s" 1>/dev/null); do couch_b=''; while read -r _ line; do files+=( $line ); [ -n "$line" ] && couch_b+=$(grep -ih "^\s*include\s" $line)$'\n'; done <<< "$couch_a"; couch_a="$couch_b"; done; printf '%s;' "${files[@]}" | sed 's/;$//')


echo "[Manual]" 'Upgrade the OpenSSH service to a version that has no security bugs and apply any patches recommended by the vendor.'
read -n 1 -p "Press Enter to continue..."


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*PubkeyAuthentication/# PubkeyAuthentication/i" "$f"; done


if [ -n $(sshd -V 2>&1 | grep -Ei "^OpenSSH(_|\s+)(7\.[0-3][^0-9]|[1-6]\.)") ]; then sed -i "s/^\s*Protocol/# Protocol/i" /etc/ssh/sshd_config; sed -i "4 i Protocol 2" /etc/ssh/sshd_config; fi


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*LogLevel/# LogLevel/i" "$f"; done;
sed -i "4 i LogLevel info" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do chown root:root "$f"; chmod u-x,go-wx "$f"; done


find -L /etc/ssh -xdev -type f -print | while read -r l_file; do if file "$l_file" | grep -Pq ':\h+OpenSSH\h+private\h+key\b'; then if [ $(stat -L -c "%G" "$l_file") == "ssh_keys" ]; then chmod u-x,g-wx,o-rwx "$l_file"; else chmod u-x,go-rwx "$l_file"; fi; fi; done


find -L /etc/ssh -xdev -type f -print | while read -r l_file; do if file "$l_file" | grep -Pq ':\h+OpenSSH\h+(\H+\h+)?public\h+key\b'; then chmod u-x,go-wx "$l_file"; fi; done


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*X11Forwarding/# X11Forwarding/i" "$f"; done;
sed -i "4 i X11Forwarding no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*MaxAuthTries/# MaxAuthTries/i" "$f"; done;
sed -i "4 i MaxAuthTries 3" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*IgnoreRhosts/# IgnoreRhosts/i" "$f"; done;
sed -i "4 i IgnoreRhosts yes" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*HostbasedAuthentication/# HostbasedAuthentication/i" "$f"; done;
sed -i "4 i HostbasedAuthentication no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*AllowTcpForwarding/# AllowTcpForwarding/i" "$f"; done; 
sed -i "4 i AllowTcpForwarding no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*PermitRootLogin/# PermitRootLogin/i" "$f"; done;
sed -i "4 i PermitRootLogin no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*PermitEmptyPasswords/# PermitEmptyPasswords/i" "$f"; done;
sed -i "4 i PermitEmptyPasswords no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*PermitUserEnvironment/# PermitUserEnvironment/i" "$f"; done;
sed -i "4 i PermitUserEnvironment no" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*LoginGraceTime/# LoginGraceTime/i" "$f"; done;
sed -i "4 i LoginGraceTime 45" /etc/ssh/sshd_config


ciphers_line=$(sshd -T 2>/dev/null | grep -Ei "^\s*Ciphers\s" | sed -E ':a s/(\s|,)(3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator\.liu\.se)(,|$)/\1/; ta;' | sed 's/,$//')
IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*Ciphers/# Ciphers/i" "$f"; done;
sed -i "4 i $ciphers_line" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;

if [[ -n $(sshd -V 2>&1 | grep -Ei '^OpenSSH(_|\s+)(8\.(2p1|[3-9]|\d\d)|9\.|\d\d)') ]]; then 
  sshd -T 2>/dev/null | grep -Ei '^\s*ClientAliveInterval\s+[1-9]' || (for f in "${conf_files[@]}"; do sed -i "s/^\s*ClientAliveInterval/# ClientAliveInterval/i" "$f"; done; sed -i "4 i ClientAliveInterval 15" /etc/ssh/sshd_config); 
  sshd -T 2>/dev/null | grep -Ei '^\s*ClientAliveCountMax\s+[1-9]' || (for f in "${conf_files[@]}"; do sed -i "s/^\s*ClientAliveCountMax/# ClientAliveCountMax/i" "$f"; done; sed -i "4 i ClientAliveCountMax 3" /etc/ssh/sshd_config); 
else 
  sshd -T 2>/dev/null | grep -Ei '^\s*ClientAliveInterval\s+[1-9]' || (for f in "${conf_files[@]}"; do sed -i "s/^\s*ClientAliveInterval/# ClientAliveInterval/i" "$f"; done; sed -i "4 i ClientAliveInterval 300" /etc/ssh/sshd_config); 
  sshd -T 2>/dev/null | grep -Ei '^\s*ClientAliveCountMax\s+0' || (for f in "${conf_files[@]}"; do sed -i "s/^\s*ClientAliveCountMax/# ClientAliveCountMax/i" "$f"; done; sed -i "4 i ClientAliveCountMax 0" /etc/ssh/sshd_config); 
fi;


if [ -z $(sshd -T 2>/dev/null | grep -Ei "^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s") ]; then 
  read -p "Enter users allowed to use SSH, separated with space (example:root admin administrator): [default:empty]" ssh_allow_users; 
  if [ -n "$ssh_allow_users" ]; then sed -i "s/^\s*AllowUsers/# AllowUsers/i" /etc/ssh/sshd_config; sed -i "4 i AllowUsers $ssh_allow_users" /etc/ssh/sshd_config; fi; 
  read -p "Enter groups allowed to use SSH, separated with space (example:root admin administrator): [default:empty]" ssh_allow_groups; 
  if [ -n "$ssh_allow_groups" ]; then sed -i "s/^\s*AllowGroups/# AllowGroups/i" /etc/ssh/sshd_config; sed -i "4 i AllowGroups $ssh_allow_groups" /etc/ssh/sshd_config; fi; 
  read -p "Enter users denied to use SSH, separated with space (example:guest nobody): [default:empty]" ssh_deny_users; 
  if [ -n "$ssh_deny_users" ]; then sed -i "s/^\s*DenyUsers/# DenyUsers/i" /etc/ssh/sshd_config; sed -i "4 i DenyUsers $ssh_deny_users" /etc/ssh/sshd_config; fi; 
  read -p "Enter groups denied to use SSH, separated with space (example:guest nobody): [default:empty]" ssh_deny_groups; 
  if [ -n "$ssh_deny_groups" ]; then sed -i "s/^\s*DenyGroups/# DenyGroups/i" /etc/ssh/sshd_config; sed -i "4 i DenyGroups $ssh_deny_groups" /etc/ssh/sshd_config; fi;
fi


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*Banner/# Banner/i" "$f"; done;
sed -i "4 i Banner /etc/issue.net" /etc/ssh/sshd_config


if [ -n $(sshd -V 2>&1 | grep -Ei "^OpenSSH(_|\s+)(7\.[0-4][^0-9]|[1-6]\.)") ]; then sed -i "s/^\s*UsePrivilegeSeparation/# UsePrivilegeSeparation/i" /etc/ssh/sshd_config; sed -i "4 i UsePrivilegeSeparation yes" /etc/ssh/sshd_config; a=$(grep ^sshd /etc/passwd 2>&1); if [ -z "$a" ]; then useradd sshd -r -d /var/empty/sshd -s /sbin/nologin -c "Couch-created SSH-user for privilege separation"; fi; fi


getent passwd | cut -d: -f6 | while read -r dir; do chmod -R go-rwx "$dir/.ssh" 2>/dev/null || true; done


macs_line=$(sshd -T 2>/dev/null | grep -Ei "^\s*MACs\s" | sed -E ':a s/(\s|,)(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh.com|umac-128@openssh.com|hmac-md5-etm@openssh.com|hmac-md5-96-etm@openssh.com|hmac-ripemd160-etm@openssh.com|hmac-sha1-etm@openssh.com|hmac-sha1-96-etm@openssh.com|umac-64-etm@openssh.com|umac-128-etm@openssh.com)(,|$)/\1/; ta;' | sed 's/,$//')
IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -ri "s/^\s*MACs\s/# MACs /i" "$f"; done;
sed -i "4 i $macs_line" /etc/ssh/sshd_config


ciphers_line=$(sshd -T 2>/dev/null | grep -Ei "^\s*KexAlgorithms\s" | sed -E ':a s/(\s|,)(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)(,|$)/\1/; ta;' | sed 's/,$//')
IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*KexAlgorithms/# KexAlgorithms/i" "$f"; done;
sed -i "4 i $ciphers_line" /etc/ssh/sshd_config


IFS=';' read -r -a conf_files <<< "$ssh_cf"
cd /etc/ssh;
for f in "${conf_files[@]}"; do sed -i "s/^\s*UsePAM/# UsePAM/i" "$f"; done;
sed -i "4 i UsePAM yes" /etc/ssh/sshd_config



