#!/usr/bin/env bash


which dnf && dnf -y install rsyslog || (which yum && yum -y install rsyslog)
which apt && apt -y install rsyslog


if [[ -n $(which systemctl) ]]; then systemctl is-enabled rsyslog | grep "^enabled" || systemctl enable rsyslog; systemctl is-active rsyslog | grep "^active" || systemctl start rsyslog; fi
if [[ -e /etc/init/rsyslog.conf ]]; then sed -ri "s/^\s*manual\a*$/# manual/" /etc/init/rsyslog.*; fi


chmod go-rwx /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true
chown root /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true


grep -Ei '^\s*(module\(load="imuxsock"|\$ModLoad imuxsock(\s|#|$))' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || sed -i '1 i\module(load="imuxsock")' /etc/rsyslog.conf


grep -Ei '^\s*(module\(load="imklog"|\$ModLoad imklog(\s|#|$))' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || sed -i '1 i\module(load="imklog")' /etc/rsyslog.conf


sed -ri 's/\s*permitnonkernelfacility="\w+"//g' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true
sed -ri 's/^(\s*module\s*\(load="imklog"[^#)]*)(\).*$|$)/\1 permitnonkernelfacility="on"\2/' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true

sed -ri 's/^(\s*\$[Kk][Ll]og[Pp]ermit[Nn]on[Kk]ernel[Ff]acility\s.*)$/## \1/' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true
sed -ri 's/^(\s*\$[Mm]od[Ll]oad\s+imklog.*)$/\1\n$KLogPermitNonKernelFacility on/' /etc/rsyslog.conf /etc/rsyslog.d/*.conf || true


for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do rm --interactive=never "$f".couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^[^#]*module\s*\([^#)]*load\s*=\s*"builtin:omfile"' | grep -vEi '^[^#)]*filecreatemode="0[0246][04]0"') ]]; then echo "$line" | sed -r 's/\s*filecreatemode="[0-9]+"//g' | sed 's/)/ filecreatemode="0640")/' >> "$f".couch_tmp; else echo "$line" >> "$f".couch_tmp; fi; done < "$f"; cp "$f".couch_tmp "$f"; done

for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do rm --interactive=never "$f".couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^[^#]*module\s*\([^#)]*load\s*=\s*"builtin:omfile"' | grep -vEi '^[^#)]*dircreatemode="0[0-7]00"') ]]; then echo "$line" | sed -r 's/\s*dircreatemode="[0-9]+"//g' | sed 's/)/ dircreatemode="0700")/' >> "$f".couch_tmp; else echo "$line" >> "$f".couch_tmp; fi; done < "$f"; cp "$f".couch_tmp "$f"; done

for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do rm --interactive=never "$f".couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^\s*\$FileCreateMode\s' | grep -vEi '^\s*\$FileCreateMode\s+0?[0246][04]0(\s|$)') ]]; then echo "## $line" >> "$f".couch_tmp; echo '$FileCreateMode 0640' >> "$f".couch_tmp; else echo "$line" >> "$f".couch_tmp; fi; done < "$f"; cp "$f".couch_tmp "$f"; done

for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do rm --interactive=never "$f".couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^\s*\$DirCreateMode\s' | grep -vEi '^\s*\$DirCreateMode\s+0?[0-7]00(\s|$)') ]]; then echo "## $line" >> "$f".couch_tmp; echo '$DirCreateMode 0700' >> "$f".couch_tmp; else echo "$line" >> "$f".couch_tmp; fi; done < "$f"; cp "$f".couch_tmp "$f"; done

grep -Ei '^[^#)]*filecreatemode(\s+|=)"?0[0246][04]0("|\s|$)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || sed -i '1 i\module(load="builtin:omfile" filecreatemode="0640" dircreatemode="0700")' /etc/rsyslog.conf


echo "[Manual]" 'Configure '\''Template'\'' setting as needed by adding parameter to '\''omfile'\'' module loading directive. Example:
module(load="builtin:omfile" template="RSYSLOG_FileFormat")

Default is RSYSLOG_FileFormat.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Review rsyslog configuration files and comment or remove including of excessive modules if there are some.'
read -n 1 -p "Press Enter to continue..."


grep -Eih '^\s*(auth,authpriv\.(\*|debug)|authpriv,auth\.(\*|debug)|authpriv\.(\*|debug);auth\.(\*|debug)|auth\.(\*|debug);authpriv\.(\*|debug))\s+/(\w+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vEi '^\s*(auth,authpriv\.(\*|debug)|authpriv,auth\.(\*|debug)|authpriv\.(\*|debug);auth\.(\*|debug)|auth\.(\*|debug);authpriv\.(\*|debug))\s+/dev(/|\s|$)' || (echo 'auth,authpriv.*                  /var/log/auth.log' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf; if [[ ! -e /var/log/auth.log ]]; then touch /var/log/auth.log; chmod go-rwx /var/log/auth.log; chown root:root /var/log/auth.log; fi)


grep -Eih '^\s*kern\.(\*|debug|info|notice)\s+-?/(\w+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vEi '^\s*kern\.(\*|debug|info|notice)\s+-?/dev(/|\s|$)' || (echo 'kern.info                           /var/log/kern.log' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf; if [[ ! -e /var/log/kern.log ]]; then touch /var/log/kern.log; chmod go-rwx /var/log/kern.log; chown root:root /var/log/kern.log; fi)


grep -Eih '^\s*cron\.(\*|debug|info|notice)\s+-?/(\w+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vEi '^\s*cron\.(\*|debug|info|notice)\s+-?/dev(/|\s|$)' || (echo 'cron.info                           /var/log/cron.log' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf; if [[ ! -e /var/log/cron.log ]]; then touch /var/log/cron.log; chmod go-rwx /var/log/cron.log; chown root:root /var/log/cron.log; fi)


grep -Eih '^\s*mail\.(\*|debug|info|notice)\s+-?/(\w+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vEi '^\s*mail\.(\*|debug|info|notice)\s+-?/dev(/|\s|$)' || (echo 'mail.info                           -/var/log/maillog' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf; if [[ ! -e /var/log/maillog ]]; then touch /var/log/maillog; chmod go-rwx /var/log/maillog; chown root:root /var/log/maillog; fi)


for f in `ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf`; do rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ $(echo "$line" | grep -Ei '^\s*(\*|\S*;\*)\.(\*|debug|info|notice|warning|warn|err|error)' | grep -vEi '^\S*[;,]auth(,\w+)*?\.none') ]]; then echo "$line" | sed -r 's/^\s*(\S+)\s/\1;auth.none /' >> $f.couch_tmp; else echo "$line" >> $f.couch_tmp; fi; done < $f; cp $f.couch_tmp $f; done

for f in `ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf`; do rm --interactive=never $f.couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do if [[ $(echo "$line" | grep -Ei '^\s*(\*|\S*;\*)\.(\*|debug|info|notice|warning|warn|err|error)' | grep -vEi '^\S*[;,]authpriv(,\w+)*?\.none') ]]; then echo "$line" | sed -r 's/^\s*(\S+)\s/\1;authpriv.none /' >> $f.couch_tmp; else echo "$line" >> $f.couch_tmp; fi; done < $f; cp $f.couch_tmp $f; done

grep -Eih '^\s*\*\.(\*|debug|info|notice)(;\S+)?\s+-?/(\w+)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -vEi '^\s*\*\.(\*|debug|info|notice)(;\S+)?\s+-?/dev(/|\s|$)' || (echo '*.info;mail.none;authpriv.none;auth.none;cron.none;kern.none               /var/log/messages' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf; if [[ ! -e /var/log/messages ]]; then touch /var/log/messages; chmod go-rwx /var/log/messages; chown root:root /var/log/messages; fi)


grep -Ei '^\s*\*\.emerg(;\S+)?\s+:omusrmsg:\*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || (echo '*.emerg                                                 :omusrmsg:*' >> /etc/rsyslog.d/security.conf; chmod go-rwx /etc/rsyslog.d/security.conf; chown root /etc/rsyslog.d/security.conf)


echo "[Manual]" 'Configure sending logs to remote designated logging server. Recommended log forwarding mechanism is RELP.  RELP works much like imtcp or imgssapi, except that no message loss can occur.
1) Install dependencies for RELP on both member hosts and central logging servers:
# apt install rsyslog-relp
OR
# yum install rsyslog-relp
OR
# zypper install rsyslog-relp
2) On usual hosts include omrelp module for sending logs to remote logging server (the remote server must be configured with imrelp module to accepr logs in RELP format). Ensure the following line is present and not commented in rsyslog configuration files:
module(load="omrelp")
Configure sending logs to designated remote server with omrelp in rsyslog configuration files. Example:
action(type="omrelp" target="192.168.233.153" port="20514")
3) On designated central logging servers include imrelp module and condigure ruleset for RELP logging in rsyslog configuration files. Example (any other actions may be configured):
module(load="imrelp" ruleset="relp")
ruleset (name="relp") { action(type="omfile" file="/var/log/relp_log") }
Configure receiving logs by RELP on designated port in rsyslog configuration files. Example:
input(type="imrelp" port="20514")

Note: Please note that with the currently supported relp protocol version, a minor message duplication may occur if a network connection between the relp client and relp server breaks after the client could successfully send some messages but the server could not acknowledge them. The window of opportunity is very slim, but in theory this is possible.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" '1) Sending logs in RELP format can be configured with TLS protection. It requires rsyslog-gnutls package installation:
# apt install rsyslog-gnutls
OR
# yum install rsyslog-gnutls
OR
# zypper install rsyslog-gnutls
2) Create private key and certificate for rsyslog which are signed by CA and trusted for designated remote logging servers and member hosts (https://www.rsyslog.com/using-tls-with-relp/).
3) On member hosts add TLS parameters configuration to configuration of sending logs to remote server in rsyslog configuration files. Example:
action(type="omrelp" target="192.168.233.153" port="20514" tls="on" tls.caCert="/home/test/cert/ca.pem" tls.myCert="/home/test/cert/ubuntu1-cert.pem" tls.myPrivKey="/home/test/cert/ubuntu1-key.pem" tls.authmode="name" tls.permittedpeer=["ubuntu-server"] )
Enable TLS transportation with tls="on" and secure it with certificates. All three certificate files are needed (CA certificate, local certificate and local private key file).
Authentication of logging server by name may be configured with setting tls.authmode to "name". By that, the subjectAltName and, as a fallback, the subject common name from the other machine'\''s certificate will be checked against the permittedpeer list to ensure the right machine uses the certificate.
4) On designated central logging servers add TLS parameters configuration to configuration of receiving logs with RELP. Example:
input(type="imrelp" port="20514" tls="on" tls.caCert="/home/test/cert/ca.pem" tls.myCert="/home/test/cert/server-cert.pem" tls.myPrivKey="/home/test/cert/server-key.pem" tls.authMode="name" tls.permittedpeer=["ubuntu-client1","ubuntu-client2","ubuntu-client3"] )
Enable TLS transportation with tls="on" and secure it with certificates. All three certificate files are needed (CA certificate, local certificate and local private key file).
Authentication of logging server by name may be configured with setting tls.authmode to "name". By that, the subjectAltName and, as a fallback, the subject common name from the other machine'\''s certificate will be checked against the permittedpeer list to ensure the right machine uses the certificate.'
read -n 1 -p "Press Enter to continue..."


c_rs_name=$(grep -Eih 'module\s*\([^#)]*?load\s*=\s*"(imrelp|imgssapi|imtcp|imudp)"[^#)]*ruleset\s*=\s*"(.*?)"' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | sed -r 's/^.*ruleset\s*=\s*"([^"]*)".*$/\1/');
if [[ -n "$c_rs_name" ]]; then \
for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do i=0; j=0; rm -f "$f".couch_tmp 2>/dev/null;
while read -r line || [[ -n "$line" ]]; do \
if [[ -n $(echo "$line" | grep -Ei "ruleset\s*\([^#)]*?name=\"${c_rs_name}\"") ]]; then i=1; j=1; rm -f /tmp/couch_temp_file; fi;
if [ "$j" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$f".couch_tmp; fi;
if [[ "$i" == "1" && -n $(echo "$line" | grep ')') ]]; then i=0; 
sed -ri 's/\s*[Qq]ueue\.[Tt]ype="\w+"//g' /tmp/couch_temp_file; sed -i 's/)/ queue.type="LinkedList")/' /tmp/couch_temp_file;
sed -ri 's/\s*[Qq]ueue\.[Ss]ave[Oo]n[Ss]hutdown="\w+"//g' /tmp/couch_temp_file; sed -i 's/)/ queue.saveOnShutdown="on")/' /tmp/couch_temp_file;
grep -Ei '^[^#)]*queue\.filename="\S' /tmp/couch_temp_file || sed -i "s/)/ queue.filename=\"${c_rs_name}.queue\")/" /tmp/couch_temp_file;
grep -Ei '^[^#)]*queue\.maxDiskSpace="\S' /tmp/couch_temp_file || sed -i 's/)/ queue.maxDiskSpace="1g")/' /tmp/couch_temp_file;
fi;
if [[ "$j" == "1" && -n $(echo "$line" | grep '}') ]]; then j=0; 
if [[ -n $(grep -Ei '^[^#}]*action\.resumeRetryCount="\S' /tmp/couch_temp_file) ]]; then sed -ri 's/^([^#}]*[Aa]ction\.[Rr]esume[Rr]etry[Cc]ount=")[^"]*(".*$)/\1-1\2/' /tmp/couch_temp_file; else sed -ri 's/^([^#}]*action\s*\()/\1 action.resumeRetryCount="-1" /' /tmp/couch_temp_file; fi;
cat /tmp/couch_temp_file >> "$f".couch_tmp; rm -f /tmp/couch_temp_file; 
fi; 
done < "$f"; cp "$f".couch_tmp "$f"; rm -f "$f".couch_tmp;
done;
fi;

for f in $(ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf); do j=0; rm -f "$f".couch_tmp 2>/dev/null; while read -r line || [[ -n "$line" ]]; do echo $i; echo $j; echo "$line"; \
if [[ -n $(echo "$line" | grep -Ei "action\s*\(") ]]; then j=1; rm -f /tmp/couch_temp_file; fi; \
if [ "$j" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$f".couch_tmp; fi; \
if [[ "$j" == "1" && -n $(echo "$line" | grep ')') ]]; then j=0; \
if [[ -n $(grep -Ei '^[^#)]*type="(omrelp|omfwd)' /tmp/couch_temp_file) ]]; then \
sed -ri 's/\s*[Qq]ueue\.[Tt]ype="\w+"//g' /tmp/couch_temp_file; sed -i 's/)/ queue.type="LinkedList")/' /tmp/couch_temp_file; \
sed -ri 's/\s*[Qq]ueue\.[Ss]ave[Oo]n[Ss]hutdown="\w+"//g' /tmp/couch_temp_file; sed -i 's/)/ queue.saveOnShutdown="on")/' /tmp/couch_temp_file; \
grep -Ei '^[^#)]*queue\.filename="\S' /tmp/couch_temp_file || sed -i 's/)/ queue.filename="remote_logging.queue")/' /tmp/couch_temp_file; \
grep -Ei '^[^#)]*queue\.maxDiskSpace="\S' /tmp/couch_temp_file || sed -i 's/)/ queue.maxDiskSpace="1g)"/' /tmp/couch_temp_file; \
sed -ri 's/\s*[Aa]ction\.[Rr]esume[Rr]etry[Cc]ount="[^"]*"//g' /tmp/couch_temp_file; sed -i 's/)/ action.resumeRetryCount="-1")/' /tmp/couch_temp_file; \
fi; \
cat /tmp/couch_temp_file >> "$f".couch_tmp; rm -f /tmp/couch_temp_file; \
fi; \
done < "$f"; cp "$f".couch_tmp "$f"; rm -f "$f".couch_tmp; \
done;


for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "\(.+ file\=\".+\"\)")0; do if [[ "$each" =~ ^.*file=\"(.*)\"\)$ ]]; then couch_temp="${BASH_REMATCH[1]}"; [ ! -e "$couch_temp" ] && touch "$couch_temp"; if [ $(echo "$couch_temp" | grep -E "(utmp|wtmp)") ]; then chmod g-wx,o-rwx "$couch_temp"; else if [[ -n $(stat -c "%u %g" "$couch_temp" | grep "^0 0$") ]]; then chmod go-rwx "$couch_temp"; else chmod g-wx,o-rwx "$couch_temp"; fi; fi; fi; done
for each in $(grep -h ^[^#] /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null | egrep "^.+\..+\s+-?/.+$" | grep -v -i IncludeConfig); do if [[ "$each" =~ ^-?(/[^:;]+)[^:]*$ ]]; then couch_temp="${BASH_REMATCH[1]}"; [ ! -e "$couch_temp" ] && touch "$couch_temp"; if [ $(echo "$couch_temp" | grep -E "(utmp|wtmp)") ]; then chmod g-wx,o-rwx "$couch_temp"; else if [[ -n $(stat -c "%u %g" "$couch_temp" | grep "^0 0$") ]]; then chmod go-rwx "$couch_temp"; else chmod g-wx,o-rwx "$couch_temp"; fi; fi; fi; done



