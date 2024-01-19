#!/usr/bin/env bash

ap_ctl=$(ap_ctl=$(which httpd); [ -z "$ap_ctl" ] && ap_ctl=$(which apachectl); [ -z "$ap_ctl" ] && ap_ctl=$(which apache2ctl); [ -z "$ap_ctl" ] && ap_ctl=$(find /bin -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /sbin -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /usr/bin -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /usr/sbin -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /usr/local -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /usr/share -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /var/local -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /var/opt -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /opt -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); [ -z "$ap_ctl" ] && ap_ctl=$(find /srv -type f \( -name apachectl -o -name httpd -o -name apache2ctl \) 2>/dev/null | egrep "bin/(apachectl|apache2ctl|httpd)" | head -n 1); echo $ap_ctl)

ap_sr=$("$ap_ctl" -t -D DUMP_RUN_CFG 2>/dev/null | grep '^ServerRoot' | sed -r 's/^ServerRoot:\s*//' | sed 's,",,g')

ap_c=$(c_file=$("$ap_ctl" -t -D DUMP_INCLUDES 2>/dev/null | grep '(\*)' | sed -r 's/^\s*\(\*\)\s*//'); [[ -z "$c_file" ]] && c_file=$(ps axo user,comm,args | awk '( $1 == "root" && ( $2 == "apache2" || $2 == "httpd") ) {print $0}' | head -n 1 | grep -E "\s-f\s" | sed -r 's;^.*\s-f\s+("[^"]*"|\S+)(\s.*$|$);\1;'); [[ -z "$c_file" ]] && c_file=$("$ap_ctl" -V 2>/dev/null | grep SERVER_CONFIG_FILE | cut -d= -f2 | sed 's,",,g'); if [[ "$c_file" =~ ^/.* ]]; then printf "$c_file"; else printf "$ap_sr/${c_file}"; fi)

ap_cf=$(if [[ -n $("$ap_ctl" -t -D DUMP_INCLUDES 2>/dev/null) ]]; then "$ap_ctl" -t -D DUMP_INCLUDES 2>/dev/null | grep -E '\([\*0-9]+\)' | sed -r 's/^[^)]*\)\s*//' | while read -r line; do printf "$line "; done | sed -r 's/\s$//'; else printf "$ap_c"; grep -Ehi "^\s*Include" "$ap_c" 2>/dev/null | sed -r 's/^\s*Include(Optional)?\s+//i' | sed -r "s/^\s*[\"']//" | sed -r "s/[\"']\s*$//" | while read -r line; do cd "$ap_sr"; printf " $(ls $line | xargs)"; done; fi)

ap_dr=$("$ap_ctl" -t -D DUMP_RUN_CFG 2>/dev/null | grep '^Main DocumentRoot' | sed -r 's/^Main DocumentRoot:\s*//' | sed 's,",,g')


echo "[Manual]" 'Leverage the package or services manager for your OS to uninstall or disable unneeded 
services. On Red Hat systems, the following will disable a given service:
chkconfig <servicename> off'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Consult Apache module documentation for descriptions of each module in order to determine the necessary modules for the specific installation: http://httpd.apache.org/docs/2.4/mod/ . The unnecessary static compiled modules are disabled through compile time configuration options as documented in http://httpd.apache.org/docs/2.4/programs/configure.html. The dynamically loaded 
modules are disabled by commenting out or removing the LoadModule directive from the Apache configuration files (typically httpd.conf). Some modules may be separate packages, and may be removed.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Perform either one of the following:
- For source builds with static modules, run the Apache ./configure script without 
including the --disable-log-config script options.
$ cd $DOWNLOAD_HTTPD
$ ./configure
- For dynamically loaded modules, add or modify the LoadModule directive so that it is present in the apache configuration as below and not commented out :LoadModule log_config_module modules/mod_log_config.so'
read -n 1 -p "Press Enter to continue..."


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+dav_module\)'##\1'g" $ap_cf
sed -i "s'^\s*\(LoadModule\s\+dav_fs_module\)'##\1'g" $ap_cf
sed -i "s'^\s*\(LoadModule\s\+dav_lock_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep -E "(dav_module|dav_fs_module|dav_lock_module)" | grep static && (echo Recompile Apache without WEBDAV modules && read -p "Next" a) || true


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+status_module\s\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep status_module | grep static && (echo Recompile Apache without mod_status module && read -p "Next" a) || true


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+autoindex_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep autoindex_module | grep static && (echo Recompile Apache without autoindex_module && read -p "Next" a) || true
sed -ri "s/^\s*(AddAlt|AddAltByEncoding|AddAltByType|AddDescription|AddIcon|AddIconByEncoding|AddIconByType|DefaultIcon|HeaderName|IndexHeadInsert|IndexIgnore|IndexIgnoreReset|IndexOptions|IndexOrderDefault|IndexStyleSheet|ReadmeName)\s/##\1 /i" $ap_cf


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+proxy_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_module | grep static && (echo Recompile Apache without proxy_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_connect_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_connect_module | grep static && (echo Recompile Apache without proxy_connect_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_ftp_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_ftp_module | grep static && (echo Recompile Apache without proxy_ftp_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_http_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_http_module | grep static && (echo Recompile Apache without proxy_http_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_fcgi_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_fcgi_module | grep static && (echo Recompile Apache without proxy_fcgi_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_scgi_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_scgi_module | grep static && (echo Recompile Apache without proxy_scgi_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_ajp_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_ajp_module | grep static && (echo Recompile Apache without proxy_ajp_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_balancer_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_balancer_module | grep static && (echo Recompile Apache without proxy_balancer_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_express_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_express_module | grep static && (echo Recompile Apache without proxy_express_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_wstunnel_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_wstunnel_module | grep static && (echo Recompile Apache without proxy_wstunnel_module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+proxy_fdpass_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep proxy_fdpass_module | grep static && (echo Recompile Apache without proxy_fdpass_module && read -p "Next" a) || true


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+userdir_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep userdir_module | grep static && (echo Recompile Apache without userdir_module && read -p "Next" a) || true


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+info_module\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep info_module | grep static && (echo Recompile Apache without info_module && read -p "Next" a) || true


cd "$ap_sr"
sed -i "s'^\s*\(LoadModule\s\+auth_basic_module\s\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep auth_basic_module | grep static && (echo Recompile Apache without mod_auth_basic module && read -p "Next" a) || true
sed -i "s'^\s*\(LoadModule\s\+auth_digest_module\s\)'##\1'g" $ap_cf
"$ap_ctl" -M 2>/dev/null | grep auth_digest_module | grep static && (echo Recompile Apache without mod_auth_digest module && read -p "Next" a) || true


echo "[Manual]" 'Perform the following:
 1 If the apacheuser and group do not already exist, create the account and group as a unique system account:
# groupadd -r apache
# useradd apache -r -g apache -d /var/www -s /sbin/nologin
 2 Configure the Apache user and group in the Apache configuration file httpd.conf:
User apache
Group apache'
read -n 1 -p "Press Enter to continue..."


cd "$ap_sr"; p=$(grep -Ehi "^\s*User\s" $ap_cf 2>/dev/null); if [[ $p =~ ^[uU][sS][eE][rR]\ \$\{(.+)\}$ ]]; then u=$(grep "${BASH_REMATCH[1]}" $ap_cf envvars 2>/dev/null | cut -d= -s -f2); else u=$(echo "$p" | sed -r 's/^\s*User\s+//i'); fi; if [ -z "$u" ]; then echo "No User directive"; else chsh -s /bin/false "$u"; fi


cd "$ap_sr"; p=$(grep -Ehi "^\s*User\s" $ap_cf 2>/dev/null); if [[ $p =~ ^[uU][sS][eE][rR]\ \$\{(.+)\}$ ]]; then u=$(grep "${BASH_REMATCH[1]}" $ap_cf envvars 2>/dev/null | cut -d= -s -f2); else u=$(echo "$p" | sed -r 's/^\s*User\s+//i'); fi; if [ -z "$u" ]; then echo "No User directive"; else passwd -l "$u"; fi


chown -R root "$ap_sr"


chgrp -R root "$ap_sr"


chmod -R o-w "$ap_sr"


cd "$ap_sr"; cd_dirs=$(grep -Ehi "^\s*CoreDumpDirectory\s" $ap_cf 2>/dev/null);
p=$(grep -Ehi "^\s*Group\s" $ap_cf 2>/dev/null);
if [[ $p =~ ^[gG][rR][oO][uU][pP]\ \$\{(.+)\}$ ]]; then q=$(grep "${BASH_REMATCH[1]}" $ap_cf envvars 2>/dev/null | cut -d= -s -f2); else q=$(echo "$p" | sed -r 's/^\s*Group\s+//i'); fi;
echo "$cd_dirs" | while read -r line; do cdd_path=$(echo "$line" | sed -r 's/^\s*CoreDumpDirectory\s+//i' | sed 's,",,g' | sed "s,',,g"); chmod o-rwx "$cdd_path"; chown root:"$q" "$cdd_path"; if [[ -n "$cdd_path" ]]; then [[ ! "$cdd_path" =~ ^/.* ]] && cdd_path="$ap_sr/$cdd_path"; if [[ -n "$ap_dr" ]]; then echo "$cdd_path" | grep "$ap_dr" && (echo "CoreDumpDirectory is placed in DocumentRoot $ap_dr, move it to another place"; read -p "Next" a) || true; fi; fi; done


cd "$ap_sr"; conf=$(grep -Ehi "^\s*Mutex\s+(fcntl|flock|file)"$ap_cf 2>/dev/null);
if [[ -n "$conf" ]]; then suffix=$(echo "$ap_sr" | sed -r 's;^/etc/(httpd|apache2);;'); echo "$conf" | while read -r line; do mu_path=$(echo "$line" | sed -r 's/^\s*Mutex\s+(fcntl|flock|file)://i' | sed 's,",,g' | sed "s,',,g"); if [[ "$mu_path" =~ \$\{(.+)\}$ ]]; then mu_path=$(grep -h "${BASH_REMATCH[1]}=" $ap_cf envvars 2>/dev/null | cut -d= -s -f2 | sed "s/\\\${\?SUFFIX}\?/${suffix}/g"); fi; [[ ! "$mu_path" =~ ^/.* ]] && mu_path="$ap_sr/$mu_path"; chown root:wheel "$mu_path"; chmod go-w "$mu_path"; if [[ -n "$ap_dr" ]]; then echo "$mu_path" | grep "$ap_dr" && (echo "LockFile directory $mu_path is placed in DocumentRoot $ap_dr, move it to another place"; read -p "Next" a) || true; fi; done; fi


cd "$ap_sr"; conf=$(grep -Ehi "^\s*PidFile\s"$ap_cf 2>/dev/null);
[[ -z "$conf" ]] && conf=$("$ap_ctl" -V 2>/dev/null | grep DEFAULT_PIDLOG | cut -d= -f2 | sed 's,",,g');
[[ -z "$conf" ]] && conf="$ap_sr/logs";
suffix=$(echo "$ap_sr" | sed -r 's;^/etc/(httpd|apache2);;');
echo "$conf" | while read -r line; do pf_path=$(echo "$line" | sed -r 's/^\s*PidFile\s+//i' | sed 's,",,g' | sed "s,',,g"); if [[ "$pf_path" =~ \$\{(.+)\}$ ]]; then pf_path=$(grep -h "${BASH_REMATCH[1]}=" $ap_cf envvars 2>/dev/null | cut -d= -s -f2 | sed "s/\\\${\?SUFFIX}\?/${suffix}/g"); fi; chmod go-w "$pf_path"; chown root:root "$pf_path"; if [[ ! "$pf_path" =~ ^/.* ]]; then pf_path="$ap_sr/$pf_path"; fi; if [[ -n "$ap_dr" ]]; then echo "$pf_path" | grep "$ap_dr" && (echo "PidFile directory $pf_path is placed in DocumentRoot $ap_dr, move it to another place"; read -p "Next" a) || true; fi; done


cd "$ap_sr"; 
conf=$(grep -Ehi "^\s*ScoreBoardFile\s" $ap_cf 2>/dev/null); [[ -z "$conf" ]] && conf=$("$ap_ctl" -V 2>/dev/null | grep DEFAULT_SCOREBOARD | cut -d= -f2 | sed 's,",,g'); 
suffix=$(echo "$ap_sr" | sed -r 's;^/etc/(httpd|apache2);;');
echo "$conf" | while read -r line; do scb_path=$(echo "$line" | sed -r 's/^\s*ScoreBoardFile\s+//i' | sed 's,",,g' | sed "s,',,g"); if [[ "$scb_path" =~ \$\{(.+)\}$ ]]; then scb_path=$(grep -h "${BASH_REMATCH[1]}=" $ap_cf envvars 2>/dev/null | cut -d= -s -f2 | sed "s/\\\${\?SUFFIX}\?/${suffix}/g"); fi; if [[ -e "$scb_path" ]]; then chmod go-w "$scb_path"; chown root "$scb_path"; if [[ ! "$scb_path" =~ ^/.* ]]; then scb_path="$ap_sr/$scb_path"; fi; if [[ -n "$ap_dr" ]]; then echo "$scb_path" | grep "$ap_dr" && (echo "ScoreBoardFile $scb_path is placed in DocumentRoot $ap_dr, move it to another place"; read -p "Next" a) || true; fi; fi; done


chmod -R g-w "$ap_sr"


cd "$ap_sr"; p=$(grep -Ehi "^\s*Group\s" $ap_cf 2>/dev/null); if [[ $p =~ ^[gG][rR][oO][uU][pP]\ \$\{(.+)\}$ ]]; then q=$(grep "${BASH_REMATCH[1]}" $ap_cf envvars 2>/dev/null | cut -d= -s -f2); else q=$(echo "$p" | sed -r 's/^\s*Group\s+//i'); fi; if [ -z "$q" ]; then echo "No Group directive"; else dr_dirs=$(grep -Ehi "^\s*DocumentRoot\s" $ap_cf 2>/dev/null); echo "$dr_dirs" | while read -r line; do dr_path=$(echo "$line" | sed -r 's/^\s*DocumentRoot\s+//i' | sed 's,",,g' | sed "s,',,g"); find -L "$dr_path" -group "$q" -perm /g=w -print | xargs chmod g-w; done; fi


cd "$ap_sr"; dr_dirs=$(grep -Ehi "^\s*DocumentRoot\s" $ap_cf 2>/dev/null); echo "$dr_dirs" | while read -r line; do dr_path=$(echo "$line" | sed -r 's/^\s*DocumentRoot\s+//i' | sed 's,",,g' | sed "s,',,g"); chmod o-rwx "$dr_path" 2>&1; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*<Directory\s+\"?/\"?\s*>" && i=1&& echo -e "\tRequire all denied" >> "$f.couch_tmp"; else if [[ -n $(echo "$line" | grep -Ei "^\s*(Require|Deny|Allow)\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; echo "$line" | grep -Ei "^\s*</Directory>" && i=0; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


echo "[Manual]" 'Perform the following to implement the recommended state:
 1 Search the Apache configuration files (httpd.conf and any included configuration files) to find all <Directory> and <Location> elements. There should be one for the document root and any special purpose directories or locations. There are likely to be other access control directives in other contexts, such as virtual hosts or special elements like <Proxy>.
 2 Include the appropriate Require directives, with values that are appropriate for the purposes of the directory.
The configurations below are just a few possible examples:
<Directory "/var/www/html/"> 
Require ip 192.169. 
</Directory> 
<Directory "/var/www/html/"> 
Require all granted 
</Directory> 
<Location /usage>
Require local
</Location> 
<Location /portal>
Require valid-user
</Location>'
read -n 1 -p "Press Enter to continue..."


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*<Directory\s+\"?/\"?\s*>" && i=1&& echo -e "\tAllowOverride None" >> "$f.couch_tmp"; else if [[ -n $(echo "$line" | grep -Ei "^\s*(AllowOverride|AllowOverrideList)\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; echo "$line" | grep -Ei "^\s*</Directory>" && i=0; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*AllowOverride\s") ]]; then echo "## $line" >> "$f.couch_tmp"; echo -e "\tAllowOverride None" >> "$f.couch_tmp"; elif [[ -n $(echo "$line" | grep -Ei "^\s*AllowOverrideList\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*<Directory\s+\"?/\"?\s*>" && i=1&& echo -e "\tOptions None" >> "$f.couch_tmp"; else if [[ -n $(echo "$line" | grep -Ei "^\s*Options\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; echo "$line" | grep -Ei "^\s*</Directory>" && i=0; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
dr_dirs=$(grep -Ehi "^\s*DocumentRoot\s" $ap_cf 2>/dev/null | sed -r 's/^\s*DocumentRoot\s+//i' | sed 's,",,g' | sed "s,',,g");
[[ -z "$dr_dirs" ]] && dr_dirs=/usr/local/apache/htdocs;
echo "$dr_dirs" | while read -r dir; do dr_path=$(readlink -f "$dir"); for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*<Directory\s+\"?(${dr_path}|${dir})\"?\s*>" && i=1&& echo -e "\tOptions None" >> "$f.couch_tmp"; else if [[ -n $(echo "$line" | grep -Ei "^\s*Options\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; echo "$line" | grep -Ei "^\s*</Directory>" && i=0; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*Options\s" | grep -Ei "(\s|\+)Includes(\s|#|$)") ]]; then echo "## $line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*Options\s+Includes\s*(#|$)" 1>/dev/null || echo "$line" | sed -r 's/(\s|\+)Includes(\s|#|$)/ \2/gi' >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*(SetHandler\s+server-status|SetHandler\s+server-info|SetHandler\s+perl-status|PerlResponseHandler\s+Apache2::Status)") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


echo "[Manual]" 'Perform the following to implement the recommended state:
 1 Locate cgi-bin files and directories enabled in the Apache configuration via Script, ScriptAlias, ScriptAliasMatch, ScriptInterpreterSource directives.
 2 Remove the printenv default CGI in cgi-bin directory if it is installed.
# rm $APACHE_PREFIX/cgi-bin/printenv'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Perform the following to implement the recommended state:
 1 Locate cgi-bin files and directories enabled in the Apache configuration via Script, ScriptAlias, ScriptAliasMatch, ScriptInterpreterSource directives.
 2 Remove the test-cgi default CGI in cgi-bin directory if it is installed.
# rm $APACHE_PREFIX/cgi-bin/test-cgi'
read -n 1 -p "Press Enter to continue..."


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^[^#]*<Directory\s+("/.+"|"[^/].*"|/.+|[^/].*)\s*>') ]]; then i=1; rm -f /tmp/couch_temp_file; fi; if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> "$f.couch_tmp"; fi; if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '^[^#]*</Directory>') ]]; then i=0; grep -Ei '^[^#]*<LimitExcept (GET\s*|POST\s*|OPTIONS\s*|HEAD\s*)*>' /tmp/couch_temp_file || sed -ri 's;(^\s*<Directory\s+("/.+"|"[^/].*"|/.+|[^/].*)\s*>.*$);\1\n\t<LimitExcept GET POST OPTIONS>\n\t\tRequire all denied\n\t</LimitExcept>;i' /tmp/couch_temp_file; cat /tmp/couch_temp_file >> "$f.couch_tmp"; rm -f /tmp/couch_temp_file; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*TraceEnable\s") ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done
sed -i 's;\(# Global configuration\);\1\nTraceEnable Off\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep rewrite_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_rewrite.so" ]; then grep -Ei '^[^#]*LoadModule\s+rewrite_module\s' $ap_cf 2>/dev/null || echo "LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so" >> "$ap_c"; fi; which a2enmod && a2enmod rewrite || if [ -f "$ap_sr/mods-available/rewrite.load" ]; then cp "$ap_sr/mods-available/rewrite.load" "$ap_sr/mods-enabled/rewrite.load"; fi; fi;
"$ap_ctl" -k graceful

if [[ -n $("$ap_ctl" -M 2>/dev/null | grep rewrite_module) ]]; then grep -Ei '^\s*RewriteCond\s+%{THE_REQUEST}\s+!HTTP/1\\\.1\$' $ap_cf 2>/dev/null || sed -i 's;\(# Global configuration\);\1\nRewriteEngine On\nRewriteCond %{THE_REQUEST} !HTTP/1\\.1$\nRewriteRule .* - [F]\n;' "$ap_c"; 
for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei '^[^#]*<VirtualHost\s') ]]; then i=1; rm -f /tmp/couch_temp_file; fi; if [ "$i" == "1" ]; then echo "$line" >> /tmp/couch_temp_file; else echo "$line" >> $f.couch_tmp; fi; if [[ "$i" == "1" && -n $(echo "$line" | grep -Ei '^[^#]*</VirtualHost>') ]]; then i=0; grep -Ei '^\s*RewriteOptions\s+Inherit' /tmp/couch_temp_file || sed -ri 's;(^[^#]*<VirtualHost\s.*$);\1\n\tRewriteOptions Inherit;' /tmp/couch_temp_file; grep -Ei '^\s*RewriteEngine\s+On' /tmp/couch_temp_file || sed -ri 's;(^[^#]*<VirtualHost\s.*$);\1\n\tRewriteEngine On;' /tmp/couch_temp_file; cat /tmp/couch_temp_file >> "$f.couch_tmp"; rm -f /tmp/couch_temp_file; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done; else echo "Module mod_rewrite is not found"; fi


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr"; 
grep -iE '^\s*(<FilesMatch\s+"\^?\\\.ht|<Files\s+"\.ht|<Files\s+~\s+"\^?\\\.ht)' $ap_cf || sed -i 's;\(# Global configuration\);\1\n<FilesMatch "^\\.ht">\n\tRequire all denied\n</FilesMatch>\n;' "$ap_c"


cd "$ap_sr"; 
if [[ -z $(grep -Ei '^\s*(<FilesMatch\s+"\^\.\*\$"|<Files\s+"\*"|<Files\s+~\s+"\^\.\*\$")' $ap_cf) ]]; then printf '\n<FilesMatch "^.*\\.(css|html?|js|pdf|txt|xml|xsl|gif|ico|jpe?g|png)$">\n\tRequire all granted\n</FilesMatch>\n<FilesMatch "^.*$">\n\tRequire all denied\n</FilesMatch>\n' >> "$ap_c"; fi


echo "[Manual]" 'Perform the following to implement the recommended state:
 1 Find any Listendirectives in the Apache configuration file with no IP address specified, or with an IP address of all zeros similar to the examples below. Keep in mind there may be both IPv4 and IPv6 addresses on the system.
Listen 80
Listen 0.0.0.0:80
Listen [::ffff:0.0.0.0]:80
 2 Modify the Listen directives in the Apache configuration file to have explicit IP addresses according to the intended usage. Multiple Listendirectives may be specified for each IP address & Port.
Listen 10.1.2.3:80
Listen 192.168.4.5:80
Listen [2001:db8::a00:20ff:fea7:ccea]:80'
read -n 1 -p "Press Enter to continue..."


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep headers_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_headers.so" ]; then grep -Ei '^[^#]*LoadModule\s+headers_module\s' $ap_cf 2>/dev/null || echo "LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so" >> "$ap_c"; fi; which a2enmod && a2enmod headers || if [ -f "$ap_sr/mods-available/headers.load" ]; then cp "$ap_sr/mods-available/headers.load" "$ap_sr/mods-enabled/headers.load"; fi; fi;
"$ap_ctl" -k graceful

if [[ -n $("$ap_ctl" -M 2>/dev/null | grep headers_module) ]]; then k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*Header\s+always\s+(set|append)\s+(x-frame-options\s+(sameorigin|deny)|[^#]*Content-Security-Policy\s[^#]*frame-ancestors\s[^#]*(none|self))" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done;
if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nHeader always append X-Frame-Options SAMEORIGIN\n;' "$ap_c"; fi;
fi


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*AddType\s[^#]*shtml.*)$/## \1/i' "$f"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*AddHandler\s.*)$/## \1/i' "$f"; done


echo "[Manual]" 'Remove all the unnecessary directories inside the DocumentRoot, all the unnecessary scripts inside the directory used to CGI execution, and all the unnecessary Alias and Directory inside the Apache configuration'
read -n 1 -p "Press Enter to continue..."


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

for f in "${conf_files[@]}"; do sed -ri 's/^(\s*LogLevel\s+(emerg|alert|crit|error|warn).*)$/## \1\nLogLevel notice\n/i' "$f"; done
k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*LogLevel\s+(notice|info|debug)" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done
if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nLogLevel notice\n;' "$ap_c"; fi

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*ErrorLog\s+\S" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done
if [ "$k" == "0" ]; then read -p "Enter Apache errors log file location:" ap_errlog; sed -i "s;\(# Global configuration\);\1\nErrorLog $ap_errlog\n;" "$ap_c"; fi


echo "[Manual]" 'If Error Logging to syslog is to be used perform the following to implement the recommended state:
 1 Add an ErrorLog directive if not already configured. Any appropriate syslog facility may be used in place of local1.
ErrorLog "syslog:local1" 
 1 Add a similar ErrorLog directive for each virtual host if necessary.

Default: local7.'
read -n 1 -p "Press Enter to continue..."


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

grep -Ei "^\s*LogFormat\s.*\scouch_combined(\s|$|#)" $ap_cf 2>/dev/null || sed -i 's;\(# Global configuration\);\1\nLogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" couch_combined\n;' "$ap_c"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*CustomLog\s" | grep -v '\\$') ]] && [[ -z $(echo "$line" | grep '%h' | grep '%l' | grep '%u' | grep '%t' | grep '%r' | grep '%>s' | grep '%b' | grep -i '%{referer}i' | grep -i '%{user-agent}i') ]]; then if [[ "$line" =~ ^.*[[:space:]]([^[:space:]]+)[[:space:]]*$ ]]; then f_name="${BASH_REMATCH[1]}"; if [[ -z $(grep -Ei "^\s*LogFormat\s.*\s${f_name}\s*$" $ap_cf | grep '%h' | grep '%l' | grep '%u' | grep '%t' | grep '%r' | grep '%>s' | grep '%b' | grep -i '%{referer}i' | grep -i '%{user-agent}i') ]]; then echo "## $line" >> "$f.couch_tmp"; echo "$line" | sed -r "s/\s${f_name}\s*$/ couch_combined/" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; fi; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*CustomLog\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost\s" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done
if [ "$k" == "0" ]; then read -p "Enter Apache Custom log file location for combined log:" ap_customlog; sed -i "s;\(# Global configuration\);\1\nCustomLog $ap_customlog couch_combined\n;" "$ap_c"; fi


echo "[Manual]" 'To implement the recommended state do either option a) if using the Linux logrotate utility or option b) if using a piped logging utility such as the Apache rotate logs:
a). File Logging with Logrotate:
 1) Add or modify the web log rotation configuration to match your configured log files in /etc/logrotate.d/httpd to be similar to the following.
/var/log/httpd/*log {
missingok
notifempty
sharedscripts
postrotate
/bin/kill -HUP `cat /var/run/httpd.pid 2>/dev/null` 2> /dev/null ||
true
endscript
}
 2) Modify the rotation period and number of logs to keep so that at least 13 weeks or 3 months of logs are retained. This may be done as the default value for all logs in /etc/logrotate.conf or in the web specific log rotation configuration in /etc/logrotate.d/httpd to be similar to the following.
# rotate log files weekly
weekly
# keep 13 weeks of backlogs
rotate 13
 3) For each virtual host configured with it'\''s own log files ensure that those log files are also included in a similar log rotation.
b). Piped Logging:
 1) Configure the log rotation interval and log file names to a suitable interval such as daily.
CustomLog "|bin/rotatelogs -l /var/logs/logfile.%Y.%m.%d 86400" combined
 2) Ensure the log file naming and any rotation scripts provide for retaining at least 3 months or 13 weeks of log files.
 3) For each virtual host configured with its own log files ensure that those log files are also included in a similar log rotation.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Update to the latest Apache release available according to either of the following:
 1 When building from source:
 1 Read release notes and related security patch information
 2 Download latest source and any dependent modules such as mod_security.
 3 Build new Apache software according to your build process with the same 
configuration options.
 4 Install and Test the new software according to your organizations testing 
process.
 5 Move to production according to your organizations deployment process.
 2 When using platform packages
 1 Read release notes and related security patch information
 2 Download and install latest available Apache package and any dependent 
software.
 3 Test the new software according to your organizations testing process.
 4 Move to production according to your organizations deployment process.'
read -n 1 -p "Press Enter to continue..."


apt-get install libapache2-mod-security2 -y 2>/dev/null || yum -y install mod_security 2>/dev/null || zypper install -n apache2-mod_security2 2>/dev/null || true

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep security2_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_security2.so" ]; then grep -Ei '^[^#]*LoadModule\s+security2_module\s' $ap_cf 2>/dev/null || echo "LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so" >> "$ap_c"; fi; which a2enmod && a2enmod security2 || if [ -f "$ap_sr/mods-available/security2.load" ]; then cp "$ap_sr/mods-available/security2.load" "$ap_sr/mods-enabled/security2.load"; fi; fi;
"$ap_ctl" -k graceful


echo "[Manual]" 'Install, configure and test the OWASP ModSecurity Core Rule Set:
1. Download the OWASP ModSecurity CRS from the project page
https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_
Project
2. Unbundled the archive and follow the instructions in the INSTALL file.
3. The modsecurity_crs_10_setup.conf file is required, and rules in the base_rules
directory are intended as a baseline useful for most applications.
4. Test the application for correct functionality after installing the CRS. Check web
server error logs and the modsec_audit.log file for blocked requests due to false
positives.
5. It is also recommended to test the application response to malicious traffic such as
an automated web application scanner to ensure the rules are active. The the web
server error log and modsec_audit.log files should show logs of the attacks and the
servers response codes.'
read -n 1 -p "Press Enter to continue..."


if [[ -z $("$ap_ctl" -M 2>/dev/null | grep -E "(ssl_module|nss_module)") ]]; then which yum && yum -y install mod_ssl 2>/dev/null; which apt-get && apt-get -y install mod_ssl 2>/dev/null; which dnf && dnf -y install mod_ssl 2>/dev/null; which zipper && zipper install -n mod_ssl 2>/dev/null; [ -f "/usr/lib/apache2/modules/mod_ssl.so" ] && echo "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so" >> "$ap_c"; which a2enmod && a2enmod ssl || if [ -f "$ap_sr/mods-available/ssl.load" ]; then cp "$ap_sr/mods-available/ssl.load" "$ap_sr/mods-enabled/ssl.load"; fi; fi
"$ap_ctl" -k graceful


echo "[Manual]" 'Perform the following to implement the recommended state:
 1 Decide on the host name to be used for the certificate. It is important to remember that the browser will compare the host name in the URL to the common name in the certificate, so that it is important that all https: URL'\''s match the correct host name. Specifically the host name www.example.com is not the same as example.com nor the same as ssl.example.com.
 2 Generate a private key using openssl. Although certificate key lengths of 1024 have been common in the past, a key length of at least 2048 or more is now recommended for strong authentication. The key must be kept confidential and will be encrypted with a passphrase by default. Follow the steps below and respond to the prompts for a passphrase. See the Apache or OpenSSL documentation for details:http://httpd.apache.org/docs/2.4/ssl/ssl_faq.html#realcert
http://www.openssl.org/docs/HOWTO/certificates.txt
# cd /etc/pki/tls/certs
# umask 077
# openssl genrsa -aes128 2048 > example.com.key
Generating RSA private key, 2048 bit long modulus
...+++
............+++
e is 65537 (0x10001)
Enter pass phrase:
Verifying - Enter pass phrase:
 3 Generate the certificate signing request (CSR) to be signed by a certificate authority. It is important that common name exactly make the web host name.
# openssl req -utf8 -new -key www.example.com.key -out www.example.com.csr
Enter pass phrase for example.com.key:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '\''.'\'', the field will be left blank.
-----
Country Name (2 letter code) [GB]:US
State or Province Name (full name) [Berkshire]:New York
Locality Name (eg, city) [Newbury]:Lima
Organization Name (eg, company) [My Company Ltd]:Durkee Consulting
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server'\''s hostname) []:www.example.com
Email Address []:ralph@example.com
Please enter the following '\''extra'\'' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
# mv www.example.com.key /etc/pki/tls/private/
 4 Send the certificate signing request (CSR) to a certificate signing authority to be signed, and follow their instructions for submission and validation. The CSR and the final signed certificate are just encoded text, and need to be protected for integrity, but not confidentiality. This certificate will be given out for every SSL connection made.
 5 The resulting signed certificate may be named www.example.com.crt and placed in /etc/pki/tls/certs/ as readable by all (mode 0444). Please note that the certificate authority does not need the private key (example.com.key) and this file must be carefully protected. With a decrypted copy of the private key, it would be possible to decrypt all conversations with the server.
 6 Do not forget the passphrase used to encrypt the private key. It will be required every time the server is started in https mode. If it is necessary to avoid requiring an administrator having to type the passphrase every time the httpdservice is started, the private key may be stored in clear text. Storing the private key in clear text increases the convenience while increasing the risk of disclosure of the key, but may be appropriate for the sake of being able to restart, if the risks are well managed. Be sure that the key file is only readable by root. To decrypt the private key and store it in clear text file the following openssl command may be used. You can tell by the private key headers whether it is encrypted or clear text.
# cd /etc/pki/tls/private/
# umask 077
# openssl rsa -in www.example.com.key -out www.example.com.key.clear
 7 Locate the Apache configuration file for mod_ssl and add or modify the SSLCertificateFile and SSLCertificateKeyFiledirectives to have the correct path for the private key and signed certificate files. If a clear text key is referenced then a passphrase will not be required. You can use the CA'\''s certificate that signed your certificate instead of the CA bundle, to speed up the initial SSL connection as fewer certificates will need to be transmitted. As an alternative, starting with Apache version 2.4.8 the CA and intermediate certificates may be concatenated to the server certificate configured with the SSLCertificateFile directive instead.
SSLCertificateFile /etc/pki/tls/certs/example.com.crt
SSLCertificateKeyFile /etc/pki/tls/private/example.com.key
# Default CA file, can be replaced with your CA'\''s certificate.
SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt
 8 Lastly, start or restart the httpd service and verify correct functioning with your favorite browser.'
read -n 1 -p "Press Enter to continue..."


cd "$ap_sr"; 
grep -Eih "^\s*SSLCertificateFile\s" $ap_cf 2>/dev/null | sed -r 's/^\s*SSLCertificateFile\s+//i' | sed 's,",,g' | sed "s,',,g" | while read -r each; do grep -i "PRIVATE KEY" "$each" 2>/dev/null && echo "Remove Private Key from certificate file $each" && read -p "Next" a; done; 
grep -Eih "^\s*SSLCertificateKeyFile\s" $ap_cf 2>/dev/null | sed -r 's/^\s*SSLCertificateKeyFile\s+//i' | sed 's,",,g' | sed "s,',,g" | while read -r each; do chown root:root "$each"; chmod 400 "$each"; done


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*SSLProtocol\s") ]]; then echo "## $line" >> "$f.couch_tmp"; echo "$line" | sed -r 's/(\s|\+)SSLv(2|3)\s+/ /i' | sed -r 's/((\s|\+)all)/\1 -SSLv3/i' | grep -Eiv '^\s*SSLProtocol\s*$' >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLProtocol\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done

if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nSSLProtocol TLSv1.2\n;' "$ap_c"; fi


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*SSLCipherSuite\s") ]] && [[ -z $(echo "$line" | grep -i '!EXP' | grep -i '!NULL' | grep -i '!LOW' | grep -i '!SSLv2' | grep -i '!RC4' | grep -i '!aNULL' | grep -i '!MD5') ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLCipherSuite\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done

if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nSSLCipherSuite ALL:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL\n;' "$ap_c"; fi

for f in "${conf_files[@]}"; do sed -ri 's/^(\s*SSLHonorCipherOrder\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nSSLHonorCipherOrder On\n;' "$ap_c"


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*SSLInsecureRenegotiation\s.*)$/## \1/i' "$f"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*SSLCompression\s.*)$/## \1/i' "$f"; done


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*SSLProtocol\s") ]] && [[ -z $(echo "$line" | grep -Ei '^\s*SSLProtocol\s+(\+?TLSv1\.[23]\s*)+$') ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLProtocol\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done

if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nSSLProtocol TLSv1.2\n;' "$ap_c"; fi


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep socache_shmcb_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_socache_shmcb.so" ]; then grep -Ei '^[^#]*LoadModule\s+socache_shmcb_module\s' $ap_cf 2>/dev/null || echo "LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so" >> "$ap_c"; fi; which a2enmod && a2enmod socache_shmcb || if [ -f "$ap_sr/mods-available/socache_shmcb.load" ]; then cp "$ap_sr/mods-available/socache_shmcb.load" "$ap_sr/mods-enabled/socache_shmcb.load"; fi; fi;
"$ap_ctl" -k graceful

if [[ -n $("$ap_ctl" -M 2>/dev/null | grep socache_shmcb_module) ]]; then k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLStaplingCache\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done;
if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nSSLStaplingCache "shmcb:logs/ssl_staple_cache(512000)"\n;' "$ap_c"; fi;
fi

if [[ -n $("$ap_ctl" -M 2>/dev/null | grep socache_shmcb_module) ]]; then for f in "${conf_files[@]}"; do sed -ri 's/^(\s*SSLUseStapling\s)/## \1/i' "$f"; done; sed -i 's;\(# Global configuration\);\1\nSSLUseStapling On\n;' "$ap_c"; fi


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep headers_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_headers.so" ]; then grep -Ei '^[^#]*LoadModule\s+headers_module\s' $ap_cf 2>/dev/null || echo "LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so" >> "$ap_c"; fi; which a2enmod && a2enmod headers || if [ -f "$ap_sr/mods-available/headers.load" ]; then cp "$ap_sr/mods-available/headers.load" "$ap_sr/mods-enabled/headers.load"; fi; fi;
"$ap_ctl" -k graceful

if [[ -n $("$ap_ctl" -M 2>/dev/null | grep headers_module) ]]; then k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*Header\s+always\s+set\s+Strict-Transport-Security\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done;
if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nHeader always set Strict-Transport-Security "max-age=86400"\n;' "$ap_c"; fi;
fi


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*SSLCipherSuite\s") ]] && [[ -z $(echo "$line" | grep -i '!3DES' | grep -i '!IDEA') ]]; then echo "$line" | sed -r 's/^(\s*SSLCipherSuite\s+\S+)/\1:!3DES:!IDEA/i' >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLCipherSuite\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done

if [ "$k" == "0" ]; then sed -i 's;\(# Global configuration\);\1\nSSLCipherSuite ALL:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL:!3DES:!IDEA\n;' "$ap_c"; fi

for f in "${conf_files[@]}"; do sed -ri 's/^(\s*SSLHonorCipherOrder\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nSSLHonorCipherOrder On\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c
cd "$ap_sr";
IFS=' ' read -r -a conf_files <<< "$ap_cf"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*SSLCipherSuite\s") ]] && [[ -z $(echo "$line" | grep -Ei '^\s*SSLCipherSuite\s+((ECDHE|EECDH|EDH|DHE|!.*)(:|\s|$))*\s*$') ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done

k=0;
for f in "${conf_files[@]}"; do i=0; while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then echo "$line" | grep -Ei "^\s*SSLCipherSuite\s" &&k=1; echo "$line" | grep -Ei "^\s*<VirtualHost" && i=1; else echo "$line" | grep -Ei "^\s*</virtualhost>" && i=0; fi; done < "$f"; done

if [ "$k" == "0" ]; then if [[ -n $(openssl version | grep -Ei '^OpenSSL\s+[1-9]\d*\.(0\.([2-9]|\d\d+)|[1-9]\d*\.)') ]]; then sed -i 's;\(# Global configuration\);\1\nSSLCipherSuite ECDHE:DHE:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL:!3DES:!IDEA\n;' "$ap_c"; else sed -i 's;\(# Global configuration\);\1\nSSLCipherSuite EECDH:EDH:!EXP:!NULL:!LOW:!SSLv2:!MD5:!RC4:!aNULL:!3DES:!IDEA\n;' "$ap_c"; fi; fi


echo "[Manual]" 'Perform the following to implement the recommended state:
Move the web content to a TLS enabled website, and add an HTTP Redirect directive to the Apache configuration file to redirect to the TLS enabled website similar to the example shown:
Redirect permanent / https://www.example.org/'
read -n 1 -p "Press Enter to continue..."


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*ServerTokens\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nServerTokens Prod\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*ServerSignature\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nServerSignature Off\n;' "$ap_c"


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

for f in "${conf_files[@]}"; do sed -ri 's;(^\s*Include\s+conf/extra/httpd-autoindex\.conf);## \1;g' "$f"; done

for f in "${conf_files[@]}"; do sed -ri 's;^(\s*Alias\s[^#]*(\s|/|")icons(\s|/|"|#|$));## \1;i' "$f"; done

for f in "${conf_files[@]}"; do i=0; rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [ "$i" == "0" ]; then if [[ -n $(echo "$line" | grep -Ei '^\s*<Directory\s+"?(\S*/)?icons(\s|/|"|>)') ]]; then i=1; echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; else echo "## $line" >> "$f.couch_tmp"; echo "$line" | grep -Ei "^\s*</Directory>" && i=0; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

for f in "${conf_files[@]}"; do rm -f "$f.couch_tmp" 2>/dev/null; cat "$f" | while IFS= read -r line || [[ -n "$line" ]]; do if [[ -n $(echo "$line" | grep -Ei "^\s*FileETag\s") ]] && [[ -n $(echo "$line" | grep -Ei '(\s|\+)(all|inode)') ]]; then echo "## $line" >> "$f.couch_tmp"; else echo "$line" >> "$f.couch_tmp"; fi; done; cp "$f.couch_tmp" "$f"; rm -f "$f.couch_tmp"; done


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*Timeout\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nTimeout 10\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*KeepAlive\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nKeepAlive On\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*MaxKeepAliveRequests\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nMaxKeepAliveRequests 100\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*KeepAliveTimeout\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nKeepAliveTimeout 5\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep reqtimeout_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_reqtimeout.so" ]; then grep -Ei '^[^#]*LoadModule\s+reqtimeout_module\s' $ap_cf 2>/dev/null || echo "LoadModule reqtimeout_module /usr/lib/apache2/modules/mod_reqtimeout.so" >> "$ap_c"; fi; which a2enmod && a2enmod reqtimeout || if [ -f "$ap_sr/mods-available/reqtimeout.load" ]; then cp "$ap_sr/mods-available/reqtimeout.load" "$ap_sr/mods-enabled/reqtimeout.load"; fi; fi;
"$ap_ctl" -k graceful

for f in "${conf_files[@]}"; do sed -ri 's/^(\s*RequestReadTimeout\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nRequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"

if [[ -z $("$ap_ctl" -M 2>/dev/null | grep reqtimeout_module) ]]; then if [ -f "/usr/lib/apache2/modules/mod_reqtimeout.so" ]; then grep -Ei '^[^#]*LoadModule\s+reqtimeout_module\s' $ap_cf 2>/dev/null || echo "LoadModule reqtimeout_module /usr/lib/apache2/modules/mod_reqtimeout.so" >> "$ap_c"; fi; which a2enmod && a2enmod reqtimeout || if [ -f "$ap_sr/mods-available/reqtimeout.load" ]; then cp "$ap_sr/mods-available/reqtimeout.load" "$ap_sr/mods-enabled/reqtimeout.load"; fi; fi;
"$ap_ctl" -k graceful

for f in "${conf_files[@]}"; do sed -ri 's/^(\s*RequestReadTimeout\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nRequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*LimitRequestLine\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nLimitRequestLine 512\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*LimitRequestFields\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nLimitRequestFields 100\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*LimitRequestFieldSize\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nLimitRequestFieldSize 1024\n;' "$ap_c"


grep "# Global configuration" $ap_c || sed -i '1 a\# Global configuration' $ap_c

IFS=' ' read -r -a conf_files <<< "$ap_cf"
cd "$ap_sr"
for f in "${conf_files[@]}"; do sed -ri 's/^(\s*LimitRequestBody\s.*)$/## \1/i' "$f"; done
sed -i 's;\(# Global configuration\);\1\nLimitRequestBody 102400\n;' "$ap_c"


aa-status || sestatus || (seli="NO"; read -p "Do you want to istall SeLinux?[yes][NO]" seli; if [ "$seli" == "yes" ]; then apt-get install -y selinux-basics selinux-policy-default || yum install -y policycoreutils || zypper install -n selinux-policy; sed -i 's;\(^\s*SELINUX=\);#\1;g' /etc/selinux/config; echo "SELINUX=enforcing" >> /etc/selinux/config; setenforce 1; fi)


sestatus && (chcon -t initrc_exec_t $ap_ctl; ap_bindir=`echo $ap_ctl | sed 's;/apachectl$;;' | sed 's;/httpd$;;'`; chcon -t httpd_exec_t $ap_bindir/httpd $ap_bindir/httpd.* $ap_bindir/apache2 $ap_bindir/apache2.* 2>/dev/null; semanage fcontext -a -t httpd_exec_t "$ap_bindir/httpd"; semanage fcontext -a -t httpd_exec_t "$ap_bindir/httpd.worker"; semanage fcontext -a -t httpd_exec_t "$ap_bindir/httpd.event"; semanage fcontext -a -t initrc_exec_t "$ap_bindir/apachectl"; semanage fcontext -a -t initrc_exec_t "$ap_bindir/apache2"; restorecon -v $ap_bindir/httpd $ap_bindir/httpd.* $ap_bindir/apachectl)


sestatus && (semanage permissive -d httpd_t) || echo "SeLinux is not installed"


sestatus && (setsebool -P httpd_enable_cgi off) || echo "SeLinux is not installed"


sestatus || aa-status || (apparmor="NO"; read -p "Do you want to istall AppArmor?[yes][NO]" apparmor; if [ "$apparmor" == "yes" ]; then apt-get install -y apparmor libapache2-mod-apparmor || zypper install -n apparmor libapache2-mod-apparmor; /etc/init.d/apparmor start; fi)


echo "[Manual]" 'Perform the following to implement the recommended state:
• Stop the Apache server
# service apache2 stop
• Create a mostly empty apache2 profile based on program dependencies.
# aa-autodep apache2
Writing updated profile for /usr/sbin/apache2.
• Set the apache2 profile in complain mode so that access violations will be allowed,
and will be logged.
# aa-complain apache2
Setting /usr/sbin/apache2 to complain mode.
• Start the apache2 service
# service apache2 start
• Throughly test the web application attempting to exercise all intended functionality
so that AppArmor will generate the necessary logs of all resources accessed. The
logs are sent via the system syslog utility, and are typically found in either the
/var/log/syslog or /var/log/messages files. Also stop and restart the web server as
part of the testing process.
• Use aa-logprof to update the profile based on logs generated during the testing.
The tool will prompt for suggested modifications to the profile, based on the logs.
The logs may also be reviewed manually in order to update the profile.
# aa-logprof
• Review and edit the profile, removing any inappropriate content, and adding
appropriate access rules. Directories with multiple files accessed with the same
permission can be simplified with the usage of wild-cards when appropriate. Reload
the updated profile using the apparmor_parser command.
# apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2
• Test the new updated profile again checking for any new apparmor denied logs
generated. Update and reload the profile as necessary. Repeat the application tests,
until no new apparmor deny logs are created, except for access which should be
prohibited.
# tail -f /var/log/syslog
• Set the apache2 profile to enforce mode, reload apparmor, and then test the web site
functionality again.
# aa-enforce /usr/sbin/apache2
# /etc/init.d/apparmor reload'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Perform the following to implement the recommended state:
• Set the profile state to enforce mode.
# aa-enforce apache2
Setting /usr/sbin/apache2 to enforce mode.
• Stop the Apache server, and confirm that is it not running. In some cases the
AppArmor controls may prevent the web server from stopping properly, and it may
be necessary to stop the process manually or even reboot the server.
# service apache2 stop
* Stopping web server apache2
# service apache2 status
* apache2 is not running
• Restart the Apache service.
# service apache2 start
* Starting web server apache2'
read -n 1 -p "Press Enter to continue..."



