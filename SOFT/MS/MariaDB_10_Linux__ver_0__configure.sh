#!/usr/bin/env bash

read -p "Enter MariaDB login: " APP_LOGIN;
stty -echo;
read -p "Enter MariaDB password: "APP_PASSWORD;
echo;
stty echo;

mysql_path=$(which mariadb || find -L /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mariadb -perm -100 -print 2>/dev/null | head -n 1 | grep mariadb || which mysql || find -L /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mysql -perm -100 -print 2>/dev/null | head -n 1 | grep mysql)

mysql_ini_file=$(if pidof mariadbd &>/dev/null; then couch_maria_ini=$(ps --no-headers -o args -p $(pidof mariadbd) | grep -E '\s--defaults-file=' | sed -r "s;^.*\s--defaults-file=([^\"']\S*|\"[^\"]*\"|'[^']*')($|\s.*$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); elif pidof mysqld &>/dev/null; then couch_maria_ini=$(ps --no-headers -o args -p $(pidof mysqld) | grep -E '\s--defaults-file=' | sed -r "s;^.*\s--defaults-file=([^\"']\S*|\"[^\"]*\"|'[^']*')($|\s.*$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); fi; if [[ -n "$couch_maria_ini" ]]; then echo "$couch_maria_ini"; else couch_maria_servbin=$(which mariadbd || find -L /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mariadbd -perm -100 -print 2>/dev/null | head -n 1 | grep mariadbd || which mysqld || find -L /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mysqld -perm -100 -print 2>/dev/null | head -n 1 | grep mysqld); [ -e "$couch_maria_servbin" ] && for file in $("$couch_maria_servbin" --verbose --help 2>/dev/null | grep -A 1 "Default options are read from" | grep -v "Default options are read from"); do if [ -e "$file" ]; then echo "$file"; break; fi; done; fi;)

mysql_all_conf_files=$(printf "$mysql_ini_file;"; if pidof mariadbd &>/dev/null; then couch_maria_extra=$(ps --no-headers -o args -p $(pidof mariadbd) | grep -E '\s--defaults-extra-file=' | sed -r "s;^.*\s--defaults-extra-file=([^\"']\S*|\"[^\"]*\"|'[^']*')($|\s.*$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); elif pidof mysqld &>/dev/null; then couch_maria_extra=$(ps --no-headers -o args -p $(pidof mysqld) | grep -E '\s--defaults-extra-file=' | sed -r "s;^.*\s--defaults-extra-file=([^\"']\S*|\"[^\"]*\"|'[^']*')($|\s.*$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); fi; [ -n "$couch_maria_extra" ] && printf "$couch_maria_extra;"; grep -E '^\s*!include\s' $mysql_ini_file | sed -r 's/(^\s*!include\s+|\s+$)//' | while read -r filename; do printf "$filename;"; done; grep -E '^\s*!includedir\s' "$mysql_ini_file" | sed -r 's/(^\s*!includedir\s+|\s+$)//' | while read -r dirname; do find "$dirname" -type f -name *.cnf -print0 | xargs -0 -I {} printf "{};"; done | sed 's/;$//')

mysql_datadir=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''datadir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2)

if [[ -z $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'select '\''test_pass_string'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" 2>&1 | grep -i "test_pass_string") ]];
then echo "Incorrect credentials, please try again.";
	exit;
fi;


echo "[Manual]" 'Migrate to 10.4 or higher version of MariaDB.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Install the latest patches for your version or upgrade to the latest version.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Install MariaDB on the dedicated for these purposes machine. Remove excess applications or services and/or remove unnecessary roles from the underlying operating system.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Perform one of the following steps to remediate this setting:
1. Configure MariaDB to use chroot:
Choose a non-system partition <chroot location> for MariaDB
Add '\''chroot=<chroot_location>'\'' to the my.cnf option file
2. Configure MariaDB to run under systemd:
If MariaDB is managed by systemd and running, stop the service: 
$ sudo systemctl stop <mysqld>.service
If a mysql user and group do not already exist, create them:
$ sudo groupadd mysql 
$ sudo useradd -r -g mysql -s /bin/false mysql
Set the ownership of the base directory: 
$ sudo chown -R mysql:mysql /usr/local/mysql/
Create or modify the <mysqld>.service file in /lib/systemd/system to include the following entries, if not already present: 
[Unit] 
Description=MariaDB Server 
[Install] 
WantedBy=multi-user.target 
[Service] 
User=mysql 
Group=mysql
If MariaDB was not already managed by systemd execute this command: 
$ sudo systemctl daemon-reload
Start the MariaDB server: 
$ sudo systemctl start <mariadb>.service
If you would like MariaDB to automatically run at startup execute this command: 
$ sudo systemctl enable <mariadb>.service
3. Follow documentation in the references for standing up MariaDB in a Docker container.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure usage of dedicated non-administrative account for MariaDB daemon/service and directly related processes.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict network access using local or network IP filtering'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Perform the following steps to remediate this setting for the datadir:
1. Backup the database.
2. Choose a non-system partition new location for MariaDB data.
3. Stop mariadbd using a command like: 
service mariadb stop.
4. Copy the data using a command like: 
cp -rp <datadir Value> <new location>.
5. Set the datadir location to the new location in the MariaDB configuration file.
6. Start mariadbd using a command like: 
service mariadb start
Note: On some Linux distributions you may need to additionally modify apparmor settings. 
For example, on a Ubuntu 14.04.1 system edit the file /etc/apparmor.d/usr.sbin.mariadbd so that the datadir access is appropriate. The original might look like this: 
# Allow data dir access 
/var/lib/mysql/ r, 
/var/lib/mysql/** rwk,
Alter those two paths to be the new location you chose above. For example, if that new location were /media/mysql, then the /etc/apparmor.d/usr.sbin.mysqld file should include something like this: 
# Allow data dir access 
/media/mysql/ r, 
/media/mysql/** rwk,'
read -n 1 -p "Press Enter to continue..."


read -p "Delete existing .mysql_history files?[y][N]" couch_a;
if [[ "$couch_a" =~ ^[Yy][eE]?[sS]?$ ]]; then find / -name .mysql_history -print | while read -r line; do rm -f "$line"; ln -s /dev/null "$line"; done; fi


check_file () { if grep -Eq '^\s*(export\s+)?MY[S]QL_PWD=\S' "$1"; then echo "[!] MYSQL PWD was found in file $1 and will be commented"; sed -ri 's/^(\s*(export\s+)?MY[S]QL_PWD=\S)/## \1/' "$1"; fi; }
export -f check_file

for filename in /etc/init.d/mysql /etc/environment /etc/profile /etc/bash.bashrc /etc/bashrc; do [ -e "$filename" ] && check_file "$filename"; done
{ find /etc/profile.d -type f -name *.sh -print 2>/dev/null; find /etc/environment.d -type f -print 2>/dev/null; find /etc/sysconfig -type f -print 2>/dev/null; } | while read -r line; do check_file "$line"; done
find / -type f \( -name .bashrc -o -name .bash_login -o -name .bash_profile -o -name .profile -o -name .bash_env -o -name .env -o -name .envrc -o -name .zshrc -o -name .zshenv \) -print 2>/dev/null | while read -r line; do check_file "$line"; done


if pidof -q mariadbd; then couch_maria_user=$(ps --no-headers -o user:32 -p $(pidof mariadbd)); elif pidof -q mysqld; then couch_maria_user=$(ps --no-headers -o user:32 -p $(pidof mysqld)); else echo "MariaDB user not found"; fi
if which nologin &>/dev/null; then usermod -s $(which nologin) $couch_maria_user; else usermod -s /bin/false $couch_maria_user; fi


echo "[Manual]" 'Use -p without password and then enter the password when prompted, use a properly secured .mariadb.cnf file, or store authentication information in encrypted format in .mylogin.cnf.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If the plugin is active and you need to disable it in your environment, first ensure either:
• you can accept the root account in MariaDB being inaccessible, OR
• you have set a strong password for the root account in MariaDB,
then add the following option under the [mariadb] or [mysqld] option group in MariaDB configuration files and restart MariaDB: 
unix_socket=OFF
If the plugin is disabled but you seek to use it, ensure the following option is set under the [mariadb] or [mysqld] option group in MariaDB configuration files, then restart MariaDB: 
unix_socket=ON
To enable an OS user to login to MariaDB using unix_socket, include '\''unix_socket'\'' as an authentication plugin in your IDENTIFIED VIA clause of CREATE USER or ALTER USER commands. For example, run:
CREATE USER '\''<user>'\''@'\''localhost'\'' IDENTIFIED VIA unix_socket;
To disable '\''unix_socket'\'' plugin for user which should not use it, switch that user account to password-based authentication. Example:
ALTER USER <user>@localhost IDENTIFIED VIA mysql_native_password;
SET PASSWORD = PASSWORD('\''<password>'\'');

Default: unix_socket plugin is ON.'
read -n 1 -p "Press Enter to continue..."


couch_ip=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = '\''bind_address'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [ -z "$couch_ip" ]; then
    read -p "Do you want to restrict MariaDB server listener to specific IP address (connections on other server host addresses will be not permitted)?[y][N]" couch_a;
    if [[ "$couch_a" =~ ^[Yy]$ ]]; then
      read -p "Enter IP address for MariaDB server listener:" couch_maria_ip; 
       if [ -n "$couch_maria_ip" ]; 
         then 
         echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*bind[_-]address\s*=)/## \1/" "$file"; done; 
         echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s/^(\s*\[(mariadb|mysqld)\].*)$/\1\nbind_address=\"${couch_maria_ip}\"/" "$file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done;
        fi;
    fi;
fi;


echo "[Manual]" 'To persist changes to global settings, you must set these variables within MariaDB configuration files.
• To set the global default per-user connection limit, set the max_user_connections variable to a numeric value.
• To set the maximum number of clients the server permits to simultaneously connect, set the max_connections variable to a numeric value.
You may also set these variables dynamically (and only temporarily) for a running instance of MariaDB by connecting as an administrator and utilizing the commands below. 
SET GLOBAL max_user_connections=<desired numeric value>; 
SET GLOBAL max_connections=<desired numeric value>;
Additionally, connections limits can be set distinctly for each user using CREATE or ALTER commands. For example: 
ALTER USER '\''fred'\''@'\''localhost'\'' WITH MAX_CONNECTIONS_PER_HOUR 5 MAX_USER_CONNECTIONS 2;

Default:
  max_connections 151
  max_user_connections 0'
read -n 1 -p "Press Enter to continue..."


read -p "Do you want to remove write group and all others access to datadir directory and all subdirectories now?[y][N]" couch_a;
if [[ "$couch_a" =~ ^[Yy][eE]?[sS]?$ ]]; then couch_datadir=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''datadir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); [ -d "$couch_datadir" ] && chmod -R g-w,o-rwx "$couch_datadir"; fi


couch_mariadb_bin=$(find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mariadb -perm -100 -ls 2>/dev/null); if [ -n "$couch_mariadb_bin" ]; then echo "$couch_mariadb_bin" | while read -r line; do chmod go-w "$line"; done; else find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mysql -perm -100 -ls 2>/dev/null | while read -r line; do chmod go-w "$line"; done; fi; 
couch_mariadbd_bin=$(find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mariadbd -perm -100 -ls 2>/dev/null); if [ -n "$couch_mariadbd_bin" ]; then echo "$couch_mariadbd_bin" | while read -r line; do chmod go-w "$line"; done; else find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mysqld -perm -100 -ls 2>/dev/null | while read -r line; do chmod go-w "$line"; done; fi; 
couch_mariadb_admin=$(find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mariadb-admin -perm -100 -ls 2>/dev/null); if [ -n "$couch_mariadb_admin" ]; then echo "$couch_mariadb_admin" | while read -r line; do chmod go-w "$line"; done; else find /bin /sbin /usr/bin /usr/ccs/bin /usr/ccs/lib /usr/lbin /usr/lib /usr/sbin /usr/local /usr/local/bin /var/local -type f -name mysqladmin -perm -100 -ls 2>/dev/null | while read -r line; do chmod go-w "$line"; done; fi;


IFS=";" read -a couch_mysql_files <<< "$mysql_all_conf_files"; for conf_file in "${couch_mysql_files[@]}"; do chmod go-w "$conf_file"; done


couch_log_bin=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_bin_basename'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); 
if [[ -n "$couch_log_bin" ]]; then cd "$mysql_datadir"; chmod o-rwx "$couch_log_bin" "$couch_log_bin".* || true; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_log_bin" "$couch_log_bin".* || true; fi; fi


couch_ssl_key=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_key'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_key" ]]; then cd "$mysql_datadir"; chmod go-rwx "$couch_ssl_key"; chmod u-wx "$couch_ssl_key"; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_error'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_f" ]]; then cd "$mysql_datadir"; ls -lLad "$couch_f"; chmod o-rwx "$couch_f"; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''slow_query_log_file'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_f" ]]; then cd "$mysql_datadir"; ls -lLad "$couch_f"; chmod o-rwx "$couch_f"; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''relay_log_basename'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); 
[[ -z "$couch_f" ]] && couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''relay_log'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); 
[[ -z "$couch_f" ]] && couch_f="$(hostname)-relay-bin"; 
cd "$mysql_datadir"; 
chmod o-rwx "$couch_f".*;
couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi);
if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f".* || true; fi;


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''general_log_file'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_f" ]]; then cd "$mysql_datadir"; ls -lLad "$couch_f"; chmod o-rwx "$couch_f"; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''plugin_dir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); 
if [[ -n "$couch_f" ]]; then cd "$mysql_datadir"; chmod ug-w "$couch_f"; chmod o-wx "$couch_f"; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; fi


cd "$mysql_datadir";
couch_ssl_cert=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_cert'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_cert" ]]; then chmod go-w "$couch_ssl_cert"; fi;
couch_ssl_ca=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_ca'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_ca" ]]; then chmod go-w "$couch_ssl_ca"; fi;
couch_ssl_capath=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_capath'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_capath" ]]; then chmod go-w "$couch_ssl_capath"; fi;
couch_ssl_crl=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_crl'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_crl" ]]; then chmod go-w "$couch_ssl_crl"; fi;
couch_ssl_crlpath=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_crlpath'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_ssl_crlpath" ]]; then chmod go-w "$couch_ssl_crlpath"; fi;


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''server_audit_file_path'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ -n "$couch_f" ]]; then cd "$mysql_datadir"; ls -lLad "$couch_f"; chmod o-rwx "$couch_f"; chmod ug-x "$couch_f"; couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); if [[ -n "$couch_sql_user" ]]; then chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; fi


couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi);
cd "$mysql_datadir";
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do couch_f=$(grep -E '^\s*file[_-]key[_-]management[_-]filename\s*=' "$file" | cut -d= -f2 | xargs); if [[ -n "$couch_f" ]]; then chmod g-w,o-rwx "$couch_f"; [[ -n "$couch_sql_user" ]] && chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; done;
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do couch_f=$(grep -E '^\s*file[_-]key[_-]management[_-]filekey\s*=' "$file" | cut -d= -f2 | xargs); if [[ -n "$couch_f" ]]; then chmod g-w,o-rwx "$couch_f"; [[ -n "$couch_sql_user" ]] && chown "$couch_sql_user":"$couch_sql_user" "$couch_f"; fi; done;


couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_error'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2)
if [ -z "$couch_a" ]; then read -p "Enter location for log_error file:" mysql_log_error_file; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s/^(\s*\[(mariadb|mysqld)\].*)$/\1\nlog_error=${mysql_log_error_file}/" "$file"; break; fi; done; fi


echo "[Manual]" 'Configure log_error to file not on the system partition.
If general_log is enabled, configure path general_log_file to be located not on the system partition.
If log_bin is enabled, configure path log_bin_basename to be located not on the system partition.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Get database location with SQL-query:
show variables like '\''datadir'\'';
Configure log_error to file not on the database partition.
If general_log is enabled, configure path general_log_file to be located not on the database partition.
If log_bin is enabled, configure path log_bin_basename to be located not on the database partition.'
read -n 1 -p "Press Enter to continue..."


echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*log[_-]warnings\s*=)/## \1/" "$file"; done; 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nlog_warnings = 2/' "$file"; break; fi; done;
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL log_warnings=2;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"


if [[ -n $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+(10\.5\.([2-9][0-9]|[0-9]{3,})|10\.[6-9]|1[1-9]|[2-9][0-9])') ]]; then
IFS=";" read -a couch_mysql_files <<< "$mysql_all_conf_files"
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*plugin[_-]load[_-]add\s*=\s*server_audit(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nplugin_load_add = server_audit/' "$conf_file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'INSTALL SONAME '\''server_audit'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi;
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*server[_-]audit[_-]logging\s*=)/## \1/" "$file"; done; 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nserver_audit_logging = ON/' "$file"; break; fi; done;
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL server_audit_logging=ON;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"
couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''server_audit_events'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [ -n "$couch_a" ] && [[ -z $(echo "$couch_a" | grep -i 'CONNECT') ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*server[_-]audit[_-]events\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s/^(\s*\[(mariadb|mysqld)\].*)$/\1\nserver_audit_events=${couch_a},CONNECT/" "$file"; echo "MariaDB restart may be needed to activate updated settings"; break; fi; done; fi;
fi;


if [[ -n $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+(10\.5\.([2-9][0-9]|[0-9]{3,})|10\.[6-9]|1[1-9]|[2-9][0-9])') ]]; then 
IFS=";" read -a couch_mysql_files <<< "$mysql_all_conf_files";
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*server_audit\s*=\s*FORCE_PLUS_PERMANENT(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nserver_audit=FORCE_PLUS_PERMANENT/' "$conf_file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done; fi;
fi;


ps --no-headers -o command -p $(pidof mysqld mariadbd) 2>/dev/null | egrep -i "allow[_-]suspicious[_-]udfs(\s|$|=on|=1|=yes|=true)" && (echo "Remove allow-suspicious-udfs option from the service start command line"; read -p "Next"); 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*allow[_-]suspicious[_-]udfs\s*(=\s*[\"']?(on|1|yes|true)|$|#))/## \1/" "$file"; done


echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*local[_-]infile)/## \1/" "$file"; done; 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nlocal-infile=0/' "$file"; break; fi; done;


ps --no-headers -o command -p $(pidof mysqld mariadbd) 2>/dev/null | egrep -i "skip[_-]grant[_-]tables(\s|$|=on|=1|=yes|=true)" && (echo "Remove skip-grant-tables option from the service start command line"; read -p "Next"); 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*skip[_-]grant[_-]tables\s*(=\s*[\"']?(on|1|yes|true)|$|#))/## \1/" "$file"; done


couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''have_symlink'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"); 
if [[ -z $(echo "$couch_a" | egrep -i 'have_symlink\s+(disabled|0|off|false|no)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*skip[_-]symbolic[_-]links)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nskip-symbolic-links = YES/' "$file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done; fi;


if [[ -z $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SHOW GLOBAL VARIABLES WHERE Variable_name = '\''secure_file_priv'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | grep -E '^\s*secure_file_priv\s+\S') ]]; 
   then 
   cd "$mysql_datadir"; 
   couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''plugin_dir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD");
   echo "$couch_a";   
   read -p "Enter path for secure-file-priv (this option limits import and export file operations, such as LOAD DATA, SELECT ... INTO OUTFILE and LOAD_FILE(), to work only with files in that directory):" c_dir_path; 
   if [ -n "$c_dir_path" ]; 
     then 
     couch_a=$(echo "$couch_a" | cut -f2);
     if [[ "$(readlink -f "$couch_a")" = "$(readlink -f "$c_dir_path")" ]] || [[ "$(readlink -f "$couch_a")" = "$(readlink -f "$c_dir_path")"/* ]]; then echo "The 'plugin_dir' directory is subdirectory for secure-file-priv that is not secure and is not compliant, break"; exit 133; fi; 
     echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*secure[_-]file[_-]priv\s*=)/## \1/" "$file"; done; 
     echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s;^(\s*\[(mariadb|mysqld)\].*)$;\1\nsecure_file_priv=\"${c_dir_path}\";" "$file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done;
     if [ ! -d "$c_dir_path" ]; 
       then 
       couch_sql_user=$(if pidof mariadbd &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mariadbd); elif pidof mysqld &>/dev/null; then ps --no-headers -o user:32 -p $(pidof mysqld); fi); 
       if [[ -n "$couch_sql_user" ]]; then mkdir "$c_dir_path"; chmod g-w,o-rwx "$c_dir_path"; chown ${couch_sql_user}:${couch_sql_user} "$c_dir_path"; fi;
     fi;       
  fi; 
fi


couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''sql_mode'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [ -n "$couch_a" ] && [[ -z $(echo "$couch_a" | grep -i 'STRICT_ALL_TABLES') ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*sql[_-]mode\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsql-mode=${couch_a},STRICT_ALL_TABLES/" "$file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done; fi;


couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''sql_mode'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [ -n "$couch_a" ] && [[ -z $(echo "$couch_a" | grep -i 'NO_AUTO_CREATE_USER') ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*sql[_-]mode\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri "s/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsql-mode=${couch_a},NO_AUTO_CREATE_USER/" "$file"; echo "MariaDB restart is needed to activate updated setting"; break; fi; done; fi;


echo "[Manual]" 'Verify access by checking the user and db tables. Use the following two queries: 
select user, host from mysql.user where (Select_priv = '\''Y'\'') or (Insert_priv = '\''Y'\'') or (Update_priv = '\''Y'\'') or (Delete_priv = '\''Y'\'') or (Create_priv = '\''Y'\'') or (Drop_priv = '\''Y'\'');
and 
select user, host from mysql.db where db = '\''mysql'\'' and ( (Select_priv = '\''Y'\'') or (Insert_priv = '\''Y'\'') or (Update_priv = '\''Y'\'') or (Delete_priv = '\''Y'\'') or (Create_priv = '\''Y'\'') or (Drop_priv = '\''Y'\''));'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-­administrative users:
select user, host from mysql.user where File_priv = '\''Y'\''; 
For each non-­administrative user, issue the following SQL statement:
REVOKE FILE ON *.* FROM '\''<user>'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-administrative users:
select user, host from mysql.user where Process_priv = '\''Y'\'';
For each non-administrative user, issue the following SQL statement:
REVOKE PROCESS ON *.* FROM '\''<user>'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-administrative users:
select user, host from mysql.user where Super_priv = '\''Y'\''; 
For each non-administrative user, issue the following SQL statement: 
REVOKE SUPER ON *.* FROM '\''<user>'\'';
It is more secure to migrate administrative users off SUPER and instead assign the specific and minimal set of mysql Dynamic Privileges needed to perform their tasks:
1. Assess the minimal set of Dynamic Permissions needed by a user to perform their duties.
2. For each user assign the appropriate Dynamic Permission and then revoke that <user> SUPER capability. For example, if administrator '\''u1'\''@'\''localhost'\'' requires SUPER for binary log purging and system variable modification, these statements make the required changes to the account thus limiting rights to what is needed:
GRANT BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN ON *.* TO '\''u1'\''@'\''localhost'\''; 
REVOKE SUPER ON *.* FROM '\''u1'\''@'\''localhost'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-administrative users:
SELECT user, host FROM mysql.user WHERE Shutdown_priv = '\''Y'\''; 
For each non-administrative user, issue the following SQL statement: 
REVOKE SHUTDOWN ON *.* FROM '\''<user>'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-administrative users:
SELECT user, host FROM mysql.user WHERE Create_user_priv = '\''Y'\''; 
For each non-administrative user, issue the following SQL statement:
REVOKE CREATE USER ON *.* FROM '\''<user>'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Allows reloading of grant tables (flush-privileges is a synonym). 
Verify using following query: 
select user, host from mysql.user where Reload_priv = '\''Y'\'';
Revoke this privilege from non-administrative users.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-administrative users: 
SELECT user, host FROM mysql.user WHERE Grant_priv = '\''Y'\''; 
SELECT user, host FROM mysql.db WHERE Grant_priv = '\''Y'\''; 
For each non-administrative user, issue the following SQL statement: 
REVOKE GRANT OPTION ON *.* FROM <user>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the non-slave users:
SELECT user, host FROM mysql.user WHERE Repl_slave_priv = '\''Y'\''; 
For each non-slave user, issue the following SQL statement: 
REVOKE REPLICATION SLAVE ON *.* FROM <user>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Enumerate the replication users.
For each replication user, issue the following SQL statement:
REVOKE SUPER ON *.* FROM '\''<replication_account>'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Check whether there are the unauthorized users, hosts, and databases returned in the result set of the audit procedure:
SELECT User,Host,Db FROM mysql.db WHERE Select_priv='\''Y'\'' OR Insert_priv='\''Y'\'' OR Update_priv='\''Y'\'' OR Delete_priv='\''Y'\'' OR Create_priv='\''Y'\'' OR Drop_priv='\''Y'\'' OR Alter_priv='\''Y'\'';
For each such user, issue the following SQL statement: 
REVOKE SELECT ON <host>.<database> FROM <user>;
REVOKE INSERT ON <host>.<database> FROM <user>;
REVOKE UPDATE ON <host>.<database> FROM <user>;
REVOKE DELETE ON <host>.<database> FROM <user>;
REVOKE CREATE ON <host>.<database> FROM <user>;
REVOKE DROP ON <host>.<database> FROM <user>;
REVOKE ALTER ON <host>.<database> FROM <user>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Each database user should be used for single purpose/person. Add/Remove users so that each user is only used for one specific purpose.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Anonymous accounts are users with no name ('\'''\'').They allow for default logins and their permissions can sometimes be used by other users.
Check for anonymous users using the query:
select user,host from mysql.user where user = '\'''\'';
For each anonymous user, DROP or assign them a name.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Host parameters for users should not contain wildcards ('\''%'\''). This can be checked using:
select user from mysql.user where host = '\''%'\'';
Enumerate all users returned after running the audit procedure. Either ALTER the user'\''s host to be specific or DROP the user.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Blank passwords allow a user to login with out using a password. Use the "select User, Password from mysql.user where length(password) = 0 or password is null;" query to verify.
For each row returned from the audit procedure, set a password for the given user using the following statement (as an example):
SET PASSWORD FOR <user>@'\''<host>'\'' = PASSWORD('\''<clear password>'\'')'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'All password hashes should be 41 bytes or longer.
If old hashed are used, perform next queries to replace old-style password hashes:
mysql> SET SESSION old_passwords=FALSE;
mysql> SET PASSWORD FOR ‘username’@’IPServer.%’=PASSWORD(‘<put password here>’);
mysql> flush privileges;'
read -n 1 -p "Press Enter to continue..."


echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*old[_-]passwords\s*=)/## \1/" "$file"; done; 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nold_passwords=0/' "$file"; break; fi; done;
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL old_passwords=OFF;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"


echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*secure[_-]auth\s*=)/## \1/" "$file"; done; 
echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsecure_auth=ON/' "$file"; break; fi; done;
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL secure_auth=ON;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"


IFS=";" read -a couch_mysql_files <<< "$mysql_all_conf_files"

which yum && yum -y install MariaDB-cracklib-password-check 2>/dev/null; which apt-get && apt-get -y install mariadb-plugin-cracklib-password-check 2>/dev/null; which dnf && dnf -y install MariaDB-cracklib-password-check 2>/dev/null; which zipper && zipper install -n MariaDB-cracklib-password-check 2>/dev/null;

couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*plugin_load_add\s*=\s*simple_password_check(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nplugin_load_add = simple_password_check/' "$conf_file"; break; fi; done; fi; 
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*plugin_load_add\s*=\s*cracklib_password_check(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nplugin_load_add = cracklib_password_check/' "$conf_file"; break; fi; done; fi; 
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*simple_password_check\s*=\s*FORCE_PLUS_PERMANENT(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsimple_password_check  = FORCE_PLUS_PERMANENT/' "$conf_file"; break; fi; done; fi; 
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*cracklib_password_check\s*=\s*FORCE_PLUS_PERMANENT(\s|$)' "$conf_file" && couch_c=1; done
if [[ "$couch_c" == 0 ]]; then for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$conf_file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\ncracklib_password_check  = FORCE_PLUS_PERMANENT/' "$conf_file"; break; fi; done; fi; 

"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'INSTALL SONAME '\''simple_password_check'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'INSTALL SONAME '\''cracklib_password_check'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''simple_password_check_minimal_length'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [ -z "$couch_a" ] || [[ -n $(echo "$couch_a" | egrep '^\s*simple_password_check_minimal_length\s+[0-7](\s|$)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*simple[_-]password[_-]check[_-]minimal[_-]length\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsimple-password-check-minimal-length = 8/' "$file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL simple_password_check_minimal_length=8;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi; 

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''simple_password_check_letters_same_case'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [ -z "$couch_a" ] || [[ -n $(echo "$couch_a" | egrep '^\s*simple_password_check_letters_same_case\s+0(\s|$)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*simple[_-]password[_-]check[_-]letters[_-]same[_-]case\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsimple-password-check-letters-same-case = 1/' "$file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL simple_password_check_letters_same_case=1;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi; 

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''simple_password_check_digits'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [ -z "$couch_a" ] || [[ -n $(echo "$couch_a" | egrep '^\s*simple_password_check_digits\s+0(\s|$)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*simple[_-]password[_-]check[_-]digits\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsimple-password-check-digits = 1/' "$file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL simple_password_check_digits=1;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi; 

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''simple_password_check_other_characters'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [ -z "$couch_a" ] || [[ -n $(echo "$couch_a" | egrep '^\s*simple_password_check_other_characters\s+0(\s|$)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*simple[_-]password[_-]check[_-]other[_-]characters\s*=)/## \1/" "$file"; done; echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nsimple-password-check-other-characters = 1/' "$file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL simple_password_check_other_characters=1;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi;


"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+(10\.[4-9]|1[1-9]|[2-9][0-9])' && (couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''default_password_lifetime'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"); if [ -z "$couch_a" ] || [[ -z $(echo "$couch_a" | egrep '^\s*default_password_lifetime\s+(9[1-9]|\d\d\d+)(\s|$)' ) ]]; then echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\ndefault_password_lifetime=90/' "$file"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL default_password_lifetime=90;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; break; fi; done; fi)


echo "[Manual]" 'Do not use password configuration option.
If it is needed use the mysql_config_editor to store authtentication credentials in .mylogin.cnf in encrypted form. If not possible, use the user-specific options file and restrict file access permissions to the user identity.'
read -n 1 -p "Press Enter to continue..."


IFS=";" read -a couch_mysql_files <<< "$mysql_all_conf_files";
couch_c=0; 
for conf_file in "${couch_mysql_files[@]}"; do grep -Ei '^\s*\[client\]' "$conf_file" && couch_c=1; done;
if [[ "$couch_c" == 0 ]]; then 
  echo "[client]" >> /etc/mysql/mariadb.conf.d/50-client.cnf; echo "ssl-verify-server-cert" >> /etc/mysql/mariadb.conf.d/50-client.cnf; 
else
  for conf_file in "${couch_mysql_files[@]}"; do sed -ri 's/^\s*ssl-verify-server-cert/## ssl-verify-server-cert/' "$conf_file"; done;
  for conf_file in "${couch_mysql_files[@]}"; do if grep -E '^\s*\[client\]' "$conf_file"; then sed -ri 's/^(\s*\[client\].*)$/\1\nssl-verify-server-cert/' "$conf_file"; break; fi; done; 
fi;


echo "[Manual]" 'Create private key and SSL-certificate for MariaDB.
Configure SSL protection for MariaDB connections.
Example:
To enroll certificate from MS AD Certification Service and configure it in MariaDB server follow next steps:
1. Generate private key and certificate request with parameters which you need:
openssl req -new -newkey rsa:2048 -nodes -keyout private.key -out cert.req -subj "/CN=<...>/OU=<...>/O=<...>/C=<...>/ST=<...>/L=<...>"
Convert private key to PKCS#1 if it is not (key-file content must start with "-----BEGIN RSA PRIVATE KEY-----"):
openssl rsa -in private.key -out private-key.pem
2. Open URL AD_CS_server_name/certsrv/, click link Request a certificate -> advanced certificate request and copy text content of cert.req file to input box. Click Submit.
Download certificate in Base64 format and save it as server-cert.pem.
Download CA certificate from CA management console or some other storage in Base64 format and save it as ca-cert.pem.
3. Copy private-key.pem, server-cert.pem and ca-cert.pem to some place on MariaDB server. Add next lines to my.cnf [mysqld] section with paths to these files, example:
ssl-ca="/var/lib/mysql/ca-cert.pem"
ssl-cert="/var/lib/mysql/server-cert.pem"
ssl-key="/var/lib/mysql/private-key.pem"
Restart MariaDB service.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Do not use a default or example certificate. Generate new certificates, keys, and other cryptographic material as needed for each affected MariaDB instance.'
read -n 1 -p "Press Enter to continue..."


if [[ -n $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | grep -E '\s(10\.(5\.([2-9]\.|\d\d)|[6-9]\.|\d\d)|1[1-9]\.|[2-9]\d\.)') ]]; then
  read -p "Enable mandatory SSL/TLS now (connections attempted using insecure transport will be rejected)?[y][N]" couch_a;
  if [[ "$couch_a" =~ ^[Yy][eE]?[sS]?$ ]]; then 
    echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*require[_-]secure[_-]transport\s*=)/## \1/" "$file"; done; 
    echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\nrequire_secure_transport=ON/' "$file"; break; fi; done;
    "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SET GLOBAL require_secure_transport=ON;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD";
  fi;
fi;


echo "[Manual]" 'Use the ALTER USER statement to require the use of SSL/TLS: 
ALTER USER '\''my_user'\''@'\''app1.example.com'\'' REQUIRE SSL;
Note: REQUIRE SSL only enforces TLS. There are additional options REQUIRE X509, REQUIRE ISSUER, REQUIRE SUBJECT and REQUIRE CIPHER which can be used to further restrict the connection.

Default: empty string, the equivalent result of using REQUIRE NONE with an ALTER USER statement.'
read -n 1 -p "Press Enter to continue..."


read -p "Set TLS versions to TLSv1.2,TLSv1.3 now (only clients that support the specified TLS versions will able to connect)?[y][N]" couch_a;
if [[ "$couch_a" =~ ^[Yy][eE]?[sS]?$ ]]; then 
  echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do sed -ri "s/^(\s*tls_version\s*=)/## \1/" "$file"; done; 
  echo "$mysql_all_conf_files" | tr \; \\n | while read -r file; do if grep -E '^\s*\[(mariadb|mysqld)\]' "$file"; then sed -ri 's/^(\s*\[(mariadb|mysqld)\].*)$/\1\ntls_version=TLSv1.2,TLSv1.3/' "$file"; break; fi; done;
  echo "MariaDB restart is needed to activate updated setting";
fi;


echo "[Manual]" 'Create a backup policy and backup schedule.
A user with full privileges is needed for backup. The credentials for this user should be protected.
Restrict filesystem permissions for backups. Implement encryption if needed.
Include next files to the backup:
• Configuration files (my.ini and included files)
• SSL files (certificates, keys)
• User Defined Functions (UDFs)
• Source code for customizations'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Implement regular backup checks and document each check.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Verify master.info, relay-log.info, and SQL_LOAD-* files are present in backups.'
read -n 1 -p "Press Enter to continue..."


read -p "Do you want to restart MariaDB server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart || service mysql restart; fi
