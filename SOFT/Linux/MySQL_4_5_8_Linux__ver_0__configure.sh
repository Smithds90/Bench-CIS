#!/usr/bin/env bash

read -p "Enter MySQL login: " COUCH_APP_LOGIN;
stty -echo;
read -p "Enter MySQL password: " COUCH_APP_PASSWORD;
echo;
stty echo;

mysql_path=$(which mysql || ps --no-headers o args p $(pidof mysqld) | cut -d" " -f1 | sed "s/mysqld$/mysql/")

mysql_ini_file=$(line=$(ps --no-headers o args p $(pidof mysqld) | grep "defaults-file"); if [[ ! -z $line ]]; then for i in $line; do echo $i | grep "defaults-file" 1>/dev/null && echo $i | cut -f2 -d=; done; else for file in `$mysql_path --help | grep -A 1 "Default options are read from the following files in the given" | grep -v "Default options are read from the following files in the given"`; do if [ -e $file ]; then echo $file; break; fi; done; fi;)

mysql_extra_configs=$(line=$(ps --no-headers o args p $(pidof mysqld) | grep "defaults-extra-file"); if [[ ! -z $line ]]; then for i in $line; do echo $i | grep "defaults-extra-file" 1>/dev/null && echo $i | cut -f2 -d=; done; fi; q=$IFS; IFS=$'\n'; for file in $(grep -E '^\s*!include\s' $mysql_ini_file | sed -r 's/(^\s*!include\s+|\s+#.*$|\s+$)//'); do printf " ${file}"; done; for dir in $(grep -E '^\s*!includedir\s' $mysql_ini_file | sed -r 's/(^\s*!includedir\s+|\s+#.*$|\s+$)//'); do for file in $(ls "$dir"/*.cnf); do printf " ${file}"; done; done; IFS=$q)

mysql_datadir=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''datadir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2)

if [[ -z $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'select '\''test_pass_string'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" 2>&1 | grep -i "test_pass_string") ]];
then echo "Incorrect credentials, please try again.";
	exit;
fi;


echo "[Manual]" 'Install MySQL on the dedicated for these purposes machine. Remove excess applications or services and/or remove unnecessary roles from the underlying operating system.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Run MySQL in Jail or Chroot'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure usage of dedicated non-administrative account for MySQL daemon/service'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict network access using local or network IP filtering'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Databases must not be located on system partitions'
read -n 1 -p "Press Enter to continue..."


for i in `find / -name .mysql_history`; do rm -f $i; ln -s /dev/null $i; done


echo MYSQL_PWD= >> /etc/init.d/mysql
for i in `find / -type f -name .bash_profile`; do echo MYSQL_PWD= >> $i; done
for i in `find / -type f -name .bashrc`; do echo MYSQL_PWD= >> $i; done
for i in `find / -type f -name .profile`; do echo MYSQL_PWD= >> $i; done
set MYSQL_PWD=


couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld))
chsh -s "$(which nologin)" $couch_sql_user


read -p "Do you want to remove all access to datadir directory and all subdirectories except access for the owner now?[yes][NO]" consent; if [ "$consent" == "yes" ]; then chmod -R go-rwx $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''datadir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); fi


chmod go-w $mysql_path
chmod go-w `which mysqld`
chmod go-w `which mysqladmin`


chmod go-w $mysql_ini_file $mysql_extra_configs


couch_log_bin=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_bin_basename'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_log_bin ]]; then cd $mysql_datadir; ls -lad $couch_log_bin $couch_log_bin.*; chmod o-rwx $couch_log_bin $couch_log_bin.*; couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); if [[ ! -z $couch_sql_user ]]; then chown $couch_sql_user:$couch_sql_user $couch_log_bin $couch_log_bin.*; fi; fi


couch_ssl_key=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_key'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);if [[ ! -z $couch_ssl_key ]]; then cd $mysql_datadir; chmod go-rwx $couch_ssl_key; chmod u-wx $couch_ssl_key; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_error'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_f ]]; then cd $mysql_datadir; ls -lad $couch_f; chmod o-rwx $couch_f; couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); if [[ ! -z $couch_sql_user ]]; then chown $couch_sql_user:$couch_sql_user $couch_f; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''slow_query_log_file'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_f ]]; then cd $mysql_datadir; ls -lad $couch_f; chmod o-rwx $couch_f; couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); if [[ ! -z $couch_sql_user ]]; then chown $couch_sql_user:$couch_sql_user $couch_f; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''relay_log_basename'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_f ]]; then cd $mysql_datadir; ls -lad $couch_f; chmod o-rwx $couch_f; couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); if [[ ! -z $couch_sql_user ]]; then chown $couch_sql_user:$couch_sql_user $couch_f; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''general_log_file'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_f ]]; then cd $mysql_datadir; ls -lad $couch_f; chmod o-rwx $couch_f; couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); if [[ ! -z $couch_sql_user ]]; then chown $couch_sql_user:$couch_sql_user $couch_f; fi; fi


couch_f=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''plugin_dir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_f ]]; then cd $mysql_datadir; ls -lad $couch_f; chmod o-w $couch_f; fi


cd $mysql_datadir;
couch_ssl_ca=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_ca'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_ssl_ca ]]; then chmod go-w $couch_ssl_ca; fi;
couch_ssl_cert=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_cert'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); if [[ ! -z $couch_ssl_cert ]]; then chmod go-w $couch_ssl_cert; fi;


couch_a=`"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''log_error'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2`;
if [ -z "$couch_a" ]; then read -p "Enter location for log_error file:" mysql_log_error_file; sed -i "s#\[mysqld\]#[mysqld]\nlog-error=${mysql_log_error_file}#" $mysql_ini_file $mysql_extra_configs; fi;
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


echo "[Manual]" 'Configure log-error to file not on the system partition.
If general-log is enabled, configure path general_log_file to be located not on the system partition.
If log-bin is enabled, configure path log_bin_basename to be located not on the system partition.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Get database location with SQL-query:
show variables like '\''datadir'\'';
Configure log-error to file not on the database partition.
If general-log is enabled, configure path general_log_file to be located not on the database partition.
If log-bin is enabled, configure path log_bin_basename to be located not on the database partition.'
read -n 1 -p "Press Enter to continue..."


sed -ri "s/^(\s*log-update(\s|=))/# \1/" $mysql_ini_file $mysql_extra_configs
ps up $(pidof mysqld) | grep "log-update" && (echo Remove --log-update from service start command line; read -p "Next" aaa)
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


$mysql_path -V | egrep -i "\s(distrib|ver)\s+[45]\." 1>/dev/null && (sed -i "s/^\s*log-warnings/# log-warnings/g" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\[mysqld\]/[mysqld]\nlog-warnings=2/g" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi)


sed -ri "s/^(\s*log-raw(\s|=))/# \1/" $mysql_ini_file $mysql_extra_configs
sed -i "s/^\s*\[mysqld\]/[mysqld]\nlog-raw=OFF/" $mysql_ini_file $mysql_extra_configs
ps up $(pidof mysqld) | grep "log-raw" && (echo Remove --log-raw from service start command line; read -p "Next" aaa)
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


sed -i "s/^\s*log-error-verbosity/# log-error-verbosity/" $mysql_ini_file $mysql_extra_configs
sed -i "s/^\s*\[mysqld\]/[mysqld]\nlog-error-verbosity=3/" $mysql_ini_file $mysql_extra_configs
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


echo "[Manual]" 'Migrate to version 5.6 or higher.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Install the latest patches for your version or upgrade to the latest version.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Each time you upgrade MySQL, you should execute mysql_upgrade, which looks for incompatibilities with the upgraded MySQL server:
- It upgrades the system tables in the mysql schema so that you can take advantage of new privileges or capabilities that might have been added.
- It upgrades the Performance Schema and sys schema.
- It examines user schemas. 
In older versions mysql_fix_privilege_tables must be used (mysql_fix_privilege_tables was superseded by mysql_upgrade in MySQL 5.1.7).'
read -n 1 -p "Press Enter to continue..."


"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SHOW DATABASES like '\''test'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | grep test && (read -p "Do you want to remove test database now?[YES][no]" consent; if [ "$consent" != "no" ]; then "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'drop database test;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; fi)


a=`"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'select user from mysql.user where user='\''root'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"`
if [ "$COUCH_APP_LOGIN" != "root" ]; then if [[ ! -z $a ]]; then read -p "Do you want to rename root account now?[yes][NO]" consent; if [ "$consent" == "yes" ]; then read -p "Enter new name for MySQL root user:" new_mysql_root_user; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'update mysql.user set user='\''$new_mysql_root_user'\'' where user='\''root'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'flush privileges;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; fi; fi; fi


"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'INSTALL PLUGIN validate_password SONAME '\''validate_password.so'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''validate_password_length'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [[ -z $(echo "$couch_a" | egrep '^\s*validate_password_length\s+([8-9]|[1-9][0-9]+)(\s|$)' ) ]]; then sed -i "s/^\s*validate-password-length/# validate-password-length/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password-length=8/" $mysql_ini_file $mysql_extra_configs; fi

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''validate_password_mixed_case_count'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [[ -z $(echo "$couch_a" | egrep '^\s*validate_password_mixed_case_count\s+[1-9](\s|$)' ) ]]; then sed -i "s/^\s*validate-password-mixed-case-count/# validate-password-mixed-case-count/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password-mixed-case-count=1/" $mysql_ini_file $mysql_extra_configs; fi

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''validate_password_number_count'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [[ -z $(echo "$couch_a" | egrep '^\s*validate_password_number_count\s+[1-9](\s|$)' ) ]]; then sed -i "s/^\s*validate-password-number-count/# validate-password-number-count/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password-number-count=1/" $mysql_ini_file $mysql_extra_configs; fi

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''validate_password_special_char_count'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [[ -z $(echo "$couch_a" | egrep '^\s*validate_password_special_char_count\s+[1-9](\s|$)' ) ]]; then sed -i "s/^\s*validate-password-special-char-count/# validate-password-special-char-count/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password-special-char-count=1/" $mysql_ini_file $mysql_extra_configs; fi

couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''validate_password_policy'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD")
if [[ -z $(echo "$couch_a" | egrep -i '^\s*validate_password_policy\s+(medium|strong|1|2)(\s|$)' ) ]]; then sed -i "s/^\s*validate-password-policy/# validate-password-policy/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password-policy=2/" $mysql_ini_file $mysql_extra_configs; fi

sed -i "s/^\s*validate-password\s*=/# validate-password =/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nvalidate-password=ON/" $mysql_ini_file $mysql_extra_configs

restart=NO; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


echo "[Manual]" 'All password hashes should be 41 bytes or longer.
If old hashed are used, perform next queries to replace old-style password hashes:
mysql> SET SESSION old_passwords=FALSE;
mysql> SET PASSWORD FOR ‘username’@’IPServer.%’=PASSWORD(‘<put password here>’);
mysql> flush privileges;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Each database user should be used for single purpose/person. Add/Remove users so that each user is only used for one specific purpose.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Host parameters for users should not contain wildcards ('\''%'\''). This can be checked using:
select user from mysql.user where host = '\''%'\'';
Enumerate all users returned after running the audit procedure. Either ALTER the user'\''s host to be specific or DROP the user.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Blank passwords allow a user to login with out using a password. Use the "select User, Password from mysql.user where length(password) = 0 or password is null;" or "select User, authentication_string from mysql.user where length(authentication_string) = 0 or authentication_string is null;" query to verify.
For each row returned from the audit procedure, set a password for the given user using the following statement (as an example):
SET PASSWORD FOR <user>@'\''<host>'\'' = PASSWORD('\''<clear password>'\'')'
read -n 1 -p "Press Enter to continue..."


a=`"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'select user from mysql.user where user='\'''\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"`
if [[ ! -z $a ]]; then read -p "Enter new name for anonymous mysql user:" mysql_anonymous_login; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'update mysql.user set user='\''$mysql_anonymous_login'\'' where user='\'''\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'flush privileges;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; fi


"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'uninstall plugin daemon_memcached;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"


"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+(5\.[7-9]|8\.)' && (couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''default_password_lifetime'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"); if [[ -z $(echo "$couch_a" | egrep '^\s*default_password_lifetime\s+(9[0-9]|[1-9][0-9][0-9]+)(\s|$)' ) ]]; then sed -i "s/^\s*default-password-lifetime/# default-password-lifetime/g" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\[mysqld\]/[mysqld]\ndefault-password-lifetime=90/g" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi; fi )


echo "[Manual]" 'Verify access by checking the user and db tables. Use the following two queries: “select user, host from mysql.user where (Select_priv = '\''Y'\'') or (Insert_priv = '\''Y'\'') or (Update_priv = '\''Y'\'') or (Delete_priv = '\''Y'\'') or (Create_priv = '\''Y'\'') or (Drop_priv = '\''Y'\'');” and “select user, host from mysql.db where db = '\''mysql'\'' and ( (Select_priv = '\''Y'\'') or (Insert_priv = '\''Y'\'') or (Update_priv = '\''Y'\'') or (Delete_priv = '\''Y'\'') or (Create_priv = '\''Y'\'') or (Drop_priv = '\''Y'\''));'
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
REVOKE SUPER ON *.* FROM '\''<user>'\'';'
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


ps --no-headers -o command p $(pidof mysqld) | egrep -i "allow-suspicious-udfs(\s|$=on)" && (echo Remove --allow-suspicious-udfs from service start command line; read -p "Next" aaa)
sed -i "s/^\s*allow-suspicious-udfs/# allow-suspicious-udfs/" $mysql_ini_file $mysql_extra_configs
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


sed -i "s/^\s*local-infile/# local-infile/" $mysql_ini_file $mysql_extra_configs
sed -i "s/^\s*\[mysqld\]/[mysqld]\nlocal-infile=0/" $mysql_ini_file $mysql_extra_configs
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


$mysql_path -V | egrep -i "\s(distrib|ver)\s+[45]\." 1>/dev/null && (sed -i "s/^\s*old-passwords/# old-passwords/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nold-passwords=0/" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi)


echo "[Manual]" 'Default value of safe-show-database is ON (from MySQL 5.1). The option is removed in MySQL 5.5. In older versions do not disable safe-show-database parameter.'
read -n 1 -p "Press Enter to continue..."


$mysql_path -V | egrep -i "\s(distrib|ver)\s+[45]\." 1>/dev/null && (sed -i "s/^\s*secure-auth/# secure-auth/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nsecure-auth=on/g" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi)


sed -i "s/^\s*skip-grant-tables/# skip-grant-tables/" $mysql_ini_file $mysql_extra_configs
sed -i "s/^\s*\[mysqld\]/[mysqld]\nskip-grant-tables=OFF/" $mysql_ini_file $mysql_extra_configs
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


echo "[Manual]" '--skip-merge'
read -n 1 -p "Press Enter to continue..."


if [[ -n $($mysql_path -V | egrep -i "\s(distrib|ver)\s+[45]\.") ]]; then couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''sql_mode'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2); echo $couch_a | grep -i 'NO_AUTO_CREATE_USER' || ( sed -i "s/^\s*sql-mode\s*=/# sql-mode =/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nsql-mode=${couch_a},NO_AUTO_CREATE_USER/" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi); fi


sed -i "s/^\s*skip-symbolic-links/# skip-symbolic-links/" $mysql_ini_file $mysql_extra_configs
sed -i "s/^\s*\[mysqld\]/[mysqld]\nskip-symbolic-links/" $mysql_ini_file $mysql_extra_configs
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


sed -i "s/^\s*password\s*=/# password=/" $mysql_ini_file $mysql_extra_configs


if [[ -z $("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'SHOW GLOBAL VARIABLES WHERE Variable_name = '\''secure_file_priv'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | grep -E '^\s*secure_file_priv\s+\S') ]]; then "$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''plugin_dir'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"; read -p "Enter path for secure-file-priv (this option limits import and export operations, such as LOAD DATA, SELECT ... INTO OUTFILE and LOAD_FILE(), to work only with files in that directory):" c_dir_path; if [ -n "$c_dir_path" ]; then sed -i "s/^\s*secure-file-priv\s*=/# secure-file-priv =/" $mysql_ini_file $mysql_extra_configs; sed -i "s#^\s*\[mysqld\]#[mysqld]\nsecure-file-priv=${c_dir_path}#" $mysql_ini_file $mysql_extra_configs; cd $mysql_datadir; [[ -d "$c_dir_path" ]] || (couch_sql_user=$(ps --no-headers -o user:25 -p $(pidof mysqld)); mkdir $c_dir_path; chown ${couch_sql_user}:${couch_sql_user} $c_dir_path); read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi; fi; fi


couch_a=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''sql_mode'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
echo $couch_a | grep -i 'STRICT_ALL_TABLES' || ( sed -i "s/^\s*sql-mode\s*=/# sql-mode =/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nsql-mode=${couch_a},STRICT_ALL_TABLES/" $mysql_ini_file $mysql_extra_configs; read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi)


read -p "Do you want to enable MySQL-server name identity verification for mysql client (connection will be lost if server certificate can not be verified)?[yes][NO]" consent; if [ "$consent" == "yes" ]; then \
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+[45]\.' && (if [[ -n $(egrep "^\s*\[(client|mysql)\]" $mysql_ini_file $mysql_extra_configs 2>/dev/null) ]]; then sed -i "s/^\s*ssl-mode\s*=/## ssl-mode=/" $mysql_ini_file $mysql_extra_configs; sed -ri "s/^\s*\[(client|mysql)\]/[\1]\nssl-verify-server-cert/" $mysql_ini_file $mysql_extra_configs; else echo "[client]" >> $mysql_ini_file; echo "ssl-verify-server-cert" >> $mysql_ini_file; fi);\
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''version'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | egrep 'version\s+8\.' && (if [[ -n $(egrep "^\s*\[(client|mysql)\]" $mysql_ini_file $mysql_extra_configs 2>/dev/null) ]]; then sed -i "s/^\s*ssl-mode\s*=/## ssl-mode=/" $mysql_ini_file $mysql_extra_configs; sed -ri "s/^\s*\[(client|mysql)\]/[\1]\nssl-mode=VERIFY_IDENTITY/" $mysql_ini_file $mysql_extra_configs; else echo "[client]" >> $mysql_ini_file; echo "ssl-mode=VERIFY_IDENTITY" >> $mysql_ini_file; fi);\
fi


cd $mysql_datadir;
i=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_ca'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [[ ! -z $i ]]; then ls -ld $i; else read -p "Enter path and name of CA cetificate pem file:" mysql_ca_cert; sed -i "s#^\s*\[mysqld\]#[mysqld]\nssl-ca=$mysql_ca_cert#" $mysql_ini_file $mysql_extra_configs; fi;
i=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_cert'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [[ ! -z $i ]]; then ls -ld $i; else read -p "Enter path and name of Server certificate pem file:" mysql_server_cert; sed -i "s#^\s*\[mysqld\]#[mysqld]\nssl-cert=$mysql_server_cert#" $mysql_ini_file $mysql_extra_configs; fi;
i=$("$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'show variables like '\''ssl_key'\'';' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD" | cut -f2);
if [[ ! -z $i ]]; then ls -ld $i; else read -p "Enter path and name of Server key pem file:" mysql_server_key; sed -i "s#^\s*\[mysqld\]#[mysqld]\nssl-key=$mysql_server_key#" $mysql_ini_file $mysql_extra_configs; fi;
"$mysql_path" --defaults-extra-file=/dev/stdin -B -N -e 'select ssl_type from mysql.user;' <<< "[client]
user=$COUCH_APP_LOGIN
password=$COUCH_APP_PASSWORD"
echo Force users to use SSL by setting the mysql.user.ssl_type field to ANY, X509 or SPECIFIED
read -p "Next" aaa
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi


echo "[Manual]" 'Do not use a default or example certificate. Generate a key specifically for MySQL'
read -n 1 -p "Press Enter to continue..."


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


sed -i "s/^\s*master-info-repository\s*=/# master-info-repository =/" $mysql_ini_file $mysql_extra_configs; sed -i "s/^\s*\[mysqld\]/[mysqld]\nmaster-info-repository=TABLE/" $mysql_ini_file $mysql_extra_configs;
if [ -e "$mysql_datadir/master.info" ]; then read -p "Delete the insecure file master.info?[Y][n]" consent; if [ "$consent" != "n" ]; then rm -f "$mysql_datadir/master.info"; fi; fi
read -p "Do you want to restart MySQL server for updating config now?[yes][NO]" restart; if [ "$restart" == "yes" ]; then service mysqld restart 2>/dev/null || service mysql restart; fi



