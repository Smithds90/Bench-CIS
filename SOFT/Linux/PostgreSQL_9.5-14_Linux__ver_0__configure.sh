#!/usr/bin/env bash

couchpgdatadir=$(if [ -n "$PGDATA" ]; then echo "$PGDATA"; else ps --no-headers o args p $(pidof postgres postmaster) | grep -oP "\s-D\s+([^'\"]\S*|'.*?'|\".*?\")" | head -n 1 | sed -r "s/^.*-D\s+//" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"; fi)

couchmainpgconf=$(cmainpg=$(ps --no-headers o args p $(pidof postgres postmaster) | grep -oP "config_file=([^'\"]\S*|'.*?'|\".*?\")" | head -n 1 | sed "s/config_file=//" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [ -n "$cmainpg" ]; then echo "$cmainpg"; else echo "$couchpgdatadir/postgresql.conf" | sed 's#//#/#g'; fi)

couchpgautoconf=$(echo "$couchmainpgconf" | sed 's#\.conf$#.auto.conf#')

sudo -u postgres touch "$couchmainpgconf"

echo "[Manual]" 'Alter the configured repositories so they only include valid and authorized sources of packages. 
As an example of adding an authorized repository, we will install the PGDG repository RPM from '\''yum.postgresql.org'\'' (note that because of a change in the way packaging is handled in RHEL 8, we also need to disable the Red Hat built-in PostgreSQL module):
# dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
Last metadata expiration check: 0:01:35 ago on Fri 04 Oct 2019 01:19:37 PM EDT.
[snip]
Installed:
pgdg-redhat-repo-42.0-19.noarch
Complete!
# dnf -qy module disable postgresql'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If the version of PostgreSQL installed is not actual, update the PostgreSQL packages.'
read -n 1 -p "Press Enter to continue..."


c_dir=$(grep '^postgres:' /etc/passwd | cut -d: -f6);
if [ -d "$c_dir" ]; then if [ -e "$c_dir/.bash_profile" ]; then sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' "$c_dir/.bash_profile"; grep -E "^\s*umask\s+[0-7]?[0-7]?77" "$c_dir/.bash_profile" || echo "umask 077" >> "$c_dir/.bash_profile"; fi; if [ -e "$c_dir/.bashrc" ]; then sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' "$c_dir/.bashrc"; grep -E "^\s*umask\s+[0-7]?[0-7]?77" "$c_dir/.bashrc" || echo "umask 077" >> "$c_dir/.bashrc"; fi; if [ -e "$c_dir/.profile" ]; then sed -i 's/\(^\|\s\|;\)[uU][mM][aA][sS][kK]\s\+\([0-7]\)[0-7]*/\1umask 077/g' "$c_dir/.profile"; grep -E "^\s*umask\s+[0-7]?[0-7]?77" "$c_dir/.profile" || echo "umask 077" >> "$c_dir/.profile"; fi; fi


couchpguser=$(ps --no-headers o user:32,args p $(pidof postgres postmaster) | grep "[[:space:]]$couchpgdatadir" | head -n 1 | cut -f1 -d" ")
couchpggroup=$(id -gn "$couchpguser")
chmod -R go-rwx "$couchpgdatadir"
chown -R ${couchpguser}:${couchpggroup} "$couchpgdatadir"


couchpguser=$(ps --no-headers o user:32,args p $(pidof postgres postmaster) | grep "[[:space:]]$couchpgdatadir" | head -n 1 | cut -f1 -d" ")
couchpggroup=$(id -gn "$couchpguser")
cd "$couchpgdatadir"
q="$IFS"
IFS=$'\n'
for a in $(sudo -u postgres psql --pset pager=off -X -A -t -c 'select setting from pg_settings where name ~ '\''.*_file$'\'';' | grep -v "^$" | sed 's#^FILE:##'); do chmod go-rwx "$a"; chown ${couchpguser}:${couchpggroup} "$a"; echo "$a" | grep -E "(^[^/]|$couchpgdatadir)" && ( echo "File $a is located in the data cluster directory, consider to relocate it"; read -p "Next" b); done
while read -r line; do if [[ -n "$line" ]]; then chmod go-rwx "$line" 2>&1; chown ${couchpguser}:${couchpggroup} "$line" 2>&1; fi; done < <(grep -Eh "^\s*include(_dir|_if_exists)?\s*=" "$couchmainpgconf" "$couchpgautoconf" | sed -r "s/^\s*include(_dir|_if_exists)?\s*=\s*([^'\"]\S*|'[^']*'|\"[^\"]*\").*$/\2/" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
IFS="$q"


echo "[Manual]" 'Perform the following steps to remediate the subdirectory locations and permissions: 
1 Determine appropriate data, log, and tablespace directories and locations based on your organization'\''s security policies. If necessary, relocate all listed directories outside the data cluster. 
2 Ensure file permissions are restricted as much as possible (only access for owner). 
3 When directories are relocated to other partitions, ensure that they are of sufficient size to mitigate against excessive space utilization. 
4 Lastly, change the settings accordingly in the postgresql.conf configuration file and restart the database cluster for changes to take effect.'
read -n 1 -p "Press Enter to continue..."


cd "$couchpgdatadir"; 
q="$IFS"
IFS=$'\n,'
for a in $(sudo -u postgres psql --pset pager=off -X -A -t -c 'select setting from pg_settings where name in ('\''unix_socket_directories'\'','\''shared_preload_libraries'\'','\''dynamic_library_path'\'','\''local_preload_libraries'\'','\''session_preload_libraries'\'')' | grep -E -v "^\\\$" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); do chmod go-rwx "$a" 2>/dev/null; done
cd "$couchpgdatadir"; for a in $(sudo -u postgres psql --pset pager=off -X -A -t -c 'select setting from pg_settings where name in ('\''external_pid_file'\'')' | grep -E -v "^\\\$" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); do chmod go-wx "$a" 2>/dev/null; done
IFS="$q"


cd "$couchpgdatadir"
while read -r ld; do [ -n "$ld" ] && chmod -R go-rwx "$ld"; done < <(sudo -u postgres psql --pset pager=off -X -A -t -c 'show log_directory')


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_destination = '\''stderr'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E '^\s*log_destination' "$couchmainpgconf" | tail -n 1 | grep -E "(syslog|stderr)" || ( echo "log_destination = 'stderr'" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set logging_collector = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*logging_collector.*$/logging_collector = on/g" "$couchmainpgconf"
grep -E '^\s*logging_collector' "$couchmainpgconf" || echo "logging_collector = on" >> "$couchmainpgconf"


grep -E "^\s*log_directory\s*=?\s*'?[^' =]+'?" "$couchmainpgconf" "$couchpgautoconf" 2>/dev/null || ( read -p "Enter log directory (a path relative to cluster's data directory or an absolute path):" log_directory; echo "log_directory = '"$log_directory"'" >> "$couchmainpgconf" )


grep -E "^\s*log_filename\s*=?\s*'?[^' =]+'?" "$couchmainpgconf" || ( echo "log_filename = 'postgresql-%Y%m%d.log'" >> "$couchmainpgconf"; sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_filename = '\''postgresql-%Y%m%d.log'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


grep -E "^\s*log_file_mode\s*=?\s*'?0?[0246]00'?" "$couchmainpgconf" || ( sed -i "s/^\s*log_file_mode/#log_file_mode/g" "$couchmainpgconf"; echo "log_file_mode = 0600" >> "$couchmainpgconf"; sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_file_mode = '\''0600'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_truncate_on_rotation = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_truncate_on_rotation.*$/log_truncate_on_rotation = on/g" "$couchmainpgconf"
grep -E '^\s*log_truncate_on_rotation' "$couchmainpgconf" || echo "log_truncate_on_rotation = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_rotation_age = '\''1d'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E "^\s*log_rotation_age\s*=?\s*'?1d'?" "$couchmainpgconf" || ( sed -i "s/^\s*log_rotation_age/#log_rotation_age/g" "$couchmainpgconf"; echo "log_rotation_age = 1d" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_rotation_size = '\''1GB'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E "^\s*log_rotation_size\s*=?\s*'?\d+GB'?" "$couchmainpgconf" || ( sed -i "s/^\s*log_rotation_size/#log_rotation_size/g" "$couchmainpgconf"; echo "log_rotation_size = 1GB" >> "$couchmainpgconf" )


grep -E "^\s*syslog_facility\s*=?\s*'?local[0-9]+'?" "$couchmainpgconf" || ( sed -i "s/^\s*syslog_facility/#syslog_facility/g" "$couchmainpgconf"; echo "syslog_facility = local0" >> "$couchmainpgconf"; sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set syslog_facility = '\''local0'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


grep -E "^\s*syslog_ident\s*=?\s*'?[^' =]+'?" "$couchmainpgconf" "$couchpgautoconf" 2>/dev/null || ( read -p "Enter syslog identificator for postresql logs:" syslog_ident; echo "syslog_ident = '"$syslog_ident"'" >> "$couchmainpgconf" )


grep -E '^\s*client_min_messages' "$couchmainpgconf" | tail -n 1 | grep -E "notice" || ( sed -i "s/^\s*client_min_messages/#client_min_messages/g" "$couchmainpgconf"; echo "client_min_messages = 'notice'" >> "$couchmainpgconf")
sudo -u postgres psql --pset pager=off -X -A -t -c 'show client_min_messages' | grep -E "notice" || (sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set client_min_messages = '\''notice'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


grep -E '^\s*log_min_messages' "$couchmainpgconf" | tail -n 1 | grep -E "(warning|notice|info|debug)" || ( sed -i "s/^\s*log_min_messages/#log_min_messages/g" "$couchmainpgconf"; echo "log_min_messages = 'warning'" >> "$couchmainpgconf" )
sudo -u postgres psql --pset pager=off -X -A -t -c 'show log_min_messages' | grep -E "(warning|notice|info|debug)" || ( sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_min_messages = '\''warning'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


grep -E '^\s*log_min_error_statement' "$couchmainpgconf" | tail -n 1 | grep -E "(error.+error|warning|notice)" || ( sed -i "s/^\s*log_min_error_statement/#log_min_error_statement/g" "$couchmainpgconf"; echo "log_min_error_statement = 'error'" >> "$couchmainpgconf" )
sudo -u postgres psql --pset pager=off -X -A -t -c 'show log_min_error_statement' | grep -E "(error|warning|notice)" || ( sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_min_error_statement = '\''error'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()' )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_min_duration_statement = '\''-1'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E "^\s*log_min_duration_statement\s*=?\s*-1" "$couchmainpgconf" || ( sed -i "s/^\s*log_min_duration_statement/#log_min_duration_statement/g" "$couchmainpgconf"; echo "log_min_duration_statement = -1" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set debug_print_parse = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*debug_print_parse.*$/debug_print_parse = off/g" "$couchmainpgconf"
grep -E '^\s*debug_print_parse' "$couchmainpgconf" || echo "debug_print_parse = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set debug_print_rewritten = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*debug_print_rewritten.*$/debug_print_rewritten = off/g" "$couchmainpgconf"
grep -E '^\s*debug_print_rewritten' "$couchmainpgconf" || echo "debug_print_rewritten = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set debug_print_plan = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*debug_print_plan.*$/debug_print_plan = off/g" "$couchmainpgconf"
grep -E '^\s*debug_print_plan' "$couchmainpgconf" || echo "debug_print_plan = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set debug_pretty_print = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*debug_pretty_print.*$/debug_pretty_print = on/g" "$couchmainpgconf"
grep -E '^\s*debug_pretty_print' "$couchmainpgconf" || echo "debug_pretty_print = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_checkpoints = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_checkpoints.*$/log_checkpoints = on/g" "$couchmainpgconf"
grep -E '^\s*log_checkpoints' "$couchmainpgconf" || echo "log_checkpoints = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_connections = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_connections.*$/log_connections = on/g" "$couchmainpgconf"
grep -E '^\s*log_connections' "$couchmainpgconf" || echo "log_connections = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_disconnections = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_disconnections.*$/log_disconnections = on/g" "$couchmainpgconf"
grep -E '^\s*log_disconnections' "$couchmainpgconf" || echo "log_disconnections = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_duration = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_duration.*$/log_duration = on/g" "$couchmainpgconf"
grep -E '^\s*log_duration' "$couchmainpgconf" || echo "log_duration = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_error_verbosity = '\''verbose'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E -h '^\s*log_error_verbosity' "$couchmainpgconf" | tail -n 1 | grep -E "^\s*log_error_verbosity\s*=?\s*'?verbose'?" || ( sed -i "s/^\s*log_error_verbosity/#log_error_verbosity/g" "$couchmainpgconf"; echo "log_error_verbosity = 'verbose'" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_line_prefix = '\''%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E -h '^\s*log_line_prefix' "$couchmainpgconf" | tail -n 1 | grep -E "^\s*log_line_prefix\s*=?\s*'?%m\s*\[%p\]:\s*\[%l-1\]\s*db=%d,\s*user=%u,\s*app=%a,\s*client=%h'?" || ( sed -i "s/^\s*log_line_prefix/#log_line_prefix/g" "$couchmainpgconf"; echo "log_line_prefix = '%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h'" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_lock_waits = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_lock_waits.*$/log_lock_waits = on/g" "$couchmainpgconf"
grep -E '^\s*log_lock_waits' "$couchmainpgconf" || echo "log_lock_waits = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_statement = '\''ddl'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E -h '^\s*log_statement' "$couchmainpgconf" | tail -n 1 | grep -E "^\s*log_statement\s*=?\s*'?(ddl|mod|all)'?" || ( sed -i "s/^\s*log_statement\(\s\|=\)/#log_statement/g" "$couchmainpgconf"; echo "log_statement = 'ddl'" >> "$couchmainpgconf" )


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_temp_files = '\''0'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E -h '^\s*log_temp_files' "$couchmainpgconf" | tail -n 1 | grep -E "^\s*log_temp_files\s*=?\s*0" || ( sed -i "s/^\s*log_temp_files/#log_temp_files/g" "$couchmainpgconf"; echo "log_temp_files = 0" >> "$couchmainpgconf" )


echo "[Manual]" 'Execute the following SQL statement(s) to remediate this setting (use required GMT or UTC timezone or timezones permitted by organization'\''s policy): 
postgres=# alter system set log_timezone = '\''UTC'\''; 
ALTER SYSTEM 
postgres=# select pg_reload_conf(); 
pg_reload_conf 
---------------- 
t 
(1 row)'
read -n 1 -p "Press Enter to continue..."


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_parser_stats = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_parser_stats.*$/log_parser_stats = off/g" "$couchmainpgconf"
grep -E '^\s*log_parser_stats' "$couchmainpgconf" || echo "log_parser_stats = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_planner_stats = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_planner_stats.*$/log_planner_stats = off/g" "$couchmainpgconf"
grep -E '^\s*log_planner_stats' "$couchmainpgconf" || echo "log_planner_stats = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_executor_stats = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_executor_stats.*$/log_executor_stats = off/g" "$couchmainpgconf"
grep -E '^\s*log_executor_stats' "$couchmainpgconf" || echo "log_executor_stats = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_statement_stats = '\''off'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -i "s/^\s*log_statement_stats.*$/log_statement_stats = off/g" "$couchmainpgconf"
grep -E '^\s*log_statement_stats' "$couchmainpgconf" || echo "log_statement_stats = off" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set syslog_split_messages = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -ri 's/^(\s*syslog_split_messages(\s|=).*)$/syslog_split_messages = on   ## \1/' "$couchmainpgconf"
grep -E '^\s*syslog_split_messages\s' "$couchmainpgconf" || echo "syslog_split_messages = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set syslog_sequence_numbers = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -ri 's/^(\s*syslog_sequence_numbers(\s|=).*)$/syslog_sequence_numbers = on   ## \1/' "$couchmainpgconf"
grep -E '^\s*syslog_sequence_numbers\s' "$couchmainpgconf" || echo "syslog_sequence_numbers = on" >> "$couchmainpgconf"


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set log_replication_commands = '\''on'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
sed -ri 's/^(\s*log_replication_commands(\s|=).*)$/log_replication_commands = on   ## \1/' "$couchmainpgconf"
grep -E '^\s*log_replication_commands\s' "$couchmainpgconf" || echo "log_replication_commands = on" >> "$couchmainpgconf"


echo "[Manual]" 'For many systems pgaudit package is available in standard repositories and can be installed with package manager. Example:
# dnf -y install pgaudit16_14
[snip]
Installed:
pgaudit16_14-1.6.0-1.rhel8.x86_64
Complete! 
Aslo it can be cloned from the GitHub repository, then build the project in the appropriate directory. Example: 
$ cd /usr/pgsql-9.5/share/contrib/ 
$ git clone https://github.com/pgaudit/pgaudit.git 
$ cd ./pgaudit 
$ PATH=/usr/pgsql-9.5/bin:$PATH 
$ make USE_PGXS=1 install 
pgaudit is now built and ready to be configured.
Next we need to alter the postgresql.conf configuration file to enable pgaudit as an extension in the shared_preload_libraries parameter, indicate which classes of statements we want to log via the pgaudit.log parameter, and restart the PostgreSQL service: 
$ vi ${PGDATA}/postgresql.conf 
Find the shared_preload_libraries entry, and add '\''pgaudit'\'' to it (preserving any existing entries): 
shared_preload_libraries = '\''pgaudit'\'' 
OR 
shared_preload_libraries = '\''pgaudit,somethingelse'\'' 
Now, add a new pgaudit-specific entry (for this example we are logging the ddl and write operations):
pgaudit.log='\''ddl,write'\'' 
Restart the PostgreSQL server for changes to take affect: 
[root@localhost ~]# systemctl restart postgresql'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If any regular or application users have been granted excessive administrative rights, those privileges should be removed immediately via the PostgreSQL ALTER ROLE SQL command. Using the same example above, the following SQL statements revoke all unnecessary elevated administrative privileges from the regular user appuser: 
$ psql -c "ALTER ROLE appuser NOSUPERUSER;" 
ALTER ROLE 
$ psql -c "ALTER ROLE appuser NOCREATEROLE;" 
ALTER ROLE 
$ psql -c "ALTER ROLE appuser NOCREATEDB;" 
ALTER ROLE 
$ psql -c "ALTER ROLE appuser NOREPLICATION;" 
ALTER ROLE 
$ psql -c "ALTER ROLE appuser NOBYPASSRLS;" 
ALTER ROLE 
$ psql -c "ALTER ROLE appuser NOINHERIT;" 
ALTER ROLE 
Verify the appuser now passes your check by having no defined Attributes: 
$ psql -c "\du appuser" 
List of roles 
Role name | Attributes | Member of 
----------+------------+----------- 
appuser | | {}'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Where possible, revoke SECURITY DEFINER on PostgreSQL functions. To change a SECURITY DEFINER function to SECURITY INVOKER, run the following SQL: 
$ sudo su - postgres 
$ psql -c "ALTER FUNCTION [functionname] SECURITY INVOKER;" 
If it is not possible to revoke SECURITY DEFINER, ensure the function can be executed by only the accounts that absolutely need such functionality. Example: 
REVOKE EXECUTE ON FUNCTION delete_customer(integer,boolean) FROM appreader; 
REVOKE 
Confirm that the appreader user may no longer execute the function: 
SELECT proname, proacl FROM pg_proc WHERE proname = '\''delete_customer'\''; 
proname | proacl 
-----------------+-------------------------------------------------------- 
delete_customer | {=X/postgres,postgres=X/postgres,appwriter=X/postgres} 
(1 row) 
Based on output above, appreader=X/postgres no longer exists in the proacl column results returned from query and confirms appreader is no longer granted execute privilege on the function.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'If a given database user has been granted excessive DML privileges for a given database table, those privileges should be revoked immediately using the revoke SQL command. Continuing with the example from the audit section, remove unauthorized grants for appreader user using the revoke statement and verify the Boolean values are false. 
postgres=# REVOKE INSERT, UPDATE, DELETE ON TABLE customer FROM appreader; 
REVOKE 
postgres=# select t.tablename, u.usename, 
has_table_privilege(u.usename, t.schemaname || '\''.'\'' || t.tablename, '\''select'\'') as select, 
has_table_privilege(u.usename, t.schemaname || '\''.'\'' || t.tablename, '\''insert'\'') as insert, 
has_table_privilege(u.usename, t.schemaname || '\''.'\'' || t.tablename, '\''update'\'') as update, 
has_table_privilege(u.usename, t.schemaname || '\''.'\'' || t.tablename, '\''delete'\'') as delete 
from pg_tables t, pg_user u 
where t.tablename = '\''customer'\'' 
and u.usename in ('\''appwriter'\'','\''appreader'\''); 
tablename | usename | select | insert | update | delete 
----------+-----------+--------+--------+--------+-------- 
customer | appwriter | t | t | t | t 
customer | appreader | t | f | f | f 
(2 rows) 
With the publication of CVE-2018-1058, it is also recommended that all privileges be revoked from the public schema for all users on all databases: 
postgres=# REVOKE CREATE ON SCHEMA public FROM PUBLIC; 
REVOKE'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Again, we are using the example from the PostgreSQL documentation using the example passwd table. We will create three database roles to illustrate the workings of RLS: 
postgres=# CREATE ROLE admin; 
CREATE ROLE 
postgres=# CREATE ROLE bob; 
CREATE ROLE 
postgres=# CREATE ROLE alice; 
CREATE ROLE 
Now, we will insert known data into the passwd table: 
postgres=# INSERT INTO passwd VALUES 
('\''admin'\'','\''xxx'\'',0,0,'\''Admin'\'','\''111-222-3333'\'',null,'\''/root'\'','\''/bin/dash'\''); 
INSERT 0 1 
postgres=# INSERT INTO passwd VALUES 
('\''bob'\'','\''xxx'\'',1,1,'\''Bob'\'','\''123-456-7890'\'',null,'\''/home/bob'\'','\''/bin/zsh'\''); 
INSERT 0 1 
postgres=# INSERT INTO passwd VALUES 
('\''alice'\'','\''xxx'\'',2,1,'\''Alice'\'','\''098-765-4321'\'',null,'\''/home/alice'\'','\''/bin/zsh'\''); 
INSERT 0 1 
And we will enable RLS on the table: 
postgres=# ALTER TABLE passwd ENABLE ROW LEVEL SECURITY; 
ALTER TABLE 
Now that RLS is enabled, we need to define one or more policies. Create the administrator policy and allow it access to all rows: 
postgres=# CREATE POLICY admin_all ON passwd TO admin USING (true) WITH 
CHECK (true); 
CREATE POLICY 
Create a policy for normal users to view all rows: 
postgres=# CREATE POLICY all_view ON passwd FOR SELECT USING (true); 
CREATE POLICY 
Create a policy for normal users that allows them to update only their own rows and to limit what values can be set for their login shell: 
postgres=# CREATE POLICY user_mod ON passwd FOR UPDATE 
USING (current_user = user_name) 
WITH CHECK ( 
current_user = user_name AND 
shell IN ('\''/bin/bash'\'','\''/bin/sh'\'','\''/bin/dash'\'','\''/bin/zsh'\'','\''/bin/tcsh'\'') 
); 
CREATE POLICY 
Grant all the normal rights on the table to the admin user: 
postgres=# GRANT SELECT, INSERT, UPDATE, DELETE ON passwd TO admin; 
GRANT 
Grant only select access on non-sensitive columns to everyone: 
postgres=# GRANT SELECT 
(user_name, uid, gid, real_name, home_phone, extra_info, home_dir, shell) 
ON passwd TO public; 
GRANT 
Grant update to only the sensitive columns: 
postgres=# GRANT UPDATE 
(pwhash, real_name, home_phone, extra_info, shell) 
ON passwd TO public; 
GRANT 
You can now verify that '\''admin'\'', '\''bob'\'', and '\''alice'\'' are properly restricted by querying the passwd table as each of these roles.
Ensure that no one has been granted Bypass RLS inadvertantly, by running the psql display command \du+. If unauthorized users do have Bypass RLS granted then resolve this using the ALTER ROLE <user> NOBYPASSRLS; command.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'With the publication of CVE-2018-1058 it is recommended that CREATE privileges be revoked from the PUBLIC role in public and other schemas of all databases: 
postgres=# REVOKE CREATE ON SCHEMA public FROM PUBLIC; 
REVOKE'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Creation of a database account that matches the local account allows PEER authentication: 
$ psql -c "create role user1 with login password '\''mypassword'\'';" 
CREATE ROLE 
Execute the following as the UNIX user account, the default authentication rules should now permit the login: 
$ su - user1 
$ psql postgres 
psql (x.x.x) 
Type "help" for help. 
postgres=# 
As per the host-based authentication rules in $PGDATA/pg_hba.conf, all login attempts via UNIX DOMAIN SOCKETS are processed on the line beginning with local. 
This is the minimal rule that must be in place allowing PEER connections: 
# TYPE DATABASE USER ADDRESS METHOD 
local all postgres peer 
More traditionally, a rule like the following would be used to allow any local PEER connection: 
# TYPE DATABASE USER ADDRESS METHOD 
local all all peer 
Once edited, the server process must reload the authentication file before it can take effect. 
Improperly configured rules cannot update i.e. the old rules remain in place. The Postgres logs will report the outcome of the SIGHUP: 
[root@localhost ~]# /etc/init.d/postgresql reload
The following examples illustrate other possible configurations. The resultant "rule" of success/failure depends upon the first matching line: 
# allow postgres user logins 
# TYPE DATABASE USER ADDRESS METHOD 
local all postgres peer 
# allow all local users 
# TYPE DATABASE USER ADDRESS METHOD 
local all all peer 
# allow all local users only if they are connecting to a db named the same as their username 
# TYPE DATABASE USER METHOD 
local samerole all peer 
# allow only local users who are members of the '\''rw'\'' role in the db 
# TYPE DATABASE USER ADDRESS METHOD 
local all +rw peer'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure the pg_hba.conf file as needed with next security restrictions:
- METHOD ident must not be used for remote logins;
- METHODs password and trust must not be used at all;
- METHOD md5 must not be used when scram-sha-256 is available (in versions 10 and higher);
- No-SSL/TLS connections (host, hostnossl) must not be used for remote logins.

Confirm a login attempt has been made by looking for a logged error message detailing the nature of the authenticating failure. In the case of failed login attempts, whether encrypted or unencrypted, check the following: 
• The server should be sitting on a port exposed to the remote connecting host i.e. NOT ip address 127.0.0.1 
listen_addresses = '\''*'\'' 
• An authenticating rule must exist in the file pg_hba.conf 
This example permits only encrypted sessions for the postgres role and denies all unencrypted session for the postgres role: 
# TYPE DATABASE USER ADDRESS METHOD 
hostssl all postgres 0.0.0.0/0 scram-sha-256 # or "hostssl all postgres 0.0.0.0/0 md5" for versions 9.5 and 9.6
hostnossl all postgres 0.0.0.0/0 reject 
The following examples illustrate other possible configurations. The resultant "rule" of success/failure depends upon the first matching line. 
# allow `postgres` user only from '\''localhost/loopback'\'' connections and only if you know the password
# TYPE DATABASE USER ADDRESS METHOD 
host all postgres 127.0.0.1/32 scram-sha-256 # or "host all postgres 127.0.0.1/32 0.0.0.0/0 md5" for versions 9.5 and 9.6

# allow users to connect remotely only to the database named after them,
# with the correct user password:
# TYPE DATABASE USER ADDRESS METHOD 
hostssl samerole all 0.0.0.0/0 scram-sha-256 # or "hostssl samerole all 0.0.0.0/0 md5" for versions 9.5 and 9.6

# allow only those users who are a member of the '\''rw'\'' role to connect
# only to the database named after them, with the correct user password:
# TYPE DATABASE USER ADDRESS METHOD 
hostssl samerole +rw 0.0.0.0/0 scram-sha-256 # or "hostssl samerole +rw 0.0.0.0/0 md5" for versions 9.5 and 9.6'
read -n 1 -p "Press Enter to continue..."


grep -E -h "^\s*tcp_keepalives_idle(\s|=)" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*tcp_keepalives_idle\s*=?\s*10" || ( sed -i "s/^\s*tcp_keepalives_idle/#tcp_keepalives_idle/g" "$couchmainpgconf"; echo "tcp_keepalives_idle = 10" >> "$couchmainpgconf" )
grep -E -h "^\s*tcp_keepalives_interval(\s|=)" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*tcp_keepalives_interval\s*=?\s*10" || ( sed -i "s/^\s*tcp_keepalives_interval/#tcp_keepalives_interval/g" "$couchmainpgconf"; echo "tcp_keepalives_interval = 10" >> "$couchmainpgconf" )
grep -E -h "^\s*tcp_keepalives_count(\s|=)" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*tcp_keepalives_count\s*=?\s*10" || ( sed -i "s/^\s*tcp_keepalives_count/#tcp_keepalives_count/g" "$couchmainpgconf"; echo "tcp_keepalives_count = 10" >> "$couchmainpgconf" )
grep -E -h "^\s*statement_timeout(\s|=)" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*statement_timeout\s*=?\s*10000" || ( sed -i "s/^\s*statement_timeout/#statement_timeout/g" "$couchmainpgconf"; echo "statement_timeout = 10000" >> "$couchmainpgconf" )


grep -E -h "^\s*max_connections\s*=?\s*" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*max_connections\s*=?\s*([1-9][0-9]|100)\s*$" || ( sed -i "s/^\s*max_connections/#max_connections/g" "$couchmainpgconf"; echo "max_connections = 30" >> "$couchmainpgconf" )
sudo -u postgres psql --pset pager=off -X -A -t -c 'update pg_authid set rolconnlimit=30 where rolcanlogin and rolconnlimit < 1;'
sudo -u postgres psql --pset pager=off -X -A -t -c 'update pg_authid set rolconnlimit=30 where rolcanlogin and rolconnlimit > 100;'


cd "$couchpgdatadir"
sed -ri "s/^\s*(ssl(\s|=).*)$/ssl = on  ## \1/g" "$couchmainpgconf"
grep -E "^\s*ssl(\s|=)" "$couchmainpgconf" || echo "ssl = on" >> "$couchmainpgconf"
couchpguser=$(ps --no-headers o user:32,args p $(pidof postgres postmaster) | grep "[[:space:]]$couchpgdatadir" | head -n 1 | cut -f1 -d" "); 
couchpggroup=$(id -gn "$couchpguser");
if [[ -z $(grep -E "^\s*ssl_cert_file\s*=\s*\S" "$couchmainpgconf" "$couchpgautoconf" 2>/dev/null) ]]; then \
  read -p "Do you want to autoinstall self-signed certificate?[yes][NO]" selfsigned;
  if [[ "$selfsigned" =~ [yY][eE]?[sS]? ]]; then 
    openssl req -new -text -out server.req; 
    openssl rsa -in privkey.pem -out server.key && rm -f privkey.pem; 
    openssl req -x509 -in server.req -text -key server.key -out server.crt; 
    chmod og-rwx server.key; 
    chown -R ${couchpguser}:${couchpggroup} server.key server.crt; 
    echo "ssl_cert_file = 'server.crt'" >> "$couchmainpgconf"; 
    echo "ssl_key_file = 'server.key'" >> "$couchmainpgconf";
  else \
    read -p "Enter certificate file path and name:" cert_file; 
    echo "ssl_cert_file = '"$cert_file"'" >> "$couchmainpgconf";
    read -p "Enter server key file path and name:" key_file; 
    echo "ssl_key_file = '"$key_file"'" >> "$couchmainpgconf";
  fi;
fi


sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set ssl_ciphers = '\''HIGH:MEDIUM:+3DES:!aNULL'\'''
sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'
grep -E -h "^\s*ssl_ciphers\s*=?\s*" "$couchmainpgconf" | tail -n 1 | grep -E "^\s*ssl_ciphers\s*=?\s*'?HIGH:MEDIUM:\+3DES:!aNULL'?" || ( sed -i "s/^\s*ssl_ciphers/#ssl_ciphers/g" "$couchmainpgconf"; echo "ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'" >> "$couchmainpgconf" )


psql -V | grep -E "^\S+\s+9\.[56](\.|\s)" && (sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set password_encryption = '\''on'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'; sed -i "s/^\s*password_encryption.*$/password_encryption = on/g" "$couchmainpgconf"; grep -E '^\s*password_encryption' "$couchmainpgconf" || echo "password_encryption = on" >> "$couchmainpgconf")
psql -V | grep -E "^\S+\s+1[0-9]\." && (sudo -u postgres psql --pset pager=off -X -A -t -c 'alter system set password_encryption = '\''scram-sha-256'\'''; sudo -u postgres psql --pset pager=off -X -A -t -c 'select pg_reload_conf()'; sed -i "s/^\s*password_encryption.*$/password_encryption = scram-sha-256/g" "$couchmainpgconf"; grep -E '^\s*password_encryption' "$couchmainpgconf" || echo "password_encryption = scram-sha-256" >> "$couchmainpgconf")


if [[ -n $(grep -E -i "(centos|rhel|oel|Oracle Linux Server)" /etc/*-release) ]]; then \
  if [[ -z $(grep -E "^1$" /proc/sys/crypto/fips_enabled) ]]; then \
    which fips-mode-setup && fips-mode-setup --enable;
  fi;
else echo "This system doesn't have available FIPS 140-2 packages or they are additional commercial option"; read -p "Next" a;
fi


if [[ -z $(sudo -u postgres psql --pset pager=off -X -A -t -c 'SELECT * FROM pg_available_extensions where name='\''pgcrypto'\''' | grep ^pgcrypto) ]]; then cmd=$(which postgres); if [ -z "$cmd" ]; then cmd=$(ps o args $(pidof postmaster postgres) | egrep "(postmaster|postgres)(\s|$)" | head -n 1 | cut -d" " -f1); fi; if [ ! -z "$cmd" ]; then couch_pg_version=$($cmd -V | grep -oP "\s(\d+)\." | sed -e 's/^\s//' -e 's/\.//'); yum -y install postgresql${couch_pg_version}-contrib || apt-get -y install postgresql${couch_pg_version}-contrib; fi; fi
sudo -u postgres psql --pset pager=off -X -A -t -c 'CREATE EXTENSION pgcrypto;'


echo "[Manual]" 'Secure network protocols with encryption protection must be used for WAL. Change parameters and restart the server as required. 
Note: SSH public keys must be generated and installed as per industry standard.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'It will be necessary to create a new role for replication purposes:
postgres=# create user replication_user REPLICATION encrypted password '\''<put password here>'\'';
CREATE ROLE
postgres=# select rolname from pg_roles where rolreplication is true;
rolname
------------------
postgres
replication_user
(2 rows)
When using pg_basebackup (or other replication tools) and when configuring recovery.conf on your standby server, you would use the replication_user (and its password).
Ensure you allow the new user via your pg_hba.conf file:
# note that '\''replication'\'' in the 2nd column is required and is a special
# keyword, not a real database
hostssl replication replication_user 0.0.0.0/0 scram-sha-256
# or md5 method for PostgreSQL 9.5 and 9.6'
read -n 1 -p "Press Enter to continue..."



