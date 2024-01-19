#!/usr/bin/env bash

read -p "Enter Apache Cassandra login: " COUCH_APP_LOGIN;
stty -echo;
read -p "Enter Apache Cassandra password: " COUCH_APP_PASSWORD;
echo;
stty echo;

cassandra_pid=$(ps --no-headers -o pid,args $(pidof java) 4 | grep -Ei '\sorg\.apache\.cassandra\.service\.CassandraDaemon' | xargs | cut -f1 -d' ')

start_script=$(cmd=$(which cassandra 2>/dev/null); if [ -z "$cmd" ]; then casn_dir=$(readlink -e /proc/$cassandra_pid/cwd); cmd=$(find "$casn_dir" -type f -name cassandra -perm -0100 | head -n 1); fi; echo "$cmd")

config_dir=$(casn_user=$(awk '/^Uid:/{print $2}' /proc/$cassandra_pid/status | xargs -I {} getent passwd {} | cut -f1 -d:); readlink -e $(grep -Eh '^\s*CASSANDRA_CONF=' "$(dirname "$start_script")/cassandra.in.sh" "$(getent passwd "$casn_user" | cut -d: -f6)/.cassandra.in.sh" /usr/share/cassandra/cassandra.in.sh /usr/local/share/cassandra/cassandra.in.sh /opt/cassandra/cassandra.in.sh 2>/dev/null | tail -n 1 | sed -r 's/\s*#.*$//' | sed -r "s;^\s*CASSANDRA_CONF=([^\"']\S*|\"[^\"]*\"|'[^']*')\s*$;\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" | sed -r "s#\\\$\{?CASSANDRA_HOME\}?#$(dirname "$start_script")/..#"))

main_config=$(conf_file=$(ps --no-headers -o pid,args $cassandra_pid | grep -E '\s-Dcassandra\.config=file:' | sed -r "s;^.*\s-Dcassandra\.config=file://([^\"']\S*|\"[^\"]*\"|'[^']*')(\s.*$|$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); if [ -n "$conf_file" ]; then readlink -f "$conf_file"; else echo "$config_dir/cassandra.yaml"; fi)

cassandra_ip=$(casn_rpc_ip=$(grep '^rpc_address:' "$main_config" | xargs | cut -f2 -d' '); if [ -z "$casn_rpc_ip" ]; then casn_prc_int=$(grep '^rpc_interface:' "$main_config" | xargs | cut -f2 -d' '); [ -n "$casn_prc_int" ] && casn_rpc_ip=$(ip -o -br address show "$casn_prc_int" | awk -F'[/ \t]+' '{print $3}'); fi; if [ -z "$casn_rpc_ip" ]; then casn_rpc_ip=$(hostname -i); fi; echo $casn_rpc_ip)

cassandra_port=$(casn_rpc_port=$(grep '^native_transport_port:' "$main_config" | xargs | cut -f2 -d' '); [ -z "$casn_rpc_port" ] && casn_rpc_port=9042; echo $casn_rpc_port)

cassandra_ssl=$(sed -n '/^client_encryption_options:/,/^\S/p' "$main_config" | grep -Eiq '^\s+enabled\s*:\s*(on|y|yes|true)(\s|$)' && printf '%s' '--ssl')

if [[ -z $(SSL_VALIDATE=false cqlsh "$cassandra_ip" "$cassandra_port" "$cassandra_ssl" --no-color -u "$COUCH_APP_LOGIN" -p "$COUCH_APP_PASSWORD" -e 'select system.blobasascii(0x746573745F706173735F737472696E67) from system.local limit 1;' 2>&1 | grep -i "test_pass_string") ]];
then echo "Incorrect credentials, please try again.";
	exit;
fi;


echo "[Manual]" 'If upgrade of the Cassandra software is needed:
For each node in the cluster:
1. Use the nodetool drain command to push all memtables data to SSTables.
2. Stop Cassandra services.
3. Backup the data set and all of your Cassandra configuration files.
4. Download/Update Java if needed.
5. Download/Update Python if needed.
6. Download the binaries for the latest Cassandra revision from the Cassandra Download Page.
7. Install new version of Cassandra.
8. Configure new version of Cassandra, taking into account all of your previous settings in your config files(cassandra.yml, cassandrea-env.sh, etc).
9. Start Cassandra services.
10. Check logs for warnings, errors.
11. Using the nodetool to upgrade your SSTables.
12. Using the nodetool command to check status of cluster.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Create a user which is only used for running Cassandra and directly related processes. This user must not have administrative rights on the system. Configure Cassandra to run with this user rights.'
read -n 1 -p "Press Enter to continue..."


casn_user=$(ps --no-headers -o user:32,args $cassandra_pid | cut -f1 -d' '); [ -n "$casn_user" ] && passwd -l "$casn_user"


casn_user=$(ps --no-headers -o user:32,args $cassandra_pid | cut -f1 -d' '); [ -n "$casn_user" ] && usermod -s "$(which nologin)" "$casn_user"


echo "[Manual]" 'Set the listen_address or listen_interface, not both, in the cassandra.yaml to an
authorized address or interface.

Default:
listen_address: localhost'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure NTP, chrony or systemd-timesyncd for time synchronizaton. Examples: 
# apt-get install ntp
# systemctl enable ntp
# systemctl start ntp
OR
# apt-get install chrony
# systemctl enable chrony
# systemctl start chrony'
read -n 1 -p "Press Enter to continue..."


valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"; awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do find "$home" -xdev \( -name 'cqlsh_history' -o -name 'cql_history' \) -print 2>/dev/null | xargs -d $'\n' sh -c 'for arg do rm -f "$arg"; ln -s /dev/null "$arg"; done' _; done)


echo "[Manual]" 'Review users cqlshrc files and remove stored credentials from them if there are any.'
read -n 1 -p "Press Enter to continue..."


chmod go-w "$start_script"
chown root:root "$start_script"


chmod go-w "$(dirname "$start_script")/cassandra.in.sh" "$config_dir/cassandra.in.sh" /usr/share/cassandra/cassandra.in.sh /usr/local/share/cassandra/cassandra.in.sh /opt/cassandra/cassandra.in.sh 2>/dev/null; 
cut -f6 -d: /etc/passwd | while read -r home; do chmod go-w "$home/.cassandra.in.sh" 2>/dev/null; done


chmod go-w "$main_config"
chown root:root "$main_config"


find -L "$config_dir" -perm /0022 | xargs -d$'\n' -I {} chmod go-w '{}'
chown -R root:root "$config_dir"


valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"; awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | (while read -r user home; do find "$home" -xdev -type f -name 'cqlshrc' -print 2>/dev/null | xargs -d$'\n' -I {} chmod go-rwx "{}"; done)


casn_user=$(ps --no-headers -o user:32, $cassandra_pid | cut -f1 -d' ');
jmx_pass_file=$(ps --no-headers -o pid,args $cassandra_pid | grep -E '\s-Dcom\.sun\.management\.jmxremote\.password\.file=' | sed -r "s;^.*\s-Dcom\.sun\.management\.jmxremote\.password\.file=([^\"']\S*|\"[^\"]*\"|'[^']*')(\s.*$|$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
if [ -e "$jmx_pass_file" ]; then chmod o-wx,go-rwx "$jmx_pass_file"; [ -n "$casn_user" ] && chown "$casn_user" "$jmx_pass_file"; fi;


jmx_rights_file=$(ps --no-headers -o pid,args $cassandra_pid | grep -E '\s-Dcom\.sun\.management\.jmxremote\.access\.file=' | sed -r "s;^.*\s-Dcom\.sun\.management\.jmxremote\.access\.file=([^\"']\S*|\"[^\"]*\"|'[^']*')(\s.*$|$);\1;" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"); 
[ -n "$jmx_rights_file" ] && chmod go-w "$jmx_rights_file"; 
[ -n "$JAVA_HOME" ] && chmod go-w "$JAVA_HOME/lib/management/jmxremote.access"; 
[ -n "$JAVA_HOME" ] && chmod go-w "$JAVA_HOME/jre/lib/management/jmxremote.access"


echo "[Manual]" 'To enable the authentication mechanism:
1. Stop the Cassandra database.
2. Modify cassandra.yaml file to modify/add entry for authenticator: set it to '\''PasswordAuthenticator'\''.
3. Start the Cassandra database.

Default:
authenticator: AllowAllAuthenticator'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable the authorization mechanism:
1. Stop the Cassandra database.
2. Modify cassandra.yaml file to modify/add entry for authorizer: set it to CassandraAuthorizer
3. Start the Cassandra database.

Default:
authorizer: AllowAllAuthorizer'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Note! Before revoking privileges ensure that there is at least one other user with superuser role assigned. To verify:
SELECT role,is_superuser,can_login FROM system_auth.roles WHERE is_superuser = True and can_login = True ALLOW FILTERING;
New login with superuser role can be created with the following statements:
create role '\''<NEW_ROLE_HERE>'\'' with password='\''<NEW_PASSWORD_HERE>'\'' and login=TRUE and superuser=TRUE ;
grant all permissions on all keyspaces to <NEW_ROLE_HERE>;
Remove the superuser role from the cassandra account by executing the following command:
ALTER ROLE cassandra WITH SUPERUSER = false;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Note! Before revoking login rights from default account ensure that there is at least one other account with login right and neccessary privileges. To verify:
SELECT role,is_superuser,can_login FROM system_auth.roles WHERE is_superuser = True and can_login = True ALLOW FILTERING;
New login with superuser role can be created with the following statements:
create role '\''<NEW_ROLE_HERE>'\'' with password='\''<NEW_PASSWORD_HERE>'\'' and login=TRUE and superuser=TRUE ;
grant all permissions on all keyspaces to <NEW_ROLE_HERE>;
Deny login access for default cassandra role by executing the following command:
ALTER ROLE cassandra WITH LOGIN = false;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Change the password for the casssandra role by issuing the following command:
alter role '\''cassandra'\'' with password '\''<NEWPASSWORD_HERE>'\'';
Where <NEWPASSWORD_HERE> is replaced with the password of your choosing.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Audit roles options and granted roles:
select role, can_login, is_superuser, member_of from system_auth.roles ALLOW FILTERING;
If there are some excessive privileges revoke them. To revoke SUPERUSER use the following command:
ALTER ROLE <role_name> WITH SUPERUSER = false;
To revoke LOGIN right use the following command:
ALTER ROLE <role_name> WITH LOGIN = false;
To revoke excessive granted roles use the following command:
REVOKE <excessive_granted_role_name> FROM <role_name>;
If some roles are redundant, drop them:
DROP ROLE <role_name>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Audit all permissions for all roles:
select * from system_auth.role_permissions;
If there are some excessive permissions revoke them with REVOKE PERMISSION statement. Examples:
REVOKE SELECT ON ALL KEYSPACES FROM data_reader;
REVOKE MODIFY ON KEYSPACE keyspace1 FROM data_writer;
REVOKE DROP ON keyspace1.table1 FROM schema_owner;
REVOKE EXECUTE ON FUNCTION keyspace1.user_function( int ) FROM report_writer;
REVOKE DESCRIBE ON ALL ROLES FROM role_admin;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable the network authorization mechanism:
1. Stop the Cassandra database.
2. Modify cassandra.yaml file to modify/add entry for network_authorizer: set it to CassandraNetworkAuthorizer
3. Start the Cassandra database.
4. Grant neccessary access permissions. Example:
ALTER ROLE test WITH ACCEESS TO DATACENTERS {'\''datacenter1'\''};

Default:
network_authorizer: AllowAllNetworkAuthorizer'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting:
1. Edit the logback-test.xml if present; otherwise, edit the logback.xml. Example:
<configuration scan="true">
<appender name="STDOUT"
class="ch.qos.logback.core.ConsoleAppender">
<filter class="ch.qos.logback.classic.filter.ThresholdFilter">
<level>INFO</level>
</filter>
<encoder>
<pattern>%-5level [%thread] %date{ISO8601} %F:%L -
%msg%n</pattern>
</encoder>
</appender>
<root level="INFO">
<appender-ref ref="STDOUT" />
</root>
<logger name="org.cisecurity.workbench" level="WARN"/>
</configuration>
2. Restart the Apache Cassandra'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable the inter-node encryption mechanism:
1. Stop the Cassandra database.
2. If not done so already, build out your keystore and truststore. (To create local keystore and truststore with local CA procedures described at https://docs.datastax.com/eol/en/security/6.7/security/secSetUpSSLCert.html may be used.)
3. Modify cassandra.yaml file to modify/add entry for '\''internode_encryption'\'', set it to all, rack or dc as needed.
4. Start the Cassandra database.

Default:
internode_encryption: none'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable the client encryption mechanism:
1. Stop the Cassandra database.
2. If not done so already, build out your keystore and truststore. (To create local keystore and truststore with local CA procedures described at https://docs.datastax.com/eol/en/security/6.7/security/secSetUpSSLCert.html may be used.)
3. Modify cassandra.yaml file to modify/add entries under client_encryption_options:
set enabled: true
set optional: false
This will force all connections to be encrypted between client and node on the cluster.
4. Start the Cassandra database.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that client cqlshrc file contain settings for SSL connection and server certificate validation.
Example settings:
[connection]
hostname = 127.0.0.1
port = 9042
factory = cqlshlib.ssl.ssl_transport_factory
[ssl]
certfile = ~/.cassandra/rootCA.crt
;; Optional, true by default
validate = true
There may be additional settings in the cqlshrc file. This may include settings for client certificate verification (see examples at https://docs.datastax.com/eol/en/security/6.7/security/Auth/secCqlshSsl.html).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Configure mandatory use of SSL on the client side in the cqlshrc files with the following parameter:
[connection]
ssl = true

Default: false.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To configure JMX authentication:
1. Edit $CASSANDRA_CONF/cassandra-env.sh to add or update these lines:
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=true"
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.password.file=/etc/cassandra/jmxremote.password"
2. Create /etc/cassandra/jmxremote.password and add neccessary users and passwords. Example:
monitor SomePassw0rd
admin 0therPassword
3. Change ownership of the jmxremote.password file to the Cassandra process user with permission to read only. Example:
chown cassandra:cassandra /etc/cassandra/jmxremote.password
chmod 400 /etc/cassandra/jmxremote.password
4. Optionally, enable access control to limit the scope of what defined users can do via JMX. Note that most operational tools in Cassandra require full read/write access. To configure a simple access file, uncomment this line in cassandra-env.sh:
#JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.access.file=/etc/cassandra/jmxremote.access"
Then edit the access file to grant your JMX users needed permission, example:
monitor readonly
admin readwrite
Another option is to edit the $JAVA_HOME/lib/management/jmxremote.access file (if you are using the JDK this file is under $JAVA_HOME/jre/lib/management/jmxremote.access) and add lines for needed permissions. 
5. Restart the Cassandra database.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To enable SSL for JMX edit $CASSANDRA_CONF/cassandra-env.sh to update or add these lines:
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.ssl=true"
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.registry.ssl=true"
JVM_OPTS="$JVM_OPTS -Djavax.net.ssl.keyStore=path_to_keystore.jks"
JVM_OPTS="$JVM_OPTS -Djavax.net.ssl.keyStorePassword=keystore-password"
JVM_OPTS="$JVM_OPTS -Djavax.net.ssl.trustStore=path_to_truststore.jks"
JVM_OPTS="$JVM_OPTS -Djavax.net.ssl.trustStorePassword=truststore-password"
You must specify the path to appropriate keystore and truststore, including passwords for each.'
read -n 1 -p "Press Enter to continue..."



