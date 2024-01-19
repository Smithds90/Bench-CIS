#!/usr/bin/env bash

read -p "Enter Oracle DBMS login: " COUCH_APP_LOGIN;
stty -echo;
read -p "Enter Oracle DBMS password: " COUCH_APP_PASSWORD;
echo;
stty echo;

export ORACLE_HOME="__or_home__";
couch_pass_check=false;
for db in $(echo "__or_dbs__");
  do export ORACLE_SID="$db";
  [[ -n $(echo "set heading off" $'\n' 'SELECT '\''test_pass_string'\'' FROM DUAL;' | "$ORACLE_HOME"/bin/sqlplus -s -l "$COUCH_APP_LOGIN"/"$COUCH_APP_PASSWORD" | grep -i "test_pass_string") ]] && couch_pass_check=true;
done;

if [[ "$couch_pass_check" == "false" ]];
   then echo "Incorrect credentials, please try again.";
   exit;
fi;


echo "[Manual]" 'Download and apply the latest quarterly Critical Patch Update patches.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this recommendation, you may perform either of the following actions.
- Manually issue the following SQL statement for each USERNAME returned in the 
Audit Procedure:
PASSWORD <username>
- Execute the following SQL script to randomly assign passwords:
begin
for r_user in
(select username from dba_users_with_defpwd where username not like '\''%XS$NULL%'\'')
loop
DBMS_OUTPUT.PUT_LINE('\''Password for user '\''||r_user.username||'\'' will be changed.'\'');
execute immediate '\''alter user "'\''||r_user.username||'\''" identified by
"'\''||DBMS_RANDOM.string('\''a'\'',16)||'\''"account lock password expire'\'';
end loop;
end;
/'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting, it is recommended that you execute the following SQL script.
$ORACLE_HOME/demo/schema/drop_sch.sql
NOTE: The recyclebin is not set to OFF within the default drop script, which means that 
the data will still be present in your environment until the recyclebin is emptied.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Set correct permissions to Oracle files and folders: 
1. Set the permissions on $ORACLE_HOME and $ORACLE_HOME/bin to 0751 or less. Set all other directories in $ORACLE_HOME to 0750 or less. Note, this limits access to the Oracle user and its group (probably DBA).
2. Set file permissions for listener.ora and sqlnet.ora to 0600.
chmod 0600 $ORACLE_HOME/network/admin/listener.ora
chmod 0600 $ORACLE_HOME/network/admin/sqlnet.ora
3. Set file permissions for tnsnames.ora to 0644.
chmod 0644 $ORACLE_HOME/network/admin/tnsnames.ora
4. Set file permissions for snmp*.ora to 0660 or stricter.
chmod o-rwx $ORACLE_HOME/network/admin/snmp*.ora'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting, execute the following SQL statement:
DROP PUBLIC DATABASE LINK <DB_LINK>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Restrict ownership and permissions on the Oracle password files to only the DBMS software installation/owner account.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Set the SECURE_CONTROL_<listener_name> for each defined listener in the listener.ora
file, according to the needs of the organization.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remove extproc from the listener.ora file.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Use a text editor such as vi to set the ADMIN_RESTRICTIONS_<listener_name> to the value ON.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Use a text editor such as vi to set the SECURE_REGISTER_<listener_name>=TCPS or SECURE_REGISTER_<listener_name>=IPC for each listener found in $ORACLE_HOME/network/admin/listener.ora.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Disable the listener password to avoid remote administration on listerner version 10g and higher.
Listener version 10.x and higher must not have a password. If it has, the listener will accept connections from any node of the network.
Edit file $ORACLE_HOME\network\admin\listener.ora and remove the entry PASSWORDS_<listener names>=PASSWORD or configure the NET Manager to not require password.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET AUDIT_SYS_OPERATIONS = TRUE SCOPE=SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting, execute one of the following SQL statements and restart the instance:
ALTER SYSTEM SET AUDIT_TRAIL = DB, EXTENDED SCOPE = SPFILE;
ALTER SYSTEM SET AUDIT_TRAIL = OS SCOPE = SPFILE;
ALTER SYSTEM SET AUDIT_TRAIL = XML, EXTENDED SCOPE = SPFILE;
ALTER SYSTEM SET AUDIT_TRAIL = DB SCOPE = SPFILE;
ALTER SYSTEM SET AUDIT_TRAIL = XML SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET GLOBAL_NAMES = TRUE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Versions 12.1 and higher are not affected by TNS Listener Poison vulnerability and no special configuration is needed.
In older versions there are some different methods to prevent TNS Listener Poison attack. For every configured listener:
1) Disable DYNAMIC_REGISTRATION in listener.ora if it is not needed (i.e. Oracle DataGuard, RAC or the PL/SQL Gateway in connection with APEX are not used). Use next directive:
DYNAMIC_REGISTRATION_listener_name=off
OR
2) If DYNAMIC_REGISTRATION can not be disabled in 11.2.0.4 use VALID_NODE_CHECKING_REGISTRATION parameter:
VALID_NODE_CHECKING_REGISTRATION_<listener_name>=LOCAL
Trusted for registration nodes can be configured with parameter REGISTRATION_INVITED_NODES_<listener name>
OR
3) If DYNAMIC_REGISTRATION can not be disabled in 11.2.0.3 and older configure SECURE_REGISTER options. If TCP protocol is used install patch 12880299 and configure SECURE_REGISTER for TCP. If IPC is used configure SECURE_REGISTER for IPC and specify unique key for IPC service in the listener configuration.
OR
4) Configure SQLNET.ENCRYPTION_SERVER parameter in sqlnet.ora to REQUIRED as follows:
SQLNET.ENCRYPTION_SERVER=REQUIRED'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'For Oracle Database versions up to 12.1 (including) to remediate this setting execute the following SQL statement:
ALTER SYSTEM SET O7_DICTIONARY_ACCESSIBILITY=FALSE SCOPE = SPFILE;
In newer versions the O7_dictionary_accessibility parameter is deprecated and nothing action is needed.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET OS_ROLES = FALSE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET REMOTE_LISTENER = '\'''\'' SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Disable use of the remote_login_passwordfile where remote administration is not necessary and authorized by specifying a value of NONE:
ALTER SYSTEM SET REMOTE_LOGIN_PASSWORDFILE = '\''NONE'\'' SCOPE = SPFILE;
In case of using OEM or DR/Data Guard, the EXCLUSIVE is required setting and can be added as an allowable and compliant VALUE.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In Oracle Database versions 12.1 and higher the REMOTE_OS_AUTHENT parameter is deprecated and no action is required.
In older versions to remediate this setting execute the following SQL statement:
ALTER SYSTEM SET REMOTE_OS_AUTHENT = FALSE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET REMOTE_OS_ROLES = FALSE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In Oracle Database versions 12.2 and higher the REMOTE_OS_AUTHENT parameter is deprecated and no action is required.
In older versions to remediate this setting execute the following SQL statement:
ALTER SYSTEM SET UTL_FILE_DIR = '\'''\'' SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'In Oracle Database versions 12.1 and higher the REMOTE_OS_AUTHENT parameter is deprecated and no action is required.
In older versions to remediate this setting execute the following SQL statement:
ALTER SYSTEM SET SEC_CASE_SENSITIVE_LOGON = TRUE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement. Configure to 5 or less
ALTER SYSTEM SET SEC_MAX_FAILED_LOGIN_ATTEMPTS = 5 SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute one of the following SQL statements.
ALTER SYSTEM SET SEC_PROTOCOL_ERROR_FURTHER_ACTION = '\''(DROP,3)'\'' SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET SEC_PROTOCOL_ERROR_TRACE_ACTION=LOG SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET SEC_RETURN_SERVER_RELEASE_BANNER = FALSE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET SQL92_SECURITY = TRUE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET "_trace_files_public" = FALSE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER SYSTEM SET RESOURCE_LIMIT = TRUE SCOPE = SPFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure:
ALTER PROFILE <profile_name> LIMIT FAILED_LOGIN_ATTEMPTS 5;

Warning! One concern is the possibility of this setting being exploited to craft a DDoS attack by using the row-locking delay between failed login attempts (see Oracle Bug 7715339 – Logon failures causes “row cache lock” waits – Allow disable of logon delay [ID 7715339.8], so the configuration of this setting depends on using the bug workaround).'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure (1/12 or more days are acceptable):
ALTER PROFILE <profile_name> LIMIT PASSWORD_LOCK_TIME 1/12;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure (set to 85 or less):
ALTER PROFILE <profile_name> LIMIT PASSWORD_LIFE_TIME 85;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure (set to 5 or more):
ALTER PROFILE <profile_name> LIMIT PASSWORD_REUSE_MAX 5;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure (set to 365 or more):
ALTER PROFILE <profile_name> LIMIT PASSWORD_REUSE_TIME 365;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Remediate this setting by executing the following SQL statement for each PROFILE returned by the audit procedure (set to 5 or less):
ALTER PROFILE <profile_name> LIMIT PASSWORD_GRACE_TIME 5;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
ALTER USER <username> IDENTIFIED BY <password>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Create a custom password verification function which fulfills the password requirements of the organization.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting, execute the following SQL statement for each PROFILE returned by the audit procedure (set to 10 or less):
ALTER PROFILE <profile_name> LIMIT SESSIONS_PER_USER 10;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this recommendation execute the following SQL statement for each user 
returned by the audit query using a functional-appropriate profile.
ALTER USER <username> PROFILE <appropriate_profile>'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting, execute the following SQL statement for each PROFILE returned by the audit procedure:
ALTER PROFILE <profile_name> LIMIT INACTIVE_ACCOUNT_TIME 120;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_ADVISOR FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_CRYPTO FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_JAVA FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_JAVA_TEST FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_JOB FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_LDAP FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_LOB FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_OBFUSCATION_TOOLKIT FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_RANDOM FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_SCHEDULER FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_SQL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_XMLGEN FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_XMLQUERY FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_FILE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_INADDR FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_TCP FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_MAIL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_SMTP FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_DBWS FROM '\''PUBLIC'\'';'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_ORAMTS FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON UTL_HTTP FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON HTTPURITYPE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_SYS_SQL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_BACKUP_RESTORE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_AQADM_SYSCALLS FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
revoke execute on DBMS_REPACT_SQL_UTL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON INITJVMAUX FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_STREAMS_ADM_UTL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_AQADM_SYS FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_STREAMS_RPC FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_PRVTAQIM FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON LTADM FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON WWV_DBMS_SQL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON WWV_EXECUTE_IMMEDIATE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_IJOB FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_FILE_TRANSFER FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_XMLSTORE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_XMLSAVE FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON DBMS_REDACT FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON OLAP_TABLE FROM PUBLIC;
REVOKE EXECUTE ON DBMS_AW FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ON OWA_UTIL FROM PUBLIC;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
DROP TABLE SYS.USER$MIG;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Ensure that only necessary users are included in the OSDBA and OSOPER groups in operating system. Exclude excessive users from the groups if any.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.AUD$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Replace <non-DBA/SYS grantee>, in the query below, with the Oracle login(s) or role(s) returned from the
associated audit procedure and execute:
REVOKE ALL ON <DBA_%> FROM <Non-DBA/SYS grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.USER_HISTORY$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.USER$ FROM <username>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.LINK$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.SCHEDULER$_CREDENTIAL FROM <username>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.DEFAULT_PWD$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.XS$VERIFIERS FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.ENC$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.HISTGRM$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.HIST_HEAD$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.CDB_LOCAL_ADMINAUTH$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALL ON SYS.PDB_SYNC$ FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE '\''<ANY Privilege>'\'' FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE <privilege> FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ANY PROCEDURE FROM OUTLN;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE ANY PROCEDURE FROM DBSNMP;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE SELECT_ANY_DICTIONARY FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE SELECT ANY TABLE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE AUDIT SYSTEM FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXEMPT ACCESS POLICY FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE BECOME USER FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE CREATE_PROCEDURE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE ALTER SYSTEM FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE CREATE ANY LIBRARY FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE CREATE LIBRARY FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE GRANT ANY OBJECT PRIVILEGE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE GRANT ANY ROLE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE GRANT ANY PRIVILEGE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE SELECT_CATALOG_ROLE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE EXECUTE_CATALOG_ROLE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE DELETE_CATALOG_ROLE FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE DBA FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To revoke excessive SYSDBA privileges, execute the following command: 
SQL> REVOKE SYSDBA FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To revoke excessive SYSOPER privileges, execute the following command: 
SQL> REVOKE SYSOPER FROM <grantee>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'To remediate this setting execute the following SQL statement.
REVOKE CONNECT FROM <proxy_user>;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT USER;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting:
AUDIT ROLE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT SYSTEM GRANT;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT PROFILE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT DATABASE LINK;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT PUBLIC DATABASE LINK;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT PUBLIC SYNONYM;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT SYNONYM;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT GRANT DIRECTORY;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT SELECT ANY DICTIONARY;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT GRANT ANY OBJECT PRIVILEGE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT GRANT ANY PRIVILEGE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT DROP ANY PROCEDURE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT ALL ON SYS.AUD$ BY ACCESS;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT PROCEDURE;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT ALTER SYSTEM;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT TRIGGER;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
AUDIT SESSION;'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE USER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER USER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP USER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE ROLE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER ROLE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP ROLE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS GRANT;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS REVOKE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE PROFILE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER PROFILE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP PROFILE;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE DATABASE LINK;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER DATABASE LINK;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP DATABASE LINK;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE SYNONYM;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER SYNONYM;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP SYNONYM;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD PRIVILEGES SELECT ANY DICTIONARY;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALL on AUDSYS.AUD$UNIFIED;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE PROCEDURE,CREATE FUNCTION,CREATE PACKAGE,CREATE PACKAGE BODY;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER PROCEDURE,ALTER FUNCTION,ALTER PACKAGE,ALTER PACKAGE BODY;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE PROCEDURE,CREATE FUNCTION,CREATE PACKAGE,CREATE PACKAGE BODY;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER SYSTEM;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS CREATE TRIGGER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS ALTER TRIGGER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS DROP TRIGGER;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."


echo "[Manual]" 'Execute the following SQL statement to remediate this setting.
ALTER AUDIT POLICY <unified audit policy name> ADD ACTIONS LOGON,LOGOFF;
If you do not have unified audit policy, create one using the CREATE AUDIT POLICY statement.'
read -n 1 -p "Press Enter to continue..."



