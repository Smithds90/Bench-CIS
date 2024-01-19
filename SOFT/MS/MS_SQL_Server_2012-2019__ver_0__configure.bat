
@echo off
echo.
echo.
echo Identify the current version and patch level of your SQL Server instances and ensure they contain the latest security fixes. Make sure to test these fixes in your test environments before updating production instances. 
echo The most recent SQL Server patches can be found here: 
echo http://blogs.msdn.com/b/sqlreleaseservices/ 
echo https://support.microsoft.com/en-us/kb/2958069
echo https://support.microsoft.com/en-us/kb/3177534
echo https://docs.microsoft.com/en-us/sql/database-engine/install-windows/latest-updatesfor-microsoft-sql-server?view=sql-server-2017
echo https://docs.microsoft.com/en-us/sql/database-engine/install-windows/latest-updatesfor-microsoft-sql-server?view=sql-server-ver15
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Uninstall excess tooling and/or remove unnecessary roles from the underlying operating system.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'clr enabled', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'clr enabled', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Cross db ownership chaining', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Cross db ownership chaining', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Database Mail XPs', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Database Mail XPs', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Remote access', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Remote access', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Remote admin connections', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Remote admin connections', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Scan for startup procs', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Scan for startup procs', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'SQL Mail XPs', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'SQL Mail XPs', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'') BEGIN ALTER DATABASE ? SET TRUSTWORTHY OFF; END'") else (sqlcmd -E -S ".\%%i" -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'') BEGIN ALTER DATABASE ? SET TRUSTWORTHY OFF; END'"))
@echo on



@echo off
echo.
echo.
echo Open SQL Server Configuration Manager; go to the SQL Server Network Configuration.
echo Ensure that only required protocols are enabled. Disable protocols not necessary.
echo 
echo By default, TCP/IP and Shared Memory protocols are enabled on all commercial editions.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo 1. In SQL Server Configuration Manager, in the console pane, expand SQL Server Network Configuration, expand Protocols for ^<InstanceName^>, and then double-click the TCP/IP or VIA protocol
echo 2. In the TCP/IP Properties dialog box, on the IP Addresses tab, several IP addresses appear in the format IP1, IP2, up to IPAll. One of these is for the IP address of the loopback adapter, 127.0.0.1. Additional IP addresses appear for each IP Address on the computer
echo 3. Under IPAll, change the TCP Port field from 1433 to a non-standard port or leave the TCP Port field empty and set the TCP Dynamic Ports value to 0 to enable dynamic port assignment and then click OK.
echo 4. In the console pane, click SQL Server Services.
echo 5. In the details pane, right-click SQL Server (^<InstanceName^>) and then click Restart, to stop and restart SQL Server.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "tokens=3 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (reg add "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\%%i\MSSQLServer\SuperSocketNetLib" /v HideInstance /t REG_DWORD /d 1 /f)
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "USE [master]; DECLARE @tsql nvarchar(max); SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'; EXEC (@tsql);") else (sqlcmd -E -S ".\%%i" -Q "USE [master]; DECLARE @tsql nvarchar(max); SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'; EXEC (@tsql);"))
@echo on



@echo off
set /P mssql_new_sa="Couch: Enter new name for 0x01 user (initially sa):"
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "USE [master]; DECLARE @tsql nvarchar(max); SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' WITH NAME=%mssql_new_sa%'; EXEC (@tsql);") else (sqlcmd -E -S ".\%%i" -Q "USE [master]; DECLARE @tsql nvarchar(max); SET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' WITH NAME=%mssql_new_sa%'; EXEC (@tsql);"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'',''master'',''tempdb'') BEGIN USE ?; exec sp_dropuser ''guest''; END'") else (sqlcmd -E -S ".\%%i" -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'',''master'',''tempdb'') BEGIN USE ?; exec sp_dropuser ''guest''; END'"))
@echo on



@echo off
net user SQLDebugger /active:no
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Xp_cmdshell', 0; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Xp_cmdshell', 0; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXEC sp_MSforeachdb 'BEGIN ALTER DATABASE ? SET AUTO_CLOSE OFF; END'") else (sqlcmd -E -S ".\%%i" -Q "EXEC sp_MSforeachdb 'BEGIN ALTER DATABASE ? SET AUTO_CLOSE OFF; END'"))
@echo on



@echo off
set /P mssql_new_sa="Couch: Enter new name for sa account:"
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "ALTER LOGIN sa WITH NAME=%mssql_new_sa%;") else (sqlcmd -E -S ".\%%i" -Q "ALTER LOGIN sa WITH NAME=%mssql_new_sa%;"))
@echo on



@echo off
echo.
echo.
echo Using Windows Computer Management, remove all unnecessary users from SQLServer2005SQLBrowserUser$^<hostname^> and SQLServerMSSQLUser$^<hostname^>$^<instance_name^>. Only SQL Server service account should be included in this group.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo To remove these unnecessary users, use the Enterprise Manager at Security -^> Server Role -^> System Administrators.
echo Windows default Service Groups of SQL Server and SQL Server Agent services must have Sysadmin privilege.
echo SQL Server and SQL Service Agent Accounts must have sysadmin privilege
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Set necessary privileges to the SQLServer Service and SQL Server Agent user. Unless is highly needed don't set account with OS administrative rights for SQLServer and SQL Server Agent servies otherwise use NetworkService account. Set a strong password to this account and change the SQLServer and Agent account service. Set only The following Windows Groups to this account: [Users, Authenticated Uses] [SQL Server Agent Default Group]. The accounts below should not be used: Built-in\LocalSystem Built-in\LocalService Built-in\NetworkService Built-in\Administrator
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Note:
echo 1) Before removing the BUILT-IN\Administrators group from sysadmin role, certify that the new administrators account was created and configured in SQL Server as sysadmin. 
echo 2) If the account LocalSystem needs access to the SQL Server, the account 'NT AUTHORITY\system' should be added to SQL Server on 'System Administrators'.
echo 
echo Set individual Windows accounts to SQL Server with 'System Administrators' privilege and remove the BUILT-IN\Administrators.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Drop all Database Samples from SQL Server.
echo Example for 2008 – AdventureWorks2008, AdventureWorksDW 2008, AdventureWorksAS2008 and AdventureWorksLT2008.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Perform the following steps:
echo 1. Open SQL Server Management Studio.
echo 2. Open the Object Explorer tab and connect to the target database instance.
echo 3. Right click the instance name and select Properties.
echo 4. Select the Security page from the left menu.
echo 5. Set the Server authentication setting to Windows Authentication mode.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'',''master'',''tempdb'') BEGIN USE ?; REVOKE CONNECT FROM guest; END'") else (sqlcmd -E -S ".\%%i" -Q "EXEC sp_MSforeachdb 'IF ''?'' NOT IN(''msdb'',''master'',''tempdb'') BEGIN USE ?; REVOKE CONNECT FROM guest; END'"))
@echo on



@echo off
echo.
echo.
echo Revoke "Server Permissions" from all users which do not need them using the following command:
echo REVOKE ^<Server Privilege^> FROM ^<user^>;
echo Permissions list:
echo ADMINISTER BULK OPERATIONS
echo ALTER ANY CONNECTION
echo ALTER ANY CREDENTIAL
echo ALTER ANY DATABASE
echo ALTER ANY ENDPOINT
echo ALTER ANY EVENT NOTIFICATION
echo ALTER ANY LINKED SERVER
echo ALTER ANY LOGIN
echo ALTER RESOURCES
echo ALTER SERVER STATE
echo ALTER SETTINGS
echo ALTER TRACE
echo AUTHENTICATE SERVER
echo CONTROL SERVER
echo CREATE ANY DATABASE
echo CREATE DDL EVENT NOTIFICATION
echo CREATE ENDPOINT
echo CREATE TRACE EVENT NOTIFICATION
echo SHUTDOWN
echo VIEW ANY DATABASE
echo VIEW ANY DEFINITION
echo VIEW SERVER STATE
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo If the orphaned user cannot or should not be matched to an existing or new login using the Microsoft documented process referenced below, run the following T-SQL query in the appropriate database to remove an orphan user:
echo USE [^<database_name^>];
echo GO
echo DROP USER ^<username^>;
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Leverage Windows Authenticated users in contained databases.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure the MSSQL service account. In the case where LocalSystem is used, use SQL Server Configuration Manager to change to a less privileged account. Otherwise, remove the account or service SID from the Administrators group. You may need to run the SQL Server Configuration Manager if underlying permissions had been changed or if SQL Server Configuration Manager was not originally used to set the service account.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure SQLAgent service account. In the case where LocalSystem is used, use SQL Server Configuration Manager to change to a less privileged account. Otherwise, remove the account or service SID from the Administrators group. You may need to run the SQL Server Configuration Manager if underlying permissions had been changed or if SQL Server Configuration Manager was not originally used to set the service account.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure the Full-Text service account. In the case where LocalSystem is used, use SQL Server Configuration Manager to change to a less privileged account. Otherwise, remove the account or service SID from the Administrators group. You may need to run the SQL Server Configuration Manager if underlying permissions had been changed or if SQL Server Configuration Manager was not originally used to set the service account.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @permission VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT permission_name FROM master.sys.server_permissions WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%%') AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);open @cursor;FETCH NEXT FROM @cursor into @permission;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='REVOKE '+@permission+' FROM public'; EXEC (@SQL);FETCH NEXT FROM @cursor into @permission;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @permission VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT permission_name FROM master.sys.server_permissions WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%%') AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);open @cursor;FETCH NEXT FROM @cursor into @permission;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='REVOKE '+@permission+' FROM public'; EXEC (@SQL);FETCH NEXT FROM @cursor into @permission;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT pr.[name] FROM master.sys.server_principals pr JOIN master.sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name like 'BUILTIN%%';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='DROP LOGIN [BUILTIN\'+@name; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT pr.[name] FROM master.sys.server_principals pr JOIN master.sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name like 'BUILTIN%%';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='DROP LOGIN [BUILTIN\'+@name; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT pr.[name] FROM master.sys.server_principals pr JOIN master.sys.server_permissions pe ON pr.[principal_id] = pe.[grantee_principal_id] WHERE pr.[type_desc] = 'WINDOWS_GROUP' AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%%';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='DROP LOGIN '+@name; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT pr.[name] FROM master.sys.server_principals pr JOIN master.sys.server_permissions pe ON pr.[principal_id] = pe.[grantee_principal_id] WHERE pr.[type_desc] = 'WINDOWS_GROUP' AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%%';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='DROP LOGIN '+@name; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT sp.name FROM msdb.dbo.sysproxylogin spl JOIN msdb.sys.database_principals dp ON dp.sid = spl.sid JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id WHERE principal_id = USER_ID('public');open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='EXEC dbo.sp_revoke_login_from_proxy @name = N''public'', @proxy_name = N'''+@name+''''; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT sp.name FROM msdb.dbo.sysproxylogin spl JOIN msdb.sys.database_principals dp ON dp.sid = spl.sid JOIN msdb.dbo.sysproxies sp ON sp.proxy_id = spl.proxy_id WHERE principal_id = USER_ID('public');open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='EXEC dbo.sp_revoke_login_from_proxy @name = N''public'', @proxy_name = N'''+@name+''''; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
echo.
echo.
echo Set the MUST_CHANGE option for SQL Authenticated logins when creating a login initially:
echo CREATE LOGIN ^<login_name^> WITH PASSWORD = '^<password_value^>' MUST_CHANGE, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;
echo Set the MUST_CHANGE option for SQL Authenticated logins when resetting a password:
echo ALTER LOGIN ^<login_name^> WITH PASSWORD = '^<new_password_value^>' MUST_CHANGE;
echo 
echo Default Value:
echo ON when creating a new login via the SSMS GUI.
echo OFF when creating a new login using T-SQL CREATE LOGIN unless the MUST_CHANGE option is explicitly included along with CHECK_EXPIRATION = ON.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR select name from sys.sql_logins;open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER LOGIN '+@name+' WITH CHECK_EXPIRATION=ON'; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR select name from sys.sql_logins;open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER LOGIN '+@name+' WITH CHECK_EXPIRATION=ON'; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR select name from sys.sql_logins;open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER LOGIN '+@name+' WITH CHECK_POLICY=ON'; EXEC (@SQL);;FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR select name from sys.sql_logins;open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER LOGIN '+@name+' WITH CHECK_POLICY=ON'; EXEC (@SQL);;FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
for /f "tokens=3 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (reg add "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\%%i\MSSQLServer" /v NumErrorLogs /t REG_DWORD /d 12 /f)
@echo on



@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'Default trace enabled', 1; RECONFIGURE;" && sqlcmd -E -S "." -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;") else (sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 1;RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'Default trace enabled', 1; RECONFIGURE;" && sqlcmd -E -S ".\%%i" -Q "EXECUTE sp_configure 'show advanced options', 0;RECONFIGURE;"))
@echo on



@echo off
echo.
echo.
echo Perform the following steps to set the level of auditing:
echo 1. Open SQL Server Management Studio.
echo 2. Right click the target instance and select Properties and navigate to the Security tab.
echo 3. Select the option 'Failed logins only' or 'Both failed and successful logins' under the "Login Auditing" section and click OK.
echo 4. Restart the SQL Server instance.
echo 
echo Default Value: only failed login attempts are captured.
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "CREATE SERVER AUDIT TrackLogins TO APPLICATION_LOG;" && sqlcmd -E -S "." -Q "CREATE SERVER AUDIT SPECIFICATION TrackAllLogins FOR SERVER AUDIT TrackLogins ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP), ADD (AUDIT_CHANGE_GROUP) WITH (STATE = ON);" && sqlcmd -E -S "." -Q "ALTER SERVER AUDIT TrackLogins WITH (STATE = ON);") else (sqlcmd -E -S ".\%%i" -Q "CREATE SERVER AUDIT TrackLogins TO APPLICATION_LOG;" && sqlcmd -E -S ".\%%i" -Q "CREATE SERVER AUDIT SPECIFICATION TrackAllLogins FOR SERVER AUDIT TrackLogins ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP), ADD (AUDIT_CHANGE_GROUP) WITH (STATE = ON);" && sqlcmd -E -S ".\%%i" -Q "ALTER SERVER AUDIT TrackLogins WITH (STATE = ON);"))
@echo on



@echo off
echo.
echo.
echo The following steps can be taken to remediate SQL injection vulnerabilities: 
echo . Review TSQL and application code for SQL Injection 
echo . Only permit minimally privileged accounts to send user input to the server 
echo . Minimize the risk of SQL injection attack by using parameterized commands and stored procedures 
echo . Reject user input containing binary data, escape sequences, and comment characters 
echo . Always validate user input and do not use it directly to build SQL statements
echo https://owasp.org/www-community/attacks/SQL_Injection
set /p=Press Enter to continue...
@echo on


@echo off
for /f "delims=. tokens=2 usebackq" %%i in (`reg query "HKLM\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul ^& reg query "HKLM\Software\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2^>nul`) do (if "%%i"=="MSSQLSERVER" (sqlcmd -E -S "." -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT name FROM sys.assemblies where is_user_defined=1 and permission_set_desc!='SAFE_ACCESS';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER ASSEMBLY '+@name+' WITH PERMISSION_SET = SAFE'; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;") else (sqlcmd -E -S ".\%%i" -Q "declare @name VARCHAR (50);DECLARE @cursor CURSOR;SET @cursor=CURSOR FOR SELECT name FROM sys.assemblies where is_user_defined=1 and permission_set_desc!='SAFE_ACCESS';open @cursor;FETCH NEXT FROM @cursor into @name;WHILE @@FETCH_STATUS=0 BEGIN declare @SQL VARCHAR(1000); SELECT @SQL='ALTER ASSEMBLY '+@name+' WITH PERMISSION_SET = SAFE'; EXEC (@SQL);FETCH NEXT FROM @cursor into @name;END;CLOSE @cursor;DEALLOCATE @cursor;"))
@echo on



@echo off
echo.
echo.
echo Ensure only AES_128 and stronger algorithms are in use. In other case change used keys.
echo Refer to Microsoft SQL Server Books Online ALTER SYMMETRIC KEY entry:
echo https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-symmetric-key-transact-sql
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Ensure only 2048-bit and stronger keys are in use. In other case change used keys.
echo Refer to Microsoft SQL Server Books Online ALTER ASYMMETRIC KEY entry:
echo https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-asymmetric-key-transactsql
set /p=Press Enter to continue...
@echo on



