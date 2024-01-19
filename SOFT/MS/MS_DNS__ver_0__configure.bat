
@echo off
echo.
echo.
echo Use separate DNS servers for internal and Internet name resolution.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo On external DNS servers:
echo dnscmd ^<ServerName^> /Config /NoRecursion 1
echo 
echo Default: 0.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure Internal DNS Servers use Forwarder Servers with Internet access for external DNS-queries.
echo dnscmd ^<ServerName^> /ResetForwarders ^<ForwarderIPaddress1 ForwarderIPaddress2 ...^> [/TimeOut ^<Time^>] /Slave
echo Or for separate zones:
echo dnscmd ^<ServerName^> /ZoneAdd ^<ZoneName^> /Forwarder ^<MasterIPaddress ...^> [/TimeOut ^<Time^>] [/Slave]
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo dnscmd ^<ServerName^> /config /secureresponses 1
echo 
echo Default: 0.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Set RootHints list to empty or custom for internal servers that are not supposed to send queries to external servers:
echo dnscmd ^<ServerName^> /RecordAdd /RootHints ^<host^> A ^<ip address^>
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo To modify security for the DNS Server service on a domain controller
echo     Open DNS Manager.
echo     In the console tree, right-click the applicable server, and then click Properties-^> Where? -^> DNS/applicable DNS server
echo     On the Security tab, modify the list of member users or groups that are allowed to administer the applicable server.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo To modify security for a directory-integrated zone
echo     Open DNS Manager.
echo     In the console tree, click the applicable zone -^> Where? -^> DNS/applicable DNS server/Forward Lookup Zones (or Reverse Lookup Zones)/applicable zone
echo     On the Action menu, click Properties.
echo     On the General tab, verify that the zone type is Active Directory-integrated.
echo     On the Security tab, modify the list of member users or groups that are allowed to securely update the applicable zone and reset their permissions as needed.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Allow only secure dynamic updates for zones where dynamic updates are needed:
echo dnscmd ^<ServerName^> /Config {^<ZoneName^>^|..AllZones} /AllowUpdate 2
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo If server has more then 1 IP-interface, set Ips on which DNS-server will listen:
echo dnscmd ^<ServerName^> /ResetListenAddresses ^<ListenAddress1^> ^<ListenAddress2^> ...
echo 
echo Default: all IP addresses.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure DNS server to select source port randomly. This is default configuration. If SendPort parameter was specified, set it to zero to use random free port:
echo dnscmd /config /sendport 0
echo 
echo Default: 0, which means that the port number is selected randomly.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo For every hosted zone configure restrictive list of servers which are permitted to get full zone description:
echo dnscmd ^<ServerName^> /ZoneResetSecondaries ^<ZoneName^> /SecureList ^<IPAddress1^> ^<IPAddress2^> …
echo Or configure list of authoritative servers for every zone using following command:
echo dnscmd ^<ServerName^> /RecordAdd ^<ZoneName^> ^<NodeName^> [/Aging] [/OpenAcl] [^<Ttl^>] NS {^<HostName^>^|^<DomainName^>} 
echo And then permit transfer to this servers:
echo dnscmd ^<ServerName^> /ZoneResetSecondaries ^<ZoneName^> /SecureNS
echo Or deny any zone transfers.
echo 
echo Default: No secondary security.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo For every zone where Secure Transfer is permitted configure restrictive list of authorized servers which are permitted to get full zone description:
echo dnscmd ^<ServerName^> /ZoneResetSecondaries ^<ZoneName^> /SecureList ^<IPAddress1^> ^<IPAddress2^> …
echo Do not include excessive servers to the list.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Set EventLogLvl to 2 (Logs only errors and warnings) or 4 (Logs errors, warnings, and informational events):
echo dnscmd ^<ServerName^> /config /eventloglevel 4
echo 
echo Default: 4.
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Set log file size to 100 MB:
echo dnscmd ^<ServerName^> /config /logfilemaxsize 0x6400000
echo 
echo Default: 0x400000 (4 MB).
set /p=Press Enter to continue...
@echo on


@echo off
echo.
echo.
echo Configure DNS server to save needed portions of logging data. Example:
echo dnscmd ^<ServerName^> /config /loglevel 0x8100f331
echo 
echo Default: 0.
set /p=Press Enter to continue...
@echo on



