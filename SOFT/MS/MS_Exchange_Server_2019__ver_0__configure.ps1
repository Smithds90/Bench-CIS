
Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ReceiveConnector `"Connection from Contoso.com`" -MaxMessageSize 25MB
To set MaxMessageSize on all receive connectors this command can be executed: 
Get-ReceiveConnector | Set-ReceiveConnector -MaxMessageSize 25MB
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Receive Connectors`" tab.
3. Double-click on the receive connector to be modified.
4. Change the Maximum receive message size (MB): to 25 or lower and click Save.

Default: 36 MB (37,748,736 bytes)."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet to disable the Pickup Directory on the Edge Transport server: 
Get-TransportService | Set-TransportService -PickupDirectoryPath `$null

Default: %programfiles%\Microsoft\Exchange Server\V15\TransportRoles\Pickup"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-OrganizationConfig -CustomerFeedbackEnabled `$false"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ReceiveConnector -Identity <'IdentityName'> -Banner '220 SMTP Server Ready'

Default:
  220 <ServerName> Microsoft ESMTP MAIL service ready at <RegionalDay-Date-24HourTimeFormat><RegionalTimeZoneOffset>"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Examples of configuration accepted authentication mechanisms for the receive connector:
Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls'
Set-ReceiveConnector -Identity <'IdentityName'> -AuthMechanism 'Tls, BasicAuth, BasicAuthRequireTLS'"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the below cmdlet: 
Set-SenderIDConfig -Enabled `$true -SpoofedDomainAction Reject

Default:
  Enabled: True
  SpoofedDomainAction: StampStatus"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SenderFilterConfig -Enabled `$true

Default:
  Enabled: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SenderReputationConfig -Enabled `$true -SenderBlockingEnabled `$true -OpenProxyDetectionEnabled `$true -SrlBlockThreshold 6

Default:
  SenderBlockingEnabled True
  OpenProxyDetectionEnabled True
  SrlBlockThreshold 7"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SenderFilterConfig -Action Reject -BlankSenderBlockingEnabled `$true

Default:
  Action Reject
  BlankSenderBlockingEnabled False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ContentFilterConfig -QuarantineMailbox <'QuarantineMailbox SmtpAddress'>

Default: no address."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ContentFilterConfig -SCLQuarantineEnabled `$true -SCLQuarantineThreshold 6
The SCLRejectThreshold must be greater than the SCLQuarantineThreshold when enabling the Quarantine.

Default:
  SCLQuarantineEnabled: False
  SCLQuarantineThreshold: 9
  SCLRejectThreshold: 7"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RecipientFilterConfig -RecipientValidationEnabled `$true

Default: False."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Execute the following cmdlet to enable the Filtering Agent: 
Enable-TransportAgent `"Attachment Filtering Agent`"
Execute the bellow script to create the desired attachment filtering state: 
`$attachmentExtensions = @( `"*.ace`", `"*.ade`", `"*.adp`", `"*.ani`", `"*.app`", `"*.appx`", `"*.arj`", `"*.asx`", `"*.bas`", `"*.bat`", `"*.cab`", `"*.chm`", `"*.cmd`", `"*.com`", `"*.cpl`", `"*.crt`", `"*.csh`", `"*.dbf`", `"*.dcr`", `"*.deb`", `"*.dex`", `"*.dif`", `"*.dir`", `"*.dll`", `"*.doc`", `"*.dot`", `"*.docm`", `"*.elf`", `"*.exe`", `"*.fxp`", `"*.hlp`", `"*.hta`", `"*.htc`", `"*.htm`", `"*.html`", `"*.img`", `"*.inf`", `"*.ins`", `"*.iso`", `"*.isp`", `"*.jar`", `"*.jnlp`", `"*.js`", `"*.jse`", `"*.kext`", `"*.ksh`", `"*.lha`", `"*.lib`", `"*.lnk`", `"*.lzh`", `"*.macho`", `"*.mda`", `"*.mdb`", `"*.mde`", `"*.mdt`", `"*.mdw`", `"*.mdz`", `"*.mht`", `"*.mhtml`", `"*.msc`", `"*.msi`", `"*.msix`", `"*.msp`", `"*.mst`", `"*.ops`", `"*.pcd`", `"*.pif`", `"*.plg`", `"*.ppa`", `"*.ppt`", `"*.ppam`", `"*.prf`", `"*.prg`", `"*.ps1`", `"*.ps11`", `"*.ps11xml`", `"*.ps1xml`", `"*.ps2`", `"*.ps2xml`", `"*.psc1`", `"*.psc2`", `"*.reg`", `"*.rev`", `"*.scf`", `"*.scr`", `"*.sct`", `"*.shb`", `"*.shs`", `"*.shtm`", `"*.shtml`", `"*.slk`", `"*.spl`", `"*.stm`", `"*.swf`", `"*.sys`", `"*.uif`", `"*.url`", `"*.vb`", `"*.vbe`", `"*.vbs`", `"*.vxd`", `"*.wsc`", `"*.wsf`", `"*.wsh`", `"*.xlam`", `"*.xla`", `"*.xlc`", `"*.xll`", `"*.xls`", `"*.xlsm`", `"*.xlt`", `"*.xlw`", `"*.xml`", `"*.xnk`", `"*.xz`", `"*.z`" ) 
foreach (`$extension in `$attachmentExtensions) { 
`$result = Add-AttachmentFilterEntry -Name `$extension -Type FileName -ErrorAction SilentlyContinue 
if (`$result) { 
  Write-Host `"Successfully added attachment `$extension`" -ForegroundColor Green 
} else { 
  Write-Host `"Attachment `$extension already exists in the list.`" -ForegroundColor Red 
} 
}

Default: these extensions are blocked: *.ade, *.adp, *.app, *.asx, *.bas, *.bat, *.chm, *.cmd, *.com, *.cpl, *.crt, *.csh, *.exe, *.fxp, *.hlp, *.hta, *.inf, *.ins, *.isp, *.js, *.jse, *.ksh, *.lnk, *.mda, *.mdb, *.mde, *.mdt, *.mdw, *.mdz, *.msc, *.msi, *.msp, *.mst, *.ops, *.pcd, *.pif, *.prf, *.prg, *.ps1, *.ps11, *.ps11xml, *.ps1xml, *.ps2, *.ps2xml, *.psc1, *.psc2, *.reg, *.scf, *.scr, *.sct, *.shb, *.shs, *.url, *.vb, *.vbe, *.vbs, *.wsc, *.wsf, *.wsh, *.xnk"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RecipientFilterConfig -Enabled `$true

Default: True."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Set 'Issue a warning' quota to 1.9 GB or less or other appropriate value.
To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MailboxDatabase `"Mailbox Database`" -IssueWarningQuota <value> KB
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Change Issue a warning at (GB): to <value> and click Save.

Default: 1.899 GB (2,039,480,320 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MailboxDatabase `"Mailbox Database`" -DeletedItemRetention 14
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Change Keep deleted items for (days): to 14 and click Save.

Default: 14"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Set 'Prohibit send and receive' quota to 2.3 GB or less or other appropriate value.
To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MailboxDatabase `"Mailbox Database`" -ProhibitSendReceiveQuota <value> GB
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Change Prohibit send and receive at (GB): to <value> and click Save.

Default: 2.3 GB (2,469,396,480 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Set 'Prohibit send' quota to 2 GB or less or other appropriate value.
To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MailboxDatabase `"Mailbox Database`" -ProhibitSendQuota <value>
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Change Prohibit send at (GB): to <value> and click Save.

Default: 2 GB (2,147,483,648 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet (set to 30 or more): 
Set-Mailboxdatabase `"Mailbox Database`" -MailboxRetention 30.00:00:00
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Change Keep deleted mailboxes for (days): to 30 or more and click Save.

Default: 30"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MailboxDatabase `"Mailbox Database`" -RetainDeletedItemsUntilBackup `$true
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Databases`" tab.
3. Double-click the database and go to the `"Limits`" settings.
4. Ensure the Don't permanently delete items until the database is backed up box is checked and click Save.

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-TransportConfig -MaxSendSize 25MB
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Send Connectors`" tab.
3. Click on `"...`" and select `"Organization Transport Settings`".
4. Change the Maximum send message size (MB): to 25 or lower and click Save.

Default: 10 MB (10,485,760 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-TransportConfig -MaxReceiveSize 25MB
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Receive Connectors`" tab.
3. Click on `"...`" and select `"Organization Transport Settings`"
4. Change the Maximum receive message size (MB): to 25 or lower and click Save.

Default: 10 MB (10,485,760 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SendConnector `"Connection to Contoso.com`" -MaxMessageSize 25MB
OR
Perform the following actions via the GUI:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Send Connectors`" tab.
3. Double-click on the send connector to be modified.
4. Change the Maximum send message size (MB): to 25 or lower and click Save.

Default: 10 MB (10,485,760 bytes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SendConnector -Identity <'IdentityName'> -ConnectionInactivityTimeOut 00:10:00

Default: 00:10:00 (10 minutes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ReceiveConnector -Identity <IdentityName> -ConnectionTimeout 00:05:00
Repeat the procedures for each Receive connector.

Default: 00:10:00 (10 minutes)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Warning: If a SmartHosts parameter is specified, the DNSRoutingEnabled parameter must be set to `$false.
To implement the recommended state, execute the following PowerShell cmdlets: 
Set-SendConnector `"Connector Name`" -DNSRoutingEnabled `$true
Set-SendConnector `"Connector Name`" -IgnoreSTARTTLS `$false
Set-SendConnector `"Connector Name`" -DomainSecureEnabled `$true

Default:
  DNSRoutingEnabled: True
  IgnoreSTARTTLS: none
  DomainSecureEnabled: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RemoteDomain `"RemoteDomain`" -NDREnabled `$false

Default: True."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RemoteDomain `"RemoteDomain`" -AllowedOOFType None

Default: External"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RemoteDomain `"RemoteDomain`" -AutoReplyEnabled `$false

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RemoteDomain `"RemoteDomain`" -AutoForwardEnabled `$false

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-OWAVirtualDirectory `"owa (Default Web Site)`" -SMimeEnabled `$true

Default: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-RpcClientAccess -Server `"Server`" -EncryptionRequired `$true

Default: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell commands: 
Stop-Service MSExchangePop3,MSExchangePop3BE 
Get-Service MSExchangePOP3,MSExchangePOP3BE | Set-Service -StartupType Disabled

Default:
  StartType: Manual"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell commands: 
Stop-Service MSExchangeImap4,MSExchangeIMAP4BE 
Get-Service MSExchangeImap4,MSExchangeIMAP4BE | Set-Service -StartupType Disabled

Default:
  StartType: Manual"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -AllowSimplePassword `$false
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Allow simple passwords box is not checked and click Save.

Default: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -AllowNonProvisionableDevices `$false
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"General`" settings.
4. Ensure the Allow mobile devices that don't fully support these policies to synchronize box is not checked and click Save.

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -PasswordHistory 4
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Change the Password recycle count to 4 and click Save.

Default: 0"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -MinPasswordLength 8
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Minimum password length box is checked and change the value to 8 or more and click Save

Default: 4"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet (set to 5 or less): 
Set-MobileDeviceMailboxPolicy `"Profile`" -MaxPasswordFailedAttempts 5

Default: Unlimited"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet (set to 365 or less): 
Set-MobileDeviceMailboxPolicy `"Profile`" -PasswordExpiration 90
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Enforce password lifetime (days) box is checked change the value to 365 and click Save

Default: Unlimited"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -DevicePolicyRefreshInterval '1:00:00'

Default: 24 hours"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -AlphanumericPasswordRequired `$true
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Require an alphanumeric password box is checked and click Save.

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -RequireDeviceEncryption `$true
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Require encryption on device box is checked and click Save

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -PasswordEnabled `$true
OR Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Require a password box is checked and click Save.

Default: False"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-MobileDeviceMailboxPolicy `"Profile`" -MaxInactivityTimeLock 00:15:00
OR Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mobile`" on the left and click on the `"Mobile device mailbox policies`" tab.
3. Double-click the policy you wish to modify and go to the `"Security`" settings.
4. Ensure the Require sign-in after the device has been inactive for (minutes) box is checked and change the value to 15 or less and click Save.

Default: 15"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-ReceiveConnector `"IDENTITY`" -ProtocolLoggingLevel Verbose
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Receive Connectors`" tab.
3. Double-click on the receive connector to be modified.
4. Change the Protocol logging level to Verbose and click Save."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell script: 
`$params = @{ 
  AdminAuditLogEnabled = `$True 
  AdminAuditLogCmdlets = '*' 
  AdminAuditLogParameters = '*' 
  AdminAuditLogExcludedCmdlets = `$null 
  AdminAuditLogAgeLimit = '90.00:00:00' 
  LogLevel = 'Verbose' 
} 
Set-AdminAuditLogConfig @params

Default:
  AdminAuditLogEnabled - True
  AdminAuditLogCmdlets - *
  AdminAuditLogParameters - *
  AdminAuditLogExcludedCmdlets - None
  AdminAuditLogAgeLimit - 90 days
  LogLevel - None"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-TransportService `"EXCHANGE1`" -ConnectivityLogEnabled `$true
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Servers`" on the left and click on the `"Servers`" tab.
3. Double-click the server and go to the `"Transport logs`" settings.
4. Ensure the Enable connectivity log box is checked and click Save.

Default: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-SendConnector `"IDENTITY`" -ProtocolLoggingLevel Verbose
OR
Perform the following actions:
1. Launch the EAC (Exchange Administrative Center).
2. Go to `"Mail Flow`" on the left and click on the `"Send Connectors`" tab.
3. Double-click on the send connector to be modified.
4. Change the Protocol logging level to Verbose and click Save.

Default: None"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To implement the recommended state, execute the following PowerShell cmdlet: 
Set-TransportService `"EXCHANGE1`" -MessageTrackingLogEnabled `$true

Default: True"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")



