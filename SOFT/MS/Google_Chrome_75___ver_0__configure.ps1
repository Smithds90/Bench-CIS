# Take domain and policy name
$domain_name = Read-Host "Enter AD domain name"
$domain = Get-AdDomain $domain_name
$domain_sid = $domain.DomainSID
$gpo_name = Read-Host "Enter target Chrome GPO name:[default is Couch_Chrome]"
if ( $gpo_name -eq "" ) { $gpo_name = "Couch_Chrome" }
Get-GPO -Name $gpo_name -Domain $domain.DNSRoot
if ( ! $? ) { New-GPO -Name $gpo_name -Domain $domain.DNSRoot }

# Set paths
$gpo = Get-GPO -Name $gpo_name -Domain $domain.DNSRoot
$domain_name = $gpo.DomainName
$num = $gpo.Id.Guid
$gpo_path = "$env:WinDir\SYSVOL\sysvol\${domain_name}\Policies\{$num}"

# Configure gPCMachineExtensionNames attribute
$gpo_search = ([adsisearcher]'(objectCategory=groupPolicyContainer)').FindAll() | where {$_.Properties.displayname -eq $gpo_name}
$ldap_query = $gpo_search.Path.replace('//','//localhost:389/')
$gpo_ldap_object = [ADSI]$ldap_query
$gpo_attrib = $gpo_ldap_object.gPCMachineExtensionNames.Value

if ( -not $gpo_attrib ) { $gpo_attrib = "" }
if ( -not $gpo_attrib.Contains("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") ) { $gpo_attrib = $gpo_attrib + "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"; }
if ( -not $gpo_attrib.Contains("[{7933F41E-56F8-41D6-A31C-4148A711EE93}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") ) { $gpo_attrib = $gpo_attrib + "[{7933F41E-56F8-41D6-A31C-4148A711EE93}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"; }
if ( -not $gpo_attrib.Contains("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]") ) { $gpo_attrib = $gpo_attrib + "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"; }
if ( -not $gpo_attrib.Contains("[{D76B9641-3288-4F75-942D-087DE603E3EA}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") ) { $gpo_attrib = $gpo_attrib + "[{D76B9641-3288-4F75-942D-087DE603E3EA}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"; }
if ( -not $gpo_attrib.Contains("[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]") ) { $gpo_attrib = $gpo_attrib + "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]"; }

$gpo_ldap_object.gPCMachineExtensionNames.Value = $gpo_attrib
$gpo_ldap_object.SetInfo()

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "BackgroundModeEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "PromptForDownloadLocation"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SavingBrowserHistoryDisabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "ComponentUpdatesEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "ThirdPartyBlockingEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RunAllFlashInAllowMode"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SuppressUnsupportedOSWarning"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SafeSitesFilterBehavior"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Disabled: 
Computer Configuration\Administrative Templates\Google\Google Chrome\Origins 
or hostname patterns for which restrictions on insecure origins should not apply"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Disabled: 
Computer Configuration\Administrative Templates\Google\Google Chrome\Disable 
Certificate Transparency enforcement for a list of Legacy Certificate Authorities"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Disabled: 
Computer Configuration\Administrative Templates\Google\Google Chrome\Disable 
Certificate Transparency enforcement for a list of URLs"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Disabled: 
Computer Configuration\Administrative Templates\Google\Google Chrome\Disable 
Certificate Transparency enforcement for a list of subjectPublicKeyInfo hashes"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultPluginsSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultNotificationsSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultWebBluetoothGuardSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultWebUsbGuardSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"
$param = "37"
$type = "STRING"
$value = "*"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Enabled with any needed values from the list: extension, hosted_app, platform_app, theme: 
Computer Configuration\Administrative Templates\Google\Google Chrome\Extensions\Configure allowed app/extension types"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\NativeMessagingBlocklist"
$param = "37"
$type = "STRING"
$value = "*"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "PasswordManagerEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AuthSchemes"
$type = "STRING"
$value = "negotiate,ntlm"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via Group Policy, make sure the following UI path is not configured with value '`"ProxyMode`": `"auto_detect`"': 
Computer Configuration\Administrative Templates\Google\Google Chrome\Proxy settings"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AllowOutdatedPlugins"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "CloudPrintProxyEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SitePerProcess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DownloadRestrictions"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DisableSafeBrowsingProceedAnyway"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RelaunchNotification"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RelaunchNotificationPeriod"
$type = "DWORD"
$value = 86400000

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RequireOnlineRevocationChecksForLocalAnchors"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "ChromeCleanupEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "BuiltInDnsClientEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Update"
$param = "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultCookiesSetting"
$type = "DWORD"
$value = 4

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "DefaultGeolocationSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "EnableMediaRouter"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "BlockThirdPartyCookies"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "MetricsReportingEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "ChromeCleanupReportingEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "BrowserSignin"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "TranslateEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "NetworkPredictionOptions"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SearchSuggestEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SpellCheckServiceEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AlternateErrorPagesEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "SyncDisabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "UrlKeyedAnonymizedDataCollectionEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AllowDeletingBrowserHistory"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostAllowRemoteAccessConnections"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostFirewallTraversal"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostAllowClientPairing"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostAllowRelayedConnection"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostRequireCurtain"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostAllowGnubbyAuth"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "RemoteAccessHostAllowUiAccessForRemoteAssistance"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via Group Policy, set the following UI path to 
Enabled and enter a domain (e.g. nodomain.local): 
Computer Configuration\Administrative Templates\Google\Google Chrome\Remote access\Configure the required domain names for remote access clients"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "CloudPrintSubmitEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "ImportSavedPasswords"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AutofillCreditCardEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome"
$param = "AutofillAddressEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value



