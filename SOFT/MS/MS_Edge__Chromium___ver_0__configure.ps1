# Take domain and policy name
$domain_name = Read-Host "Enter AD domain name"
$domain = Get-AdDomain $domain_name
$domain_sid = $domain.DomainSID
$gpo_name = Read-Host "Enter target Edge GPO name:[default is Couch_Edge]"
if ( $gpo_name -eq "" ) { $gpo_name = "Couch_Edge" }
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

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AdsSettingForIntrusiveAdsSites"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DownloadRestrictions"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AllowFileSelectionDialogs"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "MediaRouterCastAllowAllIPs"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportAutofillFormData"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportBrowserSettings"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportHomepage"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportPaymentInfo"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportSavedPasswords"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ImportSearchEngine"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "EnterpriseHardwarePlatformAPIEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AudioCaptureAllowed"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "VideoCaptureAllowed"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ScreenCaptureAllowed"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PersonalizationReportingEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BrowserNetworkTimeQueriesEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "LocalProvidersEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AudioSandboxEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "UserFeedbackAllowed"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ClickOnceEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DirectInvokeEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SSLErrorOverrideAllowed"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PaymentMethodQueryEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AllowPopupsDuringPageUnload"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PromptForDownloadLocation"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AutoImportAtFirstRun"
$type = "DWORD"
$value = 4

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BlockThirdPartyCookies"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "TrackingPrevention"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BrowserSignin"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ClearBrowsingDataOnExit"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ClearCachedImagesAndFilesOnExit"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "InPrivateModeAvailability"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ConfigureOnlineTextToSpeech"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Remove-GPRegistryValue -Name $gpo_name -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" -ValueName "HSTSPolicyBypassList" -ErrorAction SilentlyContinue


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\SyncTypesListDisabled"
$param = "11"
$type = "STRING"
$value = "passwords"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ConfigureShare"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BackgroundModeEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ExperimentationAndConfigurationServiceControl"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DeleteDataOnMigration"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SavingBrowserHistoryDisabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SyncDisabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DNSInterceptionChecksEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AutofillAddressEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AutofillCreditCardEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ComponentUpdatesEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AllowDeletingBrowserHistory"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "GloballyScopeHTTPAuthCacheEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BrowserGuestModeEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "NetworkPredictionOptions"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "EnableOnlineRevocationChecks"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ProactiveAuthEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "BrowserAddProfileEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "RendererCodeIntegrityEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ResolveNavigationErrorsUseWebService"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SearchSuggestEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "CommandLineFlagSecurityWarningsEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SitePerProcess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "TranslateEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "MetricsReportingEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ForceEphemeralProfiles"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ForceBingSafeSearch"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ForceGoogleSafeSearch"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "RunAllFlashInAllowMode"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "HideFirstRunExperience"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via GP, set the following UI path to Disabled 
Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Manage exposure of local IP addressess by WebRTC 
Note: This Group Policy path may not exist by default. It is provided by the Group Policy template MSEdge.admx/adml that can be downloaded from Microsoft here https://www.microsoft.com/ru-ru/edge/business/download.

Default: Disabled."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "RelaunchNotification"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "WebRtcLocalhostIpHandling"
$type = "STRING"
$value = "default_public_interface_only"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SendSiteInfoToImproveServices"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DiskCacheSize"
$type = "DWORD"
$value = 250609664

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "RelaunchNotificationPeriod"
$type = "DWORD"
$value = 86400000

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "ExternalProtocolDialogShowAlwaysOpenCheckbox"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "RequireOnlineRevocationChecksForLocalAnchors"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AlternateErrorPagesEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "EnableMediaRouter"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DefaultWebBluetoothGuardSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DefaultWebUsbGuardSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DefaultPluginsSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "DefaultGeolocationSetting"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AllowCrossOriginAuthPrompt"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "AuthSchemes"
$type = "STRING"
$value = "digest,ntlm,negotiate"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PasswordManagerEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SmartScreenEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SmartScreenPuaEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "SmartScreenForTrustedDownloadsEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PreventSmartScreenPromptOverride"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
$param = "PreventSmartScreenPromptOverrideForFiles"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value



