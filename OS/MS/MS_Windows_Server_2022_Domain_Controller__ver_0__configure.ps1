echo "MS Windows Server 2022 Domain Controller security policy GPO redactor"

# Take domain and policy name
$domain_name = Read-Host "Enter AD domain name"
$domain = Get-AdDomain $domain_name
$domain_sid = $domain.DomainSID
$gpo_name = Read-Host "Enter Windows Server 2022 Domain Controller Security GPO name:[default is Couch_Win2022DC]"
if ( $gpo_name -eq "" ) { $gpo_name = "Couch_Win2022DC" }
Get-GPO -Name $gpo_name -Domain $domain.DNSRoot
if ( ! $? ) { New-GPO -Name $gpo_name -Domain $domain.DNSRoot }

# Set paths
$gpo = Get-GPO -Name $gpo_name -Domain $domain.DNSRoot
$domain_name = $gpo.DomainName
$num = $gpo.Id.Guid
$gpo_path = "$env:WinDir\SYSVOL\sysvol\${domain_name}\Policies\{$num}"
$machine_inf_path = "$gpo_path\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
if ( !(Test-Path "$gpo_path\Machine\Microsoft") ) { New-Item -Path "$gpo_path\Machine\Microsoft" -type "directory" }
if ( !(Test-Path "$gpo_path\Machine\Microsoft\Windows NT") ) { New-Item -Path "$gpo_path\Machine\Microsoft\Windows NT" -type "directory" }
if ( !(Test-Path "$gpo_path\Machine\Microsoft\Windows NT\SecEdit") ) { New-Item -Path "$gpo_path\Machine\Microsoft\Windows NT\SecEdit" -type "directory" }
if ( !(Test-Path "$gpo_path\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf") )
{
    New-Item -Path "$gpo_path\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -type "file";
    $text = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1"
    [io.file]::WriteAllText($machine_inf_path,$text);
}
$audit_path = "$gpo_path\Machine\Microsoft\Windows NT\Audit\audit.csv"
if ( !(Test-Path "$gpo_path\Machine\Microsoft\Windows NT\Audit") ) { New-Item -Path "$gpo_path\Machine\Microsoft\Windows NT\Audit" -type "directory" }
if ( !(Test-Path "$gpo_path\Machine\Microsoft\Windows NT\Audit\audit.csv") ) { New-Item -Path "$gpo_path\Machine\Microsoft\Windows NT\Audit\audit.csv" -type "file"; "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value`r`n" | Set-Content -path $audit_path }

# Configure gPCMachineExtensionNames attribute
$gpo_search = ([adsisearcher]'(objectCategory=groupPolicyContainer)').FindAll() | where {$_.Properties.displayname -eq $gpo_name}
$ldap_query = $gpo_search.Path.replace('//','//localhost:389/')
$gpo_ldap_object = [ADSI]$ldap_query
$gpo_attrib = $gpo_ldap_object.gPCMachineExtensionNames.Value

if ( -not $gpo_attrib ) { $gpo_attrib = "" }

if ( -not $gpo_attrib.Contains("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") )
{
    $gpo_attrib = $gpo_attrib + "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
}

if ( -not $gpo_attrib.Contains("[{7933F41E-56F8-41D6-A31C-4148A711EE93}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") )
{
    $gpo_attrib = $gpo_attrib + "[{7933F41E-56F8-41D6-A31C-4148A711EE93}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
}

if ( -not $gpo_attrib.Contains("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]") )
{
    $gpo_attrib = $gpo_attrib + "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]";
}

if ( -not $gpo_attrib.Contains("[{D76B9641-3288-4F75-942D-087DE603E3EA}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]") )
{
    $gpo_attrib = $gpo_attrib + "[{D76B9641-3288-4F75-942D-087DE603E3EA}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
}

if ( -not $gpo_attrib.Contains("[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]") )
{
    $gpo_attrib = $gpo_attrib + "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";
}

$gpo_ldap_object.gPCMachineExtensionNames.Value = $gpo_attrib
$gpo_ldap_object.SetInfo()

#Set constants
$reg_types = @{'REG_DWORD'='4';'DWORD'='4';'STRING'='1';'REG_SZ'='1';'REG_MULTI_SZ'='7';'ARRAY'='7';'BINARY'='3';'REG_BINARY'='3';'BOOLEAN'='3'}
$cred_ids = @{"authenticated users"="*S-1-5-11";
"прошедшие проверку"="*S-1-5-11";
"users"="*S-1-5-32-545";
"пользователи"="*S-1-5-32-545";
"administrators"="*S-1-5-32-544";
"администраторы"="*S-1-5-32-544";
"guests"="*S-1-5-32-546";
"гости"="*S-1-5-32-546";
"enterprise domain controllers"="*S-1-5-9";
"контроллеры домена предприятия"="*S-1-5-9";
"service"="*S-1-5-6";
"служба"="*S-1-5-6";
"network service"="*S-1-5-20";
"local service"="*S-1-5-19";
"local system"="*S-1-5-18";
"system"="*S-1-5-18";
"система"="*S-1-5-18";
"remote desktop users"="*S-1-5-32-555";
"пользователи удаленного рабочего стола"="*S-1-5-32-555";
"domain admins"="*${domain_sid}-512";
"администраторы домена"="*${domain_sid}-512";
"schema admins"="*${domain_sid}-518";
"администраторы схемы"="*${domain_sid}-518";
"enterprise admins"="*${domain_sid}-519";
"администраторы предприятия"="*${domain_sid}-519";
"domain users"="*${domain_sid}-513";
"пользователи домена"="*${domain_sid}-513";
"backup operators"="*S-1-5-32-551";
"операторы архива"="*S-1-5-32-551";
"anonymous"="*S-1-5-7";
"nt virtual machine\virtual machines"="*S-1-5-83-0";
"local account"="*S-1-5-113";
"local account and member of administrators group"="*S-1-5-114";
"локальная учетная запись"="*S-1-5-113";
'локальная учетная запись и член группы "администраторы"'="*S-1-5-114";
"window manager\window manager group"="*S-1-5-90-0"
}
$values = @{ 'нет аудита'='0';
'успех'='1';
'отказ'='2';
'успех и отказ'='3';
'no audit'='0';
'success'='1';
'failure'='2';
'success and failure'='3'}
$guids = @{'audit ipsec driver'='{0cce9213-69ae-11d9-bed3-505054503030}';
'audit system integrity'='{0cce9212-69ae-11d9-bed3-505054503030}';
'audit security system extension'='{0cce9211-69ae-11d9-bed3-505054503030}';
'audit security state change'='{0cce9210-69ae-11d9-bed3-505054503030}';
'audit other system events'='{0cce9214-69ae-11d9-bed3-505054503030}';
'audit network policy server'='{0cce9243-69ae-11d9-bed3-505054503030}';
'audit other logon/logoff events'='{0cce921c-69ae-11d9-bed3-505054503030}';
'audit special logon'='{0cce921b-69ae-11d9-bed3-505054503030}';
'audit ipsec extended mode'='{0cce921a-69ae-11d9-bed3-505054503030}';
'audit ipsec quick mode'='{0cce9219-69ae-11d9-bed3-505054503030}';
'audit ipsec main mode'='{0cce9218-69ae-11d9-bed3-505054503030}';
'audit account lockout'='{0cce9217-69ae-11d9-bed3-505054503030}';
'audit logoff'='{0cce9216-69ae-11d9-bed3-505054503030}';
'audit logon'='{0cce9215-69ae-11d9-bed3-505054503030}';
'audit handle manipulation'='{0cce9223-69ae-11d9-bed3-505054503030}';
'audit detailed file share'='{0cce9244-69ae-11d9-bed3-505054503030}';
'audit other object access'='{0cce9227-69ae-11d9-bed3-505054503030}';
'audit filtering platform connection'='{0cce9226-69ae-11d9-bed3-505054503030}';
'audit filtering platform packet drop'='{0cce9225-69ae-11d9-bed3-505054503030}';
'audit file share'='{0cce9224-69ae-11d9-bed3-505054503030}';
'audit application generated'='{0cce9222-69ae-11d9-bed3-505054503030}';
'audit certification services'='{0cce9221-69ae-11d9-bed3-505054503030}';
'audit sam'='{0cce9220-69ae-11d9-bed3-505054503030}';
'audit kernel object'='{0cce921f-69ae-11d9-bed3-505054503030}';
'audit registry'='{0cce921e-69ae-11d9-bed3-505054503030}';
'audit file system'='{0cce921d-69ae-11d9-bed3-505054503030}';
'audit non sensitive privilege use'='{0cce9229-69ae-11d9-bed3-505054503030}';
'audit other privilege use events'='{0cce922a-69ae-11d9-bed3-505054503030}';
'audit sensitive privilege use'='{0cce9228-69ae-11d9-bed3-505054503030}';
'audit dpapi activity'='{0cce922d-69ae-11d9-bed3-505054503030}';
'audit process termination'='{0cce922c-69ae-11d9-bed3-505054503030}';
'audit process creation'='{0cce922b-69ae-11d9-bed3-505054503030}';
'audit rpc events'='{0cce922e-69ae-11d9-bed3-505054503030}';
'audit mpssvc rule-level policy change'='{0cce9232-69ae-11d9-bed3-505054503030}';
'audit other policy change events'='{0cce9234-69ae-11d9-bed3-505054503030}';
'audit filtering platform policy change'='{0cce9233-69ae-11d9-bed3-505054503030}';
'audit audit policy change'='{0cce922f-69ae-11d9-bed3-505054503030}';
'audit authorization policy change'='{0cce9231-69ae-11d9-bed3-505054503030}';
'audit authentication policy change'='{0cce9230-69ae-11d9-bed3-505054503030}';
'audit other account management events'='{0cce923a-69ae-11d9-bed3-505054503030}';
'audit application group management'='{0cce9239-69ae-11d9-bed3-505054503030}';
'audit distribution group management'='{0cce9238-69ae-11d9-bed3-505054503030}';
'audit security group management'='{0cce9237-69ae-11d9-bed3-505054503030}';
'audit computer account management'='{0cce9236-69ae-11d9-bed3-505054503030}';
'audit user account management'='{0cce9235-69ae-11d9-bed3-505054503030}';
'audit detailed directory service replication'='{0cce923e-69ae-11d9-bed3-505054503030}';
'audit directory service access'='{0cce923b-69ae-11d9-bed3-505054503030}';
'audit directory service replication'='{0cce923d-69ae-11d9-bed3-505054503030}';
'audit directory service changes'='{0cce923c-69ae-11d9-bed3-505054503030}';
'audit other account logon events'='{0cce9241-69ae-11d9-bed3-505054503030}';
'audit kerberos service ticket operations'='{0cce9240-69ae-11d9-bed3-505054503030}';
'audit credential validation'='{0cce923f-69ae-11d9-bed3-505054503030}';
'audit kerberos authentication service'='{0cce9242-69ae-11d9-bed3-505054503030}';
'audit removable storage'='{0cce9245-69ae-11d9-bed3-505054503030}';
'audit central access policy staging'='{0cce9246-69ae-11d9-bed3-505054503030}';
'audit user/device claims'='{0cce9247-69ae-11d9-bed3-505054503030}';
'audit pnp activity'='{0cce9248-69ae-11d9-bed3-505054503030}';
'audit group membership'='{0cce9249-69ae-11d9-bed3-505054503030}';
'аудит проверки учетных данных'='{0cce923f-69ae-11d9-bed3-505054503030}';
'аудит службы проверки подлинности kerberos'='{0cce9242-69ae-11d9-bed3-505054503030}';
'аудит операций с билетами службы kerberos'='{0cce9240-69ae-11d9-bed3-505054503030}';
'аудит других событий входа учетных записей'='{0cce9241-69ae-11d9-bed3-505054503030}';
'аудит управления группами приложений'='{0cce9239-69ae-11d9-bed3-505054503030}';
'аудит управления учетными записями компьютеров'='{0cce9236-69ae-11d9-bed3-505054503030}';
'аудит управления группами распространения'='{0cce9238-69ae-11d9-bed3-505054503030}';
'аудит других событий управления учетными записями'='{0cce923a-69ae-11d9-bed3-505054503030}';
'аудит управления группами безопасности'='{0cce9237-69ae-11d9-bed3-505054503030}';
'аудит управления учетными записями пользователей'='{0cce9235-69ae-11d9-bed3-505054503030}';
'аудит активности dpapi'='{0cce922d-69ae-11d9-bed3-505054503030}';
'аудит создания процессов'='{0cce922b-69ae-11d9-bed3-505054503030}';
'аудит завершения процессов'='{0cce922c-69ae-11d9-bed3-505054503030}';
'аудит событий rpc'='{0cce922e-69ae-11d9-bed3-505054503030}';
'аудит подробной репликации службы каталогов'='{0cce923e-69ae-11d9-bed3-505054503030}';
'аудит доступа к службе каталогов'='{0cce923b-69ae-11d9-bed3-505054503030}';
'аудит изменения службы каталогов'='{0cce923c-69ae-11d9-bed3-505054503030}';
'аудит репликации службы каталогов'='{0cce923d-69ae-11d9-bed3-505054503030}';
'аудит блокировки учетных записей'='{0cce9217-69ae-11d9-bed3-505054503030}';
'аудит заявок пользователей или устройств на доступ'='{0cce9247-69ae-11d9-bed3-505054503030}';
'аудит расширенного режима ipsec'='{0cce921a-69ae-11d9-bed3-505054503030}';
'аудит основного режима ipsec'='{0cce9218-69ae-11d9-bed3-505054503030}';
'аудит быстрого режима ipsec'='{0cce9219-69ae-11d9-bed3-505054503030}';
'аудит выхода из системы'='{0cce9216-69ae-11d9-bed3-505054503030}';
'аудит входа в систему'='{0cce9215-69ae-11d9-bed3-505054503030}';
'аудит сервера политики сети'='{0cce9243-69ae-11d9-bed3-505054503030}';
'аудит других событий входа и выхода'='{0cce921c-69ae-11d9-bed3-505054503030}';
'аудит специального входа'='{0cce921b-69ae-11d9-bed3-505054503030}';
'аудит событий, создаваемых приложениями'='{0cce9222-69ae-11d9-bed3-505054503030}';
'аудит служб сертификации'='{0cce9221-69ae-11d9-bed3-505054503030}';
'аудит сведений об общем файловом ресурсе'='{0cce9244-69ae-11d9-bed3-505054503030}';
'аудит общего файлового ресурса'='{0cce9224-69ae-11d9-bed3-505054503030}';
'аудит файловой системы'='{0cce921d-69ae-11d9-bed3-505054503030}';
'аудит подключения платформы фильтрации'='{0cce9226-69ae-11d9-bed3-505054503030}';
'аудит отбрасывания пакетов платформой фильтрации'='{0cce9225-69ae-11d9-bed3-505054503030}';
'аудит работы с дескрипторами'='{0cce9223-69ae-11d9-bed3-505054503030}';
'аудит объектов ядра'='{0cce921f-69ae-11d9-bed3-505054503030}';
'аудит других событий доступа к объектам'='{0cce9227-69ae-11d9-bed3-505054503030}';
'аудит реестра'='{0cce921e-69ae-11d9-bed3-505054503030}';
'аудит съемного носителя'='{0cce9245-69ae-11d9-bed3-505054503030}';
'аудит диспетчера учетных записей безопасности'='{0cce9220-69ae-11d9-bed3-505054503030}';
'аудит сверки с централизованной политикой доступа'='{0cce9246-69ae-11d9-bed3-505054503030}';
'аудит изменения политики аудита'='{0cce922f-69ae-11d9-bed3-505054503030}';
'аудит изменения политики проверки подлинности'='{0cce9230-69ae-11d9-bed3-505054503030}';
'аудит изменения политики авторизации'='{0cce9231-69ae-11d9-bed3-505054503030}';
'аудит изменения политики платформы фильтрации'='{0cce9233-69ae-11d9-bed3-505054503030}';
'аудит изменения политики на уровне правил mpssvc'='{0cce9232-69ae-11d9-bed3-505054503030}';
'аудит других событий изменения политики'='{0cce9234-69ae-11d9-bed3-505054503030}';
'аудит использования привилегий, не затрагивающих конфиденциальные данные'='{0cce9229-69ae-11d9-bed3-505054503030}';
'аудит других событий использования привилегий'='{0cce922a-69ae-11d9-bed3-505054503030}';
'аудит использования привилегий, затрагивающих конфиденциальные данные'='{0cce9228-69ae-11d9-bed3-505054503030}';
'аудит драйвера ipsec'='{0cce9213-69ae-11d9-bed3-505054503030}';
'аудит других системных событий'='{0cce9214-69ae-11d9-bed3-505054503030}';
'аудит изменения состояния безопасности'='{0cce9210-69ae-11d9-bed3-505054503030}';
'аудит расширения системы безопасности'='{0cce9211-69ae-11d9-bed3-505054503030}';
'аудит целостности системы'='{0cce9212-69ae-11d9-bed3-505054503030}';
'pnp-действие аудита'='{0cce9248-69ae-11d9-bed3-505054503030}';
'членство в группе аудита'='{0cce9249-69ae-11d9-bed3-505054503030}'
}

Write-Output "[Manual] In Control Panel/Add or Remove Programs should click over the Add/Remove Windows Components button and uncheck all Windows components that are not necessary."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] In Control Panel / Add or Remove Programs, select the programs that should be removed and then click the Remove button."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Remove all unnecessary operating systems."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Install the latest available stable build."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Install all security hotfixes after service pack for the Operating System."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To establish the recommended configuration via GP, set the following UI path to Enabled: 
Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Configure Automatic Updates
The sub-setting `"Configure automatic updating:`" has 4 possible values – all of them are valid depending on specific organizational needs, a value of 4 - Auto download and schedule the install is recommended if feasible.

Default: Enabled: 3 - Auto download and notify for install."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "UseWUServer"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$wsus_serv = Read-Host "Enter update status service address (WSUS) with HTTPS connection scheme (example: https://IntranetStat01.org.local)"

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate"
$param = "WUStatusServer"
$type = "String"
$value = $wsus_serv

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$wsus_serv = Read-Host "Enter update service address (WSUS) with HTTPS connection scheme (example: https://IntranetUpd01.org.local)"

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate"
$param = "WUServer"
$type = "String"
$value = $wsus_serv

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "ManagePreviewBuildsPolicyValue"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "DeferFeatureUpdates"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "DeferFeatureUpdatesPeriodInDays"
$type = "DWORD"
$value = 180

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "DeferQualityUpdates"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$param = "DeferQualityUpdatesPeriodInDays"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$svc_name = "SharedAccess"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "hidserv"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "Fax"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "TrkWks"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "Wlansvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "dot3svc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "FontCache3.0.0.0"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "seclogon"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "NetTcpPortSharing"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "AeLookupSvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WebClient"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "RemoteAccess"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "RemoteRegistry"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WMPNetworkSvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "ehstart"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "ehSched"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "ehRecvr"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WPCSvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "TabletInputService"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "sppuinotify"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "UI0Detect"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WdiServiceHost"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "DFSR"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "UxSms"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "wbengine"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "SNMP"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "RasMan"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "RasAuto"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "TapiSrv"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "ShellHWDetection"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "SNMPTRAP"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "wercplsupport"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "PNRPAutoReg"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "p2pimsvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "PNRPsvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "CscService"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "lltdsvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "fdPHost"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "FDResPub"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "ALG"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "p2psvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "SysMain"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "Mcx2Svc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "SSDPSRV"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "UsbStor"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "BthHFSrv"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "bthserv"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "Browser"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "MapsBroker"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "lfsvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "HomeGroupListener"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "HomeGroupProvider"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "irmon"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "MSiSCSI"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "SessionEnv"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "RpcLocator"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "upnphost"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WerSvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "Wecsvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WpnService"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinHttpAutoProxySvc"
$param = "Start"
$type = "DWORD"
$value = 4

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$svc_name = "icssvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "IISADMIN"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "LxssManager"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "FTPSVC"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "simptcp"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "WMSvc"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "W3SVC"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$svc_name = "mrxsmb10"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$param = "SMB1"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$svc_name = "Spooler"
$svc_opt = "4"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Service General Setting\]" ) ) { $text = $text + "`r`n[Service General Setting]" }
$text = $text -Replace "\r\n`"?$svc_name`"?,.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Service General Setting\]", "[Service General Setting]`r`n`"$svc_name`",$svc_opt,`"`""
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "NoConnectedUser"
$m_rv_type_name = "DWORD"
$m_rv_value = "3"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "LimitBlankPasswordUse"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$local_admin_name = Read-Host "Enter new name for local Administrator account"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\nNewAdministratorName =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`nNewAdministratorName = `"$local_admin_name`""
[io.file]::WriteAllText($machine_inf_path,$text)


$local_guest_name = Read-Host "Enter new name for local Guest account"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\nNewGuestName =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`nNewGuestName = `"$local_guest_name`""
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "scenoapplylegacyauditpolicy"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "crashonauditfail"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$m_rv_name = "AllocateDASD"
$m_rv_type_name = "REG_SZ"
$m_rv_value = "`"0`""

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
$m_rv_name = "AddPrinterDrivers"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "SubmitControl"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\NTDS\Parameters"
$m_rv_name = "ldapserverintegrity"
$m_rv_type_name = "DWORD"
$m_rv_value = "2"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "RefusePasswordChange"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


Write-Output "[Manual] To establish the recommended configuration via GP, set the following UI path to Not Configured: 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain controller: Allow vulnerable Netlogon secure channel connections

Default: Not Configured. (No machines or trust accounts are explicitly exempt from secure RPC with Netlogon secure channel connections enforcement.)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$param = "LdapEnforceChannelBinding"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "requiresignorseal"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "sealsecurechannel"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "signsecurechannel"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "disablepasswordchange"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "MaximumPasswordAge"
$m_rv_type_name = "DWORD"
$m_rv_value = "90"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netlogon\Parameters"
$m_rv_name = "requirestrongkey"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "DisableCAD"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "DontDisplayLastUserName"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "InactivityTimeoutSecs"
$m_rv_type_name = "DWORD"
$m_rv_value = "900"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "LegalNoticeText"
$m_rv_type_name = "REG_SZ"
$m_rv_value = "`"Authorized access only. All activity may be registered and monitored.`""

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$m_rv_name = "passwordexpirywarning"
$m_rv_type_name = "DWORD"
$m_rv_value = "7"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$m_rv_name = "scremoveoption"
$m_rv_type_name = "REG_SZ"
$m_rv_value = "`"1`""

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$m_rv_name = "RequireSecuritySignature"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$m_rv_name = "EnableSecuritySignature"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$m_rv_name = "EnablePlainTextPassword"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$idle_timeout = $null
$idle_timeout = Read-Host "Enter timeout for idle sessions in minutes (default 15)"
if (!$idle_timeout) {$idle_timeout="15"}

$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "autodisconnect"
$m_rv_type_name = "DWORD"
$m_rv_value = [string[]]$idle_timeout

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "requiresecuritysignature"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "enablesecuritysignature"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = " EnableForcedLogoff"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$m_rv_name = "AutoAdminLogon"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip6\Parameters"
$m_rv_name = "DisableIPSourceRouting"
$m_rv_type_name = "DWORD"
$m_rv_value = "2"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip\Parameters"
$m_rv_name = "DisableIPSourceRouting"
$m_rv_type_name = "DWORD"
$m_rv_value = "2"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip\Parameters"
$m_rv_name = "EnableICMPRedirect"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip\Parameters"
$m_rv_name = "KeepAliveTime"
$m_rv_type_name = "DWORD"
$m_rv_value = "300000"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Netbt\Parameters"
$m_rv_name = "NoNameReleaseOnDemand"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip\Parameters"
$m_rv_name = "PerformRouterDiscovery"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Session Manager"
$m_rv_name = "SafeDllSearchMode"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$m_rv_name = "ScreenSaverGracePeriod"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip6\Parameters"
$m_rv_name = "TcpMaxDataRetransmissions"
$m_rv_type_name = "DWORD"
$m_rv_value = "3"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Tcpip\Parameters"
$m_rv_name = "TcpMaxDataRetransmissions"
$m_rv_type_name = "DWORD"
$m_rv_value = "3"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\Eventlog\Security"
$m_rv_name = "WarningLevel"
$m_rv_type_name = "DWORD"
$m_rv_value = "90"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\nLSAAnonymousNameLookup =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`nLSAAnonymousNameLookup = 0"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "disabledomaincreds"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "EveryoneIncludesAnonymous"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "NullSessionPipes"
$m_rv_type_name = "REG_MULTI_SZ"
$m_rv_value = "netlogon,samr,lsarpc"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
$m_rv_name = "Machine"
$m_rv_type_name = "REG_MULTI_SZ"
$m_rv_value = "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
$m_rv_name = "Machine"
$m_rv_type_name = "REG_MULTI_SZ"
$m_rv_value = "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog,System\CurrentControlSet\Services\CertSvc,System\CurrentControlSet\Services\WINS"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "restrictnullsessaccess"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LanManServer\Parameters"
$m_rv_name = "NullSessionShares"
$m_rv_type_name = "REG_MULTI_SZ"
$m_rv_value = ""

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "ForceGuest"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "SYSTEM\CurrentControlSet\Control\Lsa"
$m_rv_name = "UseMachineId"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$m_rv_name = "AllowNullSessionFallback"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa\pku2u"
$m_rv_name = "AllowOnlineID"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$m_rv_name = "SupportedEncryptionTypes"
$m_rv_type_name = "DWORD"
$m_rv_value = "24"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "NoLMHash"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa"
$m_rv_name = "LmCompatibilityLevel"
$m_rv_type_name = "DWORD"
$m_rv_value = "5"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Services\LDAP"
$m_rv_name = "LDAPClientIntegrity"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa\MSV1_0"
$m_rv_name = "NTLMMinClientSec"
$m_rv_type_name = "DWORD"
$m_rv_value = "537395248"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Lsa\MSV1_0"
$m_rv_name = "NTLMMinServerSec"
$m_rv_type_name = "DWORD"
$m_rv_value = "537395248"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "ShutdownWithoutLogon"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Session Manager\Kernel"
$m_rv_name = "ObCaseInsensitive"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "System\CurrentControlSet\Control\Session Manager"
$m_rv_name = "ProtectionMode"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "FilterAdministratorToken"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "ConsentPromptBehaviorAdmin"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "ConsentPromptBehaviorUser"
$m_rv_type_name = "DWORD"
$m_rv_value = "0"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "EnableInstallerDetection"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "EnableSecureUIAPaths"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "EnableLUA"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "PromptOnSecureDesktop"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$m_rv_path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
$m_rv_name = "EnableVirtualization"
$m_rv_type_name = "DWORD"
$m_rv_value = "1"

$m_rv_path_boost = $m_rv_path.replace('\','\\')
$m_rv_type = $reg_types[$m_rv_type_name.ToUpper()]

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Registry Values\]" ) ) { $text = $text + "`r`n[Registry Values]" }
$text = $text -Replace "\r\nMACHINE\\$m_rv_path_boost\\$m_rv_name=.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[Registry Values\]", "[Registry Values]`r`nMACHINE\$m_rv_path\$m_rv_name=$m_rv_type,$m_rv_value"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "TrustedCredManAccessPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "NetworkLogonRight"
$cred_names = "Authenticated Users;Прошедшие проверку;Administrators;Администраторы;enterprise domain controllers"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "TcbPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "MachineAccountPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "IncreaseQuotaPrivilege"
$cred_names = "Administrators;Администраторы;LOCAL SERVICE;NETWORK SERVICE"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "InteractiveLogonRight"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "RemoteInteractiveLogonRight"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "BackupPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "SystemtimePrivilege"
$cred_names = "Administrators;Администраторы;LOCAL SERVICE"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "TimeZonePrivilege"
$cred_names = "Administrators;Администраторы;LOCAL SERVICE"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "CreatePagefilePrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "CreateTokenPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "CreateGlobalPrivilege"
$cred_names = "Administrators;Администраторы;LOCAL SERVICE;NETWORK SERVICE;SERVICE;СЛУЖБА"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "CreatePermanentPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "CreateSymbolicLinkPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DebugPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DenyNetworkLogonRight"
$cred_names ="Guests"
$local_admin_sid = '*'+(Get-ADDomain).DomainSID.value+'-500'

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids + $local_admin_sid
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DenyBatchLogonRight"
$cred_names = "Guests"
$local_admin_sid = '*'+(Get-ADDomain).DomainSID.value+'-500'

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids + $local_admin_sid
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DenyServiceLogonRight"
$cred_names = "Guests"
$local_admin_sid = '*'+(Get-ADDomain).DomainSID.value+'-500'

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids + $local_admin_sid
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DenyInteractiveLogonRight"
$cred_names = "Guests"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "DenyRemoteInteractiveLogonRight"
$cred_names = "Guests"
$local_admin_sid = '*'+(Get-ADDomain).DomainSID.value+'-500'

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids + $local_admin_sid
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "EnableDelegationPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "RemoteShutdownPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "AuditPrivilege"
$cred_names = "LOCAL SERVICE;NETWORK SERVICE"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "ImpersonatePrivilege"
$cred_names = "Administrators;Администраторы;LOCAL SERVICE;NETWORK SERVICE;SERVICE;СЛУЖБА"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "IncreaseBasePriorityPrivilege"
$cred_names = "Administrators;Администраторы;Window Manager\Window Manager Group"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "LoadDriverPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "LockMemoryPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "BatchLogonRight"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "SecurityPrivilege"
$cred_names = "Administrators;Администраторы;Exchange Servers"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "RelabelPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "SystemEnvironmentPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "ManageVolumePrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "ProfileSingleProcessPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "SystemProfilePrivilege"
$cred_names = "Administrators;Администраторы;NT SERVICE\WdiServiceHost"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "AssignPrimaryTokenPrivilege"
$cred_names = "LOCAL SERVICE;NETWORK SERVICE"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "RestorePrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "ShutdownPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "SyncAgentPrivilege"
$cred_names = ""

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$priv_name = "TakeOwnershipPrivilege"
$cred_names = "Administrators;Администраторы"

$priv_ids = @()
foreach ( $cred in $cred_names.split(';') ) { if ( $cred_ids.contains($cred.ToLower()) ) { $priv_ids = $priv_ids + $cred_ids[$cred.ToLower()] } else { $priv_ids = $priv_ids + $cred } }
$priv_ids = $priv_ids | select -uniq

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[Privilege Rights\]" ) ) { $text = $text + "`r`n[Privilege Rights]" }
$text = $text -Replace "\r\nSe$priv_name =.*?(\r\n|$)", "`$1"
$priv_string = $priv_ids -join ","
$text = $text -Replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSe$priv_name = $priv_string"
[io.file]::WriteAllText($machine_inf_path,$text)


$subcat = "audit credential validation"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit kerberos authentication service"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit kerberos service ticket operations"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit application group management"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit computer account management"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit distribution group management"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit other account management events"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit security group management"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit user account management"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit pnp activity"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit process creation"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit directory service access"
$setting = "Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit directory service changes"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit account lockout"
$setting = "Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit group membership"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit logoff"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit logon"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit other logon/logoff events"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit special logon"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit detailed file share"
$setting = "Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit file share"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit other object access"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit removable storage"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit audit policy change"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit authentication policy change"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit authorization policy change"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit mpssvc rule-level policy change"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit other policy change events"
$setting = "Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit sensitive privilege use"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit ipsec driver"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit other system events"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit security state change"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit security system extension"
$setting = "Success"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


$subcat = "audit system integrity"
$setting = "Success and Failure"

$setting_value = $values[$setting.ToLower()]
$subcat_guid = $guids[$subcat.ToLower()]

$text = Get-Content -Raw $audit_path
$text = $text -Replace "\r\n.*?$subcat_guid.*?(\r\n|$)", "`$1"
$text = $text + ",System,$subcat,$subcat_guid,$setting,,$setting_value`r`n"
[io.file]::WriteAllText($audit_path,$text)


Write-Output "[Manual] Configure System ACL for Application log file (ex., %SystemRoot%\System32\Winevt\Logs\Application.evtx) and set audit all events for Everyone.
Open file Properties->Security->Advanced->Audit and set audit all events for Everyone or run the following PowerShell commands:
`$AuditUser = [Security.Principal.NTAccount]'Everyone'       # 'Все' на русскоязычных системах
`$AuditRules = [System.Security.AccessControl.FileSystemRights]'FullControl'
`$AuditType = [System.Security.AccessControl.AuditFlags]'Success,Failure'
`$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule(`$AuditUser,`$AuditRules,`"None`",`"None`",`$AuditType)
`$path = `"`$env:SystemRoot\System32\Winevt\Logs\Application.evtx`"
`$ACL = Get-Acl `$path -Audit
`$ACL.AddAuditRule(`$AccessRule)
`$ACL | Set-Acl `$path"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Configure System ACL for Security log file (ex., %SystemRoot%\System32\Winevt\Logs\Security.evtx) and set audit all events for Everyone.
Open file Properties->Security->Advanced->Audit and set audit all events for Everyone or run the following PowerShell commands:
`$AuditUser = [Security.Principal.NTAccount]'Everyone'       # 'Все' на русскоязычных системах
`$AuditRules = [System.Security.AccessControl.FileSystemRights]'FullControl'
`$AuditType = [System.Security.AccessControl.AuditFlags]'Success,Failure'
`$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule(`$AuditUser,`$AuditRules,`"None`",`"None`",`$AuditType)
`$path = `"`$env:SystemRoot\System32\Winevt\Logs\Security.evtx`"
`$ACL = Get-Acl `$path -Audit
`$ACL.AddAuditRule(`$AccessRule)
`$ACL | Set-Acl `$path"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Configure System ACL for System log file (ex., %SystemRoot%\System32\Winevt\Logs\System.evtx) and set audit all events for Everyone.
Open file Properties->Security->Advanced->Audit and set audit all events for Everyone or run the following PowerShell commands:
`$AuditUser = [Security.Principal.NTAccount]'Everyone'       # 'Все' на русскоязычных системах
`$AuditRules = [System.Security.AccessControl.FileSystemRights]'FullControl'
`$AuditType = [System.Security.AccessControl.AuditFlags]'Success,Failure'
`$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule(`$AuditUser,`$AuditRules,`"None`",`"None`",`$AuditType)
`$path = `"`$env:SystemRoot\System32\Winevt\Logs\System.evtx`"
`$ACL = Get-Acl `$path -Audit
`$ACL.AddAuditRule(`$AccessRule)
`$ACL | Set-Acl `$path"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Configure System ACLs for files and folders with critical information."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$param = "PasswordHistorySize"
$value = "5"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "MaximumPasswordAge"
$value = "90"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "MinimumPasswordAge"
$value = "1"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "MinimumPasswordLength"
$value = "8"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "PasswordComplexity"
$value = "1"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "ClearTextPassword"
$value = "0"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "LockoutDuration"
$value = "120"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "LockoutBadCount"
$value = "5"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$param = "ResetLockoutCount"
$value = "120"

$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\n$param =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`n$param = $value"
[io.file]::WriteAllText($machine_inf_path,$text)


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application"
$param = "Retention"
$type = "STRING"
$value = "0"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application"
$param = "MaxSize"
$type = "DWORD"
$value = 51200

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security"
$param = "Retention"
$type = "STRING"
$value = "0"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security"
$param = "MaxSize"
$type = "DWORD"
$value = 204800

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup"
$param = "Retention"
$type = "STRING"
$value = "0"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup"
$param = "MaxSize"
$type = "DWORD"
$value = 51200

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System"
$param = "Retention"
$type = "STRING"
$value = "0"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System"
$param = "MaxSize"
$type = "DWORD"
$value = 51200

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Application"
$param = "RestrictGuestAccess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Security"
$param = "RestrictGuestAccess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Setup"
$param = "RestrictGuestAccess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\System"
$param = "RestrictGuestAccess"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization"
$param = "NoLockScreenCamera"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization"
$param = "NoLockScreenSlideshow"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization"
$param = "AllowInputPersonalization"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "AllowOnlineTips"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$param = "DisableExceptionChainValidation"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters"
$param = "NodeType"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
$param = "UseLogonCredential"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$param = "Enablemulticast"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "EnableFontProviders"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$param = "AllowInsecureGuestAuth"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "allowlltdioondomain"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "allowlltdioonpublicnet"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "enablelltdio"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "prohibitlltdioonprivatenet"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "allowrspndrondomain"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "allowrspndronpublicnet"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "enablerspndr"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD"
$param = "prohibitrspndronprivatenet"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Peernet"
$param = "Disabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections"
$param = "NC_AllowNetBridge_NLA"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections"
$param = "nc_showsharedaccessui"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections"
$param = "NC_StdDomainUserSetLocation"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$param = "\\*\NETLOGON"
$type = "STRING"
$value = "RequireMutualAuthentication=1,RequireIntegrity=1"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$param = "\\*\SYSVOL"
$type = "STRING"
$value = "RequireMutualAuthentication=1,RequireIntegrity=1"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
$param = "DisabledComponents"
$type = "DWORD"
$value = 255

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars"
$param = "EnableRegistrars"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\UI"
$param = "DisableWcnUi"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$param = "fMinimizeConnections"
$type = "DWORD"
$value = 3

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$param = "NoCloudApplicationNotification"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$param = "ProcessCreationIncludeCmdLine_Enabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
$param = "AllowEncryptionOracle"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
$param = "AllowProtectedCreds"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
$param = "PreventDeviceMetadataFromNetwork"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch"
$param = "DriverLoadPolicy"
$type = "DWORD"
$value = 3

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$param = "NoBackgroundPolicy"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$param = "NoGPOListChanges"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "EnableCdp"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$param = "DisableBkGndGroupPolicy"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers"
$param = "DisableWebPnPDownload"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC"
$param = "PreventHandwritingDataSharing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports"
$param = "PreventHandwritingErrorReports"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard"
$param = "ExitOnMSICW"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoWebServices"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers"
$param = "DisableHTTPPrinting"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration Wizard Control"
$param = "NoRegistration"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion"
$param = "DisableContentFileUpdates"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoOnlinePrintsWizard"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoPublishingWizard"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client"
$param = "CEIP"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows"
$param = "CEIPEnable"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting"
$param = "Disabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting"
$param = "DoReport"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
$param = "DevicePKInitBehavior"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
$param = "DevicePKInitEnabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
$param = "DeviceEnumerationPolicy"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Control Panel\International"
$param = "BlockUserInputMethodsForSignIn"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "BlockUserFromShowingAccountDetailsOnSignin"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System"
$param = "DontDisplayNetworkSelectionUI"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System"
$param = "DontEnumerateConnectedUsers"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System"
$param = "DisableLockScreenAppNotifications"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "BlockDomainPicturePassword"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "AllowDomainPINLogon"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "AllowCrossDeviceClipboard"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "UploadUserActivities"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$param = "DCSettingIndex"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$param = "ACSettingIndex"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$param = "DCSettingIndex"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$param = "ACSettingIndex"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services"
$param = "fAllowUnsolicited"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services"
$param = "fAllowToGetHelp"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
$param = "DisableQueryRemoteServer"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
$param = "ScenarioExecutionEnabled"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo"
$param = "DisabledByGroupPolicy"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
$param = "Enabled"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
$param = "AllowSharedLocalAppData"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$param = "MSAOptional"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer"
$param = "NoAutoplayfornonVolume"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoAutorun"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoDriveTypeAutoRun"
$type = "DWORD"
$value = 255

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
$param = "EnhancedAntiSpoofing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera"
$param = "AllowCamera"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$param = "DisableConsumerAccountStateContent"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$param = "DisableWindowsConsumerFeatures"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect"
$param = "RequirePinForPairing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI"
$param = "DisablePasswordReveal"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$param = "EnumerateAdministrators"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] To establish the recommended configuration via GP, set the following UI path to Enabled: Diagnostic data off (not recommended) or Enabled: Send required diagnostic data: 
Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Diagnostic Data
Note: This Group Policy path may not exist by default. It is provided by the Group Policy template DataCollection.admx/adml that is included with the Microsoft Windows 11 Release 21H2 Administrative Templates (or newer).
Note #2: In older Microsoft Windows Administrative Templates, this setting was initially named Allow Telemetry, but it was renamed to Allow Diagnostic Data starting with the Windows 11 Release 21H2 Administrative Templates.

Default: Disabled. (The device will send required diagnostic data and the end user can choose whether to send optional diagnostic data from the Settings app.)"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$param = "DoNotShowFeedbackNotifications"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
$param = "AllowBuildPreview"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer"
$param = "NoDataExecutionPrevention"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer"
$param = "NoHeapTerminationOnCorruption"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "PreXPSP2ShellProtocolBehavior"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
$param = "DisableLocation"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging"
$param = "AllowMessageSync"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
$param = "DisableUserAuth"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
$param = "DisableFileSyncNGSC"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$param = "DisableEnclosureDownload"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$param = "AllowCloudSearch"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$param = "AllowIndexingEncryptedStoresOrItems"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
$param = "NoGenTicket"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$param = "LocalSettingOverrideSpynetReporting"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
$param = "SpynetReporting"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$param = "DisableBehaviorMonitoring"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
$param = "DisableGenericRePorts"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$param = "DisableRemovableDriveScanning"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$param = "DisableEmailScanning"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$param = "DisableScriptScanning"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$param = "DisableIOAVProtection"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$param = "DisableRealtimeMonitoring"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine"
$param = "EnableFileHashComputation"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$param = "ExploitGuard_ASR_Rules"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "26190899-1602-49e8-8b27-eb1d0a1ce869"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "3b576869-a4ec-4529-8536-b80a7769e899"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "d3e037e1-3eb8-44c8-a917-57927947596d"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$param = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
$param = "EnableNetworkProtection"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
$param = "PUAProtection"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
$param = "DisableAntiSpyware"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "enablesmartscreen"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System"
$param = "shellsmartscreenlevel"
$type = "STRING"
$value = "Block"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
$param = "AllowSuggestedAppsInWindowsInkWorkspace"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
$param = "AllowWindowsInkWorkspace"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer"
$param = "EnableUserControl"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer"
$param = "AlwaysInstallElevated"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer"
$param = "SafeForScripting"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$param = "DisableAutomaticRestartSignOn"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$param = "EnableScriptBlockLogging"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$param = "EnableTranscripting"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
$param = "AllowRemoteShellAccess"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
$param = "DisallowExploitProtectionOverride"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$param = "RestrictDriverInstallationToAdministrators"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$param = "DoHPolicy"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers"
$param = "RegisterSpoolerRemoteRpcEndPoint"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$param = "NoWarningNoElevationOnInstall"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$param = "UpdatePromptSettings"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM"
$param = "SamNGCKeyROCAValidation"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall"
$param = "DisablePushToInstall"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$param = "DisableOneSettingsDownloads"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\DataCollection"
$param = "EnableOneSettingsAuditing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$param = "LimitDiagnosticLogCollection"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$param = "LimitDumpCollection"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "DisablePasswordSaving"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fSingleSessionPerUser"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fDisableCcm"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fDisableCdm"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fDisableLPT"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fDisablePNPRedir"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "EnableUiaRedirection"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fDisableLocationRedir"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fPromptForPassword"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "fEncryptRPCTraffic"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "SecurityLayer"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "UserAuthentication"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "MinEncryptionLevel"
$type = "DWORD"
$value = 3

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$idle_timeout = $null
$idle_timeout = Read-Host "Enter timeout for idle sessions in minutes (default 15)"
$idle_timeout = $idle_timeout -as [int]
if (!$idle_timeout) {$idle_timeout=15}

$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "MaxIdleTime"
$type = "DWORD"
$value = $idle_timeout * 60000

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "MaxDisconnectionTime"
$type = "DWORD"
$value = 60000

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "DeleteTempDirsOnExit"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services"
$param = "PerSessionTempDir"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client"
$param = "AllowBasic"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client"
$param = "AllowUnencryptedTraffic"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client"
$param = "AllowDigest"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service"
$param = "AllowBasic"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service"
$param = "AllowAutoConfig"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service"
$param = "AllowUnencryptedTraffic"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service"
$param = "DisableRunAs"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$param = "ScreenSaveActive"
$type = "STRING"
$value = "1"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$value = Read-Host "Enter path to screen saver (together with file name):"

$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$param = "SCRNSAVE.EXE"
$type = "STRING"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$param = "ScreenSaverIsSecure"
$type = "STRING"
$value = "1"

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$idle_timeout = $null
$idle_timeout = Read-Host "Enter timeout for idle sessions in minutes (default 15)"
$idle_timeout = $idle_timeout -as [int]
if (!$idle_timeout) {$idle_timeout=15}
$idle_timeout = $idle_timeout*60

$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$param = "ScreenSaveTimeOut"
$type = "STRING"
$value = [string[]]$idle_timeout

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$param = "NoToastApplicationNotificationOnLockScreen"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0"
$param = "NoImplicitFeedback"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
$param = "SaveZoneInformation"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"
$param = "ScanWithAntiVirus"
$type = "DWORD"
$value = 3

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent"
$param = "ConfigureWindowsSpotlight"
$type = "DWORD"
$value = 2

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent"
$param = "DisableThirdPartySuggestions"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent"
$param = "DisableTailoredExperiencesWithDiagnosticData"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent"
$param = "DisableWindowsSpotlightFeatures"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent"
$param = "DisableSpotlightCollectionOnDesktop"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$param = "NoInplaceSharing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer"
$param = "AlwaysInstallElevated"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_CURRENT_USER\Software\Policies\Microsoft\WindowsMediaPlayer"
$param = "PreventCodecDownload"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] In Domain Controllers should open Active Directory Users and Computers and remove all unnecessary accounts from the Enterprise Admins group, Domain Admins and Administrators.
On servers that are not Domain Controllers must open the Computer Management and remove all unnecessary accounts from the Administrators group."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] In Computer Management, uncheck the `" Password never expires `"of all user accounts."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters"
$param = "EnablePMTUDiscovery"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters"
$param = "IPEnableRouter"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters"
$param = "EnableAddrMaskReply"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD\Parameters"
$param = "EnableDynamicBacklog"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD\Parameters"
$param = "DynamicBacklogGrowthDelta"
$type = "DWORD"
$value = 10

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD\Parameters"
$param = "MaximumDynamicBacklog"
$type = "DWORD"
$value = 20000

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD\Parameters"
$param = "MinimumDynamicBacklog"
$type = "DWORD"
$value = 20

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters"
$param = "EnablemulticastForwarding"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters"
$param = "EnableFragmentChecking"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters"
$param = "AllowUserRawAccess"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Control\StorageDevicePolicies"
$param = "WriteProtect"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] Set the community name to a stronger name using the Service snap-in, SNMP Service, Security tab."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$key = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$param = "SFCDisable"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Control\Session Manager"
$param = "AdditionalBaseNamedObjectsProtectionMode"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Control\Session Manager"
$param = "EnhancedSecurityLevel"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Control\LSA"
$param = "Notification Packages"
$type = "MultiString"
$value = @("RASSFM","KDCSVC","scecli")

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Services\RemoteAccess\Performance"
$param = "Disable Performance Counters"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\DCI"
$param = "Timeout"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


Write-Output "[Manual] Disable Netbios protocol on the Properties of the Local Connection > TCP/IP > Properties > Advanced > Wins Tab > Disable Netbios over TCP/IP
The following command can be used to disable Netbios Protocol on all network intefaces:
reg query `"HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces`" | where {`$_ -ne ''} | foreach {	reg add `$_ /v NetbiosOptions /t REG_DWORD /d 2 /f }"
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Configure firewall to permit only necessary network access for domain controllers. In particular Internet access must be denied."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Remove web-browsers software or if some of them are necessary configure black-hole proxy for external destinations."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] With local or network firewall limit RDP access to domain controlles to an approved list of secured administrative workstations."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] Don't use Group Policy Preferences for setting users passwords."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] To prevent attacks that leverage delegation to use the account’s credentials on other systems, perform the following steps:
In Server Manager, click Tools, and click Active Directory Users and Computers. For each account within Domains Admins, Enterprise Admins or Schema Admins groups configure the `"Account is sensitive and cannot be delegated`" propetry to True:
    - Right-click the account and click Properties.
    - Click the Account tab.
    - Under Account options, select `"Account is sensitive and cannot be delegated flag`" and click OK."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


$text = Get-Content -Raw $machine_inf_path
if ( ! ( echo $text | Select-String "\[System Access\]" ) ) { $text = $text + "`r`n[System Access]" }
$text = $text -Replace "\r\nEnableAdminAccount =.*?(\r\n|$)", "`$1"
$text = $text -Replace "\[System Access\]", "[System Access]`r`nEnableAdminAccount = 0"
[io.file]::WriteAllText($machine_inf_path,$text)


Write-Output "[Manual] When EA access is required, the users whose accounts require EA rights and permissions should be temporarily placed into the Enterprise Admins group. When the activities have been completed, the accounts should be removed from the EA group. The Enterprise Admins group should contain no users on a day-to-day basis, except root domain’s built-in Administrator account."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


Write-Output "[Manual] When Schema Admins access is required, the users whose accounts require Schema Admins rights and permissions should be temporarily placed into the Schema Admins group. When the activities have been completed, the accounts should be removed from the Schema Admins group. The Schema Admins group should contain no users on a day-to-day basis, except root domain’s built-in Administrator account."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")



