# Take policy name
$gpo_name = Read-Host "Enter Skype Security GPO name:[default is Couch_Skype]"
if ( $gpo_name -eq "" ) { $gpo_name = "Couch_Skype" }
Get-GPO -Name $gpo_name
if ( ! $? ) { New-GPO -Name $gpo_name }

# Set paths
$gpo = Get-GPO -Name $gpo_name
$domain = $gpo.DomainName
$num = $gpo.Id.Guid
$gpo_path = "$env:WinDir\SYSVOL\sysvol\$domain\Policies\{$num}"

$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableVersionCheck"
$type = "DWORD"
$value = 0

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableFileTransfer"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableScreenSharing"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableApi"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "MemoryOnly"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableTCPListen"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value


$key = "HKEY_LOCAL_MACHINE\SOFTWARE\POLICIES\SKYPE\PHONE"
$param = "DisableSupernode"
$type = "DWORD"
$value = 1

Set-GPRegistryValue -Name $gpo_name -Key $key -ValueName $param -Type $type -Value $value



