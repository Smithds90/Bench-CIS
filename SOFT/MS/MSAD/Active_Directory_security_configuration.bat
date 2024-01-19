echo OFF
echo Active Directory security configuration

echo 1_1
gpresult /v
wmic product get name
echo Couch: Only approved list of necessary software and Windows components must be installed on domain controllers. If some excess software is installed, remove it.
set /P a=Next

echo 1_2
nslookup ya.ru 8.8.8.8
ping 8.8.8.8
echo Couch: If there is network access to the Internet, block it on network firewall
set /P a=Next

echo 1_3
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyServer" /t REG_SZ /d "0.0.0.1:888"
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyOverride" /t REG_SZ /d "10.0.0.0/8;192.168.0.0/16;172.16.0.0/20"
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 1
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxySettingsPerUser" /t REG_DWORD /d 0
dir iexplore.exe /s 2>&1 
dir chrome.exe /s 2>&1 
dir firefox.exe /s 2>&1 
dir opera.exe /s 2>&1 
dir browser.exe /s 2>&1
echo Couch: If some internet browser is installed, remove it
set /P a=Next

echo 1_4
echo Couch: With local or network firewall limit RDP access to domain controlles to an approved list of secured administrative workstations.
set /P a=Next

echo 1_5
findstr /s /i /m cpassword C:\Windows\SYSVOL\sysvol *.*
echo Couch: Is some is returned, remove cpassword from Group Preferences
set /P a=Next

echo 2_1
net group "Enterprise Admins" /domain 2>nul
net group "Администраторы предприятия" /domain 2>nul
echo Couch: Check that the Enterprise Admins group contains only root domain’s built-in Administrator account. Remove other accounts from this group.
set /P a=Next

echo 2_2
net group "Domain Admins" /domain 2>nul
net group "Администраторы домена" /domain 2>nul
echo Couch: Check that Domain Admins group includes only approved necessary accounts. Remove other accounts from this group.
set /P a=Next

echo 2_3
net group "Administrators" /domain 2>nul
net group "Администраторы" /domain 2>nul
echo Couch: Check that domain controller built-in Administrators group includes only approved necessary accounts. Remove other accounts from this group.
set /P a=Next

echo 2_4
net group "Shcema Admins" /domain 2>nul
net group "Администраторы схемы" /domain 2>nul
echo Couch: Check that the Schema Admins group contains only root domain’s built-in Administrator account. Remove other accounts from this group.
set /P a=Next

echo 2_5
net group /domain
echo Couch: For domain groups which have some administrative rights check that such groups include only approved necessary accounts. Remove other accounts.
set /P a=Next

echo 2_6
echo Couch: Check that every Active Directory level administrator has separate account to perform activities which don't require administrative rights.
set /P a=Next

echo 2_7
echo Couch: Check that administrative tasks are performed from secured workstation which is not user for non-administrative tasks. 
set /P a=Next

echo 2_8
for /f "tokens=1 usebackq" %%i in (`wmic useraccount get sid ^| findstr /R "S-1-5-21-[1234567890-]*-500"`) do ( set admin=%%i )
powershell -command Get-ADUser -Identity "%admin%" ^| Set-ADAccountControl -AccountNotDelegated:$true

echo 2_9
powershell -command Disable-ADAccount -Identity "%admin%"

echo 2_10
echo To implement the recommended configuration state, add the domain built-in Administrator account to the following Group Policy as <DomainName>\Administrator. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny access to this computer from the network
set /P a=Next

echo 2_11 To implement the recommended configuration state, add the domain built-in Administrator account to the following Group Policy as <DomainName>\Administrator. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on as a batch job
set /P a=Next

echo 2_12 To implement the recommended configuration state, add the domain built-in Administrator account to the following Group Policy as <DomainName>\Administrator. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on as a service
set /P a=Next

echo 2_13 To implement the recommended configuration state, add the domain built-in Administrator account to the following Group Policy as <DomainName>\Administrator. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on through Remote Desktop Services
set /P a=Next

echo 2_14 To implement the recommended configuration state, add the NT AUTHORITY\Local account and member of Administrators group (*S-1-5-114) to the following Group Policy. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny access to this computer from the network
set /P a=Next

echo 2_15 To implement the recommended configuration state, add the NT AUTHORITY\Local account and member of Administrators group (*S-1-5-114) to the following Group Policy. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on as a batch job
set /P a=Next

echo 2_16 To implement the recommended configuration state, add the NT AUTHORITY\Local account and member of Administrators group (*S-1-5-114) to the following Group Policy. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on as a service
set /P a=Next

echo 2_17 o implement the recommended configuration state, add the NT AUTHORITY\Local account and member of Administrators group (*S-1-5-114) the following Group Policy. 
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
Deny log on through Remote Desktop Services
set /P a=Next
