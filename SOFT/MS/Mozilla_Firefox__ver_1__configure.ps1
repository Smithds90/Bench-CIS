
foreach ( $prefix in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}) ) { 
if (Test-Path -Path "${prefix}\Mozilla Firefox\firefox.exe") {
  $datadir_path = $prefix+'\Mozilla Firefox\defaults\pref\local-settings.js';
  if ( ! (Test-Path "$datadir_path" ) ) {
	"pref(`"general.config.obscure_value`", 0);`r`npref(`"general.config.filename`", `"mozilla.cfg`");" | Set-Content "$datadir_path";
  }
  else {
	$text = Get-Content -Raw "$datadir_path";
	$text = $text -Replace '(^|\n)(pref\("general.config.obscure_value".*?(\n|$))', "`$1// `$2";
	$text = $text -Replace '(^|\n)(pref\("general.config.filename".*?(\n|$))', "`$1// `$2";
	$text = $text + "pref(`"general.config.obscure_value`", 0);`r`npref(`"general.config.filename`", `"mozilla.cfg`");";
	$text | Set-Content "$datadir_path";
  }
}
}


Write-Output "[Manual] Deny non-administrators the ability to write to local-settings.js."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
if ( ! (Test-Path "$p\mozilla.cfg") ) {
	"// " | Set-Content "$p\mozilla.cfg";
	}
else {
	$text = Get-Content -Raw "$p\mozilla.cfg";
	$text = "// `r`n" + $text;
	$text | Set-Content "$p\mozilla.cfg";
	}


Write-Output "[Manual] Deny non-administrators the ability to write to mozilla.cfg."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("app.update.enabled".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("app.update.auto".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("app.update.staging.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"app.update.enabled`", true);`r`nlockPref(`"app.update.auto`", true);`r`nlockPref(`"app.update.staging.enabled`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("plugins.update.notifyUser".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"plugins.update.notifyUser`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("plugins.hide_infobar_for_outdated_plugin".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"plugins.hide_infobar_for_outdated_plugin`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("app.update.interval".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"app.update.interval`", 43200);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("app.update.promptWaitTime".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"app.update.promptWaitTime`", 172800);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("app.update.silent".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"app.update.silent`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.search.update".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.search.update`", true);"
$text | Set-Content "$p\mozilla.cfg"


Write-Output "[Manual] Perform the following procedure: 
1 Drop down the Firefox menu 
2 Click on Options 
3 Select Options from the list 
4 Click on the Advanced Button in the Options window 
5 Click on Network Tab 
6 Click on Settings Button 
7 Ensure that the proxy listed (if any) is the one configured and approved by the 
enterprise."
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.http.sendSecureXSiteReferrer".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.http.sendSecureXSiteReferrer`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.auth.force-generic-ntlm-v1".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.auth.force-generic-ntlm-v1`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.http.phishy-userpass-length".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.http.phishy-userpass-length`", 1);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.IDN_show_punycode".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.IDN_show_punycode`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.fileuri.strict_origin_policy".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.fileuri.strict_origin_policy`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("services.sync.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"services.sync.enabled`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("media.peerconnection.enabled".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("media.peerconnection.use_document_iceservers".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"media.peerconnection.enabled`", false);"
$text = $text + "`r`nlockPref(`"media.peerconnection.use_document_iceservers`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.ssl_override_behavior".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.ssl_override_behavior`", 0);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.tls.version.max".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.tls.version.max`", 3);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.tls.version.min".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.tls.version.min`", 1);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.OCSP.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.OCSP.enabled`", 1);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.mixed_content.block_active_content".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.mixed_content.block_active_content`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.ocsp.require".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.ocsp.require`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("dom.disable_window_status_change".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"dom.disable_window_status_change`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.xpconnect.plugin.unrestricted".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.xpconnect.plugin.unrestricted`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("dom.disable_window_open_feature.location".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"dom.disable_window_open_feature.location`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("dom.disable_window_open_feature.status".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"dom.disable_window_open_feature.status`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("dom.allow_scripts_to_close_windows".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"dom.allow_scripts_to_close_windows`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("privacy.popups.policy".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"privacy.popups.policy`", 1);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.urlbar.filter.javascript".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.urlbar.filter.javascript`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("signon.rememberSignons".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"signon.rememberSignons`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.cookie.cookieBehavior".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.cookie.cookieBehavior`", 1);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("privacy.donottrackheader.enabled".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("privacy.donottrackheader.value".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("privacy.trackingprotection.enabled".*?(\n|$))', "`$1// `$2"
$text = $text -Replace '(^|\n)(lockPref\("privacy.trackingprotection.pbmode".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"privacy.donottrackheader.enabled`", true);"
$text = $text + "`r`nlockPref(`"privacy.donottrackheader.value`", 1);"
$text = $text + "`r`nlockPref(`"privacy.trackingprotection.enabled`", true);"
$text = $text + "`r`nlockPref(`"privacy.trackingprotection.pbmode`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("security.dialog_enable_delay".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"security.dialog_enable_delay`", 2000);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("geo.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"geo.enabled`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.helperApps.alwaysAsk.force".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.helperApps.alwaysAsk.force`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("xpinstall.whitelist.required".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"xpinstall.whitelist.required`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("extensions.blocklist.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"extensions.blocklist.enabled`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("extensions.blocklist.interval".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"extensions.blocklist.interval`", 86400);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.protocol-handler.warn-external-default".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.protocol-handler.warn-external-default`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("privacy.popups.disable_from_plugins".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"privacy.popups.disable_from_plugins`", 2);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("extensions.update.autoUpdateDefault".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"extensions.update.autoUpdateDefault`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("extensions.update.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"extensions.update.enabled`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("extensions.update.interval".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"extensions.update.interval`", 86400);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.download.manager.scanWhenDone".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.download.manager.scanWhenDone`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("network.jar.open-unsafe-types".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"network.jar.open-unsafe-types`", false);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.safebrowsing.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.safebrowsing.enabled`", true);"
$text | Set-Content "$p\mozilla.cfg"


if (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles(x86)}\Mozilla Firefox"
}

if (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe") {
$p = "${env:ProgramFiles}\Mozilla Firefox"
}
$text = Get-Content -Raw "$p\mozilla.cfg"
$text = $text -Replace '(^|\n)(lockPref\("browser.safebrowsing.malware.enabled".*?(\n|$))', "`$1// `$2"
$text = $text + "`r`nlockPref(`"browser.safebrowsing.malware.enabled`", true);"
$text | Set-Content "$p\mozilla.cfg"



