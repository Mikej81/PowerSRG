##################################
#Powershell SRG Script
#Michael Coleman, M.Coleman@F5.com
##################################
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

#Powershell Calls use space for delimiter, not Comma, and no parenthesis
#so: icontrol host path method credential body
function icontrol($ic_host, $ic_path, $ic_method, $ic_creds, [Parameter(Mandatory=$False)][string]$ic_body, [Parameter(Mandatory=$False)][bool]$log_val) 
 {

$ic_uri = $ic_host + $ic_path

 $webRequest = [System.Net.WebRequest]::Create("https://"+$ic_uri)
 $webRequest.Method = $ic_method

    if ($ic_method -eq "GET") {
        $ic_results = Invoke-RestMethod "https://$ic_uri" -Method $webRequest.Method -Credential $ic_creds -ContentType 'application/json'
    }
    else {
        $ic_results = Invoke-RestMethod "https://$ic_uri" -Method $webRequest.Method -Credential $ic_creds -Body $ic_body -ContentType 'application/json'
    }
    if ($log_val){
        write-host $ic_results | fl
    }
    return $ic_results
} 

#Remote AAA User Token only works on TMOS v12.0+
function RemoteAuth($remote_user, $remote_password, $remote_host)
{
$remoteAAAjson = @"
    {
    "username": "$remote_user",
    "password": "$remote_password",
    "loginProviderName": "tmos"
    }
"@

$remote_token = Invoke-RestMethod "https://$remote_host/mgmt/shared/authn/login" -Method POST -ContentType 'application/json'

$authtoken = $remote_token.token

return $authtoken

}

#$debug and $verbose is/are a reserved namespace, using logging instead.
$logging = $true
$bigiphost = [Microsoft.VisualBasic.Interaction]::InputBox("Enter BIG-IP FQDN (Excluding https://).  This MUST match the certificate used on the Management Interface.", "F5 BIG-IP FQDN")
$settrue = @{value= $true}
$setfalse = @{value= $false}
$jsontrue = $settrue | ConvertTo-Json
$jsonfalse = $setfalse | ConvertTo-Json

##Classification Settings:  class/unclass
$classification = "unclass"
if ($classification -eq "unclass")
{
    $ui_advisory_color = "green" 
    $ui_advisory_text = "//UNCLASSIFIED//"
}
else {
    $ui_advisory_color = "red" 
    $ui_advisory_text = "//CLASSIFIED//"
}

$bannerText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

$newcred = Get-Credential -Message "Please enter current credentials for the F5 Admin account."

#Set up variables to capture user/pass for remote AAA token generation.
$newcred_user 
$newcred_pass

$testcon = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/version" -Method GET -Credential $newcred -ContentType 'application/json' -TimeoutSec 5
if ($testcon) {
    $ver = $testcon.entries.'https://localhost/mgmt/tm/sys/version/0'.nestedStats.entries.Version.description
    #$testauth = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/source" -Method GET -Credential $newcred -ContentType 'application/json'
    $testauth = icontrol $bigiphost "/mgmt/tm/auth/source" "GET" $newcred $logging
    if ($testauth) {
        $AAAsource = $testauth.type
    }

    if ($ver -contains "12.*" ){
    ##TMOS Version 12 Only Configs
    #Write-Host [version]$ver
    [System.Windows.Forms.MessageBox]::Show("Success:  Script has been successfully tested on this version.  Configuration will continue.", "Connection Successful.") 

    #Set Up Headers
    if ($AAAsource -ne "local"){
        $x_f5_auth_token = RemoteAuth $newcred_user $newcred_pass
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("X-F5-AUTH-Token",$x_f5_auth_token)
    }

    }
    elseif ([version]$ver -le 11.5) {
    ##TMOS Version Less than or Equal to 11.5
    #Write-Host [version]$ver
    [System.Windows.Forms.MessageBox]::Show("Script has not been tested on TMOS versions below 11.6.  Script will exit", "Not Tested with this version of TMOS.") 
    }
    else {
    ##TMOS Version 11.6
    #Write-Host [version]$ver 
        [System.Windows.Forms.MessageBox]::Show("Success:  Script has been successfully tested on this version. Configuration will continue.  Question boxes left blank will leave existing configuration unmodified.", "Connection Successful.") 
    }

#Configurations supported on all tested platforms.  11.6 & 12.0

#SSHD Settings
$sshdvals = @"
{
    "inactivityTimeout":  "600",
    "banner":  "enabled",
    "banner-text":  "$bannerText",
"include":  "Protocol 2\r\nMaxAuthTries 3\r\nCiphers aes128-ctr,aes192-ctr,aes256-ctr\r\nMACs hmac-sha1,hmac-ripemd160"
}
"@
$sshdconv = $sshdvals | ConvertFrom-Json   
$sshdjson = $sshdconv | ConvertTo-Json

#[STIG NET1645] 
#SSHD
#$sshdresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/sshd" -Method PATCH -Credential $newcred -Body $sshdjson -ContentType 'application/json'
icontrol $bigiphost "/mgmt/tm/sys/sshd" "PATCH" $newcred $sshdjson $logging


#NTP Settings
$NTPQuestion = [Microsoft.VisualBasic.Interaction]::InputBox("Enter NTP Server(s).  Seperated with commas.", "NTP Configuration")
#$ntpServers = @{
# #servers= 192.168.2.25
# servers=$NTPQuestion
#}
$ntpServers = @"
{
    "servers": [ "$NTPQuestion" ]
}
"@
$ntpconv = $ntpServers | ConvertFrom-Json
$ntpjson = $ntpconv | ConvertTo-Json

#STIG NET0812
#NTP
if ($NTPQuestion) {
    #$ntpresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/ntp/" -Method PATCH -Credential $newcred -Body $ntpjson -ContentType 'application/json'
    icontrol $bigiphost "/mgmt/tm/sys/ntp/" "PATCH" $newcred $ntpjson $logging
}

#Global Settings; HTTPD UI Banner
$globalvals = @"
{
"guiSecurityBanner":"enabled",
"guiSecurityBannerText": "$bannerText"
}
"@
$globalconv = $globalvals | ConvertFrom-Json
$globaljson = $globalconv | ConvertTo-Json

icontrol $bigiphost "/mgmt/tm/sys/global-settings" "PATCH" $newcred $globaljson $logging

#Advisory Banners.  PITA that its 3 seperate DB settings
$advisoryenable = @"
{
 "value": "$True"
}
"@
$advisoryenable_json = $advisoryenable | ConvertFrom-Json | ConvertTo-Json
$advisoryColor = @"
{
 "value": "$ui_advisory_color"
}
"@
$advisoryColor_json = $advisoryColor | ConvertFrom-Json | ConvertTo-Json 
$advisoryText = @"
{
 "value": "$ui_advisory_text"
}
"@
$advisoryText_json = $advisoryText | ConvertFrom-Json | ConvertTo-Json

icontrol $bigiphost "/mgmt/tm/sys/db/ui.advisory.enabled" "PATCH" $newcred $advisoryenable_json $logging
icontrol $bigiphost "/mgmt/tm/sys/db/ui.advisory.color" "PATCH" $newcred $advisoryColor_json $logging
icontrol $bigiphost "/mgmt/tm/sys/db/ui.advisory.text" "PATCH" $newcred $advisoryText_json $logging

#HTTPD Settings
$httpvals = @{
    authPamIdleTimeout= 600
    sslCiphersuite= 'ALL:!ADH:!RC4:!RSA:!EXPORT:!EXP:!LOW:!MD5:!aNULL:!eNULL'
    sslProtocol= 'all -SSLv2 -SSLv3'}
$httpdjson = $httpvals | ConvertTo-Json

#[STIG NET1639] 
#HTTPD Timeouts
#$httpdresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/httpd/" -Method PATCH -Credential $newcred -Body $httpdjson -ContentType 'application/json'
icontrol $bigiphost "/mgmt/tm/sys/httpd/" "PATCH" $newcred $httpdjson

#HTTPD & ACL Settings
#HTTPD / SSH ACL Allowed
$aclallow = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Admin GUI / SSH Allowed Subnet or IP.  You can enter IP's seperated by a space, or Network ID / Subnet (NON-CIDR)", "Management Access ACL") 
$httpdacl = @"
{
    "allow": [ "$aclallow" ]
}
"@
$aclconv = $httpdacl | ConvertFrom-Json
$acljson = $aclconv | ConvertTo-Json

if ($aclallow){
    icontrol $bigiphost "/mgmt/tm/sys/httpd" "PATCH" $newcred $acljson $logging
    icontrol $bigiphost "/mgmt/tm/sys/sshd" "PATCH" $newcred $acljson $logging
}

#[STIG NET0405]
#Call Home Disable
$chval = @{
    autoCheck = 'disabled'
}
$chjson = $chval | ConvertTo-Json

icontrol $bigiphost "/mgmt/tm/sys/software/update" "PATCH" $newcred $chjson $logging


#[STIG NET1665]
#SNMP Remove
$snmpcheck = icontrol $bigiphost "/mgmt/tm/sys/snmp/communities/" "GET" $newcred
if ($snmpcheck) {
    foreach ($item in $snmpcheck.items) {
        if ($item.communityName -eq "comm-public") {
            $snmpstring = $item.name
            #$snmpresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/snmp/communities/$snmpstring" -Method DELETE -Credential $newcred -ContentType 'application/json'
            icontrol $bigiphost "/mgmt/tm/sys/snmp/communities/$snmpstring" "DELETE" $newcred
            }
        }
}

##Strict Password Policy Enforcement
##Only say yes if you want strict passwords


$strictpolicy = @"
{
    "expirationWarning": "7",
    "maxDuration": "90",
    "maxLoginFailures": "3",
    "minDuration": "1",
    "minimumLength": "8",
    "passwordMemory": "3",
    "policyEnforcement": "enabled",
    "requiredLowercase": "2",
    "requiredNumeric": "2",
    "requiredSpecial": "2",
    "requiredUppercase": "2"
}
"@
$strictJson = $strictpolicy | ConvertFrom-Json | ConvertTo-Json
##Default Policy
$laxpolicy = @"
{
    "expirationWarning": "7",
    "maxDuration": "99999",
    "maxLoginFailures": "0",
    "minDuration": "0",
    "minimumLength": "6",
    "passwordMemory": "0",
    "policyEnforcement": "disabled",
    "requiredLowercase": "0",
    "requiredNumeric": "0",
    "requiredSpecial": "0",
    "requiredUppercase": "0"
}
"@
$laxJson = $laxpolicy | ConvertFrom-Json | ConvertTo-Json
if ($AAAsource -eq "local") {
$strictPolicyQuestion = [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to enable strict password policy for local accounts?  Select No to disable, Cancel to skip.", 'YesNoCancel,Question', "Strict Password Policy")
    if ($strictPolicyQuestion -eq 'Yes') {
        icontrol $bigiphost "/mgmt/tm/auth/password-policy" "PATCH" $newcred $strictJson $logging
    }
    elseif ($strictPolicyQuestion -eq 'No') {
        icontrol $bigiphost "/mgmt/tm/auth/password-policy" "PATCH" $newcred $laxJson $logging
    }

}

#Enable or Disable App Mode [jsontrue/jsonfalse]
#Allow turning off and on App Mode Lite
$AppQuestion = [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to enable Appliance Mode?", 'YesNoCancel,Question', "Appliance Mode")
if ($AppQuestion -eq 'Yes') {
    $AppMode = $jsontrue
}
Else {
  $AppMode = $jsonfalse  
}

#STIG NET0700
#App Mode Lite / Disable Bash & Disable Root

icontrol $bigiphost "/mgmt/tm/sys/db/systemauth.disablebash" "PATCH" $newcred $AppMode
icontrol $bigiphost "/mgmt/tm/sys/db/systemauth.disablerootlogin" "PATCH" $newcred $AppMode

#Config Completed Message
#[System.Windows.Forms.MessageBox]::Show("Configurations completed.") 

}
else {
##Connection failed.
    [System.Windows.Forms.MessageBox]::Show("Failed:  Please validate the host, and credentials used.", "Connection Failed.")
return
}


##If MGMT AAA Source is not local, the admin rename / disable will fail, this will work for systems with AAA set to local currently.
##Possible solution, switch AAA to local, perform updates, switch back to Remote.
##Not successfully tested in 11.6, so leaving outside of version check for now.  This was an 11.6 added feature so <11.6 will be a no go.

if ($AAAsource -eq "local") {
##Maybe ask what the new Admin should be called?  Add checking to see if xAdmin already exists, and if so, then what?

$adminpasswd = [Microsoft.VisualBasic.Interaction]::InputBox("Enter New Admin User Password", "New Admin Credentials (xadmin)") 

#Admin User
$jsonuser = @"
{
    "name": "xadmin",
    "password": "$adminpasswd",
    "role": "admin",
    "shell": "tmsh",
    "partitionaccess": [ {
        "name": "all-partitions",
        "role": "admin"
        }
    ]
}
"@

$user = $jsonuser | ConvertFrom-Json
$o = $user | ConvertTo-Json


$rolejson = @"
{
"partitionAccess": [
{
"name": "all-partitions",
"role": "admin"
}
]
}
"@
#Set New Default Admin
$defadmin = @"
{"value": "xadmin"}
"@

if ($adminpasswd){
#Rename / Disable Default Admin
$userresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user" -Method POST -Credential $newcred -Body $o -ContentType 'application/json'
#Added patch to support updating user on following executions, i.e. password update.
$updateuserresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user/xadmin" -Method PATCH -Credential $newcred -Body $o -ContentType 'application/json'
#set partition access and role
$updateroleresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user/xadmin" -Method PATCH -Credential $newcred -Body $rolejson -ContentType 'application/json'
$defadminresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/db/systemauth.primaryadminuser" -Method PATCH -Credential $newcred -Body $defadmin -ContentType 'application/json'
}
}


function ExtractPKCS12($path_to_pkcs12, $cert_key_name, $passphrase)
{
$bash_path = "/mgmt/tm/util/bash" 
$pkcs12_cert_json = @"
{
    "command": "run", 
    "utilCmdArgs": "-c \"openssl pkcs12 -in $path_to_pkcs12 -nokeys -out $cert_key_name.crt -password pass:$passphrase -nodes\""

}
"@
$pkcs12_key_json = @"
{
    "command": "run", 
    "utilCmdArgs": "-c \"openssl pkcs12 -in $path_to_pkcs12 -nocerts -out $cert_key_name.key -password pass:$passphrase -nodes\""

}
"@
icontrol $bigiphost $bash_path "POST" $newcred $pkcs12_cert_json $logging
icontrol $bigiphost $bash_path "POST" $newcred $pkcs12_key_json $logging

}

function InstallCrypto ($pair_name, $pair_path)
{
$certpath = "/mgmt/tm/sys/crypto/cert"
$keypath = "/mgmt/tm/sys/crypto/key"

$cert_vals = @"
{
"command":"install",
"name":"$pair_name",
"from-local-file":"$pair_path.crt"
}
"@
$cert_json = $cert_vals | ConvertFrom-Json | ConvertTo-Json
$key_vals = @"
{
"command":"install",
"name":"$pair_name",
"from-local-file":"$pair_path.key"
}
"@
$key_json = $key_vals | ConvertFrom-Json | ConvertTo-Json

icontrol $bigiphost $certpath "POST" $newcred $cert_json $logging
icontrol $bigiphost $keypath "POST" $newcred $key_json $logging

}

#File Dialog window to allow easy selection of files.
function Get-FileName($initialDirectory)
{   
 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
 Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 $OpenFileDialog.initialDirectory = $initialDirectory
 $OpenFileDialog.filter = "All files (*.*)| *.*"
 $OpenFileDialog.ShowDialog() | Out-Null
 $OpenFileDialog.filename
}

#To be used later
function Get-FileEncoding
{
    [CmdletBinding()] Param (
     [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string]$Path
    )

    [byte[]]$byte = get-content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $Path
 
    if ( $byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf )
    { Write-Output 'UTF8' }
    elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff)
    { Write-Output 'Unicode' }
    elseif ($byte[0] -eq 0 -and $byte[1] -eq 0 -and $byte[2] -eq 0xfe -and $byte[3] -eq 0xff)
    { Write-Output 'UTF32' }
    elseif ($byte[0] -eq 0x2b -and $byte[1] -eq 0x2f -and $byte[2] -eq 0x76)
    { Write-Output 'UTF7'}
    else
    { Write-Output 'ASCII' }
}

function UploadCrypto($hostname, $credentials)
{
    ##does not account for chunking required for files over 1MB, yet.  Not many Certs/Keys will be over this size, but wont hurt to add better error handling.
    [int]$chunk_size = 512 * 1024
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type",'application/octet-stream')

    $file_obj = Get-FileName -initialDirectory "C:\"
    $file_enc = Get-FileEncoding $file_obj
    $file_content = Get-Content -Path $file_obj
    $file_base = Get-ChildItem $file_obj -name
    $file_start = 0
    $file_end = (Get-Item $file_obj).Length
    [string]$content_range = [string]$file_start+ "-"+ [string]([int]$file_end-1)+ "/"+ [string]$file_end
    $headers.add("Content-Range", "$content_range")

    $upload_path = "/mgmt/shared/file-transfer/uploads/$file_base"
    $upload_uri = "https://"+$hostname+$upload_path

    $uploadResults = Invoke-RestMethod $upload_uri -Method POST -Credential $credentials -InFile $file_obj -Headers $headers -ContentType 'application/octet-stream'

    return $uploadResults
}
<<<<<<< HEAD

$encrypt_cookie_json = @"
{
    "kind": "tm:ltm:rule:rulestate",
    "name": "_encrypt_http_cookies",
    "apiAnonymous": "when RULE_INIT {\n \n\t# Cookie name prefix\n\tset static::ck_pattern \"BIGipServer*\"\n \n\t# Log debug to /var/log/ltm? 1=yes, 0=no)\n\tset static::ck_debug 1\n \n\t# Cookie encryption passphrase\n\t# Change this to a custom string!\n\tset static::ck_pass \"mypass1234\"\n}\nwhen HTTP_REQUEST {\n \n\tif {$static::ck_debug}{log local0. \"Request cookie names: [HTTP::cookie names]\"}\n\t\n\t# Check if the cookie names in the request match our string glob pattern\n\tif {[set cookie_names [lsearch -all -inline [HTTP::cookie names] $static::ck_pattern]] ne \"\"}{\n \n\t\t# We have at least one match so loop through the cookie(s) by name\n\t\tif {$static::ck_debug}{log local0. \"Matching cookie names: [HTTP::cookie names]\"}\n\t\tforeach cookie_name $cookie_names {\n\t\t\t\n\t\t\t# Decrypt the cookie value and check if the decryption failed (null return value)\n\t\t\tif {[HTTP::cookie decrypt $cookie_name $static::ck_pass] eq \"\"}{\n \n\t\t\t\t# Cookie wasn't encrypted, delete it\n\t\t\t\tif {$static::ck_debug}{log local0. \"Removing cookie as decryption failed for $cookie_name\"}\n\t\t\t\tHTTP::cookie remove $cookie_name\n\t\t\t}\n\t\t}\n\t\tif {$static::ck_debug}{log local0. \"Cookie header(s): [HTTP::header values Cookie]\"}\n\t}\n}\nwhen HTTP_RESPONSE {\n \n\tif {$static::ck_debug}{log local0. \"Response cookie names: [HTTP::cookie names]\"}\n\t\n\t# Check if the cookie names in the request match our string glob pattern\n\tif {[set cookie_names [lsearch -all -inline [HTTP::cookie names] $static::ck_pattern]] ne \"\"}{\n\t\t\n\t\t# We have at least one match so loop through the cookie(s) by name\n\t\tif {$static::ck_debug}{log local0. \"Matching cookie names: [HTTP::cookie names]\"}\n\t\tforeach cookie_name $cookie_names {\n\t\t\t\n\t\t\t# Encrypt the cookie value\n\t\t\tHTTP::cookie encrypt $cookie_name $static::ck_pass\n\t\t}\n\t\tif {$static::ck_debug}{log local0. \"Set-Cookie header(s): [HTTP::header values Set-Cookie]\"}\n\t}\n}"
}
"@

icontrol $bigiphost "/mgmt/tm/ltm/rule" "POST" $newcred $encrypt_cookie_json $logging
=======
>>>>>>> master
