##################################
#Powershell SRG Script
#Michael Coleman, M.Coleman@F5.com
##################################
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') 

#$debug and $verbose is/are a reserved namespace, using logging instead.
$logging = $true
$bigiphost = [Microsoft.VisualBasic.Interaction]::InputBox("Enter BIG-IP FQDN (Excluding https://).  This MUST match the certificate used on the Management Interface.", "F5 BIG-IP FQDN")
$settrue = @{value= $true}
$setfalse = @{value= $false}
$jsontrue = $settrue | ConvertTo-Json
$jsonfalse = $setfalse | ConvertTo-Json

$bannerText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

$newcred = Get-Credential -Message "Please enter current credentials for the F5 Admin account."

#Set up variables to capture user/pass for remote AAA token generation.
$newcred_user 
$newcred_pass


$testcon = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/version" -Method GET -Credential $newcred -ContentType 'application/json' -TimeoutSec 5
if ($testcon) {
    $ver = $testcon.entries.'https://localhost/mgmt/tm/sys/version/0'.nestedStats.entries.Version.description
    $testauth = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/source" -Method GET -Credential $newcred -ContentType 'application/json'
    if ($testauth) {
        $AAAsource = $testauth.type
    }

    if ($ver -contains "12.*" ){
    ##TMOS Version 12 Only Configs
    #Write-Host [version]$ver
    [System.Windows.Forms.MessageBox]::Show("Success:  Script has been successfully tested on this version.  Prepare for the pop-ups!", "Connection Successful.") 

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
        [System.Windows.Forms.MessageBox]::Show("Success:  Script has been successfully tested on this version. Configuration will continue.", "Connection Successful.") 
    }

#Configurations supported on all tested platforms.  11.6 & 12.0

#SSHD Settings
$sshdvals = @"
{
    "inactivityTimeout":  "600",
    "banner":  "enabled",
    "banner-text":  "$bannerText",
"include":  "Protocol 2\r\nMaxAuthTries 3\r\nCiphers aes128-ctr,aes192-ctr,aes256-ctr"
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
    $ntpresponse = icontrol $bigiphost "/mgmt/tm/sys/ntp/" "PATCH" $newcred $ntpjson $logging
}


#HTTPD Settings
$httpvals = @{
    authPamIdleTimeout= 600
    sslCiphersuite= 'ALL:!ADH:!RC4:!EXPORT40:!EXP:!LOW'}
$httpdjson = $httpvals | ConvertTo-Json

#[STIG NET1639] 
#HTTPD Timeouts
$httpdresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/httpd/" -Method PATCH -Credential $newcred -Body $httpdjson -ContentType 'application/json'

#Write-Host $httpdresponse

#HTTPD & ACL Settings
$aclallow = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Admin GUI / SSH Allowed Subnet or IP.  You can enter IP's seperated by a space, or Network ID / Subnet (NON-CIDR)", "New Admin Credentials (xadmin)") 
$httpdacl = @"
{
    "allow": [ "$aclallow" ]
}
"@
$aclconv = $httpdacl | ConvertFrom-Json
$acljson = $aclconv | ConvertTo-Json

#HTTPD / SSH ACL Allowed
if ($aclallow){
    $aclresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/httpd" -Method PATCH -Credential $newcred -Body $acljson -ContentType 'application/json'
    $sshdaclresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/sshd" -Method PATCH -Credential $newcred -Body $acljson -ContentType 'application/json'

    #write-host $aclresponse
    #write-host $sshdaclresponse

}

#Call Home
$chval = @{
    autoCheck = 'disabled'
}
$chjson = $chval | ConvertTo-Json

#[STIG NET0405]
#Call Home Disable
$chresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/software/update" -Method PATCH -Credential $newcred -Body $chjson -ContentType 'application/json'

#Write-Host $chresponse

#[STIG NET1665]
#SNMP Remove
$snmpcheck = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/snmp/communities/" -Method GET -Credential $newcred -ContentType 'application/json'
if ($snmpcheck) {
    foreach ($item in $snmpcheck.items) {
        if ($item.communityName -eq "comm-public") {
            $snmpstring = $item.name
            $snmpresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/snmp/communities/$snmpstring" -Method DELETE -Credential $newcred -ContentType 'application/json'
            }
        }
}
#Write-Host $snmpresponse

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

$bashresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/db/systemauth.disablebash" -Method PATCH -Credential $newcred -Body $AppMode -ContentType 'application/json'
$rootresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/db/systemauth.disablerootlogin" -Method PATCH -Credential $newcred -Body $AppMode -ContentType 'application/json'

#Write-Host $bashresponse
#Write-Host $rootresponse

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

$adminpasswd = [Microsoft.VisualBasic.Interaction]::InputBox("Enter New Admin User Password", "password") 

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

#Write-Host $o

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

#Rename / Disable Default Admin
$userresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user" -Method POST -Credential $newcred -Body $o -ContentType 'application/json'
#Added patch to support updating user on following executions, i.e. password update.
$updateuserresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user/xadmin" -Method PATCH -Credential $newcred -Body $o -ContentType 'application/json'
#set partition access and role
$updateroleresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/auth/user/xadmin" -Method PATCH -Credential $newcred -Body $rolejson -ContentType 'application/json'
$defadminresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/db/systemauth.primaryadminuser" -Method PATCH -Credential $newcred -Body $defadmin -ContentType 'application/json'

}

#Powershell Calls use space for delimiter, not Comma, and no parenthesis
#so: icontrol host path method credential body
Function icontrol($ic_host, $ic_path, $ic_method, $ic_creds, [Parameter(Mandatory=$False)][string]$ic_body, [Parameter(Mandatory=$False)][bool]$log_val) 
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
        write-host $ic_results
    }
    return $ic_results
}

#Remote AAA User Token only works on TMOS v12.0+
Function RemoteAuth($remote_user, $remote_password, $remote_host)
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