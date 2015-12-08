##################################
#Powershell SRG Script
#Michael Coleman, M.Coleman@F5.com
##################################
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') 

$bigiphost = [Microsoft.VisualBasic.Interaction]::InputBox("Enter BIG-IP FQDN (Excluding https://).  This MUST match the certificate used on the Management Interface.", "F5 BIG-IP FQDN")
$settrue = @{value= $true}
$setfalse = @{value= $false}
$jsontrue = $settrue | ConvertTo-Json
$jsonfalse = $setfalse | ConvertTo-Json



$newcred = Get-Credential -Message "Please enter current credentials for the F5 Admin account."
#Set up variables to capture user/pass for remote AAA token generation.
$newcred_user 
$newcred_pass

$x_f5_auth_token = RemoteAuth($newcred_user, $newcred_pass)

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
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("X-F5-AUTH-Token",$x_f5_auth_token)

    }
    elseif ([version]$ver -le 11.5) {
    ##TMOS Version Less than or Equal to 11.5
    #Write-Host [version]$ver
    [System.Windows.Forms.MessageBox]::Show("Script has not been tested on TMOS versions below 11.6.  Script will exit", "Not Tested with this version of TMOS.") 
    }
    else {
    ##TMOS Version 11.6
    #Write-Host [version]$ver 
        [System.Windows.Forms.MessageBox]::Show("Success:  Script has been successfully tested on this version.  Prepare for the pop-ups!", "Connection Successful.") 
    }

#Configurations supported on all tested platforms.  11.6 & 12.0

#SSHD Settings
$sshdvals = @{
    inactivityTimeout = 600
    include = "Protocol 2
    MaxAuthTries 3
    Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
    }   
$sshdjson = $sshdvals | ConvertTo-Json

#[STIG NET1645] 
#SSHD
$sshdresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/sshd" -Method PATCH -Credential $newcred -Body $sshdjson -ContentType 'application/json'
#Write-Host $sshdresponse

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
    $ntpresponse = Invoke-RestMethod "https://$bigiphost/mgmt/tm/sys/ntp/" -Method PATCH -Credential $newcred -Body $ntpjson -ContentType 'application/json'

    #Write-Host $ntpresponse
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
$AppQuestion = [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to enable Appliance Mode?", "Appliance Mode", 4)
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

[System.Windows.Forms.MessageBox]::Show("Configurations completed.") 

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
Function icontrol($ic_host, $ic_path, $ic_method, $ic_creds, [Parameter(Mandatory=$False)][string]$ic_body) 
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