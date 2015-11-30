##################################
#Powershell SRG Script
#Michael Coleman, M.Coleman@F5.com
##################################
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') 

$bigiphost = Microsoft.VisualBasic.Interaction]::InputBox("Enter BIG-IP FQDN (Excluding https://)", "FQDN")
$settrue = @{value= $true}
$setfalse = @{value= $false}
$jsontrue = $settrue | ConvertTo-Json
$jsonfalse = $setfalse | ConvertTo-Json

$newcred = Get-Credential
$adminpasswd = [Microsoft.VisualBasic.Interaction]::InputBox("Enter New Admin User Password", "password") 

#Enable or Disable App Mode [jsontrue/jsonfalse]
$AppQuestion = [Microsoft.VisualBasic.Interaction]::MsgBox("Do you want to enable Appliance Mode?",'YesNoCancel,Question', "Respond")
if ($AppQuestion -eq 'Yes') {
    $AppMode = $jsontrue
}
Else {
  $AppMode = $jsonfalse  
}

#NTP Settings
$ntpServers = @{
    servers= 192.168.2.25
    }
$ntpjson = $ntpServers | ConvertTo-Json

#HTTPD Settings
$aclallow = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Admin GUI / SSH Allowed Subnet or IP.  You can enter IP's seperated by a space, or a Network ID / Subnet (NON-CIDR)", "network") 
$acl = @{
    allow = $aclallow
}
$acljson = $httpdacl | ConvertTo-Json
$httpvals = @{
    authPamIdleTimeout= 600
    sslCiphersuite= 'ALL:!ADH:!RC4:!EXPORT40:!EXP:!LOW'}
$httpdjson = $httpvals | ConvertTo-Json

#SSHD Settings
$sshdvals = @{
    inactivityTimeout = 600
    include = "Protocol 2
    MaxAuthTries 3"
    }   
$sshdjson = $sshdvals | ConvertTo-Json

#Call Home
$chval = @{
    autoCheck = 'disabled'
}
$chjson = $chval | ConvertTo-Json

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

Write-Host $o

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

###########
#Functions 
###########

#STIG NET0700
#App Mode Lite / Disable Bash & Disable Root

$bashresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/db/systemauth.disablebash' -Method PATCH -Credential $newcred -Body $AppMode -ContentType 'application/json'
$rootresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/db/systemauth.disablerootlogin' -Method PATCH -Credential $newcred -Body $AppMode -ContentType 'application/json'

#Write-Host $bashresponse
#Write-Host $rootresponse

#STIG NET0812
#NTP
$ntpresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/ntp/' -Method PATCH -Credential $newcred -Body $ntpjson -ContentType 'application/json'

#Write-Host $ntpresponse

#[STIG NET1639] 
#HTTPD Timeouts
$httpdresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/httpd/' -Method PATCH -Credential $newcred -Body $httpdjson -ContentType 'application/json'
#Write-Host $httpdresponse

#[STIG NET1645] 
#SSHD
$sshdresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/sshd' -Method PATCH -Credential $newcred -Body $sshdjson -ContentType 'application/json'
#Write-Host $sshdresponse

#HTTPD / SSH ACL Allowe
$aclresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/httpd' -Method PATCH -Credential $newcred -Body $acljson -ContentType 'application/json'

#[STIG NET0405]
#Call Home Disable
$chresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/software/update' -Method PATCH -Credential $newcred -Body $chjson -ContentType 'application/json'

#Write-Host $chresponse

#[STIG NET1665]
#SNMP Remoce
$snmpresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/snmp/communities/comm-public' -Method DELETE -Credential $newcred -ContentType 'application/json'

#Write-Host $snmpresponse

#Rename / Disable Default Admin
$userresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/auth/user' -Method POST -Credential $newcred -Body $o -ContentType 'application/json'
#Added patch to support updating user on following executions, i.e. password update.
$updateuserresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/auth/user/xadmin' -Method PATCH -Credential $newcred -Body $o -ContentType 'application/json'
#set partition access and role
$updateroleresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/auth/user/xadmin' -Method PATCH -Credential $newcred -Body $rolejson -ContentType 'application/json'
$defadminresponse = Invoke-RestMethod 'https://f53.f5lab.com/mgmt/tm/sys/db/systemauth.primaryadminuser' -Method PATCH -Credential $newcred -Body $defadmin -ContentType 'application/json'

