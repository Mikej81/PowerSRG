################################################
## BashSRG - Bash STIG/SRG configuration Script
## Michael Coleman.  M.Coleman@F5.com
################################################
#!/bin/sh
###change 1

echo
echo "###############################################"
echo " BASHSRG - Bash STIG/SRG Configuration Script"
echo " Michael Coleman.  M.Coleman@F5.com\\n"
echo "###############################################"
echo

bannerText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

tmsh modify sys sshd inactivity-timeout 900
tmsh modify sys sshd banner enabled
tmsh modify sys sshd banner-text "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
tmsh modify sys sshd include '"Protocol 2
MaxAuthTries 3
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
MACs hmac-sha1,hmac-ripemd160"'

if [[ `tmsh list sys sshd allow` == *"ALL"* ]]
then
    echo "SSHD ALLOWS FROM ALL NETWORKS"
else
    echo "SSHD ACLS CONFIGURED"
fi

ntp=`tmsh list sys ntp servers`
if [ ${#ntp} -le 28]
then
    echo "NTP IS NOT CONFIGURED"
else
    echo "NTP IS CONFIGURED"
fi

tmsh modify sys global-settings gui-security-banner enabled
tmsh modify sys global-settings gui-security-banner-text "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
tmsh modify sys db ui.advisory.enabled value true
tmsh modify sys db ui.advisory.color value green
tmsh modify sys db ui.advisory.text value "//UNCLASSIFIED//"

tmsh modify sys httpd max-clients 10
tmsh modify sys httpd auth-pam-idle-timeout 900
tmsh modify sys httpd ssl-ciphersuite 'DEFAULT:!aNULL:!eNULL:!EXPORT:!EXP:!ADH:!DES:!RC4:!RSA:!LOW:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!DHE'
tmsh modify sys httpd ssl-protocol 'all -SSLv2 -SSLv3 -TLSv1'

if [[ `tmsh list sys httpd allow` == *"ALL"*]]
then
    echo "HTTPD ALLOWS FROM ALL NETWORKS"
else
    echo "HTTPD ACL CONFIGURED"
fi

tmsh modify sys software update auto-check disabled
tmsh modify sys software update auto-phonehome disabled

tmsh modify sys snmp communities delete { comm-public }

tmsh modify auth password-policy expiration-warning 7
tmsh modify auth password-policy max-duration 90
tmsh modify auth password-policy max-login-failures 3
tmsh modify auth password-policy min-duration 1
tmsh modify auth password-policy minimum-length 8
tmsh modify auth password-policy password-memory 3
tmsh modify auth password-policy policy-enforcement enabled
tmsh modify auth password-policy required-lowercase 2
tmsh modify auth password-policy required-numeric 2
tmsh modify auth password-policy required-special 2
tmsh modify auth password-policy required-uppercase 2


tmsh modify sys db systemauth.disablebash value true
tmsh modify sys db systemauth.disablerootlogin value true


