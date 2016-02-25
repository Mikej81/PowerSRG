################################################
## BashSRG - Bash STIG/SRG configuration Script
## Michael Coleman.  M.Coleman@F5.com
################################################
#!/bin/sh
vercomp () {
    if [[ $1 == $2 ]]
    then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done
    return 0
}
icontrol() {
	
}

echo 
echo "###############################################"
echo " BASHSRG - Bash STIG/SRG Configuration Script"
echo " Michael Coleman.  M.Coleman@F5.com\\n"
echo "###############################################"
echo

logging=true
jsontrue='{"value": "true"}'
jsonfalse='{"value": "false"}'

echo -n "Enter BIG-IP FQDN (Excluding https://) and press [ENTER]: "
read bigiphost
if [[ "$bigiphost" == "" ]]
then
	echo "Not host entered.  Exiting..."
	exit
fi
##Classification Settings:  class/unclass
echo -n "Enter BIG-IP Classification (class/unclass) and press [ENTER]: (default: unclass)"
read bigipclass

if [ -n "$bigipclass" ]
 then
	bigipclass="unclass"
fi
if [ "$bigipclass" = "unclass" ]
 then
    ui_advisory_color="green" 
    ui_advisory_text="//UNCLASSIFIED//"
else
    ui_advisory_color="red"
    ui_advisory_text="//CLASSIFIED//"
fi

bannerText='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:\r\n\r\nThe USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\r\n\r\nAt any time, the USG may inspect and seize data stored on this IS.\r\nCommunications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.\r\nThis IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\r\n\r\nNotwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'


echo -n "Enter Username and press [ENTER]: "
read _username
echo -n "Password: "
read -s _password

testconn=`curl -i -sk --user $_username:$_password -H 'application/json' -X GET https://$bigiphost/mgmt/tm/sys/version -c bigipcookie.txt | tr , '\n\' | grep Version | sed 's/^.*[^0-9]\([0-9]*\.[0-9]*\.[0-9]*\).*$/\1/'`

#If Connection is good, lets make magic happen!
if [ -n "$testconn" ]
 	then
		##extract version
		#echo "$testconn"
		testauth=`curl -i -sk --user $_username:$_password -H 'application/json' -X GET https://$bigiphost/mgmt/tm/auth/source -b bigipcookie.txt`
	    if [ -n "$testauth" ] 
	    	then
	    	#echo $testauth
	        AAAsource="$testauth"
	    fi

    if vercomp $ver 12.0
    	then
    	##TMOS Version 12 Only Configs
    	echo "Success:  Script has been successfully tested on this version.  Configuration will continue."

	    #Set Up Headers
	    if [[ "$AAAsource" == *"local"* ]]
	    	then
	    	echo "Not local auth."
	    fi
    elif vercomp $ver 11.5
   		then
    		##TMOS Version Less than or Equal to 11.5
    		echo "Script has not been tested on TMOS versions below 11.6.  Script will exit" 
    		exit
    else 
    	##TMOS Version 11.6
        echo "Success:  Script has been successfully tested on this version. Configuration will continue."
    fi
	#[STIG NET1645]
	#SSHD Configurations
	sshdjson='
	{
	    "inactivityTimeout":  "600",
	    "banner":  "enabled",
	    "banner-text":  "$bannerText",
	"include":  "Protocol 2\r\nMaxAuthTries 3\r\nCiphers aes128-ctr,aes192-ctr,aes256-ctr"
	}
	'
	sshdresponse=`curl -i -sk --user $_username:$_password -H 'application/json' -X PATCH https://$bigiphost/mgmt/tm/sys/sshd -b bigipcookie.txt -d $sshdjson` 
	#[STIG NET0812]
	#NTP Settings
	echo "Enter NTP Servers (seperated by a comma) and press [ENTER]: "
	read NTPQuestion
	ntpjson='
	{
	    "servers": [ "$NTPQuestion" ]
	}
	'
	if [ -n "$NTPQuestion" ]
		then
		ntpresponse=`curl -i -sk --user $_username:$_password -H 'application/json' -X PATCH https://$bigiphost/mgmt/tm/sys/ntp/ -b bigipcookie.txt -d $ntpjson`
	fi

	##Global Settings
	##
fi