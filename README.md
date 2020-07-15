# PowerSRG (PowerShell SRG)
# Powershell Script to automate base BIG-IP hardening, and STIG/SRG configuration.
 Michael Coleman, M.Coleman@F5.Com
 
# Instructions
Before running the powershell script, you will need set ScriptExecution policy level:

Set-ExecutionPolicy RemoteSigned

Then, run the script.  The message boxes will guide you...

For the Bash script, just run.

# History
7/15/2020:  Added remediation for [CVE-2020-5902](https://support.f5.com/csp/article/K52145254), as well as latest STIG/SRG updates from MUDG 2.6.  Added notes pointing to configurations that can now be accomplished via [DO](https://github.com/Mikej81/f5-securecloud-DO).  

12/7/2015:  Added Version control, error handling, base icontrol function.  Moved most mods inside testcon, ensures that connection is good, and using a supported version of TMOS.

12/8/2015:  Lots of bug fixes, code cleanup, added functions.

2/25/2016:  Added Cookie encryption iRule.

9/27/2016:  Moved some code around for Windows 10 support.  Tightened security around supported ciphers and protocols for SSHD/HTTPD.

3/17/2017:  Added some updates to PowerSRG.sh.  Not completed, just does the basic patching.  

# *TODO:

-Found Admin rename / disable does not work when using Remote AAA.  Figure out work around for that. Possibly switch to local, update, switch back to AAA. What effects on currently logged in user?

-SelfIP Lockdown

# Verified Working:

* 15.x
* 14.x
* 13.x
* 12.x
* 11.6.x

# PowerShell Functions
-iControl() - streamlines the PowerShell Invoke-RestMethod, adds logging / debug.

-RemoteAuth() - placeholder to support Remote AAA X-F5-Auth-Token in v12. *Caveat:  Will only work in v12.

-ExtractPKCS12() - Performs extraction of Cert/Key pairs from PKCS12 files uploaded to the BIG-IP.

-InstallCrypto() - Installs Cert/Key pair from BIG-IP filesystem.

-UploadCrypto() - Allows uploading of Certs, Keys, and Pairs.

-Get-Filename() - Uses File Dialog window to allow for easy selection of files for upload.

-Get-FileEncoding() - Determines file encoding type, for use later.

# STIG, SRG, CVE, NIST SP 800-53r4 Controls, and General Hardening Resolved with this script:

NIST SP 800-53r4 - Password Strength Policy — IA-5(1)

NIST SP 800-53r4 - Usage banner — AC-8

NIST SP 800-53r4 - Maximum Failed Login Attempts — AC-7

NIST SP 800-53r4 / STIG NET1639 - Idle Timeouts for Management Access — AC-2(5), SC-10

NIST SP 800-53r4 - Session Locking and Termination — AC-11, AC-12 (Advice-only block)

NIST SP 800-53r4 / STIG NET0812 - NTP Configuration — AU-8(1,2)

STIG NET1645 - SSHD Lockdown

STIG NET0405 - Call Home Disable.

STIG NET1665 - Remove default SNMP communities

STIG NET0700 - Appliance Mode
