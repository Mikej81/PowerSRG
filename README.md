# PowerSRG (PowerShell SRG)
# Powershell Script to automate base BIG-IP hardening, and STIG/SRG configuration.
 Michael Coleman, M.Coleman@F5.Com


12/7/2015:  Added Version control, error handling, base icontrol function.  Moved most mods inside testcon, ensures that connection is good, and using a supported version of TMOS.
12/8/2015:  Lots of bug fixes, code cleanup, added functions.

# *TODO:

-Working on CreateClientSSLProfile() function.

-Workflow Upload, Split (key/pair, as needed), install.  Tie to CreateClientSSLProfile() when completed.

-Work on upload NTP keys, and install accordingly.

-Found Admin rename / disable does not work when using Remote AAA.  Figure out work around for that. Possibly switch to local, update,
switch back to AAA. What effects on currently logged in user?

# Verified Working:
-11.6.0

-12.0.0

#Functions
-iControl() - streamlines the PowerShell Invoke-RestMethod, adds logging / debug.

-RemoteAuth() - placeholder to support Remote AAA X-F5-Auth-Token in v12. *Caveat:  Will only work in v12.

-ExtractPKCS12() - Performs extraction of Cert/Key pairs from PKCS12 files uploaded to the BIG-IP.

-InstallCrypto() - Installs Cert/Key pair from BIG-IP filesystem.

-UploadCrypto() - Allows uploading of Certs, Keys, and Pairs.

-Get-Filename() - Uses File Dialog window to allow for easy selection of files for upload.

-Get-FileEncoding() - Determines file encoding type, for use later.
