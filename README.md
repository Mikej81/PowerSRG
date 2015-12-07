# PowerSRG (PowerShell SRG)
# Powershell Script to automate STIG/SRG configuration on an F5 BIG-IP.
 Michael Coleman, M.Coleman@F5.Com


12/7/2015:  Added Version control, error handling, base icontrol function.  Moved most mods inside testcon, ensures that connection is good, and using a supported version of TMOS.

# *TODO:

-Found Admin rename / disable does not work with using Remote AAA.
Figure out work around for that. Possibly switch to local, update,
switch back to AAA. What effects on currently logged in user?

-Should probably add support for Remote AAA admin users...

-Added iControl Function, need to move all requests.

-Add logging.

# Verified Working:
-11.6.0
-12.0.0

