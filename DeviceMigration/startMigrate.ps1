<# INTUNE TENANT-TO-TENANT DEVICE MIGRATION V7.0
Synopsis
This solution will automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be Hybrid Entra Joined, Active Directory Domain Joined, or Entra Joined.
DESCRIPTION
Intune Device Migration Solution leverages the Microsoft Graph API to automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.  The solution will also migrate the device's primary user profile data and files.  The solution leverages Windows Configuration Designer to create a provisioning package containing a Bulk Primary Refresh Token (BPRT).  Tasks are set to run after the user signs into the PC with destination tenant credentials to update Intune attributes including primary user, Entra ID device group tag, and device category.  In the last step, the device is registered to the destination tenant Autopilot service.  
USE
This script is packaged along with the other files into an intunewin file.  The intunewin file is then uploaded to Intune and assigned to a group of devices.  The script is then run on the device to start the migration process.

NOTES
When deploying with Microsoft Intune, the install command must be "%WinDir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File startMigrate.ps1" to ensure the script runs in 64-bit mode.
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"

# Import module
Import-Module "$($PSScriptRoot)\DeviceMigration.psm1" -Force

# Import config settings from JSON file
$config = Get-Content "$($PSScriptRoot)\config.json" | ConvertFrom-Json

# Start Transcript
Start-Transcript -Path "$($config.logPath)\DeviceMigration.log" -Append -Verbose
log "Starting Device Migration V-7..."

# Initialize script
log "Initializing startMigrate.ps1..."
try
{
    initializeScript -installTag $true
    log "Script initialized successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to initialize script. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# Copy package files to local machine
$destination = $config.localPath
log "Copying package files to $($destination)..."
Copy-Item -Path "$($PSScriptRoot)\*" -Destination $destination -Recurse -Force
log "Package files copied successfully."

# Authenticate to source tenant
log "Authenticating to source tenant..."
try
{
    $sourceHeaders = msGraphAuthenticate -tenantName $config.sourceTenant.tenantname -clientId $config.sourceTenant.clientId -clientSecret $config.sourceTenant.clientSecret
    log "Authenticated to $($config.sourceTenant.tenantName) source tenant successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to authenticate to $($config.sourceTenant.tenantName) source tenant. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# Authenticate to target tenant
log "Authenticating to target tenant..."
try
{
    $targetHeaders = msGraphAuthenticate -tenantName $config.targetTenant.tenantname -clientId $config.targetTenant.clientId -clientSecret $config.targetTenant.clientSecret
    log "Authenticated to $($config.targetTenant.tenantName) target tenant successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to authenticate to $($config.targetTenant.tenantName) target tenant. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# Check Microsoft account connection registry policy
log "Checking Microsoft account connection registry policy..."
$accountConnectionPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts"
$accountConnectionName = "AllowMicrosoftAccountConnection"
$accountConnectionValue = Get-ItemPropertyValue -Path $accountConnectionPath -Name $accountConnectionName -ErrorAction SilentlyContinue
if($accountConnectionValue -ne 1)
{
    log "Microsoft account connection registry policy is not set. Setting policy..."
    Set-ItemProperty -Path $accountConnectionPath -Name $accountConnectionName -Value 1
    log "Microsoft account connection registry policy set successfully."
}
else
{
    log "Microsoft account connection registry policy is set."
}

function deviceObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$headers,
        [string]$hostname = $env:COMPUTERNAME,
        [string]$serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber,
        [string]$azureAdJoined = (dsregcmd.exe /status | Select-String "AzureAdJoined").ToString().Split(":")[1].Trim(),
        [string]$domainjoined = (dsregcmd.exe /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim(),
        [string]$certPath = "Cert:\LocalMachine\My",
        [string]$intuneIssuer = "Microsoft Intune MDM Device CA",
        [string]$azureIssuer = "MS-Organization-Access",
        [string]$groupTag = $config.groupTag,
        [string]$regPath = $config.regPath,
        [bool]$mdm = $false
    )
    $cert = Get-ChildItem -Path $certPath | Where-Object {$_.Issuer -match $intuneIssuer}
    if($cert)
    {
        $mdm = $true
        $intuneId = ((Get-ChildItem $cert | Select-Object Subject).Subject).TrimStart("CN=")
        $entraDeviceId = ((Get-ChildItem $certPath | Where-Object {$_.Issuer -match $azureIssuer} | Select-Object Subject).Subject).TrimStart("CN=")
        $autopilotObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers)
        if(($autopilotObject.'@odata.count') -eq 1)
        {
            $autopilotId = $autopilotObject.value.id
            if([string]::IsNullOrEmpty($groupTag))
            {
                $groupTag = $autopilotObject.value.groupTag
            }
            else
            {
                $groupTag = $groupTag
            }
        }
        else
        {
            $autopilotId = $null
        }   
    }
    else
    {
        $intuneId = $null
        $entraDeviceId = $null
        $autopilotId = $null
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        $groupTag = $null
    }
    else
    {
        $groupTag = $groupTag
    }
    $pc = @{
        hostname = $hostname
        serialNumber = $serialNumber
        azureAdJoined = $azureAdJoined
        domainJoined = $domainJoined
        intuneId = $intuneId
        entraDeviceId = $entraDeviceId
        autopilotId = $autopilotId
        groupTag = $groupTag
        mdm = $mdm
    }
    log "Writing device object to registry..."
    foreach($x in $pc.Keys)
    {
        $name = "OLD_$($x)"
        $value = $($pc[$x])
        if(![string]::IsNullOrEmpty($value))
        {
            log "Writing $($name) with value $($value)."
            try
            {
                reg.exe add $regPath /v $name /t REG_SZ /d $value /f | Out-Host
                log "Successfully wrote $($name) with value $($value)."
            }
            catch
            {
                $message = $_.Exception.Message
                log "Failed to write $($name) with value $($value).  Error: $($message)."
            }
        }
        else
        {
            log "Value for $($name) is null.  Not writing to registry."
        }
    }
    return $pc
}

# Create OLD device object
log "Creating current (OLD) device object record..."
try
{
    $pc = deviceObject -headers $sourceHeaders
    log "Current (OLD) device object record created successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to create current (OLD) device object record. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "deviceObject"
}

# Create OLD user object
log "Creating current (OLD) user object record..."
try
{
    $currentUser = userObject -domainJoined $pc.domainJoined -azureAdJoined $pc.azureAdJoined -headers $sourceHeaders
    log "Current (OLD) user object record created successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to create current (OLD) user object record. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "userObject"
}

# Attempt to get new user info based on current SAMName
$sam = $currentUser.SAMName
$newUserObject = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName,'$sam')" -Headers $targetHeaders

# if new user graph request is successful, set new user object
if($newUserObject.StatusCode -eq 200)
{
    log "New user found in $($config.targetTenant.tenantName) tenant."
    $newUser = @{
        user = $newUserObject.value.userPrincipalName
        entraUserId = $newUserObject.value.id
        SAMName = $newUserObject.value.userPrincipalName.Split("@")[0]
    }
    foreach($x in $newUser)
    {
        $name = "NEW_$($x)"
        $value = $($newUser[$x])
        if(![string]::IsNullOrEmpty($value))
        {
            log "Writing $($name) with value $($value)."
            try
            {
                reg.exe add $config.regPath /v $name /t REG_SZ /d $value /f | Out-Host
                log "Successfully wrote $($name) with value $($value)."
            }
            catch
            {
                $message = $_.Exception.Message
                log "Failed to write $($name) with value $($value).  Error: $($message)."
            }
        }
    }
}
else
{
    log "New user not found."
    # run getTargetUserName function which is a textbox to prompt the user to enter their new email address
    $newUPN = getTargetUserName
    $newUserObject = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$newUPN" -Headers $targetHeaders
    if($newUserObject.StatusCode -eq 200)
    {
        log "New user found in $($config.targetTenant.tenantName) tenant."
        $newUser = @{
            user = $newUserObject.value.userPrincipalName
            entraUserId = $newUserObject.value.id
            SAMName = $newUserObject.value.userPrincipalName.Split("@")[0]
        }
        foreach($x in $newUser)
        {
            $name = "NEW_$($x)"
            $value = $($newUser[$x])
            if(![string]::IsNullOrEmpty($value))
            {
                log "Writing $($name) with value $($value)."
                try
                {
                    reg.exe add $config.regPath /v $name /t REG_SZ /d $value /f | Out-Host
                    log "Successfully wrote $($name) with value $($value)."
                }
                catch
                {
                    $message = $_.Exception.Message
                    log "Failed to write $($name) with value $($value).  Error: $($message)."
                }
            }
        }
    }
    else
    {
        $newUser = $null
        log "New user not found."
    }
}


# Convert new user object ID to SID
if($newUser.id)
{
    $newSID = convertToSid -objectId $newUser.id
    log "New user object ID converted to SID."
    reg.exe add $config.regPath /v "NEW_SID" /t REG_SZ /d $newSID /f | Out-Host
}
else
{
    log "New user object ID not found."
    exitScript -exitCode 4 -functionName "convertToSid"
}

# Remove MDM certificate if present
if($pc.mdm -eq $true)
{
    log "Removing MDM certificate..."
    Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match "Microsoft Intune MDM Device CA"} | Remove-Item -Force
    log "MDM certificate removed successfully."
}
else
{
    log "MDM certificate not present."
}

# Remove MDM enrollment
if($pc.mdm -eq $true)
{
    log "Removing MDM enrollment..."
    $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach($enrollment in $enrollments)
    {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if($key)
        {
            log "Removing MDM enrollment $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recure
            log "MDM enrollment removed successfully."
        }
        else
        {
            log "MDM enrollment not present."
        }
    }
}
else
{
    log "MDM enrollment not present."
}
$enrollId = $enrollPath.Split("\")[-1]
$additionalPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\Provinsioning\OMADM\Accounts\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
    "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
)
foreach($path in $additionalPaths)
{
    if(Test-Path $path)
    {
        log "Removing $($path)..."
        Remove-Item -Path $path -Recurse
        log "$($path) removed successfully."
    }
    else
    {
        log "$($path) not present."
    }
}

# Set migration tasks
log "Setting migration tasks..."
try
{
    setTasks -tasks @("reboot","postMigrate")
    log "Migration tasks set successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set migration tasks. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "setTasks"
}

# Leave Azure AD / Entra Join
if($pc.azureAdJoined -eq "YES")
{
    log "PC is Azure AD Joined.  Leaving Azure AD..."
    try
    {
        Start-Process -FilePath "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
        log "PC left Azure AD successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to leave Azure AD. Error: $message"
        log "Exiting script."
        exitScript -exitCode 4 -functionName "dsregcmd"
    }
}
else
{
    log "PC is not Azure AD Joined."
}

# Leave Domain/Hybrid Join
if($pc.domainJoined -eq "YES")
{
    log "PC is Domain/Hybrid Joined.  Leaving Domain..."
    try
    {
        unjoinDomain -unjoinAccount "Administrator" -hostname $pc.hostname
        log "PC left Domain successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to leave Domain. Error: $message"
        log "Exiting script."
        exitScript -exitCode 4 -functionName "unjoinDomain"
    }
}
else
{
    log "PC is not Domain/Hybrid Joined."
}

# Remove SCCM client if required
log "Checking for SCCM client..."
if($config.SCCM -eq $true)
{
    log "SCCM enabled.  Removing SCCM client..."
    try
    {
        removeSCCM
        log "SCCM client removed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to remove SCCM client. Error: $message"
        log "Exiting script."
        exitScript -exitCode 4 -functionName "removeSCCM"
    }
}
else
{
    log "SCCM not enabled."
}

# Install provisioning package
$ppkg = (Get-ChildItem -Path $config.localPath -Filter "*.ppkg" -Recurse).FullName
if($ppkg)
{
    log "Provisioning package found. Installing..."
    try
    {
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force
        log "Provisioning package installed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to install provisioning package. Error: $message"
        log "Exiting script."
        exitScript -exitCode 4 -functionName "Install-ProvisioningPackage"
    }
}
else
{
    log "Provisioning package not found."
    exitScript -exitCode 4 -functionName "Install-ProvisioningPackage"
}

# Delete Intune and Autopilot object if exist
if($pc.mdm -eq $true)
{
    if([string]::IsNullOrEmpty($pc.intuneId))
    {
        log "Intune object not found."
    }
    else
    {
        log "Deleting Intune object..."
        try
        {
            Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($pc.intuneId)" -Headers $sourceHeaders
            Start-Sleep -Seconds 2
            log "Intune object deleted successfully."
        }
        catch
        {
            $message = $_.Exception.Message
            log "Failed to delete Intune object. Error: $message"
            log "Exiting script."
            exitScript -exitCode 4 -functionName "Intune object delete"
        }
    }
    if([string]::IsNullOrEmpty($pc.autopilotId))
    {
        log "Autopilot object not found."
    }
    else
    {
        log "Deleting Autopilot object..."
        try
        {
            Invoke-RestMethod -Method Delete -Uri "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities/$($pc.autopilotId)" -Headers $sourceHeaders
            Start-Sleep -Seconds 2
            log "Autopilot object deleted successfully."
        }
        catch
        {
            $message = $_.Exception.Message
            log "Failed to delete Autopilot object. Error: $message"
            log "Exiting script."
            exitScript -exitCode 4 -functionName "Autopilot object delete"
        }
    }
}
else
{
    log "PC is not MDM enrolled."
}

# Set Auto logon Admin account
log "Setting Auto logon Admin account..."
try
{
    setAutoLogonAdmin
    log "Auto logon Admin account set successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set Auto logon Admin account. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "setAutoLogonAdmin"
}

# Enable auto logon
log "Enabling auto logon..."
try
{
    toggleAutoLogon -enable $true
    log "Auto logon enabled successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to enable auto logon. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "toggleAutoLogon"
}

# Disable logon provider
log "Disabling logon provider..."
try
{
    toggleLogonProvider -enable $false
    log "Logon provider disabled successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable logon provider. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "disableLogonProvider"
}

# Disable DisplayLastUser
log "Disabling DisplayLastUser..."
try
{
    toggleDisplayLastUser -enable $false
    log "DisplayLastUser disabled successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable DisplayLastUser. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "disableDisplayLastUser"
}

# Set lock screen caption
log "Setting lock screen caption..."
try 
{
    setLockScreenCaption -caption "Device Migration in Progress..." -text "Your PC is being migrated to the $($config.targetTenant.tenantName) tenant and will automatically reboot in 30 seconds.  Please do not power off."
    log "Lock screen caption set successfully."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "setLockScreenCaption"
}

# Stop transcript and restart
log "$pc.hostname will reboot in 30 seconds..."
Stop-Transcript
shutdown -r -t 30

