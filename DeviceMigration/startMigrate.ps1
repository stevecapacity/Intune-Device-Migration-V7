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

# Move module to PSModule variable
Move-Item "$($PSScriptRoot)\DeviceMigration.psm1" -Destination "$($env:ProgramFiles)\WindowsPowerShell\Modules\" -Force

# Import module
Import-Module DeviceMigration -Force

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
    $user = userObject -domainJoined $pc.domainJoined -azureAdJoined $pc.azureAdJoined -headers $sourceHeaders
    log "Current (OLD) user object record created successfully."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to create current (OLD) user object record. Error: $message"
    log "Exiting script."
    exitScript -exitCode 4 -functionName "userObject"
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
if($config.SCCM -eq $true)
{
    log "Checking for SCCM client..."
    $CCMpath = "C:\Windows\ccmsetup\ccmsetup.exe"
    if($CCMpath)
    {
        log "SCCM client found.  Removing SCCM client..."
        Start-Process -FilePath $CCMpath -ArgumentList "/uninstall" -Wait -NoNewWindow
        $CCMProcess = Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue
        if($CCMProcess)
        {
            log "SCCM client still running; stopping..."
            Stop-Process -Name "ccmsetup" -Force -ErrorAction SilentlyContinue
            log "SCCM client stopped successfully."
        }
        else
        {
            log "SCCM client removed successfully."
        }
    }

    # Stop SCCM services
    $services = @("CcmExec","smstsmgr","CmRcService","ccmsetup")
    foreach($service in $services)
    {
        log "Stopping $($service) service..."
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        log "$($service) service stopped successfully."
    }
    else
    {
        log "$service not found."
    }

    # remove WMI Namespaces
    Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name = 'ccm'" -Namespace "root" | Remove-WmiObject
    Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name = 'sms'" -Namespace "root\cimv2" | Remove-WmiObject

    # remove SCCM registry keys
    $sccmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\"
    foreach($service in $services)
    {
        $serviceKey = $sccmRegPath + $service
        if(Test-Path $serviceKey)
        {
            log "Removing $serviceKey registry key..."
            Remove-Item -Path $serviceKey -Recurse -Force -ErrorAction SilentlyContinue
            log "Removed $serviceKey registry key."
        }
        else
        {
            log "$serviceKey registry key not found."
        }
    }

    # remove sccm registry keys
    $sccmRegPath = "HKLM:\SOFTWARE\Microsoft\"
    $sccmKeys = @("CCM","SMS","CCMSetup")
    foreach($key in $sccmKeys)
    {
        $keyPath = $sccmRegPath + $key
        if(Test-Path $keyPath)
        {
            log "Removing $keyPath registry key..."
            Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue
            log "Removed $keyPath registry key."
        }
        else
        {
            log "$keyPath registry key not found."
        }
    }

    # Reset MDM authority
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove SCCM files and folders
    $sccmFolders = @("C:\Windows\ccm","C:\Windows\ccmsetup","C:\Windows\ccmcache","C:\Windows\ccmcache2","C:\Windows\SMSCFG.ini","C:\Windows\SMS*.mif")
    foreach($folder in $sccmFolders)
    {
        if(Test-Path $folder)
        {
            log "Removing $folder..."
            Remove-Item -Path $folder -Recurse -Force -ErrorAction SilentlyContinue
            log "Removed $folder."
        }
        else
        {
            log "$folder not found."
        }
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

shutdown -r -t 30

Stop-Transcript