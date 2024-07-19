<# REBOOT.PS1
Synopsis
Reboot.ps1 automatically changes the userSid and user profile ownership to the new user and reboots the machine.
DESCRIPTION
This script is used to change ownership of the original user profile to the destination user and then reboot the machine.  It is executed by the 'reboot' scheduled task.
USE
.\reboot.ps1
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
log "Starting Reboot.ps1..."

# Initialize script
log "Initializing Reboot.ps1..."
try
{
    initializeScript
    log "Script initialized"
}
catch
{
    $message = $_.Exception.Message
    log "Error initializing script: $message"
    exitScript -exitCode 1 -functionName "initializeScript"
}

# disable reboot task
log "Disabling reboot task..."
Disable-ScheduledTask -TaskName "Reboot"
log "Reboot task disabled"

# disable auto logon
log "Disabling auto logon..."
try
{
    toggleAutoLogon -enable $false
    log "Auto logon disabled"
}
catch
{
    $message = $_.Exception.Message
    log "Error disabling auto logon: $message"
    exitScript -exitCode 1 -functionName "disableAutoLogon"
}

# Retrieve variables from registry
log "Retrieving variables from registry..."
$regKey = "Registry::$config.regPath"
$values = (Get-ItemProperty -Path $regKey).Property
foreach($x in $values)
{
    $name = $x
    $value = (Get-ItemProperty -Path $regKey).$x
    if(![string]::IsNullOrEmpty($value))
    {
        log "Retrieved $($name): $value"
        New-Variable -Name $name -Value $value -Force
    }
    else
    {
        log "Error retrieving $name"
        exitScript -exitCode 1 -functionName "retrieveVariables"
    }
}

# Remove aadBrokerPlugin from profile
$aadBrokerPath = (Get-ChildItem -Path "$($OLD_profilePath)\AppData\Local\Packages" -Recures | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"}).FullName
if($aadBrokerPath)
{
    log "Removing aadBrokerPlugin from profile..."
    Remove-Item -Path $aadBrokerPath -Recurse -Force
    log "aadBrokerPlugin removed"
}
else
{
    log "aadBrokerPlugin not found"
}

# Change ownership of user profile
log "Changing ownership of user profile..."
$profile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $OLD_SID}
$changes = @{
    NewOwnerSID = $NEW_SID
    Flags = 0
}
$profile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changes
Start-Sleep -Seconds 1

# Cleanup logon cache
function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUPN = $OLD_UPN
    )
    log "Cleaning up logon cache..."
    $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($GUID in $logonCacheGUID)
    {
        $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No subkeys found for $GUID"
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
                {
                    $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        log "Error - no sub folders found for $subKey"
                        continue
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                            if($cacheUsername -eq $oldUserName)
                            {
                                Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                log "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                continue                                       
                            }
                        }
                    }
                }
            }
        }
    }
}

# run cleanupLogonCache
log "Running cleanupLogonCache..."
try
{
    cleanupLogonCache
    log "cleanupLogonCache completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run cleanupLogonCache: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "cleanupLogonCache"
}

# cleanup identity store cache
function cleanupIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OLD_UPN
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                        if($idCacheUsername -eq $oldUserName)
                        {
                            Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                            log "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                            continue
                        }
                    }
                }
            }
        }
    }
}

# run cleanup identity store cache if not domain joined
if($OLD_domainJoined -eq "NO")
{
    log "Running cleanupIdentityStore..."
    try
    {
        cleanupIdentityStore
        log "cleanupIdentityStore completed"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to run cleanupIdentityStore: $message"
        log "Exiting script..."
        exitScript -exitCode 1 -functionName "cleanupIdentityStore"
    }
}
else
{
    log "Machine is domain joined - skipping cleanupIdentityStore."
}

# update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$targetSAMName = $OLD_SAMName
    )

    if($NEW_SAMName -like "$($OLD_SAMName)_*")
    {
        log "New user is $NEW_SAMName, which is the same as $OLD_SAMName with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($GUID in $logonCacheGUID)
        {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No subkeys found for $GUID"
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    if($subKey -eq "Name2Sid")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $NEW_SID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAMName value (in Name2Sid registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "SAM_Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $NEW_SID)
                                {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $targetSAMName -Force
                                    log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "Sid2Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                if($subFolder -eq $NEW_SID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

# run updateSamNameLogonCache
log "Running updateSamNameLogonCache..."
try
{
    updateSamNameLogonCache
    log "updateSamNameLogonCache completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run updateSamNameLogonCache: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "updateSamNameLogonCache"
}

# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $OLD_SAMName
    )
    if($NEW_SAMName -like "$($OLD_SAMName)_*")
    {
        log "Cleaning up identity store cache..."
        $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($key in $idCacheKeys)
        {
            $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No keys listed under '$idCache\$key' - skipping..."
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        log "No subfolders detected for $subkey- skipping..."
                        continue
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            if($subFolder -eq $NEW_SID)
                            {
                                Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                log "Attempted to update SAMName value to $targetSAMName."
                            }
                            else
                            {
                                log "Skipping different user SID ($subFolder) in $subKey registry folder..."
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $NEW_SAMName, which does not match older username ($OLD_SAMName) with _##### appended to end. SamName IdentityStore registry will not be updated."
    }
}

# run updateSamNameIdentityStore if not domain joined
if($OLD_domainJoined -eq "NO")
{
    log "Running updateSamNameIdentityStore..."
    try
    {
        updateSamNameIdentityStore
        log "updateSamNameIdentityStore completed"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to run updateSamNameIdentityStore: $message"
        log "Exiting script..."
        exitScript -exitCode 1 -functionName "updateSamNameIdentityStore"
    }
}
else
{
    log "Machine is domain joined - skipping updateSamNameIdentityStore."
}

# enable displayLastUserName
log "Enabling displayLastUserName..."
try
{
    toggleDisplayLastUserName -enable $true
    log "displayLastUserName enabled"
}
catch
{
    $message = $_.Exception.Message
    log "Error enabling displayLastUserName: $message"
    exitScript -exitCode 1 -functionName "toggleDisplayLastUserName"
}

# enable logon provider
log "Enabling logon provider..."
try
{
    toggleLogonProvider -enable $true
    log "Logon provider enabled"
}
catch
{
    $message = $_.Exception.Message
    log "Error enabling logon provider: $message"
    exitScript -exitCode 1 -functionName "toggleLogonProvider"
}

# set lock screen caption
log "Setting lock screen caption..."
try
{
    setLockScreenCaption -caption "Welcome to $($config.targetTenant.tenantName)" -text "Please log in with your new email address"
    log "Lock screen caption set"
}
catch
{
    $message = $_.Exception.Message
    log "Error setting lock screen caption: $message"
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

log "Reboot.ps1 complete"
Stop-Transcript

shutdown -r -t 5