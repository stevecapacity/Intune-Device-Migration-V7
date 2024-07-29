<# POSTMIGRATE.PS1
Synopsis
PostMigrate.ps1 is run after the migration reboots have completed and the user signs into the PC.
DESCRIPTION
This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.  The device is then registered with AutoPilot.
USE
.\postMigrate.ps1
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"

# Import the module
Import-Module "$($psscriptroot)\DeviceMigration.psm1" -Force

# Import settings from the JSON file
$config = Get-Content "$($psscriptroot)\config.json" | ConvertFrom-Json

# Start Transcript
Start-Transcript -Path "$($config.logPath)\DeviceMigration.log" -Append -Verbose
log "Starting PostMigrate.ps1..."

# Initialize script
log "Initializing script postMigrate.ps1..."
try
{
    initializeScript
    log "Script initialized."
}
catch
{
    $message = $_.Exception.Message
    log "Error initializing script: $message"
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable postMigrate task
log "Disabling postMigrate task..."
Disable-ScheduledTask -TaskName "postMigrate"
log "postMigrate task disabled."

# authenticate to target tenant if exists
if($config.targetTenant.tenantName)
{
    log "Authenticating to target tenant..."
    try
    {
        $headers = msGraphAuthenticate -targetTenant $config.targetTenant.tenantName -clientID $config.targetTenant.clientID -clientSecret $config.targetTenant.clientSecret
        log "Authenticated to target tenant."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Error authenticating to target tenant: $message"
        exitScript -exitCode 5 -functionName "authenticateToTargetTenant"
    }
}
else
{
    log "No target tenant specified.  Authenticating into source tenant."
    try
    {
        $headers = msGraphAuthenticate -sourceTenant $config.sourceTenant.tenantName -clientID $config.sourceTenant.clientID -clientSecret $config.sourceTenant.clientSecret
        log "Authenticated to source tenant."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Error authenticating to source tenant: $message"
        exitScript -exitCode 6 -functionName "authenticateToSourceTenant"
    }
}

# Get current device Intune and Entra attributes
log "Getting current device attributes..."
$intuneDeviceId = ((Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match "Microsoft Intune MDM Device CA"} | Select-Object Subject).Subject).TrimStart("CN=")
$entraDeviceId = ((Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Issuer -match "MS-Organization-Access"} | Select-Object Subject).Subject).TrimStart("CN=")

# FUNCTION: setPrimaryUser
function setPrimaryUser()
{
    param(
        [string]$targetUserId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "NEW_entraUserID").NEW_entraUserID,
        [string]$sourceUserId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OLD_entraUserID").OLD_entraUserID
    )
    if([string]::IsNullOrEmpty($targetUserId))
    {
        log "Target user not found- proceeding with source user $($sourceUserId)."
        $userId = $sourceUserId
    }
    else
    {
        log "Target user found- proceeding with target user $($targetUserId)."
        $userId = $targetUserId
    }
    $userUri = "https://graph.microsoft.com/beta/users/$userId"
    $id = "@odata.id"
    $JSON = @{ $id=$userUri } | ConvertTo-Json
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneDeviceId/users/`$reg" -Method Post -Headers $headers -Body $JSON
    log "Primary user set to $($userId)."
}

# run setPrimaryUser
log "Setting primary user..."
try
{
    setPrimaryUser
    log "Primary user set."
}
catch
{
    $message = $_.Exception.Message
    log "Error setting primary user: $message"
    exitScript -exitCode 4 -functionName "setPrimaryUser"
}

# FUNCTION: updateGroupTag
function updateGroupTag()
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$groupTag
    )
    log "Updating group tag to $($groupTag)..."
    $entraDeviceObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$entraDeviceId" -Headers $headers
    $physicalIds = $entraDeviceObject.physicalIds
    $groupTag = "[OrderID]:$groupTag"
    $physicalIds += $groupTag
    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$entraDeviceId" -Method Patch -Headers $headers -Body $body
    log "Group tag updated to $($groupTag)."
}

# run updateGroupTag
$groupTag = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OLG_groupTag").OLD_groupTag
if([string]::IsNullOrEmpty($groupTag))
{
    log "Group tag not found."
}
else
{
    log "Group tag found- proceeding with group tag $($groupTag)."
    try
    {
        updateGroupTag -groupTag $groupTag
        log "Group tag updated."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Error updating group tag: $message"
        exitScript -exitCode 7 -functionName "updateGroupTag"
    }
}

# FUNCTION: migrateBitlockerKey
function migrateBitlockerKey()
{
    Param(
        [string]$mountPoint = "C:",
        [PSCustomObject]$bitLockerVolume = (Get-BitLockerVolume -MountPoint $mountPoint),
        [string]$keyProtectorId = ($bitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorId
    )
    if($bitLockerVolume.KeyProtector.count -gt 0)
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $keyProtectorId
        log "Bitlocker recovery key migrated."
    }
    else
    {
        log "No bitlocker recovery key found."
    }
}

# FUNCTION: decryptDrive
function decryptDrive()
{
    Param(
        [string]$mountPoint = "C:"
    )
    Disable-BitLocker -MountPoint $mountPoint
    log "Drive decrypted."
}

# check bitlocker settings in config file and either migrate or decrypt
log "Checking bitlocker settings..."
if($config.bitlocker -eq "MIGRATE")
{
    log "Migrating bitlocker recovery key..."
    try
    {
        migrateBitlockerKey
        log "Bitlocker recovery key migrated."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Error migrating bitlocker recovery key: $message"
        exitScript -exitCode 8 -functionName "migrateBitlockerKey"
    }
}
elseif($config.bitlocker -eq "DECRYPT")
{
    log "Decrypting drive..."
    try
    {
        decryptDrive
        log "Drive decrypted."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Error decrypting drive: $message"
        exitScript -exitCode 9 -functionName "decryptDrive"
    }
}
else
{
    log "Bitlocker settings not found."
}

# Register device in Autopilot
log "Registering device in Autopilot..."

# Get hardware info
$serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
$hardwareId = ((Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
$tag = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OLG_groupTag").OLD_groupTag
if([string]::IsNullOrEmpty($tag))
{
    $groupTag = ""
}
else
{
    $groupTag = $tag
}

# Construct JSON
$json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "groupTag":"$groupTag",
    "serialNumber":"$serialNumber",
    "productKey":"",
    "hardwareIdentifier":"$hardwareId",
    "assignedUserPrincipalName":"",
    "state":{
        "@odata.type":"microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus":"pending",
        "deviceRegistrationId":"",
        "deviceErrorCode":0,
        "deviceErrorName":""
    }
}
"@

# Post device
try
{
    Invoke-RestMethod -Method Post -Body $json -ContentType "application/json" -Uri "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities" -Headers $headers
    log "Device registered in Autopilot."
}
catch
{
    $message = $_.Exception.Message
    log "Error registering device in Autopilot: $message"
    exitScript -exitCode 4 -functionName "registerDeviceInAutopilot"
}

# Cleanup
log "Cleaning up migration files..."
Remove-Item -Path $config.localPath -Recurse -Force
log "Migration files cleaned up."

# Remove scheduled tasks
log "Removing scheduled tasks..."
$tasks = @("reboot", "postMigrate")
foreach($task in $tasks)
{
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    log "$task task removed."
}

# Remove MigrationUser
log "Removing MigrationUser..."
Remove-LocalUser -Name "MigrationInProgress"
log "MigrationUser removed."

# End Transcript
log "Device migration complete"
Stop-Transcript