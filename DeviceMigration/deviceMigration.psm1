# Intune Device Migration Module
# Author: Steve Weiner
# Version: 1.0
# Date: 07/15/2024
# Description: This module contains all functions that are used in the Intune Device Migration solution.

# FUNCTION: log
# DESCRIPTION: Logs messages to the console and to a log file.
# PARAMETERS: $message - The message to log.

function log()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$timestamp - $message"
}

# FUNCTION: exitScript
# DESCRIPTION: Exits the script with error code and takes action depending on the error code.
# PARAMTETERS: $errorCode - The error code to exit with, $functionName - The name of the function that is exiting.

function exitScript()
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [int]$errorCode,
        [Parameter(Mandatory=$true)]
        [string]$functionName,
        [string]$localpath = $config.localPath
    )
    if($exitCode -eq 1)
    {
        log "Function $($functionName) failed with critical error.  Exiting script with exit code $($exitCode)."
        log "Will remove $($localpath) and reboot device.  Please log in with local admin credentials on next boot to troubleshoot."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        # enable password logon provider
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
        log "Enabled logon provider."
        log "rebooting device..."
        shutdown -r -t 30
        Stop-Transcript
        Exit 1
    }
    elseif($exitCode -eq 4)
    {
        log "Function $($functionName) failed with non-critical error.  Exiting script with exit code $($exitCode)."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        Stop-Transcript
        Exit 0
    }
    else
    {
        log "Function $($functionName) failed with unknown error.  Exiting script with exit code $($exitCode)."
        Stop-Transcript
        Exit 0
    }
}

# FUNCTION: generatePassword
# DESCRIPTION: Generates a random password.
# PARAMETERS: $length - The length of the password to generate.

function generatePassword()
{
    Param(
        [int]$length = 12
    )
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
    $securePassword = New-Object -TypeName System.Security.SecureString
    1..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}

# FUNCTION: initializeScript
# DESCRIPTION: Initializes the script by creating a log file and starting a transcript.
# PARAMETERS: $logPath - The path to the log file, $installTag - used in startMigrate.ps1 to indicate to Intune that package installed, $localPath - The path to the local directory.

function initializeScript()
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false)]
        [bool]$installTag,
        [string]$localPath = $config.localPath
    )
    log "Initializing script..."
    if(!(Test-Path $localPath))
    {
        New-Item -ItemType Directory -Path $localPath -Force -Verbose
        log "Created $($localPath)."
    }
    else
    {
        log "$($localPath) already exists."
    }
    if($installTag -eq $true)
    {
        $installTagPath = "$($localPath)\installed.tag"
        New-Item -ItemType File -Path $installTagPath -Force -Verbose
        log "Created $($installTagPath)."
    }
    $context = whoami
    log "Running as $($context)."
}

# FUNCTION: msGraphAuthenticate
# DESCRIPTION: Authenticates to Microsoft Graph.
# PARAMETERS: $tenantId - The tenant ID, $clientId - The client ID, $clientSecret - The client secret.

function msGraphAuthenticate()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$tenantName,
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$clientSecret
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)
    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body
    # Get token from OAuth response

    $token = -join ("Bearer ", $response.access_token)

    # Reinstantiate headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    log "MS Graph Authenticated."
    return $headers
}

# FUNCTION: toggleDisplayLastUser
# DESCRIPTION: Toggles the display last user setting.
# PARAMETERS: $enable - Whether to enable or disable the setting.

function toggleDisplayLastUser()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [bool]$enable,
        [string]$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regName = "DontDisplayLastUserName"
    )
    $currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if($enable -eq $false)
    {
        if($currentValue -eq 1)
        {
            log "Display last user is already disabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Verbose
            log "Disabled display last user."
        }
    }
    elseif($enable -eq $true)
    {
        if($currentValue -eq 0)
        {
            log "Display last user is already enabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Verbose
            log "Enabled display last user."
        }
    }
    else
    {
        log "Invalid parameter.  Please specify either true or false."
    }
}

# FUNCTION: deviceObject
# DESCRIPTION: Creates a device object.
# PARAMETERS: $hostname - The hostname of the device, $serialNumber - The serial number of the device, $azureAdJoined - Whether the device is Azure AD joined, $domainJoined - Whether the device is domain joined, $certPath - The path to the certificate store, $intuneIssuer - The Intune certificate issuer, $azureIssuer - The Azure certificate issuer, $groupTag - The group tag, $mdm - Whether the device is MDM enrolled.

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

# FUNCTION: userObject
# DESCRIPTION: Creates a user object.
# PARAMETERS: $domainJoined - Whether the user is domain joined, $azureAdJoined - Whether the user is Azure AD joined, $headers - The headers for the REST API call.
function userObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domainJoined,
        [Parameter(Mandatory=$true)]
        [string]$azureAdJoined,
        [Parameter(Mandatory=$true)]
        [object]$headers,
        [string]$regPath = $config.regPath,
        [string]$user = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath"),
        [string]$SAMName = ($user).Split("\")[1]
    )
    if($domainJoined -eq "NO")
    {
        $upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName")
        if($azureAdJoined -eq "YES")
        {
            $entraUserId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
        }
        else
        {
            $entraUserId = $null
        }
    }
    else
    {
        $upn = $null
        $entraUserId = $null
    }
    $user = @{
        user = $user
        upn = $upn
        entraUserId = $entraUserId
        profilePath = $profilePath
        SAMName = $SAMName
        SID = $SID
    }
    foreach($x in $user.Keys)
    {
        $name = "OLD_$($x)"
        $value = $($user[$x])
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
    }
    return $user
}

# FUNCTION: setTasks
# DESCRIPTION: Sets the scheduled tasks.
# PARAMETERS: $taskName - The name of the task, $taskPath - The path to the task

function setTasks()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [array]$tasks,
        [string]$localPath = $config.localPath
    )
    foreach($task in $tasks)
    {
        $taskPath = "$($localPath)\$($task).xml"
        if($taskPath)
        {
            log "Setting $($task) task..."
            schtasks.exe /Create /XML $taskPath /TN $task /F | Out-Host
            log "Successfully set $($task) task."
        }
        else
        {
            log "Failed to set $($task) task."
        }
    }
}

# FUNCTION: unjoinDomain
# DESCRIPTION: Unjoins the device from the domain.
# PARAMETERS: $unjoinAccount - The account to unjoin the device with, $hostname - The hostname of the device.

function unjoinDomain()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$unjoinAccount,
        [Parameter(Mandatory=$true)]
        [string]$hostname
    )
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceAlias
    $dns = Get-DnsClientServerAddress -InterfaceAlias $adapter | Select-Object -ExpandProperty ServerAddresses
    if($dns -ne '8.8.8.8')
    {
        log "Breaking line of sight to domain controller..."
        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses ("8.8.8.8","8.8.4.4")
        log "Successfully broke line of sight to domain controller."
    }
    else
    {
        log "Line of sight to domain controller is already broken."
    }
    $password = generatePassword
    log "Generated password for $unjoinAccount."
    log "Checking $unjoinAccount status..."
    [bool]$acctStatus = (Get-LocalUser -Name $unjoinAccount).Enabled
    if($acctStatus -eq $false)
    {
        log "$unjoinAccount is disabled; setting password and enabling..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        Get-LocalUser -Name $unjoinAccount | Enable-LocalUser
        log "Successfully set password and enabled $unjoinAccount."
    }
    else
    {
        log "$unjoinAccount is enabled; setting password..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        log "Successfully set password for $unjoinAccount."
    }
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$hostname\$unjoinAccount", $password)
    log "Unjoining $hostname from domain..."
    Remove-Computer -UnjoinDomainCredential $cred -PassThru -Force -Verbose
    log "Successfully unjoined $hostname from domain."
}

# FUNCTION: toggleLogonProvider
# DESCRIPTION: Toggles the logon provider.
# PARAMETERS: $enable - Whether to enable or disable the logon provider.

function toggleLogonProvider()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [bool]$enable,
        [string]$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",
        [string]$regName = "Disabled"
    )
    if($enable -eq $false)
    {
        $currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if($currentValue -eq 1)
        {
            log "Logon provider is already disabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Verbose
            log "Disabled logon provider."
        }
    }
    elseif($enable -eq $true)
    {
        $currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if($currentValue -eq 0)
        {
            log "Logon provider is already enabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Verbose
            log "Enabled logon provider."
        }
    }
    else
    {
        log "Invalid parameter.  Please specify either true or false."
    }
}

# FUNCTION: setAutoLogonAdmin
# DESCRIPTION: Sets the auto logon for the administrator account.
# PARAMETERS: $username - The username to set auto logon for, $password - The password to set auto logon for.

function setAutoLogonAdmin()
{
    Param(
        [string]$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$regName = "AutoAdminLogon",
        [string]$migrateAdmin = "MigrationInProgress"
    )
    log "Creating local admin account..."
    $adminPW = generatePassword
    $adminGroup = Get-CimInstance -Query "Select * From Win32_Group Where LocalAccount = True And SID = 'S-1-5-32-544'"
    $adminGroupName = $adminGroup.Name
    New-LocalUser -Name $migrateAdmin -Password $adminPW
    Add-LocalGroupMember -Group $adminGroupName -Member $migrateAdmin
    log "Successfully created local admin account."
    reg.exe add $regPath /v "AutoAdminLogon" /t REG_SZ /d 0 /f | Out-Host
    reg.exe add $regPath /v "DefaultUserName" /t REG_SZ /d $migrateAdmin /f | Out-Host
    reg.exe add $regPath /v "DefaultPassword" /t REG_SZ /d "@Password*123" | Out-Host
    log "Successfully set auto logon to $migrateAdmin."
}

# FUNCTION: toggleAutoLogon
# DESCRIPTION: Toggles the auto logon setting.
# PARAMETERS: $enable - Whether to enable or disable the auto logon setting.

function toggleAutoLogon()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [bool]$enable,
        [string]$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$regName = "AutoAdminLogon"
    )
    if($enable -eq $false)
    {
        $currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if($currentValue -eq 0)
        {
            log "Auto logon is already disabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Verbose
            log "Disabled auto logon."
        }
    }
    elseif($enable -eq $true)
    {
        $currentValue = Get-ItemPropertyValue -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        if($currentValue -eq 1)
        {
            log "Auto logon is already enabled."
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Verbose
            log "Enabled auto logon."
        }
    }
    else
    {
        log "Invalid parameter.  Please specify either true or false."
    }
}

# FUNCTION: setLockScreenCaption
# DESCRIPTION: Sets the lock screen caption.
# PARAMETERS: $caption - The caption to set, $text - The text to set.
function setLockScreenCaption()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$caption,
        [Parameter(Mandatory=$true)]
        [string]$text,
        [string]$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    )
    log "Setting lock screen caption..."
    reg.exe add $regPath /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $regPath /v "legalnoticetext" /t REG_SZ /d $text /f | Out-Host
    log "Successfully set lock screen caption."
}

# FUNCTION: getTargetUsername
# DESCRIPTION: Prompts the user for a username.

function getTargetUsername()
{
    # Text box
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Enter user name'
    $form.Size = New-Object System.Drawing.Size(300,200)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(75,120)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'OK'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,120)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10,20)
    $label.Size = New-Object System.Drawing.Size(280,20)
    $label.Text = 'Please enter your target email address in the space below and click OK:'
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10,40)
    $textBox.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox)

    $form.Topmost = $true

    $form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $user = $textBox.Text
        return $user
    }
    else
    {
        return $null
    }
}
