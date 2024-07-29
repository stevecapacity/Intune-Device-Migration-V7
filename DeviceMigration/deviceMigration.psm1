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
        [string]$localpath = $config.localPath,
        [array]$tasks = @("reboot", "postMigrate")
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
        foreach($task in $tasks)
        {
            Disable-ScheduledTask -TaskName $task -Verbose
            log "Disabled $($task) task."
        }
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
        foreach($task in $tasks)
        {
            Disable-ScheduledTask -TaskName $task -Verbose
            log "Disabled $($task) task."
        }
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
        log "Setting install tag for Intune app detection..."
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