function log {
    param (
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$ts - $message"
}

Start-Transcript -Path "C:\ProgramData\IntuneMigration\userFinder.log" -Append -Verbose

$installedNuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
if(-not($installedNuget))
{
    log "NuGet package provider not installed.  Installing..."
    Install-PackageProvider -Name NuGet -Force
    log "NuGet package provider installed successfully."
}
else
{
    log "NuGet package provider already installed."
}
# Check for Az.Accounts module
$installedAzAccounts = Get-Module -Name Az.Accounts -ErrorAction SilentlyContinue
if(-not($installedAzAccounts))
{
    log "Az.Accounts module not installed.  Installing..."
    Install-Module -Name Az.Accounts -Force
    Import-Module Az.Accounts
    log "Az.Accounts module installed successfully."
}
else
{
    log "Az.Accounts module already installed."
    Import-Module Az.Accounts
}
Connect-AzAccount
$theToken = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"

#Get Token form OAuth
$token = -join("Bearer ", $theToken.Token)

#Reinstantiate headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", $token)
$headers.Add("Content-Type", "application/json")

$newUserObject = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/me" -Headers $headers -Method "GET"

$newUser = @{
    upn = $newUserObject.userPrincipalName
    entraUserId = $newUserObject.id
    SAMName = $newUserObject.userPrincipalName.Split("@")[0]
    SID = $newUserObject.securityIdentifier
}

foreach($x in $newUser.Keys)
{
    $newUserName = "NEW_$($x)"
    $newUserValue = $($newUser[$x])
    if(![string]::IsNullOrEmpty($newUserValue))
    {
        log "Writing $($newUserName) with value $($newUserValue)..."
        try
        {
            reg.exe add "HKLM\SOFTWARE\IntuneMigration" /v $newUserName /t REG_SZ /d $newUserValue /f | Out-Null
            log "Successfully wrote $($newUserName) with value $($newUserValue)."
        }
        catch
        {
            $message = $_.Exception.Message
            log "Failed to write $($newUserName) with value $($newUserValue).  Error: $($message)."
        }
    }
}

Stop-Transcript