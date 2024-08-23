function log {
    param (
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$ts - $message"
}

Import-Module Az.Accounts

#Get Token form OAuth
Clear-AzContext -Force
Update-AzConfig -EnableLoginByWam $false -LoginExperienceV2 Off
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
} | ConvertTo-JSON

$newUser | Out-File "C:\Users\Public\Documents\newUserInfo.json"
