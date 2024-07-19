# try to get new user

$sam = $user.SAMName
$newUserId = (Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName,'$sam')").value.id

if([string]::IsNullOrEmpty($newUser))
{
    Write-Host "User not found"
    $newUPN = getTargetUserName
    $newUserId = (Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/beta/users?`$filter=startsWith(userPrincipalName,'$newUPN')").value.id
    if([string]::IsNullOrEmpty($newUser))
    {
        $newUserId = $null
    }
    else
    {
        Write-Host "User found"
        $newUserId = $newUserId
    }
}
else
{
    Write-Host "User found"
    $newUserId = $newUserId
}

if([string]::IsNullOrEmpty($newUserId))
{
    Write-Host "User not found"
    exit 1
}
else
{
    Write-Host "User found.  Converting to SID"
    $newSID = ConvertToSid -ObjectId $newUserId
}

reg.exe add $regPath /v "NewSID" /t REG_SZ /d $newSID /f