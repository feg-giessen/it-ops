$wlanName = "" # Name of the WLAN to update
$site = "https://127.0.0.1:8443"
$username = ""
$password = ""

# Logic for generating new PSK key

$psk = "Your new PSK" 
"PSK: $psk" | Write-Host

# Allow self signed certifiactes.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$mySession = $null

$param = '{"username":"' + ${username} + '","password":"' + ${password} + '","remember":false,"strict":true}'
$url = "$site/api/login"
Invoke-RestMethod -SessionVariable mySession -Uri $url -Method Post -Body $param | out-null

$url = "$site/api/s/default/rest/wlanconf"
$wlanList = Invoke-RestMethod -WebSession $mySession -Uri $url -Method Get

$wlanConfig = $wlanList.data | Where { $_.name -eq $wlanName }

if ($wlanConfig -eq $null) {
    throw "WLAN-Configuration not found: " + $wlanName
}

$wlanConfigId = $wlanConfig._id
$wlanConfig.x_passphrase = $psk

$url = "$site/api/s/default/rest/wlanconf/$wlanConfigId"
$wlanConfig | ConvertTo-Json -Compress -OutVariable jsonConfig | out-null

$headers = @{
    'Content-Type' = 'application/json; charset=utf-8'
    'X-Csrf-Token' = ($mySession.Cookies.GetCookies($site) | Where { $_.Name -eq 'csrf_token' }).Value
}
$apiResult = Invoke-RestMethod -WebSession $mySession -Uri $url -Method Put -Body $jsonConfig -Headers $headers

$apiResult.meta.rc | Write-Host
