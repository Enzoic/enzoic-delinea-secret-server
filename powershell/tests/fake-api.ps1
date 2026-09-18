param([int]$Port = 8787)
$ErrorActionPreference = 'Stop'

$prefix = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "LISTENING $prefix"

function Get-Sha256Hex([string]$s) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($s)) } finally { $sha.Dispose() }
    return (-join ($b | ForEach-Object { $_.ToString('x2') })).ToLower()
}

# ---- fake Secret Server data ----------------------------------------------
$folders = @(
    @{ id = 1; folderName = 'Service Accounts'; folderPath = '\Service Accounts' }
    @{ id = 2; folderName = 'Finance';          folderPath = '\Finance' }
    @{ id = 3; folderName = 'Shared';           folderPath = '\Finance\Shared' }
    @{ id = 4; folderName = 'Shared';           folderPath = '\Service Accounts\Shared' }
    @{ id = 5; folderName = 'Solo';             folderPath = '\Solo' }
)
$secrets = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt 105; $i++) {
    [void]$secrets.Add(@{ id = 1000 + $i; name = "svc-$i"; folderId = 1
                          folderPath = '\Service Accounts'; checkOutEnabled = $false })
}
[void]$secrets.Add(@{ id = 9001; name = 'needs-checkout'; folderId = 2
                      folderPath = '\Finance'; checkOutEnabled = $true })
[void]$secrets.Add(@{ id = 9002; name = 'forbidden'; folderId = 2
                      folderPath = '\Finance'; checkOutEnabled = $false })
[void]$secrets.Add(@{ id = 9003; name = 'compromised'; folderId = 5
                      folderPath = '\Solo'; checkOutEnabled = $false })
[void]$secrets.Add(@{ id = 9004; name = 'weak'; folderId = 5
                      folderPath = '\Solo'; checkOutEnabled = $false })
[void]$secrets.Add(@{ id = 9005; name = 'clean'; folderId = 5
                      folderPath = '\Solo'; checkOutEnabled = $false })
[void]$secrets.Add(@{ id = 9006; name = 'apidown'; folderId = 5
                      folderPath = '\Solo'; checkOutEnabled = $false })
[void]$secrets.Add(@{ id = 9007; name = 'dup-of-compromised'; folderId = 5
                      folderPath = '\Solo'; checkOutEnabled = $false })

$pwFor = @{
    9003 = 'breached1'; 9004 = 'weakpw'; 9005 = 'cleanpw'
    9006 = 'servererror'; 9007 = 'breached1'
}

# ---- counters the tests assert on -----------------------------------------
$state = @{
    TokenBodies  = New-Object System.Collections.ArrayList
    EnzoicBodies = New-Object System.Collections.ArrayList
    AuthedGets   = 0
    Force401At   = -1        # set via /_control to force one 401
    Fired401     = $false
    SlowTokenFor = 0         # sleep this many seconds on the next token call
    TokenErrorDesc = ''      # error_description to return on a rejected grant
}

function Send-Json($ctx, $obj, [int]$status = 200) {
    $json  = $obj | ConvertTo-Json -Depth 8 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $ctx.Response.StatusCode  = $status
    $ctx.Response.ContentType = 'application/json'
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.OutputStream.Close()
}
function Read-Body($ctx) { return (New-Object IO.StreamReader($ctx.Request.InputStream)).ReadToEnd() }
function Get-Page($items, $q) {
    $take = 100; $skip = 0
    if ($q['take']) { $take = [int]$q['take'] }
    if ($q['skip']) { $skip = [int]$q['skip'] }
    $slice = @($items | Select-Object -Skip $skip -First $take)
    return @{ records = $slice; hasNext = (($skip + $slice.Count) -lt $items.Count)
              nextSkip = $skip + $slice.Count; total = $items.Count }
}

while ($listener.IsListening) {
    $ctx  = $listener.GetContext()
    $path = $ctx.Request.Url.AbsolutePath
    $q = @{}
    foreach ($k in $ctx.Request.QueryString.AllKeys) { if ($k) { $q[$k] = $ctx.Request.QueryString[$k] } }

    try {
        # ---- control plane for the tests ---------------------------------
        if ($path -eq '/_control/reset') {
            $state.TokenBodies.Clear(); $state.EnzoicBodies.Clear()
            $state.AuthedGets = 0; $state.Fired401 = $false
            $state.Force401At = -1
            $state.TokenErrorDesc = ''
            if ($q['force401At']) { $state.Force401At = [int]$q['force401At'] }
            if ($q['tokenErrorDesc']) { $state.TokenErrorDesc = [string]$q['tokenErrorDesc'] }
            Send-Json $ctx @{ ok = $true }; continue
        }
        if ($path -eq '/_control/stats') {
            Send-Json $ctx @{
                tokenCalls   = $state.TokenBodies.Count
                tokenBodies  = @($state.TokenBodies.ToArray())
                enzoicCalls  = $state.EnzoicBodies.Count
                enzoicBodies = @($state.EnzoicBodies.ToArray())
                authedGets   = $state.AuthedGets
                fired401     = $state.Fired401
            }; continue
        }

        # ---- fake Enzoic -------------------------------------------------
        if ($path -eq '/enzoic/passwords') {
            $body = Read-Body $ctx
            [void]$state.EnzoicBodies.Add($body)
            $auth = $ctx.Request.Headers['Authorization']

            if ($auth -ne 'basic DEADBEEFDEADBEEFDEADBEEFDEADBEEF') {
                Send-Json $ctx @{ message = 'bad key' } 401; continue
            }
            $partial = ($body | ConvertFrom-Json).partialSHA256
            if ($partial.Length -ne 10) { Send-Json $ctx @{ message = "bad prefix len $($partial.Length)" } 400; continue }

            $breached = Get-Sha256Hex 'breached1'
            $weak     = Get-Sha256Hex 'weakpw'
            $err      = Get-Sha256Hex 'servererror'

            if ($partial -eq $err.Substring(0,10)) { Send-Json $ctx @{ message = 'boom' } 500; continue }

            if ($partial -eq $breached.Substring(0,10)) {
                Send-Json $ctx @{ candidates = @(
                    # a decoy sharing the prefix: the client MUST compare the FULL hash
                    @{ sha256 = ($breached.Substring(0,10) + ('f' * 54)); revealedInExposure = $true; exposureCount = 999999 }
                    @{ sha256 = $breached.ToUpper(); revealedInExposure = $true; exposureCount = 12345 }
                )}; continue
            }
            if ($partial -eq $weak.Substring(0,10)) {
                Send-Json $ctx @{ candidates = @(
                    @{ sha256 = $weak; revealedInExposure = $false }   # exposureCount omitted
                )}; continue
            }
            Send-Json $ctx @{ message = 'not found' } 404      # 404 = clean
            continue
        }

        # ---- fake Secret Server ------------------------------------------
        if ($path -eq '/SecretServer/oauth2/token') {
            $body = Read-Body $ctx
            [void]$state.TokenBodies.Add($body)
            if ($state.SlowTokenFor -gt 0) { Start-Sleep -Seconds $state.SlowTokenFor }
            if ($body -match 'grant_type=password') {
                $pw = [Uri]::UnescapeDataString((($body -split '&' |
                      Where-Object { $_ -like 'password=*' }) -replace '^password='))
                if ($pw -ne 'p@ss&w+rd=1 x') {
                    # Secret Server sends error_description only sometimes; the
                    # tests cover both shapes.
                    $err = @{ error = 'invalid_grant' }
                    if ($state.TokenErrorDesc) { $err['error_description'] = $state.TokenErrorDesc }
                    Send-Json $ctx $err 400; continue
                }
            }
            Send-Json $ctx @{ access_token = "tok-$($state.TokenBodies.Count)"
                              refresh_token = 'rt-1'; expires_in = '1200'; token_type = 'bearer' }
            continue
        }

        # everything under /api needs a bearer token
        if ($path -like '/SecretServer/api/*') {
            $state.AuthedGets++
            if ($state.Force401At -ge 0 -and $state.AuthedGets -eq $state.Force401At -and -not $state.Fired401) {
                $state.Fired401 = $true
                Send-Json $ctx @{ message = 'token expired' } 401; continue
            }
            if ($ctx.Request.Headers['Authorization'] -notlike 'Bearer tok-*') {
                Send-Json $ctx @{ message = 'no bearer' } 401; continue
            }
        }

        if ($path -eq '/SecretServer/api/v1/folders') {
            $text = ''
            if ($q['filter.searchText']) { $text = $q['filter.searchText'] }
            Send-Json $ctx (Get-Page @($folders | Where-Object { $_.folderName -like "*$text*" }) $q)
            continue
        }
        if ($path -eq '/SecretServer/api/v2/secrets') {
            $hit = @($secrets)
            if ($q['filter.folderId']) {
                $fid = [int]$q['filter.folderId']
                $hit = @($secrets | Where-Object { $_.folderId -eq $fid })
            }
            Send-Json $ctx (Get-Page $hit $q); continue
        }
        if ($path -match '^/SecretServer/api/v2/secrets/(\d+)$') {
            $id = [int]$Matches[1]
            if ($q['noAutoCheckout'] -ne 'true') { Send-Json $ctx @{ message = 'noAutoCheckout missing' } 500; continue }
            if ($id -eq 9002) { Send-Json $ctx @{ message = 'nope' } 403; continue }
            $pw = "Password$id!"
            if ($pwFor.ContainsKey($id)) { $pw = $pwFor[$id] }
            if ($id -eq 1000 -or $id -eq 1001) { $pw = 'hunter2' }
            Send-Json $ctx @{
                id = $id; name = "secret-$id"
                items = @(
                    @{ slug = 'username'; itemValue = "user$id"; isPassword = $false; isFile = $false }
                    @{ slug = 'password'; itemValue = $pw;       isPassword = $true;  isFile = $false }
                    @{ slug = 'private-key'; itemValue = 'BLOB'; isPassword = $true;  isFile = $true }
                )
            }
            continue
        }

        Send-Json $ctx @{ message = "no route $path" } 404
    } catch {
        try { Send-Json $ctx @{ message = "$_" } 500 } catch { }
    }
}
