<#
.SYNOPSIS
    Read secrets out of Delinea Secret Server and check them against Enzoic.

.DESCRIPTION
    PowerShell port of src/enzoic_delinea/delinea.py. Same endpoints, same
    verdicts, same read-only guarantee - it never writes to Secret Server.

    A pipeline sees one password at the moment it changes. This SWEEPS the
    vault and answers the question a customer asks first: what is already bad
    in there? No WinRM, no CredSSP, no Run Secret, no Run Site, and no
    "Allow Confidential Secret Fields to be used in Scripts".

    With no -Folder and no -All it lists the folders the account can see, so a
    first run is always safe.

    Settings resolve in this order, highest first:
        1. a parameter on the command line
        2. an environment variable (SS_BASE_URL, SS_USERNAME, SS_PASSWORD,
           SS_DOMAIN, ENZOIC_API_KEY)
        3. the config file
    A scheduled task keeps everything in the config file; an operator can
    override any single value for one run without editing it.

    Endpoints (verified against the 12.1.2 OpenAPI spec). Note the versions:
    search and get are v2, folders are v1. /api/v1/secrets has no GET at all.

        POST /oauth2/token                  grant_type=password | refresh_token
        GET  /api/v1/folders                filter.searchText (a CONTAINS match)
        GET  /api/v2/secrets                filter.folderId, paged
        GET  /api/v2/secrets/{id}           items[] incl. isPassword + itemValue

.PARAMETER BaseUrl
    Scheme, host and the /SecretServer virtual directory, e.g.
    https://secretserver.example.com/SecretServer. Without the vdir the token
    endpoint 404s. Also settable as SS_BASE_URL or BaseUrl in the config.

.PARAMETER Username
    Secret Server account. DOMAIN\user is accepted. SS_USERNAME / Username.

.PARAMETER Password
    Password for that account. SS_PASSWORD / Password. Prefer the config file
    for anything repeatable - a command line lands in shell history.

.PARAMETER Domain
    Secret Server domain for an AD-synced account. Refers to the Secret Server
    account, not the Windows account running this. SS_DOMAIN / Domain.

.PARAMETER EnzoicApiKey
    The raw 32-hex Enzoic key - not base64, not key:secret. Omit to list
    secrets without checking them. ENZOIC_API_KEY / EnzoicApiKey.

.PARAMETER Config
    Path to the config file (.psd1 or .json). Default: enzoic-delinea.config.psd1
    next to this script, then in the current directory.

.PARAMETER Folder
    One or more folder names, or full paths. A bare leaf name matching more than
    one folder is an error, not a guess - pass the full path instead.

.PARAMETER All
    Sweep every secret in every visible folder.

.PARAMETER ListFolders
    List visible folders and stop, even when the config file names a folder.

.PARAMETER ReportDirectory
    Write a NEW dated CSV per run into this directory, e.g.
    enzoic-scan-service-accounts-20260827-143012.csv. Nothing is overwritten.

.PARAMETER Csv
    Write to this exact path instead, overwriting it. Use for a "latest.csv"
    that a dashboard picks up; use -ReportDirectory for history.

.PARAMETER RetainReports
    Keep only the newest N reports in -ReportDirectory, deleting older ones.
    0 (the default) keeps everything.

.PARAMETER Reveal
    Print passwords in the console table. Off by default; the table shows
    "<n chars>" instead. Reports never contain passwords either way.

.PARAMETER Insecure
    Skip TLS certificate validation. For a lab with a self-signed cert only.

.PARAMETER PassThru
    Emit the result objects to the pipeline as well as printing the table.

.PARAMETER ProtectSecret
    Prompt for a value and print a DPAPI blob for PasswordEncrypted or
    EnzoicApiKeyEncrypted, then exit. Run this AS THE ACCOUNT THAT WILL RUN THE
    SCAN - a blob generated under your own login does not decrypt for a service
    account, which is the usual way this fails on a domain-joined box.

.PARAMETER MachineScope
    With -ProtectSecret, bind the blob to the MACHINE instead of the user, so
    any account on that computer can decrypt it. Survives a service account
    with no loaded profile and a password reset; the file ACL becomes the real
    control. For unattended scheduled tasks. See the README.

.EXAMPLE
    .\Invoke-EnzoicDelineaScan.ps1
    List the folders this account can see. Always the first run.

.EXAMPLE
    .\Invoke-EnzoicDelineaScan.ps1 -Folder 'Service Accounts' -ReportDirectory C:\enzoic-reports
    Sweep one folder and its subfolders, dropping a new dated report.

.EXAMPLE
    .\Invoke-EnzoicDelineaScan.ps1 -All -PassThru |
        Where-Object { $_.Verdict -eq 'Compromised' } | Sort-Object Exposures -Descending
    Sweep everything and pull out just the breached credentials.

.EXAMPLE
    .\Invoke-EnzoicDelineaScan.ps1 -ProtectSecret -MachineScope
    Print a machine-scope DPAPI blob to paste into the config file.

.NOTES
    Requires Windows PowerShell 5.1 or PowerShell 7+. No modules.
    Read-only. Exit code 0 on success, 1 on a fatal error.
#>

[CmdletBinding()]
param(
    [string]   $Config,
    [string[]] $Folder,
    [switch]   $All,
    [switch]   $ListFolders,
    [string]   $ReportDirectory,
    [string]   $Csv,
    [int]      $RetainReports,
    [switch]   $Reveal,
    [switch]   $Insecure,
    [switch]   $PassThru,
    [switch]   $ProtectSecret,
    [switch]   $MachineScope,

    # Connection settings. Declared last so the positional order of everything
    # above is unchanged. Get-Setting resolves these by name out of
    # $PSBoundParameters, so declaring them is all that is needed.
    [string]   $BaseUrl,
    [string]   $Username,
    [string]   $Password,
    [string]   $Domain,
    [string]   $EnzoicApiKey
)

# StrictMode 1.0 catches the typo that matters (an uninitialized variable) but
# keeps PowerShell's scalar .Count shim. Under 2.0, a function that returns a
# collection of exactly one item unrolls it to a scalar and every .Count on the
# result becomes a hard error - a tenant with one visible folder would crash.
# Collections are still wrapped in @() at each call site below; this is the
# second half of that belt.
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:EnzoicUrl  = 'https://api.enzoic.com/v1/passwords'
$script:TimeoutSec = 60
$script:Retries    = 3

# Secret Server Cloud throttles the API; on-prem effectively does not. A sweep
# is one GET per secret, so a large vault WILL be throttled. Back off and retry
# rather than losing the run. ThrottleDelayMs paces every request and defaults
# to 0, so on-prem behaviour is byte-for-byte what it was.
$script:ThrottleRetries = 5
$script:ThrottleMaxWait = 60
$script:ThrottleDelayMs = 0

# Extra args for Invoke-RestMethod that differ by PowerShell edition.
$script:WebArgs = @{ UseBasicParsing = $true }

# Enzoic answers cached by FULL hash, so a password reused across 40 secrets
# costs one API call.
$script:EnzoicCache = @{}

# Secret Server session state: base url, credentials, tokens, expiry.
$script:SS = $null


#--- helpers -----------------------------------------------------------------#

function Get-Prop {
    <# Safe property read. Secret Server omits fields rather than nulling them,
       and Set-StrictMode turns a missing property into a hard error. #>
    param($Object, [Parameter(Mandatory)][string]$Name, $Default = $null)

    if ($null -eq $Object) { return $Default }
    $p = $null
    try { $p = $Object.PSObject.Properties[$Name] } catch { return $Default }
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function ConvertTo-Hashtable {
    # ConvertFrom-Json has no -AsHashtable on 5.1.
    param($InputObject)

    $h = @{}
    if ($null -eq $InputObject) { return $h }
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function ConvertFrom-SecureStringToPlain {
    param([Parameter(Mandatory)][Security.SecureString]$Secure)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function New-ProtectedSecret {
    <# Print a DPAPI blob for PasswordEncrypted / EnzoicApiKeyEncrypted.

       Run it AS THE ACCOUNT THAT WILL RUN THE SCAN. A user-scope blob made
       under an admin's own login does not decrypt for DEV\svc_enzoic_task, and
       that is the single most common way this fails on a domain-joined box.

       -Machine binds the blob to the computer instead of the user: any account
       on that box can decrypt it, which is what lets it survive a service
       account with no loaded profile, and a password reset. The file ACL
       becomes the real control at that point. That is a policy choice, not a
       default - the README lays out both sides. #>
    param([switch]$Machine)

    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host "Generating a DPAPI value as: $who" -ForegroundColor Cyan
    if ($Machine) {
        Write-Host 'Scope: MACHINE - ANY account on this computer can decrypt it.' -ForegroundColor Yellow
    } else {
        Write-Host "Scope: USER - only $who, on this computer, can decrypt it." -ForegroundColor DarkGray
        Write-Host '       If a scheduled task runs as a different account, re-run this as that account.' -ForegroundColor DarkGray
    }

    $first  = Read-Host 'Value to encrypt' -AsSecureString
    $second = Read-Host 'Confirm'          -AsSecureString
    $a = ConvertFrom-SecureStringToPlain -Secure $first
    $b = ConvertFrom-SecureStringToPlain -Secure $second
    if (-not $a)   { throw 'Empty value - nothing to encrypt.' }
    if ($a -ne $b) { throw 'The two values do not match.' }

    if ($Machine) {
        try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
        $bytes = [Security.Cryptography.ProtectedData]::Protect(
                     [Text.Encoding]::Unicode.GetBytes($a), $null,
                     [Security.Cryptography.DataProtectionScope]::LocalMachine)
        $blob = (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
    } else {
        $blob = ConvertFrom-SecureString -SecureString $first
    }

    Write-Host ''
    Write-Host 'Paste into the config file as PasswordEncrypted or EnzoicApiKeyEncrypted:'
    Write-Host ''
    Write-Output $blob
    Write-Host ''
}


#--- config ------------------------------------------------------------------#

function Import-ScanConfig {
    <# Load .psd1 (Import-PowerShellDataFile: data only, no code runs) or .json. #>
    param([string]$Path)

    if (-not $Path) {
        $candidates = @()
        foreach ($dir in @($PSScriptRoot, (Get-Location).Path)) {
            if (-not $dir) { continue }
            $candidates += (Join-Path $dir 'enzoic-delinea.config.psd1')
            $candidates += (Join-Path $dir 'enzoic-delinea.config.json')
        }
        $Path = $candidates |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                Select-Object -First 1
    }
    if (-not $Path) { return @{} }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Config file not found: $Path"
    }

    if ([IO.Path]::GetExtension($Path) -eq '.json') {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        $cfg = ConvertTo-Hashtable (ConvertFrom-Json $raw)
    } else {
        $cfg = Import-PowerShellDataFile -LiteralPath $Path
    }
    $script:ConfigPath = (Resolve-Path -LiteralPath $Path).Path
    return $cfg
}

function Unprotect-ConfigSecret {
    <# Decrypt a DPAPI blob from the config file.

       Handles BOTH scopes with one call: DPAPI records the scope in the blob
       itself and ignores the scope argument on decrypt, so ConvertTo-SecureString
       reads a machine-scope blob as happily as a user-scope one.

       A user-scope blob needs the creating account, on this machine, with that
       account's profile loaded. Note it is the profile that carries the master
       key (%APPDATA%\Microsoft\Protect), and %APPDATA% roams - so for a DOMAIN
       user with a roaming profile or AD credential roaming, the blob is NOT
       necessarily confined to this box. It is still confined to that user. #>
    param([Parameter(Mandatory)][string]$Encrypted)

    try {
        $secure = ConvertTo-SecureString -String $Encrypted
    } catch {
        $who = '(unknown)'
        try { $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { }
        throw ("Could not decrypt an encrypted config value (DPAPI). This script " +
               "is running as $who. A user-scope blob only decrypts for the " +
               "account that created it, on this machine, with that account's " +
               "profile loaded. On a domain-joined box the usual causes are: " +
               "the blob was generated under a different account than the one " +
               "this runs as; the service account has no loaded user profile; " +
               "or the account's password was reset by an administrator. Fix: " +
               "re-generate it AS this account with '-ProtectSecret', or use " +
               "'-ProtectSecret -MachineScope' for an unattended task.")
    }
    return (ConvertFrom-SecureStringToPlain -Secure $secure)
}

function Get-Setting {
    <# Parameter, then environment variable, then config file. #>
    param(
        [Parameter(Mandatory)][string] $Name,
        [string] $EnvName,
        [switch] $Secret,          # also accept "<Name>Encrypted", a DPAPI blob
        $Default = $null
    )

    if ($script:Bound.ContainsKey($Name)) { return $script:Bound[$Name] }

    if ($EnvName) {
        $v = [Environment]::GetEnvironmentVariable($EnvName)
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }

    if ($Secret -and $script:Cfg.ContainsKey("${Name}Encrypted")) {
        $v = [string]$script:Cfg["${Name}Encrypted"]
        if (-not [string]::IsNullOrWhiteSpace($v)) { return (Unprotect-ConfigSecret $v) }
    }

    if ($script:Cfg.ContainsKey($Name)) {
        $v = $script:Cfg[$Name]
        $blank = ($null -eq $v) -or (($v -is [string]) -and [string]::IsNullOrWhiteSpace($v))
        if (-not $blank) { return $v }
    }
    return $Default
}


#--- http plumbing -----------------------------------------------------------#

function Initialize-Tls {
    param([bool]$SkipValidation)

    # -bor rather than assignment, so a host with TLS 1.3 enabled keeps it.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    if (-not $SkipValidation) { return }
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:WebArgs['SkipCertificateCheck'] = $true
        $script:WebArgs.Remove('UseBasicParsing')
    } else {
        # Process-wide on 5.1 - there is no per-request opt-out on this edition.
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    Write-Warning 'TLS certificate validation is DISABLED (-Insecure).'
}

function Get-RetryAfterSeconds {
    <# Seconds to wait per the Retry-After header, or 0 if it says nothing
       usable. The header is either a delta in seconds or an HTTP-date, and the
       two editions expose headers through different types: 5.1 hands back a
       WebHeaderCollection (string indexer), 7 an HttpResponseHeaders
       (TryGetValues). Try both and treat any failure as "no header". #>
    param($ErrorRecord)

    $raw = $null
    try {
        $headers = $ErrorRecord.Exception.Response.Headers
        if ($null -eq $headers) { return 0 }

        $values = $null
        if ($headers.GetType().GetMethod('TryGetValues')) {
            if ($headers.TryGetValues('Retry-After', [ref]$values)) {
                $raw = @($values)[0]
            }
        } else {
            $raw = $headers['Retry-After']
        }
    } catch { return 0 }

    if ([string]::IsNullOrWhiteSpace($raw)) { return 0 }

    $seconds = 0
    if ([int]::TryParse(([string]$raw).Trim(), [ref]$seconds)) {
        if ($seconds -lt 0) { return 0 }
        return $seconds
    }

    # HTTP-date form. Anything in the past collapses to 0.
    $when = [DateTime]::MinValue
    if ([DateTime]::TryParse(([string]$raw).Trim(),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor
            [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$when)) {
        $delta = [int][Math]::Ceiling(($when - [DateTime]::UtcNow).TotalSeconds)
        if ($delta -gt 0) { return $delta }
    }
    return 0
}

function Get-ThrottleWait {
    <# How long to sleep before throttle retry N. Honour Retry-After when the
       server sends one, otherwise exponential backoff. Capped either way so a
       hostile header cannot park the scan for an hour. #>
    param($ErrorRecord, [int]$Attempt)

    $wait = Get-RetryAfterSeconds $ErrorRecord
    if ($wait -le 0) { $wait = [int][Math]::Pow(2, $Attempt) }
    if ($wait -gt $script:ThrottleMaxWait) { $wait = $script:ThrottleMaxWait }
    if ($wait -lt 1) { $wait = 1 }
    return $wait
}

function Get-HttpStatusCode {
    param($ErrorRecord)

    $resp = $null
    try { $resp = $ErrorRecord.Exception.Response } catch { return 0 }
    if ($null -eq $resp) { return 0 }
    try { return [int]$resp.StatusCode } catch { return 0 }
}

function Get-HttpErrorBody {
    param($ErrorRecord)

    try {
        $d = $ErrorRecord.ErrorDetails
        if ($d -and $d.Message) { return [string]$d.Message }
    } catch { }

    # 5.1 leaves the body on the response stream when ErrorDetails is empty.
    try {
        $stream = $ErrorRecord.Exception.Response.GetResponseStream()
        if ($null -eq $stream) { return '' }
        $reader = New-Object IO.StreamReader($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } catch { return '' }
}

function Get-OAuthErrorDescription {
    <# Pull error_description (or error) out of an OAuth failure body.

       The token endpoint answers a rejected grant with
       {"error":"invalid_grant","error_description":"..."}. The description is
       the only thing that separates a wrong password from a locked-out account
       from 2FA being enabled, so it is worth reporting verbatim. A non-JSON
       body (an IIS error page) yields nothing and the caller falls back. #>
    param([string]$Body)

    if ([string]::IsNullOrWhiteSpace($Body)) { return '' }
    try { $o = ConvertFrom-Json $Body } catch { return '' }

    $desc = Get-Prop $o 'error_description'
    if ([string]::IsNullOrWhiteSpace($desc)) { $desc = Get-Prop $o 'error' }
    if ([string]::IsNullOrWhiteSpace($desc)) { return '' }

    $desc = ([string]$desc).Trim()
    if ($desc.Length -gt 200) { $desc = $desc.Substring(0, 200) }
    return $desc
}

function Test-IsTimeout {
    param($ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex) {
        if ($ex -is [Net.WebException] -and
            $ex.Status -eq [Net.WebExceptionStatus]::Timeout) { return $true }
        if ($ex -is [Threading.Tasks.TaskCanceledException]) { return $true }   # PS7
        $ex = $ex.InnerException
    }
    return $false
}

function ConvertTo-QueryString {
    <# Encode by hand. A password containing & or + silently corrupts the token
       request otherwise, and the failure reads exactly like a wrong password. #>
    param([hashtable]$Fields)

    $parts = foreach ($k in $Fields.Keys) {
        '{0}={1}' -f [Uri]::EscapeDataString([string]$k),
                     [Uri]::EscapeDataString([string]$Fields[$k])
    }
    return ($parts -join '&')
}


#--- auth --------------------------------------------------------------------#

function Request-SSToken {
    param([Parameter(Mandatory)][hashtable]$Fields, [Parameter(Mandatory)][string]$What)

    $url  = "$($script:SS.Base)/oauth2/token"
    $body = ConvertTo-QueryString $Fields

    # Separate budgets again: warming up after an app pool recycle and being
    # throttled by a cloud tenant are different waits with different limits.
    $warm      = 0
    $throttled = 0

    while ($true) {
        $resp = $null
        # The try covers the CALL only. Parsing below must not land in the
        # catch, or a malformed 200 gets reported as a connectivity failure.
        try {
            $resp = Invoke-RestMethod -Uri $url -Method Post -Body $body `
                        -ContentType 'application/x-www-form-urlencoded' `
                        -TimeoutSec $script:TimeoutSec @script:WebArgs
        } catch {
            $status = Get-HttpStatusCode $_

            # switch rebinds $_ to its input, so the error record has to be
            # carried in by hand - inside the case blocks $_ is $status.
            $rec = $_

            if ($status -eq 0 -and (Test-IsTimeout $rec)) {
                # Connect succeeded, the app did not answer: Secret Server is
                # warming up after an IIS app pool recycle. Worth waiting out.
                $warm++
                if ($warm -ge $script:Retries) {
                    throw ("$url accepted the connection but never responded. The " +
                           'host is up - this is the application, not the network. ' +
                           'Usually an IIS app pool recycle; load the site in a ' +
                           'browser, wait, and retry.')
                }
                $wait = 10 * $warm
                Write-Warning ("no response in $($script:TimeoutSec)s (warming up)" +
                               " - retrying in ${wait}s")
                Start-Sleep -Seconds $wait
                continue
            }

            if ($status -eq 0) { throw "Could not reach ${url}: $($_.Exception.Message)" }

            if ($status -eq 429 -and $throttled -lt $script:ThrottleRetries) {
                $throttled++
                $wait = Get-ThrottleWait -ErrorRecord $rec -Attempt $throttled
                Write-Warning ("token endpoint throttled (HTTP 429) - retry " +
                               "$throttled/$($script:ThrottleRetries) in ${wait}s")
                Start-Sleep -Seconds $wait
                continue
            }

            $detail = switch ($status) {
                400 {
                    # The generic hint covers three unrelated causes. Secret
                    # Server's own error_description tells them apart (login
                    # failed vs locked out vs 2FA required), so lead with it
                    # when the body carries one.
                    $hint = 'bad credentials, or the account has 2FA (the password grant cannot satisfy it), or the refresh token expired'
                    $said = Get-OAuthErrorDescription (Get-HttpErrorBody $rec)
                    if ($said) { "$said [$hint]" } else { $hint }
                }
                404 { 'wrong base URL, or Enable Webservices is off. SS_BASE_URL needs the /SecretServer virtual directory' }
                429 { "still throttled after $($script:ThrottleRetries) retries - the tenant is rate limiting logins" }
                default {
                    $b = Get-HttpErrorBody $rec
                    if ($b.Length -gt 200) { $b.Substring(0, 200) } else { $b }
                }
            }
            throw "$What failed (HTTP ${status}): $detail"
        }

        $token = Get-Prop $resp 'access_token'
        if (-not $token) { throw "$What returned HTTP 200 with no access_token." }
        $script:SS.Token = $token

        # expires_in is a STRING in the spec. refresh_token is only issued
        # when the server allows it and the session timeout is not Unlimited.
        $script:SS.RefreshToken = Get-Prop $resp 'refresh_token'
        $seconds = [int](Get-Prop $resp 'expires_in' 1200)
        $lead    = $seconds - 60
        if ($lead -lt 30) { $lead = 30 }
        $script:SS.ExpiresAt = [DateTime]::UtcNow.AddSeconds($lead)
        return
    }
}

function Invoke-SSLogin {
    $fields = @{
        grant_type = 'password'
        username   = $script:SS.User
        password   = $script:SS.Password
    }
    # Optional. A domain login can also be expressed as DOMAIN\user in Username.
    if ($script:SS.Domain) { $fields['domain'] = $script:SS.Domain }
    Request-SSToken -Fields $fields -What 'Token request'
}

function Update-SSToken {
    if (-not $script:SS.RefreshToken) { Invoke-SSLogin; return }
    try {
        Request-SSToken -Fields @{
            grant_type    = 'refresh_token'
            refresh_token = $script:SS.RefreshToken
        } -What 'Token refresh'
    } catch {
        Invoke-SSLogin      # an aged-out refresh token 400s like a bad password
    }
}

function Connect-SecretServer {
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [string]$Domain
    )

    $script:SS = @{
        Base         = $BaseUrl.TrimEnd('/')
        User         = $Username
        Password     = $Password
        Domain       = $Domain
        Token        = $null
        RefreshToken = $null
        ExpiresAt    = [DateTime]::MinValue
    }
    Invoke-SSLogin
}


#--- requests ----------------------------------------------------------------#

function Invoke-SSGet {
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Query = @{})

    if (-not $script:SS.Token) { Invoke-SSLogin }
    elseif ([DateTime]::UtcNow -ge $script:SS.ExpiresAt) { Update-SSToken }

    $url = "$($script:SS.Base)/api/$Path"
    if ($Query.Count) { $url += '?' + (ConvertTo-QueryString $Query) }

    if ($script:ThrottleDelayMs -gt 0) {
        Start-Sleep -Milliseconds $script:ThrottleDelayMs
    }

    # Two independent budgets. A refresh and a throttle are unrelated failures,
    # and sharing one counter meant a single 401 spent the only retry.
    $refreshed = $false
    $throttled = 0

    while ($true) {
        try {
            return Invoke-RestMethod -Uri $url -Method Get `
                       -Headers @{ Authorization = "Bearer $($script:SS.Token)" } `
                       -TimeoutSec $script:TimeoutSec @script:WebArgs
        } catch {
            $status = Get-HttpStatusCode $_
            $rec    = $_      # switch rebinds $_ to its input

            # Token died before ExpiresAt said it would - revoked, or the
            # server's session timeout is shorter than expires_in claimed.
            if ($status -eq 401 -and -not $refreshed) {
                $refreshed = $true
                Update-SSToken
                continue
            }

            if ($status -eq 429 -and $throttled -lt $script:ThrottleRetries) {
                $throttled++
                $wait = Get-ThrottleWait -ErrorRecord $rec -Attempt $throttled
                Write-Warning ("throttled by Secret Server (HTTP 429) - retry " +
                               "$throttled/$($script:ThrottleRetries) in ${wait}s")
                Start-Sleep -Seconds $wait
                continue
            }

            $message = switch ($status) {
                400 { 'refused - double lock, comment required, or check-out' }
                401 { 'still unauthorized after a token refresh - the account was disabled or its session revoked mid-scan' }
                403 { 'no View permission for this account' }
                404 { 'not found' }
                429 { ("still throttled after $($script:ThrottleRetries) retries. " +
                       'Raise ThrottleDelayMs to pace the sweep, or narrow it with -Folder') }
                0   { "could not reach ${url}: $($_.Exception.Message)" }
                default { "HTTP $status" }
            }
            throw $message
        }
    }
}

function Get-SSPaged {
    <# Everything here is paged the same way: take/skip in, records/hasNext/
       nextSkip back. #>
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Query = @{})

    $out  = New-Object Collections.ArrayList
    $skip = 0
    while ($true) {
        $q = @{} + $Query
        $q['take'] = 100
        $q['skip'] = $skip

        $page    = Invoke-SSGet -Path $Path -Query $q
        $records = @(Get-Prop $page 'records' @())
        foreach ($r in $records) { [void]$out.Add($r) }

        if ($records.Count -eq 0 -or -not [bool](Get-Prop $page 'hasNext' $false)) { break }

        $next = [int](Get-Prop $page 'nextSkip' ($skip + 100))
        if ($next -le $skip) { break }   # never spin if the server repeats a page
        $skip = $next
    }
    return @($out.ToArray())
}


#--- secret server api -------------------------------------------------------#

function Get-SSFolder {
    param([string]$SearchText = '')

    return @(Get-SSPaged -Path 'v1/folders' -Query @{
        'filter.searchText'             = $SearchText
        'filter.onlyIncludeRootFolders' = 'false'      # include nested folders
    })
}

function Resolve-SSFolder {
    <# Resolve a name to exactly one folder, refusing to guess when ambiguous.
       filter.searchText is a CONTAINS match and two folders can share a leaf
       name, so a wrong guess would silently sweep the wrong folder. #>
    param([Parameter(Mandatory)][string]$Name)

    $normalized = $Name.Replace('/', '\').TrimEnd('\')
    $leaf       = ($normalized -split '\\')[-1]

    # @() because a single match unrolls to a scalar on return.
    $found = @(Get-SSFolder -SearchText $leaf)
    if ($found.Count -eq 0) { throw "No folder matching '$Name' (or no View permission)" }

    $norm = {
        param($s)
        if ($s) { return ([string]$s).Replace('/', '\').Trim('\').ToLower() }
        return ''
    }

    $wanted = & $norm $leaf
    $exact  = @($found | Where-Object { (& $norm (Get-Prop $_ 'folderName')) -eq $wanted })

    if ($Name -match '[\\/]') {
        $wantedPath = & $norm $normalized
        $byPath = @($found | Where-Object { (& $norm (Get-Prop $_ 'folderPath')) -eq $wantedPath })
        if ($byPath.Count) { $exact = $byPath }
    }

    $candidates = @($exact)
    if ($candidates.Count -eq 0) { $candidates = @($found) }
    if ($candidates.Count -gt 1) {
        $listing = ($candidates | ForEach-Object {
            '    {0,-6} {1}' -f $_.id, (Get-Prop $_ 'folderPath' '?') }) -join [Environment]::NewLine
        throw ("$($candidates.Count) folders match '$Name'. Pass the full path:" +
               [Environment]::NewLine + $listing)
    }
    return $candidates[0]
}

function Get-SSSecretList {
    param($FolderId)

    $q = @{}
    if ($null -ne $FolderId) {
        $q['filter.folderId']          = $FolderId
        $q['filter.includeSubFolders'] = 'true'
    }
    return @(Get-SSPaged -Path 'v2/secrets' -Query $q)
}

function Get-SSSecret {
    param([Parameter(Mandatory)]$SecretId)

    # noAutoCheckout, or reading a checkout-required secret checks it out under
    # THIS account and locks it away from whoever needs it.
    return Invoke-SSGet -Path "v2/secrets/$SecretId" -Query @{ noAutoCheckout = 'true' }
}


#--- enzoic ------------------------------------------------------------------#

function Test-EnzoicPassword {
    <# Return @{ Verdict; Exposures }. Only a 10-char hash prefix is sent. #>
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$ApiKey
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try   { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Password)) }
    finally { $sha.Dispose() }
    $full = (-join ($bytes | ForEach-Object { $_.ToString('x2') })).ToLower()

    if ($script:EnzoicCache.ContainsKey($full)) { return $script:EnzoicCache[$full] }

    $result = @{ Verdict = 'Clean'; Exposures = 0 }
    $body   = @{ partialSHA256 = $full.Substring(0, 10) } | ConvertTo-Json -Compress

    try {
        # The key is the RAW 32-hex value - not base64, not key:secret.
        $resp = Invoke-RestMethod -Uri $script:EnzoicUrl -Method Post `
                    -Headers @{ Authorization = "basic $ApiKey" } `
                    -ContentType 'application/json' -Body $body -TimeoutSec 15 `
                    @script:WebArgs

        foreach ($c in @(Get-Prop $resp 'candidates' @())) {
            $sha256 = Get-Prop $c 'sha256'
            if (-not $sha256) { continue }
            if (([string]$sha256).ToLower() -ne $full) { continue }

            # revealedInExposure separates a real breach from
            # known-weak-but-never-exposed.
            if ([bool](Get-Prop $c 'revealedInExposure' $false)) {
                $result.Verdict = 'Compromised'
            } else {
                $result.Verdict = 'Weak'
            }
            $result.Exposures = [int](Get-Prop $c 'exposureCount' 0)
            break
        }
    } catch {
        $status = Get-HttpStatusCode $_
        if ($status -eq 401 -or $status -eq 403) {
            throw ("Enzoic rejected the API key (HTTP $status). It must be the raw " +
                   '32-hex key - not base64, not key:secret.')
        }
        # 404 = prefix absent = clean. Anything else is INCONCLUSIVE, which is
        # not the same thing as clean.
        if ($status -ne 404) { $result = @{ Verdict = 'CheckFailed'; Exposures = 0 } }
    }

    $script:EnzoicCache[$full] = $result
    return $result
}


#--- reports -----------------------------------------------------------------#

function New-ReportPath {
    <# A new dated file per run, never an overwrite. The stamp is
       yyyyMMdd-HHmmss so the files sort chronologically by name. #>
    param([Parameter(Mandatory)][string]$Directory, [string]$Scope)

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $Directory -Force)
        Write-Verbose "created report directory $Directory"
    }

    $slug = 'all'
    if ($Scope) {
        $slug = (($Scope -replace '[^\w\-]+', '-').Trim('-')).ToLower()
        if (-not $slug)          { $slug = 'scan' }
        if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40) }
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path  = Join-Path $Directory "enzoic-scan-$slug-$stamp.csv"

    # Two runs inside the same second would otherwise collide.
    $n = 1
    while (Test-Path -LiteralPath $path -PathType Leaf) {
        $path = Join-Path $Directory "enzoic-scan-$slug-$stamp-$n.csv"
        $n++
    }
    return $path
}

function Remove-OldReport {
    <# Optional retention, so a nightly scheduled task does not fill the disk.
       Newest N survive; ordered by write time, not by name, in case the scope
       slug changes between runs. #>
    param([Parameter(Mandatory)][string]$Directory, [int]$Retain)

    if ($Retain -le 0) { return }
    $old = @(Get-ChildItem -LiteralPath $Directory -Filter 'enzoic-scan-*.csv' -File |
             Sort-Object LastWriteTime -Descending | Select-Object -Skip $Retain)
    foreach ($f in $old) {
        Remove-Item -LiteralPath $f.FullName -Force
        Write-Verbose "pruned $($f.Name)"
    }
    if ($old.Count) { Write-Host "Pruned $($old.Count) report(s), keeping the newest $Retain." }
}


#--- main --------------------------------------------------------------------#

$script:Bound      = $PSBoundParameters
$script:Cfg        = @{}
$script:ConfigPath = $null
$exitCode          = 0

try {
    # Before anything else: this mode needs no config and no server.
    if ($ProtectSecret) {
        New-ProtectedSecret -Machine:$MachineScope
        exit 0
    }
    if ($MachineScope) {
        Write-Warning '-MachineScope only applies with -ProtectSecret; ignoring it.'
    }

    $script:Cfg = Import-ScanConfig -Path $Config
    if ($script:ConfigPath) {
        Write-Host "Config: $($script:ConfigPath)" -ForegroundColor DarkGray
    } else {
        Write-Warning ('No config file found. Copy enzoic-delinea.config.example.psd1 ' +
                       'to enzoic-delinea.config.psd1 and fill it in.')
    }

    $baseUrl   =        Get-Setting -Name 'BaseUrl'      -EnvName 'SS_BASE_URL'
    $username  =        Get-Setting -Name 'Username'     -EnvName 'SS_USERNAME'
    $password  =        Get-Setting -Name 'Password'     -EnvName 'SS_PASSWORD'    -Secret
    $domain    =        Get-Setting -Name 'Domain'       -EnvName 'SS_DOMAIN'
    $enzoicKey =        Get-Setting -Name 'EnzoicApiKey' -EnvName 'ENZOIC_API_KEY' -Secret
    $reportDir =        Get-Setting -Name 'ReportDirectory'
    $csvPath   =        Get-Setting -Name 'Csv'
    $retain    = [int]( Get-Setting -Name 'RetainReports' -Default 0)
    $scanAll   = [bool](Get-Setting -Name 'All'           -Default $false)
    $reveal    = [bool](Get-Setting -Name 'Reveal'        -Default $false)
    $insecure  = [bool](Get-Setting -Name 'Insecure'      -Default $false)

    # Pace the sweep. Only needed against a cloud tenant that throttles harder
    # than the 429 backoff can absorb; 0 leaves on-prem runs at full speed.
    $delayMs = [int](Get-Setting -Name 'ThrottleDelayMs' -Default 0)
    if ($delayMs -lt 0)    { $delayMs = 0 }
    if ($delayMs -gt 10000){ $delayMs = 10000 }
    $script:ThrottleDelayMs = $delayMs

    $folders = @(Get-Setting -Name 'Folder') |
               Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $folders = @($folders)

    if (-not $baseUrl)  { $baseUrl  = Read-Host 'Base URL (https://host/SecretServer)' }
    if (-not $username) { $username = Read-Host 'Username' }
    if (-not $password) {
        $password = ConvertFrom-SecureStringToPlain (Read-Host "Password for $username" -AsSecureString)
    }

    Initialize-Tls -SkipValidation $insecure

    Connect-SecretServer -BaseUrl $baseUrl -Username $username `
                         -Password $password -Domain $domain
    Write-Host "Authenticated to $($script:SS.Base) as $username" -ForegroundColor DarkGray

    if (-not $enzoicKey) {
        Write-Warning ('No Enzoic API key configured - secrets will be listed but ' +
                       'NOT checked. Set EnzoicApiKey in the config file.')
    }

    #-- folder listing mode --------------------------------------------------#
    if ($ListFolders -or (-not $scanAll -and $folders.Count -eq 0)) {
        $visible = @(Get-SSFolder)
        if ($visible.Count) {
            $visible |
                Select-Object @{ n = 'Id';         e = { $_.id } },
                              @{ n = 'FolderPath'; e = { Get-Prop $_ 'folderPath' '' } } |
                Sort-Object FolderPath | Format-Table -AutoSize | Out-Host
            Write-Host "$($visible.Count) folder(s). Sweep with -Folder NAME or -All."
        } else {
            Write-Warning 'No folders visible - this account needs View permission.'
        }
        exit 0
    }

    #-- collect the secrets in scope ----------------------------------------#
    $summaries = New-Object Collections.ArrayList
    $scopeName = 'all'

    if ($scanAll) {
        Write-Host 'Scope: all folders' -ForegroundColor DarkGray
        foreach ($s in @(Get-SSSecretList -FolderId $null)) { [void]$summaries.Add($s) }
    } else {
        $seen  = New-Object Collections.Generic.HashSet[int]
        $names = New-Object Collections.ArrayList
        foreach ($name in $folders) {
            $f = Resolve-SSFolder -Name $name
            $path = Get-Prop $f 'folderPath' $name
            Write-Host "Scope: $path (id $($f.id), incl. subfolders)" -ForegroundColor DarkGray
            [void]$names.Add(($path -split '\\')[-1])
            foreach ($s in @(Get-SSSecretList -FolderId $f.id)) {
                # Overlapping folder entries in the config would double-count.
                if ($seen.Add([int]$s.id)) { [void]$summaries.Add($s) }
            }
        }
        $scopeName = ($names.ToArray() -join '-')
    }

    Write-Host "Scanning $($summaries.Count) secret(s)"

    #-- read and check ------------------------------------------------------#
    $rows  = New-Object Collections.ArrayList
    $i     = 0
    $total = $summaries.Count

    foreach ($s in $summaries) {
        $i++
        if ($total -gt 1) {
            Write-Progress -Activity 'Enzoic sweep' `
                -Status "$i of ${total}: $(Get-Prop $s 'name' $s.id)" `
                -PercentComplete ([int](100 * $i / $total))
        }

        $row = [ordered]@{
            Id        = $s.id
            Folder    = [string](Get-Prop $s 'folderPath' '')
            Name      = [string](Get-Prop $s 'name' '')
            Username  = ''
            Password  = $null
            Verdict   = ''
            Exposures = 0
            Note      = ''
        }

        if ([bool](Get-Prop $s 'checkOutEnabled' $false)) {
            $row.Note = 'requires check-out - skipped'
        } else {
            try {
                $detail = Get-SSSecret -SecretId $s.id
                foreach ($item in @(Get-Prop $detail 'items' @())) {
                    if ((Get-Prop $item 'slug' '') -eq 'username') {
                        $row.Username = [string](Get-Prop $item 'itemValue' '')
                    } elseif ([bool](Get-Prop $item 'isPassword' $false) -and
                              -not [bool](Get-Prop $item 'isFile' $false)) {
                        $row.Password = Get-Prop $item 'itemValue'
                    }
                }
            } catch {
                $row.Note = $_.Exception.Message
            }
        }

        if ($enzoicKey -and $row.Password) {
            $verdict       = Test-EnzoicPassword -Password $row.Password -ApiKey $enzoicKey
            $row.Verdict   = $verdict.Verdict
            $row.Exposures = $verdict.Exposures
        }

        [void]$rows.Add([pscustomobject]$row)
    }
    if ($total -gt 1) { Write-Progress -Activity 'Enzoic sweep' -Completed }

    #-- console table -------------------------------------------------------#
    if ($rows.Count) {
        $rows | Format-Table -AutoSize -Property `
            Id, Folder, Name, Username,
            @{ Name = 'Password'; Expression = {
                    if (-not $_.Password) { '' }
                    elseif ($reveal)      { $_.Password }
                    else                  { "<$($_.Password.Length) chars>" } } },
            Verdict,
            @{ Name = 'Exposures'; Align = 'right'; Expression = {
                    if ($_.Exposures) { '{0:N0}' -f $_.Exposures } else { '' } } },
            Note | Out-Host
    } else {
        Write-Warning ('Zero secrets in scope. The API returns only what this account ' +
                       'has View on, and no-permission is indistinguishable from empty ' +
                       '- check BOTH grants on the folder Sharing tab: Folder ' +
                       'Permissions = View AND Secret Permissions = View.')
    }

    #-- reports -------------------------------------------------------------#
    # Deliberately omits Password. The report is safe to email; the console
    # table with -Reveal is not.
    $reportCols = @('Id', 'Folder', 'Name', 'Username', 'Verdict', 'Exposures', 'Note')

    if ($reportDir) {
        $dated = New-ReportPath -Directory $reportDir -Scope $scopeName
        $rows | Select-Object $reportCols |
            Export-Csv -LiteralPath $dated -NoTypeInformation -Encoding UTF8
        Write-Host "Report: $dated" -ForegroundColor Cyan
        Remove-OldReport -Directory $reportDir -Retain $retain
    }

    if ($csvPath) {
        $rows | Select-Object $reportCols |
            Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "CSV: $csvPath"
    }

    #-- summary -------------------------------------------------------------#
    if ($enzoicKey -and $rows.Count) {
        Write-Host ''
        $rows | Group-Object { if ($_.Verdict) { $_.Verdict } else { '-' } } |
            Sort-Object Name | ForEach-Object {
                $color = 'Gray'
                if     ($_.Name -eq 'Compromised') { $color = 'Red' }
                elseif ($_.Name -eq 'Weak')        { $color = 'Yellow' }
                elseif ($_.Name -eq 'CheckFailed') { $color = 'Magenta' }
                elseif ($_.Name -eq 'Clean')       { $color = 'Green' }
                Write-Host ('  {0,-12} {1}' -f $_.Name, $_.Count) -ForegroundColor $color
            }
        if (@($rows | Where-Object { $_.Verdict -eq 'CheckFailed' }).Count) {
            Write-Warning 'CheckFailed is NOT Clean - re-run those.'
        }
    }

    if ($PassThru) { $rows.ToArray() }
}
catch {
    # WriteErrorLine, not Write-Error: goes to stderr and sets the exit code
    # without wrapping the message in a screenful of ErrorRecord decoration.
    # The message is the thing the operator needs to read.
    Write-Host ''
    $Host.UI.WriteErrorLine("ERROR: $($_.Exception.Message)")
    Write-Verbose "at $($_.ScriptStackTrace)"
    $exitCode = 1
}

exit $exitCode
