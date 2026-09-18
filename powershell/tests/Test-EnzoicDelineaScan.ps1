<#
.SYNOPSIS
    Tests for Invoke-EnzoicDelineaScan.ps1. The PowerShell counterpart to
    tests/test_delinea.py.

.DESCRIPTION
    Runs against a fake Secret Server and a fake Enzoic on localhost - no VM,
    no vault, no API key, no network. Covers token refresh and both fallbacks,
    401-triggered renewal, paging, folder ambiguity, check-out skipping, 403
    handling, the Enzoic wire format and verdict mapping, response caching,
    config precedence, DPAPI values, and dated reports.

    Fully isolated from the real config: SS_* / ENZOIC_API_KEY are cleared for
    the duration, and every run is pointed at an explicit -Config path. An
    earlier version of the Python suite picked up the live ENZOIC_API_KEY and
    tried to spend it during a test run.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-EnzoicDelineaScan.ps1
#>

[CmdletBinding()]
param(
    [int]    $Port = 8799,
    [string] $FakeApi,      # path to fake-api.ps1; defaults to next to this file
    [switch] $KeepWorkDir
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0
$script:Failures = New-Object Collections.ArrayList

$ScriptUnderTest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EnzoicDelineaScan.ps1'
if (-not $FakeApi) { $FakeApi = Join-Path $PSScriptRoot 'fake-api.ps1' }
$Base    = "http://localhost:$Port/SecretServer"
$EnzoicU = "http://localhost:$Port/enzoic/passwords"
$GoodKey = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF'
$GoodPw  = 'p@ss&w+rd=1 x'      # deliberately full of & + = and a space

foreach ($p in @($ScriptUnderTest, $FakeApi)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "not found: $p" }
}

$WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("enzoic-tests-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $WorkDir -Force)


#--- assertions --------------------------------------------------------------#

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Pass++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } catch {
        $script:Fail++
        [void]$script:Failures.Add("$Name :: $($_.Exception.Message)")
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkRed
    }
}

function Assert-True   { param($Condition, [string]$Message) if (-not $Condition) { throw "expected true: $Message" } }
function Assert-Equal  {
    param($Expected, $Actual, [string]$Message)
    if ("$Expected" -ne "$Actual") { throw "$Message - expected [$Expected], got [$Actual]" }
}
function Assert-Match  {
    param([string]$Pattern, [string]$Text, [string]$Message)
    if ($Text -notmatch $Pattern) { throw "$Message - [$Pattern] not found in: $Text" }
}
function Assert-NoMatch {
    param([string]$Pattern, [string]$Text, [string]$Message)
    if ($Text -match $Pattern) { throw "$Message - [$Pattern] SHOULD NOT appear in: $Text" }
}


#--- harness -----------------------------------------------------------------#

function Start-FakeApi {
    $log = Join-Path $WorkDir 'fake-api.log'
    $script:Server = Start-Process powershell `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FakeApi, '-Port', $Port `
        -RedirectStandardOutput $log -RedirectStandardError (Join-Path $WorkDir 'fake-api.err') `
        -WindowStyle Hidden -PassThru

    foreach ($i in 1..40) {
        try {
            $null = Invoke-RestMethod "http://localhost:$Port/_control/stats" -TimeoutSec 2 -UseBasicParsing
            return
        } catch { Start-Sleep -Milliseconds 250 }
    }
    throw "fake API never came up on port $Port. See $log"
}

function Reset-FakeApi {
    param([int]$Force401At = -1, [string]$TokenErrorDesc)
    $u = "http://localhost:$Port/_control/reset"
    $qs = @()
    if ($Force401At -ge 0) { $qs += "force401At=$Force401At" }
    if ($TokenErrorDesc)   { $qs += "tokenErrorDesc=$([Uri]::EscapeDataString($TokenErrorDesc))" }
    if ($qs.Count) { $u += '?' + ($qs -join '&') }
    $null = Invoke-RestMethod $u -TimeoutSec 5 -UseBasicParsing
}

function Get-FakeStats { return Invoke-RestMethod "http://localhost:$Port/_control/stats" -TimeoutSec 5 -UseBasicParsing }

function New-TestConfig {
    <# Write a .psd1 and return its path. Values are emitted as literals. #>
    param([hashtable]$Settings, [string]$Name = 'cfg')

    $lines = New-Object Collections.ArrayList
    [void]$lines.Add('@{')
    foreach ($k in $Settings.Keys) {
        $v = $Settings[$k]
        if     ($v -is [bool])   { [void]$lines.Add("    $k = `$$($v.ToString().ToLower())") }
        elseif ($v -is [int])    { [void]$lines.Add("    $k = $v") }
        elseif ($v -is [array])  {
            $items = ($v | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ', '
            [void]$lines.Add("    $k = @($items)")
        }
        else { [void]$lines.Add("    $k = '" + ([string]$v -replace "'", "''") + "'") }
    }
    [void]$lines.Add('}')

    $path = Join-Path $WorkDir "$Name.psd1"
    Set-Content -LiteralPath $path -Value ($lines.ToArray() -join [Environment]::NewLine) -Encoding UTF8
    return $path
}

function Format-Args {
    <# Quote VALUES but never parameter names. Quoting '-Config' makes
       PowerShell pass it as a positional value instead of a switch, which
       silently turns every test into "Config file not found: -Config". #>
    param([string[]]$Arguments)

    return (($Arguments | ForEach-Object {
        if ($_ -like '-*') { $_ } else { "'" + ($_ -replace "'", "''") + "'" }
    }) -join ' ')
}

function Invoke-Child {
    <# Run powershell.exe and return @{ Out; Exit } with stdout+stderr merged.

       Two traps, both PowerShell 5.1 specific:
         - Under $ErrorActionPreference='Stop', a native command writing to
           stderr raises a TERMINATING NativeCommandError. Every test that
           asserts on an error message would blow up instead of asserting.
         - The child wraps its output at the console width, inserting newlines
           mid-sentence, so a literal match on a long message fails. Collapse
           runs of whitespace before returning. \s+ in a pattern still works. #>
    param([string]$Command)

    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & powershell -NoProfile -ExecutionPolicy Bypass -Command $Command 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }

    return @{ Out = ($raw -replace '\s+', ' '); Raw = $raw; Exit = $code }
}

function Invoke-Scan {
    <# Run the script under test in a child process with the real environment
       variables blanked, so a developer's live .env cannot leak into a test. #>
    param([string[]]$Arguments)

    $quoted = Format-Args $Arguments
    return Invoke-Child (
        "`$env:SS_BASE_URL=''; `$env:SS_USERNAME=''; `$env:SS_PASSWORD=''; " +
        "`$env:SS_DOMAIN=''; `$env:ENZOIC_API_KEY=''; " +
        "& '$ScriptUnderTest' $quoted")
}

function Invoke-ScanWithEnv {
    <# Same, but sets specific environment variables first, to test precedence. #>
    param([hashtable]$Env, [string[]]$Arguments)

    $sets = ($Env.Keys | ForEach-Object {
        "`$env:$_='" + ($Env[$_] -replace "'", "''") + "'" }) -join '; '
    $quoted = Format-Args $Arguments
    return Invoke-Child "$sets; & '$ScriptUnderTest' $quoted"
}

function Invoke-ScanIsolated {
    <# Run a COPY of the script from a directory that has no config file in it.

       Invoke-Scan blanks the environment, but config discovery ALSO searches
       $PSScriptRoot and the working directory - and the script under test sits
       next to the developer's real enzoic-delinea.config.psd1. Without this,
       'no config file at all' silently picks that one up and sweeps the live
       settings instead of the test's. It fails only on a machine that has a
       real config, which is every machine that has actually run the tool. #>
    param([string[]]$Arguments)

    $dir = Join-Path $WorkDir 'noconfig'
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
    $copy = Join-Path $dir (Split-Path -Leaf $ScriptUnderTest)
    Copy-Item -LiteralPath $ScriptUnderTest -Destination $copy -Force

    foreach ($stray in @('enzoic-delinea.config.psd1', 'enzoic-delinea.config.json')) {
        $q = Join-Path $dir $stray
        if (Test-Path -LiteralPath $q) { Remove-Item -LiteralPath $q -Force }
    }

    $quoted = Format-Args $Arguments
    return Invoke-Child (
        "Set-Location '$dir'; " +
        "`$env:SS_BASE_URL=''; `$env:SS_USERNAME=''; `$env:SS_PASSWORD=''; " +
        "`$env:SS_DOMAIN=''; `$env:ENZOIC_API_KEY=''; " +
        "& '$copy' $quoted")
}

# The script hardcodes the real Enzoic URL. For the Enzoic tests we lift the
# function definitions out of it via the AST and dot-source them, so the tests
# exercise the SHIPPING code while pointing $script:EnzoicUrl at the fake.
function New-FunctionsUnderTestFile {
    $errs = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($ScriptUnderTest, [ref]$null, [ref]$errs)
    if ($errs) { throw "parse errors in the script under test: $($errs[0].Message)" }

    $funcs = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
    $text  = ($funcs | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine * 2

    $path = Join-Path $WorkDir 'functions.ps1'
    Set-Content -LiteralPath $path -Value $text -Encoding UTF8
    Write-Host "  (extracted $($funcs.Count) functions from the script under test)" -ForegroundColor DarkGray
    return $path
}


#--- run ---------------------------------------------------------------------#

Write-Host "Script under test: $ScriptUnderTest"
Write-Host "Work dir:          $WorkDir"
Write-Host ''

try {
    Start-FakeApi
    Write-Host "Fake API up on port $Port" -ForegroundColor DarkGray

    $baseCfg = @{
        BaseUrl  = $Base
        Username = 'svc_enzoic_api'
        Password = $GoodPw
    }

    #=== auth ================================================================#
    Write-Host "`nauth" -ForegroundColor Cyan

    Test-Case 'password grant URL-encodes & + = and space intact' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{}) 'auth1'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Authenticated to' $r.Out 'login banner'
        $s = Get-FakeStats
        Assert-Match 'password=p%40ss%26w%2Brd%3D1%20x' $s.tokenBodies[0] 'encoded body'
    }

    Test-Case 'wrong password reports HTTP 400 as credentials-or-2FA, exit 1' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'u'; Password = 'wrong' }) 'auth2'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'HTTP 400' $r.Out 'status in message'
        Assert-Match '2FA'      $r.Out 'the 2FA hint that saves an hour'
    }

    Test-Case "a 400 leads with Secret Server's own error_description" {
        # The generic hint names three unrelated causes. When the server says
        # which one it is, that has to reach the operator - it is the whole
        # difference between retyping a password and unlocking an account.
        Reset-FakeApi -TokenErrorDesc 'The user account has been locked out.'
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'u'; Password = 'wrong' }) 'auth2b'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'HTTP 400'    $r.Out 'status'
        Assert-Match 'locked out'  $r.Out "the server's actual reason"
        Assert-Match '2FA'         $r.Out 'the hint is kept as well'
    }

    Test-Case 'a 400 with no error_description still falls back to the hint' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'u'; Password = 'wrong' }) 'auth2c'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'HTTP 400'      $r.Out 'status'
        Assert-Match 'invalid_grant' $r.Out 'the error code, when that is all there is'
        Assert-Match '2FA'           $r.Out 'the hint'
    }

    Test-Case 'missing /SecretServer vdir reports the 404 hint' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = "http://localhost:$Port/Wrong"
                                  Username = 'u'; Password = $GoodPw }) 'auth3'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'HTTP 404' $r.Out 'status'
        Assert-Match 'Enable Webservices' $r.Out 'the hint'
    }

    Test-Case 'unreachable host is a reach error, not a 400' {
        $cfg = New-TestConfig (@{ BaseUrl = 'http://localhost:1/SecretServer'
                                  Username = 'u'; Password = 'p' }) 'auth4'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'Could not reach' $r.Out 'reach error'
    }

    Test-Case '401 mid-sweep triggers a refresh_token grant and the sweep continues' {
        Reset-FakeApi -Force401At 3
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; EnzoicApiKey = '' }) 'auth5'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        $s = Get-FakeStats
        Assert-True $s.fired401 'the fake actually issued a 401'
        Assert-Equal 2 $s.tokenCalls 'one password grant + one renewal'
        Assert-Match 'grant_type=refresh_token' $s.tokenBodies[1] 'renewal used the refresh token'
        Assert-Match 'Scanning 5 secret' $r.Out 'sweep completed after the renewal'
    }

    #=== folders =============================================================#
    Write-Host "`nfolders" -ForegroundColor Cyan

    Test-Case 'no folder and no -All lists folders and stops' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f1'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match '5 folder\(s\)' $r.Out 'folder count'
        Assert-Match '\\Service Accounts' $r.Out 'a folder path'
        Assert-NoMatch 'Scanning' $r.Out 'must not sweep'
    }

    Test-Case '-ListFolders overrides a Folder set in the config' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'f2'
        $r = Invoke-Scan @('-Config', $cfg, '-ListFolders')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match '5 folder\(s\)' $r.Out 'listed instead of swept'
        Assert-NoMatch 'Scanning' $r.Out 'must not sweep'
    }

    Test-Case 'ambiguous leaf name refuses to guess and lists the candidates' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f3'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Shared')
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match '2 folders match' $r.Out 'ambiguity error'
        Assert-Match '\\Finance\\Shared' $r.Out 'candidate 1'
        Assert-Match '\\Service Accounts\\Shared' $r.Out 'candidate 2'
    }

    Test-Case 'full path disambiguates a shared leaf name' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f4'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', '\Finance\Shared')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scope: \\Finance\\Shared \(id 3' $r.Out 'resolved to id 3'
    }

    Test-Case 'forward slashes are accepted in a folder path' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f5'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', '/Finance/Shared')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match '\(id 3' $r.Out 'resolved to id 3'
    }

    Test-Case 'a folder matching exactly one result does not crash on .Count' {
        # Regression: a single-item return unrolls to a scalar in PowerShell.
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f6'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Solo')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scope: \\Solo \(id 5' $r.Out 'resolved'
        Assert-NoMatch "property 'Count'" $r.Out 'no StrictMode Count error'
    }

    Test-Case 'unknown folder name is a clean error' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'f7'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'NoSuchFolder')
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'No folder matching' $r.Out 'error text'
        Assert-Match 'View permission' $r.Out 'names the likely cause'
    }

    #=== sweeping ============================================================#
    Write-Host "`nsweeping" -ForegroundColor Cyan

    Test-Case 'paging collects every record across pages' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's1'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Service Accounts')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scanning 105 secret' $r.Out '105 = two pages'
    }

    Test-Case '-All sweeps every folder' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's2'
        $r = Invoke-Scan @('-Config', $cfg, '-All')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scope: all folders' $r.Out 'scope banner'
        Assert-Match 'Scanning 112 secret' $r.Out '105 + 7'
    }

    Test-Case 'the same folder listed twice yields each secret once' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = @('Solo', '\Solo') }) 's3'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scanning 5 secret' $r.Out 'not 10'
    }

    Test-Case 'check-out-required secrets are skipped, never checked out' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's4'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Finance')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'requires check-out - skipped' $r.Out 'the note'
    }

    Test-Case 'a 403 on one secret is noted and the sweep continues' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's5'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Finance')
        Assert-Equal 0 $r.Exit 'sweep survives'
        Assert-Match 'no View permission for this account' $r.Out 'the note'
    }

    Test-Case 'isFile password items are ignored, username slug is picked up' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's6'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Solo', '-Reveal')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'user9003' $r.Out 'username from the slug'
        Assert-Match 'breached1' $r.Out 'the real password, not the file blob'
        Assert-NoMatch 'BLOB' $r.Out 'the isFile item must be ignored'
    }

    Test-Case 'passwords are masked unless -Reveal' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's7'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Solo')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match '<9 chars>' $r.Out 'masked length'
        Assert-NoMatch 'breached1' $r.Out 'no cleartext password'
    }

    Test-Case 'every secret read sends noAutoCheckout=true' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 's8'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', 'Solo')
        # the fake returns HTTP 500 "noAutoCheckout missing" if it is ever absent
        Assert-NoMatch 'HTTP 500' $r.Out 'noAutoCheckout was present on all reads'
        Assert-Equal 0 $r.Exit 'exit code'
    }

    #=== enzoic ==============================================================#
    Write-Host "`nenzoic" -ForegroundColor Cyan

    . (New-FunctionsUnderTestFile)
    $script:EnzoicUrl   = $EnzoicU
    $script:WebArgs     = @{ UseBasicParsing = $true }
    $script:EnzoicCache = @{}

    Test-Case 'only a 10-char prefix of the hash is sent' {
        Reset-FakeApi
        $script:EnzoicCache = @{}
        $null = Test-EnzoicPassword -Password 'cleanpw' -ApiKey $GoodKey
        $s = Get-FakeStats
        Assert-Equal 1 $s.enzoicCalls 'one call'
        $sent = ($s.enzoicBodies[0] | ConvertFrom-Json).partialSHA256
        Assert-Equal 10 $sent.Length 'prefix length'
        Assert-NoMatch 'cleanpw' $s.enzoicBodies[0] 'the password itself never leaves'
    }

    Test-Case 'revealedInExposure true maps to Compromised with the count' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'breached1' -ApiKey $GoodKey
        Assert-Equal 'Compromised' $v.Verdict 'verdict'
        Assert-Equal 12345 $v.Exposures 'exposure count'
    }

    Test-Case 'a prefix-colliding decoy candidate is rejected on the full hash' {
        # The fake returns a decoy sharing the 10-char prefix with
        # exposureCount 999999. Matching on the prefix would pick it up.
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'breached1' -ApiKey $GoodKey
        Assert-Equal 12345 $v.Exposures 'must not be 999999'
    }

    Test-Case 'candidate sha256 is compared case-insensitively' {
        # The fake returns the matching hash UPPERCASED.
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'breached1' -ApiKey $GoodKey
        Assert-Equal 'Compromised' $v.Verdict 'uppercase hash still matches'
    }

    Test-Case 'revealedInExposure false maps to Weak, not Compromised' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'weakpw' -ApiKey $GoodKey
        Assert-Equal 'Weak' $v.Verdict 'verdict'
        Assert-Equal 0 $v.Exposures 'omitted exposureCount defaults to 0'
    }

    Test-Case 'HTTP 404 means the prefix is absent, i.e. Clean' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'cleanpw' -ApiKey $GoodKey
        Assert-Equal 'Clean' $v.Verdict 'verdict'
    }

    Test-Case 'a 500 is CheckFailed - inconclusive is NOT Clean' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        $v = Test-EnzoicPassword -Password 'servererror' -ApiKey $GoodKey
        Assert-Equal 'CheckFailed' $v.Verdict 'verdict'
    }

    Test-Case 'an unreachable Enzoic is CheckFailed, not Clean' {
        $script:EnzoicCache = @{}
        $saved = $script:EnzoicUrl
        $script:EnzoicUrl = 'http://localhost:1/passwords'
        try { $v = Test-EnzoicPassword -Password 'whatever' -ApiKey $GoodKey }
        finally { $script:EnzoicUrl = $saved }
        Assert-Equal 'CheckFailed' $v.Verdict 'verdict'
    }

    Test-Case 'a rejected API key throws instead of silently passing' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        $threw = $false
        try { $null = Test-EnzoicPassword -Password 'cleanpw' -ApiKey 'WRONGKEY' }
        catch { $threw = $true; Assert-Match 'raw 32-hex' $_.Exception.Message 'names the fix' }
        Assert-True $threw 'must throw on 401'
    }

    Test-Case 'answers are cached by full hash - a reused password costs one call' {
        Reset-FakeApi; $script:EnzoicCache = @{}
        foreach ($i in 1..5) { $null = Test-EnzoicPassword -Password 'breached1' -ApiKey $GoodKey }
        $s = Get-FakeStats
        Assert-Equal 1 $s.enzoicCalls 'five checks, one API call'
    }

    Test-Case 'the SHA-256 is of the UTF-8 bytes, lowercase hex' {
        $sha = [Security.Cryptography.SHA256]::Create()
        $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('breached1'))
        $sha.Dispose()
        $expected = (-join ($b | ForEach-Object { $_.ToString('x2') })).ToLower()
        Reset-FakeApi; $script:EnzoicCache = @{}
        $null = Test-EnzoicPassword -Password 'breached1' -ApiKey $GoodKey
        $s = Get-FakeStats
        Assert-Equal $expected.Substring(0, 10) ($s.enzoicBodies[0] | ConvertFrom-Json).partialSHA256 'prefix'
    }

    #=== verdicts end to end =================================================#
    Write-Host "`nverdicts end to end" -ForegroundColor Cyan
    # The shipping script talks to the real Enzoic URL, so these drive the same
    # code through the fake by overriding the URL in a dot-sourced copy.

    Test-Case 'a full sweep produces the right verdict mix and summary' {
        Reset-FakeApi
        $copy = Join-Path $WorkDir 'scan-fakeenzoic.ps1'
        $text = Get-Content -LiteralPath $ScriptUnderTest -Raw
        $text = $text.Replace("'https://api.enzoic.com/v1/passwords'", "'$EnzoicU'")
        Assert-Match ([regex]::Escape($EnzoicU)) $text 'URL substitution applied'
        Set-Content -LiteralPath $copy -Value $text -Encoding UTF8

        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; EnzoicApiKey = $GoodKey }) 'v1'
        $out = (Invoke-Child "& '$copy' -Config '$cfg'").Out

        Assert-Match 'Compromised\s+2' $out '9003 + 9007 share a breached password'
        Assert-Match 'Weak\s+1'        $out '9004'
        Assert-Match 'Clean\s+1'       $out '9005'
        Assert-Match 'CheckFailed\s+1' $out '9006'
        Assert-Match 'CheckFailed is NOT Clean' $out 'the warning fires'
        Assert-Match '12,345' $out 'exposure count is thousands-separated'

        $s = Get-FakeStats
        Assert-Equal 4 $s.enzoicCalls '5 passwords, 4 distinct - the cache saved one'
    }

    #=== dpapi / domain service accounts =====================================#
    Write-Host "`ndpapi (domain service accounts)" -ForegroundColor Cyan

    # New-ProtectedSecret is interactive. Read-Host is a cmdlet, and a FUNCTION
    # of the same name shadows it for everything called from this scope, so the
    # prompts can be answered without a console.
    function New-FakeReadHost {
        param([string[]]$Answers)
        $script:FakeAnswers = $Answers
        $script:FakeIndex   = 0
    }
    function Read-Host {
        param([string]$Prompt, [switch]$AsSecureString)
        $v = $script:FakeAnswers[$script:FakeIndex]
        $script:FakeIndex++
        return (ConvertTo-SecureString -String $v -AsPlainText -Force)
    }

    Test-Case '-ProtectSecret round-trips a user-scope value' {
        New-FakeReadHost @($GoodPw, $GoodPw)
        $blob = New-ProtectedSecret 6>$null
        Assert-Match '^[0-9a-fA-F]+$' $blob 'blob is hex'
        Assert-Equal $GoodPw (Unprotect-ConfigSecret $blob) 'round trip'
    }

    Test-Case '-ProtectSecret -MachineScope round-trips, and differs from user scope' {
        New-FakeReadHost @($GoodPw, $GoodPw)
        $user = New-ProtectedSecret 6>$null
        New-FakeReadHost @($GoodPw, $GoodPw)
        $machine = New-ProtectedSecret -Machine 6>$null
        Assert-Equal $GoodPw (Unprotect-ConfigSecret $machine) 'round trip'
        Assert-True ($user -ne $machine) 'the two scopes produce different blobs'
    }

    Test-Case 'one decrypt path reads both scopes - DPAPI records it in the blob' {
        New-FakeReadHost @('scope-test', 'scope-test')
        $machine = New-ProtectedSecret -Machine 6>$null
        # ConvertTo-SecureString takes no scope argument, yet this must work.
        Assert-Equal 'scope-test' (Unprotect-ConfigSecret $machine) 'machine blob via the user-scope API'
    }

    Test-Case 'a mismatched confirmation is refused' {
        New-FakeReadHost @('aaa', 'bbb')
        $threw = $false
        try { $null = New-ProtectedSecret 6>$null } catch { $threw = $true }
        Assert-True $threw 'must refuse'
    }

    Test-Case 'an empty value is refused' {
        New-FakeReadHost @('', '')
        $threw = $false
        try { $null = New-ProtectedSecret 6>$null } catch { $threw = $true }
        Assert-True $threw 'must refuse'
    }

    Test-Case 'a machine-scope blob authenticates from another process' {
        # This is the scheduled-task case: the blob is decrypted by a process
        # that is not the one that made it.
        Reset-FakeApi
        New-FakeReadHost @($GoodPw, $GoodPw)
        $blob = New-ProtectedSecret -Machine 6>$null
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'
                                  PasswordEncrypted = $blob; Folder = 'Solo' }) 'd6'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scanning 5 secret' $r.Out 'swept with a machine-scope blob'
    }

    Test-Case 'the DPAPI failure names the account the script is running as' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'u'
                                  PasswordEncrypted = 'deadbeef'; Folder = 'Solo' }) 'd7'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Assert-Match ([regex]::Escape($me)) $r.Out 'names the running identity'
        Assert-Match 'no loaded user profile' $r.Out 'names the service-account cause'
        Assert-Match 'MachineScope' $r.Out 'names the fix'
    }

    Test-Case '-MachineScope without -ProtectSecret warns instead of silently doing nothing' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'd8'
        $r = Invoke-Scan @('-Config', $cfg, '-MachineScope')
        Assert-Equal 0 $r.Exit 'still runs'
        Assert-Match 'only applies with -ProtectSecret' $r.Out 'the warning'
    }

    #=== config ==============================================================#
    Write-Host "`nconfig" -ForegroundColor Cyan

    Test-Case 'a missing config file is a warning, not a crash' {
        $r = Invoke-Scan @('-Config', (Join-Path $WorkDir 'nope.psd1'))
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'Config file not found' $r.Out 'clear message'
    }

    Test-Case 'a JSON config works as well as a psd1' {
        Reset-FakeApi
        $json = Join-Path $WorkDir 'cfg.json'
        (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'; Password = $GoodPw
            Folder = 'Solo' } | ConvertTo-Json) | Set-Content -LiteralPath $json -Encoding UTF8
        $r = Invoke-Scan @('-Config', $json)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scanning 5 secret' $r.Out 'swept via JSON config'
    }

    Test-Case 'an environment variable beats the config file' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'
                                  Password = 'WRONG-in-file'; Folder = 'Solo' }) 'c3'
        $r = Invoke-ScanWithEnv @{ SS_PASSWORD = $GoodPw } @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'env var supplied the working password'
        Assert-Match 'Scanning 5 secret' $r.Out 'swept'
    }

    Test-Case 'a parameter beats an environment variable' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Finance' }) 'c4'
        $r = Invoke-ScanWithEnv @{ SS_PASSWORD = $GoodPw } @('-Config', $cfg, '-Folder', 'Solo')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scope: \\Solo' $r.Out '-Folder won over the config'
        Assert-NoMatch 'Scope: \\Finance' $r.Out 'config folder was overridden'
    }

    Test-Case 'the connection settings work as parameters, with no config file at all' {
        # The documented precedence promises a parameter for every setting.
        # BaseUrl/Username/Password/EnzoicApiKey have to be bindable or the
        # quick start in the README is a lie.
        Reset-FakeApi
        $r = Invoke-ScanIsolated @('-BaseUrl', $Base, '-Username', 'svc_enzoic_api',
                                   '-Password', $GoodPw, '-Folder', 'Solo')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Authenticated to' $r.Out 'logged in from parameters alone'
        Assert-Match 'Scope: \\Solo'    $r.Out 'swept the folder'
        Assert-NoMatch 'Config:'        $r.Out 'no config file was discovered'
    }

    Test-Case 'a connection parameter beats both the environment and the config' {
        Reset-FakeApi
        # Config and environment both carry a wrong password; the parameter is
        # the only correct one, so a successful login proves precedence.
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'
                                  Password = 'from-config' }) 'c4b'
        $r = Invoke-ScanWithEnv @{ SS_PASSWORD = 'from-env' } `
                 @('-Config', $cfg, '-Password', $GoodPw, '-Folder', 'Solo')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Authenticated to' $r.Out 'the parameter password won'
    }

    Test-Case 'a blank config value falls through instead of being used' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'
                                  Password = $GoodPw; Folder = '   ' }) 'c5'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'folder\(s\)' $r.Out 'whitespace Folder means list, not sweep'
    }

    Test-Case 'a DPAPI PasswordEncrypted value is decrypted and used' {
        Reset-FakeApi
        $enc = ConvertTo-SecureString -String $GoodPw -AsPlainText -Force | ConvertFrom-SecureString
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'svc_enzoic_api'
                                  PasswordEncrypted = $enc; Folder = 'Solo' }) 'c6'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Scanning 5 secret' $r.Out 'decrypted password authenticated'
    }

    Test-Case 'a corrupt DPAPI value gives an actionable error' {
        Reset-FakeApi
        $cfg = New-TestConfig (@{ BaseUrl = $Base; Username = 'u'
                                  PasswordEncrypted = 'not-a-dpapi-blob'; Folder = 'Solo' }) 'c7'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 1 $r.Exit 'exit code'
        Assert-Match 'account that created it, on this machine' $r.Out 'explains DPAPI binding'
    }

    Test-Case 'no Enzoic key warns loudly and still lists the secrets' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'c8'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'No Enzoic API key configured' $r.Out 'the warning'
        Assert-Match 'Scanning 5 secret' $r.Out 'still swept'
    }

    #=== reports =============================================================#
    Write-Host "`nreports" -ForegroundColor Cyan

    Test-Case 'each run drops a NEW dated report, never overwriting' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r1'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir }) 'r1'
        foreach ($i in 1..3) { $null = Invoke-Scan @('-Config', $cfg) }
        $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.csv')
        Assert-Equal 3 $files.Count 'three runs, three files'
        Assert-Equal 3 (@($files.Name | Select-Object -Unique)).Count 'all names distinct'
    }

    Test-Case 'the report directory is created if it does not exist' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r2\nested\deep'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir }) 'r2'
        $r = Invoke-Scan @('-Config', $cfg)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-True (Test-Path -LiteralPath $dir) 'directory created'
    }

    Test-Case 'the report filename carries the scope and a sortable stamp' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r3'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = '\Finance\Shared'; ReportDirectory = $dir }) 'r3'
        $null = Invoke-Scan @('-Config', $cfg)
        $name = @(Get-ChildItem -LiteralPath $dir -Filter '*.csv')[0].Name
        Assert-Match '^enzoic-scan-shared-\d{8}-\d{6}\.csv$' $name "filename shape: $name"
    }

    Test-Case '-All names the report "all"' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r4'
        $cfg = New-TestConfig ($baseCfg + @{ ReportDirectory = $dir }) 'r4'
        $null = Invoke-Scan @('-Config', $cfg, '-All')
        $name = @(Get-ChildItem -LiteralPath $dir -Filter '*.csv')[0].Name
        Assert-Match '^enzoic-scan-all-\d{8}-\d{6}\.csv$' $name "filename shape: $name"
    }

    Test-Case 'the report NEVER contains a password column' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r5'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir }) 'r5'
        $null = Invoke-Scan @('-Config', $cfg, '-Reveal')   # even with -Reveal
        $file = @(Get-ChildItem -LiteralPath $dir -Filter '*.csv')[0]
        $raw  = Get-Content -LiteralPath $file.FullName -Raw
        Assert-NoMatch 'Password' $raw 'no password header'
        Assert-NoMatch 'breached1' $raw 'no password value'
        $cols = (Import-Csv -LiteralPath $file.FullName)[0].PSObject.Properties.Name
        Assert-Equal 'Id Folder Name Username Verdict Exposures Note' ($cols -join ' ') 'columns'
    }

    Test-Case 'RetainReports keeps only the newest N' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r6'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir
                                             RetainReports = 2 }) 'r6'
        foreach ($i in 1..4) {
            $null = Invoke-Scan @('-Config', $cfg)
            Start-Sleep -Milliseconds 1100   # distinct second in the stamp
        }
        $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.csv')
        Assert-Equal 2 $files.Count 'pruned down to 2'
    }

    Test-Case 'RetainReports 0 keeps everything' {
        Reset-FakeApi
        $dir = Join-Path $WorkDir 'r7'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir
                                             RetainReports = 0 }) 'r7'
        foreach ($i in 1..3) { $null = Invoke-Scan @('-Config', $cfg) }
        Assert-Equal 3 (@(Get-ChildItem -LiteralPath $dir -Filter '*.csv')).Count 'nothing pruned'
    }

    Test-Case '-Csv writes one fixed path and overwrites it' {
        Reset-FakeApi
        $fixed = Join-Path $WorkDir 'latest.csv'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'r8'
        foreach ($i in 1..2) { $null = Invoke-Scan @('-Config', $cfg, '-Csv', $fixed) }
        Assert-True (Test-Path -LiteralPath $fixed) 'file exists'
        Assert-Equal 5 (@(Import-Csv -LiteralPath $fixed)).Count 'overwritten, not appended'
    }

    Test-Case 'ReportDirectory and Csv can both be used in one run' {
        Reset-FakeApi
        $dir   = Join-Path $WorkDir 'r9'
        $fixed = Join-Path $WorkDir 'r9-latest.csv'
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo'; ReportDirectory = $dir }) 'r9'
        $r = Invoke-Scan @('-Config', $cfg, '-Csv', $fixed)
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Equal 1 (@(Get-ChildItem -LiteralPath $dir -Filter '*.csv')).Count 'dated report'
        Assert-True (Test-Path -LiteralPath $fixed) 'fixed report'
    }

    #=== output ==============================================================#
    Write-Host "`noutput" -ForegroundColor Cyan

    Test-Case '-PassThru emits objects with the expected properties' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'o1'
        $cmd = "& '$ScriptUnderTest' -Config '$cfg' -PassThru | " +
               "Select-Object -First 1 | ForEach-Object { `$_.PSObject.Properties.Name -join ',' }"
        $out = (Invoke-Child $cmd).Out
        Assert-Match 'Id,Folder,Name,Username,Password,Verdict,Exposures,Note' $out "props: $out"
    }

    Test-Case 'without -PassThru nothing goes to the object pipeline' {
        Reset-FakeApi
        $cfg = New-TestConfig ($baseCfg + @{ Folder = 'Solo' }) 'o2'
        $cmd = "`$r = @(& '$ScriptUnderTest' -Config '$cfg'); 'COUNT=' + `$r.Count"
        $out = (Invoke-Child $cmd).Out
        Assert-Match 'COUNT=0' $out "pipeline output: $out"
    }

    Test-Case 'an empty scope explains that permissions look like emptiness' {
        Reset-FakeApi
        $cfg = New-TestConfig $baseCfg 'o3'
        $r = Invoke-Scan @('-Config', $cfg, '-Folder', '\Finance\Shared')
        Assert-Equal 0 $r.Exit 'exit code'
        Assert-Match 'Zero secrets in scope' $r.Out 'the warning'
        Assert-Match 'Secret Permissions = View' $r.Out 'names the second grant'
    }
}
finally {
    if ($script:Server -and -not $script:Server.HasExited) {
        Stop-Process -Id $script:Server.Id -Force -ErrorAction SilentlyContinue
    }
    if (-not $KeepWorkDir) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "`nWork dir kept: $WorkDir" -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host ("=" * 60)
if ($script:Fail -eq 0) {
    Write-Host "$($script:Pass) passed, 0 failed" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Pass) passed, $($script:Fail) FAILED" -ForegroundColor Red
$script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
exit 1
