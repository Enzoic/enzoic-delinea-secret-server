# Enzoic vault sweep for Delinea Secret Server — PowerShell

Reads passwords out of Secret Server over its REST API and checks each one
against Enzoic's compromised-credentials database.

Read-only. It never writes to Secret Server. The only thing it writes is a CSV
report on your own filesystem.

**Windows PowerShell 5.1 or PowerShell 7+. No modules, no dependencies.** One
script file; copy it to the box and run it.

> Before the first run, read
> **[../docs/secret-server-setup.md](../docs/secret-server-setup.md)** — the
> Secret Server account, the two permission grants people miss, and where the
> Enzoic API key comes from. It applies to both implementations.
>
> The [Python version](../python/README.md) is the same tool for a host that
> will not be Windows. The two are at parity; see
> [Differences from the Python version](#differences-from-the-python-version).

## Quick start

Three values — see [the shared setup doc](../docs/secret-server-setup.md) for
where each comes from:

| | |
|---|---|
| `BaseUrl` | `https://yourserver/SecretServer` — including the `/SecretServer` vdir |
| `Username` / `Password` | A Secret Server account with View on the folders **and** secrets in scope |
| `EnzoicApiKey` | The raw 32-hex key. Blank lists the secrets without checking them |

Either pass them on the command line:

```powershell
.\Invoke-EnzoicDelineaScan.ps1 -BaseUrl 'https://yourserver/SecretServer' `
    -Username 'svc_enzoic_api' -EnzoicApiKey '<32-hex key>'
```

...or put them in a config file, which is what you want for anything repeatable:

```powershell
Copy-Item .\enzoic-delinea.config.example.psd1 .\enzoic-delinea.config.psd1
notepad .\enzoic-delinea.config.psd1
.\Invoke-EnzoicDelineaScan.ps1
```

The config file is picked up automatically from next to the script, then the
working directory. Anything you omit is prompted for.

With no `-Folder` and no `-All`, the script lists the folders the account can
see and stops. That is always a safe first run.

## Running it

```powershell
.\Invoke-EnzoicDelineaScan.ps1                      # list visible folders
.\Invoke-EnzoicDelineaScan.ps1 -All                 # sweep every secret
.\Invoke-EnzoicDelineaScan.ps1 -Folder 'Finance'    # one folder and its subfolders
Get-Help .\Invoke-EnzoicDelineaScan.ps1 -Full       # full parameter help
```

`-Reveal` prints passwords in the console table; off by default, it shows
`<n chars>` instead. `-PassThru` emits objects:

```powershell
.\Invoke-EnzoicDelineaScan.ps1 -All -PassThru |
    Where-Object { $_.Verdict -eq 'Compromised' } | Sort-Object Exposures -Descending
```

Exit code 0 on success, 1 on a fatal error, so a scheduled task's Last Run
Result is meaningful.

## Output

| Verdict | Meaning |
|---|---|
| `Compromised` | Enzoic matched the password and `revealedInExposure` is true. `Exposures` is `exposureCount` |
| `Weak` | Enzoic matched the password and `revealedInExposure` is false — not exposed in a breach |
| `Clean` | Checked against Enzoic, no match |
| `CheckFailed` | The lookup did not complete. Not a pass |
| *(blank)* | Not checked. `Note` gives the reason: requires check-out, no password field, read error, or no API key configured |

Matching is on the full SHA-256, not the 10-character prefix sent to the API,
and is case-insensitive.

## Config file

`.psd1` or `.json`. Override the location with `-Config <path>`.
`enzoic-delinea.config.example.psd1` is the annotated template and documents
every key.

Settings resolve **parameter > environment variable > config file**. So a
scheduled task keeps everything in the file, and you can override one value for
one run without editing it. Environment variables: `SS_BASE_URL`,
`SS_USERNAME`, `SS_PASSWORD`, `SS_DOMAIN`, `ENZOIC_API_KEY` — the same names
the Python version uses.

Two keys worth calling out:

- **`Folder` takes a list** — `@('Finance', 'Service Accounts')`. Subfolders are
  always included. Overlapping folders are de-duplicated by secret ID rather
  than swept twice. A bare leaf name matching more than one folder is an error,
  not a guess — pass the full path instead.
- **`ThrottleDelayMs`** paces the sweep. A sweep is one request per secret, and
  **Secret Server Cloud rate limits where on-prem does not**. An HTTP 429 is
  already caught and retried with backoff, honouring the `Retry-After` header,
  so leave this at `0` and raise it (try `100`) only if a large cloud sweep
  still exhausts its retries. No effect on-prem.

`Insecure = $true` skips TLS certificate validation, if Secret Server uses a
certificate the machine does not trust.

## Reports

`ReportDirectory` writes a new file per run and never overwrites:

```
enzoic-scan-finance-20260827-143012.csv
enzoic-scan-all-20260828-020007.csv
```

The stamp is `yyyyMMdd-HHmmss`, so files sort chronologically by name. The
directory is created if missing. `RetainReports = N` keeps only the newest N.

`-Csv <path>` is separate: one fixed path, overwritten each run, for a dashboard
that wants a stable "latest". Both can be used in the same run.

Reports never contain passwords, with or without `-Reveal`.

## Scheduling

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\enzoic\Invoke-EnzoicDelineaScan.ps1"'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'Enzoic vault sweep' -Action $action -Trigger $trigger `
    -User 'DOMAIN\svc_enzoic_task' -RunLevel Limited
```

Everything else comes from the config file. Note that **`powershell.exe -File`
cannot pass an array**: `-Folder 'A','B'` arrives as the single literal string
`A,B` and fails as `No folder matching 'A,B'`. A multi-folder list has to come
from the config file, or use `-Command`.

Keep `Reveal = $false` in anything scheduled — a transcript would otherwise
capture every password in the vault.

If the secrets are DPAPI-encrypted, read [Encrypting the two
secrets](#encrypting-the-two-secrets) before scheduling: `-User
'DOMAIN\svc_enzoic_task'` means a user-scope blob must have been generated *as
that account*, and a first scheduled run that fails while manual runs succeed is
almost always this.

## Troubleshooting

**HTTP 400 on login.** The message includes Secret Server's own reason. Causes:
wrong password; the account is locked out; the account has 2FA, which the OAuth
password grant cannot satisfy; or an AD-synced account that needs `Domain` set,
or `DOMAIN\user` in `Username`.

**HTTP 404 on login.** `BaseUrl` is missing the `/SecretServer` virtual
directory, or web services are disabled.

**"Could not reach ..."** — network, DNS, or TLS, not authentication. For an
untrusted certificate, `Insecure = $true`. On PowerShell 5.1 that is
process-wide; PowerShell 7 applies it per request.

**The connection is accepted but nothing responds.** Usually an IIS app pool
recycle. The script retries with a backoff, then says so.

**A folder appears but the sweep finds no secrets in it.** The account has
Folder Permissions but not Secret Permissions. Both are needed — see [the
shared setup doc](../docs/secret-server-setup.md#it-needs-two-separate-grants).

**HTTP 429 / "still throttled after N retries".** Secret Server Cloud rate
limiting. The script already backs off and retries, honouring `Retry-After`;
if it still runs out, set `ThrottleDelayMs = 100` to pace the whole sweep, or
narrow the run with `-Folder`.

**HTTP 401 from Enzoic.** The API key is not the raw 32-hex value — see
[Getting an Enzoic API
key](../docs/secret-server-setup.md#getting-an-enzoic-api-key).

**An empty scope.** The script says so rather than reporting a clean vault. "No
secrets" and "no permission to see the secrets" are indistinguishable from the
API.

## Verifying the script before pointing it at your vault

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-EnzoicDelineaScan.ps1
```

64 cases against a fake Secret Server and a fake Enzoic on localhost. No vault,
no API key, no network, nothing external contacted. Covers token refresh,
paging, folder ambiguity, checked-out secrets, 403 handling, the Enzoic wire
format and verdict mapping, config precedence, DPAPI values in both scopes,
dated reports and retention, and that reports contain no passwords.

`tests/fake-api.ps1` is the stub server; the suite starts and stops it.

Two Enzoic details worth naming, both tested: the fake returns a **decoy
candidate sharing the 10-character prefix** with a much larger exposure count,
so matching on the prefix instead of the full hash fails the suite; and it
returns the matching hash **uppercased**, so a case-sensitive comparison fails
too.

The suite blanks `SS_*` and `ENZOIC_API_KEY` in every child process, so a run
on a configured machine cannot reach a real vault or spend a real API key.

---

# Reference

Everything below is optional detail. The Quick start above is enough to run it.

## Securing the config file

The config file holds a password that can read every secret in scope. Restrict
it to the account that runs the scan:

```powershell
icacls .\enzoic-delinea.config.psd1 /inheritance:r /grant:r "$env:USERDOMAIN\$env:USERNAME:F"
```

`/inheritance:r` drops inherited permissions so the grant is the whole ACL. Note
the domain-qualified name — an unqualified `$env:USERNAME` resolves against the
local SAM database first, which on a domain-joined machine is not the account
you meant.

`.psd1` is read with `Import-PowerShellDataFile`, which parses data only.
Nothing in the config file executes.

## Encrypting the two secrets

Optional. Instead of plaintext `Password` / `EnzoicApiKey`, set
`PasswordEncrypted` / `EnzoicApiKeyEncrypted` to a DPAPI blob:

```powershell
.\Invoke-EnzoicDelineaScan.ps1 -ProtectSecret                 # user scope
.\Invoke-EnzoicDelineaScan.ps1 -ProtectSecret -MachineScope   # machine scope
```

It prompts twice, prints the blob to paste into the config, and names the
identity it encrypted under. One decrypt path reads both scopes — DPAPI records
the scope in the blob — so there is no config key to set and a wrong guess is
impossible.

These blobs are **interchangeable with the Python version's**: it produces and
consumes the same format, and both test suites assert it against the other
implementation.

**Scope of the protection.** DPAPI means other accounts cannot read the file. It
does not mean the file is useless off the machine. A user-scope master key lives
in `%APPDATA%\Microsoft\Protect\<SID>`, and `%APPDATA%` is the **roaming** half
of the profile — so a domain user with a roaming profile, or with AD credential
roaming enabled, can decrypt their own blob on another machine. Treat DPAPI as
"other accounts cannot read it", not as "it cannot leave this host".

## Who runs the script

Secret Server authentication does not depend on it. The script logs in with an
explicit username and password over the OAuth password grant. It never uses the
caller's Windows identity — no Kerberos, no CredSSP, no WinRM, no delegation. A
domain user, a local user, `SYSTEM`, a gMSA are all equivalent to Secret Server.
The `Domain` setting refers to the Secret Server account, not the Windows
account running the script.

DPAPI is the exception, and only if the secrets are encrypted. A user-scope blob
needs the creating account, on that machine, with its profile loaded:

| Cause | Symptom |
|---|---|
| Blob generated under an admin's login, task runs as a service account | Fails on the first scheduled run after working by hand |
| Service account with no loaded user profile | Same, and it persists across reboots |
| Account's password reset by an administrator | Domain accounts usually recover via the AD backup master key, which needs DC connectivity; a local account loses the blob |

Two options, and this is a policy call rather than a default:

- **User scope, generated as the runtime account.** Run `-ProtectSecret` as the
  service account — `PsExec -u`, or a one-off scheduled task under that account.
  Narrowest, and subject to all three rows above.
- **Machine scope** (`-ProtectSecret -MachineScope`). Any account on that
  computer can decrypt it, so the file ACL is the control rather than a second
  layer behind DPAPI. It survives the profile case, a password reset, and being
  generated from a different session. For an unattended nightly task this is
  usually the right trade.

**Not verified against a domain.** Both scopes, the round trip, the
cross-process decrypt and the error text are covered by tests. The three rows in
the table above are documented Windows behaviour, exercised on a workgroup
machine — no domain login, no roaming profile and no cross-account scheduled
task was reproduced here. Worth ten minutes on a lab DC before relying on it.

## Differences from the Python version

Same wire behaviour, same verdicts, same config keys. These are the deviations
that remain, and they are deliberate.

- **`-PassThru` emits live objects** into the PowerShell pipeline, including
  `Password`. The Python version's equivalent is `--json` on stdout, which
  follows `--reveal` and masks by default — stdout is far more likely to be
  redirected into a file than a PowerShell object stream is.
- **`-Insecure` is process-wide on 5.1**
  (`ServerCertificateValidationCallback`); PowerShell 7 gets the per-request
  `-SkipCertificateCheck` instead. Python applies it per session.
- **The cold-start retry keys off any timeout**, not specifically a read
  timeout: .NET surfaces both as `WebExceptionStatus.Timeout` and does not
  distinguish them the way Python's `requests` does.
- **`Set-StrictMode -Version 1.0`, not 2.0.** Under 2.0, a function returning a
  collection of exactly one item unrolls it to a scalar and every `.Count` on
  the result becomes a hard error — a tenant with one visible folder crashed
  during testing. Fixed by wrapping the call sites in `@()`; the lower strict
  mode is the second belt.
- **`Write-Progress`** during a sweep. The Python version prints its progress
  to stderr instead.

Things that used to be on this list and no longer are: dated reports and
retention, multi-folder lists, `Domain`, throttle handling, and DPAPI-encrypted
config values are all present in both now.
