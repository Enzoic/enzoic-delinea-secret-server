# Enzoic vault sweep for Delinea Secret Server — Python

Reads passwords out of Secret Server over its REST API and checks each one
against Enzoic's compromised-credentials database.

Read-only. It never writes to Secret Server. The only thing it writes is a CSV
report on your own filesystem.

**Python 3.11+, one dependency (`requests`).** Runs on Windows, Linux and macOS.

> Before the first run, read
> **[../docs/secret-server-setup.md](../docs/secret-server-setup.md)** — the
> Secret Server account, the two permission grants people miss, and where the
> Enzoic API key comes from. It applies to both implementations.
>
> The [PowerShell version](../powershell/README.md) is the same tool for a
> Windows host that will not have Python on it. The two are at parity; see
> [Differences from the PowerShell version](#differences-from-the-powershell-version).

## Install

With [uv](https://docs.astral.sh/uv/):

```console
$ cd python
$ uv sync
$ uv run enzoic-delinea
```

Or with pip, into a virtualenv:

```console
$ cd python
$ python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
$ pip install -e .
$ enzoic-delinea
```

Or not at all. `src/enzoic_delinea/delinea.py` has no intra-package imports, so
it runs as a single file on any host that already has `requests`:

```console
$ python src/enzoic_delinea/delinea.py --all
```

Examples below use the installed `enzoic-delinea` command; `uv run
enzoic-delinea`, `python -m enzoic_delinea` and `python delinea.py` are
interchangeable with it.

## Quick start

Three values — see [the shared setup doc](../docs/secret-server-setup.md) for
where each comes from:

| | |
|---|---|
| `base_url` | `https://yourserver/SecretServer` — including the `/SecretServer` vdir |
| `username` / `password` | A Secret Server account with View on the folders **and** secrets in scope |
| `enzoic_api_key` | The raw 32-hex key. Blank lists the secrets without checking them |

Either pass them as arguments:

```console
$ enzoic-delinea --base-url https://yourserver/SecretServer \
      --username svc_enzoic_api --enzoic-api-key <32-hex key>
```

...or put them in a config file, which is what you want for anything repeatable:

```console
$ cp enzoic-delinea.config.example.toml enzoic-delinea.config.toml
$ $EDITOR enzoic-delinea.config.toml
$ enzoic-delinea
```

...or in a `.env`, if that fits your deployment better:

```console
$ cp .env.example .env
$ $EDITOR .env
```

Anything you omit is prompted for; the password prompt does not echo.

With no `--folder` and no `--all`, it lists the folders the account can see and
stops. That is always a safe first run.

## Running it

```console
$ enzoic-delinea                            # list visible folders
$ enzoic-delinea --all                      # sweep every secret
$ enzoic-delinea --folder Finance           # one folder and its subfolders
$ enzoic-delinea --help                     # full argument help
```

`--reveal` prints passwords; off by default, it shows `<n chars>` instead.
`--json` emits the rows as JSON on stdout, for anything downstream:

```console
$ enzoic-delinea --all --json |
      jq '[.[] | select(.verdict == "Compromised")] | sort_by(-.exposures)'
```

Progress and diagnostics go to **stderr**, the table and `--json` to **stdout**,
so a redirect gets the data and nothing else.

Exit code 0 on success, 1 on a fatal error, so a cron job's status is
meaningful.

## Output

| Verdict | Meaning |
|---|---|
| `Compromised` | Enzoic matched the password and `revealedInExposure` is true. `exposures` is `exposureCount` |
| `Weak` | Enzoic matched the password and `revealedInExposure` is false — not exposed in a breach |
| `Clean` | Checked against Enzoic, no match |
| `CheckFailed` | The lookup did not complete. Not a pass |
| *(blank)* | Not checked. `note` gives the reason: requires check-out, no password field, read error, or no API key configured |

Matching is on the full SHA-256, not the 10-character prefix sent to the API,
and is case-insensitive.

## Configuration

Settings resolve **argument > environment variable > config file**.
So a scheduled run keeps everything in the file, and you can override one value
for one run without editing it.

A `.env` file is a way of setting the environment variables, not a fourth
layer — and a real environment variable beats the `.env`. The full order,
highest first:

1. a command-line argument
2. a real environment variable
3. a value from `.env`
4. the config file

| Setting | Argument | Environment | Config key |
|---|---|---|---|
| Base URL | `--base-url` | `SS_BASE_URL` | `base_url` |
| Username | `--username` | `SS_USERNAME` | `username` |
| Password | `--password` | `SS_PASSWORD` | `password` / `password_encrypted` |
| Domain | `--domain` | `SS_DOMAIN` | `domain` |
| Enzoic key | `--enzoic-api-key` | `ENZOIC_API_KEY` | `enzoic_api_key` / `enzoic_api_key_encrypted` |
| Folders | `--folder` (repeatable) | — | `folder` |
| Everything | `--all` | — | `all` |
| Dated reports | `--report-directory` | — | `report_directory` |
| Retention | `--retain-reports` | — | `retain_reports` |
| Fixed CSV | `--csv` | — | `csv` |
| Reveal | `--reveal` | — | `reveal` |
| Skip TLS checks | `--insecure` | — | `insecure` |
| Pacing | `--throttle-delay-ms` | — | `throttle_delay_ms` |

### The config file

`.toml` or `.json`, found automatically as `enzoic-delinea.config.toml` (then
`.json`) next to the package and then in the working directory. Override with
`--config <path>`. `enzoic-delinea.config.example.toml` is the annotated
template and documents every key.

**Key names are matched case- and separator-insensitively**, so `base_url`,
`BaseUrl` and `base-url` are the same key. That is deliberate: the same key
names describe the PowerShell port's `.psd1`, so the two implementations are
documented once.

Two keys worth calling out:

- **`folder` takes a list** — `folder = ["Finance", "Service Accounts"]`, or
  repeat `--folder` on the command line. Subfolders are always included.
  Overlapping folders are de-duplicated by secret ID rather than swept twice. A
  bare leaf name matching more than one folder is an error, not a guess — pass
  the full path instead.
- **`throttle_delay_ms`** paces the sweep. A sweep is one request per secret,
  and **Secret Server Cloud rate limits where on-prem does not**. An HTTP 429 is
  already caught and retried with backoff, honouring the `Retry-After` header,
  so leave this at `0` and raise it (try `100`) only if a large cloud sweep
  still exhausts its retries. No effect on-prem.

`insecure = true` skips TLS certificate validation, if Secret Server uses a
certificate the machine does not trust.

### Securing the config file

The config file holds a password that can read every secret in scope.

```console
$ chmod 600 enzoic-delinea.config.toml                      # Linux, macOS
```
```powershell
icacls .\enzoic-delinea.config.toml /inheritance:r /grant:r "$env:USERDOMAIN\$env:USERNAME:F"
```

Note the domain-qualified name in the `icacls` grant — an unqualified
`$env:USERNAME` resolves against the local SAM database first, which on a
domain-joined machine is not the account you meant.

Both `.env` and the config file are gitignored.

### Encrypting the two secrets (Windows)

Optional, and Windows only. Instead of plaintext `password` /
`enzoic_api_key`, set `password_encrypted` / `enzoic_api_key_encrypted` to a
DPAPI blob:

```console
> enzoic-delinea --protect-secret                    # user scope
> enzoic-delinea --protect-secret --machine-scope    # machine scope
```

It prompts twice, prints the blob to paste into the config, and names the
identity it encrypted under. One decrypt path reads both scopes — DPAPI records
the scope in the blob — so there is no config key to set and a wrong guess is
impossible.

These blobs are **interchangeable with the PowerShell version's**: the format is
the hex of a DPAPI blob over the value's UTF-16LE bytes, which is exactly what
`ConvertFrom-SecureString` emits. Both test suites assert the round trip against
the other implementation.

**Scope of the protection.** DPAPI means other accounts cannot read the file. It
does not mean the file is useless off the machine — a user-scope master key
lives in `%APPDATA%`, the roaming half of the profile, so a domain user with a
roaming profile can decrypt their own blob on another machine. It is still
confined to that user.

A user-scope blob needs the creating account, on that machine, with its profile
loaded. Generate it **as the account that will run the scan**, or use
`--machine-scope` for an unattended task and let the file ACL be the control.
A first scheduled run that fails while manual runs succeed is almost always a
user-scope blob generated under the wrong account; the error message says so.

On Linux and macOS there is no DPAPI. Keep the secrets in environment variables
and `chmod 600` the config file.

## Reports

`--report-directory` (or `report_directory`) writes a new file per run and
never overwrites:

```
enzoic-scan-finance-20260827-143012.csv
enzoic-scan-all-20260828-020007.csv
```

The stamp is `yyyymmdd-HHMMSS`, so files sort chronologically by name. The
directory is created if missing. `--retain-reports N` keeps only the newest N —
ordered by write time, not by name, in case the scope slug changes between runs.

`--csv <path>` is separate: one fixed path, overwritten each run, for a
dashboard that wants a stable "latest". Both can be used in the same run.

Reports never contain passwords, with or without `--reveal`. There is a test
asserting it, because it is the one thing that must not regress: the report is
the artifact that gets emailed.

## Scheduling

```cron
0 2 * * *  /opt/enzoic/.venv/bin/enzoic-delinea --config /etc/enzoic/scan.toml
```

Or as a systemd timer, or a Windows scheduled task:

```powershell
$action  = New-ScheduledTaskAction -Execute 'C:\enzoic\.venv\Scripts\enzoic-delinea.exe' `
    -Argument '--config C:\enzoic\scan.toml'
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'Enzoic vault sweep' -Action $action -Trigger $trigger `
    -User 'DOMAIN\svc_enzoic_task' -RunLevel Limited
```

Keep `reveal = false` in anything scheduled — captured output would otherwise
contain every password in the vault.

Unlike the PowerShell version, a multi-folder list *can* be passed on the
command line here (`--folder A --folder B`), so it does not have to live in the
config file.

## Troubleshooting

**HTTP 400 on login.** The message includes Secret Server's own reason. Causes:
wrong password; the account is locked out; the account has 2FA, which the OAuth
password grant cannot satisfy; or an AD-synced account that needs `domain` set,
or `DOMAIN\user` in `username`.

**HTTP 404 on login.** `base_url` is missing the `/SecretServer` virtual
directory, or web services are disabled.

**"Could not reach ..."** — network, DNS, or TLS, not authentication. For an
untrusted certificate, `insecure = true`.

**The connection is accepted but nothing responds.** Usually an IIS app pool
recycle. It retries with a backoff, then says so — and says explicitly that
this is the application and not the network, because a read timeout after a
successful connect reads like a network fault and is not one.

**A folder appears but the sweep finds no secrets in it.** The account has
Folder Permissions but not Secret Permissions. Both are needed — see [the
shared setup doc](../docs/secret-server-setup.md#it-needs-two-separate-grants).

**HTTP 429 / "still throttled after N retries".** Secret Server Cloud rate
limiting. It already backs off and retries, honouring `Retry-After`; if it still
runs out, set `throttle_delay_ms = 100` to pace the whole sweep, or narrow the
run with `--folder`.

**HTTP 401 from Enzoic.** The API key is not the raw 32-hex value — see
[Getting an Enzoic API
key](../docs/secret-server-setup.md#getting-an-enzoic-api-key).

**An empty scope.** It says so rather than reporting a clean vault. "No secrets"
and "no permission to see the secrets" are indistinguishable from the API.

**`ModuleNotFoundError: tomllib`.** Python 3.10 or older. `tomllib` is stdlib
from 3.11; use a `.json` config file, or upgrade.

## Verifying it before pointing it at your vault

```console
$ python tests/test_delinea.py
```

66 cases on Windows, 59 elsewhere (the DPAPI suite is Windows-only), against a
fake Secret Server and a fake Enzoic. No vault, no API key, no network, nothing
external contacted.

Covers token refresh and both fallbacks, the cold-start retry, folder paging and
ambiguity, multi-folder de-duplication, check-out skipping, 403 handling, 429
backoff and `Retry-After` in both header forms, the Enzoic wire format and
verdict mapping, hash caching, config precedence across all three layers, DPAPI
in both scopes, dated reports and retention, `--json` masking, and that reports
contain no passwords.

Two Enzoic details worth naming, both tested: a **decoy candidate sharing the
10-character prefix** with a much larger exposure count, so matching on the
prefix instead of the full hash fails the suite; and the matching hash returned
**uppercased**, so a case-sensitive comparison fails too.

The suite blanks `SS_*` and `ENZOIC_API_KEY` and stubs out `.env` loading in
every test, so a run on a configured machine cannot reach a real vault or spend
a real API key. An earlier version picked up the live `ENZOIC_API_KEY` and tried
to spend it during a test run.

Two of the DPAPI tests shell out to `powershell.exe` and assert the blob format
against the actual PowerShell implementation, in both directions. They skip if
`powershell.exe` is not on `PATH`.

## Differences from the PowerShell version

Same wire behaviour, same verdicts, same config keys. These are the deviations
that remain, and they are deliberate.

- **`--json` follows `--reveal`** and masks passwords by default. PowerShell's
  `-PassThru` hands objects to a live shell; stdout here is far more likely to
  be redirected into a file, so the safe default differs.
- **DPAPI is Windows-only**, so `--protect-secret` and the `*_encrypted` config
  keys raise a clear error elsewhere. The blobs themselves are wire-compatible
  with the PowerShell version in both directions.
- **The cold-start retry keys off `ReadTimeout` specifically**, which `requests`
  distinguishes from a connect timeout. .NET does not, so the PowerShell version
  retries on any timeout.
- **`--insecure` is per-session**; on PowerShell 5.1 the equivalent is
  process-wide.
- **Progress goes to stderr**, where the PowerShell version uses
  `Write-Progress`.
- **A multi-folder list works on the command line** here. `powershell.exe -File`
  cannot pass an array, so the PowerShell version needs the config file for that.

Things that used to be on this list and no longer are: dated reports and
retention, multi-folder lists, `SS_DOMAIN`, throttle handling, a config file,
and DPAPI-encrypted config values are all present in both now.
