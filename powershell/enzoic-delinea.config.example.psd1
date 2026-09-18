<#
    Copy to enzoic-delinea.config.psd1 and fill in. The README has the detail.

      Copy-Item .\enzoic-delinea.config.example.psd1 .\enzoic-delinea.config.psd1
      icacls .\enzoic-delinea.config.psd1 /inheritance:r /grant:r "$env:USERDOMAIN\$env:USERNAME:F"

    Gitignored, and it holds a password that can read every secret in scope -
    do not paste it into a ticket or a chat window.

    Precedence: command-line parameter > environment variable > this file.
#>

@{
    # Must include the /SecretServer vdir or the token endpoint 404s, which
    # looks identical to "Enable Webservices is off".
    BaseUrl = 'https://secretserver.example.com/SecretServer'

    # An application account, not a human login: no UI, so no 2FA to break the
    # password grant, and no license consumed. Needs View on BOTH the folder
    # and its secrets - two separate grants on the Sharing tab.
    Username = 'svc_enzoic_api'
    Password = ''

    # Better than plaintext. Generate AS THE ACCOUNT THAT WILL RUN THE SCAN:
    #     .\Invoke-EnzoicDelineaScan.ps1 -ProtectSecret
    # For an unattended scheduled task, add -MachineScope.
    # PasswordEncrypted = ''

    # Optional. DOMAIN\user in Username works too.
    # Domain = 'example.com'

    # The RAW 32-hex key - not base64, not key:secret.
    # Blank lists the secrets without checking them.
    EnzoicApiKey = ''
    # EnzoicApiKeyEncrypted = ''

    # A name or a full path; @('A', 'B') for several. Subfolders are always
    # included. A bare name matching two folders is an error, not a guess.
    # Blank, with All = $false, lists the visible folders - the right first run.
    Folder = ''
    All    = $false

    # A new dated CSV per run, never overwritten. Reports hold no passwords.
    ReportDirectory = 'C:\enzoic-reports'
    RetainReports   = 0     # keep the newest N; 0 keeps everything

    # Separate: one fixed path, overwritten each run, for a dashboard.
    # Csv = 'C:\enzoic-reports\latest.csv'

    Reveal   = $false       # print passwords in the console table
    Insecure = $false       # skip TLS validation - self-signed lab cert only

    # Pause between API calls. A sweep is one request per secret, and Secret
    # Server Cloud rate limits where on-prem does not. A 429 is already caught
    # and retried with backoff, so leave this at 0 and only raise it (try 100)
    # if a large cloud sweep still spends its retries. No effect on on-prem.
    ThrottleDelayMs = 0
}
