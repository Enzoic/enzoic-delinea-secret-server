#!/usr/bin/env python3
"""
Read secrets out of Delinea Secret Server and check them against Enzoic.

    enzoic-delinea                  list the folders this account can see
    enzoic-delinea --all            sweep every secret, all folders
    enzoic-delinea --folder NAME    sweep one folder (and its subfolders)

Read-only. It never writes to Secret Server. The only thing it writes is a CSV
report on your own filesystem, and the report never contains passwords.

Settings resolve in this order, highest first:

    1. a command-line argument
    2. an environment variable (SS_BASE_URL, SS_USERNAME, SS_PASSWORD,
       SS_DOMAIN, ENZOIC_API_KEY) - a .env file sets these, and a real
       environment variable beats the file
    3. the config file (enzoic-delinea.config.toml or .json)

This is the Python half of a two-language pair; powershell/ has the same tool
for a host that will not have Python on it. Same endpoints, same verdicts, same
read-only guarantee, and the same config keys - the two are interchangeable.

Endpoints (verified against the 12.1.2 OpenAPI spec). Note the versions:
search and get are v2, folders are v1. /api/v1/secrets has no GET at all.

    POST /oauth2/token                      grant_type=password | refresh_token
    GET  /api/v1/folders                    filter.searchText (a CONTAINS match)
    GET  /api/v2/secrets                    filter.folderId, paged
    GET  /api/v2/secrets/{id}               items[] incl. isPassword + itemValue
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import email.utils
import getpass
import hashlib
import json
import math
import os
import re
import sys
import time

import requests

ENZOIC_URL = "https://api.enzoic.com/v1/passwords"
TIMEOUT = 60
RETRIES = 3

# Secret Server Cloud throttles the API; on-prem effectively does not. A sweep
# is one GET per secret, so a large vault WILL be throttled. Back off and retry
# rather than losing the run. throttle_delay_ms paces every request and
# defaults to 0, so on-prem behaviour is unchanged.
THROTTLE_RETRIES = 5
THROTTLE_MAX_WAIT = 60

CONFIG_NAMES = ("enzoic-delinea.config.toml", "enzoic-delinea.config.json")

# Columns written to a report. Deliberately omits the password: the report is
# the artifact that gets emailed. The console table with --reveal is not.
REPORT_COLUMNS = ["id", "folder", "name", "username", "verdict", "exposures", "note"]


class SSError(RuntimeError):
    def __init__(self, message, status=0):
        super().__init__(message)
        self.status = status


def load_env(path=None):
    """Minimal .env loader. Real environment variables win over the file."""
    path = path or next(
        (p for p in (".env", os.path.join(os.path.dirname(__file__), ".env"))
         if os.path.isfile(p)), None)
    if not path or not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip().removeprefix("export ").strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]          # keep '#' and spaces inside quotes
            os.environ.setdefault(key.strip(), value)
    return path


# --- config file --------------------------------------------------------- #

def _norm(key):
    """Fold BaseUrl, base_url and base-url onto one name.

    The PowerShell port uses PascalCase because that is what a .psd1 looks
    like. Normalising means one set of key names describes both implementations,
    which is the point of keeping them at parity.
    """
    return re.sub(r"[_\-\s]+", "", str(key)).lower()


def load_config(path=None):
    """Load a .toml or .json config. Returns (settings, resolved_path).

    Searched next to this file, then in the working directory - the same order
    the PowerShell version uses.
    """
    if not path:
        here = os.path.dirname(os.path.abspath(__file__))
        candidates = [os.path.join(d, n)
                      for d in (here, os.getcwd()) for n in CONFIG_NAMES]
        path = next((p for p in candidates if os.path.isfile(p)), None)
    if not path:
        return {}, None
    if not os.path.isfile(path):
        raise SSError(f"Config file not found: {path}")

    if path.lower().endswith(".json"):
        with open(path, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
    else:
        import tomllib                       # stdlib since 3.11
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    if not isinstance(raw, dict):
        raise SSError(f"{path} must contain a table of settings, not a "
                      f"{type(raw).__name__}")
    return {_norm(k): v for k, v in raw.items()}, os.path.abspath(path)


def setting(name, cli, env_name, cfg, default=None, secret=False):
    """Argument, then environment variable, then config file.

    `secret` also accepts a "<name>Encrypted" key holding a DPAPI blob, so the
    config file need not carry the password in plaintext.
    """
    if cli is not None and cli != "":
        return cli
    if env_name and os.environ.get(env_name):
        return os.environ[env_name]
    value = cfg.get(_norm(name))
    if secret and not value:
        blob = cfg.get(_norm(name + "Encrypted"))
        if blob:
            return dpapi_unprotect(str(blob))
    return default if value is None or value == "" else value


# --- DPAPI (Windows) ------------------------------------------------------ #
#
# Wire-compatible with the PowerShell port: a lowercase hex string of the DPAPI
# blob over the value's UTF-16LE bytes, which is exactly what
# ConvertFrom-SecureString emits. A blob generated by either implementation
# decrypts in the other.

_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_CRYPTPROTECT_LOCAL_MACHINE = 0x04


def _dpapi_call(func_name, data, flags):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    func = getattr(crypt32, func_name)
    func.restype = wintypes.BOOL

    buf = ctypes.create_string_buffer(data, len(data))
    src = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = Blob()
    ok = func(ctypes.byref(src), None, None, None, None, flags, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error(), f"{func_name} failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_protect(text, machine=False):
    if os.name != "nt":
        raise SSError("DPAPI is a Windows feature. On Linux or macOS, keep the "
                      "secrets in environment variables and restrict the config "
                      "file with chmod 600.")
    flags = _CRYPTPROTECT_UI_FORBIDDEN | (_CRYPTPROTECT_LOCAL_MACHINE if machine else 0)
    return _dpapi_call("CryptProtectData", text.encode("utf-16-le"), flags).hex()


def dpapi_unprotect(blob_hex):
    """Decrypt a config value. One path reads both scopes - DPAPI records the
    scope in the blob itself and ignores the flag on decrypt."""
    if os.name != "nt":
        raise SSError("This config file holds a DPAPI-encrypted value, which "
                      "only Windows can decrypt. Use the plaintext key, or an "
                      "environment variable, on this platform.")
    try:
        raw = bytes.fromhex(str(blob_hex).strip())
    except ValueError:
        raise SSError("An encrypted config value is not valid hex. It should be "
                      "the output of --protect-secret, pasted whole.")
    try:
        return _dpapi_call("CryptUnprotectData", raw,
                           _CRYPTPROTECT_UI_FORBIDDEN).decode("utf-16-le")
    except OSError:
        who = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '?')}"
        raise SSError(
            f"Could not decrypt an encrypted config value (DPAPI). This is "
            f"running as {who}. A user-scope blob only decrypts for the account "
            f"that created it, on this machine, with that account's profile "
            f"loaded. The usual causes on a domain-joined box: the blob was "
            f"generated under a different account than the one this runs as; "
            f"the service account has no loaded user profile; or the account's "
            f"password was reset by an administrator. Fix: re-generate it AS "
            f"this account with --protect-secret, or use --protect-secret "
            f"--machine-scope for an unattended task.")


def protect_secret(machine=False):
    """Prompt twice and print a blob to paste into the config file."""
    who = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '?')}"
    print(f"Generating a DPAPI value as: {who}", file=sys.stderr)
    if machine:
        print("Scope: MACHINE - ANY account on this computer can decrypt it.",
              file=sys.stderr)
    else:
        print(f"Scope: USER - only {who}, on this computer, can decrypt it.\n"
              f"       If a scheduled task runs as a different account, re-run "
              f"this as that account.", file=sys.stderr)

    first = getpass.getpass("Value to encrypt: ")
    second = getpass.getpass("Confirm: ")
    if not first:
        raise SSError("Empty value - nothing to encrypt.")
    if first != second:
        raise SSError("The two values do not match.")

    print("\nPaste into the config file as password_encrypted or "
          "enzoic_api_key_encrypted:\n", file=sys.stderr)
    print(dpapi_protect(first, machine=machine))
    return 0


# --- throttling ----------------------------------------------------------- #

def retry_after_seconds(response):
    """Seconds to wait per the Retry-After header, or 0 if it says nothing
    usable. The header is either a delta in seconds or an HTTP-date."""
    try:
        raw = (response.headers.get("Retry-After") or "").strip()
    except Exception:
        return 0
    if not raw:
        return 0
    try:
        seconds = int(raw)
        return seconds if seconds > 0 else 0
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return 0
    if when is None:
        return 0
    if when.tzinfo is None:
        when = when.replace(tzinfo=_dt.timezone.utc)
    delta = (when - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    return max(0, math.ceil(delta))         # anything in the past collapses to 0


def throttle_wait(response, attempt):
    """Honour Retry-After when the server sends one, otherwise exponential
    backoff. Capped either way so a hostile header cannot park the scan."""
    wait = retry_after_seconds(response)
    if wait <= 0:
        wait = 2 ** attempt
    return max(1, min(wait, THROTTLE_MAX_WAIT))


class SecretServer:
    """OAuth with refresh, folder lookup, secret search and read."""

    def __init__(self, base_url, username, password, verify=True, domain=None,
                 throttle_delay_ms=0):
        self.base = base_url.rstrip("/")
        self.user, self._pw = username, password
        self.domain = domain or None
        self.throttle_delay_ms = max(0, min(int(throttle_delay_ms or 0), 10000))
        self.session = requests.Session()
        self.session.verify = verify
        if not verify:
            requests.packages.urllib3.disable_warnings()
        self.token = self.refresh_token = None
        self.expires_at = 0.0

    # -- auth ------------------------------------------------------------- #

    def _token(self, data, what):
        url = f"{self.base}/oauth2/token"
        # Separate budgets: warming up after an app pool recycle and being
        # throttled by a cloud tenant are different waits with different limits.
        warm = throttled = 0
        while True:
            try:
                r = self.session.post(url, data=data, timeout=TIMEOUT)
            except requests.exceptions.ReadTimeout:
                # Connect succeeded, app did not answer: Secret Server is
                # warming up after an app pool recycle. Worth waiting out.
                warm += 1
                if warm >= RETRIES:
                    raise SSError(f"{url} accepted the connection but never "
                                  f"responded. The host is up - this is the "
                                  f"application, not the network. Usually an "
                                  f"IIS app pool recycle; load the site in a "
                                  f"browser, wait, and retry.")
                wait = 10 * warm
                print(f"  no response in {TIMEOUT}s (warming up) - retrying in "
                      f"{wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            except requests.RequestException as exc:
                raise SSError(f"Could not reach {url}: {exc}")

            if r.status_code == 429 and throttled < THROTTLE_RETRIES:
                throttled += 1
                wait = throttle_wait(r, throttled)
                print(f"  throttled by Secret Server (HTTP 429) - retry "
                      f"{throttled}/{THROTTLE_RETRIES} in {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            break

        if r.status_code != 200:
            raise SSError(f"{what} failed (HTTP {r.status_code}): " + {
                400: "bad credentials, or the account has 2FA (the password "
                     "grant cannot satisfy it), or the refresh token expired",
                404: "wrong base URL, or Enable Webservices is off",
                429: f"still throttled after {THROTTLE_RETRIES} retries",
            }.get(r.status_code, r.text[:200]))

        body = r.json()
        self.token = body["access_token"]
        # expires_in is a string in the spec; refresh_token is only issued when
        # the server allows it and the session timeout is not Unlimited.
        self.refresh_token = body.get("refresh_token")
        self.expires_at = time.time() + max(int(body.get("expires_in") or 1200) - 60, 30)

    def login(self):
        data = {"grant_type": "password", "username": self.user,
                "password": self._pw}
        # Optional. A domain login can also be expressed as DOMAIN\user.
        if self.domain:
            data["domain"] = self.domain
        self._token(data, "Token request")

    def _renew(self):
        if not self.refresh_token:
            return self.login()
        try:
            self._token({"grant_type": "refresh_token",
                         "refresh_token": self.refresh_token}, "Token refresh")
        except SSError:
            self.login()      # an aged-out refresh token 400s like a bad password

    # -- requests --------------------------------------------------------- #

    def get(self, path, **params):
        if not self.token:
            self.login()
        elif time.time() >= self.expires_at:
            self._renew()

        url = f"{self.base}/api/{path}"
        if self.throttle_delay_ms:
            time.sleep(self.throttle_delay_ms / 1000.0)

        # Two independent budgets. A refresh and a throttle are unrelated
        # failures, and sharing one counter meant a single 401 spent the only
        # retry.
        refreshed, throttled = False, 0
        while True:
            r = self.session.get(
                url, params=params, timeout=TIMEOUT,
                headers={"Authorization": f"Bearer {self.token}"})
            if r.status_code == 401 and not refreshed:
                # Token died before expires_at said it would - revoked, or the
                # server's session timeout is shorter than expires_in claimed.
                refreshed = True
                self._renew()
                continue
            if r.status_code == 429 and throttled < THROTTLE_RETRIES:
                throttled += 1
                wait = throttle_wait(r, throttled)
                print(f"  throttled by Secret Server (HTTP 429) - retry "
                      f"{throttled}/{THROTTLE_RETRIES} in {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
                continue
            break

        if r.status_code != 200:
            raise SSError({
                400: "refused - double lock, comment required, or check-out",
                401: "still unauthorized after a token refresh - the account "
                     "was disabled or its session revoked mid-scan",
                403: "no View permission for this account",
                404: "not found",
                429: f"still throttled after {THROTTLE_RETRIES} retries. Raise "
                     f"throttle_delay_ms to pace the sweep, or narrow it with "
                     f"--folder",
            }.get(r.status_code, f"HTTP {r.status_code}"), r.status_code)
        return r.json()

    def paged(self, path, **params):
        """Yield records across pages. Everything here is paged the same way."""
        skip = 0
        while True:
            page = self.get(path, take=100, skip=skip, **params)
            records = page.get("records") or []
            yield from records
            if not records or not page.get("hasNext"):
                return
            skip = page.get("nextSkip", skip + 100)

    # -- api -------------------------------------------------------------- #

    def folders(self, text=""):
        return list(self.paged("v1/folders", **{
            "filter.searchText": text,
            "filter.onlyIncludeRootFolders": "false",   # include nested folders
        }))

    def find_folder(self, name):
        """Resolve a name to one folder, refusing to guess when ambiguous."""
        leaf = name.replace("/", "\\").rstrip("\\").split("\\")[-1]
        found = self.folders(leaf)
        if not found:
            raise SSError(f"No folder matching {name!r} (or no View permission)")

        def norm(s):
            return (s or "").replace("/", "\\").strip("\\").lower()

        exact = [f for f in found if norm(f["folderName"]) == norm(leaf)]
        if "\\" in name or "/" in name:
            exact = [f for f in found if norm(f["folderPath"]) == norm(name)] or exact
        candidates = exact or found
        if len(candidates) > 1:
            listing = "\n".join(f"    {f['id']:<6} {f['folderPath']}" for f in candidates)
            raise SSError(f"{len(candidates)} folders match {name!r}:\n{listing}")
        return candidates[0]

    def secrets(self, folder_id=None):
        params = {}
        if folder_id is not None:
            params = {"filter.folderId": folder_id,
                      "filter.includeSubFolders": "true"}
        return self.paged("v2/secrets", **params)

    def secret(self, secret_id):
        # noAutoCheckout, or reading a checkout-required secret checks it out
        # under this account and locks it away from whoever needs it.
        return self.get(f"v2/secrets/{secret_id}", noAutoCheckout="true")


def enzoic_check(password, api_key, cache={}):
    """Return (verdict, exposure_count). Only a 10-char hash prefix is sent."""
    full = hashlib.sha256(password.encode()).hexdigest()
    if full in cache:
        return cache[full]

    result = ("Clean", 0)
    try:
        # The key is the RAW 32-hex value - not base64, not key:secret.
        r = requests.post(ENZOIC_URL, timeout=15,
                          headers={"Authorization": f"basic {api_key}"},
                          json={"partialSHA256": full[:10]})
        if r.status_code in (401, 403):
            raise SSError(f"Enzoic rejected the API key (HTTP {r.status_code}). "
                          "It must be the raw 32-hex key - not base64, not "
                          "key:secret.")
        if r.status_code == 200:
            for c in r.json().get("candidates") or []:
                if str(c.get("sha256", "")).lower() == full:
                    # revealedInExposure separates a real breach from
                    # known-weak-but-never-exposed.
                    result = ("Compromised" if c.get("revealedInExposure")
                              else "Weak", int(c.get("exposureCount") or 0))
                    break
        elif r.status_code != 404:          # 404 = prefix absent = clean
            result = ("CheckFailed", 0)
    except requests.RequestException:
        result = ("CheckFailed", 0)         # inconclusive is NOT clean

    cache[full] = result
    return result


# --- reports -------------------------------------------------------------- #

def new_report_path(directory, scope):
    """A new dated file per run, never an overwrite. The stamp is
    yyyymmdd-HHMMSS so the files sort chronologically by name."""
    os.makedirs(directory, exist_ok=True)

    slug = re.sub(r"[^\w\-]+", "-", scope or "all").strip("-").lower() or "scan"
    slug = slug[:40]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(directory, f"enzoic-scan-{slug}-{stamp}.csv")

    # Two runs inside the same second would otherwise collide.
    n = 1
    while os.path.exists(path):
        path = os.path.join(directory, f"enzoic-scan-{slug}-{stamp}-{n}.csv")
        n += 1
    return path


def prune_reports(directory, retain):
    """Optional retention, so a nightly scheduled task does not fill the disk.
    Newest N survive; ordered by write time, not by name, in case the scope
    slug changes between runs."""
    if retain <= 0 or not os.path.isdir(directory):
        return 0
    files = [os.path.join(directory, f) for f in os.listdir(directory)
             if f.startswith("enzoic-scan-") and f.endswith(".csv")]
    files = [f for f in files if os.path.isfile(f)]
    files.sort(key=os.path.getmtime, reverse=True)
    for stale in files[retain:]:
        os.remove(stale)
    pruned = max(0, len(files) - retain)
    if pruned:
        print(f"Pruned {pruned} report(s), keeping the newest {retain}.",
              file=sys.stderr)
    return pruned


def write_report(rows, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=REPORT_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


# --- cli ------------------------------------------------------------------ #

def build_parser():
    p = argparse.ArgumentParser(
        prog="enzoic-delinea",
        description="Sweep Delinea Secret Server and check every password "
                    "against Enzoic. Read-only.")
    p.add_argument("--config", metavar="PATH",
                   help="config file (.toml or .json); found automatically next "
                        "to the package, then in the working directory")
    p.add_argument("--folder", action="append", metavar="NAME",
                   help="folder name or full path; repeat for several. "
                        "Subfolders are always included")
    p.add_argument("--all", action="store_true", help="every folder")
    p.add_argument("--list-folders", action="store_true",
                   help="list the folders this account can see and stop")
    p.add_argument("--reveal", action="store_true",
                   help="print passwords in the console table and in --json")
    p.add_argument("--csv", metavar="PATH",
                   help="one fixed path, overwritten each run (no passwords)")
    p.add_argument("--report-directory", metavar="DIR",
                   help="a new dated CSV per run, never overwritten")
    p.add_argument("--retain-reports", type=int, metavar="N",
                   help="keep only the newest N dated reports; 0 keeps all")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="emit the rows as JSON on stdout instead of a table")
    p.add_argument("--throttle-delay-ms", type=int, metavar="MS",
                   help="pause between API calls; only needed against a cloud "
                        "tenant that throttles harder than the backoff absorbs")
    p.add_argument("--insecure", action="store_true", help="skip TLS checks")
    p.add_argument("--base-url", metavar="URL")
    p.add_argument("--username", metavar="NAME")
    p.add_argument("--password", metavar="VALUE")
    p.add_argument("--domain", metavar="NAME",
                   help="Secret Server domain; DOMAIN\\user in --username works too")
    p.add_argument("--enzoic-api-key", metavar="KEY")
    p.add_argument("--protect-secret", action="store_true",
                   help="print a DPAPI blob for the config file (Windows)")
    p.add_argument("--machine-scope", action="store_true",
                   help="with --protect-secret: bind to the computer, not the user")
    return p


def as_list(value):
    """Config `folder` accepts a string or a list; the CLI accepts repeats."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)] if str(value).strip() else []


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        # Before anything else: this mode needs no config and no server.
        if args.protect_secret:
            return protect_secret(machine=args.machine_scope)
        if args.machine_scope:
            print("WARNING: --machine-scope only applies with --protect-secret; "
                  "ignoring it.", file=sys.stderr)

        env = load_env()
        if env:
            print(f"Loaded env from {env}", file=sys.stderr)
        cfg, cfg_path = load_config(args.config)
        if cfg_path:
            print(f"Config: {cfg_path}", file=sys.stderr)

        base = setting("BaseUrl", args.base_url, "SS_BASE_URL", cfg)
        user = setting("Username", args.username, "SS_USERNAME", cfg)
        pw = setting("Password", args.password, "SS_PASSWORD", cfg, secret=True)
        domain = setting("Domain", args.domain, "SS_DOMAIN", cfg)
        key = setting("EnzoicApiKey", args.enzoic_api_key, "ENZOIC_API_KEY",
                      cfg, secret=True)
        report_dir = setting("ReportDirectory", args.report_directory, None, cfg)
        csv_path = setting("Csv", args.csv, None, cfg)
        retain = int(setting("RetainReports", args.retain_reports, None, cfg, 0) or 0)
        delay_ms = int(setting("ThrottleDelayMs", args.throttle_delay_ms, None,
                               cfg, 0) or 0)
        scan_all = bool(args.all or setting("All", None, None, cfg, False))
        reveal = bool(args.reveal or setting("Reveal", None, None, cfg, False))
        insecure = bool(args.insecure or setting("Insecure", None, None, cfg, False))
        folders = as_list(args.folder) or as_list(cfg.get(_norm("Folder")))

        base = base or input("Base URL (https://host/SecretServer): ")
        user = user or input("Username: ")
        pw = pw or getpass.getpass(f"Password for {user}: ")

        ss = SecretServer(base, user, pw, verify=not insecure, domain=domain,
                          throttle_delay_ms=delay_ms)
        ss.login()
        print(f"Authenticated to {ss.base} as {user}", file=sys.stderr)

        if not key:
            print("WARNING: no Enzoic API key configured - secrets will be "
                  "listed but NOT checked.", file=sys.stderr)

        # -- folder listing mode ------------------------------------------ #
        if args.list_folders or (not scan_all and not folders):
            visible = ss.folders()
            for f in sorted(visible, key=lambda f: f.get("folderPath") or ""):
                print(f"{f['id']:<8} {f.get('folderPath', '')}")
            print(f"\n{len(visible)} folder(s). Sweep with --folder NAME or --all."
                  if visible else
                  "\nNo folders visible - this account needs View permission.",
                  file=sys.stderr)
            return 0

        # -- collect the secrets in scope ---------------------------------- #
        summaries, scope_name = [], "all"
        if scan_all:
            print("Scope: all folders", file=sys.stderr)
            summaries = list(ss.secrets())
        else:
            seen, names = set(), []
            for name in folders:
                f = ss.find_folder(name)
                path = f.get("folderPath") or name
                print(f"Scope: {path} (id {f['id']}, incl. subfolders)",
                      file=sys.stderr)
                names.append(path.replace("/", "\\").rstrip("\\").split("\\")[-1])
                for s in ss.secrets(f["id"]):
                    # Overlapping folder entries would otherwise double-count.
                    if s["id"] not in seen:
                        seen.add(s["id"])
                        summaries.append(s)
            scope_name = "-".join(names)

        print(f"Scanning {len(summaries)} secret(s)", file=sys.stderr)

        # -- read and check ------------------------------------------------ #
        rows = []
        total = len(summaries)
        # The PowerShell port uses Write-Progress. Only on a terminal: a
        # redirected log does not want a carriage return per secret.
        progress = total > 1 and sys.stderr.isatty()
        for n, s in enumerate(summaries, 1):
            if progress:
                print(f"\r  {n} of {total}: {s.get('name', s['id'])[:50]:<50}",
                      end="", file=sys.stderr, flush=True)
            row = {"id": s["id"], "folder": s.get("folderPath", ""),
                   "name": s["name"], "username": "", "password": None,
                   "verdict": "", "exposures": 0, "note": ""}
            if s.get("checkOutEnabled"):
                row["note"] = "requires check-out - skipped"
            else:
                try:
                    for item in ss.secret(s["id"])["items"]:
                        if item.get("slug") == "username":
                            row["username"] = item.get("itemValue") or ""
                        elif item.get("isPassword") and not item.get("isFile"):
                            row["password"] = item.get("itemValue")
                except SSError as err:
                    row["note"] = str(err)
            if key and row["password"]:
                row["verdict"], row["exposures"] = enzoic_check(row["password"], key)
            rows.append(row)
        if progress:
            print("\r" + " " * 60 + "\r", end="", file=sys.stderr, flush=True)
    except SSError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    # -- output ------------------------------------------------------------ #
    def shown(row):
        if not row["password"]:
            return ""
        return row["password"] if reveal else f"<{len(row['password'])} chars>"

    if args.as_json:
        # Follows --reveal exactly as the console table does. PowerShell's
        # -PassThru hands objects to a live shell; stdout here is far more
        # likely to be redirected into a file, so the default is masked.
        print(json.dumps([dict(r, password=shown(r)) for r in rows], indent=2))
    elif rows:
        fw = max([len(r["folder"]) for r in rows] + [6])
        nw = max([len(r["name"]) for r in rows] + [4])
        for r in rows:
            line = (f"{r['id']:>6}  {r['folder']:<{fw}}  {r['name']:<{nw}}  "
                    f"{r['username']:<24}  {shown(r)}")
            if r["verdict"]:
                line += f"  [{r['verdict']}]"
            if r["exposures"]:
                line += f"  {r['exposures']:,} exposures"
            if r["note"]:
                line += f"  ({r['note']})"
            print(line)
    else:
        print("WARNING: zero secrets in scope. The API returns only what this "
              "account has View on, and no-permission is indistinguishable from "
              "empty - check BOTH grants on the folder Sharing tab: Folder "
              "Permissions = View AND Secret Permissions = View.",
              file=sys.stderr)

    if report_dir:
        dated = new_report_path(report_dir, scope_name)
        write_report(rows, dated)
        print(f"Report: {dated}", file=sys.stderr)
        prune_reports(report_dir, retain)

    if csv_path:
        write_report(rows, csv_path)
        print(f"CSV: {csv_path}", file=sys.stderr)

    if key and rows:
        counts = {}
        for r in rows:
            counts[r["verdict"] or "-"] = counts.get(r["verdict"] or "-", 0) + 1
        print("", *[f"  {v:<12} {n}" for v, n in sorted(counts.items())],
              sep="\n", file=sys.stderr)
        if counts.get("CheckFailed"):
            print("  CheckFailed is NOT Clean - re-run those.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
