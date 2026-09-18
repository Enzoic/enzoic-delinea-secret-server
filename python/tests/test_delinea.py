"""Offline tests: the whole client against a fake Secret Server. No VM needed."""
import contextlib, io, json, os, sys, tempfile, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from enzoic_delinea import delinea as ds

FAILURES = 0


def t(name, fn):
    global FAILURES
    try:
        fn()
        print(f"  PASS  {name}")
    except BaseException as e:                 # SystemExit too - argparse exits
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")
        FAILURES += 1


class Resp:
    def __init__(self, status, payload, headers=None):
        self.status_code, self._payload = status, payload
        self.headers = headers or {}
        self.text = json.dumps(payload)
    def json(self):
        return self._payload


FOLDERS = [
    {"id": 3, "folderName": "Service Accounts", "folderPath": "\\Service Accounts"},
    {"id": 9, "folderName": "Service Accounts", "folderPath": "\\Acme\\Service Accounts"},
    {"id": 4, "folderName": "Lab", "folderPath": "\\Lab"},
    {"id": 11, "folderName": "Nested", "folderPath": "\\Lab\\Nested"},
]
SECRETS = [
    {"id": 1, "name": "svc_backup", "folderPath": "\\Lab", "checkOutEnabled": False},
    {"id": 2, "name": "svc_sql", "folderPath": "\\Lab\\Nested", "checkOutEnabled": False},
    {"id": 3, "name": "locked", "folderPath": "\\Lab", "checkOutEnabled": True},
    {"id": 4, "name": "no_perm", "folderPath": "\\Lab", "checkOutEnabled": False},
]
PASSWORDS = {1: "Password1", 2: "long-unique-9481"}


class FakeSS:
    """Pages at 2 so the paging path is always exercised."""
    def __init__(self):
        self.grants, self.n, self.verify = [], 0, True

    def post(self, url, data=None, timeout=None, **kw):
        assert url.endswith("/oauth2/token"), url
        self.grants.append(data["grant_type"])
        if data["grant_type"] == "password" and data.get("password") != "correct":
            return Resp(400, {"error": "invalid_grant"})
        if data["grant_type"] == "refresh_token" and data["refresh_token"] != "RT1":
            return Resp(400, {"error": "invalid_grant"})
        self.n += 1
        return Resp(200, {"access_token": f"AT{self.n}", "refresh_token": "RT1",
                          "token_type": "bearer", "expires_in": "2"})

    def _page(self, rows, params):
        skip = params.get("skip", 0)
        return Resp(200, {"records": rows[skip:skip + 2], "total": len(rows),
                          "hasNext": skip + 2 < len(rows), "nextSkip": skip + 2})

    def get(self, url, params=None, headers=None, timeout=None, **kw):
        assert headers["Authorization"].startswith("Bearer AT"), headers
        p = params or {}
        if url.endswith("/api/v1/folders"):
            assert p.get("filter.onlyIncludeRootFolders") == "false", \
                "folder search must not be restricted to root folders"
            txt = (p.get("filter.searchText") or "").lower()
            return self._page([f for f in FOLDERS
                               if txt in f["folderName"].lower()], p)
        if url.endswith("/api/v2/secrets"):
            if "filter.folderId" in p:
                assert p["filter.includeSubFolders"] == "true"
                return self._page([s for s in SECRETS
                                   if s["folderPath"].startswith("\\Lab")], p)
            return self._page(SECRETS, p)                 # --all: no filter
        if "/api/v2/secrets/" in url:
            sid = int(url.rsplit("/", 1)[1])
            assert p.get("noAutoCheckout") == "true", "must not auto-check-out"
            if sid not in PASSWORDS:
                return Resp(403, {"message": "no view"})
            return Resp(200, {"id": sid, "items": [
                {"slug": "username", "isPassword": False, "itemValue": f"u{sid}"},
                {"slug": "password", "isPassword": True, "itemValue": PASSWORDS[sid]},
            ]})
        raise AssertionError("unexpected GET " + url)


def client(fake=None):
    fake = fake or FakeSS()
    c = ds.SecretServer("https://ss.example.com/SecretServer", "u", "correct")
    c.session = fake
    return c


print("auth")

def test_login():
    c = client(); c.login()
    assert c.token == "AT1" and c.refresh_token == "RT1"
t("password grant sets the token", test_login)

def test_bad_creds():
    c = ds.SecretServer("https://x/SecretServer", "u", "wrong"); c.session = FakeSS()
    try:
        c.login()
    except ds.SSError as e:
        assert "2FA" in str(e), e
        return
    raise AssertionError("expected SSError")
t("bad credentials name 2FA as a cause", test_bad_creds)

def test_refresh():
    f = FakeSS(); c = client(f); c.login()
    c.expires_at = 0
    c.folders("Lab")
    assert f.grants == ["password", "refresh_token"], f.grants
t("expired token refreshes", test_refresh)

def test_no_refresh_token():
    f = FakeSS(); c = client(f); c.login()
    c.refresh_token, c.expires_at = None, 0
    c.folders("Lab")
    assert f.grants == ["password", "password"], f.grants
t("no refresh token falls back to the password grant", test_no_refresh_token)

def test_stale_refresh_token():
    f = FakeSS(); c = client(f); c.login()
    c.refresh_token, c.expires_at = "STALE", 0
    c.folders("Lab")
    assert f.grants == ["password", "refresh_token", "password"], f.grants
t("aged-out refresh token re-authenticates", test_stale_refresh_token)

def test_read_timeout_retries():
    f, calls, slept = FakeSS(), [], []
    real = f.post
    def flaky(url, **kw):
        calls.append(1)
        if len(calls) < 3:
            raise ds.requests.exceptions.ReadTimeout("timed out")
        return real(url, **kw)
    f.post = flaky
    c = client(f)
    real_sleep, ds.time.sleep = ds.time.sleep, lambda s: slept.append(s)
    try:
        c.login()
    finally:
        ds.time.sleep = real_sleep
    assert c.token and len(calls) == 3 and slept == [10, 20], (calls, slept)
t("read timeout retries with backoff (cold-starting server)", test_read_timeout_retries)

def test_read_timeout_gives_up_clearly():
    f = FakeSS()
    f.post = lambda url, **kw: (_ for _ in ()).throw(
        ds.requests.exceptions.ReadTimeout("x"))
    c = client(f)
    real_sleep, ds.time.sleep = ds.time.sleep, lambda s: None
    try:
        c.login()
    except ds.SSError as e:
        assert "not the network" in str(e), e
        return
    finally:
        ds.time.sleep = real_sleep
    raise AssertionError("expected SSError")
t("exhausted timeout blames the app, not the network", test_read_timeout_gives_up_clearly)

print("folders")

def test_folders_paged_and_nested():
    got = client().folders()
    assert len(got) == 4, got
    assert "\\Lab\\Nested" in [f["folderPath"] for f in got]
t("lists nested folders across pages", test_folders_paged_and_nested)

def test_find_unique():
    assert client().find_folder("Lab")["id"] == 4
t("unique name resolves", test_find_unique)

def test_find_ambiguous():
    try:
        client().find_folder("Service Accounts")
    except ds.SSError as e:
        assert "2 folders match" in str(e), e
        return
    raise AssertionError("should refuse to guess")
t("ambiguous name refuses to guess", test_find_ambiguous)

def test_find_by_path():
    assert client().find_folder("\\Acme\\Service Accounts")["id"] == 9
t("full path disambiguates", test_find_by_path)

def test_find_missing():
    try:
        client().find_folder("Nope")
    except ds.SSError as e:
        assert "View permission" in str(e), e
        return
    raise AssertionError("expected SSError")
t("missing folder mentions permissions", test_find_missing)

print("secrets")

def test_all_secrets():
    assert [s["id"] for s in client().secrets()] == [1, 2, 3, 4]
t("--all pages every secret with no folder filter", test_all_secrets)

def test_folder_secrets():
    assert [s["id"] for s in client().secrets(4)] == [1, 2, 3, 4]
t("folder sweep sends includeSubFolders", test_folder_secrets)

def test_403_is_an_error():
    try:
        client().secret(4)
    except ds.SSError as e:
        assert e.status == 403 and "View permission" in str(e), e
        return
    raise AssertionError("expected SSError")
t("403 explains the missing permission", test_403_is_an_error)

print("enzoic")

def post_stub(resp, seen=None):
    def fake(url, timeout=None, headers=None, json=None):
        if seen is not None:
            seen.update(url=url, headers=headers, body=json)
        return resp
    return fake

def with_post(stub, fn):
    real, ds.requests.post = ds.requests.post, stub
    try:
        return fn()
    finally:
        ds.requests.post = real

def test_wire_format():
    seen = {}
    out = with_post(post_stub(Resp(404, {}), seen),
                    lambda: ds.enzoic_check("hunter2", "a" * 32, cache={}))
    full = ds.hashlib.sha256(b"hunter2").hexdigest()
    assert seen["url"] == "https://api.enzoic.com/v1/passwords"
    assert seen["headers"]["Authorization"] == "basic " + "a" * 32   # raw key
    assert seen["body"] == {"partialSHA256": full[:10]}              # 10 chars only
    assert out == ("Clean", 0)                                       # 404 = clean
t("sends a 10-char prefix with the raw key; 404 means clean", test_wire_format)

def test_compromised():
    full = ds.hashlib.sha256(b"Password1").hexdigest()
    r = Resp(200, {"candidates": [
        {"sha256": "0" * 64, "revealedInExposure": True, "exposureCount": 1},
        {"sha256": full.upper(), "revealedInExposure": True, "exposureCount": 2647331}]})
    out = with_post(post_stub(r), lambda: ds.enzoic_check("Password1", "k", cache={}))
    assert out == ("Compromised", 2647331), out
t("matches the full hash, case-insensitively", test_compromised)

def test_weak_not_compromised():
    full = ds.hashlib.sha256(b"Tr0ub4dor").hexdigest()
    r = Resp(200, {"candidates": [{"sha256": full, "revealedInExposure": False,
                                   "exposureCount": 0}]})
    out = with_post(post_stub(r), lambda: ds.enzoic_check("Tr0ub4dor", "k", cache={}))
    assert out[0] == "Weak", out
t("revealedInExposure false is Weak, not Compromised", test_weak_not_compromised)

def test_error_is_not_clean():
    out = with_post(post_stub(Resp(500, {})),
                    lambda: ds.enzoic_check("x", "k", cache={}))
    assert out[0] == "CheckFailed", out
t("a failed check is never reported as Clean", test_error_is_not_clean)

def test_bad_key():
    try:
        with_post(post_stub(Resp(401, {})),
                  lambda: ds.enzoic_check("x", "k", cache={}))
    except ds.SSError as e:
        assert "raw 32-hex" in str(e), e
        return
    raise AssertionError("expected SSError")
t("401 names the key format", test_bad_key)

def test_cache():
    calls = []
    def counting(url, **kw):
        calls.append(1)
        return Resp(404, {})
    shared = {}
    with_post(counting, lambda: [ds.enzoic_check("same", "k", cache=shared)
                                 for _ in range(5)])
    assert len(calls) == 1, calls
t("a reused password costs one API call", test_cache)

print(".env")

def write_env(body):
    fh = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False, encoding="utf-8")
    fh.write(body); fh.close()
    return fh.name

def test_env_parsing():
    path = write_env('# c\n\nexport SS_USERNAME=svc\nSS_PASSWORD="p@ss word#1"\nJUNK\n')
    for k in ("SS_USERNAME", "SS_PASSWORD"):
        os.environ.pop(k, None)
    ds.load_env(path)
    assert os.environ["SS_USERNAME"] == "svc"          # 'export ' stripped
    assert os.environ["SS_PASSWORD"] == "p@ss word#1"  # '#' inside quotes kept
    for k in ("SS_USERNAME", "SS_PASSWORD"):
        os.environ.pop(k, None)
t("handles comments, export, quotes and '#' in values", test_env_parsing)

def test_env_does_not_override():
    path = write_env("SS_USERNAME=from_file\n")
    os.environ["SS_USERNAME"] = "from_shell"
    ds.load_env(path)
    assert os.environ["SS_USERNAME"] == "from_shell"
    os.environ.pop("SS_USERNAME", None)
t("a real environment variable beats the file", test_env_does_not_override)

print("end to end")

SS_VARS = ("SS_BASE_URL", "SS_USERNAME", "SS_PASSWORD", "ENZOIC_API_KEY")

def run_main(args, enzoic_key=None):
    """Isolated from the operator's real .env - it once tried to call the
    live Enzoic API with a real key during a unit test run."""
    fake = FakeSS()
    saved = {k: os.environ.pop(k, None) for k in SS_VARS}
    os.environ.update(SS_BASE_URL="https://ss.example.com/SecretServer",
                      SS_USERNAME="u", SS_PASSWORD="correct")
    if enzoic_key:
        os.environ["ENZOIC_API_KEY"] = enzoic_key
    real_env, ds.load_env = ds.load_env, lambda *a, **k: None
    real_sess, ds.requests.Session = ds.requests.Session, lambda: fake
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = ds.main(args)
    finally:
        ds.load_env, ds.requests.Session = real_env, real_sess
        for k in SS_VARS:
            os.environ.pop(k, None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
    return rc, buf.getvalue()

def test_default_lists_folders():
    rc, out = run_main([])
    assert rc == 0 and "\\Lab\\Nested" in out, out
    assert len(out.strip().splitlines()) == 4, out
t("no arguments lists every folder", test_default_lists_folders)

def test_sweep_all():
    rc, out = run_main(["--all", "--reveal"])
    assert rc == 0, rc
    assert "Password1" in out and "long-unique-9481" in out, out
    assert "requires check-out" in out, out          # id 3 skipped, not read
    assert "View permission" in out, out             # id 4 403, reported
    assert len(out.strip().splitlines()) == 4, out
t("--all reads, skips check-out, and reports the 403", test_sweep_all)

def test_masked_by_default():
    rc, out = run_main(["--all"])
    assert "Password1" not in out and "<9 chars>" in out, out
t("passwords are masked without --reveal", test_masked_by_default)

def test_enzoic_in_sweep():
    rc, out = with_post(post_stub(Resp(404, {})),
                        lambda: run_main(["--all"], enzoic_key="a" * 32))
    assert "[Clean]" in out, out
t("a key in the environment turns the check on", test_enzoic_in_sweep)

def test_csv_has_no_passwords():
    path = tempfile.mktemp(suffix=".csv")
    run_main(["--all", "--reveal", "--csv", path])
    body = open(path, encoding="utf-8").read()
    os.unlink(path)
    assert "svc_backup" in body and "Password1" not in body, body
t("the CSV never contains passwords", test_csv_has_no_passwords)

print("config file")

def write_cfg(body, suffix=".toml"):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                     encoding="utf-8")
    fh.write(body); fh.close()
    return fh.name

def test_toml_config():
    path = write_cfg('base_url = "https://a/SecretServer"\nretain_reports = 7\n')
    cfg, resolved = ds.load_config(path)
    os.unlink(path)
    assert cfg["baseurl"] == "https://a/SecretServer", cfg
    assert cfg["retainreports"] == 7, cfg
    assert os.path.isabs(resolved), resolved
t("a .toml config loads", test_toml_config)

def test_json_config():
    path = write_cfg('{"BaseUrl": "https://b/SecretServer"}', ".json")
    cfg, _ = ds.load_config(path)
    os.unlink(path)
    assert cfg["baseurl"] == "https://b/SecretServer", cfg
t("a .json config loads", test_json_config)

def test_key_names_are_normalised():
    path = write_cfg('BaseUrl = "x"\nRetainReports = 3\nThrottleDelayMs = 50\n')
    cfg, _ = ds.load_config(path)
    os.unlink(path)
    # PascalCase is what the PowerShell .psd1 uses. One set of key names has to
    # describe both implementations or "parity" is a documentation claim only.
    assert ds.setting("base_url", None, None, cfg) == "x", cfg
    assert ds.setting("throttle-delay-ms", None, None, cfg) == 50, cfg
t("BaseUrl, base_url and base-url are the same key", test_key_names_are_normalised)

def test_missing_config_is_an_error():
    try:
        ds.load_config(os.path.join(tempfile.gettempdir(), "nope-9182.toml"))
    except ds.SSError as e:
        assert "Config file not found" in str(e), e
        return
    raise AssertionError("expected SSError")
t("an explicit --config that does not exist is an error", test_missing_config_is_an_error)

def test_no_config_is_not_an_error():
    cfg, path = ds.load_config(None)
    assert isinstance(cfg, dict) and path is None or path, (cfg, path)
t("no config file at all is fine", test_no_config_is_not_an_error)

def test_precedence():
    cfg = {"username": "from_config"}
    os.environ.pop("SS_USERNAME", None)
    assert ds.setting("Username", None, "SS_USERNAME", cfg) == "from_config"
    os.environ["SS_USERNAME"] = "from_env"
    assert ds.setting("Username", None, "SS_USERNAME", cfg) == "from_env"
    assert ds.setting("Username", "from_cli", "SS_USERNAME", cfg) == "from_cli"
    os.environ.pop("SS_USERNAME", None)
t("argument beats environment beats config file", test_precedence)

def test_encrypted_key_is_consulted():
    seen = []
    real, ds.dpapi_unprotect = ds.dpapi_unprotect, lambda b: seen.append(b) or "decrypted"
    try:
        out = ds.setting("Password", None, None,
                         {"passwordencrypted": "ABCD"}, secret=True)
    finally:
        ds.dpapi_unprotect = real
    assert out == "decrypted" and seen == ["ABCD"], (out, seen)
t("a blank password falls back to password_encrypted", test_encrypted_key_is_consulted)

def test_plaintext_wins_over_encrypted():
    calls = []
    real, ds.dpapi_unprotect = ds.dpapi_unprotect, lambda b: calls.append(b)
    try:
        out = ds.setting("Password", None, None,
                         {"password": "plain", "passwordencrypted": "ABCD"},
                         secret=True)
    finally:
        ds.dpapi_unprotect = real
    assert out == "plain" and not calls, (out, calls)
t("a plaintext value is not overridden by an encrypted one", test_plaintext_wins_over_encrypted)

def test_as_list():
    assert ds.as_list(None) == [] and ds.as_list("") == []
    assert ds.as_list("Finance") == ["Finance"]
    assert ds.as_list(["A", "B"]) == ["A", "B"]
    assert ds.as_list(["A", "  ", ""]) == ["A"]
t("folder accepts a string, a list, or nothing", test_as_list)

print("domain")

def test_domain_is_sent():
    f = FakeSS(); sent = []
    real = f.post
    def spy(url, data=None, **kw):
        sent.append(dict(data)); return real(url, data=data, **kw)
    f.post = spy
    c = ds.SecretServer("https://ss.example.com/SecretServer", "u", "correct",
                        domain="example.com")
    c.session = f
    c.login()
    assert sent[0].get("domain") == "example.com", sent
t("Domain is sent as a form field on the password grant", test_domain_is_sent)

def test_domain_absent_when_unset():
    f = FakeSS(); sent = []
    real = f.post
    def spy(url, data=None, **kw):
        sent.append(dict(data)); return real(url, data=data, **kw)
    f.post = spy
    client(f).login()
    assert "domain" not in sent[0], sent
t("no Domain means no domain field at all", test_domain_absent_when_unset)

print("throttling")

def test_retry_after_seconds():
    assert ds.retry_after_seconds(Resp(429, {}, {"Retry-After": "12"})) == 12
t("Retry-After as a delta in seconds", test_retry_after_seconds)

def test_retry_after_http_date():
    when = ds._dt.datetime.now(ds._dt.timezone.utc) + ds._dt.timedelta(seconds=30)
    stamp = when.strftime("%a, %d %b %Y %H:%M:%S GMT")
    got = ds.retry_after_seconds(Resp(429, {}, {"Retry-After": stamp}))
    assert 25 <= got <= 31, got
t("Retry-After as an HTTP-date", test_retry_after_http_date)

def test_retry_after_past_and_garbage():
    assert ds.retry_after_seconds(Resp(429, {}, {"Retry-After": "Tue, 01 Jan 1980 00:00:00 GMT"})) == 0
    assert ds.retry_after_seconds(Resp(429, {}, {"Retry-After": "soon"})) == 0
    assert ds.retry_after_seconds(Resp(429, {}, {})) == 0
    assert ds.retry_after_seconds(Resp(429, {}, {"Retry-After": "-5"})) == 0
t("an unusable Retry-After is 0, not a crash", test_retry_after_past_and_garbage)

def test_throttle_wait_backoff_and_cap():
    assert [ds.throttle_wait(Resp(429, {}, {}), n) for n in (1, 2, 3)] == [2, 4, 8]
    # A hostile header must not park the scan for an hour.
    assert ds.throttle_wait(Resp(429, {}, {"Retry-After": "99999"}), 1) == ds.THROTTLE_MAX_WAIT
    assert ds.throttle_wait(Resp(429, {}, {}), 99) == ds.THROTTLE_MAX_WAIT
t("backoff is exponential and capped", test_throttle_wait_backoff_and_cap)

def no_sleep(fn):
    real, ds.time.sleep = ds.time.sleep, lambda s: slept.append(s)
    try:
        return fn()
    finally:
        ds.time.sleep = real

def test_429_retries_then_succeeds():
    global slept
    slept = []
    f = FakeSS(); c = client(f); c.login()
    real, n = f.get, []
    def throttled(url, **kw):
        n.append(1)
        if len(n) <= 2:
            return Resp(429, {}, {"Retry-After": "3"})
        return real(url, **kw)
    f.get = throttled
    out = no_sleep(lambda: c.folders("Lab"))
    assert len(out) == 1 and slept == [3, 3], (out, slept)
t("a 429 backs off and retries, honouring Retry-After", test_429_retries_then_succeeds)

def test_429_gives_up_with_advice():
    global slept
    slept = []
    f = FakeSS(); c = client(f); c.login()
    f.get = lambda url, **kw: Resp(429, {}, {})
    try:
        no_sleep(lambda: c.folders("Lab"))
    except ds.SSError as e:
        assert e.status == 429 and "throttle_delay_ms" in str(e), e
        assert len(slept) == ds.THROTTLE_RETRIES, slept
        return
    raise AssertionError("expected SSError")
t("exhausted throttle retries name the fix", test_429_gives_up_with_advice)

def test_401_and_429_budgets_are_separate():
    global slept
    slept = []
    f = FakeSS(); c = client(f); c.login()
    real, seq = f.get, []
    def flaky(url, **kw):
        seq.append(1)
        if len(seq) == 1:
            return Resp(401, {})
        if len(seq) == 2:
            return Resp(429, {}, {"Retry-After": "1"})
        return real(url, **kw)
    f.get = flaky
    out = no_sleep(lambda: c.folders("Lab"))
    # Sharing one counter meant a single 401 spent the only throttle retry.
    assert len(out) == 1 and slept == [1], (out, slept)
    assert f.grants == ["password", "refresh_token"], f.grants
t("a 401 does not spend the throttle budget", test_401_and_429_budgets_are_separate)

def test_throttle_delay_paces_requests():
    global slept
    slept = []
    f = FakeSS()
    c = ds.SecretServer("https://ss.example.com/SecretServer", "u", "correct",
                        throttle_delay_ms=250)
    c.session = f
    c.login()
    no_sleep(lambda: c.folders("Lab"))
    assert slept == [0.25], slept          # one paged GET
t("throttle_delay_ms paces every request", test_throttle_delay_paces_requests)

def test_throttle_delay_is_clamped():
    c = ds.SecretServer("https://x/SecretServer", "u", "p", throttle_delay_ms=999999)
    assert c.throttle_delay_ms == 10000, c.throttle_delay_ms
    c = ds.SecretServer("https://x/SecretServer", "u", "p", throttle_delay_ms=-5)
    assert c.throttle_delay_ms == 0, c.throttle_delay_ms
t("throttle_delay_ms is clamped to a sane range", test_throttle_delay_is_clamped)

print("reports")

def test_report_name_shape():
    d = tempfile.mkdtemp()
    path = ds.new_report_path(os.path.join(d, "made", "on", "demand"), "Service Accounts")
    assert os.path.isdir(os.path.dirname(path)), path
    name = os.path.basename(path)
    assert name.startswith("enzoic-scan-service-accounts-"), name
    assert name.endswith(".csv") and len(name.split("-")[-2]) == 8, name
t("a dated report is slugged and the directory is created", test_report_name_shape)

def test_report_never_overwrites():
    d = tempfile.mkdtemp()
    a = ds.new_report_path(d, "lab"); open(a, "w").close()
    b = ds.new_report_path(d, "lab"); open(b, "w").close()
    assert a != b, (a, b)                   # two runs inside the same second
t("two runs in the same second do not collide", test_report_never_overwrites)

def test_retention_keeps_newest():
    d = tempfile.mkdtemp()
    made = []
    for i in range(5):
        p = os.path.join(d, f"enzoic-scan-lab-2026010{i}-000000.csv")
        open(p, "w").close()
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
        made.append(p)
    open(os.path.join(d, "unrelated.csv"), "w").close()
    ds.prune_reports(d, 2)
    left = sorted(os.listdir(d))
    assert left == ["enzoic-scan-lab-20260103-000000.csv",
                    "enzoic-scan-lab-20260104-000000.csv",
                    "unrelated.csv"], left
t("retention keeps the newest N and leaves other files alone", test_retention_keeps_newest)

def test_retention_zero_keeps_everything():
    d = tempfile.mkdtemp()
    for i in range(3):
        open(os.path.join(d, f"enzoic-scan-lab-2026010{i}-000000.csv"), "w").close()
    ds.prune_reports(d, 0)
    assert len(os.listdir(d)) == 3, os.listdir(d)
t("retention 0 keeps everything", test_retention_zero_keeps_everything)

print("end to end, part two")

def test_list_folders_flag():
    rc, out = run_main(["--list-folders"])
    assert rc == 0 and "\\Lab\\Nested" in out, out
t("--list-folders lists and stops", test_list_folders_flag)

def test_folder_list_dedups():
    # Both names resolve to folders whose sweep returns the same four secrets.
    rc, out = run_main(["--folder", "Lab", "--folder", "Nested"])
    ids = [line.split()[0] for line in out.strip().splitlines()]
    assert ids == ["1", "2", "3", "4"], ids     # not eight rows
t("overlapping folders are swept once, not twice", test_folder_list_dedups)

def test_json_masks_by_default():
    rc, out = run_main(["--all", "--json"])
    rows = json.loads(out)
    assert rc == 0 and len(rows) == 4, rows
    assert rows[0]["password"] == "<9 chars>", rows[0]
    assert "Password1" not in out, out
t("--json masks passwords without --reveal", test_json_masks_by_default)

def test_json_reveals_on_request():
    rc, out = run_main(["--all", "--json", "--reveal"])
    rows = json.loads(out)
    assert rows[0]["password"] == "Password1", rows[0]
t("--json --reveal prints them", test_json_reveals_on_request)

def test_dated_report_written_and_pruned():
    d = tempfile.mkdtemp()
    for i in range(2):
        rc, out = run_main(["--all", "--reveal",
                            "--report-directory", d, "--retain-reports", "1"])
        assert rc == 0, out
    files = os.listdir(d)
    assert len(files) == 1, files
    body = open(os.path.join(d, files[0]), encoding="utf-8").read()
    assert "svc_backup" in body and "Password1" not in body, body
t("a dated report is written, pruned, and holds no passwords", test_dated_report_written_and_pruned)

def test_config_file_drives_a_run():
    d = tempfile.mkdtemp()
    cfg = os.path.join(d, "enzoic-delinea.config.toml")
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write('all = true\nreveal = true\n')
    rc, out = run_main(["--config", cfg])
    assert rc == 0 and "Password1" in out, out
t("all and reveal can come from the config file", test_config_file_drives_a_run)

print("dpapi")

if os.name != "nt":
    print("  SKIP  DPAPI is Windows-only")
else:
    def test_dpapi_round_trip_user():
        blob = ds.dpapi_protect("p@ss&w+rd=1 x")
        assert ds.dpapi_unprotect(blob) == "p@ss&w+rd=1 x"
        int(blob, 16)                       # lowercase hex, as PowerShell emits
        assert blob == blob.lower(), blob
    t("user-scope round trip", test_dpapi_round_trip_user)

    def test_dpapi_round_trip_machine():
        blob = ds.dpapi_protect("machine value", machine=True)
        # One decrypt path reads both scopes - DPAPI records the scope itself.
        assert ds.dpapi_unprotect(blob) == "machine value"
    t("machine-scope round trip, decrypted by the same call", test_dpapi_round_trip_machine)

    def test_dpapi_unicode():
        assert ds.dpapi_unprotect(ds.dpapi_protect("paßwort – é")) == "paßwort – é"
    t("non-ASCII survives the UTF-16LE round trip", test_dpapi_unicode)

    def test_dpapi_bad_hex():
        try:
            ds.dpapi_unprotect("not hex at all")
        except ds.SSError as e:
            assert "valid hex" in str(e), e
            return
        raise AssertionError("expected SSError")
    t("a malformed blob says what it should have been", test_dpapi_bad_hex)

    def test_dpapi_tampered_blob():
        blob = ds.dpapi_protect("x")
        broken = blob[:-8] + ("0" * 8 if not blob.endswith("0" * 8) else "1" * 8)
        try:
            ds.dpapi_unprotect(broken)
        except ds.SSError as e:
            assert "--protect-secret" in str(e), e
            return
        raise AssertionError("expected SSError")
    t("a blob that will not decrypt names the likely cause", test_dpapi_tampered_blob)

    # The parity claim in the README is that a blob made by either
    # implementation decrypts in the other. Assert it rather than assert it in
    # prose. Skipped when powershell.exe is not on PATH.
    import shutil, subprocess

    if not shutil.which("powershell.exe"):
        print("  SKIP  powershell.exe not on PATH - cross-implementation check")
    else:
        def test_powershell_can_read_our_blob():
            blob = ds.dpapi_protect("shared-secret-42")
            ps = ("$s = ConvertTo-SecureString -String '%s'; "
                  "$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); "
                  "[Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)" % blob)
            out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=60)
            assert out.stdout.strip() == "shared-secret-42", (out.stdout, out.stderr)
        t("PowerShell decrypts a blob this made", test_powershell_can_read_our_blob)

        def test_we_can_read_a_powershell_blob():
            ps = ("ConvertFrom-SecureString -SecureString "
                  "(ConvertTo-SecureString 'from-powershell' -AsPlainText -Force)")
            out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=60)
            blob = out.stdout.strip()
            assert blob, out.stderr
            assert ds.dpapi_unprotect(blob) == "from-powershell"
        t("this decrypts a blob PowerShell made", test_we_can_read_a_powershell_blob)

print("")
print(f"FAILURES: {FAILURES}" if FAILURES else "ALL TESTS PASSED")
sys.exit(1 if FAILURES else 0)
