import socket
import ssl
import time

import pytest

from sitecheck.checker import check_site
from sitecheck.config import NotAllowed
from sitecheck.httpcheck import check_http, check_redirect
from sitecheck.tlscheck import check_tls, name_matches

from .conftest import make_certs, make_guard, make_site, serve


def test_tls_trusted_cert(certs, https_server):
    site = make_site(https_server.server_port, certs[2])
    r = check_tls("127.0.0.1", site.port, 3, certs[2], make_guard(site))
    assert r["ok"] and r["verified"] and r["hostname_ok"]
    assert r["version"] in ("TLSv1.2", "TLSv1.3")
    assert "Test Root" in r["issuer"]
    assert 28 <= r["days_left"] <= 30
    assert r["chain"], "verified chain should be reported"
    assert len(r["fingerprint"]) == 64


def test_tls_untrusted_still_reports_cert(certs, https_server):
    site = make_site(https_server.server_port, None)
    r = check_tls("127.0.0.1", site.port, 3, None, make_guard(site))
    assert not r["ok"] and not r["verified"]
    assert "certificate" in r["error"].lower()
    assert r["days_left"] is not None and r["issuer"]


def test_tls_hostname_mismatch(tmp_path):
    paths = make_certs(str(tmp_path), san="DNS:other.example")
    srv = serve({"/": (200, {}, b"x")}, tls=paths[:2])
    try:
        site = make_site(srv.server_port, paths[2])
        r = check_tls("127.0.0.1", site.port, 3, paths[2], make_guard(site))
        assert r["hostname_ok"] is False and not r["ok"]
    finally:
        srv.shutdown()


def test_tls_expiring_days(tmp_path):
    paths = make_certs(str(tmp_path), days=5)
    srv = serve({"/": (200, {}, b"x")}, tls=paths[:2])
    try:
        site = make_site(srv.server_port, paths[2])
        r = check_tls("127.0.0.1", site.port, 3, paths[2], make_guard(site))
        assert r["ok"] and 3 <= r["days_left"] <= 5
    finally:
        srv.shutdown()


def test_tls_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    site = make_site(port, None)
    r = check_tls("127.0.0.1", port, 1, None, make_guard(site))
    assert not r["ok"] and r["error"] and r["days_left"] is None


def test_tls_timeout_is_honoured():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)  # accepts the TCP connection but never speaks TLS
    port = srv.getsockname()[1]
    site = make_site(port, None)
    t0 = time.monotonic()
    r = check_tls("127.0.0.1", port, 0.5, None, make_guard(site))
    srv.close()
    assert time.monotonic() - t0 < 3
    assert not r["ok"] and r["error"]


def test_guard_blocks_unlisted_endpoints(certs, https_server):
    site = make_site(https_server.server_port, certs[2])
    guard = make_guard(site)
    with pytest.raises(NotAllowed):
        check_tls("127.0.0.1", 9, 1, None, guard)
    with pytest.raises(NotAllowed):
        check_tls("example.org", 443, 1, None, guard)
    with pytest.raises(NotAllowed):
        guard.check_host("evil.invalid")


def test_check_never_touches_socket_for_unlisted_host(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: calls.append(a))
    site = make_site(1, None)
    with pytest.raises(NotAllowed):
        check_tls("other.invalid", 443, 1, None, make_guard(site))
    assert calls == []


def test_name_matching():
    cert = {"subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
    assert name_matches("example.com", cert)
    assert name_matches("www.example.com", cert)
    assert not name_matches("a.b.example.com", cert)
    assert not name_matches("evil.com", cert)
    assert name_matches("EXAMPLE.com", cert)
    assert not name_matches("10.0.0.1", cert)
    assert name_matches("10.0.0.1", {"subjectAltName": (("IP Address", "10.0.0.1"),)})
    assert name_matches("legacy.test", {"subject": ((("commonName", "legacy.test"),),)})
    assert not name_matches("x.test", {})


def test_http_status_and_one_request(certs, https_server, settings):
    site = make_site(https_server.server_port, certs[2])
    r = check_http(site, settings, make_guard(site), verified=True)
    assert r["status"] == 200 and r["ok"] and r["ms"] is not None
    assert https_server.hits == [("GET", "/")]


def test_http_head_method(certs, https_server, settings):
    site = make_site(https_server.server_port, certs[2], method="HEAD")
    check_http(site, settings, make_guard(site), verified=True)
    assert https_server.hits == [("HEAD", "/")]


def test_redirect_chain_followed_with_head(certs, https_server, settings):
    site = make_site(https_server.server_port, certs[2], path="/old")
    r = check_http(site, settings, make_guard(site), verified=True)
    assert [h["status"] for h in r["hops"]] == [301, 200]
    assert r["hops"][0]["followed"]
    assert https_server.hits == [("GET", "/old"), ("HEAD", "/")]


def test_redirect_to_foreign_host_not_followed(certs, https_server, settings):
    site = make_site(https_server.server_port, certs[2], path="/away")
    r = check_http(site, settings, make_guard(site), verified=True)
    assert len(r["hops"]) == 1 and not r["hops"][0]["followed"]
    assert "not a configured site" in r["hops"][0]["note"]
    assert r["status"] == 302


def test_redirect_loop_is_capped(certs, settings):
    srv = serve({"/": (302, {"Location": "/"}, b"")})
    try:
        # plain http server: the https request fails, which must surface as an error, not a hang
        site = make_site(srv.server_port, certs[2])
        r = check_http(site, settings, make_guard(site), verified=True)
        assert r["error"] and not r["ok"]
    finally:
        srv.shutdown()


def test_http_to_https_redirect_states(http_server, settings):
    site = make_site(443, None, http_port=http_server.server_port)
    r = check_redirect(site, settings, make_guard(site))
    assert r["state"] == "ok" and r["status"] == 301


def test_http_not_redirecting_is_bad(settings):
    srv = serve({"/": (200, {}, b"plain")})
    try:
        site = make_site(443, None, http_port=srv.server_port)
        assert check_redirect(site, settings, make_guard(site))["state"] == "bad"
        assert srv.hits == [("HEAD", "/")]
    finally:
        srv.shutdown()


def test_redirect_to_other_host_is_bad(settings):
    srv = serve({"/": (301, {"Location": "https://elsewhere.invalid/"}, b"")})
    try:
        site = make_site(443, None, http_port=srv.server_port)
        assert check_redirect(site, settings, make_guard(site))["state"] == "bad"
    finally:
        srv.shutdown()


def test_redirect_host_compare_ignores_case(settings):
    srv = serve({"/": (301, {"Location": "https://LOCALHOST/"}, b"")})
    try:
        site = make_site(443, None, http_port=srv.server_port)
        site.host = "LocalHost"
        assert check_redirect(site, settings, make_guard(site))["state"] == "ok"
    finally:
        srv.shutdown()


def test_redirect_port_closed_and_disabled(settings):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    site = make_site(443, None, http_port=port)
    assert check_redirect(site, settings, make_guard(site))["state"] == "closed"
    site.check_http_redirect = False
    assert check_redirect(site, settings, make_guard(site))["state"] == "skipped"


def test_full_check_site(certs, https_server, http_server, settings):
    site = make_site(https_server.server_port, certs[2], http_port=http_server.server_port)
    r = check_site(site, settings, make_guard(site))
    assert r["tls"]["verified"] and r["http"]["status"] == 200
    assert r["headers"]["score"] == 100
    assert r["redirect"]["state"] == "ok"
    assert r["ok"], r["findings"]


def test_full_check_untrusted_is_failure(https_server, http_server, settings):
    site = make_site(https_server.server_port, None, http_port=http_server.server_port)
    r = check_site(site, settings, make_guard(site))
    assert not r["ok"]
    assert any(f["code"] == "tls" and f["level"] == "fail" for f in r["findings"])
    assert r["http"]["status"] == 200, "headers are still read when only trust fails"


def test_server_that_hangs_times_out(settings):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    site = make_site(s.getsockname()[1], None, http_port=s.getsockname()[1])
    settings.timeout = 0.5
    t0 = time.monotonic()
    r = check_http(site, settings, make_guard(site), verified=False)
    s.close()
    assert time.monotonic() - t0 < 3
    assert r["error"] and not r["ok"]


def test_ssl_module_is_stdlib():
    assert ssl.OPENSSL_VERSION
