import json
import struct

import pytest

from sitecheck import cli, dnscheck, report
from sitecheck.config import ConfigError, Settings, load, parse
from sitecheck.headers import score_headers
from sitecheck.store import Store

from .conftest import GOOD_HEADERS


def lower(h):
    return {k.lower(): v for k, v in h.items()}


def cfg_with(*sites, **settings):
    return {"settings": settings, "site": list(sites)}


def test_perfect_headers():
    r = score_headers(lower(GOOD_HEADERS), True)
    assert r["score"] == 100 and r["hint"] is None


def test_no_headers_gives_zero_and_hint():
    r = score_headers({}, True)
    assert r["score"] == 0
    assert "Content-Security-Policy" in r["hint"] or "Strict-Transport-Security" in r["hint"]
    assert all(i["hint"] for i in r["items"])


def test_weak_hsts_and_unsafe_csp_are_partial():
    h = lower(GOOD_HEADERS)
    h["strict-transport-security"] = "max-age=300"
    h["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
    items = {i["key"]: i for i in score_headers(h, True)["items"]}
    assert 0 < items["hsts"]["points"] < 25
    assert 0 < items["csp"]["points"] < 25
    assert "max-age" in items["hsts"]["hint"]


def test_csp_nonce_allows_inline():
    h = {"content-security-policy": "script-src 'unsafe-inline' 'nonce-abc'"}
    assert {i["key"]: i for i in score_headers(h, True)["items"]}["csp"]["points"] == 25


def test_frame_protection_either_way():
    assert {i["key"]: i for i in score_headers({"x-frame-options": "DENY"}, True)["items"]}["frame"]["points"] == 15
    assert {i["key"]: i for i in score_headers({"x-frame-options": "ALLOW-FROM x"}, True)["items"]}["frame"]["points"] == 0
    assert {i["key"]: i for i in score_headers({"content-security-policy": "frame-ancestors 'none'"}, True)["items"]}["frame"]["points"] == 15


def test_hsts_not_credited_over_http():
    assert score_headers(lower(GOOD_HEADERS), False)["score"] == 75


def test_garbage_header_values():
    r = score_headers({"strict-transport-security": "???", "x-content-type-options": "yes", "content-security-policy": ";;;"}, True)
    assert r["score"] <= 25


def test_config_valid():
    c = parse(cfg_with({"name": "a", "host": "Example.COM"}, {"name": "b", "host": "10.0.0.5", "port": 8443}), "<memory>")
    assert [s.host for s in c.sites] == ["example.com", "10.0.0.5"]
    assert c.sites[1].port == 8443
    assert c.guard().permits("example.com", 443)
    assert not c.guard().permits("example.com", 22)
    assert not c.guard().permits("other.com", 443)


@pytest.mark.parametrize("bad", [
    {"name": "a"},
    {"host": "x.com"},
    {"name": "a", "host": "https://x.com"},
    {"name": "a", "host": "x.com/path"},
    {"name": "a", "host": "x.com", "port": 0},
    {"name": "a", "host": "x.com", "port": "443"},
    {"name": "a", "host": "x.com", "path": "no-slash"},
    {"name": "a", "host": "x.com", "method": "POST"},
    {"name": "a b", "host": "x.com"},
    {"name": "a", "host": "x.com", "surprise": 1},
    {"name": "a", "host": ""},
])
def test_config_rejects(bad):
    with pytest.raises(ConfigError):
        parse(cfg_with(bad))


def test_config_rejects_duplicates_empty_and_bad_settings():
    with pytest.raises(ConfigError):
        parse(cfg_with({"name": "a", "host": "x.com"}, {"name": "a", "host": "y.com"}))
    with pytest.raises(ConfigError):
        parse({"site": []})
    with pytest.raises(ConfigError):
        parse(cfg_with({"name": "a", "host": "x.com"}, timeout=0))
    with pytest.raises(ConfigError):
        parse(cfg_with({"name": "a", "host": "x.com"}, timeout="soon"))
    with pytest.raises(ConfigError):
        parse(cfg_with({"name": "a", "host": "x.com"}, bogus=1))


def test_config_file_errors(tmp_path):
    with pytest.raises(ConfigError):
        load(str(tmp_path / "missing.toml"))
    p = tmp_path / "bad.toml"
    p.write_text("[[site\n")
    with pytest.raises(ConfigError):
        load(str(p))


def test_config_pick(tmp_path):
    c = parse(cfg_with({"name": "a", "host": "x.com"}, {"name": "b", "host": "y.com"}))
    assert [s.name for s in c.pick(["b"])] == ["b"]
    with pytest.raises(ConfigError):
        c.pick(["zzz"])


def test_db_path_is_relative_to_config(tmp_path):
    p = tmp_path / "s.toml"
    p.write_text('[[site]]\nname="a"\nhost="x.com"\n')
    assert load(str(p)).settings.db == str(tmp_path / "sitecheck.db")


def fake_result(site="a", ts=1000, days=40, status=200, ms=100.0, issuer="CA", problems=()):
    res = {
        "site": site, "host": f"{site}.test", "ts": ts, "ok": not problems,
        "dns": {"a": ["1.2.3.4"], "aaaa": [], "caa": [], "caa_checked": True, "caa_error": None},
        "tls": {"days_left": days, "version": "TLSv1.3", "issuer": issuer, "fingerprint": "ff" * 32, "not_after": 2e9,
                "hostname_ok": True, "verified": True, "chain": [], "error": None, "self_signed": False, "cipher": "x"},
        "http": {"status": status, "ms": ms, "final_url": "https://a.test/", "error": None, "hops": [], "reason": "OK", "headers": {}},
        "redirect": {"state": "ok", "status": 301, "location": None, "error": None},
        "headers": score_headers({}, True),
        "findings": [{"level": "fail", "code": c, "msg": c} for c in problems],
    }
    return res


def test_store_records_and_diffs(tmp_path):
    st = Store(str(tmp_path / "t.db"))
    assert st.record(fake_result(ts=1)) == []
    changes = st.record(fake_result(ts=2, issuer="New CA", problems=("expiry",)))
    fields = {c[2]: (c[3], c[4]) for c in changes}
    assert fields["issuer"] == ("CA", "New CA")
    assert fields["problems"] == ("", "expiry")
    assert st.record(fake_result(ts=3, issuer="New CA", problems=("expiry",))) == []
    assert len(st.history("a")) == 3
    assert st.latest("a")["ts"] == 3
    assert st.latest("nobody") is None
    assert len(st.changes("a")) == len(changes)
    assert st.changes("other") == []


def test_store_sites_are_independent(tmp_path):
    st = Store(str(tmp_path / "t.db"))
    st.record(fake_result("a", 1))
    assert st.record(fake_result("b", 2, issuer="Other")) == []


def test_html_report_escapes():
    res = fake_result("a", problems=("<script>",))
    res["findings"][0]["msg"] = "<script>alert(1)</script>"
    out = report.html_report([(res, [(1, 10.0, 0, 0, 1), (2, 20.0, 0, 0, 1)])], [(1, "a", "f", "<b>", "x")])
    assert "<script>alert" not in out and "&lt;script&gt;" in out and "&lt;b&gt;" in out
    assert "<polyline" in out


def test_report_line_handles_failed_check():
    res = fake_result(status=None, ms=None, days=None)
    res["http"]["status"] = None
    assert "-" in report.line(res)
    assert "checked" in report.detail_text(res)


def test_dns_query_roundtrip_and_caa_parse():
    q = dnscheck.build_query("example.com", dnscheck.CAA, 77)
    assert struct.unpack("!H", q[:2])[0] == 77 and q.endswith(struct.pack("!HH", 257, 1))
    rdata = bytes([0, 5]) + b"issue" + b"letsencrypt.org"
    name = b"\xc0\x0c"
    reply = struct.pack("!HHHHHH", 77, 0x8180, 1, 1, 0, 0) + q[12:] + name + struct.pack("!HHIH", 257, 1, 60, len(rdata)) + rdata
    rcode, answers = dnscheck.parse_response(reply, 77)
    assert rcode == 0 and dnscheck.parse_caa(answers[0][1]) == 'issue "letsencrypt.org"'


def test_dns_malformed_replies():
    with pytest.raises(dnscheck.DnsError):
        dnscheck.parse_response(b"\x00\x01", 1)
    with pytest.raises(dnscheck.DnsError):
        dnscheck.parse_response(struct.pack("!HHHHHH", 2, 0x8180, 0, 0, 0, 0), 1)
    loop = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + b"\0\0\0\0"
    with pytest.raises(dnscheck.DnsError):
        dnscheck.parse_response(loop, 1)
    with pytest.raises(dnscheck.DnsError):
        dnscheck.parse_caa(b"\x00\xff")


def test_cli_init_run_and_exit_codes(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init"]) == 0
    assert cli.main(["init"]) == 2
    assert cli.main(["-c", "nope.toml", "run"]) == 2
    assert "sitecheck:" in capsys.readouterr().err
    assert cli.main(["report"]) == 2


def test_cli_run_against_local_server(certs, https_server, http_server, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    conf = tmp_path / "s.toml"
    conf.write_text(f'[settings]\ntimeout = 3\n[[site]]\nname = "loc"\nhost = "127.0.0.1"\nport = {https_server.server_port}\n'
                    f'http_port = {http_server.server_port}\nca_file = {json.dumps(certs[2])}\n')
    assert cli.main(["-c", str(conf), "run"]) == 0
    assert "OK" in capsys.readouterr().out
    assert cli.main(["-c", str(conf), "report", "--html", "r.html"]) == 0
    assert "loc" in (tmp_path / "r.html").read_text()
    assert cli.main(["-c", str(conf), "log"]) == 0
    assert cli.main(["-c", str(conf), "run", "-s", "ghost"]) == 2
    conf.write_text(conf.read_text().replace(json.dumps(certs[2]), '"nonexistent.pem"'))
    assert cli.main(["-c", str(conf), "run", "--no-store"]) == 1


def test_settings_defaults():
    assert Settings().timeout > 0
