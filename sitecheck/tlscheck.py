import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
import time

HOSTNAME_CODES = (62, 64)


def decode_der(der):
    # No public API decodes a certificate we refused to verify, so use the one ssl itself uses in its tests.
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)
    finally:
        os.unlink(path)


def _rdn(seq):
    return {k: v for part in seq for k, v in part}


def _label(seq):
    d = _rdn(seq)
    org, cn = d.get("organizationName"), d.get("commonName")
    if org and cn:
        return f"{org} / {cn}"
    return org or cn or ""


def name_matches(host, cert):
    sans = cert.get("subjectAltName", ())
    try:
        ip = ipaddress.ip_address(host)
        return any(k == "IP Address" and _same_ip(v, ip) for k, v in sans)
    except ValueError:
        pass
    names = [v for k, v in sans if k == "DNS"]
    if not names:
        cn = _rdn(cert.get("subject", ())).get("commonName")
        names = [cn] if cn else []
    host = host.lower()
    for pat in names:
        pat = pat.lower()
        if pat == host:
            return True
        if pat.startswith("*.") and "." in host and host.split(".", 1)[1] == pat[2:] and host.count(".") == pat.count("."):
            return True
    return False


def _same_ip(text, ip):
    try:
        return ipaddress.ip_address(text) == ip
    except ValueError:
        return False


def _context(verify, ca_file):
    if verify:
        return ssl.create_default_context(cafile=ca_file)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _handshake(host, port, timeout, ctx):
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        der = s.getpeercert(True)
        info = s.getpeercert() or decode_der(der)
        chain = []
        getter = getattr(s, "get_verified_chain", None) if ctx.verify_mode != ssl.CERT_NONE else getattr(s, "get_unverified_chain", None)
        try:
            chain = [decode_der(c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER)) for c in (getter() if getter else [])]
        except (ssl.SSLError, ValueError, AttributeError, TypeError):
            chain = []
        return info, der, chain, s.version(), (s.cipher() or ("", "", 0))[0]


def check_tls(host, port, timeout, ca_file, guard):
    guard.check(host, port)
    out = {"ok": False, "error": None, "verified": False, "hostname_ok": None, "version": None, "cipher": None,
           "subject": None, "issuer": None, "not_before": None, "not_after": None, "days_left": None,
           "san": [], "chain": [], "self_signed": None, "fingerprint": None, "ms": None}
    t0 = time.perf_counter()
    try:
        try:
            info, der, chain, version, cipher = _handshake(host, port, timeout, _context(True, ca_file))
            out["verified"], out["hostname_ok"] = True, True
        except ssl.SSLCertVerificationError as exc:
            out["error"] = exc.verify_message or str(exc)
            info, der, chain, version, cipher = _handshake(host, port, timeout, _context(False, None))
            out["hostname_ok"] = name_matches(host, info)
            if exc.verify_code in HOSTNAME_CODES:
                out["hostname_ok"] = False
    except (OSError, ssl.SSLError) as exc:
        out["error"] = (out["error"] + "; " if out["error"] else "") + (str(exc) or type(exc).__name__)
        return out
    out["ms"] = round((time.perf_counter() - t0) * 1000, 1)
    out["version"], out["cipher"] = version, cipher
    out["subject"], out["issuer"] = _label(info.get("subject", ())), _label(info.get("issuer", ()))
    out["self_signed"] = info.get("subject") == info.get("issuer")
    out["san"] = [v for _, v in info.get("subjectAltName", ())]
    out["fingerprint"] = hashlib.sha256(der).hexdigest()
    out["chain"] = [_label(c.get("subject", ())) for c in chain]
    nb, na = ssl.cert_time_to_seconds(info["notBefore"]), ssl.cert_time_to_seconds(info["notAfter"])
    out["not_before"], out["not_after"] = nb, na
    out["days_left"] = int((na - time.time()) // 86400)
    out["ok"] = out["verified"] and out["days_left"] >= 0
    return out
