import http.client
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .tlscheck import _context

ERRORS = (OSError, http.client.HTTPException, ssl.SSLError, ValueError)


def _request(scheme, host, port, method, path, ctx, timeout, ua):
    t0 = time.perf_counter()
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, headers={"User-Agent": ua, "Accept": "*/*", "Connection": "close"})
        r = conn.getresponse()
        ms = round((time.perf_counter() - t0) * 1000, 1)
        headers = {}
        for k, v in r.getheaders():
            k = k.lower()
            headers[k] = headers[k] + ", " + v if k in headers else v
        return {"status": r.status, "reason": r.reason, "headers": headers, "ms": ms}
    finally:
        conn.close()


def _url(scheme, host, port, path):
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}{'' if port == default else f':{port}'}{path}"


def check_http(site, settings, guard, verified):
    ctx = _context(True, site.ca_file) if verified else _context(False, None)
    scheme, host, port, path = "https", site.host, site.port, site.path
    out = {"ok": False, "error": None, "status": None, "reason": None, "ms": None, "hops": [], "final_url": None, "headers": {}}
    for i in range(settings.max_redirects + 1):
        guard.check(host, port)
        method = site.method if i == 0 else "HEAD"
        try:
            r = _request(scheme, host, port, method, path, ctx, settings.timeout, settings.user_agent)
        except ERRORS as exc:
            out["error"] = str(exc) or type(exc).__name__
            if timed_out(exc):
                out["error"] = f"timed out after {settings.timeout:g}s"
            return out
        url = _url(scheme, host, port, path)
        loc = r["headers"].get("location")
        hop = {"url": url, "status": r["status"], "location": loc, "followed": False}
        out["hops"].append(hop)
        if i == 0:
            out["ms"] = r["ms"]
        out["status"], out["reason"], out["headers"], out["final_url"] = r["status"], r["reason"], r["headers"], url
        if not (300 <= r["status"] < 400 and loc):
            break
        target = urlsplit(urljoin(url, loc))
        if target.scheme not in ("http", "https") or not target.hostname:
            break
        tport = target.port or (443 if target.scheme == "https" else 80)
        if not guard.permits(target.hostname, tport) or i == settings.max_redirects:
            hop["note"] = "not followed" + ("" if guard.permits(target.hostname, tport) else " (not a configured site)")
            break
        hop["followed"] = True
        scheme, host, port = target.scheme, target.hostname, tport
        path = (target.path or "/") + (f"?{target.query}" if target.query else "")
    out["ok"] = out["status"] is not None and out["status"] < 400
    return out


def timed_out(exc):
    return isinstance(exc, TimeoutError) or "timed out" in str(exc)


def check_redirect(site, settings, guard):
    out = {"state": "skipped", "status": None, "location": None, "error": None}
    if not site.check_http_redirect:
        return out
    guard.check(site.host, site.http_port)
    try:
        r = _request("http", site.host, site.http_port, "HEAD", site.path, None, settings.timeout, settings.user_agent)
    except ConnectionRefusedError:
        out["state"] = "closed"
        return out
    except ERRORS as exc:
        out["state"], out["error"] = "error", str(exc) or type(exc).__name__
        return out
    loc = r["headers"].get("location")
    out["status"], out["location"] = r["status"], loc
    target = urlsplit(urljoin(_url("http", site.host, site.http_port, site.path), loc)) if loc else None
    good = target is not None and 300 <= r["status"] < 400 and target.scheme == "https" and (target.hostname or "").lower() == site.host.lower()
    out["state"] = "ok" if good else "bad"
    return out
