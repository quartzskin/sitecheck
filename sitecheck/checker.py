import time

from .dnscheck import check_dns
from .headers import score_headers
from .httpcheck import check_http, check_redirect
from .tlscheck import check_tls


def _finding(level, code, msg):
    return {"level": level, "code": code, "msg": msg}


def judge(res, settings):
    f = []
    dns, tls, http, red = res["dns"], res["tls"], res["http"], res["redirect"]
    if not dns["a"] and not dns["aaaa"]:
        f.append(_finding("fail", "dns", "host does not resolve"))
    if tls["error"] and tls["days_left"] is None:
        f.append(_finding("fail", "tls", "TLS handshake failed: " + tls["error"]))
    else:
        if tls["error"]:
            f.append(_finding("fail", "tls", "certificate not trusted: " + tls["error"]))
        if tls["hostname_ok"] is False:
            f.append(_finding("fail", "hostname", "certificate does not cover this host name"))
        days = tls["days_left"]
        if days is not None and days < 0:
            f.append(_finding("fail", "expired", f"certificate expired {-days} day(s) ago"))
        elif days is not None and days <= 7:
            f.append(_finding("fail", "expiry", f"certificate expires in {days} day(s)"))
        elif days is not None and days < settings.warn_days:
            f.append(_finding("warn", "expiry", f"certificate expires in {days} days"))
    if http["error"]:
        f.append(_finding("fail", "http", "request failed: " + http["error"]))
    elif http["status"] >= 400:
        f.append(_finding("fail", "status", f"HTTP {http['status']} {http['reason']}"))
    if red["state"] == "bad":
        f.append(_finding("fail", "redirect", f"http:// does not redirect to https:// (status {red['status']})"))
    elif red["state"] == "error":
        f.append(_finding("warn", "redirect", "http:// check failed: " + red["error"]))
    if http["ms"] is not None and http["ms"] > settings.slow_ms:
        f.append(_finding("warn", "slow", f"response took {http['ms']:.0f} ms (limit {settings.slow_ms})"))
    if http["status"] is not None and res["headers"]["score"] < settings.min_score:
        f.append(_finding("warn", "headers", f"header score {res['headers']['score']} is under {settings.min_score}: {res['headers']['hint']}"))
    if dns["caa_checked"] and not dns["caa"]:
        f.append(_finding("info", "caa", "no CAA record"))
    return f


def check_site(site, settings, guard):
    guard.check_host(site.host)
    res = {"site": site.name, "host": site.host, "ts": int(time.time())}
    res["dns"] = check_dns(site.host, guard, settings)
    res["tls"] = check_tls(site.host, site.port, settings.timeout, site.ca_file, guard)
    res["http"] = check_http(site, settings, guard, verified=res["tls"]["verified"])
    res["redirect"] = check_redirect(site, settings, guard)
    final = res["http"]["final_url"] or ""
    res["headers"] = score_headers(res["http"]["headers"], final.startswith("https://"))
    res["findings"] = judge(res, settings)
    res["ok"] = not any(x["level"] != "info" for x in res["findings"])
    return res


def check_all(sites, settings, guard, progress=None):
    results = []
    for site in sites:
        results.append(check_site(site, settings, guard))
        if progress:
            progress(results[-1])
    return results
