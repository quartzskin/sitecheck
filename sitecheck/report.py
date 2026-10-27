import html
import time


def when(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def verdict(res):
    levels = {f["level"] for f in res["findings"]}
    return "FAIL" if "fail" in levels else "WARN" if "warn" in levels else "OK"


def line(res):
    http, tls = res["http"], res["tls"]
    status = http["status"] if http["status"] is not None else "-"
    ms = f"{http['ms']:.0f}ms" if http["ms"] is not None else "-"
    days = f"{tls['days_left']}d" if tls["days_left"] is not None else "-"
    score = f"{res['headers']['score']}/100" if http["status"] is not None else "-"
    return f"{verdict(res):<5} {res['site']:<16} {status!s:<4} {ms:>8}  cert {days:>5}  headers {score}"


def problems(res):
    return [f"      {f['level']}: {f['msg']}" for f in res["findings"] if f["level"] != "info"]


def detail_text(res):
    d, t, h, r = res["dns"], res["tls"], res["http"], res["redirect"]
    out = [f"{res['site']}  ({res['host']})", f"checked {when(res['ts'])}   {verdict(res)}", ""]
    out.append("DNS")
    out.append(f"  A     {', '.join(d['a']) or 'none'}")
    out.append(f"  AAAA  {', '.join(d['aaaa']) or 'none'}")
    caa = ", ".join(d["caa"]) if d["caa"] else ("none" if d["caa_checked"] else f"not checked ({d['caa_error']})")
    out.append(f"  CAA   {caa}")
    out += ["", "TLS"]
    if t["version"]:
        out.append(f"  {t['version']}  {t['cipher']}")
        out.append(f"  issuer   {t['issuer'] or '?'}" + ("  (self-signed)" if t["self_signed"] else ""))
        out.append(f"  expires  {when(t['not_after'])}  ({t['days_left']} days)")
        out.append(f"  host     {'matches' if t['hostname_ok'] else 'DOES NOT MATCH'}   trusted: {'yes' if t['verified'] else 'no'}")
        if t["chain"]:
            out.append("  chain    " + " > ".join(t["chain"]))
    if t["error"]:
        out.append(f"  error    {t['error']}")
    out += ["", "HTTP"]
    if h["error"]:
        out.append(f"  error    {h['error']}")
    for hop in h["hops"]:
        extra = f" -> {hop['location']}" if hop["location"] else ""
        out.append(f"  {hop['status']}  {hop['url']}{extra}" + (f"  [{hop['note']}]" if hop.get("note") else ""))
    if h["ms"] is not None:
        out.append(f"  response time {h['ms']:.0f} ms")
    red = r["state"] if r["state"] != "bad" else f"BAD (status {r['status']}, location {r['location']})"
    out.append(f"  http->https redirect: {red}")
    if h["status"] is not None:
        out += ["", f"HEADERS  {res['headers']['score']}/100"]
        for i in res["headers"]["items"]:
            out.append(f"  {i['points']:>2}/{i['max']:<2} {i['name']}" + (f"  - {i['hint']}" if i["hint"] else ""))
    out += ["", "FINDINGS"]
    out += [f"  {f['level']}: {f['msg']}" for f in res["findings"]] or ["  none"]
    return "\n".join(out)


def sparkline_svg(values, width=160, height=28):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return ""
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    pts = " ".join(f"{i * (width - 4) / (len(vals) - 1) + 2:.1f},{height - 3 - (v - lo) / span * (height - 6):.1f}" for i, v in enumerate(vals))
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"><polyline points="{pts}" fill="none" stroke="#35566b" stroke-width="1.5"/></svg>'


CSS = """
body{font:14px/1.4 system-ui,sans-serif;margin:2rem auto;max-width:62rem;padding:0 1rem}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #ccc;vertical-align:top}
.OK{color:#1a7f37}.WARN{color:#9a6700}.FAIL{color:#b3261e;font-weight:bold}
.hint{color:#555;font-size:.9em}
code{font:12px Consolas,monospace}
"""


def html_report(rows, changes):
    e = html.escape
    out = ['<!doctype html><meta charset="utf-8"><title>sitecheck report</title>', f"<style>{CSS}</style>", "<h1>sitecheck</h1>"]
    out.append("<table><tr><th>site<th>state<th>status<th>latency<th>cert<th>headers<th>history (latency)")
    for res, hist in rows:
        http, tls = res["http"], res["tls"]
        v = verdict(res)
        notes = "".join(f'<div class="hint">{e(f["level"])}: {e(f["msg"])}</div>' for f in res["findings"] if f["level"] != "info")
        ms = f"{http['ms']:.0f} ms" if http["ms"] is not None else "-"
        days = f"{tls['days_left']} days" if tls["days_left"] is not None else "-"
        score = f"{res['headers']['score']}/100" if http["status"] is not None else "-"
        out.append(
            f'<tr><td><b>{e(res["site"])}</b><br><code>{e(res["host"])}</code>{notes}<td class="{v}">{v}'
            f"<td>{e(str(http['status'] if http['status'] is not None else '-'))}<td>{ms}<td>{days}<td>{score}"
            f"<td>{sparkline_svg([h[1] for h in hist])}"
        )
    out.append("</table>")
    out.append("<h2>Changes</h2>")
    if changes:
        out.append("<table><tr><th>when<th>site<th>what<th>was<th>now")
        for ts, site, field, old, new in changes:
            out.append(f"<tr><td>{when(ts)}<td>{e(site)}<td>{e(field)}<td><code>{e(old or '')}</code><td><code>{e(new or '')}</code>")
        out.append("</table>")
    else:
        out.append("<p>Nothing has changed between runs yet.</p>")
    return "\n".join(out) + "\n"
