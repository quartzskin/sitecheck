import re

HSTS_MIN = 15552000

# key, label, max points
CHECKS = (
    ("hsts", "Strict-Transport-Security", 25),
    ("csp", "Content-Security-Policy", 25),
    ("xcto", "X-Content-Type-Options", 15),
    ("frame", "Frame protection", 15),
    ("referrer", "Referrer-Policy", 10),
    ("permissions", "Permissions-Policy", 10),
)

WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", ""}


def _directives(csp):
    out = {}
    for part in csp.split(";"):
        bits = part.split()
        if bits:
            out.setdefault(bits[0].lower(), bits[1:])
    return out


def _hsts(h, https):
    v = h.get("strict-transport-security")
    if not https:
        return 0, v, "serve the site over https first, then add Strict-Transport-Security"
    if not v:
        return 0, v, "add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.IGNORECASE)
    if not m:
        return 0, v, "Strict-Transport-Security has no max-age; use max-age=31536000"
    if int(m.group(1)) < HSTS_MIN:
        return 12, v, f"raise HSTS max-age to at least {HSTS_MIN} (now {m.group(1)})"
    return 25, v, None


def _csp(h, _):
    v = h.get("content-security-policy")
    if not v:
        return 0, v, "add a Content-Security-Policy, start from default-src 'self'"
    d = _directives(v)
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        return 12, v, "CSP has no default-src or script-src; add default-src 'self'"
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        return 12, v, "drop 'unsafe-inline' from script-src (use nonces or hashes)"
    return 25, v, None


def _xcto(h, _):
    v = h.get("x-content-type-options")
    if v and v.strip().lower() == "nosniff":
        return 15, v, None
    return 0, v, "add: X-Content-Type-Options: nosniff"


def _frame(h, _):
    csp = _directives(h.get("content-security-policy", ""))
    xfo = h.get("x-frame-options")
    if "frame-ancestors" in csp:
        return 15, "frame-ancestors " + " ".join(csp["frame-ancestors"]), None
    if xfo and xfo.strip().lower() in ("deny", "sameorigin"):
        return 15, xfo, None
    return 0, xfo, "add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')"


def _referrer(h, _):
    v = h.get("referrer-policy")
    if v is None:
        return 0, v, "add: Referrer-Policy: strict-origin-when-cross-origin"
    if v.strip().lower() in WEAK_REFERRER:
        return 4, v, "use Referrer-Policy: strict-origin-when-cross-origin"
    return 10, v, None


def _permissions(h, _):
    v = h.get("permissions-policy")
    if v:
        return 10, v, None
    return 0, v, "add: Permissions-Policy: camera=(), microphone=(), geolocation=()"


_FUNCS = {"hsts": _hsts, "csp": _csp, "xcto": _xcto, "frame": _frame, "referrer": _referrer, "permissions": _permissions}


def score_headers(headers, https):
    items, total = [], 0
    for key, label, top in CHECKS:
        pts, value, hint = _FUNCS[key](headers, https)
        total += pts
        items.append({"key": key, "name": label, "points": pts, "max": top, "value": value, "hint": hint})
    worst = max((i for i in items if i["hint"]), key=lambda i: i["max"] - i["points"], default=None)
    return {"score": total, "max": 100, "items": items, "hint": worst["hint"] if worst else None}
