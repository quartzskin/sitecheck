import argparse
import json
import os
import sys

from . import report
from .checker import check_all
from .config import ConfigError, NotAllowed, find_config, load
from .store import Store

SAMPLE = '''# sites you own; sitecheck connects to nothing else
[settings]
timeout = 8          # seconds, per connection
warn_days = 21       # certificate warning threshold
min_score = 50       # header score below this is a warning
slow_ms = 2000
db = "sitecheck.db"  # relative to this file

[[site]]
name = "main"
host = "example.com"
# port = 443
# http_port = 80
# path = "/"
# method = "GET"          # or HEAD
# check_http_redirect = true
# ca_file = "internal-ca.pem"
'''


def build_parser():
    p = argparse.ArgumentParser(prog="sitecheck", description="Checks TLS, headers, redirects and DNS of sites listed in a config file.")
    p.add_argument("-c", "--config", help="config file (default: $SITECHECK_CONFIG or ./sitecheck.toml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="check the configured sites; exit 1 if anything warns or fails")
    r.add_argument("-s", "--site", action="append", help="only this site name (repeatable)")
    r.add_argument("--no-store", action="store_true", help="do not write to the database")
    r.add_argument("--json", action="store_true", help="print full results as JSON")
    r.add_argument("-v", "--verbose", action="store_true", help="print full detail per site")

    rp = sub.add_parser("report", help="summarise the last stored results (no network)")
    rp.add_argument("--html", nargs="?", const="sitecheck-report.html", metavar="FILE", help="write an HTML report")

    lg = sub.add_parser("log", help="show what changed between runs")
    lg.add_argument("-s", "--site")
    lg.add_argument("-n", type=int, default=30)

    g = sub.add_parser("gui", help="window with a table of the last results")
    g.add_argument("--demo", action="store_true", help="use made-up data, touch no network or database")
    g.add_argument("--snapshot", metavar="PNG", help="render the window to a PNG and exit (Windows)")

    i = sub.add_parser("init", help="write a sample config")
    i.add_argument("path", nargs="?", default="sitecheck.toml")
    return p


def cmd_run(cfg, args):
    sites = cfg.pick(args.site)
    store = None if args.no_store else Store(cfg.settings.db)

    def show(res):
        if store:
            store.record(res)
        if args.json:
            return
        print(report.line(res))
        for p in report.problems(res):
            print(p)
        if args.verbose:
            print(report.detail_text(res) + "\n")

    results = check_all(sites, cfg.settings, cfg.guard(), show)
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    return 0 if all(r["ok"] for r in results) else 1


def _stored(cfg):
    store = Store(cfg.settings.db)
    rows = []
    for site in cfg.sites:
        res = store.latest(site.name)
        if res:
            rows.append((res, store.history(site.name)))
    return store, rows


def cmd_report(cfg, args):
    store, rows = _stored(cfg)
    if not rows:
        print("no stored results yet; run 'sitecheck run' first", file=sys.stderr)
        return 2
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.html_report(rows, store.changes(limit=50)))
        print("wrote", os.path.abspath(args.html))
    else:
        for res, _ in rows:
            print(report.line(res))
            for p in report.problems(res):
                print(p)
    return 0 if all(r["ok"] for r, _ in rows) else 1


def cmd_log(cfg, args):
    rows = Store(cfg.settings.db).changes(args.site, args.n)
    if not rows:
        print("no changes recorded")
    for ts, site, field, old, new in rows:
        print(f"{report.when(ts)}  {site:<16} {field:<12} {old if old is not None else '-'} -> {new if new is not None else '-'}")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "init":
        if os.path.exists(args.path):
            print(f"{args.path} already exists", file=sys.stderr)
            return 2
        with open(args.path, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE)
        print("wrote", args.path)
        return 0
    try:
        if args.cmd == "gui" and args.demo:
            from .gui import run_gui
            return run_gui(None, demo=True, snapshot=args.snapshot)
        cfg = load(find_config(args.config))
        if args.cmd == "gui":
            from .gui import run_gui
            return run_gui(cfg, demo=False, snapshot=args.snapshot)
        return {"run": cmd_run, "report": cmd_report, "log": cmd_log}[args.cmd](cfg, args)
    except (ConfigError, NotAllowed) as exc:
        print(f"sitecheck: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
