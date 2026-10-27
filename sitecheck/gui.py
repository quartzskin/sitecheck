import os
import queue
import random
import threading
import time
import tkinter as tk
from tkinter import ttk

from . import report
from .checker import check_all, judge
from .config import Settings
from .headers import score_headers
from .store import Store

COLUMNS = (("site", "Site", 110, "w"), ("status", "Status", 70, "w"), ("days", "Cert days left", 100, "e"),
           ("score", "Header score", 95, "e"), ("ms", "Response ms", 95, "e"), ("checked", "Last checked", 130, "w"))


def row_values(res):
    http, tls = res["http"], res["tls"]
    return (res["site"], report.verdict(res),
            "-" if tls["days_left"] is None else tls["days_left"],
            f"{res['headers']['score']}/100" if http["status"] is not None else "-",
            "-" if http["ms"] is None else f"{http['ms']:.0f}",
            report.when(res["ts"]))


def detail_body(res, changes=()):
    body = report.detail_text(res)
    hints = [f"  {i['name']}: {i['hint']}" for i in res["headers"]["items"] if i["hint"]] if res["http"]["status"] is not None else []
    if hints:
        body += "\n\nFIX HINTS\n" + "\n".join(hints)
    if changes:
        body += "\n\nRECENT CHANGES\n" + "\n".join(f"  {report.when(t)} {f}: {o or '-'} -> {n or '-'}" for t, _, f, o, n in changes)
    return body


def _fake(name, ip, status, ms, days, headers, redirect="ok", error=None):
    s = Settings()
    https = status is not None
    res = {
        "site": name, "host": f"{name}.example.net", "ts": int(time.time()),
        "dns": {"a": [ip], "aaaa": [], "caa": ['issue "letsencrypt.org"'], "caa_checked": True, "caa_error": None},
        "tls": {"ok": days is not None and days >= 0, "error": error, "verified": days is not None and days >= 0 and not error,
                "hostname_ok": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "subject": f"{name}.example.net", "issuer": "Example CA / Demo Issuing CA 1", "not_before": None,
                "not_after": time.time() + (days or 0) * 86400, "days_left": days, "san": [f"{name}.example.net"],
                "chain": [f"{name}.example.net", "Demo Issuing CA 1"], "self_signed": False, "fingerprint": "ab" * 32, "ms": 40},
        "http": {"ok": https and status < 400, "error": None, "status": status, "reason": {200: "OK", 503: "Service Unavailable"}.get(status, ""),
                 "ms": ms, "hops": [{"url": f"https://{name}.example.net/", "status": status, "location": None, "followed": False}],
                 "final_url": f"https://{name}.example.net/", "headers": headers},
        "redirect": {"state": redirect, "status": 301 if redirect == "ok" else 200, "location": None, "error": None},
    }
    res["headers"] = score_headers(headers, https)
    res["findings"] = judge(res, s)
    res["ok"] = not any(f["level"] != "info" for f in res["findings"])
    return res


def _hist(seed, base, n=24, bad_at=()):
    rnd = random.Random(seed)
    now = int(time.time())
    out = []
    for i in range(n):
        ms = max(20, base * (1 + rnd.uniform(-.25, .3)) * (3 if i in bad_at else 1))
        out.append((now - (n - i) * 3600, ms, 0, 0, 0 if i in bad_at else 1))
    return out


def demo_rows():
    full = {"strict-transport-security": "max-age=63072000; includeSubDomains", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=(), microphone=()"}
    docs = dict(full, **{"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    shop = {"strict-transport-security": "max-age=86400", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN"}
    api = {"x-content-type-options": "nosniff"}
    return [
        (_fake("blog", "203.0.113.10", 200, 142, 62, full), _hist(1, 140)),
        (_fake("shop", "203.0.113.11", 200, 380, 17, shop), _hist(2, 360)),
        (_fake("docs", "203.0.113.12", 200, 95, 74, docs), _hist(3, 100)),
        (_fake("status", "203.0.113.13", 503, 1850, 40, dict(full, **{"permissions-policy": ""})), _hist(4, 300, bad_at=(19, 20, 21, 22, 23))),
        (_fake("legacy", "198.51.100.7", 200, 2600, 3, api, redirect="bad"), _hist(5, 2200)),
        (_fake("api", "203.0.113.15", 200, 61, 28, api), _hist(6, 60)),
    ]


class App:
    def __init__(self, root, cfg, demo):
        self.root, self.cfg, self.demo = root, cfg, demo
        self.rows = []
        self.inbox = queue.Queue()
        root.title("sitecheck" + (" (demo data)" if demo else ""))

        bar = ttk.Frame(root, padding=8)
        bar.pack(fill="x")
        self.run_btn = ttk.Button(bar, text="Run checks", command=self.run_checks)
        self.run_btn.pack(side="left")
        self.open_btn = ttk.Button(bar, text="Open config", command=self.open_config)
        self.open_btn.pack(side="left", padx=6)
        if demo:
            self.run_btn.state(["disabled"])
            self.open_btn.state(["disabled"])
        self.status = ttk.Label(bar, text="")
        self.status.pack(side="right")

        panes = ttk.PanedWindow(root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        top = ttk.Frame(panes)
        self.tree = ttk.Treeview(top, columns=[c[0] for c in COLUMNS], show="headings", selectmode="browse", height=7)
        for key, title, width, anchor in COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor=anchor)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.detail())
        panes.add(top, weight=1)

        bottom = ttk.Frame(panes)
        self.text = tk.Text(bottom, width=90, height=18, wrap="none", state="disabled")
        scroll = ttk.Scrollbar(bottom, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        panes.add(bottom, weight=2)

        self.reload()
        root.after(150, self.poll)

    def reload(self):
        keep = self.tree.selection()
        if self.demo:
            self.rows = demo_rows()
        else:
            store = Store(self.cfg.settings.db)
            self.rows = [(r, store.history(s.name)) for s in self.cfg.sites if (r := store.latest(s.name))]
        self.tree.delete(*self.tree.get_children())
        for i, (res, _) in enumerate(self.rows):
            self.tree.insert("", "end", iid=str(i), values=row_values(res))
        if self.rows:
            pick = keep[0] if keep and int(keep[0]) < len(self.rows) else "0"
            self.tree.selection_set(pick)
        self.detail()
        newest = max((r["ts"] for r, _ in self.rows), default=None)
        self.status.configure(text=("last run " + report.when(newest)) if newest and not self.demo else "")

    def detail(self):
        sel = self.tree.selection()
        if sel:
            res = self.rows[int(sel[0])][0]
            changes = () if self.demo else Store(self.cfg.settings.db).changes(res["site"], 6)
            body = detail_body(res, changes)
        else:
            body = "No results yet. Press Run checks (or run 'sitecheck run')."
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", body)
        self.text.configure(state="disabled")

    def open_config(self):
        try:
            os.startfile(self.cfg.path)
        except (AttributeError, OSError) as exc:
            self.status.configure(text=f"cannot open {self.cfg.path}: {exc}")

    def run_checks(self):
        self.run_btn.state(["disabled"])
        self.status.configure(text="checking...")
        sites = self.cfg.sites

        def work():
            store = Store(self.cfg.settings.db)
            try:
                check_all(sites, self.cfg.settings, self.cfg.guard(), store.record)
                self.inbox.put(None)
            except Exception as exc:  # noqa: BLE001 - shown in the status bar
                self.inbox.put(exc)

        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            msg = self.inbox.get_nowait()
        except queue.Empty:
            pass
        else:
            self.run_btn.state(["!disabled"])
            self.reload()
            if msg:
                self.status.configure(text=f"check failed: {msg}")
        self.root.after(150, self.poll)


def run_gui(cfg, demo, snapshot=None):
    if snapshot and os.name != "nt":
        print("sitecheck: --snapshot needs Windows (PrintWindow)")
        return 2
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (OSError, AttributeError):
            pass
    root = tk.Tk()
    App(root, cfg, demo)
    if snapshot:
        failure = []

        def shoot():
            from .winshot import capture
            try:
                root.update()
                capture(root, snapshot)
            except OSError as exc:
                failure.append(exc)
            root.destroy()

        root.after(700, shoot)
        root.mainloop()
        if failure:
            print(f"sitecheck: snapshot failed: {failure[0]}")
            return 1
        print("wrote", snapshot)
        return 0
    root.mainloop()
    return 0
