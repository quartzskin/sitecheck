import json
import sqlite3
from contextlib import closing

SCHEMA = """
create table if not exists results (
    id integer primary key,
    ts integer not null,
    site text not null,
    ok integer not null,
    status integer,
    ms real,
    days integer,
    score integer,
    data text not null
);
create index if not exists results_site_ts on results (site, ts);
create table if not exists changes (
    id integer primary key,
    ts integer not null,
    site text not null,
    field text not null,
    old text,
    new text
);
create index if not exists changes_ts on changes (ts);
"""


def summary(res):
    codes = ",".join(sorted({f["code"] for f in res["findings"] if f["level"] != "info"}))
    return {
        "status": res["http"]["status"],
        "final_url": res["http"]["final_url"],
        "tls_version": res["tls"]["version"],
        "issuer": res["tls"]["issuer"],
        "cert": (res["tls"]["fingerprint"] or "")[:16],
        "score": res["headers"]["score"] if res["http"]["status"] is not None else None,
        "a": ",".join(res["dns"]["a"]),
        "aaaa": ",".join(res["dns"]["aaaa"]),
        "caa": ",".join(res["dns"]["caa"]),
        "problems": codes,
    }


class Store:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        return closing(sqlite3.connect(self.path))

    def record(self, res):
        prev = self.latest(res["site"])
        now = summary(res)
        changes = []
        if prev:
            old = summary(prev)
            for key, val in now.items():
                if str(old[key] if old[key] is not None else "") != str(val if val is not None else ""):
                    changes.append((res["ts"], res["site"], key, None if old[key] is None else str(old[key]), None if val is None else str(val)))
        with self._conn() as c:
            c.execute("insert into results (ts, site, ok, status, ms, days, score, data) values (?,?,?,?,?,?,?,?)",
                      (res["ts"], res["site"], int(res["ok"]), res["http"]["status"], res["http"]["ms"],
                       res["tls"]["days_left"], res["headers"]["score"], json.dumps(res)))
            c.executemany("insert into changes (ts, site, field, old, new) values (?,?,?,?,?)", changes)
            c.commit()
        return changes

    def latest(self, site):
        with self._conn() as c:
            row = c.execute("select data from results where site=? order by ts desc, id desc limit 1", (site,)).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, site, limit=30):
        with self._conn() as c:
            rows = c.execute("select ts, ms, score, days, ok from results where site=? order by ts desc, id desc limit ?", (site, limit)).fetchall()
        return rows[::-1]

    def changes(self, site=None, limit=50):
        sql, args = "select ts, site, field, old, new from changes", []
        if site:
            sql += " where site=?"
            args.append(site)
        sql += " order by ts desc, id desc limit ?"
        with self._conn() as c:
            return c.execute(sql, (*args, limit)).fetchall()
