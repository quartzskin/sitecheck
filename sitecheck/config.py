import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field

DEFAULT_NAMES = ("sitecheck.toml",)
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ConfigError(Exception):
    pass


class NotAllowed(Exception):
    pass


@dataclass
class Site:
    name: str
    host: str
    port: int = 443
    http_port: int = 80
    path: str = "/"
    method: str = "GET"
    check_http_redirect: bool = True
    ca_file: str | None = None


@dataclass
class Settings:
    timeout: float = 8.0
    db: str = "sitecheck.db"
    warn_days: int = 21
    min_score: int = 50
    slow_ms: int = 2000
    max_redirects: int = 5
    dns_server: str | None = None
    user_agent: str = "sitecheck/0.1 (monitor for my own sites)"


@dataclass
class Config:
    path: str
    settings: Settings = field(default_factory=Settings)
    sites: list[Site] = field(default_factory=list)

    def guard(self):
        return Guard(self.sites)

    def pick(self, names):
        if not names:
            return list(self.sites)
        by_name = {s.name: s for s in self.sites}
        missing = [n for n in names if n not in by_name]
        if missing:
            raise ConfigError("not in config: " + ", ".join(missing))
        return [by_name[n] for n in names]


class Guard:
    """Every connection goes through here; anything not in the config is refused."""

    def __init__(self, sites):
        self._hosts = {s.host.lower() for s in sites}
        self._endpoints = set()
        for s in sites:
            self._endpoints.add((s.host.lower(), s.port))
            self._endpoints.add((s.host.lower(), s.http_port))

    def check_host(self, host):
        if (host or "").lower() not in self._hosts:
            raise NotAllowed(f"{host} is not a configured site")

    def check(self, host, port):
        if (str(host).lower(), port) not in self._endpoints:
            raise NotAllowed(f"{host}:{port} is not a configured site endpoint")

    def permits(self, host, port):
        return (str(host).lower(), port) in self._endpoints


def find_config(explicit=None):
    if explicit:
        return explicit
    env = os.environ.get("SITECHECK_CONFIG")
    if env:
        return env
    for name in DEFAULT_NAMES:
        if os.path.exists(name):
            return name
    raise ConfigError("no config found (use --config, SITECHECK_CONFIG or ./sitecheck.toml; 'sitecheck init' writes a sample)")


def _valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.match(host))


def _take(table, allowed, where):
    extra = set(table) - allowed
    if extra:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(extra))}")


def _typed(value, kind, key, where):
    if isinstance(value, bool) or not isinstance(value, kind):
        raise ConfigError(f"{where}: '{key}' has the wrong type")
    return value


def parse(data, path="<memory>"):
    base = os.path.dirname(os.path.abspath(path)) if path != "<memory>" else os.getcwd()
    cfg = Config(path=path)

    raw = data.get("settings", {})
    _take(data, {"settings", "site"}, "config")
    _take(raw, set(Settings.__dataclass_fields__), "[settings]")
    s = cfg.settings
    for key, value in raw.items():
        want = type(getattr(s, key)) if getattr(s, key) is not None else str
        if want is float:
            want = (int, float)
        _typed(value, want, key, "[settings]")
        setattr(s, key, value)
    if not 0 < s.timeout <= 120:
        raise ConfigError("[settings]: timeout must be between 0 and 120 seconds")
    if s.max_redirects < 0 or s.max_redirects > 10:
        raise ConfigError("[settings]: max_redirects must be 0-10")
    if not os.path.isabs(s.db):
        s.db = os.path.join(base, s.db)

    sites = data.get("site", [])
    if not isinstance(sites, list) or not sites:
        raise ConfigError("config lists no sites ([[site]] tables)")
    seen = set()
    for i, raw_site in enumerate(sites, 1):
        where = f"site #{i}"
        _take(raw_site, set(Site.__dataclass_fields__), where)
        for req in ("name", "host"):
            if req not in raw_site:
                raise ConfigError(f"{where}: missing '{req}'")
        site = Site(name=_typed(raw_site["name"], str, "name", where), host=_typed(raw_site["host"], str, "host", where).strip().lower())
        for key in ("port", "http_port"):
            if key in raw_site:
                setattr(site, key, _typed(raw_site[key], int, key, where))
        for key in ("path", "method", "ca_file"):
            if key in raw_site:
                setattr(site, key, _typed(raw_site[key], str, key, where))
        if "check_http_redirect" in raw_site:
            site.check_http_redirect = _typed(raw_site["check_http_redirect"], bool, "check_http_redirect", where)
        if not NAME_RE.match(site.name):
            raise ConfigError(f"{where}: bad name {site.name!r}")
        if site.name in seen:
            raise ConfigError(f"{where}: duplicate name {site.name!r}")
        seen.add(site.name)
        if not _valid_host(site.host):
            raise ConfigError(f"{where}: host must be a bare host name or IP, got {site.host!r}")
        for port in (site.port, site.http_port):
            if not 0 < port < 65536:
                raise ConfigError(f"{where}: port out of range")
        if not site.path.startswith("/") or re.search(r"\s", site.path):
            raise ConfigError(f"{where}: path must start with / and contain no spaces")
        site.method = site.method.upper()
        if site.method not in ("GET", "HEAD"):
            raise ConfigError(f"{where}: method must be GET or HEAD")
        if site.ca_file and not os.path.isabs(site.ca_file):
            site.ca_file = os.path.join(base, site.ca_file)
        cfg.sites.append(site)
    return cfg


def load(path):
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    return parse(data, path)
