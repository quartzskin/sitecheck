import http.server
import os
import shutil
import ssl
import subprocess
import threading
from typing import ClassVar

import pytest

from sitecheck.config import Guard, Settings, Site

CANDIDATES = [
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
]


def find_openssl():
    return shutil.which("openssl") or next((p for p in CANDIDATES if os.path.exists(p)), None)


def make_certs(d, days=30, san="IP:127.0.0.1,DNS:localhost"):
    exe = find_openssl()
    if not exe:
        pytest.skip("openssl not available")

    def run(*args):
        subprocess.run([exe, *args], cwd=d, check=True, capture_output=True, env={**os.environ, "MSYS_NO_PATHCONV": "1"})

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "365",
        "-subj", "/O=Test Org/CN=Test Root", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost")
    with open(os.path.join(d, "ext.cnf"), "w") as fh:
        fh.write(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.pem",
        "-days", str(days), "-extfile", "ext.cnf")
    return os.path.join(d, "leaf.pem"), os.path.join(d, "leaf.key"), os.path.join(d, "ca.pem")


class Handler(http.server.BaseHTTPRequestHandler):
    routes: ClassVar[dict] = {}
    hits: ClassVar[list] = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).hits.append(("GET", self.path))
        status, headers, body = self.routes.get(self.path, (404, {}, b"nope"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        type(self).hits.append(("HEAD", self.path))
        status, headers, _ = self.routes.get(self.path, (404, {}, b""))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()


def serve(routes, tls=None):
    handler = type("H", (Handler,), {"routes": routes, "hits": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls[0], tls[1])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.hits = handler.hits
    return srv


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    return make_certs(str(tmp_path_factory.mktemp("pki")))


GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


@pytest.fixture
def https_server(certs):
    srv = serve({"/": (200, GOOD_HEADERS, b"hello"), "/old": (301, {"Location": "/"}, b""),
                 "/away": (302, {"Location": "https://other.invalid/"}, b"")}, tls=certs[:2])
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def http_server():
    srv = serve({"/": (301, {"Location": "https://127.0.0.1/"}, b"")})
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def settings():
    return Settings(timeout=3)


def make_site(port, ca, **kw):
    return Site(name="t", host="127.0.0.1", port=port, ca_file=ca, **kw)


def make_guard(*sites):
    return Guard(list(sites))
