import ipaddress
import os
import random
import re
import socket
import struct
import subprocess

A, AAAA, CAA = 1, 28, 257


class DnsError(Exception):
    pass


def build_query(name, qtype, qid):
    labels = name.rstrip(".").encode("idna").decode("ascii").split(".")
    body = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + body + struct.pack("!HH", qtype, 1)


def read_name(data, pos):
    labels, end, jumps = [], None, 0
    while True:
        if pos >= len(data):
            raise DnsError("name runs past end of packet")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > 32:
                raise DnsError("compression loop")
            continue
        labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if end is not None else pos)


def parse_response(data, qid):
    try:
        rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        if rid != qid or not flags & 0x8000:
            raise DnsError("reply does not match the query")
        if flags & 0x0200:
            raise DnsError("reply truncated")
        pos = 12
        for _ in range(qd):
            _, pos = read_name(data, pos)
            pos += 4
        answers = []
        for _ in range(an):
            _, pos = read_name(data, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(data):
                raise DnsError("record runs past end of packet")
            answers.append((rtype, data[pos:pos + rdlen]))
            pos += rdlen
        return flags & 0xF, answers
    except struct.error as exc:
        raise DnsError("short or malformed reply") from exc


def query(name, qtype, server, timeout):
    qid = random.randrange(65536)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_query(name, qtype, qid), server)
            data, _ = sock.recvfrom(4096)
        except OSError as exc:
            raise DnsError(f"resolver {server[0]}: {exc}") from exc
    return parse_response(data, qid)


def parse_caa(rdata):
    if len(rdata) < 2 or 2 + rdata[1] > len(rdata):
        raise DnsError("bad CAA record")
    tag = rdata[2:2 + rdata[1]].decode("ascii", "replace")
    return f'{tag} "{rdata[2 + rdata[1]:].decode("utf-8", "replace")}"'


def caa_records(host, server, timeout):
    labels = host.split(".")
    for i in range(len(labels) - 1):
        rcode, answers = query(".".join(labels[i:]), CAA, server, timeout)
        if rcode not in (0, 3):
            raise DnsError(f"resolver answered rcode {rcode}")
        found = [parse_caa(r) for t, r in answers if t == CAA]
        if found:
            return found
    return []


def system_resolver():
    if os.name == "nt":
        try:
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        for line in out.splitlines():
            m = re.search(r"DNS.*:\s*(\d+\.\d+\.\d+\.\d+)\s*$", line)
            if m:
                return m.group(1)
        return None
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                m = re.match(r"\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def addresses(host, family):
    try:
        info = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in info})


def check_dns(host, guard, settings):
    guard.check_host(host)
    out = {"a": addresses(host, socket.AF_INET), "aaaa": addresses(host, socket.AF_INET6), "caa": [], "caa_checked": False, "caa_error": None}
    try:
        ipaddress.ip_address(host)
        out["caa_error"] = "ip address"
        return out
    except ValueError:
        pass
    server = settings.dns_server or system_resolver()
    if not server:
        out["caa_error"] = "no resolver found"
        return out
    ip, _, port = server.partition(":") if server.count(":") == 1 else (server, "", "")
    try:
        out["caa"] = caa_records(host, (ip, int(port) if port else 53), settings.timeout)
        out["caa_checked"] = True
    except DnsError as exc:
        out["caa_error"] = str(exc)
    return out
