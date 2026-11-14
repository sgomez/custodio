#!/usr/bin/python3 -I
"""Self-test of the hand-made D-Bus client of e2e/vm/snap-client.py against a fake peer on a socket in a temporary directory (no bus, no VM).
Usage: snap-dbus-selftest.py DIR-OF-snap-client.py"""
import importlib.util
import os
import sys
import tempfile
import threading
import socket

spec = importlib.util.spec_from_file_location("snap_client", os.path.join(sys.argv[1], "snap-client.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
bad = []


def serve(path, reply_for):
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def run():
        s, _ = srv.accept()
        got = b""
        while b"\r\n" not in got:
            got += s.recv(256)
        s.sendall(b"OK 00\r\n")
        while b"BEGIN\r\n" not in got:
            got += s.recv(256)
        while True:
            try:
                kind, f, _ = c.read_message(s)
            except ConnectionError:
                return
            s.sendall(reply_for(f))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def reply_p2p(f):
    return c.message(3, 9, [(4, "s", "org.freedesktop.DBus.Error.UnknownMethod"), (5, "u", 1), (2, "s", "no such method " + f[3])])


def reply_bus(f):
    if f[3] == "Hello":
        return c.message(2, 8, [(5, "u", 1)])
    return c.message(3, 9, [(4, "s", "org.freedesktop.DBus.Error.AccessDenied"), (5, "u", 2)])


def reply_ok(f):
    return c.message(2, 8, [(5, "u", 1)])


with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "a.sock")
    serve(p, reply_p2p)
    r = c.dbus_call("p2p", "ImportP12", sock_path=p)
    if not r.startswith("error org.freedesktop.DBus.Error.UnknownMethod"):
        bad.append(f"p2p unknown method answered '{r}'")
    p = os.path.join(d, "b.sock")
    serve(p, reply_bus)
    r = c.dbus_call("bus", "ListKeys", uid=1000, sock_path=p)
    if not r.startswith("error org.freedesktop.DBus.Error.AccessDenied"):
        bad.append(f"bus denial answered '{r}'")
    p = os.path.join(d, "c.sock")
    serve(p, reply_ok)
    r = c.dbus_call("p2p", "ListKeys", sock_path=p)
    if r != "ok":
        bad.append(f"a method return answered '{r}'")
    r = c.dbus_call("p2p", "ListKeys", sock_path=os.path.join(d, "missing.sock"))
    if not r.startswith("error FileNotFoundError"):
        bad.append(f"a missing socket answered '{r}'")
for b in bad:
    print(b, file=sys.stderr)
sys.exit(1 if bad else 0)
