#!/usr/bin/python3 -I
"""One call of com.rfirma.Custodio1 that the CLI does not offer, for the owner-* cases (F91), made as the user running it on the system bus.
Usage: owner-call.py sign ID [SIGNATURE-FILE] | delete ID | replace ID CERTIFICATE-DER-FILE | import ID P12-FILE PASSWORD
Prints one line: "ok" or "error <D-Bus error name>". Exit 0 when that line was printed, 2 on anything else.

Why not busctl: `busctl call` prints "Call failed: <message>" and drops the error name (docs/findings/F91.md); GLib's D-Bus
(the one agent.py uses, from python3-gi) keeps it. The calls, each with the signature of docs/api.md; none sets the interactive-
authorization flag (Gio.DBusCallFlags.NONE), because the service asks polkit itself, with AllowUserInteraction, and the flag only matters to
the bus-level policy:
  sign     Sign(id s, mechanism u, hash u, salt_len u, data ay) -> ay   as "(suuuay)": CKM_RSA_PKCS 0x0001, hash 0, salt 0, 32 bytes
  delete   DeleteKey(id s)                                              as "(s)"
  replace  ReplaceCertificate(id s, certificate ay)                     as "(say)"
  import   ImportP12(id s, p12 ay, password s) -> s                     as "(says)" (F92: the ops-polkit-* cases)
  list     ListKeys() -> a(sssay)                                       no parameters (F133: prints "ID<TAB>TYPE<TAB>KIND" per key, not "ok")
"""
import sys

from gi.repository import Gio, GLib

NAME = "com.rfirma.Custodio1"
PATH = "/com/rfirma/Custodio1"


def build(argv):
    """(method, parameters) of the call that argv asks for."""
    if len(argv) in (2, 3) and argv[0] == "sign":
        return "Sign", GLib.Variant("(suuuay)", (argv[1], 1, 0, 0, bytes(range(32))))
    if len(argv) == 2 and argv[0] == "delete":
        return "DeleteKey", GLib.Variant("(s)", (argv[1],))
    if len(argv) == 3 and argv[0] == "replace":
        with open(argv[2], "rb") as f:
            der = f.read()
        return "ReplaceCertificate", GLib.Variant("(say)", (argv[1], der))
    if len(argv) == 4 and argv[0] == "import":
        with open(argv[2], "rb") as f:
            p12 = f.read()
        return "ImportP12", GLib.Variant("(says)", (argv[1], p12, argv[3]))
    if argv == ["list"]:
        return "ListKeys", None
    sys.exit("usage: owner-call.py sign ID [SIGNATURE-FILE] | delete ID | replace ID CERTIFICATE-DER-FILE | import ID P12-FILE PASSWORD | list")


def main():
    method, params = build(sys.argv[1:])
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    try:
        reply = bus.call_sync(NAME, PATH, NAME, method, params, None, Gio.DBusCallFlags.NONE, 60000, None)
    except GLib.Error as err:
        remote = Gio.DBusError.get_remote_error(err) if Gio.DBusError.is_remote_error(err) else None
        if remote is None:
            print(f"owner-call: not a D-Bus error reply: {err.message}", file=sys.stderr)
            return 2
        print(f"error {remote}")
        return 0
    if method == "Sign" and len(sys.argv) == 4:  # F94: the signature is kept, for the sweep of the journal
        with open(sys.argv[3], "wb") as f:
            f.write(bytes(reply.unpack()[0]))
    if method == "ListKeys":  # F133: one line per key, "ID<TAB>KEY TYPE<TAB>STORAGE KIND", as the service returned them
        for key_id, key_type, kind, _cert in reply.unpack()[0]:
            print(f"{key_id}\t{key_type}\t{kind}")
        return 0
    print("ok")
    return 0


sys.exit(main())
