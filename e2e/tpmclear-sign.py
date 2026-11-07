#!/usr/bin/python3 -I
"""One Sign call on the system bus for the tpm-clear-* cases (F140), as the user running it. Usage: tpmclear-sign.py ID rsa|ec
Prints one line: "ok", or "error <D-Bus error name>: <message>" (owner-call.py keeps only the name; the message is what docs/api.md documents). Exit 0 when a line was printed.
RSA: CKM_RSA_PKCS (0x1) over 32 bytes; EC: CKM_ECDSA (0x1041) over 32 bytes; no hash, no salt."""
import sys

from gi.repository import Gio, GLib

if len(sys.argv) != 3 or sys.argv[2] not in ("rsa", "ec"):
    sys.exit(__doc__)
mechanism = 0x1 if sys.argv[2] == "rsa" else 0x1041
bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
try:
    bus.call_sync("com.rfirma.Custodio1", "/com/rfirma/Custodio1", "com.rfirma.Custodio1", "Sign",
                  GLib.Variant("(suuuay)", (sys.argv[1], mechanism, 0, 0, bytes(range(32)))), None, Gio.DBusCallFlags.NONE, 60000, None)
except GLib.Error as err:
    if not Gio.DBusError.is_remote_error(err):
        print(f"tpmclear-sign: not a D-Bus error reply: {err.message}", file=sys.stderr)
        sys.exit(2)
    name = Gio.DBusError.get_remote_error(err)
    message = err.message.removeprefix(f"GDBus.Error:{name}: ")  # GLib puts the error name in front of the service's message
    print(f"error {name}: {message}")
    sys.exit(0)
print("ok")
