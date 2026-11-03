#!/usr/bin/python3 -I
"""Test polkit authentication agent. Registers for the session it runs in and answers every
BeginAuthentication according to the word in $E2E_DIR/mode: "approve" completes the authentication
through polkit's agent helper (the PAM stack accepts anyone), "deny" cancels. Each request is
appended to $E2E_DIR/requests as "<mode> <action>", and (F95) its polkit subject to $E2E_DIR/subjects as
"<action> <polkit.subject-pid> <uid of the identity>"."""
import os
import socket
import stat
import subprocess
import sys

from gi.repository import Gio, GLib

E2E_DIR = os.environ["E2E_DIR"]
PATH = "/org/e2e/Agent"
HELPER = "/usr/lib/polkit-1/polkit-agent-helper-1"
# Polkit 127 (Ubuntu 26.04) has no setuid helper: the agent talks to a root helper that systemd starts per connection on this socket.
HELPER_SOCKET = "/run/polkit/agent-helper.socket"


def authenticate(user, cookie):
    """The reply of polkit's agent helper: through the setuid program if there is one, else through the socket. Both take the
    cookie and an empty password; the socket also takes the user name as the first line."""
    if os.stat(HELPER).st_mode & stat.S_ISUID:
        return subprocess.run([HELPER, user], input=cookie + "\n\n", text=True,
                              capture_output=True, check=False).stdout
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(30)
        s.connect(HELPER_SOCKET)
        s.sendall(f"{user}\n{cookie}\n\n".encode())
        chunks = []
        while chunk := s.recv(4096):
            chunks.append(chunk)
    return b"".join(chunks).decode(errors="replace")


def mode():
    with open(os.path.join(E2E_DIR, "mode")) as f:
        return f.read().strip()


# GLib's own D-Bus (Gio), from python3-gi / python3-gobject-base: the Python D-Bus bindings (python3-dbus) are not in the
# AlmaLinux 10 repositories, and these are on every target.
AGENT_XML = """<node><interface name="org.freedesktop.PolicyKit1.AuthenticationAgent">
  <method name="BeginAuthentication">
    <arg type="s" name="action_id" direction="in"/><arg type="s" name="message" direction="in"/>
    <arg type="s" name="icon_name" direction="in"/><arg type="a{ss}" name="details" direction="in"/>
    <arg type="s" name="cookie" direction="in"/><arg type="a(sa{sv})" name="identities" direction="in"/>
  </method>
  <method name="CancelAuthentication"><arg type="s" name="cookie" direction="in"/></method>
</interface></node>"""
ERROR_CANCELLED = "org.freedesktop.PolicyKit1.Error.Cancelled"
ERROR_FAILED = "org.freedesktop.PolicyKit1.Error.Failed"


def on_call(_conn, _sender, _path, _iface, method, params, invocation):
    if method == "CancelAuthentication":
        invocation.return_value(None)
        return
    action_id, _message, _icon, _details, cookie, _identities = params.unpack()
    decision = mode()
    with open(os.path.join(E2E_DIR, "requests"), "a") as f:
        f.write(f"{decision} {action_id}\n")
    uids = ",".join(str(ident[1].get("uid")) for ident in _identities if ident[0] == "unix-user") or "-"
    with open(os.path.join(E2E_DIR, "subjects"), "a") as f:
        f.write(f"{action_id} {_details.get('polkit.subject-pid', '-')} {uids}\n")
    if decision != "approve":
        invocation.return_dbus_error(ERROR_CANCELLED, "denied by the test agent")
        return
    if "SUCCESS" not in authenticate(os.environ["USER"], cookie):
        invocation.return_dbus_error(ERROR_FAILED, "authentication failed")
        return
    invocation.return_value(None)


def main():
    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    node = Gio.DBusNodeInfo.new_for_xml(AGENT_XML)
    bus.register_object(PATH, node.interfaces[0], on_call, None, None)
    session = os.environ["XDG_SESSION_ID"]
    subject = ("unix-session", {"session-id": GLib.Variant("s", session)})
    bus.call_sync("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                  "org.freedesktop.PolicyKit1.Authority", "RegisterAuthenticationAgent",
                  GLib.Variant("((sa{sv})ss)", (subject, "en_US.UTF-8", PATH)),
                  None, Gio.DBusCallFlags.NONE, -1, None)
    print("agent registered", flush=True)
    GLib.MainLoop().run()


sys.exit(main())
