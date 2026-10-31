#!/usr/bin/python3 -I
"""Test polkit authentication agent. Registers for the session it runs in and answers every
BeginAuthentication according to the word in $E2E_DIR/mode: "approve" completes the authentication
through polkit's agent helper (the PAM stack accepts anyone), "deny" cancels. Each request is
appended to $E2E_DIR/requests as "<mode> <action>"."""
import os
import socket
import stat
import subprocess
import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

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


class Agent(dbus.service.Object):
    @dbus.service.method("org.freedesktop.PolicyKit1.AuthenticationAgent",
                         in_signature="sssa{ss}sa(sa{sv})", out_signature="")
    def BeginAuthentication(self, action_id, message, icon, details, cookie, identities):
        decision = mode()
        with open(os.path.join(E2E_DIR, "requests"), "a") as f:
            f.write(f"{decision} {action_id}\n")
        if decision != "approve":
            raise dbus.DBusException("denied by the test agent",
                                     name="org.freedesktop.PolicyKit1.Error.Cancelled")
        user = os.environ["USER"]
        out = authenticate(user, cookie)
        if "SUCCESS" not in out:
            raise dbus.DBusException("authentication failed",
                                     name="org.freedesktop.PolicyKit1.Error.Failed")

    @dbus.service.method("org.freedesktop.PolicyKit1.AuthenticationAgent",
                         in_signature="s", out_signature="")
    def CancelAuthentication(self, cookie):
        pass


def main():
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    Agent(bus, PATH)
    session = os.environ["XDG_SESSION_ID"]
    authority = dbus.Interface(
        bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"),
        "org.freedesktop.PolicyKit1.Authority")
    subject = ("unix-session", {"session-id": dbus.String(session)})
    authority.RegisterAuthenticationAgent(subject, "en_US.UTF-8", PATH)
    print("agent registered", flush=True)
    GLib.MainLoop().run()


sys.exit(main())
