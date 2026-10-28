# A system custodian with polkit for imported keys on Linux

Question: can Custodio put, in front of every signature with a key imported from a `.p12`, a
human-presence barrier that a process of the same user cannot get around? The design is a system
service that keeps the key under its own uid, receives only the hash —the client builds and
finishes the signed document— and asks polkit for authorization before signing it. Without it, the
key lives in a `.p12` or a software token whose PIN the desktop keyring hands to any process in the
session.

Threat model: an unprivileged process with the person's uid (for example, an AI agent with a
shell). It wins if it gets a signature the person did not approve, or captures the secret the person
approves it with. Out of scope: root, physical access and a compromised kernel.

Everything here was **read** in source code or primary documentation, at the commits each link
cites (October 2026). **Nothing was measured**: there was no Linux VM at hand. The experiment that
would confirm each claim is in [Pending experiments](#pending-experiments).

## Verdict

**With a password, no: the polkit dialog is not a trusted path against a process of the same uid,
in any session.** polkit lets any process register an authentication agent for another process of
the same user, and that agent takes precedence over GNOME Shell's or KDE's: the attacker receives
the dialog of the legitimate signature, draws its own and keeps the password, without `ptrace` or
persistence. With it, the attacker signs whenever it wants through its own agent. It also has other
routes: GNOME Shell's gcr prompter draws a modal identical to polkit's for anyone who asks, Mutter
and KWin accept keyboard injection from unsandboxed clients, and the compositor and the agent run
with the person's uid, who controls how they start. **With a physical factor that leaves no
reusable secret (fingerprint with `pam_fprintd`, FIDO key with `pam_u2f`), Custodio does guarantee
presence** —no finger or touch, no signature, on Wayland, X11 or a TTY— **but never intent**: it
signs the hash it receives, the attacker controls which hash arrives, and no polkit dialog can show
the document. And Custodio does not choose that factor: the system's `polkit-1` PAM stack does. The
package works everywhere as `.deb` and `.rpm`, costs a layer or a sysext on immutable distributions,
needs a separate host package for flatpak clients (no portal fits) and, as a snap, depends on the
store granting two interfaces. What Custodio gives regardless of all that is **a key that cannot be
copied**: the attacker goes from taking the key away to using it only while it is inside the
machine, and that holds even with no dialog.

## Session × package

"Protects" refers to the presence barrier. Each cell has two values: with a password in the PAM
stack / with a physical factor (fingerprint or FIDO). No cell protects intent (section 5).

| Session \ package | `.deb` / `.rpm` | flatpak client | snap | immutable |
|---|---|---|---|---|
| GNOME Wayland | no / yes | no / yes, with the host package | no / yes, if the store grants `polkit` and `dbus` | no / yes, with a layer or sysext |
| KDE Wayland | no / yes | same as GNOME | same as GNOME | same as GNOME |
| XWayland attacker in a Wayland session | no / yes | same | same | same |
| X11 | no / yes | same | same | same |
| TTY | no / yes | n/a: graphical clients | n/a | no / yes |

The rows barely differ, and that is not an oversight. The differences between Wayland and X11
(sections 1 and 2) decide whether the attacker can **read keystrokes** or **press buttons**, but the
route that steals the password —the per-process agent— does not go through the screen, and a
physical factor is not typed. The packaging decides the column (section 3); the row decides almost
nothing.

## Revision: an agent that makes mistakes, not an attacker

The verdict and the table answer a hostile attacker. The real problem is more modest: an AI agent
with a shell **signing by mistake**. Such an agent does not register a fake polkit agent or inject
keystrokes, but it does look for workarounds when something blocks it, such as pulling a secret
with `secret-tool` or signing with a `.p12` it finds on disk. Under this model two things change:

- **polkit is enough, with a password or a fingerprint.** Hijacking the dialog (section 1) takes
  intent; a mistaken agent does not do it. The action must be `auth_self` or `auth_admin`, never the
  `_keep` variants, or the second signature passes without asking
  ([polkit(8)](https://man.archlinux.org/man/polkit.8.en)).
- **What Custodio really adds is moving the key out of the user's reach.** While the `.p12` or a
  token PIN is at hand, the agent can sign without going through Custodio. Custodio prevents it if,
  after importing, the person deletes the original `.p12`.

Intent is still unprotected: Custodio signs the hash it receives (section 5).

## Custodio as a PKCS#11 token

Presented as a PKCS#11 token, Custodio is just another token for any PKCS#11 program, with no
client-specific code. `C_Sign` is where authorization is requested. PKCS#11 already provides
per-signature authorization with `CKA_ALWAYS_AUTHENTICATE` and `C_Login(CKU_CONTEXT_SPECIFIC)`
([PKCS#11 3.0](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html));
**not verified** that NSS and OpenSSL honour it.

The service needs the caller's identity (pid or pidfd and uid) to build the polkit subject. There
are two transports.

### (A) `p11-kit server` with our module inside

At p11-kit commit `7b24bd5`:

- On accept, `check_credentials` compares the client's uid and gid (`SO_PEERCRED`) with a single
  `--user`/`--group`, and only if the server created the socket: with systemd activation it checks
  nothing ([server.c#L407-L438](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/server.c#L407-L438),
  [#L633-L635](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/server.c#L633-L635)).
- It then `fork()`s, duplicates the socket onto stdin and stdout and runs `p11-kit remote`, which
  keeps it for the whole connection
  ([server.c#L637-L688](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/server.c#L637-L688),
  [remote.c#L113-L158](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/remote.c#L113-L158)).
  A module loaded there can read the identity with `getsockopt(0, SOL_SOCKET, SO_PEERPIDFD)`. No API
  guarantees it: it is a p11-kit internal. **Not tested at runtime.**
- There is no intended way to pass the identity to the module: the client controls `pReserved`, and
  in per-token mode it is lost
  ([proxy.c#L349](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/proxy.c#L349)).
- Its units are user units
  ([p11-kit-server.socket](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/p11-kit-server.socket)):
  a system service needs its own, with a socket open to every uid and the filter in our module.
- What it saves is the client: `p11-kit-client.so`, or `remote: unix:path=…` in a `.module`
  ([rpc-transport.c#L1263-L1301](https://github.com/p11-glue/p11-kit/blob/7b24bd57a9fe789e053734e9223b0d4322e6484e/p11-kit/rpc-transport.c#L1263-L1301)).
  It ships in Debian, Ubuntu, Fedora and Arch, and the flatpak runtime builds it
  ([p11-kit.bst](https://gitlab.com/freedesktop-sdk/freedesktop-sdk/-/blob/master/elements/components/p11-kit.bst);
  **not checked** in the installed tree). The service still has to implement a full PKCS#11 module.

### (B) Our own module talking to the service over the system D-Bus

- The service passes polkit a `system-bus-name` subject with the sender, and polkit fetches the
  credentials and the `ProcessFD` itself
  ([polkitsystembusname.c#L505-L564](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkit/polkitsystembusname.c#L505-L564)).
  Needs polkit ≥ 124 and a bus with `ProcessFD`: dbus-daemon ≥ 1.15.8 or dbus-broker ≥ 34.
- zbus provides `get_connection_credentials()` with `process_fd()`
  ([dbus.rs](https://github.com/dbus2/zbus/blob/a7108e0ea5f84bd53c76d8415bcb8bd8ff51af51/zbus/src/fdo/dbus.rs#L276-L284)).
- Bus policy, activation and a dedicated uid are conventional, as in fwupd or fprintd.
- **Flatpak clients:** with `--system-talk-name`, the service sees xdg-dbus-proxy's credentials,
  not the app's ([flatpak-proxy.c#L36-L42](https://github.com/flatpak/xdg-dbus-proxy/blob/72b40c8f6d9d585cfbdb249690724f740d207087/flatpak-proxy.c#L36-L42)).
  The uid and session are right, and that is enough to know who signs. Flathub's linter accepts a
  custom name in `--system-talk-name`, but a person moderates it and rejects apps that depend on the
  host for their main function
  ([requirements](https://docs.flathub.org/docs/for-app-authors/requirements)). For a signing app
  where Custodio is optional, it is not the main function.
- The `.so` carries a D-Bus client into third-party processes (Firefox, LibreOffice): threads and
  `fork` need care. **Not verified** in those programs.
- Template: [siguldry-pkcs11](https://github.com/fedora-infra/siguldry/blob/762ea937897a7e215eab82d9cff6a0a02ceade04/siguldry-pkcs11/src/lib.rs#L336-L337),
  from Fedora's infrastructure, in Rust with `cryptoki-sys`, which exports only signing and forwards
  to a system service over a socket. [native-pkcs11](https://github.com/google/native-pkcs11) offers
  a `Backend` trait as an alternative.

### Recommendation

**(B).** Identity and polkit fit without tricks, following the standard pattern of system services.
(A) saves the client `.so`, but depends on a p11-kit internal, is designed for a per-user server and
does not avoid implementing PKCS#11 in the service.

---

## 1. Trusted path

### The attacker can register the agent that receives the dialog

`RegisterAuthenticationAgent` accepts two scopes: the session and a process. For the session, polkit
requires the caller to be in it; **for a process, the check is "explicitly OK"** and only requires
the caller's user and the process's user to match
([`polkitbackendinteractiveauthority.c` L2781-L2856](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L2781-L2856)).
The only thing it prevents is a second agent **for the same scope** ("An authentication agent
already exists for the given subject", L2849-L2856): that is why a process cannot register for the
session while gnome-shell
([`shell-polkit-authentication-agent.c` L95-L112](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/216e6d957fe534ac7bbfaf1187472585586935f9/src/shell-polkit-authentication-agent.c#L95-L112))
or `polkit-kde-authentication-agent-1`
([`main.cpp` L69-L71](https://invent.kde.org/plasma/polkit-kde-agent-1/-/blob/25ca2c79fe33a695f14c0ffb610b9cf8d3658408/main.cpp#L69-L71))
holds it. But the process scope is free, and when looking for an agent **polkit checks the
process's first** —also when the subject is a bus name, which resolves to its process— and only then
the session's
([L1910-L1960](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L1910-L1960)).
`pkttyagent --process <pid>` does exactly that
([`pkttyagent.c` L94-L174](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/programs/pkttyagent.c#L94-L174)).

The attack: the attacker registers an agent for the signing client's pid. When the person signs,
Custodio calls `CheckAuthorization` with the client as subject, and polkit delivers
`BeginAuthentication` **to the attacker's agent**, which draws its own dialog and receives the
password.

### What the agent cannot do: answer without the secret

Answering is protected. `AuthenticationAgentResponse2` is accepted only from uid 0
([L3131-L3138](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L3131-L3138)),
that is, from `polkit-agent-helper-1`, which runs the `polkit-1` PAM stack
([`polkitagenthelper-pam.c` L218](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitagent/polkitagenthelper-pam.c#L218))
as setuid or, in recent versions, as a tightly confined socket-activated service
([`polkit-agent-helper@.service.in`](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/data/polkit-agent-helper@.service.in)).
A fake agent **approves nothing without going through PAM**. The problem is not the answer but the
capture: with the stolen password, the attacker registers an agent for its own process, calls
Custodio and gives the password to the helper. And if the person is an administrator, the same
password opens `sudo`, which is already out of the model.

### The other routes, which the per-process agent makes unnecessary

- **A genuine system dialog on demand (GNOME).** GNOME Shell implements
  `org.gnome.keyring.SystemPrompter` on the session bus and draws, with its own widgets, whatever
  title, message and description any client asks for
  ([`keyring.js` L15-L113 and L201-L223](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/216e6d957fe534ac7bbfaf1187472585586935f9/js/ui/components/keyring.js#L201-L223));
  `pinentry-gnome3` uses it that way. Looking like a system modal proves nothing about its origin.
- **Keyboard injection on GNOME Wayland.** `org.gnome.Mutter.RemoteDesktop.CreateSession` does not
  check who calls: the only check on the session is that the bus name that created it uses it
  ([`meta-remote-desktop.c` L51-L80](https://gitlab.gnome.org/GNOME/mutter/-/blob/2b9c0787f99dacef16ba987656e28ffcb344b9a2/src/backends/meta-remote-desktop.c#L51-L80),
  [`meta-remote-desktop-session.c` L410-L416](https://gitlab.gnome.org/GNOME/mutter/-/blob/2b9c0787f99dacef16ba987656e28ffcb344b9a2/src/backends/meta-remote-desktop-session.c#L410-L416)).
  Mutter has a sender checker, but applies it only to the accessibility manager
  ([`meta-a11y-manager.c` L409-L411](https://gitlab.gnome.org/GNOME/mutter/-/blob/2b9c0787f99dacef16ba987656e28ffcb344b9a2/src/backends/meta-a11y-manager.c#L409-L411)).
  **Not measured** whether the virtual keyboard reaches polkit's modal dialog.
- **Injection on KDE Wayland.** KWin restricts `org_kde_kwin_fake_input` and the
  `zkde_screencast_unstable_v1` screen capture, but **only denies them to sandboxed clients**; a
  normal client gets them
  ([`wayland_server.cpp` L132-L163](https://invent.kde.org/plasma/kwin/-/blob/3bdf5cd0640673a0dac755fcb76a76b9b80751c2/src/wayland_server.cpp#L132-L163)).
- **`/dev/uinput` with Steam installed.** The `steam-devices` rule gives `uaccess` to `/dev/uinput`
  ([`60-steam-input.rules` L5](https://github.com/ValveSoftware/steam-devices/blob/22ec85e5ff5ea2e15c56d71a41bcbef46356cd60/60-steam-input.rules#L5)):
  the session user can create a virtual keyboard the kernel treats as a physical one, in any session
  and any VT.
- **`ptrace` on the compositor or the agent.** KDE's agent is a separate user process; GNOME's lives
  inside gnome-shell, also a user process. With `kernel.yama.ptrace_scope=0`, a process of the same
  uid reads their memory. Fedora has always run with 0 through the `elfutils-default-yama-scope`
  subpackage, and there is a change under way to drop it
  ([rhbz#2461722](https://bugzilla.redhat.com/show_bug.cgi?id=2461722)); the default on Debian,
  Ubuntu and openSUSE is **not verified**.
- **The user owns session startup.** Even with `ptrace` restricted, gnome-shell loads extensions
  from `~/.local/share/gnome-shell/extensions`
  ([`fileUtils.js`](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/main/js/misc/fileUtils.js)),
  and KDE's agent is a systemd user unit
  ([`plasma-polkit-agent.service.in`](https://invent.kde.org/plasma/polkit-kde-agent-1/-/blob/25ca2c79fe33a695f14c0ffb610b9cf8d3658408/plasma-polkit-agent.service.in))
  that a drop-in in `~/.config/systemd/user/` changes
  ([systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)).
  At the next login, the attacker runs inside the component that draws the dialog.

### XWayland as the attacker

Through the X protocol, an XWayland client does not see the dialog: it gets no keys from Wayland
surfaces, and XTest only leaves the X server if Xwayland starts with `-enable-ei-portal`
([Xwayland(1)](https://gitlab.freedesktop.org/xorg/xserver/-/blob/master/hw/xwayland/man/Xwayland.man)),
which Mutter passes when built with it
([`meta-xwayland.c` L923-L928](https://gitlab.gnome.org/GNOME/mutter/-/blob/2b9c0787f99dacef16ba987656e28ffcb344b9a2/src/wayland/meta-xwayland.c#L923-L928)),
and then goes through the remote desktop portal, which asks for consent. But the attacker is not
"an X client": it is a process that also speaks D-Bus, registers polkit agents and writes to
`~/.config`. Everything above works for it just the same. **The XWayland/Wayland distinction only
matters if the process is sandboxed** —a flatpak without the session bus, for example— and that is
no longer this threat model.

## 2. X11

A flat no. On X11, XInput 2.1 raw events reach any client **even while another holds a keyboard
grab** ([XI2proto.txt L2579-L2583](https://gitlab.freedesktop.org/xorg/proto/xorgproto/-/blob/6d3907b6d5dc4aa7d7ee6ee5d7d8714e7466630b/specs/XI2proto.txt#L2579-L2583)):
the dialog's keyboard grab does not stop keylogging, and XTest injects events the server treats as
coming from the device. gcr prompts change nothing, because on X11 they are drawn by just another
client. Another VT would be a trusted path, but neither polkit nor its agents use one, and the
per-process agent of section 1 makes it pointless. With a physical factor, X11 is the same as
Wayland: a fingerprint cannot be injected.

How many people are still on X11, with each distribution's sources:

- **GNOME** removed the X11 session in GNOME 50, after disabling it by default at build time in 49
  (summarised by Fedora's change: [Changes/WaylandOnlyGNOME](https://fedoraproject.org/wiki/Changes/WaylandOnlyGNOME)).
- **Fedora 43** dropped GNOME's X11 session packages
  ([release notes](https://docs.fedoraproject.org/en-US/fedora/f43/release-notes/desktop/)).
- **Ubuntu 25.10** dropped "Ubuntu on Xorg"
  ([announcement](https://discourse.ubuntu.com/t/ubuntu-25-10-drops-support-for-gnome-on-xorg/62538));
  24.04 LTS still offers it.
- **KDE Plasma 6.8** is Wayland-only and 6.7 is the last series with an X11 session. **No primary
  source found**: only press ([Phoronix](https://www.phoronix.com/news/KDE-Plasma-68-Wayland-Exclusive)).
- **Debian 13 and openSUSE**: **not verified**. Xfce, MATE and Cinnamon are still X11 in practice.

## 3. Package reach

### `.deb` and `.rpm`

The easy case. The package installs, all under `/usr`:

- a systemd system unit, with `DynamicUser=` and `StateDirectory=` so the key lives in a directory
  only the service uid can read
  ([systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html));
- the system bus policy in `/usr/share/dbus-1/system.d/` and, for bus activation, the `.service` in
  `/usr/share/dbus-1/system-services/`;
- the action in `/usr/share/polkit-1/actions/`, with `org.freedesktop.policykit.owner` pointing to
  Custodio's uid, because without that annotation only root can ask about another user or pass
  *details*
  ([polkit(8)](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/docs/man/polkit.xml#L465-L484),
  [L1104-L1145](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L1104-L1145)).
  With `DynamicUser=` the uid changes, so Custodio needs a fixed system user (`sysusers.d`) or runs
  as root.

The action must be `auth_self` or `auth_admin`, never `*_keep`: with `_keep`, polkit approves for a
few minutes any check of the same action and subject
([polkit(8) L602-L612](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/docs/man/polkit.xml#L602-L612)),
which turns one approval into a burst of signatures.

### flatpak clients

- **A flatpak app can talk to Custodio.** `--system-talk-name=<name>` is a flatpak permission
  ([`flatpak-context.c`](https://github.com/flatpak/flatpak/blob/13b1eeb0a19b91660e82fe4162ba3b413a13e72d/common/flatpak-context.c#L2560)),
  and Flathub's linter does not veto a custom name: it only blocks wildcards and the
  `org.freedesktop.DBus`, `org.freedesktop.impl.portal.` and similar prefixes
  ([Flathub linter](https://docs.flathub.org/docs/for-app-authors/linter)).
- **What Custodio sees.** The system bus goes through `xdg-dbus-proxy`, so the connection's pid is
  the proxy's, not the app's. flatpak starts that proxy inside a bwrap with the same
  `/.flatpak-info` as the app
  ([`flatpak-run-dbus.c` L29-L31 and L102](https://github.com/flatpak/flatpak/blob/13b1eeb0a19b91660e82fe4162ba3b413a13e72d/common/flatpak-run-dbus.c#L29-L102)),
  which the app cannot modify
  ([`flatpak-run.c` L1665-L1698](https://github.com/flatpak/flatpak/blob/13b1eeb0a19b91660e82fe4162ba3b413a13e72d/common/flatpak-run.c#L1665-L1698)):
  reading `/proc/<pid>/root/.flatpak-info`, Custodio learns the app-id. polkit pins the process with
  the `ProcessFD` from `GetConnectionCredentials`
  ([`polkitsystembusname.c` L509-L561](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkit/polkitsystembusname.c#L509-L561))
  and, if that process is not in a logind session —user manager processes are not—, uses the uid's
  graphical session
  ([`polkitbackendsessionmonitor-systemd.c` L385-L424](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendsessionmonitor-systemd.c#L385-L424)).
- **The app-id does not authenticate the app.** `flatpak run --command=sh <app-id>` gives the
  attacker a shell with the same `/.flatpak-info`. Restricting Custodio to "calls from a given
  flatpak" stops nobody.
- **No portal fits.** xdg-desktop-portal has none for signing with a custodied key; the secrets
  portal only hands a secret to the app, which is the model Custodio replaces.
- **A host package is required.** A flatpak cannot install systemd units, bus policies or polkit
  actions. Custodio has to arrive as a separate `.deb`, `.rpm` or sysext. A client detects it by
  asking the system bus's `org.freedesktop.DBus` for `NameHasOwner` or `ListActivatableNames`, which
  the proxy always lets through, and if it is missing, shows how to install it. Bitwarden documents
  the same route for its flatpak: copying its `.policy` by hand into `/usr/share/polkit-1/actions/`
  ([Bitwarden](https://bitwarden.com/help/biometrics/)).

### snap

- A strict snap can be Custodio: its daemons start as root and can drop to `snap_daemon`
  ([System usernames](https://snapcraft.io/docs/system-usernames)).
- Owning a name on the system bus needs the `dbus` slot, whose connection is denied by default when
  it carries a name
  ([`dbus.go` L36-L46](https://github.com/canonical/snapd/blob/8d4d073ab30352e6cbab9343f7197c1488082560/interfaces/builtin/dbus.go#L36-L46));
  on a classic system it can answer unconfined clients, such as a client installed from a `.deb`
  (L119-L139).
- Installing the polkit action needs the `polkit` plug with `action-prefix`, which has
  `allow-installation: false` in the base declaration
  ([`polkit.go` L47-L61](https://github.com/canonical/snapd/blob/8d4d073ab30352e6cbab9343f7197c1488082560/interfaces/builtin/polkit.go#L47-L61)):
  without a Snap Store grant it does not install.
- **Not verified:** how a strictly confined client snap connects to Custodio's slot.

### Immutable distributions

Everything Custodio installs lives under `/usr`, which a
[systemd-sysext(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-sysext.html)
extension overlays; on Silverblue or Kinoite the other route is an `rpm-ostree install` layer.
systemd, the bus and polkit must be reloaded after merging the extension. **Not verified**: sysext
support on Fedora Atomic and SteamOS, and whether SteamOS keeps anything installed with `pacman`
after an update.

## 4. TPM 2.0

- **Import, without the key ever leaving again.** `TPM2_Import` takes an external key wrapped for a
  TPM parent and returns a blob only that TPM can decrypt; `tpm2_import` does it from a PEM, with RSA
  1024 to 4096 and ECC P-192 to P-521 depending on what the chip supports
  ([`tpm2_import.1.md`](https://github.com/tpm2-software/tpm2-tools/blob/915443b32e04fb4c8ddee80b653b234669395a6a2/man/tpm2_import.1.md)).
  The key passes in the clear through Custodio's memory once, at import. `TPM2_LoadExternal` does not
  fit: it loads the key into the null hierarchy, and it has to be given in the clear again on every
  boot ([TPM 2.0 Library, part 3](https://trustedcomputinggroup.org/resource/tpm-library-specification/)).
- **Algorithms.** The PC Client profile requires RSA 2048 and 3072 (3072 since 1.05), P-256 and
  P-384 (P-384 since 1.04) and SHA-384 (since 1.04); SHA-512 is optional and RSA 4096 is absent
  ([PTP 1.06, tables 3 and 4, pp. 16-17](https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-TPM-Profile-for-TPM-2.0-Version-1.06-Revision-32_5April24.pdf)).
  The FNMT issues citizen certificates with RSA 2048 (AC FNMT Usuarios) and ECC P-256 (AC Usuarios
  G2) ([DPC for citizens §6.1.5](https://www.sede.fnmt.gob.es/documents/10445900/10536309/dpc_personasfisicas.pdf),
  [certificate profiles](https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_ac_usuarios.pdf)),
  which fit any conformant TPM. **Not verified** which older TPMs or firmware TPMs (fTPM, PTT) miss
  1.04, and what happens with a SHA-512 signature on a TPM that lacks it.
- **Libraries.** `tpm2-tss` (ESAPI/FAPI), `tpm2-pkcs11`, `tpm2-openssl` and, in Rust,
  [`tss-esapi`](https://docs.rs/tss-esapi), which wraps ESAPI. With `tpm2-pkcs11`, Custodio would sign
  through the same PKCS#11 calls it already makes for a software store.
- **Access.** `/dev/tpmrm0` is `0660` group `tss`
  ([`tpm-udev.rules`](https://github.com/tpm2-software/tpm2-tss/blob/2b10cb16e187ec097f1915005d6d91018f9033cd/dist/tpm-udev.rules)):
  Custodio gets in with `SupplementaryGroups=tss`.
- **The TPM gives no presence.** A key's `authValue` is a PIN typed in the user's software, so it
  has the same problem as the password in section 1. The TPM protects the **copy**, not the **use**.
- **Without a TPM**, the key in a file owned by Custodio's uid is still safe from this model's
  attacker, who is not root. What is lost is outside the model: root reads it, it travels in
  backups of `/var/lib` and on an unencrypted disk, and there is no attempt limit.
- **Fallback with `systemd-creds`**, when there is no TPM or the chip lacks the algorithm: the key
  file is encrypted with a key bound to the TPM, if there is one, or with the host key
  (`/var/lib/systemd/credential.secret`)
  ([systemd-creds(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)).
  Bound to the TPM, it protects the key in backups and on a stolen disk. With the host key, a backup
  of `/var/lib` takes both. Either way Custodio decrypts the key in its memory to sign, and root can
  take it; with `TPM2_Import`, it cannot.
- **Import is the weak point, with or without a TPM.** The `.p12` and its password pass through the
  person's session at import, and the `.p12` often stays in `~/Downloads`. If the attacker was
  present at import, or the file is still there, Custodio protects nothing.

## 5. What the person sees in the dialog

- **Custodio writes the text, not the client.** polkit replaces the action's message with the
  `polkit.message` detail (translated with `polkit.gettext_domain`) and fills `$(key)` from the
  *details*
  ([L2308-L2340](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L2308-L2340)),
  but only accepts *details* from uid 0 or the action's owner
  ([L1104-L1145](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitbackend/polkitbackendinteractiveauthority.c#L1104-L1145)).
  An arbitrary client cannot change the text. JavaScript rules read the *details* and decide the
  result, but not the message.
- **What Custodio knows about the document, it knows from the attacker.** Custodio receives a hash
  and, at most, a name the client sends. If the attacker controls the client —`ptrace`,
  `LD_PRELOAD`, a `.desktop` in `~/.local/share/applications`— or talks to Custodio directly, it
  chooses both. A dialog saying "Sign contract.pdf" would show whatever the attacker wanted.
- **No person can check a hash fingerprint.** There is nothing to compare it against.
- **The realistic attack is substitution.** The attacker waits until the person really signs and
  swaps the hash: the dialog appears when expected, the person approves and the attacker's
  signature comes out. polkit cannot prevent it because it does not see the document, and neither
  does Custodio.
- On top of that, GNOME Shell does not even show the *details*, only the message
  ([`polkitAgent.js` L439-L452](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/216e6d957fe534ac7bbfaf1187472585586935f9/js/ui/components/polkitAgent.js#L439-L452));
  KDE shows the action id and the vendor under "Details".

What the dialog can claim, truthfully, is **one signature per approval**: with `auth_self`, without
`_keep`, each hash asks for its own authentication.

## 6. Fingerprint

`pam_fprintd` enters the `polkit-1` stack, which includes the system authentication stack
([`polkit-1.in`](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/data/polkit-1.in)):
on Fedora with `authselect enable-feature with-fingerprint`; on Debian and Ubuntu with
`libpam-fprintd`'s profile in `pam-auth-update`. GNOME Shell shows PAM's informational messages in
the dialog ([`polkitAgent.js` L305-L313](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/216e6d957fe534ac7bbfaf1187472585586935f9/js/ui/components/polkitAgent.js#L305-L313)).
**Not measured** on either family.

It fits, and it is the only way Custodio is any use against this attacker, within these limits:

- **Presence, not intent.** The attacker can request a signature just when it expects the person to
  touch the reader for another reason, or show a fake "unlock with your fingerprint" dialog. It wins
  one signature per touch, not the key or a reusable secret.
- **No binding to the operation**, as seen in section 5.
- **Custodio does not decide it.** The `polkit-1` PAM service is one for the whole system
  ([`polkitagenthelper-pam.c` L218](https://github.com/polkit-org/polkit/blob/cbeec50d18f93c2e43ff5ed58ac9e3a6a2933eed/src/polkitagent/polkitagenthelper-pam.c#L218)).
  If the stack accepts the password as an alternative to the fingerprint, the attacker picks the
  password, and Custodio does not know which factor approved it.
- The same holds for a FIDO key with [`pam_u2f`](https://developers.yubico.com/pam-u2f/) requiring
  a touch.

For the physical factor not to depend on the PAM configuration, Custodio would have to talk to
`fprintd` or the FIDO key directly, without polkit. **Not studied.**

## 7. Prior art

- **`ssh-add -c`**: the agent asks for confirmation through `ssh-askpass` on every use
  ([ssh-add(1)](https://man.openbsd.org/ssh-add)). The askpass runs as the user: the same problem as
  here. OpenSSH's FIDO keys (`-sk`) require touching the key by default
  ([ssh-keygen(1)](https://man.openbsd.org/ssh-keygen), `no-touch-required`), which is the sound
  equivalent: physical presence, no secret to steal.
- **`tpm2-pkcs11`**: keys in the TPM, protected by a user PIN. It does not custody them in a service
  or ask for presence.
- **`run0` and `systemd-homed`**: use polkit to elevate or unlock. Their barrier is the same as
  here and, against a process of the same uid, just as weak.
- **gnome-keyring and gcr**: anyone can use the system prompter (section 1); it proves no origin. By
  design, it does not isolate one app from another inside the session
  ([SecurityPhilosophy](https://wiki.gnome.org/Projects/GnomeKeyring/SecurityPhilosophy)).
- **Keyrings and the TPM.** None keeps secrets inside the TPM: where there is a TPM, it only seals
  the master password to unlock without typing it, and then the secret leaves in the clear for a
  user process.
  - **gnome-keyring and KWallet (KF6)**: no TPM upstream, only third-party workarounds
    ([tpm-keyring-unlock](https://github.com/dmitriitimoshenko/tpm-keyring-unlock)). KWallet dropped
    its per-application access control in 6.30 because the caller declares its own appId
    ([ba22916](https://invent.kde.org/frameworks/kwallet/-/commit/ba229169deda9f80d4669ec23a63781ac9c437fc)).
  - **libsecret**: since 0.20.5, its file backend seals the master password in the TPM
    ([!83](https://gitlab.gnome.org/GNOME/libsecret/-/merge_requests/83),
    [!90](https://gitlab.gnome.org/GNOME/libsecret/-/merge_requests/90)). It is off by default
    (`-Dtpm2=false`), and the seal has no PCRs and no authorization, so any process of the uid with
    access to `/dev/tpmrm0` unseals it.
  - **oo7**: the daemon reads the password from a `systemd-creds` credential, which can be bound to
    the TPM ([#253](https://github.com/linux-credentials/oo7/pull/253)). Its README warns that anyone
    who can read the file and use the TPM decrypts it
    ([README](https://github.com/linux-credentials/oo7/blob/main/server/README.md)).
  - **Not verified**: which distributions build libsecret with `tpm2`, and whether `systemd-creds
    encrypt --user` binds the credential to the TPM by default.
- **fwupd**: a system daemon with polkit actions, mostly `auth_admin`. It guards operations, not
  keys.
- **`systemd-creds`**: encrypts service credentials with the TPM, with no person involved.
- **1Password** unlocks with polkit and PAM and keeps the secret in memory, out of reach of
  unprivileged processes; it says nothing about a same-uid attacker
  ([1Password](https://support.1password.com/system-authentication-linux-security/)).
- **Bitwarden** unlocks with polkit and, in its flatpak, asks the person to copy its `.policy` onto
  the host by hand ([Bitwarden](https://bitwarden.com/help/biometrics/)): the same packaging problem
  as in section 3.
- **keylime** and **sssd**: do not custody personal signing keys; not prior art.

None of the prior art that guards something with polkit claims to defend against a process of the
same uid.

Closer to the design in [Custodio as a PKCS#11 token](#custodio-as-a-pkcs11-token):

- **[linux-id](https://github.com/matejsmycka/linux-id)**: a software FIDO2 key with the key in the
  TPM. On every use it asks through pinentry or, with `--auth fprintd`, for the fingerprint over
  D-Bus directly from fprintd, without PAM or polkit
  ([fprintd.go#L71-L94](https://github.com/matejsmycka/linux-id/blob/a3eabc5081950ddfd3ee155e2876856c41aa7b4c/fprintd/fprintd.go#L71-L94)).
  It is a user service and speaks neither PKCS#11 nor X.509.
- **[ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent)**: SSH keys sealed in the TPM, with
  askpass confirmation on every use
  ([agent.go#L241](https://github.com/Foxboron/ssh-tpm-agent/blob/43795283993ef79015729399bdecf413fb7705d8/agent/agent.go#L241)).
  Same uid; SSH only.
- **fprintd in ssh-agent proposal**
  ([openssh-unix-dev, June 2025](https://lists.mindrot.org/pipermail/openssh-unix-dev/2025-June/041936.html)):
  no code. The project's answer
  ([041942](https://lists.mindrot.org/pipermail/openssh-unix-dev/2025-June/041942.html)) is that the
  fingerprint protects use, not the key.
- **pcscd**: a system service with polkit, but it checks on connect and in `SCardConnect`, not on
  every signature ([winscard_svc.c](https://github.com/LudovicRousseau/PCSC/blob/8926ecb11ece8f1d2faf9296117869d366ecc6dc/src/winscard_svc.c#L571)).
- **siguldry-pkcs11**: a PKCS#11 module forwarding to a system service over a socket; it authorizes
  only through the socket's permissions.
- **gnome-keyring**: its PKCS#11 module talks over a socket to a daemon of the same uid, which reads
  the client's credentials but does not authorize with them
  ([gkm-rpc-dispatch.c#L2130-L2136](https://github.com/GNOME/gnome-keyring/blob/e970619902bf662ce3f182e87f3f7dda00caff43/pkcs11/rpc-layer/gkm-rpc-dispatch.c#L2130-L2136)).
- **tpm2-pkcs11, kryoptic and SoftHSM**: PKCS#11 tokens loaded by the caller itself; they only ask
  for the PIN. tpm2-pkcs11 or kryoptic could be Custodio's store.

**Does it exist already?** No, as far as the search went: GitHub, freedesktop and GNOME GitLab, and
the web. Nothing combines a service under another uid, imported X.509 keys, a PKCS#11 interface and
authorization on every `C_Sign`. Debian Code Search was not consulted, and Fedora's and Arch's
packages were not reviewed one by one. None of the close ones has a natural place for the feature,
so the sensible route is a small project of its own that reuses siguldry-pkcs11 as a template and,
if needed, tpm2-pkcs11 or kryoptic as the store.

## 8. Non-exportable keys, as in Windows Hello

Windows Hello generates the key inside the TPM and never lets it out: neither the person, nor a
process of theirs, nor the administrator can export it. Using it takes a gesture
([Platform Crypto Provider](https://learn.microsoft.com/en-us/archive/blogs/pki/setting-up-tpm-protected-certificates-using-a-microsoft-certificate-authority-part-1-microsoft-platform-crypto-provider)).
But Windows Hello does not import keys, and a CA's `.p12` does not go through it.

### What Windows does with a `.p12`

- **The import wizard asks** whether to mark the key exportable (unchecked by default) and whether
  to enable strong protection, which warns or asks for a password on every use. `certutil
  -importpfx` does the same with `NoExport`
  ([certutil `NoExport`](https://learn.microsoft.com/en-us/archive/blogs/pki/marking-private-keys-as-non-exportable-with-certutil-importpfx)).
- **The key goes to the user's software provider**, encrypted with DPAPI, not to the TPM. There,
  "non-exportable" is a flag the API honours: mimikatz bypasses it with `crypto::capi`, which
  patches CryptoAPI in its own process, as the same user
  ([mimikatz, `crypto` module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto)). It is
  the same case as `CKA_EXTRACTABLE=false` in a softoken the caller loads itself.
- **The TPM is only reached by hand**, with `certutil -csp "Microsoft Platform Crypto Provider"
  -importpfx`. The wizard does not offer it. **Not verified** that it works: at least one documented
  attempt fails ([Server Fault question](https://windows-hexerror.linestarve.com/q/sf923819-certutil-importpfx-to-a-tpm-fails)).

### What Custodio can offer

The wizard's question, with a guarantee that does not rest on a flag: if the person says no,
Custodio has no export path at all. If they say yes, export goes through the same authorization as a
signature. Custodio can offer three grades:

| Grade | Who cannot get the key out | How |
|---|---|---|
| Custodio does not export | A process of the person's uid | The interface only signs: no export method on D-Bus, and in PKCS#11 the key has `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, so `C_GetAttributeValue(CKA_VALUE)` and `C_WrapKey` fail |
| Key in the TPM | Root, backups of `/var/lib` and a stolen disk | `TPM2_Import` (section 4) |
| Key born in the TPM | Nobody, ever: it never existed outside | `TPM2_Create` with `fixedTPM` and `fixedParent`, and a CSR the CA signs |

- **The other uid already gives the first grade.** The PKCS#11 attributes only tell the client what
  Custodio will do. The real guarantee is that the key lives in a directory the person's uid cannot
  read.
- **An imported key cannot reach the third grade.** `TPM2_Import` requires `fixedTPM` and
  `fixedParent` to be clear, because the key comes from outside. Without an `authPolicy` that allows
  `TPM2_Duplicate`, it cannot be taken out of the TPM again either. **Not verified** that
  `tpm2_import` leaves the policy empty by default.
- **The third grade is Windows Hello's, and it requires generating the key in Custodio.** That needs
  `C_GenerateKeyPair` in the interface and a CSR the CA accepts. The FNMT generates the key on the
  person's machine with its Configurador and issues the certificate for that key. **Not studied**
  whether the Configurador can generate it in a system PKCS#11 token, which is what would let the key
  be born in Custodio.
- **The Windows Hello gesture is the physical factor of section 6**, with the same limits: presence,
  not intent. **Not verified** whether Windows Hello holds against a process of the same user. There
  are signs that a Windows Hello for Business key can be used from an unprivileged user through CNG
  ([Mollema](https://dirkjanm.io/borrowing-windows-hello-keys/)).
- **Import is still the weak point** (section 4). In the first two grades the `.p12` went through
  the session, and Custodio only protects the key if the person deletes the original.

## Pending experiments

All in a Fedora 43 VM (GNOME and KDE) and Ubuntu 24.04 (to have X11), with an administrator user
and a non-administrator one. None has been run.

1. **Per-process agent.** Terminal A: `echo $$`. Terminal B (attacker): `pkttyagent --process <pid of A>`.
   Terminal A: `pkcheck --action-id org.freedesktop.policykit.exec --process $$ --allow-user-interaction`.
   Expected: the password is asked in B, not in GNOME Shell's or KDE's dialog.
2. **Genuine modal with arbitrary text (GNOME).**
   `printf 'SETTITLE Authentication required\nSETDESC Authentication is required to sign\nGETPIN\n' | pinentry-gnome3`.
   Expected: a GNOME Shell modal indistinguishable from polkit's.
3. **Keyboard injected into the dialog (GNOME).** With `pkexec true` waiting for a password, from
   another terminal: `gdbus call --session --dest org.gnome.Mutter.RemoteDesktop --object-path /org/gnome/Mutter/RemoteDesktop --method org.gnome.Mutter.RemoteDesktop.CreateSession`,
   `… --object-path <session> --method org.gnome.Mutter.RemoteDesktop.Session.Start` and
   `… NotifyKeyboardKeysym 0x61 true` / `false`. Expected: a dot appears in the password field.
4. **`fake_input` on KDE.** `wayland-info | grep fake_input` in a normal terminal and inside
   `flatpak run --command=wayland-info <app>`. Expected: advertised outside, not inside.
5. **`ptrace`.** `cat /proc/sys/kernel/yama/ptrace_scope` and `gdb -p $(pgrep -x gnome-shell)` as
   the user, on each distribution.
6. **flatpak against the system bus.** `flatpak run --system-talk-name=org.freedesktop.hostname1 --command=sh <app>`
   and, inside, `gdbus call --system --dest org.freedesktop.hostname1 --object-path /org/freedesktop/hostname1 --method org.freedesktop.DBus.Peer.Ping`.
   On the host, `busctl --system status <unique name>`: expected, the pid of `xdg-dbus-proxy`, and its
   `/proc/<pid>/root/.flatpak-info` with the app-id.
7. **Fingerprint in polkit.** Fedora: `authselect enable-feature with-fingerprint`, `fprintd-enroll`
   and `pkexec true`. Expected: GNOME's dialog asks for the finger. Repeat on Ubuntu with
   `pam-auth-update`.
8. **TPM.** With `swtpm` or a real TPM: `tpm2_getcap algorithms`; `tpm2_testparms rsa3072 ecc384`;
   `openssl pkcs12 -in <test p12> -nocerts -nodes -out key.pem`;
   `tpm2_createprimary -C o -c parent.ctx`;
   `tpm2_import -C parent.ctx -G rsa -i key.pem -u key.pub -r key.priv`;
   `tpm2_load -C parent.ctx -u key.pub -r key.priv -c key.ctx`;
   `tpm2_sign -c key.ctx -g sha256 -d digest.bin -o sig`. Repeat with a P-256 `.p12`.
9. **Non-exportable key.** With Custodio as a PKCS#11 token:
   `pkcs11-tool --read-object --type privkey --id <id>` must fail, and `pkcs11-tool --list-objects`
   must show the key as `sensitive` and not `extractable`. With a TPM, after `tpm2_import`,
   `tpm2_readpublic -c key.ctx` must show attributes without `fixedTPM` and an empty `authPolicy`,
   and `tpm2_duplicate` must fail.
