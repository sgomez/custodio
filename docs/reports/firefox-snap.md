# Firefox snap and Custodio

Question: how can the confined Firefox snap, the default browser of Ubuntu, use Custodio without
changes from Mozilla or Canonical?

Tried on the `ubuntu2604` lab VM on 2026-11-11: Ubuntu 26.04, dbus-daemon 1.16.2 (AppArmor
mediation), Firefox snap 154.0-1 rev 8763 (publisher mozilla), the `.deb` built from v0.7.0. Sources
read: the generated profile `/var/lib/snapd/apparmor/profiles/snap.firefox.firefox`, snapd
`interfaces/apparmor/template.go` and `interfaces/builtin/*.go`, the snaps' `snapcraft.yaml`,
Launchpad, Mozilla and snapcraft forum threads. Each claim is **verified** (run or read) or
**inferred**.

## Verdict

Custodio's service listens, besides the bus, on a socket at `/run/snap.<snap>/custodio.sock`; the
module, copied into `~/snap/<snap>/common/` and registered in the snap's NSS profile, connects there.
polkit then authorizes Firefox itself, pinned by the pidfd the kernel gives on that socket, and the
AppArmor label tells which snap called. Nobody else has to act. It rests on a default rule of
snapd's template that no document promises, so an end-to-end test must catch the day it changes.

## What the snap allows

| Step | Result |
|---|---|
| Load `/usr/lib/custodio/libcustodio_pkcs11.so` | No: the snap sees its base's `/usr`. **Verified** |
| Load a copy in `~/snap/firefox/common/` | Yes: `owner @{HOME}/snap/@{SNAP_INSTANCE_NAME}/** mrkix`; no denial. **Verified** |
| Call `com.rfirma.Custodio1` on the system bus | No: `apparmor="DENIED" operation="dbus_method_call" member="ListKeys"`. **Verified** |
| Connect to a socket in `~/snap/firefox/common/` or `/run/user/<uid>/snap.firefox/` | Yes, both `owner` rules. **Verified** |
| Connect to a root socket, mode 0666, in `/run/snap.firefox/` | Yes: `/run/snap.@{SNAP_INSTANCE_NAME}/** mrwklix`, no `owner`. **Verified** |
| Connect to an abstract socket of an unconfined listener | No: connect needs `peer=(label=snap.NAME.*)`. **Verified** (other strict snap) |

On the `/run/snap.firefox/` socket the server read `peer pid 6075 uid 1000 label
b'snap.firefox.firefox (enforce)'`. `SO_PEERCRED`, `SO_PEERPIDFD` and `SO_PEERSEC` are the kernel's,
so the client cannot forge them. polkit 127 accepts a `unix-process` subject `{pidfd: h, uid: i}`
(`uid` an int32 from `SO_PEERCRED`; a dead process gives "Process not found"). **Verified.**

- **Registration.** The Firefox snap 154 keeps its profiles in
  `~/snap/firefox/common/.mozilla/firefox/`. The host's `modutil -dbdir sql:<profile> -add Custodio
  -libfile ~/snap/firefox/common/libcustodio_pkcs11.so`, run outside the snap, registered the copy,
  and Firefox loaded it with no AppArmor denial. **Verified.**
- **Another uid in polkit.** polkit lets a caller ask about a subject with another uid only if the
  caller is trusted for the action. Custodio is, through `org.freedesktop.policykit.owner
  unix-user:custodio` in `data/com.rfirma.custodio.policy`. **Verified** (polkit 127, host).
- **Stacked labels.** On Ubuntu, `aa-exec` with a snap profile from an unconfined process is turned
  into a stack: the peer label reads `snap.<snap>.<app>//&unconfined (enforce)`, not the snap's own.
  **Verified** with another strict snap's profile on the host, Ubuntu with kernel 7.0.
- **Other LSMs.** Where SELinux is the major LSM (Fedora, RHEL/Alma), `SO_PEERSEC` returns an SELinux
  context such as `unconfined_u:unconfined_r:unconfined_t:s0`, never an AppArmor label. **Inferred.**

## `/run/snap.<name>/`

- Added by snapd PR #6109 (snapd 2.36.1, 2018) so that snaps get a scratch directory in `/run`
  (LP #1802112). Not in the snapcraft docs; no statement that it is internal or stable. **Verified.**
- No snapd or snap-confine code creates or cleans it: it is the host's `/run`, not bind-mounted. It
  lasts until reboot and survives refresh and remove; the directory did not exist until created.
  **Verified** (source); lifetime **inferred**.
- Every strict snap gets the same rules, so Chromium (`~/snap/chromium/current/.pki/nssdb`) and
  Thunderbird (`~/snap/thunderbird/common/.thunderbird/`) should work the same way. A parallel
  instance (`firefox_x`) has its own `/run/snap.firefox_x/`. **Inferred**, only Firefox run.
- The snap can write in that directory: it must stay root `0755`, so the snap cannot replace the
  socket. `/run` is `noexec`, so the module cannot live there. **Inferred.**

## Routes rejected

- **snapd `dbus` interface:** the slot must be a snap, and Firefox would need a plug from Mozilla
  plus a store declaration. **Verified.**
- **snapd `pkcs11` interface:** Ubuntu Core only (`allow-installation: false`); Firefox has no such
  plug. **Verified.**
- **A relay in the user's session** (socket to D-Bus): works, but polkit and the journal see the
  relay. Handing the accepted fd to the service keeps Firefox's credentials, but the relay keeps a
  copy and can inject requests under them. **Verified.**
- **A virtual PC/SC reader** behind the snap's `pcscd` plug (not connected by default): polkit sees
  pcscd, which uses a PID, not a pidfd; the PIN goes in a plain APDU; every process sees the card.
  **Inferred.**
- **Native messaging or a portal:** no PKCS#11 portal exists; native messaging serves signing from a
  page, never TLS client authentication. **Verified.**
- **An input-method abstract socket** (`@tmp/.mozc.*` in `desktop-legacy`): reachable, but it borrows
  another interface's rule. **Inferred.**
- **A root module in `/var/snap/firefox/common/` with `SecurityDevices` in
  `/etc/firefox/policies/policies.json`:** loadable, but it writes into another snap's data, `snap
  remove` deletes it and the policy file replaces the administrator's. **Inferred.**

## What others do

Ubuntu's own guide (`enable-smart-cards-in-snapped-browsers`) connects `firefox:pcscd` for the
bundled OpenSC and has other modules copied to `~/snap/firefox/common/`, "experimental and
unsupported". Belgium's eID tells users to leave the snap. LP #1967632 (host modules) and Mozilla
bug 1734371 are open, with no work started. **Verified.**
