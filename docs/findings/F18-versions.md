## 3. Minimum versions and distributions

Versions read: as in `F18-always-authenticate.md`.

Why the minimums: polkit 124 added pidfd support (`pidfd` parameter in `CheckAuthorization`,
polkit NEWS, verified). dbus 1.15.8 added `ProcessFD` to `GetConnectionCredentials` (dbus NEWS,
verified); stable releases are 1.16.0 and later. dbus-broker 34 added it (NEWS, verified). polkit's
own code uses it: `polkitsystembusname.c` calls `GetConnectionCredentials` and reads the
`ProcessFD` key into a pidfd (polkit `main`, read 2026-10-27, verified). polkit 124 does
this too (see `F41.md`). Releases before 124 were not read. So polkit 124+ on a bus that
exposes `ProcessFD` is enough; on a bus without it polkit falls back to the PID, which is
what makes the older rows unsafe against PID reuse.

| Release | polkit | dbus-daemon / dbus-broker | Meets? |
|---|---|---|---|
| Debian 12 | 122 | 1.14.10 / 33 | No |
| Debian 13 | 126 | 1.16.2 / 37 | Yes |
| Ubuntu 22.04 | 0.105 | 1.12.20 / 29 | No |
| Ubuntu 24.04 | 124 | 1.14.10 / 35 | Only with dbus-broker installed |
| Ubuntu 25.10 | 126 | 1.16.2 / 37 | Yes |
| Ubuntu 26.04 | 127 | 1.16.2 / 37 | Yes |
| Fedora 41 | 125 | 1.14.10 / 36 | Yes (dbus-broker default, inferred) |
| Fedora 42, 43 | 126 | 1.16.x / 36-37 | Yes |
| RHEL/Alma/Rocky 9 | 0.117 | 1.12.20 / 28 | No |
| RHEL/Alma 10 | 125 | 1.14.10 / 36 | Yes with dbus-broker (the default, inferred) |
| openSUSE Leap 15.6 | 121 | 1.12.2 / 28 | No |
| openSUSE Leap 16.0 | 123 | 1.14.10 / 36 | No (polkit) |
| openSUSE Tumbleweed | 128 | 1.14.10 / 37 | Only with dbus-broker |
| Arch | 128 | 1.16.2 / 37 | Yes with dbus-broker (the default, observed in the e2e image) |

"Default bus" is inferred for rows not run; package versions were checked, not each distribution's default. Observed in the e2e images: Fedora 44, Alma 10 and Arch run dbus-broker (see `F45.md`).
The end-to-end runs cover Debian 13, Ubuntu 26.04, Fedora 44, Alma 10 and Arch, and Ubuntu 24.04 as
the refusal target (`F53.md`); Ubuntu 24.04 with dbus-broker was run by hand (`F57.md`). No other row was run.
RHEL 10 was checked through CentOS Stream 10 and the AlmaLinux 10 repository.

Consequence: supported targets are Debian 13, Ubuntu 25.10 and later, Fedora 41 and later,
RHEL/Alma 10 and Arch. Ubuntu 24.04 works only with `dbus-broker`. Debian 12, Ubuntu 22.04,
RHEL 9 and Leap are out.

