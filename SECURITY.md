# Security policy

## Supported versions

custodio is pre-1.0: only the latest release gets fixes.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/sgomez/custodio/security/advisories/new). Do not open a public issue.

Include the affected version, the distribution, and the steps that reproduce it. Leave out real key material: private keys, `.p12` files, passwords and certificates that identify a person. Use throwaway keys such as the test fixtures.

You will get an answer within 7 days. Once a fix ships, the advisory is published with credit to the reporter, unless they prefer otherwise.

## Scope

The [threat model](docs/threat-model.md) says what Custodio protects, from whom, and what it leaves out; a report about something it lists as out of scope or not guaranteed is not a vulnerability.

In scope: signing without a polkit authorization, or with an authorization reused from an earlier signature; reading or exporting a private key; the key store's files and permissions; the D-Bus interface and its bus policy; memory safety of the PKCS#11 module; and any path that leaks a key or password into logs, errors or `Debug` output. Bugs in polkit, D-Bus or the applications that load the module go to their maintainers. The Firefox snap sockets are in scope too: a peer the label check should refuse (another snap, an unconfined process, a stacked or non-AppArmor label) that gets served, a call beyond listing and signing, and a socket the snap can replace. So is the registration command (`custodio register`): a write outside the user's own browser profiles and snap directory, an edit of a profile a running browser holds, or a half-written module copy or profile left behind.
