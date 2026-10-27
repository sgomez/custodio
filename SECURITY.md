# Security policy

## Supported versions

custodio is pre-1.0: only the latest release gets fixes.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/sgomez/custodio/security/advisories/new). Do not open a public issue.

Include the affected version, the distribution, and the steps that reproduce it. Leave out real key material: private keys, `.p12` files, passwords and certificates that identify a person. Use throwaway keys such as the test fixtures.

You will get an answer within 7 days. Once a fix ships, the advisory is published with credit to the reporter, unless they prefer otherwise.

## Scope

In scope: signing without a polkit authorization, or with an authorization reused from an earlier signature; reading or exporting a private key; the key store's files and permissions; the D-Bus interface and its bus policy; memory safety of the PKCS#11 module; and any path that leaks a key or password into logs, errors or `Debug` output. Bugs in polkit, D-Bus or the applications that load the module go to their maintainers.
