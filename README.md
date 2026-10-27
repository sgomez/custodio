# Custodio

A Linux system service that holds signing keys imported from a `.p12` file and asks for polkit
authorization on every signature. It shows up as a PKCS#11 token, so any program that speaks
PKCS#11 can use it.

It stops a process running as the user, such as an AI agent with a shell, from signing by mistake.
It does not protect against an attacker running as the same uid, against root, or the user's
intent: the dialog cannot prove what is being signed.

## Names

- System D-Bus name: `com.rfirma.Custodio1`
- polkit action: `com.rfirma.custodio.sign`
