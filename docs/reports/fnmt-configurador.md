# The FNMT Configurador and keys born in Custodio

Question: can the key of an FNMT personal certificate ("persona física") be generated in Custodio
instead of in the Configurador, so that it never exists outside it (grade 3 in
`polkit-custodian-linux.md` section 8)?

Inspected: `configuradorfnmt_5.1.2.amd64.deb` from
<https://descargas.cert.fnmt.es/Linux/configuradorfnmt_5.1.2.amd64.deb> (October 2026; the download
page lists the RPM as 5.0.3). Static reading only: file listing and `strings` on the classes of
`configuradorfnmt.jar`. Nothing was executed and nothing was decompiled. Each claim is **verified**
(found in the package or an FNMT page) or **inferred**.

## Verdict

The Configurador cannot generate the key in, or install it into, an arbitrary PKCS#11 token. The
practical route is still importing what it produces (M3). The one route to a key born in Custodio
is speaking the Configurador's own `fnmtcr://` protocol, which is undocumented and was not tried.

## What the Configurador does

- **It is a Java application** (`es.gob.fnmt.cert.certrequest.CertRequest`) with its own Temurin 21
  JRE, SunPKCS11, `java.smartcardio` and BC-FIPS. `/usr/bin/configuradorfnmt` runs that JRE with
  `-classpath configuradorfnmt.jar:...`. The jar is signed (`META-INF/TE-B6C45.RSA`). **Verified.**
- **Software mode keeps the private key in the Configurador's own local store** between request
  and download. **Verified.**
- **Card mode exists, for a closed list of cards.** `OperationCard` calls
  `Pkcs11Manager.createKeyPairOnCard`. The request URL turns it on (`forcecard`). The card is
  recognised by its ATR over PC/SC: Ceres, GyD, Bit4Id, Gemalto or Oberthur; anything else throws
  `UnknownCardException`. Module paths are hardcoded per brand; on Linux only Ceres
  (`/usr/lib{,64}/libpkcs11-fnmtdnie.so`) and Gemalto (`/usr/lib{,64}/libIDPrimePKCS11.so`). No
  option names another module and nothing mentions p11-kit. **Verified.**
- **On download, Linux** installs the key into the NSS softoken (`KeyInstallerLinux`: Firefox
  profiles, `~/.pki/nssdb`, `/etc/pki/nssdb`) and offers a PKCS#12 backup. **Verified.**
- **On download, Windows** installs into `Cert:\CurrentUser\My`: Java `Windows-MY`, then PowerShell
  `Import-PfxCertificate`, then `certutil -importPFX` (`KeyInstallerWindows`). No `-csp`, no
  Platform Crypto Provider, no `NoExport`. The key never reaches the TPM or Windows Hello.
  **Verified** in the jar of the Linux package; that the Windows build ships the same jar is
  **inferred**.
- **Card certificates are an institutional product.** The FNMT FAQ sends card or USB certificates
  to its "catálogo de servicios"
  ([FAQ 1340](https://www.sede.fnmt.gob.es/preguntas-frecuentes/certificado-de-persona-fisica/-/asset_publisher/eIal9z2VE0Kb/content/1340-que-pasos-debo-seguir-para-solicitar-un-certificado-fnmt-de-persona-fisica-o-el-certificado-de-representacion-de-administrador-unico-o-solidario)).
  That a citizen on the web flow never gets card mode is **inferred**.

## The `fnmtcr://` protocol

- The `.desktop` file registers `x-scheme-handler/fnmtcr` and runs the Configurador with the URL.
  **Verified.**
- URL parameters: `fileId`, `desKey`, `storageServer` and `retrieveServer` (two servlets),
  `keyType`; for a request `keyLength` and `forcecard`; for installation `signedData` (PKCS#7,
  Base64, optionally gzip). **Verified** as strings in `UrlParametersFnmt*`.
- Results go through an "intermediate server": encrypted with `desKey` (`CipherDataManager`,
  `JsCipher`) and sent with `op=`, `id=`, `v=` and `dat=` (`IntermediateSvrUtil`). The request
  produces a key pair and a CSR (`AbstractPkcs11Util$CsrAndKeyPair`). **Verified** as strings; the
  exact formats are **not known**.
- It follows the scheme of AutoFirma (`afirma://` with storage and retrieve servlets), whose source
  is public. **Inferred** from the names; not compared.

## Routes for Custodio

| Route | Key born in Custodio | Assessment |
|---|---|---|
| Import the `.p12` backup | No | The planned M3 route. The `.p12` and the NSS copy stay behind unless removed. |
| Import from the NSS database the Configurador wrote | No | Removes the `.p12` from the flow; NSS is a stable format. Password of that database not checked. |
| Pose as a Ceres or Gemalto card (virtual reader, our module at their path) | Yes | Impersonates an FNMT card, clashes with their packages, server side unknown. Rejected. |
| Java agent through `JAVA_TOOL_OPTIONS` that redirects card mode to our module | Yes | Feasible, but it is the same-uid code injection Custodio defends against, and it breaks with any internal rename. Proof of concept at most. |
| Implement `fnmtcr://` (in rFirma; Custodio only adds `C_GenerateKeyPair`) | Yes | Best of the routes that give grade 3. Undocumented protocol, `v=` suggests a version check, one handler per scheme, any web page can open the URL. Check the FNMT's certification practice statement first. |
| Ask the FNMT to accept a generic PKCS#11 module | Yes | Small change for them (SunPKCS11 is already there). Outside our control. |

## Open

- Exact CSR and message formats: decompile `IntermediateSvrUtil`, `CipherDataManager`, `JsCipher`
  and `UrlParametersFnmt*`, and compare with AutoFirma.
- What the FNMT server checks (`v=`, card versus software requests).
- Whether the certification practice statement says where the subscriber's key must be generated.
