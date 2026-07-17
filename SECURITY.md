# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately using GitHub Security
Advisories:

  https://github.com/LibreSCRS/LibreAgent/security/advisories/new

For non-GitHub correspondence, contact the project release signing
identity:

  librescrs@proton.me

We respond to security reports within five business days. Please give
us a reasonable disclosure window before publishing.

## Release verification

LibreSCRS release tags are cryptographically signed.

- **Git tags** are GPG-signed with the LibreSCRS Release Signing key
  (fingerprint `6B05889AC9A6A7188DF639B06F27A989C2031D16`). The release
  workflow imports the published key (`KEYS` in this repository) and
  rejects any unsigned or wrong-fingerprint tag. Verify locally with
  `gpg --import KEYS && git verify-tag <TAG>`.
- **Release artifacts.** LibreAgent ships only the source library
  (`LibreAgent::Core`), consumed from source or as a CONFIG package; it
  publishes no separate binary artifacts of its own. The components that
  distribute binaries sign them via Sigstore cosign keyless using GitHub
  Actions OIDC. See <https://librescrs.github.io/security/> for that
  end-to-end verification guide including expected OIDC issuer +
  identity values.

## Supported versions

| Version | Supported |
|---------|-----------|
| 4.x     | ✅ Active  |
