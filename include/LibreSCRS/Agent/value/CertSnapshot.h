// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/value/CardReadSnapshot.h> // GroupSnapshot / FieldSnapshot (composed, not re-rolled)
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

// Agent-owned wire enum for the certificate chain/trust verdict.
// Decoupled from LM's Trust::ChainStatus numbering via an explicit switch in
// the consumer; Unknown sits at a non-colliding 255 so an append-only LM
// ChainStatus addition can never silently alias it. The first 5 values (0-4)
// mirror LM's Trust::TrustStore::ChainStatus by name and ordinal (pinned by a
// static_assert at the mapping site); Revoked/OfflineUnverified are
// agent-only additions LM's ChainStatus does not itself carry (no revocation
// checking is wired -- Revoked is reserved vocabulary for a future
// OCSP/CRL-aware TrustVerifier; OfflineUnverified is emitted whenever the
// TrustVerifier could not reach a real verdict at all, e.g. no TSL sources
// configured or the trust store failed to build). Existing values 0-4/255 are
// FROZEN; 5/6 are this task's append -- never renumber or reuse either range.
enum class CertTrustStatus : std::uint32_t {
    Trusted = 0,
    UntrustedRoot = 1,
    BrokenChain = 2,
    InvalidCertificate = 3,
    Expired = 4,
    Revoked = 5,
    OfflineUnverified = 6,
    Unknown = 255,
};

// One certificate, fully parsed agent-side into client-renderable form. No DER
// crosses the wire: the agent does ALL X.509 parsing and ships
// field-groups + stable codes, so clients (LibreCelik et al.) link neither LM
// nor OpenSSL. `fields` reuses the identity GroupSnapshot/FieldSnapshot value
// type (all Text fields for certs: DN strings, ISO-8601 dates, hex serial, hex
// extension values); the Certificates1 marshaller emits the (ssv) wire shape
// (labelKey, labelFallback, value) — NOT the Identity1 (sssv) shape.
struct CertSnapshot
{
    std::string certId;            // lowercase-hex SHA-256(DER); opaque, stable, unique
    bool signingCapable{false};    // paired on-card private key (keyFID) AND a signing-suitable keyUsage
    std::uint32_t keyUsageBits{0}; // bit i (1u<<i) set per KeyUsageBit ordinal; client localizes names
    std::vector<std::string> ekuOids;
    std::vector<std::string> chainSubjectCns{}; // leaf..root subject CNs (display); currently just [leaf CN]
    std::uint32_t trustStatus{static_cast<std::uint32_t>(CertTrustStatus::Unknown)};
    // Closed-vocabulary tokens mirroring trustStatus (see the CertTrustStatus
    // comment above for the pairing): "trusted", "untrusted-root",
    // "broken-chain", "invalid", "expired", "revoked", "offline-unverified".
    // Populated by CertReadFlow from the injected TrustVerifier, alongside
    // trustStatus -- never set independently. NOT its own wire member: it
    // rides a "security" group appended to `fields` below (dict-key growth,
    // the lawful append route on both wires), so this member and that group
    // are always written together from the same call site.
    std::vector<std::string> securityStatus;
    std::vector<GroupSnapshot> fields; // subject/issuer/validity/publicKey/cert/ext/security groups
};

} // namespace LibreSCRS::Agent
