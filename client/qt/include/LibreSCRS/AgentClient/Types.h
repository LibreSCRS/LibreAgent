// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <cstdint>

// Transport-neutral Qt value types the lifted AgentClient API (a later
// task) hands back to LibreCelik/LibreKDE. Header-only aggregates -- no
// vtable, no exported symbols, nothing to implement in a .cpp -- mirroring
// the agent-side GroupSnapshot/FieldSnapshot (identity fields) and
// CertSnapshot (certificates) value types these are the Qt-facing shape of,
// without depending on either agent-side header (this library never links
// LibreAgent::Core; it only speaks the socket wire).
namespace LibreSCRS::AgentClient {

// Client-facing, DEDUCED trust verdict. Distinct from the agent's own
// wire-numeric LibreSCRS::Agent::CertTrustStatus (Trusted/UntrustedRoot/
// BrokenChain/InvalidCertificate/Expired/Unknown=255): that enum is the
// agent's internal chain-verdict taxonomy carried as a raw uint on
// cert-info.trustStatus; mapping the wire value into this simpler,
// display-oriented set is the lifted API's job (a later task), not this
// header's.
enum class TrustStatus : std::uint8_t {
    Unknown,
    Trusted,
    Untrusted,
    Revoked,
    Expired,
};

// One labeled value out of a card-read result (an identity field, a
// certificate subject/issuer/validity field, ...). `detail` carries a
// richer, field-specific payload alongside the display-ready `value`
// (e.g. raw bytes for a photo-adjacent field) when the agent supplies one;
// empty/invalid when it does not.
struct Field
{
    QString key;
    QString value;
    QVariant detail;
    QVariantMap extra;
};

// A named collection of Field values (e.g. "personal", "address", "subject",
// "validity") -- the Qt-facing mirror of the agent's GroupSnapshot grouping.
struct FieldGroup
{
    QString key;
    QList<Field> fields;
    QVariantMap extra;
};

// One signing certificate, parsed agent-side and shipped field-groups + the
// stable identifiers a client needs to pick a signer and render a trust
// decision. No DER crosses the wire -- see cert-info in
// wire/librescrs-agent.cddl -- so this type carries none either.
struct CertificateInfo
{
    QString id;
    QString subject;
    QString issuer;
    QDateTime notBefore;
    QDateTime notAfter;
    bool signingCapable = false;
    TrustStatus trust = TrustStatus::Unknown;
    // Wire token vocabulary, forwarded as-is (not re-validated or
    // re-interpreted here) -- e.g. EKU/keyUsage-derived status strings the
    // agent already resolved. A later task defines the closed set, if any.
    QStringList securityStatus;
    QVariantMap extra;
};

} // namespace LibreSCRS::AgentClient
