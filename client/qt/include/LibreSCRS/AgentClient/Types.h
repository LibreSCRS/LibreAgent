// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <QDateTime>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <cstdint>

/// @file
/// @brief Transport-neutral Qt value types the `AgentClient` API hands back
///        to the GUI hosts consuming this library.
///
/// Header-only aggregates — no vtable, no exported symbols, nothing to
/// implement in a .cpp — mirroring the agent-side GroupSnapshot/FieldSnapshot
/// (identity fields) and CertSnapshot (certificates) value types these are
/// the Qt-facing shape of, without depending on either agent-side header
/// (this library never links `LibreAgent::Core`; it only speaks the socket
/// wire).
namespace LibreSCRS::AgentClient {

/// @brief Client-facing, DEDUCED trust verdict for a certificate.
///
/// Distinct from the agent's own wire-numeric `LibreSCRS::Agent::CertTrustStatus`
/// (Trusted/UntrustedRoot/BrokenChain/InvalidCertificate/Expired/Unknown=255):
/// that enum is the agent's internal chain-verdict taxonomy carried as a raw
/// uint on `cert-info.trustStatus`; this simpler, display-oriented set is
/// what `CertificateInfo::trust` carries after the agent maps its verdict
/// down to it.
enum class TrustStatus : std::uint8_t {
    Unknown,   ///< No verdict available.
    Trusted,   ///< Chain validated to a trusted anchor.
    Untrusted, ///< Chain builds but does not validate to a trusted anchor.
    Revoked,   ///< The certificate (or a chain member) is revoked.
    Expired,   ///< The certificate is outside its validity window.
};

/// @brief One labeled value out of a card-read result (an identity field, a
///        certificate subject/issuer/validity field, ...).
struct Field
{
    QString key;       ///< Frozen wire field key (e.g. "given_name", "subject").
    QString value;     ///< Display-ready stringified value.
    QVariant detail;   ///< Richer, field-specific payload alongside `value` (e.g. raw bytes for a
                       ///< photo-adjacent field) when the agent supplies one; empty/invalid when it does not.
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result struct.
};

/// @brief A named collection of `Field` values (e.g. "personal", "address",
///        "subject", "validity") — the Qt-facing mirror of the agent's
///        GroupSnapshot grouping.
struct FieldGroup
{
    QString key;         ///< Frozen wire group key (e.g. "personal", "subject").
    QList<Field> fields; ///< The group's fields, in agent-supplied order.
    QVariantMap extra;   ///< Forward-compatible pass-through, as on every result struct.
};

/// @brief One signing certificate, parsed agent-side and shipped as
///        field-groups plus the stable identifiers a client needs to pick a
///        signer and render a trust decision.
///
/// No DER crosses the wire — see `cert-info` in wire/librescrs-agent.cddl —
/// so this type carries none either; fetch the raw bytes separately via
/// `AgentClient::certificateDer()`.
struct CertificateInfo
{
    QString id; ///< Opaque certificate id — pass back as-is to `AgentClient::certificateDer()` / `AgentCard::sign()`.
    QString subject;                          ///< Display-ready subject DN.
    QString issuer;                           ///< Display-ready issuer DN.
    QDateTime notBefore;                      ///< Validity window start.
    QDateTime notAfter;                       ///< Validity window end.
    bool signingCapable = false;              ///< Whether this certificate's key can be used for `AgentCard::sign()`.
    TrustStatus trust = TrustStatus::Unknown; ///< Deduced trust verdict; see `TrustStatus`.
    /// @brief Wire token vocabulary, forwarded as-is (not re-validated or
    ///        re-interpreted here) — e.g. EKU/keyUsage-derived status
    ///        strings the agent already resolved. The closed set, if any, is
    ///        agent-defined; this library does not constrain it.
    QStringList securityStatus;
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result struct.
};

/// @brief The card-independent, synchronous visible-signature layout preview
///        result — `AgentClient::layoutVisualSignature()`'s return value.
///
/// Mirrors the agent's `LibreSCRS::Signing::VisualSignatureLayout` /
/// wire `layout` reply arm field-for-field. `clipped` is PIXEL-PARITY
/// load-bearing: `true` means even the floor font size does not fit the
/// requested box, so a renderer MUST install the same clip path the agent's
/// PAdES emitter installs when it actually stamps the signature — the
/// preview-parity rule a GUI client's preview renderer depends on (see
/// `AgentClient::layoutVisualSignature()`'s doc comment).
struct LayoutResult
{
    double fontSize = 0.0;   ///< PDF user units.
    double lineHeight = 0.0; ///< PDF user units.
    QStringList lines;       ///< Word-wrapped text, one entry per rendered line.
    bool clipped = false;    ///< See the struct doc comment.
    QVariantMap extra;       ///< Forward-compatible pass-through, as on every result struct.
};

} // namespace LibreSCRS::AgentClient
