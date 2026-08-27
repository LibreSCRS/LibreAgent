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
    /// @brief X.509 KeyUsage bitmask: bit i (`1u << i`) is set for KeyUsage
    ///        ordinal i in RFC 5280 §4.2.1.3 order (digitalSignature = 0,
    ///        nonRepudiation = 1, ...). Zero when the certificate carries no
    ///        KeyUsage extension.
    ///
    /// Carried as a TYPED member rather than an `extra` entry on purpose: a
    /// consumer may derive a STABLE, persisted identifier from these bits
    /// (a folder/URL name, a cache key), and a string-keyed lookup would let
    /// a producer-side rename break that consumer silently — no compile
    /// error, no link error, just an empty value at run time. The name is
    /// part of the API; renaming it is a source break the compiler reports.
    /// The bits themselves are forwarded verbatim: this library neither
    /// localizes nor interprets them.
    quint32 keyUsageBits = 0;
    /// @brief ExtendedKeyUsage OIDs in dotted-decimal form, in the order the
    ///        agent supplied them; empty when the certificate carries no EKU
    ///        extension. Display-oriented, forwarded verbatim — see
    ///        `keyUsageBits` for why this is typed rather than an `extra`
    ///        entry.
    QStringList extendedKeyUsageOids;
    /// @brief Certification-path subject common names, ordered leaf..root,
    ///        display only — never a trust decision (that is `trust` /
    ///        `securityStatus`). Empty when the agent resolved no path. See
    ///        `keyUsageBits` for why this is typed rather than an `extra`
    ///        entry.
    QStringList chainSubjectCns;
    /// @brief Forward-compatible pass-through, as on every result struct, plus
    ///        two entries this type always carries.
    ///
    /// `extra["trustStatusWire"]` (`uint`) is the raw wire verdict `trust`
    /// collapsed — several wire causes share one display value, so this is the
    /// only way back to the cause.
    ///
    /// `extra["fields"]` (`QVariantMap`) is the agent's grouped certificate
    /// field dict, whole and in the agent's own grouping:
    ///
    ///     group key -> QVariantMap( field key -> QVariantList{ labelKey,
    ///                                                          labelFallback,
    ///                                                          value } )
    ///
    /// all three cell elements being `QString`. The group keys the agent emits
    /// today are `subject`, `issuer`, `validity`, `publicKey`, `cert`, `ext`,
    /// `basicConstraints`, `san`, `ian`, `crlDp`, `aia`,
    /// `certificatePolicies`, `eku` and `security` — see
    /// `librescrs-agent.cddl` (`cert-info`'s `fields` map) for the
    /// authoritative vocabulary — but that vocabulary is APPEND-ONLY on the
    /// wire and is forwarded verbatim, so a consumer must render the groups it
    /// recognises and ignore the rest rather than assume the list is closed.
    /// The enumeration above documents MEMBERSHIP, not sequence: on the wire
    /// the `fields` map's entries arrive in the map's key order, not in the
    /// order listed here.
    /// One further group, `diagnostic`, is emitted INSTEAD of all of the above
    /// (and alone) when the agent cannot parse a certificate's DER at all — it
    /// carries a single `parseError` field with the parser's own message, and
    /// is a failure channel rather than part of the certificate vocabulary,
    /// though a client decodes it through this same generic path. `labelKey`
    /// is the agent's i18n key for the field's label and `labelFallback` its
    /// English text; a consumer that has no catalogue entry for the key
    /// renders the fallback.
    ///
    /// The key is ABSENT — not an empty map — when the certificate carried no
    /// field dict at all. The typed members above are extracted FROM this dict
    /// and remain the supported way to read what they name; the dict is
    /// additional, for a consumer (a certificate viewer) that renders detail
    /// no typed member carries.
    QVariantMap extra;
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
