// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/ErrorCode.h>
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QString>
#include <QVariant>

#include <cstddef>
#include <cstdint>

/// @file
/// @brief Typed `Card1.Sign` / `Credentials1` vocabulary for the
///        `AgentClient` API.
///
/// Each enum here has exactly one wire token string; the mapping table
/// lives in the INTERNAL `client/qt/src/TokenMap.{h,cpp}` TU (never in a
/// public header — a wire token is an encoding detail, not part of this
/// library's C++ API) and is pinned against the CDDL/agent-side vocabulary
/// by `client/qt/tests/TokenMapTest.cpp`'s round-trip tests.
namespace LibreSCRS::AgentClient {

/// @brief Signature container format (wire/librescrs-agent.cddl's
///        `sign-opts.format`; `LibreSCRS::Agent::Operations::SignatureParams::isKnownFormat`'s
///        closed set).
enum class SignatureFormat : std::uint8_t {
    PAdES, ///< PDF Advanced Electronic Signature.
    CAdES, ///< CMS Advanced Electronic Signature.
    XAdES, ///< XML Advanced Electronic Signature.
    JAdES, ///< JSON Advanced Electronic Signature.
    ASiCe, ///< Associated Signature Container, extended (ASiC-E).
};

/// @brief eIDAS AdES conformance level (wire/librescrs-agent.cddl's
///        `sign-opts.level`; `SignatureParams::isKnownLevel`'s closed set).
enum class SignatureLevel : std::uint8_t {
    BB,   ///< B-B: baseline, no timestamp.
    BT,   ///< B-T: baseline + signing-time timestamp.
    BLT,  ///< B-LT: baseline + long-term validation material embedded.
    BLTA, ///< B-LTA: baseline + long-term validation + archive timestamp.
};

/// @brief Signature packaging relative to the signed document
///        (wire/librescrs-agent.cddl's `sign-opts.packaging`).
///
/// `Enveloping` is forward-declared here for API completeness but has no
/// agent-side counterpart yet — `SignatureParams::isKnownPackaging` accepts
/// only enveloped/detached today (see `SignatureParamsTest.cpp`'s
/// "enveloping is out of scope" case); a `sign()` call with
/// `Packaging::Enveloping` is rejected agent-side
/// (`Error.UnsupportedSignatureParameter`), not by this library.
enum class Packaging : std::uint8_t {
    Enveloped,  ///< Signature embedded inside the document container (e.g. PAdES-in-PDF).
    Enveloping, ///< Document embedded inside the signature container. Not yet supported agent-side.
    Detached,   ///< Signature and document ship as separate artifacts.
};

/// @brief Credential mutation verb for `AgentCard::managePin()`
///        (wire/librescrs-agent.cddl's `cred-verb`: "change" / "unblock" /
///        "activate_pin"), the ManagePin request's `verb` field.
enum class PinVerb : std::uint8_t {
    Change,      ///< Change a known-good PIN/CAN to a new value.
    Unblock,     ///< Unblock a blocked credential via its PUK/recovery path.
    ActivatePin, ///< Move a transport PIN to operational (first-use activation).
};

/// @brief `Card1.Sign` options for `AgentCard::sign()`.
///
/// Defaults match the agent's own invisible-signature, baseline-level,
/// enveloped-container default (see `sign-opts` in the CDDL and
/// `SignatureParams::defaultPackagingFor`).
struct SignOptions
{
    SignatureFormat format = SignatureFormat::PAdES; ///< Signature container format.
    SignatureLevel level = SignatureLevel::BB;       ///< eIDAS AdES conformance level.
    Packaging packaging = Packaging::Enveloped;      ///< Packaging relative to the document.
    /// Visible-signature placement/appearance; empty means invisible. PAdES
    /// only — the agent rejects a populated map paired with any other
    /// `format` (`Error.UnsupportedSignatureParameter`). Gated on the
    /// `"visual-sign"` feature token: `AgentCard::sign()` refuses locally
    /// with `ErrorCode::CapabilityMissing` when this is non-empty and the
    /// connected agent's `features()` lacks that token, on both transports,
    /// before the request is ever sent.
    ///
    /// Required keys, exactly mirroring the wire's `visualSignature` nested
    /// map (`wire/librescrs-agent.cddl`'s `visual-sig-opts`) — all six are
    /// required together, not independently optional:
    ///   - `"page"` (uint, 0-based)
    ///   - `"x"`, `"y"`, `"width"`, `"height"` (double, PDF user units;
    ///     width/height must be positive)
    ///   - `"text"` (string; may contain `{placeholder}` tokens the engine
    ///     resolves at sign time)
    QVariantMap visualSignature;
    /// Timestamp authority URL for THIS sign only; empty means the agent
    /// default (Config1's LastTsaUrl/TsaUrls). https-only, non-empty host —
    /// the agent rejects anything else at method entry
    /// (`Error.UnsupportedSignatureParameter`), as it does a tsaUrl paired
    /// with `SignatureLevel::BB` (meaningful only for the timestamped/
    /// long-term family). Gated on the `"tsa-url"` feature token, the same
    /// posture as `visualSignature` above.
    QString tsaUrl;
    QVariantMap extra; ///< Forward-compatible pass-through, as on every result/options struct.
};

/// @brief One photo field's key alongside the artifact fd carrying its bytes
///        (the event-side photo-result's `{key, fd}` pair,
///        wire/librescrs-agent.cddl).
///
/// Move-only (`FdHandle` is move-only): a `getPhoto()` result is returned as
/// `std::vector<PhotoItem>`, never copied.
struct PhotoItem
{
    QString key;       ///< Photo field key (e.g. "portrait").
    FdHandle fd;       ///< Sealed fd carrying the photo bytes; read and close promptly.
    QVariantMap extra; ///< Forward-compatible metadata pass-through, as on every other result/options struct.
};

/// @brief Minimum/maximum document count for `AgentCard::signBatch()` —
///        mirrors the wire's frozen `sign-batch` bound (the bus's
///        per-message fd budget shared by the request's document fds and the
///        result's artifact fds; see `wire/librescrs-agent.cddl`'s
///        `sign-batch` comment). Duplicated here rather than shared with a
///        Core header because this library never links `LibreAgent::Core`
///        (see `TransportSeam.h`'s file comment) — kept in lockstep with the
///        Core-side `Operations::kMinBatchDocuments`/`kMaxBatchDocuments` by
///        convention, the same way the wire's own CDDL/Messages.h comments
///        already duplicate the bound across independently-linked TUs.
inline constexpr std::size_t kMinBatchDocuments = 1;  ///< Fewer than this refuses with `CallError::InvalidArguments`.
inline constexpr std::size_t kMaxBatchDocuments = 12; ///< More than this refuses with `CallError::InvalidArguments`.

/// @brief One document entered into an `AgentCard::signBatch()` request: a
///        caller-supplied display name (untrusted chrome — echoed back
///        verbatim on the matching `BatchSignRow` and rendered, sanitized, in
///        the agent's consent prompt) plus the document's fd.
///
/// Move-only (`FdHandle` is move-only): a `signBatch()` call takes
/// `std::vector<BatchDocument>` by value and moves every fd across the seam.
struct BatchDocument
{
    QString displayName; ///< Untrusted display name, echoed back verbatim on the matching `BatchSignRow`.
    FdHandle fd;         ///< The document's bytes; ownership moves across the seam with the call.
};

/// @brief One row of a `signBatch()` result, index-aligned with the request's
///        `docs` (same order, same count).
///
/// A FAILED row (independently failed, or past the halt point of a wrong/
/// blocked signing credential) carries `error != ErrorCode::None`; its
/// `artifact` is still a VALID, open handle to the wire's pinned zero-length
/// sealed memfd (the frozen convention: `h`/the socket fd-index is
/// non-nullable, so a failed row still resolves a real, just empty,
/// descriptor) rather than an invalid/closed one — `error` is what a caller
/// checks to distinguish "failed" from "succeeded with an empty artifact",
/// never the fd's validity. `meta` is empty/default on a failed row.
///
/// Move-only (`FdHandle` is move-only), like `PhotoItem`: a `signBatch()`
/// result is returned as `std::vector<BatchSignRow>`, never copied.
struct BatchSignRow
{
    QString displayName; ///< Echoed back verbatim from the matching request `BatchDocument`.
    FdHandle artifact;   ///< Signed bytes on success; a valid zero-length handle on a failed row (see above).
    QVariantMap
        meta; ///< Signature metadata (format/level/...), as `AgentOperation::signMeta()`; empty on a failed row.
    ErrorCode error = ErrorCode::None; ///< `ErrorCode::None` on success; the row's (or halt's) failure code otherwise.
};

} // namespace LibreSCRS::AgentClient
