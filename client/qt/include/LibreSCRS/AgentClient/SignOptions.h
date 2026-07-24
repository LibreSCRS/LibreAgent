// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QString>
#include <QVariant>

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
    QVariantMap visualSignature;                     ///< Visible-signature placement/appearance; empty means invisible.
    QString tsaUrl;    ///< Timestamp authority URL; empty means the agent default (Config1's LastTsaUrl/TsaUrls).
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

} // namespace LibreSCRS::AgentClient
