// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/AgentClient/FdHandle.h>

#include <QString>
#include <QVariant>

#include <cstdint>

// Typed Card1.Sign / Credentials1 vocabulary for the lifted AgentClient API
// (a later task). Each enum here has exactly one wire token string; the
// mapping table lives in the INTERNAL client/qt/src/TokenMap.{h,cpp} TU
// (never in a public header -- a wire token is an encoding detail, not part
// of this library's C++ API) and is pinned against the CDDL/agent-side
// vocabulary by client/qt/tests/TokenMapTest.cpp's round-trip tests.
namespace LibreSCRS::AgentClient {

// wire/librescrs-agent.cddl's sign-opts.format; LibreSCRS::Agent::Operations::
// SignatureParams::isKnownFormat's closed set.
enum class SignatureFormat : std::uint8_t {
    PAdES,
    CAdES,
    XAdES,
    JAdES,
    ASiCe,
};

// wire/librescrs-agent.cddl's sign-opts.level; SignatureParams::isKnownLevel's
// closed set (b-b/b-t/b-lt/b-lta).
enum class SignatureLevel : std::uint8_t {
    BB,
    BT,
    BLT,
    BLTA,
};

// wire/librescrs-agent.cddl's sign-opts.packaging. Enveloping is
// forward-declared here for API completeness but has no agent-side
// counterpart yet -- SignatureParams::isKnownPackaging accepts only
// enveloped/detached today (see SignatureParamsTest.cpp's
// "enveloping is out of scope" case); a Sign call with Packaging::Enveloping
// is rejected agent-side (Error.UnsupportedSignatureParameter), not by this
// library.
enum class Packaging : std::uint8_t {
    Enveloped,
    Enveloping,
    Detached,
};

// wire/librescrs-agent.cddl's cred-verb ("change" / "unblock" /
// "activate_pin"), the ManagePin request's verb field.
enum class PinVerb : std::uint8_t {
    Change,
    Unblock,
    ActivatePin,
};

// Card1.Sign options. Defaults match the agent's own invisible-signature,
// baseline-level, enveloped-container default (see sign-opts in the CDDL and
// SignatureParams::defaultPackagingFor).
struct SignOptions
{
    SignatureFormat format = SignatureFormat::PAdES;
    SignatureLevel level = SignatureLevel::BB;
    Packaging packaging = Packaging::Enveloped;
    QVariantMap visualSignature; // empty = invisible
    QString tsaUrl;              // empty = agent default (Config1's LastTsaUrl/TsaUrls)
    QVariantMap extra;
};

// One photo field's key alongside the artifact fd carrying its bytes (the
// event-side photo-result's `{key, fd}` pair, wire/librescrs-agent.cddl).
// Move-only (FdHandle is move-only): a GetPhoto result is returned as
// std::vector<PhotoItem>, never copied.
struct PhotoItem
{
    QString key;
    FdHandle fd;
    QVariantMap extra; // forward-compatible metadata pass-through, as on every other result/options struct
};

} // namespace LibreSCRS::AgentClient
