// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// Internal wire-token <-> enum vocabulary for SignOptions.h's typed enums.
// NOT a public header (lives in client/qt/src/, not client/qt/include/) --
// a wire token is an encoding detail of how the Qt client's lifted API (a
// later task) talks to the socket wire; nothing declared here is installed
// or part of this library's public API/ABI.
//
// Every token string is pinned against its ONE authoritative source:
//   - format/level/packaging: LibreSCRS::Agent::Operations::SignatureParams
//     (include/LibreSCRS/Agent/operations/SignatureParams.h)'s
//     isKnownFormat/isKnownLevel/isKnownPackaging closed sets -- the SAME
//     strings SignFlow.cpp passes through unvalidated from the wire's
//     sign-opts.{format,level,packaging}. Packaging::Enveloping has no
//     agent-side counterpart yet (see SignOptions.h's own doc comment);
//     "enveloping" is a forward-declared token in the same lowercase
//     convention as its two siblings.
//   - PinVerb: wire/librescrs-agent.cddl's `cred-verb` group
//     ("change" / "unblock" / "activate_pin").
//
// Round-trip (enum -> token -> enum) coverage for every pair, plus
// unknown-token -> nullopt, lives in client/qt/tests/TokenMapTest.cpp.
#include <LibreSCRS/AgentClient/SignOptions.h>

#include <optional>
#include <string_view>

namespace LibreSCRS::AgentClient::detail {

[[nodiscard]] std::string_view toToken(SignatureFormat format) noexcept;
[[nodiscard]] std::string_view toToken(SignatureLevel level) noexcept;
[[nodiscard]] std::string_view toToken(Packaging packaging) noexcept;
[[nodiscard]] std::string_view toToken(PinVerb verb) noexcept;

[[nodiscard]] std::optional<SignatureFormat> signatureFormatFromToken(std::string_view token) noexcept;
[[nodiscard]] std::optional<SignatureLevel> signatureLevelFromToken(std::string_view token) noexcept;
[[nodiscard]] std::optional<Packaging> packagingFromToken(std::string_view token) noexcept;
[[nodiscard]] std::optional<PinVerb> pinVerbFromToken(std::string_view token) noexcept;

} // namespace LibreSCRS::AgentClient::detail
