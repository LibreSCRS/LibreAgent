// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL, not installed (lives under src/, not include/): the pure
// SignParams -> LM SigningRequest assembly LmSigner::sign drives, pulled out
// into its own free function so it is unit-testable in isolation -- no live
// card session, no signing engine, no plugin candidates. Declaring this in
// LmSeams.h (the public, installed header) would pull LM's Signing types into
// every LmSeams.h consumer, breaking the seam-boundary invariant documented
// there ("LmSeams.cpp is the ONLY agent TU that consumes the LM Signing
// surface"); this header extends that same boundary by exactly one sibling
// TU (this one, plus its dedicated test), never the public include tree.
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Signing/Enums.h>
#include <LibreSCRS/Signing/SigningRequest.h>

#include <cstdint>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Assemble the immutable LM SigningRequest for one sign, given the already-
// resolved concrete format/level/packaging (mapFormat/mapLevel/mapPackaging
// have already turned the SignParams' wire strings into these enums by the
// time LmSigner calls this) plus the target key's ckaId and whether the
// expired-cert gate allows this sign to proceed with an expired certificate.
//
// tsaUrl -> LM per-request TSA override: @p params.tsaUrl empty installs NO
// override (the request rides the engine's own service-level TsaProvider,
// built from Config's TsaUrls); non-empty installs `staticTsa(tsaUrl)` --
// NOT the validating `staticTsaChecked`, because the https+host shape was
// already validated at the agent's method entry (CardObject::Sign /
// SocketFrontend::handleSign) before a SignParams was even constructed; using
// the non-throwing factory here means a THIRD, defense-in-depth check would
// never itself throw for an input that already passed entry validation.
//
// visual -> LM's PAdES-only VisualSignatureParams::Builder (pageIndex/rect/
// textTemplate), float pixel-parity source (x/y/width/height are the wire's
// float64) rounded to LM's integer Rect (PDF user units are integer
// quantities at that API boundary).
//
// Throws std::invalid_argument iff SigningRequest::Builder::build() itself
// does (in practice: `visual` paired with a non-PAdES @p format) -- entry
// validation is expected to have already rejected that combination, so this
// is a defense-in-depth throw, not the primary rejection path. LmSigner::sign
// wraps this call in a try/catch and maps the throw onto
// SignOutcome::Status::SigningEngineError.
[[nodiscard]] LibreSCRS::Signing::SigningRequest
buildSigningRequest(const SignParams& params, LibreSCRS::Signing::SignatureFormat format,
                    LibreSCRS::Signing::SignatureLevel level, LibreSCRS::Signing::PackagingMode packaging,
                    const std::vector<std::uint8_t>& keyId, bool allowExpiredCert);

} // namespace LibreSCRS::Agent::Operations
