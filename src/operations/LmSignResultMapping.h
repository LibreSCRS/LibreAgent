// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL, not installed (lives under src/, not include/): the pure LM
// SigningResult::Status -> SignOutcome::Status classification LmSigner::sign
// drives, pulled out into its own free function so it is unit-testable in
// isolation against a hand-built SigningResult -- no live card session, no
// signing engine, no PC/SC. Declaring this in LmSeams.h (the public,
// installed header) would pull LM's Signing types into every LmSeams.h
// consumer, breaking the seam-boundary invariant documented there ("LmSeams.cpp
// is the ONLY agent TU that consumes the LM Signing surface"); this header
// extends that boundary by exactly one sibling TU (this one, plus its
// dedicated test), mirroring LmSigningRequestBuilder.h's own precedent.
//
// Why this exists: BatchSignFlow's own unit tests use a fake Signer, so they
// can prove the FLOW's halt-code mapping (SignOutcome::Status::AuthFailed/
// CardBlocked -> ErrorCode::CredentialWrong/CredentialBlocked) but can never
// observe whether LmSigner itself still classifies the LM library's own
// PinVerificationFailed/CardBlocked statuses into those two SignOutcome
// values -- a regression there would slip past every fake-signer test. This
// header/its test close that gap.
#include <LibreSCRS/Agent/operations/Seams.h> // SignOutcome
#include <LibreSCRS/Signing/SigningResult.h>

namespace LibreSCRS::Agent::Operations {

// Translate an LM SigningResult's terminal status into the seam's hermetic
// SignOutcome::Status. KeyAmbiguous is a SigningEngineError on the LM wire
// distinguished only by its dedicated ErrorKey (the CKA_ID duplicate-
// detection). PinVerificationFailed/CardBlocked are the two statuses that
// cause a caller (BatchSignFlow) to halt a batch, downstream-mapped to
// ErrorCode::CredentialWrong/CredentialBlocked.
[[nodiscard]] SignOutcome::Status mapSigningResultStatus(const LibreSCRS::Signing::SigningResult& r) noexcept;

} // namespace LibreSCRS::Agent::Operations
