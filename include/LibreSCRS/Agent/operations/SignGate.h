// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// The per-level expired-cert gate as a pure decision, factored out of
// LmSigner so the policy is unit-testable without a live card or LM types. The
// "expired" input is computed from the cert's notAfter at the call site; the
// other two come from the signing level/options.
namespace LibreSCRS::Agent::Operations {

enum class ExpiredGate {
    Proceed,                // not expired (or otherwise fine): sign normally
    ProceedAllowingExpired, // B-B + expired + explicit consent: forward allowExpiredCert(true)
    Blocked,                // expired + (qualified-family OR no B-B consent): CertExpiredBlocked
};

// Policy:
//   - not expired                              -> Proceed
//   - expired + qualified-family (B-T/LT/LTA)  -> Blocked ALWAYS (never honour
//       allowExpired: a timestamp over an expired cert is internally inconsistent)
//   - expired + B-B + allowExpired             -> ProceedAllowingExpired
//   - expired + B-B + !allowExpired            -> Blocked (consent required)
[[nodiscard]] constexpr ExpiredGate evaluateExpiredGate(bool expired, bool qualifiedFamily, bool allowExpired) noexcept
{
    if (!expired) {
        return ExpiredGate::Proceed;
    }
    if (qualifiedFamily) {
        return ExpiredGate::Blocked;
    }
    return allowExpired ? ExpiredGate::ProceedAllowingExpired : ExpiredGate::Blocked;
}

} // namespace LibreSCRS::Agent::Operations
