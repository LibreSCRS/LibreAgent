// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/MrzPayload.h> // MrzParts
#include <LibreSCRS/Agent/operations/Seams.h>

#include <cstddef>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Programmable recording double over the CredentialDepositor seam. Records the
// plugin-facing parts of every deposit (the check-digit-STRIPPED trio the
// plugin setCredentials keys consume) plus how many candidates the caller
// offered, and answers a scripted verdict. Lets the renegotiation leg be
// asserted end-to-end without a plugin registry or a real card.
//
// The recorded fields are plain std::strings: a test fixture spells ICAO
// specimen values, never a real document's secret (the no-plain-copy rule
// binds the PRODUCTION parser/deposit path).
struct FakeCredentialDepositor final : CredentialDepositor
{
    struct Deposit
    {
        std::string documentNumber;
        std::string dateOfBirth;
        std::string dateOfExpiry;
        std::size_t candidateCount{0};
    };

    std::vector<Deposit> deposits;
    // Scripted return: "at least one candidate accepted a deposit attempt".
    bool accepted{true};

    bool depositMrz(LibreSCRS::SmartCard::CardSession&, const CandidateList& candidates, const MrzParts& parts) override
    {
        deposits.push_back(Deposit{
            .documentNumber = std::string{parts.documentNumber.view()},
            .dateOfBirth = std::string{parts.dateOfBirth.view()},
            .dateOfExpiry = std::string{parts.dateOfExpiry.view()},
            .candidateCount = candidates.size(),
        });
        return accepted;
    }
};

} // namespace LibreSCRS::Agent::Operations
