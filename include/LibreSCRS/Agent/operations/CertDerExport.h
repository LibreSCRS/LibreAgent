// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h> // CandidateList
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Pure: return the DER whose sha256Hex equals @p certId, else nullopt. Exposed
// for unit testing the matcher independently of card I/O.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
matchCertDer(const std::vector<std::vector<std::uint8_t>>& candidateDers, const std::string& certId);

// Live export: re-read the PKI candidates off @p session and return the DER for
// @p certId. Reuses the same candidate routing as selectSigningCandidate (the
// applet self-activates on the live session). nullopt when no candidate owns it.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
exportCertDer(const CandidateList& candidates, const std::string& certId, LibreSCRS::SmartCard::CardSession& session);

} // namespace LibreSCRS::Agent::Operations
