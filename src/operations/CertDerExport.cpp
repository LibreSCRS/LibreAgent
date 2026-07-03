// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Agent/operations/CertDerExport.h>
#include <LibreSCRS/Agent/util/Sha256Hex.h> // sha256Hex
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>

namespace LibreSCRS::Agent::Operations {

std::optional<std::vector<std::uint8_t>> matchCertDer(const std::vector<std::vector<std::uint8_t>>& candidateDers,
                                                      const std::string& certId)
{
    for (const auto& der : candidateDers) {
        if (!der.empty() && sha256Hex(der) == certId) {
            return der;
        }
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> exportCertDer(const CandidateList& candidates, const std::string& certId,
                                                       LibreSCRS::SmartCard::CardSession& session)
{
    for (const auto& cand : candidates) {
        if (!cand) {
            continue;
        }
        std::vector<LibreSCRS::Plugin::CertificateData> certs;
        try {
            certs = cand->readCertificates(session);
        } catch (...) {
            log::warn("certder: a candidate threw on readCertificates; skipping");
            continue;
        }
        std::vector<std::vector<std::uint8_t>> ders;
        ders.reserve(certs.size());
        for (auto& cd : certs) {
            ders.push_back(std::move(cd.derBytes));
        }
        if (auto hit = matchCertDer(ders, certId)) {
            return hit;
        }
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Agent::Operations
