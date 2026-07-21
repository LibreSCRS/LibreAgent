// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>

#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Programmable recording double over the CredentialManager seam. Each method
// records its call (plus the non-secret pinLabel; secret arguments are
// retained as independently-cleansed Secure::String copies — never
// std::string) and returns the pre-seeded result. Unseeded mutation results
// default to Unsupported — the answer of a card that advertises no credential
// management — so an unwired fake fails the same, valid way a real bare card
// does.
struct FakeCredentialManager final : CredentialManager
{
    std::vector<LibreSCRS::Plugin::PinStatusEntry> listResult;
    // Identity returned with listResult (CredentialListing::pluginId): the
    // candidate a real seam would report as the listing winner.
    std::string listPluginId;
    LibreSCRS::Plugin::PINResult changePinResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    LibreSCRS::Plugin::PINResult activateTransportPinResult{.outcome =
                                                                LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    LibreSCRS::Plugin::PINResult activateSigningKeyResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};

    enum class Call { List, ChangePin, ActivateTransportPin, ActivateSigningKey };
    std::vector<Call> calls;
    std::string lastPinLabel;
    LibreSCRS::Secure::String lastOldPin;
    LibreSCRS::Secure::String lastNewPin;
    LibreSCRS::Secure::String lastTransportValue;
    LibreSCRS::Secure::String lastSignPin;

    [[nodiscard]] CredentialListing list(LibreSCRS::SmartCard::CardSession&, const CandidateList&) override
    {
        calls.push_back(Call::List);
        return {listResult, listPluginId};
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                         std::string_view pinLabel,
                                                         const LibreSCRS::Secure::String& oldPin,
                                                         const LibreSCRS::Secure::String& newPin) override
    {
        calls.push_back(Call::ChangePin);
        lastPinLabel = std::string{pinLabel};
        lastOldPin = oldPin;
        lastNewPin = newPin;
        return changePinResult;
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&,
                                                                    const CandidateList&, std::string_view pinLabel,
                                                                    const LibreSCRS::Secure::String& transportValue,
                                                                    const LibreSCRS::Secure::String& newPin) override
    {
        calls.push_back(Call::ActivateTransportPin);
        lastPinLabel = std::string{pinLabel};
        lastTransportValue = transportValue;
        lastNewPin = newPin;
        return activateTransportPinResult;
    }
    [[nodiscard]] LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&,
                                                                  const CandidateList&,
                                                                  const LibreSCRS::Secure::String& signPin) override
    {
        calls.push_back(Call::ActivateSigningKey);
        lastSignPin = signPin;
        return activateSigningKeyResult;
    }
};

} // namespace LibreSCRS::Agent::Operations
