// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Observations shared out of the const plugin entry points (candidates are
// shared_ptr<const CardPlugin>, so the stub cannot record into itself).
struct PinOpsRecorder
{
    int pinListCalls{0};
    int changeCalls{0};
    int transportCalls{0};
    int signKeyCalls{0};
    std::string lastLabel;
    LibreSCRS::Secure::String lastOldPin;
    LibreSCRS::Secure::String lastNewPin;
    LibreSCRS::Secure::String lastTransportValue;
    LibreSCRS::Secure::String lastSignPin;
};

// Plugin that overrides NONE of the PIN entry points: calls reach the LM base
// defaults, so a seam observes a REAL Unsupported / empty list — not a
// synthetic one minted by the test.
class BasePinPlugin : public LibreSCRS::Plugin::CardPlugin
{
public:
    explicit BasePinPlugin(
        std::string id, LibreSCRS::Plugin::CardCapabilities caps = LibreSCRS::Plugin::CardCapabilities::PinManagement)
        : m_caps(caps)
    {
        setIdentity(std::move(id), "stub", 0);
    }
    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return m_caps;
    }
    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession&, GroupCallback) const override
    {
        return LibreSCRS::Plugin::ReadResult::communicationError(LibreSCRS::Auth::ErrorKeys::genericComm());
    }

private:
    LibreSCRS::Plugin::CardCapabilities m_caps;
};

// Stub overriding all four PIN entry points: canned results + recording.
class PinStubPlugin final : public BasePinPlugin
{
public:
    PinStubPlugin(std::string id, std::shared_ptr<PinOpsRecorder> rec,
                  LibreSCRS::Plugin::CardCapabilities caps = LibreSCRS::Plugin::CardCapabilities::PinManagement)
        : BasePinPlugin(std::move(id), caps), m_rec(std::move(rec))
    {}

    std::vector<LibreSCRS::Plugin::PinStatusEntry> pinList;
    LibreSCRS::Plugin::PINResult mutationResult; // returned by all three mutating entry points
    bool throwOnPinList{false};
    bool throwOnMutation{false};

    std::vector<LibreSCRS::Plugin::PinStatusEntry> getPINList(LibreSCRS::SmartCard::CardSession&) const override
    {
        ++m_rec->pinListCalls;
        if (throwOnPinList) {
            throw std::runtime_error{"stub: getPINList failed"};
        }
        return pinList;
    }
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, std::string_view pinLabel,
                                           const LibreSCRS::Secure::String& oldPin,
                                           const LibreSCRS::Secure::String& newPin) const override
    {
        ++m_rec->changeCalls;
        if (throwOnMutation) {
            throw std::runtime_error{"stub: changePIN failed"};
        }
        m_rec->lastLabel = std::string{pinLabel};
        m_rec->lastOldPin = oldPin;
        m_rec->lastNewPin = newPin;
        return mutationResult;
    }
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&, std::string_view pinLabel,
                                                      const LibreSCRS::Secure::String& transportValue,
                                                      const LibreSCRS::Secure::String& newPin) const override
    {
        ++m_rec->transportCalls;
        if (throwOnMutation) {
            throw std::runtime_error{"stub: activateTransportPin failed"};
        }
        m_rec->lastLabel = std::string{pinLabel};
        m_rec->lastTransportValue = transportValue;
        m_rec->lastNewPin = newPin;
        return mutationResult;
    }
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&,
                                                    const LibreSCRS::Secure::String& signPin) const override
    {
        ++m_rec->signKeyCalls;
        if (throwOnMutation) {
            throw std::runtime_error{"stub: activateSigningKey failed"};
        }
        m_rec->lastSignPin = signPin;
        return mutationResult;
    }

private:
    std::shared_ptr<PinOpsRecorder> m_rec;
};

} // namespace LibreSCRS::Agent::Operations
