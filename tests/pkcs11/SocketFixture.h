// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// Stand the socket double up on a private path and point the module at it.
//
// The twin of the bus backend's BusFixture, and deliberately the same SHAPE:
// the C-ABI suites that use it are one set of claims about the module, and a
// fixture that took different arguments would quietly turn "the two transports
// disagree" into "the two suites were never asking the same question".
//
// The address is handed over through the environment because that is what this
// tree's factory reads, and it is set before the module is loaded -- the client
// is constructed inside C_Initialize, not at dlopen.

#include "fakes/FakeSocketAgent.h"

#include <LibreSCRS/Agent/wire/PreReadAuth.h>

#include <cstdlib>
#include <functional>
#include <memory>
#include <string>

namespace LibreSCRS::Agent::Test {

struct SocketFixture
{
    std::unique_ptr<FakeSocketAgent> fake;

    explicit SocketFixture(bool hasCard = true, const std::string& preRead = "None",
                           const std::function<void(FakeSocketAgent&)>& cfg = {})
    {
        fake = std::make_unique<FakeSocketAgent>();
        const Wire::PreReadAuth auth = (preRead == "Can")   ? Wire::PreReadAuth::Can
                                       : (preRead == "Mrz") ? Wire::PreReadAuth::Mrz
                                                            : Wire::PreReadAuth::None;
        if (hasCard) {
            fake->addReader(kReader0, /*hasCard=*/true, kCard0, auth);
            fake->addCert(kCard0, kCertId, /*signingCapable=*/true, kDecryptableKeyUsage);
        } else {
            fake->addReader(kReader0);
        }
        if (cfg)
            cfg(*fake);
        fake->start();
        ::setenv("LIBRESCRS_AGENT_SOCK", fake->path().c_str(), 1);
    }

    ~SocketFixture()
    {
        ::unsetenv("LIBRESCRS_AGENT_SOCK");
    }

    SocketFixture(const SocketFixture&) = delete;
    SocketFixture& operator=(const SocketFixture&) = delete;
};

} // namespace LibreSCRS::Agent::Test
