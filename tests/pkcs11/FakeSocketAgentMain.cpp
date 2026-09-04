// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Standalone process that stands the socket agent double up on a path given to
// it, and idles until killed. Used by the pkcs11-tool integration test so an
// EXTERNAL consumer can drive the real C_* ABI against a fake card backend,
// exactly as a deployed application would drive it against the real agent.
//
// Argv: <socket-path> [hasCard(0|1)] [preReadAuth(None|Mrz|Can)]

#include "fakes/FakeSocketAgent.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

namespace {
volatile std::sig_atomic_t g_stop = 0;
void onSignal(int)
{
    g_stop = 1;
}
} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::fputs("usage: FakeSocketAgentMain <socket-path> [hasCard] [preReadAuth]\n", stderr);
        return 2;
    }
    namespace T = LibreSCRS::Agent::Test;
    namespace W = LibreSCRS::Agent::Wire;

    const bool hasCard = argc < 3 || std::strcmp(argv[2], "0") != 0;
    const std::string preRead = argc >= 4 ? argv[3] : "None";
    const W::PreReadAuth auth = (preRead == "Can")   ? W::PreReadAuth::Can
                                : (preRead == "Mrz") ? W::PreReadAuth::Mrz
                                                     : W::PreReadAuth::None;

    // SIGPIPE would take this process down when a consumer disconnects
    // mid-reply, which is an ordinary thing for a consumer to do.
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);

    T::FakeSocketAgent fake;
    fake.setPath(argv[1]);
    if (hasCard) {
        fake.addReader(T::kReader0, /*hasCard=*/true, T::kCard0, auth);
        fake.addCert(T::kCard0, T::kCertId, /*signingCapable=*/true, T::kDecryptableKeyUsage);
    } else {
        fake.addReader(T::kReader0);
    }
    fake.start();

    // Readiness on stdout, so the harness waits on an event rather than a sleep.
    std::fputs("READY\n", stdout);
    std::fflush(stdout);

    while (g_stop == 0) {
        const timespec ts{0, 50 * 1000 * 1000};
        nanosleep(&ts, nullptr);
    }
    fake.stop();
    return 0;
}
