// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Minimal downstream consumer for the ClientQt-only case (PKGSMOKE_COMPONENTS
// set to ClientQt): includes a public client header via its installed path
// and exercises a value type whose implementation needs neither a live
// QCoreApplication nor a D-Bus session, so this stays a plain link/resolve
// proof — the full running-consumer proof already exists in ci.yml's
// client-lm-less job. Success here proves the installed CONFIG package
// resolves LibreAgent::ClientQt (and only the dependencies ClientQt actually
// needs) without pulling in LibreMiddleware; see
// fixtures/LibreAgentCoreTargets.stub.cmake for the co-installation case this
// guards against.
#include <LibreSCRS/AgentClient/FdHandle.h>

int main()
{
    const LibreSCRS::AgentClient::FdHandle handle;
    return handle.valid() ? 1 : 0;
}
