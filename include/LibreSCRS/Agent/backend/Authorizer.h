// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>

#include <string_view>

namespace LibreSCRS::Agent {

// Authorization action ids for Config1 mutation, gated by the Authorizer.
// Shared by the backend's action-selection path and the Authorizer implementations
// so the strings cannot drift between the two.
inline constexpr const char* kActionConfigure = "org.librescrs.agent.configure";
inline constexpr const char* kActionConfigureTrust = "org.librescrs.agent.configure.trust";
// Card1.Sign authorization. Default-allow (NOT auth_self): the signing PIN is
// the human-presence proof; the authorization action exists so a site policy CAN
// restrict which clients may request a signature, and the rate-limiter caps
// abuse under the default.
inline constexpr const char* kActionSign = "org.librescrs.agent.sign";
// PKCS#11 lease establishment (Pkcs11_1.Login). Default-allow, PIN-as-consent
// (the prompter PIN is the human-presence proof), site-restrictable. The lease
// + rate-limiter bound abuse; SignRaw/Decrypt within an active lease are NOT
// re-authorized (the lease is the grant) but ARE audited.
inline constexpr const char* kActionPkcs11Login = "org.librescrs.agent.pkcs11.login";

// Authorization-of-the-CLIENT policy gate (distinct from authentication-TO-the-
// card, which is the PIN). Shared by Config1 mutation and, later, Card1.Sign
// (org.librescrs.agent.sign). Injected by ctor-DI (no singleton).
//
// @p caller is an opaque, transport-resolved CallerToken identifying the
// requesting client (Linux: the unique D-Bus name, e.g. ":1.42", captured from
// the in-flight message). Unlike a bare pid_t it is REUSE-IMMUNE for the
// connection's lifetime, so it is a TOCTOU-safe handle for an authorization
// subject: the platform Authorizer impl resolves it to a process subject (pidfd
// / start-time pinned) at authorization-check time. authorize() MUST be called synchronously
// while the requesting client is blocked on the reply.
class Authorizer
{
public:
    virtual ~Authorizer() = default;
    [[nodiscard]] virtual bool authorize(std::string_view actionId, const CallerToken& caller) = 0;
};

// Allows every action. Test/dev only, and the explicit "no policy gate" mode.
class AllowAllAuthorizer final : public Authorizer
{
public:
    [[nodiscard]] bool authorize(std::string_view /*actionId*/, const CallerToken& /*caller*/) override
    {
        return true;
    }
};

// Degraded fallback used only when the platform authorization service is
// unreachable at startup (no system authorization backend). Fail-closed
// allow-LIST: only the low-tier configure action, the default-allow sign action
// and the default-allow PKCS#11 login action are permitted; everything else —
// the trust/timestamping tier (configure.trust requires auth_self, which only
// the real authorization service can satisfy) and any future/unknown action id
// — is denied. So TsaUrls/TslSources cannot be changed remotely in this mode;
// they are seeded via the agent's config file (the file-load path bypasses this
// gate). In the normal path the platform Authorizer impl replaces this with a
// policy-backed authorizer.
class DefaultAuthorizer final : public Authorizer
{
public:
    [[nodiscard]] bool authorize(std::string_view actionId, const CallerToken& /*caller*/) override
    {
        return actionId == kActionConfigure || actionId == kActionSign || actionId == kActionPkcs11Login;
    }
};

} // namespace LibreSCRS::Agent
