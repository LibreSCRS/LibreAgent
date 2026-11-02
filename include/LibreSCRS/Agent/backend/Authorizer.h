// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h>

#include <cstdint>
#include <functional>
#include <string_view>

namespace LibreSCRS::Agent {

/// What the policy gate concluded. THREE states, because two cannot tell a
/// refusal from a silence: a client told "not authorized" when the authority
/// never answered has been told something untrue about a security decision.
enum class AuthorizationOutcome : std::uint8_t {
    Granted,   ///< The authority answered, and the answer was yes.
    Denied,    ///< The authority answered, and the answer was no.
    Undecided, ///< No answer was obtained. NOTHING was decided, nothing was done.
};

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
// Credentials1 mutation (ManagePin / ActivateSigningKey). Default-allow,
// PIN-as-consent (the PIN(s) collected during the operation are the
// human-presence proof), site-restrictable. Same posture as Card1.Sign; the
// rate-limiter caps abuse under the default-allow gate.
inline constexpr const char* kActionCredentialsManage = "org.librescrs.agent.credentials.manage";

// Authorization-of-the-CLIENT policy gate (distinct from authentication-TO-the-
// card, which is the PIN). Shared by Config1 mutation and, later, Card1.Sign
// (org.librescrs.agent.sign). Injected by ctor-DI (no singleton).
//
// @p caller is an opaque, transport-resolved CallerToken identifying the
// requesting client (Linux: the unique D-Bus name, e.g. ":1.42", captured from
// the in-flight message). Unlike a bare pid_t it is REUSE-IMMUNE for the
// connection's lifetime, so it is a TOCTOU-safe handle for an authorization
// subject: the platform Authorizer impl resolves it to a process subject (pidfd
// / start-time pinned) at authorization-check time, while the requesting client
// is still waiting on its reply.
//
// Two ways to ask. authorizeAsync() is the one a request dispatcher uses: an
// authority may hold its answer while a PERSON decides (a polkit password
// dialog), and a dispatcher that waited for it would stop serving every other
// client -- and, on a bus connection, every signal the agent's worker threads
// emit -- for as long as the dialog stays open. authorize() remains for callers
// that are not on a dispatch thread and for the authorities that never wait
// (every in-core implementation below).
class Authorizer
{
public:
    /// Receives the outcome of one authorizeAsync() call, exactly once.
    using Completion = std::function<void(AuthorizationOutcome)>;

    virtual ~Authorizer() = default;

    /// Decide synchronously. The caller waits for the authority's answer.
    [[nodiscard]] virtual AuthorizationOutcome authorize(std::string_view actionId, const CallerToken& caller) = 0;

    /// Decide without making the caller wait. @p done runs exactly once with
    /// the outcome: inline, before this returns, for an authority that answers
    /// at once (the default, which forwards to authorize()), or later -- on
    /// whatever thread the authority answers on -- for one that has to wait.
    /// The caller therefore defers its own reply into @p done and must not
    /// assume where or when it runs; what @p done captures must outlive that.
    virtual void authorizeAsync(std::string_view actionId, const CallerToken& caller, Completion done)
    {
        done(authorize(actionId, caller));
    }
};

// Degraded fallback used only when the platform authorization service is
// unreachable at startup (no system authorization backend). Fail-closed
// allow-LIST: only the low-tier configure action, the default-allow sign action,
// the default-allow PKCS#11 login action and the default-allow credential-manage
// action are permitted; everything else — the trust/timestamping tier
// (configure.trust requires auth_self, which only the real authorization service
// can satisfy) and any future/unknown action id — is denied. So TsaUrls/TslSources
// cannot be changed remotely in this mode; they are seeded via the agent's config
// file (the file-load path bypasses this gate). In the normal path the platform
// Authorizer impl replaces this with a policy-backed authorizer.
class DefaultAuthorizer final : public Authorizer
{
public:
    // Never Undecided: this fallback calls out to nothing external, so there is
    // nothing that can fail to answer.
    [[nodiscard]] AuthorizationOutcome authorize(std::string_view actionId, const CallerToken& /*caller*/) override
    {
        return (actionId == kActionConfigure || actionId == kActionSign || actionId == kActionPkcs11Login ||
                actionId == kActionCredentialsManage)
                   ? AuthorizationOutcome::Granted
                   : AuthorizationOutcome::Denied;
    }
};

} // namespace LibreSCRS::Agent
