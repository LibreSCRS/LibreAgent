// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/operations/CardPluginRouting.h> // CandidateList
#include <LibreSCRS/Agent/operations/LmRawCrypto.h>       // RawCryptoResult
#include <LibreSCRS/Agent/operations/Seams.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {
class CredentialCache;
}

namespace LibreSCRS::Agent::Operations {

class PrompterClientBase;
class PromptSerializer;
class CardSessionHolder;

// The terminal raw-crypto op, injected so the flow's orchestration (open +
// PIN-as-consent collection + status mapping) is unit-testable against fakes
// with no live card. Production binds Operations::signRaw /
// Operations::decryptRaw; tests inject a fake that models verifyPIN + the
// on-card op. Same signature for sign and decrypt — the routed candidates +
// certId select the key, the bytes are input/ciphertext.
//
// @p pin carries the PIN-as-consent secret the flow just collected from the
// agent prompter:
//   * non-null  -> the op MUST verify it on-card (plugin->verifyPIN) BEFORE the
//                  sign/decipher, holding the card across both so a PIN-ALWAYS
//                  key keeps its verified state for the immediately-following
//                  op. A verify rejection surfaces RawCryptoStatus::AuthFailed.
//                  This is the FIRST op of a lease (or after a prior auth fail).
//   * null      -> the PIN is already verified for this held channel (a
//                  subsequent op within the same lease); the op skips the verify
//                  and signs/deciphers directly.
// For the DigestInfo (opensc) path the PIN is NEVER cached — only a lease-scoped
// "verified" boolean is (see RawCryptoFlowDeps). EXCEPTION — the hash-on-card
// (pkcs15/IAS-ECC) sign path: PKCS15Card::sign owns the atomic verify+MSE+PSO
// and therefore needs the PIN, so the op deposits it per-session via
// plugin.setCredentials("pin") (a Secure::String in the plugin's session-keyed
// map) to serve subsequent null-PIN ops in the lease; it is wiped on holder
// teardown (CardSessionHolder::invalidate -> clearCredentials, on card removal /
// idle close). The PIN bytes the flow passes are owned by its Secure::String for
// the duration of the call and cleansed when it drops; the op must not retain
// them beyond the per-session deposit above.
using RawCryptoOp = std::function<RawCryptoResult(
    const CandidateList& candidates, const std::string& certId, std::span<const std::uint8_t> bytes,
    const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token)>;

// References-only dependency bundle, mirroring SignFlowDeps minus the AdES
// signer/params (the raw path has no SigningEngineProvider, no document
// vocabulary — just the certId + the terminal op). Same front-half seams so the
// shared FlowPrelude + the unified PIN/CAN credential provider are reused.
struct RawCryptoFlowDeps
{
    CardSessionHolder& holder;
    PrompterClientBase& prompter;
    PromptSerializer& serializer;
    CredentialCache& cache;
    OperationPhaseSink& phaseSink;
    std::string cardKey;
    std::string requester;
    std::string certId; // selects the exact key/cert (SHA-256(DER))
    RawCryptoOp signOp;
    RawCryptoOp decryptOp;
    LibreSCRS::CancelToken token;
    // Lease-scoped PIN-verified state (NEVER the PIN itself — only a boolean):
    //   isPinVerified()   -> true iff the on-card PIN was already verified for
    //                        THIS held channel/lease, so this op may skip the
    //                        prompt + verify (the verified state persists on the
    //                        held opensc channel; the SR card is not PIN-ALWAYS).
    //   markPinVerified() -> called by the flow after a verify+op both succeed,
    //                        so the lease's subsequent ops skip the re-prompt.
    //   clearPinVerified() -> called by the flow when a verify-SKIPPED op fails
    //                        because the held channel silently dropped (the lease
    //                        idle-timeout outlives the holder's idle-close, so a
    //                        fresh unverified channel can be reacquired under a
    //                        still-"verified" lease). Resets the boolean so the
    //                        recovery path re-prompts + re-verifies; if the host
    //                        wires nothing, the flow re-prompts every op anyway.
    // All default to the "always verify, never remember" posture (each op
    // prompts) when the host wires no lease state — fail-safe, never caches.
    std::function<bool()> isPinVerified;
    std::function<void()> markPinVerified;
    std::function<void()> clearPinVerified;
};

// Agent-thread flow the Pkcs11_1.SignRaw / Decrypt methods call. Mirrors
// SignFlow::run (open the held session via FlowPrelude::openSession, install ONE
// unified credential provider that routes PIN (purpose == Signing) uncached to
// the agent prompter and CAN/MRZ through the cache), then calls the injected
// terminal raw-crypto op. PIN/CAN are collected ONLY by the agent prompter —
// never off the wire (CKF_PROTECTED_AUTHENTICATION_PATH on the module side).
//
// Watchdog discipline matches SignFlow: AwaitingConsent (unbounded human PIN
// entry, never armed) then Authenticating + Signing AFTER the PIN is collected,
// so the per-op watchdog covers the on-card PSO but never times the human.
class RawCryptoFlow
{
public:
    enum class Outcome { Ok, Cancelled, KeyNotFound, AuthFailed, NotSupported, CardError };
    struct Result
    {
        Outcome outcome{Outcome::CardError}; // default fails closed
        std::vector<std::uint8_t> bytes;     // signature or plaintext on Ok
        std::string msgFallback;
    };

    explicit RawCryptoFlow(RawCryptoFlowDeps deps);

    [[nodiscard]] Result runSign(std::span<const std::uint8_t> input);
    [[nodiscard]] Result runDecrypt(std::span<const std::uint8_t> ciphertext);

private:
    enum class Op { Sign, Decrypt };
    [[nodiscard]] Result run(Op op, std::span<const std::uint8_t> bytes);

    RawCryptoFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
