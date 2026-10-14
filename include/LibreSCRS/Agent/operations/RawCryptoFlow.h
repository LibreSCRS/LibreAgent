// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/crypto/Mechanism.h>
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
// with no live card. Production binds Operations::signRaw / decryptRaw /
// deriveRaw (and preflight) with bindLmRawCrypto; tests inject a fake that
// models the PIN check + the on-card op. Same signature for sign, decrypt and derive — the bytes are
// input/ciphertext/peer point. The op receives the key the preflight resolved -- it reads
// nothing off the card itself -- and the mechanism the caller named.
//
// @p pin carries the PIN-as-consent secret the flow just collected from the
// agent prompter:
//   * non-null  -> the op hands it to the resolving plugin
//                  (setCredentials "pin"), which presents it to the card and
//                  uses the key in ONE card transaction — never a separate
//                  verifyPIN, across which a key the card wants the PIN for on
//                  every operation loses its verified state. A refused PIN
//                  surfaces RawCryptoStatus::AuthFailed. This is the FIRST op
//                  of a lease (or after a prior auth fail / recovery), and
//                  every op with a key the card marks for consent per
//                  operation. Never empty: an empty answer arrives as a
//                  dismissed prompt (SerializingPrompter), and the op refuses
//                  one as AuthFailed.
//   * null      -> the PIN is already verified for this held channel (a
//                  subsequent op within the same lease); the op signs /
//                  deciphers directly — or, for a key the card marks for
//                  consent per operation, answers RawCryptoStatus::
//                  ConsentRequired without using the key (only the card's
//                  certificates are read, to find it).
// The flow itself never caches the PIN, only a lease-scoped boolean (see
// RawCryptoFlowDeps); the plugin holds the deposit: for an ordinary key it
// stays after a successful op to serve the lease's null-PIN ops (the
// hash-on-card pkcs15/IAS-ECC family signs only with it) and is wiped on
// holder teardown (CardSessionHolder::invalidate -> clearCredentials, on card
// removal / idle close); after a failed op, and after every op with a key the
// card marks, the op erases it itself. The PIN bytes the flow passes are owned
// by its Secure::String for the duration of the call and cleansed when it drops.
using RawCryptoOp = std::function<RawCryptoResult(
    const SigningSelection& key, Mechanism mechanism, std::span<const std::uint8_t> bytes,
    const LibreSCRS::Secure::String* pin, LibreSCRS::SmartCard::CardSession& session, LibreSCRS::CancelToken token)>;

// The check before any prompt (production: Operations::preflight): resolves
// certId among the candidates off the held session and refuses a request the
// key cannot take. Its key is the one handed to the RawCryptoOp.
using RawCryptoPreflightOp =
    std::function<RawCryptoPreflight(const CandidateList& candidates, const std::string& certId, Mechanism mechanism,
                                     std::span<const std::uint8_t> input, LibreSCRS::SmartCard::CardSession& session)>;

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
    // Checks the request against the key before any prompt (see
    // LmRawCrypto::preflight); its key is the one the op then uses.
    // No preflight or no op wired for the request is a refusal (CardError)
    // before any prompt.
    RawCryptoPreflightOp preflight;
    RawCryptoOp signOp;
    RawCryptoOp decryptOp;
    RawCryptoOp deriveOp; // ECDH; the flow names it `pkcs11-derive` in the prompt
    LibreSCRS::CancelToken token;
    // Lease-scoped PIN state (NEVER the PIN itself — only a boolean):
    //   isPinVerified()   -> true iff an op with the PIN already succeeded for
    //                        THIS held channel/lease, so this op may run without
    //                        a prompt (on the card's verified state on the held
    //                        session, or the PIN the plugin keeps deposited).
    //   markPinVerified() -> called by the flow after an op that presented the
    //                        PIN succeeded, so the lease's subsequent ops skip
    //                        the prompt.
    //   clearPinVerified() -> called by the flow when an op run without the PIN
    //                        fails because the held channel silently dropped (the
    //                        lease idle-timeout outlives the holder's idle-close,
    //                        so a fresh channel can be reacquired under a
    //                        still-"verified" lease). Resets the boolean so the
    //                        recovery path prompts and retries with the PIN.
    // A success with a key the card marks for consent per operation
    // (RawCryptoResult::alwaysAuthenticate) never marks the lease verified, and
    // the consent it asks for under a verified lease never clears it: that
    // state is right for the card's other keys.
    // With no lease state wired every op prompts — fail-safe.
    std::function<bool()> isPinVerified;
    std::function<void()> markPinVerified;
    std::function<void()> clearPinVerified;
    // Asked immediately before EVERY PIN prompt this flow raises -- the first
    // of a lease (at the very top of the run, before the card session is
    // opened), a key the card marks for consent per operation, and the
    // recovery re-prompt alike. false = the caller is over its prompt budget:
    // nothing is raised and the op ends RateLimited. Empty = no prompt is
    // allowed (fail closed), so a host that does not wire its budget gets no
    // prompts rather than unlimited ones. Only the cold refusal is free of
    // card I/O: a marked key under a warm lease is known only after the card's
    // certificates are read.
    std::function<bool()> allowPrompt;
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
    enum class Outcome { Ok, Cancelled, KeyNotFound, AuthFailed, NotSupported, CardError, RateLimited, InvalidInput };
    struct Result
    {
        Outcome outcome{Outcome::CardError}; // default fails closed
        std::vector<std::uint8_t> bytes;     // signature, plaintext or secret on Ok
        std::string msgFallback;
    };

    explicit RawCryptoFlow(RawCryptoFlowDeps deps);

    [[nodiscard]] Result runSign(Mechanism mechanism, std::span<const std::uint8_t> input);
    [[nodiscard]] Result runDecrypt(Mechanism mechanism, std::span<const std::uint8_t> ciphertext);
    [[nodiscard]] Result runDerive(std::span<const std::uint8_t> peerPoint);
    // The entry for @p mechanism, as the agent's PKCS#11 calls reach it:
    // EcdhDerive derives, RsaPkcs1Decrypt decrypts, anything else is a
    // signature (whose preflight refuses what is not one).
    [[nodiscard]] Result run(Mechanism mechanism, std::span<const std::uint8_t> bytes);

private:
    enum class Op { Sign, Decrypt, Derive };
    [[nodiscard]] Result runOp(Op op, Mechanism mechanism, std::span<const std::uint8_t> bytes);

    RawCryptoFlowDeps m_deps;
};

} // namespace LibreSCRS::Agent::Operations
