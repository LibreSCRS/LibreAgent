// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/operations/PromptContext.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/CancelToken.h>
#include <functional>
#include <string>
#include <utility>

namespace LibreSCRS::Agent::Operations {

// Per-operation PrompterClientBase decorator that routes every prompt request
// through the single agent-wide PromptSerializer, so concurrent operations
// queue behind one live prompt instead of stacking dialogs.
//
// Constructed cheaply inside the credential-provider lambda (per operation) so
// it carries that operation's CancelToken: a worker queued behind another's
// live prompt is woken — and returns a Cancelled PromptResult without ever
// raising a dialog — the moment its op is cancelled (client CancelCurrent,
// watchdog, reader removal). A cache HIT short-circuits in
// CredentialCache::requestCredential before this decorator is ever called, so
// the gate is contended only when a dialog actually has to be raised; the
// per-reader card I/O stays fully parallel.
//
// The references (serializer, inner) must outlive this decorator; in
// production both are agent-owned and live for the whole operation. The token
// is held by value (cheap LM handle) and shares cancellation state with the
// op's CancelSource.
class SerializingPrompter final : public PrompterClientBase
{
public:
    /// @param cardKey Gate key: prompts for DIFFERENT cards run concurrently,
    ///        prompts for the same card serialize. One card per reader slot, so
    ///        this is per-reader independence in practice.
    /// @param stillWanted Optional check, re-run for requestCan/requestMrz
    ///        ONLY (never requestPin/requestPinChange) AFTER this decorator
    ///        has acquired the per-card slot -- i.e. after any FIFO wait
    ///        behind a same-card sibling -- and BEFORE the inner prompter is
    ///        ever invoked. Exists because the wait for the slot can itself
    ///        outlast a sibling's whole prompt: a caller's own pre-dispatch
    ///        "is this still needed" check cannot see a sibling's window
    ///        closing WHILE this operation sat queued behind it, only this
    ///        can, because it runs on the far side of the wait. Returning
    ///        false skips the inner prompter call entirely and yields a
    ///        placeholder Cancelled-shaped PromptResult instead -- the
    ///        caller (CredentialCache::requestCredential) re-derives the
    ///        actual outcome itself rather than trusting this placeholder's
    ///        contents, so its shape carries no meaning of its own. Left
    ///        null (the default): always wanted, i.e. no change from before
    ///        this parameter existed. Restricted to Can/Mrz because the
    ///        notion of "generation" this guards belongs to the cacheable
    ///        pre-read secret, never to the operational PIN, which the CARD's
    ///        own counter governs.
    SerializingPrompter(PromptSerializer& serializer, PrompterClientBase& inner, LibreSCRS::CancelToken token,
                        std::string cardKey, std::function<bool()> stillWanted = nullptr)
        : m_serializer(serializer), m_inner(inner), m_token(std::move(token)), m_cardKey(std::move(cardKey)),
          m_stillWanted(std::move(stillWanted))
    {}

    [[nodiscard]] PromptResult requestPin(const PromptOptions& options) override
    {
        return gated([&] {
            const PromptOptions stamped = stamp(options, PromptKind::Pin);
            const auto live = m_serializer.registerLivePrompt(m_cardKey, stamped.promptId);
            return m_inner.requestPin(stamped);
        });
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions& options) override
    {
        return gatedWithStillWanted([&] {
            const PromptOptions stamped = stamp(options, PromptKind::Can);
            const auto live = m_serializer.registerLivePrompt(m_cardKey, stamped.promptId);
            return m_inner.requestCan(stamped);
        });
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions& options) override
    {
        return gatedWithStillWanted([&] {
            const PromptOptions stamped = stamp(options, PromptKind::Mrz);
            const auto live = m_serializer.registerLivePrompt(m_cardKey, stamped.promptId);
            return m_inner.requestMrz(stamped);
        });
    }
    // The two-secret change prompt is gated identically: it holds THIS CARD's
    // slot across the one modal, so a change dialog can never stack on top of
    // another prompt for the same card. Cancelled-while-queued surfaces as a
    // Cancelled-shaped result, which the change flow maps to UserCancelled — the
    // same outcome as the user dismissing the dialog.
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& options) override
    {
        return m_serializer.serialize(
            m_cardKey, m_token,
            [&] {
                const PromptOptions stamped = stamp(options, PromptKind::ChangePin);
                const auto live = m_serializer.registerLivePrompt(m_cardKey, stamped.promptId);
                return m_inner.requestPinChange(stamped);
            },
            [] {
                PinChangePromptResult r;
                r.status = PromptStatus::Cancelled;
                return r;
            });
    }

    // The in-dialog dismiss names its prompt; the inner client turns that into
    // the host's addressed cancel. A worker still QUEUED behind the gate has no
    // id yet and is handled by the cancellation-aware wait in serialize().
    void cancel(const std::string& promptId) noexcept override
    {
        m_inner.cancel(promptId);
    }

private:
    // The ONE writer of a prompt's id and deadline. Every prompt passes through
    // this decorator, so the six PromptOptions construction sites cannot forget
    // -- a site that forgot would ship a dialog that never expires, silently.
    //
    // Per RAISED prompt, not per operation: a re-prompt after a wrong CAN needs
    // its own address, or a cancel meant for it would close the first dialog.
    // Minted inside the gate, so a worker cancelled while queued burns no id.
    //
    // The reader is resolved from THIS decorator's card key, which is the same
    // key the gate serializes on -- so the dialog names the reader whose slot it
    // is actually holding.
    [[nodiscard]] PromptOptions stamp(const PromptOptions& options, PromptKind kind)
    {
        PromptOptions out = options;
        stampPrompt(out, PromptContext{m_serializer.readerIdentityFor(m_cardKey), m_serializer.idMinter()}, kind);
        return out;
    }

    template <typename Fn>
    PromptResult gated(Fn&& doPrompt)
    {
        return m_serializer.serialize(m_cardKey, m_token, std::forward<Fn>(doPrompt), [] {
            // Cancelled while queued: surface as a user-cancelled prompt so the
            // credential path maps it to CredentialResult::cancelled() — the
            // same outcome as the user dismissing the dialog.
            return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
        });
    }

    // Same as gated(), plus the post-acquire m_stillWanted re-check (see the
    // constructor's doc). Used ONLY by requestCan/requestMrz -- requestPin and
    // requestPinChange go through the plain gated() above and never consult
    // m_stillWanted, so installing it never gates an operational PIN prompt.
    template <typename Fn>
    PromptResult gatedWithStillWanted(Fn&& doPrompt)
    {
        return m_serializer.serialize(
            m_cardKey, m_token,
            [this, &doPrompt]() -> PromptResult {
                // Evaluated AFTER acquire() has returned -- i.e. after any
                // FIFO wait behind a same-card sibling -- and BEFORE doPrompt
                // (which is what actually raises the dialog) runs.
                if (m_stillWanted && !m_stillWanted()) {
                    // Placeholder only: the caller re-derives the real outcome
                    // itself (see the constructor's doc) rather than trusting
                    // this result's status/secret.
                    return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
                }
                return doPrompt();
            },
            [] {
                // Cancelled while QUEUED (never reached acquire()): the
                // existing CancelToken path, unrelated to m_stillWanted.
                return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
            });
    }

    PromptSerializer& m_serializer;
    PrompterClientBase& m_inner;
    LibreSCRS::CancelToken m_token;
    std::string m_cardKey;
    std::function<bool()> m_stillWanted;
};

} // namespace LibreSCRS::Agent::Operations
