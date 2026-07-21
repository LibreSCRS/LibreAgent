// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/CancelToken.h>

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
    SerializingPrompter(PromptSerializer& serializer, PrompterClientBase& inner, LibreSCRS::CancelToken token)
        : m_serializer(serializer), m_inner(inner), m_token(std::move(token))
    {}

    [[nodiscard]] PromptResult requestPin(const PromptOptions& options) override
    {
        return gated([&] { return m_inner.requestPin(options); });
    }
    [[nodiscard]] PromptResult requestCan(const PromptOptions& options) override
    {
        return gated([&] { return m_inner.requestCan(options); });
    }
    [[nodiscard]] PromptResult requestMrz(const PromptOptions& options) override
    {
        return gated([&] { return m_inner.requestMrz(options); });
    }
    // The two-secret change prompt is gated identically: it holds the single
    // agent-wide slot across the one modal, so a change dialog can never stack on
    // top of another reader's live prompt. Cancelled-while-queued surfaces as a
    // Cancelled-shaped result, which the change flow maps to UserCancelled — the
    // same outcome as the user dismissing the dialog.
    [[nodiscard]] PinChangePromptResult requestPinChange(const PromptOptions& options) override
    {
        return m_serializer.serialize(
            m_token, [&] { return m_inner.requestPinChange(options); },
            [] {
                PinChangePromptResult r;
                r.status = PromptStatus::Cancelled;
                return r;
            });
    }

    // The in-dialog dismiss is the inner client's concern (it issues
    // Prompter1.CancelCurrent for the live modal); forward unchanged. A worker
    // still QUEUED behind the gate is handled by the cancellation-aware wait
    // in serialize(), not here.
    void cancel() noexcept override
    {
        m_inner.cancel();
    }

private:
    template <typename Fn>
    PromptResult gated(Fn&& doPrompt)
    {
        return m_serializer.serialize(m_token, std::forward<Fn>(doPrompt), [] {
            // Cancelled while queued: surface as a user-cancelled prompt so the
            // credential path maps it to CredentialResult::cancelled() — the
            // same outcome as the user dismissing the dialog.
            return PromptResult{PromptStatus::Cancelled, std::nullopt, ""};
        });
    }

    PromptSerializer& m_serializer;
    PrompterClientBase& m_inner;
    LibreSCRS::CancelToken m_token;
};

} // namespace LibreSCRS::Agent::Operations
