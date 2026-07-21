// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h> // PromptOptions, PromptResult, PromptStatus

namespace LibreSCRS::Agent::Operations {

// Frozen backend interface: the secret returns as a cleansing Secure::String,
// never an fd/memfd, so the core never sees the transport. The single-secret
// surface (requestPin / requestCan / requestMrz) is frozen; growth happens by
// APPENDING virtuals with safe defaults (cancel, requestPinChange) so every
// existing implementer keeps compiling and the no-fd principle holds.
//
// Pure-virtual interface the seam layer consumes. The backend's production
// prompter client inherits this; tests derive Fakes from this directly.
class PrompterClientBase
{
public:
    virtual ~PrompterClientBase() = default;
    [[nodiscard]] virtual PromptResult requestPin(const PromptOptions& options) = 0;
    [[nodiscard]] virtual PromptResult requestCan(const PromptOptions& options) = 0;
    [[nodiscard]] virtual PromptResult requestMrz(const PromptOptions& options) = 0;
    // Asks the prompter service to dismiss its current modal. Wired by
    // OperationBase::requestCancel when the op is in AwaitingConsent.
    // Default-impl is a no-op so test fakes that do not exercise this
    // path stay simple; the backend's production prompter client overrides.
    virtual void cancel() noexcept {}
    // Two-secret PIN-change prompt: current + new PIN captured in one modal
    // (the confirm re-entry never leaves the prompter). Appended with a safe
    // default so a backend that has not wired multi-secret prompting fails
    // closed with status == Error; production backends override. Secrets
    // return as cleansing Secure::Strings — never an fd/memfd.
    [[nodiscard]] virtual PinChangePromptResult requestPinChange(const PromptOptions& options)
    {
        (void)options;
        PinChangePromptResult r;
        r.status = PromptStatus::Error;
        r.userMessage = "PIN change prompting is not supported by this backend";
        return r;
    }
};

} // namespace LibreSCRS::Agent::Operations
