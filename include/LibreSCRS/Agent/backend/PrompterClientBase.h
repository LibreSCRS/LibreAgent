// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h> // PromptOptions, PromptResult, PromptStatus
#include <string>

namespace LibreSCRS::Agent::Operations {

// Frozen backend interface: the secret returns as a cleansing Secure::String,
// never an fd/memfd, so the core never sees the transport. The single-secret
// surface (requestPin / requestCan / requestMrz) is frozen; growth happens by
// APPENDING virtuals with safe defaults (requestPinChange) so every existing
// implementer keeps compiling and the no-fd principle holds. Growth NEVER
// happens by adding an overload of an existing name: C++ name lookup hides an
// inherited overload set as soon as a derived class declares any member of that
// name, so every implementer would trip -Woverloaded-virtual -- which a host
// repo builds with -Werror. A member whose shape must change is REPLACED, and
// its implementers migrate in the same breath.
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
    // Asks the prompter to dismiss the ONE prompt @p promptId names. Wired by
    // OperationBase::requestCancel when the op is in AwaitingConsent. The
    // prompt gate is keyed by card, so more than one dialog can be on screen:
    // an unaddressed dismissal would close whichever is topmost -- very often
    // another card's. An id that names no live prompt is a no-op. Default-impl
    // is a no-op so test fakes that do not exercise this path stay simple; the
    // backend's production prompter client overrides.
    virtual void cancel(const std::string& promptId) noexcept
    {
        (void)promptId;
    }
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
