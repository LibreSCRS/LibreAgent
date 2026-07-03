// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h> // PromptOptions, PromptResult, PromptStatus

namespace LibreSCRS::Agent::Operations {

// Frozen backend interface: the secret returns as a cleansing Secure::String,
// never an fd/memfd, so the core never sees the transport.
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
};

} // namespace LibreSCRS::Agent::Operations
