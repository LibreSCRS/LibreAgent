// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/OperationChannel.h>

namespace LibreSCRS::Agent::Operations {

// Channel of an operation nobody on the bus asked for or waits on (a work
// closure run on the reader's worker, a background read): every emission is
// dropped, so no signal or result reaches a client.
class SilentOperationChannel final : public OperationChannel
{
public:
    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus, ErrorCode, std::string_view, std::string_view) noexcept override {}
    bool emitResult(const ResultPayload&) noexcept override
    {
        return true;
    }
};

} // namespace LibreSCRS::Agent::Operations
