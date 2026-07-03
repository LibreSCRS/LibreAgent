// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/OperationChannel.h>

#include <string>
#include <vector>

namespace LibreSCRS::Agent::Operations {

// Recording double over the frozen OperationChannel emit-only surface. Captures
// every property-changed pulse, every Finished(status, code, msgKey, fallback)
// and every Result payload so a test can assert the exact emission sequence.
struct FakeOperationChannel final : OperationChannel
{
    int propsChanged{0};

    struct Finish
    {
        OperationStatus status;
        ErrorCode code;
        std::string msgKey;
        std::string msgFallback;
    };
    std::vector<Finish> finished;
    std::vector<ResultPayload> results;

    void emitPropertiesChanged() noexcept override
    {
        ++propsChanged;
    }

    void emitFinished(OperationStatus status, ErrorCode code, std::string_view msgKey,
                      std::string_view msgFallback) noexcept override
    {
        finished.push_back({status, code, std::string(msgKey), std::string(msgFallback)});
    }

    // Optional injectable failure: when set to false, models a backend channel
    // whose required large-result seal failed (Photo1/Sign1 memfd), so a test can
    // exercise the op's fail-closed path. Defaults to true (delivery succeeds).
    bool deliverResult{true};

    bool emitResult(const ResultPayload& result) noexcept override
    {
        results.push_back(result);
        return deliverResult;
    }
};

} // namespace LibreSCRS::Agent::Operations
