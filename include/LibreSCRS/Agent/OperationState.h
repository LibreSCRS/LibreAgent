// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <atomic>
#include <cstdint>

namespace LibreSCRS::Agent::Operations {

// Shared atomic state bridging the bus thread (read by adaptor) and the
// worker thread (written by OperationBase). Constructed BEFORE the
// adaptor so the same shared_ptr can be handed to both at adaptor ctor
// time — no post-construction rebind, no window where Cancel could be
// silently dropped between adaptor publication and worker wire-up.
struct OperationState
{
    std::atomic<std::uint32_t> phase{0};
    std::atomic<double> progress{0.0};
    std::atomic<bool> isIndeterminate{false};
    std::atomic<std::uint32_t> watchdogTimeoutSec{60};
    std::atomic<bool> cancelled{false};
    // Terminal-property mirrors of the Finished signal. Populated by
    // OperationBase::finish() BEFORE the wire signal fires. A client that
    // learns the op path only from a method return — and therefore may
    // subscribe to Finished after a fast op already emitted it — reads
    // these within the cleanup grace window to recover the missed result.
    // completed gates the others: when false they are meaningless.
    std::atomic<bool> completed{false};
    std::atomic<std::uint32_t> terminalStatus{0};
    std::atomic<std::uint32_t> terminalErrorCode{0};
};

} // namespace LibreSCRS::Agent::Operations
