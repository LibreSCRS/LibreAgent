// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <utility>

namespace LibreSCRS::Agent {

// Deferred method reply for the asynchronous Pkcs11_1 surface.
//
// The synchronous PKCS#11 methods (CertDer / PublicKey / Login / SignRaw /
// Decrypt) used to BLOCK the single bus-dispatch thread on a per-reader worker
// hop. They are now async backend methods: the slot validates on the dispatch
// thread, then hands the card I/O to the per-reader worker and returns the
// dispatch thread IMMEDIATELY; the worker fulfils THIS reply on completion. So
// the bus event loop stays responsive (other clients, SIGTERM) for the whole
// in-flight op duration.
//
// Reply<Outcome, Results...> is the agent-side, platform-agnostic handle the
// Pkcs11Broker logic fulfils. It carries a NEUTRAL @p Outcome enum — no wire
// string, no backend type — so the broker is unit-testable and backend-agnostic.
// Production binds ok to the platform success reply and err to the
// Outcome->wire mapping (see the backend's deferred-reply path, which resolves the
// Outcome to an org.librescrs.Agent.Error.* name); unit tests bind them to
// capturing lambdas so the logic stays bus-free and synchronously testable.
//
// EXACTLY-ONCE / FAIL-CLOSED: an async reply MUST be fulfilled or the client
// hangs. The held state carries a `done` latch and a fallback Outcome; if the
// Reply is destroyed without ever being fulfilled (e.g. the worker op was torn
// down on reader removal / abandoned while wedged, so the closure that owned it
// never ran to completion), the last owner's destructor delivers the fallback
// Outcome. Both ok/fail and the destructor route through fulfil() under the
// latch, so the reply is sent exactly once.
template <typename Outcome, typename... Results>
class Reply
{
public:
    using OkFn = std::function<void(const Results&...)>;
    using ErrFn = std::function<void(Outcome)>;

    // @p fallback is the Outcome delivered if the Reply is dropped unfulfilled
    // (the worker never completed the op). The backend maps it to a device /
    // communication error — the correct fail-closed outcome for a card op that
    // never produced a result.
    Reply(OkFn ok, ErrFn err, Outcome fallback)
        : m_state(std::make_shared<State>(std::move(ok), std::move(err), fallback))
    {}

    Reply(const Reply&) = default;
    Reply& operator=(const Reply&) = default;
    Reply(Reply&&) = default;
    Reply& operator=(Reply&&) = default;
    ~Reply() = default;

    void ok(const Results&... results) const
    {
        if (!m_state) {
            return;
        }
        m_state->fulfil([&] { m_state->ok(results...); });
    }

    void fail(Outcome outcome) const
    {
        if (!m_state) {
            return;
        }
        m_state->fulfil([&] { m_state->err(outcome); });
    }

private:
    struct State
    {
        State(OkFn okIn, ErrFn errIn, Outcome fallbackIn)
            : ok(std::move(okIn)), err(std::move(errIn)), fallback(fallbackIn)
        {}

        // The LAST owner's destructor delivers the fail-closed reply if nobody
        // ever fulfilled it — closing the "client hangs forever" hole on every op
        // teardown path (reader removed / worker abandoned).
        ~State()
        {
            fulfil([this] { err(fallback); });
        }

        // Send the reply exactly once. The done flag is atomic with a CAS so the
        // success path (worker thread) and a fail/teardown path can never both
        // send: whoever wins the CAS sends, the loser is a no-op. send() must not
        // throw out (a late reply on a torn-down call is benign); swallow it.
        template <class F>
        void fulfil(F&& send) noexcept
        {
            bool expected = false;
            if (!done.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                return;
            }
            try {
                send();
            } catch (...) {
            }
        }

        OkFn ok;
        ErrFn err;
        Outcome fallback;
        std::atomic<bool> done{false};
    };

    std::shared_ptr<State> m_state;
};

} // namespace LibreSCRS::Agent
