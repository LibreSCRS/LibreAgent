// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <compare>
#include <cstdint>
#include <string>
#include <utility>

namespace LibreSCRS::Agent {

// Opaque, backend-minted identity of a connected client. Replaces the raw bus
// name that today is the Authorizer subject, the Pkcs11 Caller.busName, the
// LeaseKey caller, the RateLimiter key and the disconnect-table sender. The
// core never parses or constructs the underlying string.
class CallerToken
{
public:
    CallerToken() = default;
    explicit CallerToken(std::string value) noexcept : m_value(std::move(value)) {}
    [[nodiscard]] const std::string& str() const noexcept
    {
        return m_value;
    }
    [[nodiscard]] bool empty() const noexcept
    {
        return m_value.empty();
    }
    friend bool operator==(const CallerToken&, const CallerToken&) noexcept = default;
    friend std::strong_ordering operator<=>(const CallerToken&, const CallerToken&) noexcept = default;

private:
    std::string m_value;
};

// Stable, opaque, per-process identity minted by PresenceModel for one reader or
// one card insertion. NEVER a card fingerprint. 0 reserved for "none". The
// backend owns the ObjectId<->path mapping; no core component reconstructs a path.
class ObjectId
{
public:
    ObjectId() = default;
    explicit ObjectId(std::uint64_t value) noexcept : m_value(value) {}
    [[nodiscard]] std::uint64_t value() const noexcept
    {
        return m_value;
    }
    [[nodiscard]] bool valid() const noexcept
    {
        return m_value != 0;
    }
    friend bool operator==(const ObjectId&, const ObjectId&) noexcept = default;
    friend std::strong_ordering operator<=>(const ObjectId&, const ObjectId&) noexcept = default;

private:
    std::uint64_t m_value{0};
};

// Opaque identity of one in-flight operation. Minted by OperationManager::publish;
// the backend owns OperationId<->op-path.
class OperationId
{
public:
    OperationId() = default;
    explicit OperationId(std::uint64_t value) noexcept : m_value(value) {}
    [[nodiscard]] std::uint64_t value() const noexcept
    {
        return m_value;
    }
    [[nodiscard]] bool valid() const noexcept
    {
        return m_value != 0;
    }
    friend bool operator==(const OperationId&, const OperationId&) noexcept = default;
    friend std::strong_ordering operator<=>(const OperationId&, const OperationId&) noexcept = default;

private:
    std::uint64_t m_value{0};
};

} // namespace LibreSCRS::Agent
