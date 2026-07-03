// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace LibreSCRS::Agent {

// Presentation-layer field type, matches the {"text","date","binary"}
// strings on the Operation.Identity1.Result payload (photos are stripped
// from the Identity1 payload and ride on Photo1.Result; Photo remains in
// the enum because the seam adapter classifies fields before splitting).
enum class FieldType : std::uint8_t {
    Text = 0,
    Date = 1,
    Binary = 2,
    Photo = 3,
};

// One field within a group. Text/Date use textValue; Binary/Photo use
// binaryValue. Exactly one is populated per field per its type.
struct FieldSnapshot
{
    std::string fieldKey;
    std::string labelKey;
    std::string labelFallback;
    FieldType type{FieldType::Text};
    std::string textValue;
    std::vector<std::uint8_t> binaryValue;
};

// A labelled group of fields.
struct GroupSnapshot
{
    std::string groupKey;
    std::string labelKey;
    std::string labelFallback;
    std::vector<FieldSnapshot> fields;
};

// Top-level read snapshot. Agent-side type — no LM types appear in the
// header (the seam layer converts LM's CardData to this on the way in).
struct CardReadSnapshot
{
    std::string cardType;
    std::vector<GroupSnapshot> groups;

    [[nodiscard]] bool empty() const noexcept
    {
        return groups.empty();
    }
};

} // namespace LibreSCRS::Agent
