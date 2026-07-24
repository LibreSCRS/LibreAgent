// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
//
// INTERNAL — never installed. The canonical `Field::extra` key spellings for
// identity-field wire metadata, shared by the producer (the transport's
// payload scrub) and the consumer (IdentityRows.cpp's flatten rule) so the
// two cannot drift. The spellings are PUBLIC API surface (documented on
// IdentityRows.h) — change them nowhere.
#include <QLatin1StringView>

namespace LibreSCRS::AgentClient {

inline constexpr QLatin1StringView kFieldExtraLabelKey{"labelKey"};
inline constexpr QLatin1StringView kFieldExtraLabelFallback{"labelFallback"};
inline constexpr QLatin1StringView kFieldExtraType{"type"};

/// The identity field-type token for binary payloads (skipped by the row
/// flatten; the bytes ride `Field::detail`).
inline constexpr QLatin1StringView kFieldTypeBinary{"binary"};

} // namespace LibreSCRS::AgentClient
