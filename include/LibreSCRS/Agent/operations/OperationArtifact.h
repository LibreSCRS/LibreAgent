// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <string_view>

/// @file
/// @brief The words a consent prompt shows for what an operation acts on.
///
/// The prompter receives an operation's category as its trusted `artifact`
/// (never client-supplied), and a prompter maps each word to its own localised
/// text. The words are therefore a closed vocabulary shared by the agent and
/// every prompter; they are spelled here once rather than in each host and
/// each flow.

namespace LibreSCRS::Agent::Operations::Artifact {

inline constexpr std::string_view kIdentity = "identity";
inline constexpr std::string_view kPhoto = "photo";
inline constexpr std::string_view kCertificates = "certificates";
inline constexpr std::string_view kTokenInfo = "token";
inline constexpr std::string_view kCredentials = "credentials";
inline constexpr std::string_view kSignature = "signature";
inline constexpr std::string_view kSignatureBatch = "signature-batch";

} // namespace LibreSCRS::Agent::Operations::Artifact
