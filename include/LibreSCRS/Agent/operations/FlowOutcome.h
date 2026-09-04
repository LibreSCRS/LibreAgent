// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief The two verdict vocabularies the read and sign flows share.
///
/// Five flows returned the same three-way verdict and two seams returned the
/// same six-way one, each declaring its own copy. Nothing separated them: the
/// enumerators, their order and their meaning were identical, and every
/// mapping between a flow and its caller was written out once per flow.
///
/// Declaring them once is not about the lines saved. It is that a new
/// enumerator now reaches every `switch` at compile time: `-Wswitch` names the
/// ones that do not handle it, in a build that fails, instead of leaving each
/// flow's own copy to be found and extended by whoever remembers.
///
/// A flow whose verdicts are genuinely its own keeps its own enum — several
/// do, and they are not these.

namespace LibreSCRS::Agent::Operations {

/// @brief How a flow ended.
///
/// `Cancelled` is not an error: the caller or the holder stopped the work, and
/// nothing about the card is known to be wrong. `Error` carries an
/// `ErrorCode` alongside it wherever it is returned.
enum class FlowOutcome {
    Ok,        ///< The flow produced its result.
    Cancelled, ///< Stopped on request; no verdict about the card.
    Error,     ///< Failed; the accompanying code says how.
};

/// @brief How a seam call into the card layer ended.
///
/// Wider than @ref FlowOutcome because a seam is where the card's own
/// refusals surface, and a flow above it needs to tell them apart before it
/// decides whether to retry, re-authenticate, or give up.
enum class SeamStatus {
    Ok,                 ///< The call produced its result.
    AuthFailed,         ///< The card refused the credential presented.
    ParseError,         ///< The card answered, but the answer did not decode.
    UnsupportedCard,    ///< No plugin claims this card.
    CommunicationError, ///< The exchange itself failed.
    Cancelled,          ///< Stopped on request.
};

} // namespace LibreSCRS::Agent::Operations
