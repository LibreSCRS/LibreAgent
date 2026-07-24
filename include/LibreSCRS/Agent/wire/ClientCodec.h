// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/Messages.h>

#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

// Client-role codec: the inverse of Messages.h's server-role parseRequest /
// makeReply / toCbor. Messages.h models the AGENT side (parse untrusted
// requests, build trusted replies+events); this header models the CLIENT
// side of the same CDDL contract (wire/librescrs-agent.cddl) — build
// requests, decode whatever the agent sends back.
//
// The agent is untrusted from the client's point of view too (it could be a
// newer or older build speaking a superset/subset of this contract), so
// decoding is APPEND-TOLERANT the way CDDL:120-128 requires:
//   - unknown MAP KEYS inside a recognised shape are ignored (same rule
//     parseRequest already applies on the server side);
//   - a whole reply arm / event `t` this client does not (yet) recognise is
//     NOT an error: it decodes into UnknownReply / UnknownEvent, never a
//     throw, never nullopt.
// Only genuinely malformed input (bad CBOR, a required field missing/wrong
// type inside an otherwise-recognised shape, the err-info code/name XOR
// violated, an out-of-range fd-index) yields std::nullopt.
//
// Replies carry no per-arm tag (every reply shares `t: "Reply"`; CDDL:105)
// — the arms are discriminated STRUCTURALLY, by which keys are present
// (CDDL:118-140). Events, like requests, DO carry their own `t` per arm
// (CDDL:156-186), so parseEvent dispatches on `t` exactly like
// parseRequest does.

namespace LibreSCRS::Agent::Wire {

// Messages.h already defines the request variant; reuse it verbatim rather
// than duplicating a second type (Tasks 12-13 see it under this name too).
using RequestVariant = Request;

// A reply arm / event this client build does not recognise — a forward-
// compatibility escape hatch, never a parse failure.
struct UnknownReply
{
    bool operator==(const UnknownReply&) const = default;
};
struct UnknownEvent
{
    bool operator==(const UnknownEvent&) const = default;
};

// reply-ok arms (CDDL:118-119: hello-ack, op-started, state, cert-list,
// cert-der, public-key, config, ack, raw-signature, sign-recovery) plus the
// error arm (err-info, modelled as ErrInfo) and UnknownReply.
// sign-recovery's payload (`result: sign-result`) is byte-identical to the
// Sign op-result-ready payload, so it reuses SignResult rather than adding
// a distinct wrapper type.
using ReplyVariant = std::variant<HelloAck, OpStarted, StateReply, CertListReply, CertDerReply, PublicKeyReply,
                                  ConfigReply, AckReply, RawSignatureReply, SignResult, ErrInfo, UnknownReply>;

// event arms (CDDL:156-186) plus UnknownEvent.
using EventVariant = std::variant<ReaderAdded, ReaderRemoved, CardAdded, CardRemoved, PropertyChanged, ConfigChanged,
                                  OpProgress, OpResultReady, OpFinished, AgentQuiesced, UnknownEvent>;

struct DecodedReply
{
    std::uint64_t requestId{0};
    ReplyVariant reply;
};
struct DecodedEvent
{
    EventVariant event;
};

// Decode one reply frame body (the bytes after the 8-byte frame header).
// `fds` is that frame's SCM_RIGHTS fd vector, indexed per CDDL fd-index; the
// only reply payload that carries one is sign-recovery's `artifact` (the
// signed document, GetSignResult). The decoded SignResult keeps the raw
// wire index (Messages.h's wire-shape type is unchanged) — a caller
// resolves the actual fd via `fds[artifact]` — but an index with no
// matching entry in `fds` is malformed and this returns std::nullopt.
[[nodiscard]] std::optional<DecodedReply> parseReply(std::span<const std::uint8_t> body, std::span<const int> fds);

// Decode one event frame body. Same fd-index bounds rule applies to
// OpResultReady's Sign artifact and each Photo item's fd.
[[nodiscard]] std::optional<DecodedEvent> parseEvent(std::span<const std::uint8_t> body, std::span<const int> fds);

// Encode one request into a canonical CBOR frame body, reusing the existing
// toCbor(RequestEnvelope) encoder (no canonical-encoding logic is
// duplicated here). CDDL:47 makes `req: uint` a mandatory field of every
// request frame, so `requestId` is a real parameter, not decoration; it
// defaults to 0 so a call site that does not (yet) track request ids still
// compiles, but real callers pass their assigned id explicitly.
[[nodiscard]] std::vector<std::uint8_t> encodeRequest(const RequestVariant& req, std::uint64_t requestId = 0);

} // namespace LibreSCRS::Agent::Wire
