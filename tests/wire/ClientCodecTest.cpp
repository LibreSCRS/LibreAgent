// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Client-role codec tests: the inverse of MessagesRoundTripTest.cpp.
//   (a) every reply/event shape: server-role encoder -> parseReply/parseEvent
//       -> decode-then-reencode is byte-identical to the original (the same
//       "byte-stable" idiom MessagesRoundTripTest uses for requests; several
//       reply/event structs have no operator== of their own, so this is the
//       equality check available without touching Messages.h).
//   (b) every request type: encodeRequest -> the existing server-role
//       parseRequest -> equal request (Request's alternatives already have
//       operator==).
//   (c) an unknown extra map key inside a known shape is ignored.
//   (d) an unknown reply arm / event `t` decodes to UnknownReply/UnknownEvent,
//       never nullopt, never a throw.
//   (e) the one genuinely structurally-ambiguous reply pair (public-key's
//       RSA/EC, sharing "kty") + the err-info code/name XOR rule.
//   (f) fd-index bounds mapping, including out-of-range -> nullopt.
//   (g) ErrorCode append tolerance: an unrecognised numeric value (one a
//       newer agent appended) decodes through verbatim; a value too wide to
//       ever fit ErrorCode's uint32 wire width still nullopts.
//   (h) parseReply's entry point rejects well-formed-but-non-canonical CBOR,
//       not just malformed CBOR.
//   (i) the SAME append tolerance as (g), generalized to every other closed
//       enum on this wire (OperationPhase, OperationStatus, PreReadAuth,
//       QuiesceReason numeric raw carry; CredentialOutcome/sync-error TEXT
//       token decode-time degrade), each still bounded by its own
//       underlying-type width. Degradation MEANING (hold-last-phase,
//       status-as-Error, ...) is asserted at the AgentOperation layer
//       (client/qt/tests/SeamMappingTest.cpp), not here.
#include <LibreSCRS/Agent/wire/ClientCodec.h>

#include <gtest/gtest.h>

#include <limits>

using namespace LibreSCRS::Agent::Wire;

namespace {

std::span<const int> noFds()
{
    return {};
}

// ---- (a) reply round-trip: makeReply/makeErrorReply/makeSignRecoveryReply
// -> parseReply -> re-encode the decoded value with the SAME maker -> bytes
// match the original. Proves parseReply captured every field faithfully.
template <class T, class Maker>
void expectReplyRoundTrip(std::uint64_t reqId, const T& arm, Maker makeIt, std::span<const int> fds = {})
{
    const auto originalBytes = makeIt(reqId, arm).encode();
    const auto decoded = parseReply(originalBytes, fds);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->requestId, reqId);
    ASSERT_TRUE(std::holds_alternative<T>(decoded->reply));
    const auto& got = std::get<T>(decoded->reply);
    const auto reencodedBytes = makeIt(reqId, got).encode();
    EXPECT_EQ(reencodedBytes, originalBytes);
}

// ---- (a) event round-trip: toCbor(event) -> parseEvent -> re-encode ->
// bytes match.
template <class T>
void expectEventRoundTrip(const T& ev, std::span<const int> fds = {})
{
    const auto originalBytes = toCbor(ev).encode();
    const auto decoded = parseEvent(originalBytes, fds);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<T>(decoded->event));
    const auto& got = std::get<T>(decoded->event);
    const auto reencodedBytes = toCbor(got).encode();
    EXPECT_EQ(reencodedBytes, originalBytes);
}

// ---- (b) request round-trip: encodeRequest -> the existing server-role
// parseRequest -> equal request (Request's alternatives have operator==).
template <class T>
void expectRequestRoundTrip(std::uint64_t reqId, const T& body)
{
    const auto bytes = encodeRequest(RequestVariant{body}, reqId);
    const auto parsed = parseRequest(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->req, reqId);
    ASSERT_TRUE(std::holds_alternative<T>(parsed->body));
    EXPECT_EQ(std::get<T>(parsed->body), body);
}

CertInfo makeSampleCertInfo()
{
    CertInfo ci;
    ci.certId = "deadbeef";
    ci.signingCapable = true;
    ci.fields["Subject"]["CN"] = CertField{"cn.subject.key", "Common Name", "John Doe"};
    ci.keyUsageBits = 1;
    ci.ekus = {"clientAuth"};
    ci.chainSubjectCns = {"Root CA"};
    ci.trustStatus = 0;
    return ci;
}

CredentialRecord makeFullCredentialRecord()
{
    CredentialRecord rec;
    rec.id = "sign:0x92";
    rec.label = "Signing PIN";
    rec.kind = "sign";
    rec.state = "operational";
    rec.retriesLeft = 3;
    rec.retriesMax = 3;
    rec.usesLeft = 5;
    rec.usesMax = 20;
    rec.unblocksLeft = 10;
    rec.minLength = 4;
    rec.maxLength = 8;
    rec.canChange = true;
    rec.unblockable = true;
    rec.unblockStyle = "unblockAndChange";
    rec.activatable = true;
    rec.keyActivationPending = true;
    rec.keyActivatable = true;
    rec.recovery = "holderViaPuk";
    rec.probeSafe = true;
    rec.blockedGuidanceKey = "guidance.blocked.key";
    rec.blockedGuidanceFallback = "Blocked; contact issuer";
    rec.keyActivationGuidanceKey = "guidance.activate.key";
    rec.keyActivationGuidanceFallback = "Activate your signing key";
    return rec;
}

CredentialRecord makeBareCredentialRecord()
{
    CredentialRecord rec;
    rec.id = "unknown:0x00";
    rec.label = "";
    rec.kind = "unknown";
    rec.state = "unknown";
    rec.unblockStyle = "unknown";
    rec.recovery = "unknown";
    return rec;
}

// ============================================================================
// (b) requests: encodeRequest -> parseRequest, every request type.
// ============================================================================

TEST(ClientCodec, EncodeRequestEveryTypeRoundTripsThroughServerParse)
{
    expectRequestRoundTrip(1, Hello{1, std::nullopt});
    expectRequestRoundTrip(2, Hello{1, std::string("LibreMac/0.1")});
    expectRequestRoundTrip(3, GetState{});
    expectRequestRoundTrip(4, ReadIdentity{"reader/0:card/0"});
    expectRequestRoundTrip(5, GetPhoto{"reader/0:card/0"});
    expectRequestRoundTrip(6, ReadCertificates{"reader/0:card/0"});
    expectRequestRoundTrip(7, Sign{"card/0", "abc123", 0,
                                   SignOpts{"pades", "b-lt", "enveloped", true, std::string("Doc"), std::string("why"),
                                            std::string("Belgrade")}});
    expectRequestRoundTrip(
        8, Sign{"card/0", "abc123", 2,
                SignOpts{"auto", "b-b", "auto", std::nullopt, std::nullopt, std::nullopt, std::nullopt}});
    expectRequestRoundTrip(9, GetCertDer{"reader/0", "certid"});
    expectRequestRoundTrip(10, GetConfig{});
    expectRequestRoundTrip(11, SetConfig{"DefaultLevel", CborValue(std::string("b-t"))});
    expectRequestRoundTrip(12, ResetConfig{"TsaUrls"});
    expectRequestRoundTrip(13, CancelOp{42});
    expectRequestRoundTrip(14, GetSignResult{42});
    expectRequestRoundTrip(15, PkLogin{"reader/0"});
    expectRequestRoundTrip(16, PkLogout{"reader/0"});
    expectRequestRoundTrip(17, PkPublicKey{"reader/0", "certid"});
    expectRequestRoundTrip(18, PkSignRaw{"reader/0", "certid", {0xDE, 0xAD}});
    expectRequestRoundTrip(19, PkDecrypt{"reader/0", "certid", {0xBE, 0xEF}});
    expectRequestRoundTrip(
        25, SignBatch{"card/0",
                      "abc123",
                      {BatchDocument{"invoice-1.pdf", 0}, BatchDocument{"invoice-2.pdf", 1}},
                      SignOpts{"pades", "b-b", "enveloped", std::nullopt, std::nullopt, std::nullopt, std::nullopt}});
    expectRequestRoundTrip(20, ListCredentials{"reader/0:card/0"});
    expectRequestRoundTrip(21, ManagePin{"reader/0:card/0", "sign:0x92", "change", std::nullopt});
    expectRequestRoundTrip(22, ManagePin{"reader/0:card/0", "user:0x01", "activate_pin", std::optional<bool>{true}});
    expectRequestRoundTrip(23, ManagePin{"reader/0:card/0", "user:0x01", "unblock", std::optional<bool>{false}});
    expectRequestRoundTrip(24, ActivateSigningKey{"reader/0:card/0"});
}

TEST(ClientCodec, EncodeRequestDefaultsRequestIdToZero)
{
    // The library's one-arg call form: encodeRequest(variant). CDDL:47
    // mandates `req: uint` on every request frame, so this still has to
    // produce a valid, parseable frame -- with req defaulted to 0.
    const auto bytes = encodeRequest(RequestVariant{GetState{}});
    const auto parsed = parseRequest(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->req, 0u);
    EXPECT_TRUE(std::holds_alternative<GetState>(parsed->body));
}

// ============================================================================
// (a) replies: server-role encoder -> parseReply -> byte-stable re-encode.
// ============================================================================

TEST(ClientCodec, HelloAckRoundTrips)
{
    expectReplyRoundTrip(1, HelloAck{"0.1.0", {"pki", "sign"}},
                         [](std::uint64_t r, const HelloAck& a) { return makeReply(r, a); });
}

TEST(ClientCodec, OpStartedRoundTrips)
{
    expectReplyRoundTrip(2, OpStarted{42}, [](std::uint64_t r, const OpStarted& a) { return makeReply(r, a); });
}

TEST(ClientCodec, StateReplyRoundTrips)
{
    StateReply state;
    state.readers.push_back(ReaderState{"r1", "Reader One", true, std::string("c1")});
    state.readers.push_back(ReaderState{"r2", "Reader Two", false, std::nullopt}); // exercises optText absent
    state.cards.push_back(CardState{"c1", "r1", 0x3, PreReadAuth::Can});
    expectReplyRoundTrip(3, state, [](std::uint64_t r, const StateReply& a) { return makeReply(r, a); });
}

TEST(ClientCodec, CertListReplyRoundTrips)
{
    CertListReply certList;
    certList.certs.push_back(makeSampleCertInfo());
    expectReplyRoundTrip(4, certList, [](std::uint64_t r, const CertListReply& a) { return makeReply(r, a); });
}

TEST(ClientCodec, CertDerReplyRoundTrips)
{
    expectReplyRoundTrip(5, CertDerReply{{0xDE, 0xAD, 0xBE, 0xEF}},
                         [](std::uint64_t r, const CertDerReply& a) { return makeReply(r, a); });
}

// (e) structural discrimination: public-key's RSA and EC arms share the
// "kty" key and are discriminated by its VALUE, not by key presence -- the
// one genuinely ambiguous-looking reply pair on this wire (CDDL:135-136).
TEST(ClientCodec, PublicKeyReplyDiscriminatesRsaFromEcByKtyValue)
{
    const PublicKeyReply rsa = RsaPublicKey{{0x01, 0x02}, {0x03}};
    expectReplyRoundTrip(6, rsa, [](std::uint64_t r, const PublicKeyReply& a) { return makeReply(r, a); });

    const PublicKeyReply ec = EcPublicKey{"P-256", {0x04}, {0x05}};
    expectReplyRoundTrip(7, ec, [](std::uint64_t r, const PublicKeyReply& a) { return makeReply(r, a); });
}

TEST(ClientCodec, ConfigReplyRoundTrips)
{
    ConfigReply config;
    config.entries.emplace("DefaultLevel", CborValue(std::string("b-t")));
    expectReplyRoundTrip(8, config, [](std::uint64_t r, const ConfigReply& a) { return makeReply(r, a); });
}

TEST(ClientCodec, AckReplyRoundTrips)
{
    expectReplyRoundTrip(9, AckReply{}, [](std::uint64_t r, const AckReply& a) { return makeReply(r, a); });
}

TEST(ClientCodec, RawSignatureReplyRoundTrips)
{
    expectReplyRoundTrip(10, RawSignatureReply{{0xAA, 0xBB}},
                         [](std::uint64_t r, const RawSignatureReply& a) { return makeReply(r, a); });
}

// (f) fd-index: sign-recovery's artifact is a valid index into `fds`.
TEST(ClientCodec, SignRecoveryReplyRoundTripsWithValidFdIndex)
{
    const int fdVec[] = {7};
    expectReplyRoundTrip(
        11, SignResult{0, SignMeta{"pades", "b-lta", true, true}},
        [](std::uint64_t r, const SignResult& a) { return makeSignRecoveryReply(r, a); }, fdVec);
}

// (f) fd-index: an out-of-range artifact index is malformed -> nullopt.
TEST(ClientCodec, SignRecoveryReplyRejectsOutOfRangeFdIndex)
{
    const auto bytes = makeSignRecoveryReply(12, SignResult{5, SignMeta{"pades", "b-lta", true, true}}).encode();
    const int fdVec[] = {7}; // only index 0 is valid; artifact=5 is out of range
    EXPECT_FALSE(parseReply(bytes, fdVec).has_value());
    EXPECT_FALSE(parseReply(bytes, noFds()).has_value());
}

TEST(ClientCodec, NumericErrorReplyRoundTrips)
{
    expectReplyRoundTrip(13, ErrInfo{ErrorCode::CardRemoved, std::string("cardRemoved"), std::string("Card removed")},
                         [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });
}

TEST(ClientCodec, NamedErrorReplyRoundTrips)
{
    expectReplyRoundTrip(14, ErrInfo{SyncError::UnknownCard, std::nullopt, std::nullopt},
                         [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });
    expectReplyRoundTrip(15, ErrInfo{SyncError::UnknownCredential, std::nullopt, std::nullopt},
                         [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });
}

// GetSignResult's dedicated dead-end name: a pinned member of sync-error now,
// not a borrowed stand-in -- must round-trip like every other named member
// above, AND (the genuinely distinguishing assertion) decoding the literal
// wire string "NoResult" must land on the real SyncError::NoResult value, NOT
// the degrade-to-CommunicationError bucket an unrecognised token falls into
// (ErrInfoDegradesUnrecognisedSyncErrorNameToCommunicationError below) --
// before this name was pinned, "NoResult" on the wire was indistinguishable
// from any other unknown token and silently landed there too.
TEST(ClientCodec, NamedErrorReplyNoResultRoundTripsAndDoesNotDegrade)
{
    expectReplyRoundTrip(16, ErrInfo{SyncError::NoResult, std::nullopt, std::nullopt},
                         [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });

    CborValue::Map err;
    err.emplace("name", CborValue(std::string("NoResult")));
    CborValue::Map reply;
    reply.emplace("t", CborValue(std::string("Reply")));
    reply.emplace("req", CborValue::uint(31));
    reply.emplace("err", CborValue(std::move(err)));
    const auto bytes = CborValue(std::move(reply)).encode();
    const auto decoded = parseReply(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<ErrInfo>(decoded->reply));
    const auto& err_ = std::get<ErrInfo>(decoded->reply);
    ASSERT_TRUE(std::holds_alternative<SyncError>(err_.code));
    EXPECT_EQ(std::get<SyncError>(err_.code), SyncError::NoResult);
}

// (i) sync-error is a TEXT-token enum: an unrecognised name has no numeric
// width to bound, so it DEGRADES AT DECODE to CommunicationError -- the
// generic-protocol-error bucket an unrecognised D-Bus error name already
// falls back to on the other transport -- instead of failing the err-info
// map (and the whole reply frame) closed.
TEST(ClientCodec, ErrInfoDegradesUnrecognisedSyncErrorNameToCommunicationError)
{
    CborValue::Map err;
    err.emplace("name", CborValue(std::string("FutureError")));
    CborValue::Map reply;
    reply.emplace("t", CborValue(std::string("Reply")));
    reply.emplace("req", CborValue::uint(30));
    reply.emplace("err", CborValue(std::move(err)));
    const auto bytes = CborValue(std::move(reply)).encode();
    const auto decoded = parseReply(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<ErrInfo>(decoded->reply));
    const auto& err_ = std::get<ErrInfo>(decoded->reply);
    ASSERT_TRUE(std::holds_alternative<SyncError>(err_.code));
    EXPECT_EQ(std::get<SyncError>(err_.code), SyncError::CommunicationError);
}

// (g) same append-tolerance, on err-info's numeric `code` arm: a code past
// InvalidDocument=19 -- simulating a newer agent -- decodes, it does not
// nullopt just because this build doesn't have a name for it.
TEST(ClientCodec, NumericErrorReplyToleratesAppendedErrorCodeValue)
{
    expectReplyRoundTrip(28, ErrInfo{static_cast<ErrorCode>(20), std::nullopt, std::nullopt},
                         [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });
}

// (g) the tolerance is bounded by the wire field's actual width: a `code`
// that doesn't fit ErrorCode's uint32_t underlying type at all -- as opposed
// to merely being past this build's last known name -- is still malformed.
// Pins decodeErrorCode's pre-existing width check.
TEST(ClientCodec, NumericErrorReplyRejectsCodeAboveUint32Range)
{
    CborValue::Map err;
    err.emplace("code", CborValue::uint(static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1));
    CborValue::Map reply;
    reply.emplace("t", CborValue(std::string("Reply")));
    reply.emplace("req", CborValue::uint(29));
    reply.emplace("err", CborValue(std::move(err)));
    const auto bytes = CborValue(std::move(reply)).encode();
    EXPECT_FALSE(parseReply(bytes, noFds()).has_value());
}

// (g) the exact upper boundary of the raw-pass-through width check: UINT32_MAX
// itself -- the LAST value that still fits ErrorCode's uint32_t underlying
// type -- must decode through raw rather than nullopt. Complements the two
// tests above, which pin an arbitrary future value (20) and the first value
// that overflows the width (UINT32_MAX + 1); this one pins the boundary value
// itself, distinguishing "one past the edge" from "exactly at the edge".
TEST(ClientCodec, NumericErrorReplyToleratesErrorCodeAtUint32MaxBoundary)
{
    expectReplyRoundTrip(
        30, ErrInfo{static_cast<ErrorCode>(std::numeric_limits<std::uint32_t>::max()), std::nullopt, std::nullopt},
        [](std::uint64_t r, const ErrInfo& a) { return makeErrorReply(r, a); });
}

// (e) err-info code/name XOR (CDDL:105-113): both present, or neither, is
// malformed -- never a silent pick of one side.
TEST(ClientCodec, ErrInfoRejectsBothCodeAndNamePresent)
{
    CborValue::Map err;
    err.emplace("code", CborValue::uint(static_cast<std::uint64_t>(ErrorCode::CardRemoved)));
    err.emplace("name", CborValue(std::string("UnknownCard")));
    CborValue::Map reply;
    reply.emplace("t", CborValue(std::string("Reply")));
    reply.emplace("req", CborValue::uint(16));
    reply.emplace("err", CborValue(std::move(err)));
    const auto bytes = CborValue(std::move(reply)).encode();
    EXPECT_FALSE(parseReply(bytes, noFds()).has_value());
}

TEST(ClientCodec, ErrInfoRejectsNeitherCodeNorNamePresent)
{
    CborValue::Map err;
    err.emplace("msgKey", CborValue(std::string("x"))); // no code, no name
    CborValue::Map reply;
    reply.emplace("t", CborValue(std::string("Reply")));
    reply.emplace("req", CborValue::uint(17));
    reply.emplace("err", CborValue(std::move(err)));
    const auto bytes = CborValue(std::move(reply)).encode();
    EXPECT_FALSE(parseReply(bytes, noFds()).has_value());
}

// (c) an unrecognised EXTRA map key inside a known reply arm is ignored.
TEST(ClientCodec, IgnoresUnknownReplyMapKeys)
{
    CborValue::Map arm;
    arm.emplace("t", CborValue(std::string("Reply")));
    arm.emplace("req", CborValue::uint(18));
    arm.emplace("ok", CborValue(true));
    arm.emplace("futureField", CborValue(std::string("ignored"))); // unknown extra key
    const auto bytes = CborValue(std::move(arm)).encode();
    const auto decoded = parseReply(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->requestId, 18u);
    EXPECT_TRUE(std::holds_alternative<AckReply>(decoded->reply));
}

// (d) a reply shape this client build does not recognise decodes to
// UnknownReply -- never nullopt, never a throw.
TEST(ClientCodec, UnrecognisedReplyShapeDecodesToUnknownReply)
{
    CborValue::Map arm;
    arm.emplace("t", CborValue(std::string("Reply")));
    arm.emplace("req", CborValue::uint(19));
    arm.emplace("futureShape", CborValue(std::string("something-new")));
    const auto bytes = CborValue(std::move(arm)).encode();
    std::optional<DecodedReply> decoded;
    EXPECT_NO_THROW(decoded = parseReply(bytes, noFds()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->requestId, 19u);
    EXPECT_TRUE(std::holds_alternative<UnknownReply>(decoded->reply));
}

// A frame that is not a reply at all (wrong/missing top-level `t`) is
// malformed for parseReply's contract, not an unknown arm.
TEST(ClientCodec, ParseReplyRejectsNonReplyTopLevelTag)
{
    CborValue::Map m;
    m.emplace("t", CborValue(std::string("ReaderAdded")));
    m.emplace("req", CborValue::uint(1));
    const auto bytes = CborValue(std::move(m)).encode();
    EXPECT_FALSE(parseReply(bytes, noFds()).has_value());
}

TEST(ClientCodec, ParseReplyRejectsMalformedBytes)
{
    const std::vector<std::uint8_t> garbage{0xff, 0x00, 0x9f};
    EXPECT_FALSE(parseReply(garbage, noFds()).has_value());
    EXPECT_FALSE(parseEvent(garbage, noFds()).has_value());
}

// (h) well-formed-but-non-canonical CBOR (legal per the base RFC 8949 grammar,
// but violating the §4.2 canonical subset Cbor.cpp's decode() enforces via its
// re-encode-and-compare guard) must be rejected at parseReply's entry point
// too, not just at the Cbor-level decode() unit tests (CborRoundTripTest.cpp).
// Hand-built map(3){ "req":18, "t":"Reply", "ok":true } -- a structurally
// valid ack-reply shape QCBOR itself accepts, but with keys out of canonical
// (length-ascending) order: "req" (len 3) appears before "t" (len 1).
TEST(ClientCodec, ParseReplyRejectsNonCanonicalCbor)
{
    const std::vector<std::uint8_t> nonCanonical{0xa3, 0x63, 'r', 'e', 'q', 0x12, 0x61, 't', 0x65,
                                                 'R',  'e',  'p', 'l', 'y', 0x62, 'o',  'k', 0xf5};
    EXPECT_FALSE(parseReply(nonCanonical, noFds()).has_value());
}

// ============================================================================
// (a) events: toCbor(event) -> parseEvent -> byte-stable re-encode.
// ============================================================================

TEST(ClientCodec, ReaderAddedRoundTrips)
{
    expectEventRoundTrip(ReaderAdded{ReaderState{"r1", "Reader One", false, std::nullopt}});
}

TEST(ClientCodec, ReaderRemovedRoundTrips)
{
    expectEventRoundTrip(ReaderRemoved{"r1"});
}

TEST(ClientCodec, CardAddedRoundTrips)
{
    expectEventRoundTrip(CardAdded{CardState{"c1", "r1", 0x3, PreReadAuth::Can}});
}

// cardType/atr round-trip once populated (the single-candidate/held-
// session-resolved case, or a post-read authoritative update).
TEST(ClientCodec, CardAddedRoundTripsWithCardTypeAndAtr)
{
    CardState cs{"c1", "r1", 0x3, PreReadAuth::Can};
    cs.cardType = "SRB-eID";
    cs.atr = "3B7F96000080318065B085040132900085";
    expectEventRoundTrip(CardAdded{cs});
}

// cardType/atr are OPTIONAL keys -- an older agent's frame (or one that
// simply has not resolved cardType yet) omits them entirely. Absence must
// decode to empty (nullopt), never fail the frame closed.
TEST(ClientCodec, CardStateDecodesMissingCardTypeAndAtrAsEmpty)
{
    CborValue::Map card;
    card.emplace("handle", CborValue(std::string("c1")));
    card.emplace("reader", CborValue(std::string("r1")));
    card.emplace("caps", CborValue::uint(0));
    card.emplace("preAuth", CborValue::uint(0));
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("CardAdded")));
    ev.emplace("card", CborValue(std::move(card)));
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<CardAdded>(decoded->event));
    const auto& got = std::get<CardAdded>(decoded->event).card;
    EXPECT_FALSE(got.cardType.has_value());
    EXPECT_FALSE(got.atr.has_value());
}

// (i) PreReadAuth append-tolerance: a value past Can=2 -- a future unlock
// method this build does not name -- decodes through raw rather than failing
// the frame closed. What it MEANS (default to None) is a client-layer
// concern (SocketTransport's preAuthToken()), not asserted at this layer.
TEST(ClientCodec, CardStateToleratesAppendedPreAuthValue)
{
    CborValue::Map card;
    card.emplace("handle", CborValue(std::string("c1")));
    card.emplace("reader", CborValue(std::string("r1")));
    card.emplace("caps", CborValue::uint(0));
    card.emplace("preAuth", CborValue::uint(9)); // past Can=2
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("CardAdded")));
    ev.emplace("card", CborValue(std::move(card)));
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<CardAdded>(decoded->event));
    EXPECT_EQ(static_cast<std::uint8_t>(std::get<CardAdded>(decoded->event).card.preAuth), 9u);
}

// (i) the tolerance is bounded by PreReadAuth's own uint8_t underlying
// storage: a preAuth value that doesn't fit a byte at all is still
// malformed -- it would silently alias two distinct future values.
TEST(ClientCodec, CardStateRejectsPreAuthAboveUint8Range)
{
    CborValue::Map card;
    card.emplace("handle", CborValue(std::string("c1")));
    card.emplace("reader", CborValue(std::string("r1")));
    card.emplace("caps", CborValue::uint(0));
    card.emplace("preAuth", CborValue::uint(256));
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("CardAdded")));
    ev.emplace("card", CborValue(std::move(card)));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

TEST(ClientCodec, CardRemovedRoundTrips)
{
    expectEventRoundTrip(CardRemoved{"c1"});
}

TEST(ClientCodec, PropertyChangedRoundTrips)
{
    std::map<std::string, CborValue> props;
    props.emplace("hasCard", CborValue(true));
    expectEventRoundTrip(PropertyChanged{"r1", "org.librescrs.Reader1", props});
}

TEST(ClientCodec, ConfigChangedRoundTrips)
{
    expectEventRoundTrip(ConfigChanged{"DefaultLevel"});
}

TEST(ClientCodec, OpProgressRoundTripsWithAllOptionalsPresentAndAbsent)
{
    // Fractional progress lands as f16 on the wire (QCBOR preferred
    // serialization) -- exercises float decode, not just uint.
    expectEventRoundTrip(
        OpProgress{9, OperationPhase::Signing, 0.5, std::optional<bool>{false}, std::optional<std::uint64_t>{30}});
    expectEventRoundTrip(OpProgress{9, OperationPhase::Created, std::nullopt, std::nullopt, std::nullopt});
}

TEST(ClientCodec, OpFinishedRoundTrips)
{
    expectEventRoundTrip(OpFinished{24, OperationStatus::Error, ErrorCode::CardRemoved, "op.failed", "Card removed"});
    expectEventRoundTrip(OpFinished{25, OperationStatus::Ok, ErrorCode::None, "", ""});
}

// (i) OperationPhase append-tolerance: a phase past this build's last known
// value (Done=7) -- as a newer agent would send -- decodes through raw
// rather than failing the frame closed. Hold-last-phase degradation is a
// client-layer (AgentOperation) concern, asserted in SeamMappingTest.cpp, not
// here -- the codec is a stateless carrier.
TEST(ClientCodec, OpProgressToleratesAppendedPhaseValue)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpProgress")));
    ev.emplace("op", CborValue::uint(50));
    ev.emplace("phase", CborValue::uint(99)); // past Done=7
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<OpProgress>(decoded->event));
    const auto& progress = std::get<OpProgress>(decoded->event);
    EXPECT_EQ(progress.op, 50u);
    EXPECT_EQ(static_cast<std::uint32_t>(progress.phase), 99u);
}

// (i) the tolerance is bounded by OperationPhase's own uint32_t underlying
// storage, exactly like ErrorCode's width check.
TEST(ClientCodec, OpProgressRejectsPhaseAboveUint32Range)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpProgress")));
    ev.emplace("op", CborValue::uint(51));
    ev.emplace("phase", CborValue::uint(static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

// (i) OperationStatus append-tolerance, combined with the pre-existing
// ErrorCode tolerance in the SAME frame: a status past Error=2 AND a code
// past InvalidDocument=19 both decode through raw. Status degradation
// ("treat as Error") is a client-layer (AgentOperation) concern, asserted in
// SeamMappingTest.cpp, not here.
TEST(ClientCodec, OpFinishedToleratesAppendedStatusAndErrorCodeValues)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpFinished")));
    ev.emplace("op", CborValue::uint(52));
    ev.emplace("status", CborValue::uint(7)); // past Error=2
    ev.emplace("code", CborValue::uint(10000));
    ev.emplace("msgKey", CborValue(std::string("")));
    ev.emplace("msgFallback", CborValue(std::string("")));
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<OpFinished>(decoded->event));
    const auto& finished = std::get<OpFinished>(decoded->event);
    EXPECT_EQ(finished.op, 52u);
    EXPECT_EQ(static_cast<std::uint32_t>(finished.status), 7u);
    EXPECT_EQ(static_cast<std::uint32_t>(finished.code), 10000u);
}

// (i) the tolerance is bounded by OperationStatus's own uint32_t underlying
// storage.
TEST(ClientCodec, OpFinishedRejectsStatusAboveUint32Range)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpFinished")));
    ev.emplace("op", CborValue::uint(53));
    ev.emplace("status", CborValue::uint(static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1));
    ev.emplace("code", CborValue::uint(0));
    ev.emplace("msgKey", CborValue(std::string("")));
    ev.emplace("msgFallback", CborValue(std::string("")));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

// (g) ErrorCode is wire-frozen APPEND-ONLY (ErrorCode.h): a code past this
// build's last known value (InvalidDocument=19) -- as a newer agent would
// send -- must decode through, not fail closed like OperationStatus/etc.
// static_cast<ErrorCode>(v) is well-defined for any value that fits the
// enum's uint32_t underlying type; byte-stable re-encode proves the carried
// value survived the round trip unmodified.
TEST(ClientCodec, OpFinishedToleratesAppendedErrorCodeValue)
{
    expectEventRoundTrip(OpFinished{30, OperationStatus::Error, static_cast<ErrorCode>(20), "op.failed", "unknown"});
    // A huge-but-still-uint32 value, as far from the known range as this wire
    // field can ever carry.
    expectEventRoundTrip(
        OpFinished{31, OperationStatus::Error, static_cast<ErrorCode>(4000000000U), "op.failed", "unknown"});
}

TEST(ClientCodec, AgentQuiescedRoundTrips)
{
    expectEventRoundTrip(AgentQuiesced{QuiesceReason::ScreenLocked});
}

// (i) QuiesceReason append-tolerance: a reason past Shutdown=3 -- a future
// one -- decodes through raw rather than failing the frame closed.
TEST(ClientCodec, AgentQuiescedToleratesAppendedReasonValue)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("AgentQuiesced")));
    ev.emplace("reason", CborValue::uint(42)); // past Shutdown=3
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<AgentQuiesced>(decoded->event));
    EXPECT_EQ(static_cast<std::uint8_t>(std::get<AgentQuiesced>(decoded->event).reason), 42u);
}

// (i) the tolerance is bounded by QuiesceReason's own uint8_t underlying
// storage, exactly like PreReadAuth's width check.
TEST(ClientCodec, AgentQuiescedRejectsReasonAboveUint8Range)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("AgentQuiesced")));
    ev.emplace("reason", CborValue::uint(256));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

TEST(ClientCodec, OpResultReadyIdentityRoundTrips)
{
    IdentityResult idResult;
    idResult.fields["MRZ"]["Name"] = IdentityField{"name.key", "Name", "text", std::string("JOHN DOE")};
    idResult.fields["MRZ"]["Raw"] = IdentityField{"raw.key", "Raw", "binary", CborValue::Bytes{0x01, 0x02}};
    expectEventRoundTrip(OpResultReady{20, idResult});
}

// Progressive per-group delivery: ONE group's field map -- the SAME (sssv)
// cell shape as one entry of OpResultReadyIdentity's own outer map above,
// carried by its own event rather than nested inside the grouped Result.
TEST(ClientCodec, OpIdentityGroupRoundTrips)
{
    OpIdentityGroup group;
    group.op = 20;
    group.groupKey = "MRZ";
    group.fields["Name"] = IdentityField{"name.key", "Name", "text", std::string("JOHN DOE")};
    group.fields["Raw"] = IdentityField{"raw.key", "Raw", "binary", CborValue::Bytes{0x01, 0x02}};
    expectEventRoundTrip(group);
}

// Adversarial group/field KEY survives the agent-side WIRE ENCODE hop
// verbatim: `encodeOpResult`'s Identity arm (Messages.cpp) is the one
// production encode path a plugin-supplied group/field string actually
// crosses on its way to the wire -- the client-side fakes (FakeAgent /
// FakeSocketAgent, see FieldKeyParityTest / TransportParityTest) build wire
// structures directly and never touch it, so this hop was previously backed
// only by a manual read of encodeIdentityFieldsMap/encodeOpResult, never by a
// test that actually drives an unusual key through it. Mirrors the group/
// field string TransportParityTest already proved survives the CLIENT-side
// conversions (`Mixed_CASE.Group-1` / `Weird_Field.Key-2` -- same adversarial
// strings, so this closes the identical gap on the agent-side encode leg
// instead of just re-proving the client leg again).
TEST(ClientCodec, IdentityResultAdversarialGroupAndFieldKeysSurviveEncodeOpResultVerbatim)
{
    constexpr std::string_view kGroupKey = "Mixed_CASE.Group-1";
    constexpr std::string_view kFieldKey = "Weird_Field.Key-2";

    IdentityResult idResult;
    idResult.fields[std::string(kGroupKey)][std::string(kFieldKey)] =
        IdentityField{"label.key", "Label", "text", std::string("value")};

    // (a) byte-stable round-trip via the shared helper (toCbor -> parseEvent
    // -> re-encode -> bytes match) -- proves the whole frame, not just the
    // key, is unharmed.
    expectEventRoundTrip(OpResultReady{50, idResult});

    // (b) the DIRECT assertion the follow-up asked for: decode via the
    // client-role ClientCodec and read the actual map key back out, rather
    // than trusting byte-equality to imply it. Deliberately re-decodes
    // (rather than reusing (a)'s internals) so this test stands on its own.
    const auto bytes = toCbor(OpResultReady{50, idResult}).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<OpResultReady>(decoded->event));
    const auto& ready = std::get<OpResultReady>(decoded->event);
    ASSERT_TRUE(std::holds_alternative<IdentityResult>(ready.result));
    const auto& decodedIdentity = std::get<IdentityResult>(ready.result);

    const auto groupIt = decodedIdentity.fields.find(std::string(kGroupKey));
    ASSERT_NE(groupIt, decodedIdentity.fields.end())
        << "group key was mutated/dropped somewhere between encodeOpResult and ClientCodec decode";
    const auto fieldIt = groupIt->second.find(std::string(kFieldKey));
    ASSERT_NE(fieldIt, groupIt->second.end())
        << "field key was mutated/dropped somewhere between encodeOpResult and ClientCodec decode";
    EXPECT_EQ(fieldIt->second.labelKey, "label.key");
    ASSERT_TRUE(std::holds_alternative<std::string>(fieldIt->second.value));
    EXPECT_EQ(std::get<std::string>(fieldIt->second.value), "value");
}

// (f) fd-index: Photo items reference fds by index; a valid index round-trips.
TEST(ClientCodec, OpResultReadyPhotoRoundTripsWithValidFdIndex)
{
    PhotoResult photoResult;
    photoResult.photos.push_back(PhotoItem{"MRZ:Photo", 0});
    const int fdVec[] = {11};
    expectEventRoundTrip(OpResultReady{21, photoResult}, fdVec);
}

// (f) fd-index: an out-of-range Photo fd index is malformed -> nullopt.
TEST(ClientCodec, OpResultReadyPhotoRejectsOutOfRangeFdIndex)
{
    PhotoResult photoResult;
    photoResult.photos.push_back(PhotoItem{"MRZ:Photo", 3});
    const auto bytes = toCbor(OpResultReady{21, photoResult}).encode();
    const int fdVec[] = {11}; // only index 0 valid; fd=3 is out of range
    EXPECT_FALSE(parseEvent(bytes, fdVec).has_value());
}

TEST(ClientCodec, OpResultReadyCertificatesRoundTrips)
{
    CertListResult certListResult;
    certListResult.certs.push_back(makeSampleCertInfo());
    expectEventRoundTrip(OpResultReady{22, certListResult});
}

// (f) fd-index: Sign's artifact is fd-referenced too, same as sign-recovery.
TEST(ClientCodec, OpResultReadySignRoundTripsWithValidFdIndexAndRejectsInvalid)
{
    const int fdVec[] = {5};
    expectEventRoundTrip(OpResultReady{23, SignResult{0, SignMeta{"pades", "b-lta", true, true}}}, fdVec);

    const auto bytes = toCbor(OpResultReady{23, SignResult{9, SignMeta{"pades", "b-lta", true, true}}}).encode();
    EXPECT_FALSE(parseEvent(bytes, fdVec).has_value());
}

// (f) fd-index: every row's artifact is fd-referenced, including a FAILED
// row's -- the wire's zero-length-sealed-memfd convention still resolves a
// real index, never an absent one.
TEST(ClientCodec, OpResultReadySignBatchRoundTripsWithValidFdIndices)
{
    SignBatchResult batch;
    batch.rows.push_back(SignBatchRow{"invoice-1.pdf", 0, SignMeta{"pades", "b-b", false, false}, ErrorCode::None});
    batch.rows.push_back(SignBatchRow{"invoice-2.pdf", 1, SignMeta{}, ErrorCode::CredentialWrong});
    const int fdVec[] = {5, 6};
    expectEventRoundTrip(OpResultReady{29, batch}, fdVec);
}

// (f) fd-index: an out-of-range row artifact index is malformed -> nullopt.
TEST(ClientCodec, OpResultReadySignBatchRejectsOutOfRangeFdIndex)
{
    SignBatchResult batch;
    batch.rows.push_back(SignBatchRow{"invoice-1.pdf", 9, SignMeta{"pades", "b-b", false, false}, ErrorCode::None});
    const auto bytes = toCbor(OpResultReady{30, batch}).encode();
    const int fdVec[] = {5}; // only index 0 valid; artifact=9 is out of range
    EXPECT_FALSE(parseEvent(bytes, fdVec).has_value());
}

// (g) SignBatch row errorCode is the SAME append-tolerant numeric ErrorCode
// as every other errorCode field on this wire: a value past this build's
// last known code decodes through raw rather than failing the row closed.
TEST(ClientCodec, OpResultReadySignBatchRowToleratesAppendedErrorCodeValue)
{
    SignBatchResult batch;
    batch.rows.push_back(
        SignBatchRow{"invoice-1.pdf", 0, SignMeta{"pades", "b-b", false, false}, static_cast<ErrorCode>(20)});
    const int fdVec[] = {5};
    expectEventRoundTrip(OpResultReady{31, batch}, fdVec);
}

TEST(ClientCodec, OpResultReadyCredentialsListRoundTrips)
{
    CredentialsResult listing;
    listing.result.outcome = CredentialOutcome::Ok;
    listing.result.blocked = false;
    listing.records = {makeFullCredentialRecord(), makeBareCredentialRecord()};
    expectEventRoundTrip(OpResultReady{25, listing});
}

TEST(ClientCodec, OpResultReadyCredentialsFailedMutationRoundTrips)
{
    CredentialsResult failed;
    failed.result.outcome = CredentialOutcome::InvalidPin;
    failed.result.retriesLeft = 2;
    failed.result.blocked = false;
    expectEventRoundTrip(OpResultReady{26, failed});
}

TEST(ClientCodec, OpResultReadyCredentialsKeyActivationFailedRoundTrips)
{
    CredentialsResult keyFail;
    keyFail.result.outcome = CredentialOutcome::KeyActivationFailed;
    keyFail.result.blocked = false;
    keyFail.result.pinActivated = true;
    keyFail.result.keyActivated = false;
    expectEventRoundTrip(OpResultReady{27, keyFail});
}

// (i) cred-outcome is a TEXT-token enum: an unrecognised token has no
// numeric width to bound, so it DEGRADES AT DECODE to Unspecified instead of
// failing the cred-result (and the whole op-result-ready event) closed.
TEST(ClientCodec, CredResultDegradesUnrecognisedOutcomeTokenToUnspecified)
{
    CborValue::Map credResult;
    credResult.emplace("outcome", CborValue(std::string("futureOutcome")));
    credResult.emplace("blocked", CborValue(false));
    CborValue::Map result;
    result.emplace("kind", CborValue(std::string("Credentials")));
    result.emplace("result", CborValue(std::move(credResult)));
    result.emplace("records", CborValue(CborValue::Array{}));
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpResultReady")));
    ev.emplace("op", CborValue::uint(54));
    ev.emplace("result", CborValue(std::move(result)));
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<OpResultReady>(decoded->event));
    const auto& ready = std::get<OpResultReady>(decoded->event);
    ASSERT_TRUE(std::holds_alternative<CredentialsResult>(ready.result));
    EXPECT_EQ(std::get<CredentialsResult>(ready.result).result.outcome, CredentialOutcome::Unspecified);
}

// An OpResultReady whose nested op-result `kind` is not one of the five
// closed alternatives is malformed (nested-unknown, not a top-level unknown
// shape) -- the append-tolerant escape hatch covers unrecognised top-level
// `t` tags, not a novel discriminator inside an otherwise-known event.
TEST(ClientCodec, OpResultReadyRejectsUnrecognisedResultKind)
{
    CborValue::Map result;
    result.emplace("kind", CborValue(std::string("SomethingNew")));
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("OpResultReady")));
    ev.emplace("op", CborValue::uint(28));
    ev.emplace("result", CborValue(std::move(result)));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

// (c) an unrecognised EXTRA map key inside a known event is ignored.
TEST(ClientCodec, IgnoresUnknownEventMapKeys)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("CardRemoved")));
    ev.emplace("handle", CborValue(std::string("c1")));
    ev.emplace("futureField", CborValue(std::string("ignored")));
    const auto bytes = CborValue(std::move(ev)).encode();
    const auto decoded = parseEvent(bytes, noFds());
    ASSERT_TRUE(decoded.has_value());
    ASSERT_TRUE(std::holds_alternative<CardRemoved>(decoded->event));
    EXPECT_EQ(std::get<CardRemoved>(decoded->event).handle, "c1");
}

// (d) an event `t` this client build does not recognise decodes to
// UnknownEvent -- never nullopt, never a throw.
TEST(ClientCodec, UnrecognisedEventTagDecodesToUnknownEvent)
{
    CborValue::Map ev;
    ev.emplace("t", CborValue(std::string("SomeFutureEvent")));
    ev.emplace("payload", CborValue(std::string("opaque")));
    const auto bytes = CborValue(std::move(ev)).encode();
    std::optional<DecodedEvent> decoded;
    EXPECT_NO_THROW(decoded = parseEvent(bytes, noFds()));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(std::holds_alternative<UnknownEvent>(decoded->event));
}

TEST(ClientCodec, ParseEventRejectsMissingTag)
{
    CborValue::Map ev;
    ev.emplace("handle", CborValue(std::string("c1")));
    const auto bytes = CborValue(std::move(ev)).encode();
    EXPECT_FALSE(parseEvent(bytes, noFds()).has_value());
}

TEST(ClientCodec, ParseReplyRejectsNonMapTopLevel)
{
    EXPECT_FALSE(parseReply(CborValue::uint(7).encode(), noFds()).has_value());
}

TEST(ClientCodec, ParseEventRejectsNonMapTopLevel)
{
    EXPECT_FALSE(parseEvent(CborValue::uint(7).encode(), noFds()).has_value());
}

// ---- defaulted operator== smoke (this task's struct sweep) -----------------
//
// Every reply arm / op-result payload / event struct that lacked its own
// equality operator now spells `bool operator==(const T&) const = default;`.
// A defaulted comparison operator can silently do the wrong thing if a field
// is later added without the compiler ever complaining (unlike a hand-written
// operator that forgets a field, `= default` always widens correctly -- but
// the more relevant risk here is a COPY-PASTE mistake in the class body, e.g.
// forgetting a member entirely before the operator== line, which nothing else
// catches). These four cases -- one per struct category this task touched --
// each construct two field-identical instances (must compare equal) and one
// instance differing in exactly one field (must compare unequal), proving the
// defaulted operator genuinely compares by value instead of being vacuously
// true/false or only comparing a leading field.
TEST(ClientCodec, DefaultedOperatorEqualsComparesByValueReplyArms)
{
    const HelloAck helloA{"4.3.0", {"credentials", "batch-sign"}};
    const HelloAck helloB{"4.3.0", {"credentials", "batch-sign"}};
    const HelloAck helloC{"4.3.1", {"credentials", "batch-sign"}};
    EXPECT_EQ(helloA, helloB);
    EXPECT_NE(helloA, helloC);

    EXPECT_EQ(AckReply{}, AckReply{});

    const ErrInfo errA{SyncError::UnknownCard, std::optional<std::string>{"k"}, std::nullopt};
    const ErrInfo errB{SyncError::UnknownCard, std::optional<std::string>{"k"}, std::nullopt};
    const ErrInfo errC{ErrorCode::CardRemoved, std::optional<std::string>{"k"}, std::nullopt};
    EXPECT_EQ(errA, errB);
    EXPECT_NE(errA, errC);

    StateReply stateA{{ReaderState{"r1", "Reader", true, std::optional<std::string>{"c1"}}}, {}};
    StateReply stateB = stateA;
    StateReply stateC = stateA;
    stateC.readers[0].hasCard = false;
    EXPECT_EQ(stateA, stateB);
    EXPECT_NE(stateA, stateC);
}

TEST(ClientCodec, DefaultedOperatorEqualsComparesByValueOpResultPayloads)
{
    IdentityResult idA;
    idA.fields["MRZ"]["Name"] = IdentityField{"name.key", "Name", "text", std::string("JOHN")};
    IdentityResult idB = idA;
    IdentityResult idC = idA;
    idC.fields["MRZ"]["Name"] = IdentityField{"name.key", "Name", "text", std::string("JANE")};
    EXPECT_EQ(idA, idB);
    EXPECT_NE(idA, idC);

    const SignResult signA{7, SignMeta{"pades", "b-b", true, false}};
    const SignResult signB{7, SignMeta{"pades", "b-b", true, false}};
    const SignResult signC{8, SignMeta{"pades", "b-b", true, false}};
    EXPECT_EQ(signA, signB);
    EXPECT_NE(signA, signC);

    SignBatchResult batchA;
    batchA.rows.push_back(SignBatchRow{"a.pdf", 1, SignMeta{"pades", "b-b", false, false}, ErrorCode::None});
    SignBatchResult batchB = batchA;
    SignBatchResult batchC = batchA;
    batchC.rows[0].code = ErrorCode::CredentialWrong;
    EXPECT_EQ(batchA, batchB);
    EXPECT_NE(batchA, batchC);

    // OpResultReady wraps OpResult (a std::variant) -- proves the outer
    // struct's defaulted == genuinely reaches through the variant, not just
    // comparing `op`.
    const OpResultReady readyA{5, signA};
    const OpResultReady readyB{5, signB};
    const OpResultReady readyC{5, signC};
    EXPECT_EQ(readyA, readyB);
    EXPECT_NE(readyA, readyC);
}

TEST(ClientCodec, DefaultedOperatorEqualsComparesByValueEvents)
{
    std::map<std::string, CborValue> propsA;
    propsA.emplace("CardType", CborValue(std::string("SRB-eID")));
    PropertyChanged pcA{"c1", "org.librescrs.Agent.Card1", propsA};
    PropertyChanged pcB = pcA;
    PropertyChanged pcC = pcA;
    pcC.props["CardType"] = CborValue(std::string("SRB-vehicle"));
    EXPECT_EQ(pcA, pcB);
    EXPECT_NE(pcA, pcC);

    const OpFinished finA{9, OperationStatus::Ok, ErrorCode::None, "", ""};
    const OpFinished finB{9, OperationStatus::Ok, ErrorCode::None, "", ""};
    const OpFinished finC{9, OperationStatus::Error, ErrorCode::CardRemoved, "op.failed", "Card removed"};
    EXPECT_EQ(finA, finB);
    EXPECT_NE(finA, finC);

    const AgentQuiesced qA{QuiesceReason::ScreenLocked};
    const AgentQuiesced qB{QuiesceReason::ScreenLocked};
    const AgentQuiesced qC{QuiesceReason::Shutdown};
    EXPECT_EQ(qA, qB);
    EXPECT_NE(qA, qC);
}

TEST(ClientCodec, DefaultedOperatorEqualsComparesByValueCredentialsAndOpIdentityGroup)
{
    const CredentialOpResult credOutcomeA{CredentialOutcome::Ok, std::optional<int>{3}, false, std::nullopt,
                                          std::nullopt};
    CredentialsResult credA{credOutcomeA, {}};
    CredentialsResult credB = credA;
    CredentialsResult credC = credA;
    credC.result.retriesLeft = 2;
    EXPECT_EQ(credA, credB);
    EXPECT_NE(credA, credC);

    OpIdentityGroup grpA;
    grpA.op = 20;
    grpA.groupKey = "MRZ";
    grpA.fields["Name"] = IdentityField{"name.key", "Name", "text", std::string("JOHN")};
    OpIdentityGroup grpB = grpA;
    OpIdentityGroup grpC = grpA;
    grpC.groupKey = "Registration";
    EXPECT_EQ(grpA, grpB);
    EXPECT_NE(grpA, grpC);
}

} // namespace
