// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <LibreSCRS/Agent/OperationPhase.h>      // OperationPhase, OperationStatus
#include <LibreSCRS/Agent/wire/CredentialWire.h> // CredentialOpResult, CredentialRecord
#include <LibreSCRS/Agent/wire/ErrorCode.h>      // ErrorCode
#include <LibreSCRS/Agent/wire/PreReadAuth.h>    // PreReadAuth

#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

// Typed message model over the reconciled CDDL (wire/librescrs-agent.cddl).
// The agent is a SERVER: it PARSES inbound requests (untrusted -> strict) and
// BUILDS outbound replies + events (trusted, from core results). The value enums
// are the upstream core enums so the WireContractGuard anchoring holds; the two
// socket-only vocabularies (SyncError names, QuiesceReason) are declared here.

namespace LibreSCRS::Agent::Wire {

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;

// Why a request could not be modeled from its CBOR (distinct from CborError,
// which is the byte-level decode failure). All fail closed.
enum class WireError : std::uint8_t {
    NotDecodable,   // the frame body was not canonical CBOR
    NotAMap,        // top-level item is not a map
    MissingField,   // a required field is absent
    WrongType,      // a field has the wrong CBOR type
    NoTag,          // no `t` discriminator
    UnknownMessage, // `t` is not a known request tag
    BadEnum,        // an enum-valued field is out of range
    BadConfigKey,   // a config key outside the settable / known set
};

// Socket-only lifecycle vocabulary (no core enum — AgentQuiesced is host-specific).
enum class QuiesceReason : std::uint8_t { SystemSleep = 0, ScreenLocked = 1, SessionInactive = 2, Shutdown = 3 };

// Named synchronous-method errors (D-Bus Error.* names). Distinct from the async
// numeric ErrorCode. Order is not wire-significant (the wire carries the name).
enum class SyncError : std::uint8_t {
    UnknownCard,
    KeyNotFound,
    NotAuthorized,
    UserNotLoggedIn,
    UnknownConfigKey,
    ReadOnlyConfig,
    InvalidConfigValue,
    UnsupportedProtocol,
    AuthFailed,
    CommunicationError,
    NotSupported,
    UnsupportedOnThisCard,
    UnsupportedSignatureParameter,
    InputTooLarge,
    RateLimited,
    UnknownCredential,
    InvalidRequest,
    // GetSignResult has nothing to serve for the requested op: the op never
    // reached a retained Sign result (wrong kind, never completed, or the
    // recovery grace window already elapsed), OR the requester does not own
    // it -- the two are deliberately indistinguishable on the wire (an
    // IDOR-safe agent must answer a not-mine op exactly like an absent one,
    // never a distinct "not yours" error that would let op ids be enumerated
    // for ownership). Previously served ad hoc (a borrowed InvalidRequest/
    // KeyNotFound stand-in, depending on which host); this is the dedicated
    // name both hosts serve now.
    NoResult,
};

// The wire name for a SyncError (== the CDDL literal). Never empty.
[[nodiscard]] std::string_view syncErrorName(SyncError e) noexcept;

// ---- shared sub-types --------------------------------------------------------

// Card1.Sign's `visualSignature` nested map (PAdES-only visible-signature
// appearance). All six fields are required when the map itself is present
// (the outer `? visualSignature` on sign-opts is what is optional, not any
// field inside it) — mirrors LM's VisualSignatureParams field-for-field.
// page is 0-based; x/y/width/height are PDF user units carried as float64 on
// the wire (narrowed to LM's integer Rect agent-side, in LmSigner).
struct VisualSignatureOpts
{
    std::uint64_t page{0};
    double x{0.0};
    double y{0.0};
    double width{0.0};
    double height{0.0};
    std::string text;
    bool operator==(const VisualSignatureOpts&) const = default;
};

// Card1.Sign options. format/level/packaging required; the rest optional.
// tsaUrl/visualSignature are validated at method entry (https+host;
// PAdES-only respectively) before a SignParams is ever constructed — this
// struct itself carries no invariant beyond the CBOR shape.
struct SignOpts
{
    std::string format;
    std::string level;
    std::string packaging;
    std::optional<bool> allowExpired;
    std::optional<std::string> displayName;
    std::optional<std::string> reason;
    std::optional<std::string> location;
    std::optional<std::string> tsaUrl;
    std::optional<VisualSignatureOpts> visualSignature;
    bool operator==(const SignOpts&) const = default;
};

struct ReaderState
{
    std::string handle;
    std::string name;
    bool hasCard{false};
    std::optional<std::string> card;
    bool operator==(const ReaderState&) const = default;
};

struct CardState
{
    std::string handle;
    std::string reader;
    std::uint32_t caps{0}; // capabilities bitmask (CardCapabilities bits)
    PreReadAuth preAuth{PreReadAuth::None};
    // Optional (append-only, feature-gated "card-type"): absent == not yet
    // known / an older agent. cardType is the single-candidate pluginId at
    // insertion (else absent until a real read resolves it authoritatively);
    // atr is uppercase hex, no separators, the full session ATR (present from
    // insertion onward in practice).
    std::optional<std::string> cardType;
    std::optional<std::string> atr;
    bool operator==(const CardState&) const = default;
};

// One grouped field cell (labelKey, labelFallback, value) — the Certificates1
// (ssv) shape (value is always a UTF-8 string on the cert surface).
struct CertField
{
    std::string labelKey;
    std::string labelFallback;
    std::string value;
    bool operator==(const CertField&) const = default;
};

struct CertInfo
{
    std::string certId;
    bool signingCapable{false};
    std::map<std::string, std::map<std::string, CertField>> fields; // group -> field -> cell
    std::uint32_t keyUsageBits{0};
    std::vector<std::string> ekus;
    std::vector<std::string> chainSubjectCns;
    std::uint32_t trustStatus{0};
    bool operator==(const CertInfo&) const = default;
};

struct SignMeta
{
    std::string format;
    std::string level;
    bool tsaUsed{false};
    bool chainComplete{false};
    bool operator==(const SignMeta&) const = default;
};

// ---- requests (client -> agent) ---------------------------------------------

struct Hello
{
    std::uint64_t proto{0};
    std::optional<std::string> client;
    bool operator==(const Hello&) const = default;
};
struct GetState
{
    bool operator==(const GetState&) const = default;
};
struct ReadIdentity
{
    std::string card;
    bool operator==(const ReadIdentity&) const = default;
};
struct GetPhoto
{
    std::string card;
    bool operator==(const GetPhoto&) const = default;
};
struct ReadCertificates
{
    std::string card;
    bool operator==(const ReadCertificates&) const = default;
};
// Lightweight token-info read (PKCS#15 TokenInfo or equivalent). Result rides
// the EXISTING Identity1/IdentityResult shape (op-result-ready kind
// "Identity", a single "token" group: label/serial_number/manufacturer) — no
// new result shape. Gated behind the "credentials"-style "token-info"
// hello-ack feature token + the PKI capability bit (token info is
// PKI-adjacent, the same gate ReadCertificates uses).
struct ReadTokenInfo
{
    std::string card;
    bool operator==(const ReadTokenInfo&) const = default;
};
struct Sign
{
    std::string card;
    std::string cert;
    std::uint64_t inFd{0}; // fd-index into the frame's SCM_RIGHTS vector
    SignOpts opts;
    bool operator==(const Sign&) const = default;
};
// One document entered into a Card1.SignBatch request: a client-supplied
// display name (untrusted chrome, echoed back on its result row) plus the
// fd-index of its bytes on the SAME frame's SCM_RIGHTS vector.
struct BatchDocument
{
    std::string name;
    std::uint64_t fdIndex{0};
    bool operator==(const BatchDocument&) const = default;
};
// Card1.SignBatch: N documents signed under ONE consent + credential prompt,
// sharing cert/opts across the whole batch (only each document's identity
// varies). Entry validated to 1-12 documents; 0 or more than 12 is
// Error.InvalidRequest, no Operation minted.
struct SignBatch
{
    std::string card;
    std::string cert;
    std::vector<BatchDocument> docs;
    SignOpts opts;
    bool operator==(const SignBatch&) const = default;
};
struct GetCertDer
{
    std::string reader;
    std::string cert;
    bool operator==(const GetCertDer&) const = default;
};
struct GetConfig
{
    bool operator==(const GetConfig&) const = default;
};
struct SetConfig
{
    std::string key; // a settable-config-key
    CborValue value; // `any`
    bool operator==(const SetConfig&) const = default;
};
struct ResetConfig
{
    std::string key; // a config-key
    bool operator==(const ResetConfig&) const = default;
};
struct CancelOp
{
    std::uint64_t op{0};
    bool operator==(const CancelOp&) const = default;
};
struct GetSignResult
{
    std::uint64_t op{0};
    bool operator==(const GetSignResult&) const = default;
};
struct PkLogin
{
    std::string reader;
    bool operator==(const PkLogin&) const = default;
};
struct PkLogout
{
    std::string reader;
    bool operator==(const PkLogout&) const = default;
};
struct PkPublicKey
{
    std::string reader;
    std::string cert;
    bool operator==(const PkPublicKey&) const = default;
};
struct PkSignRaw
{
    std::string reader;
    std::string cert;
    std::vector<std::uint8_t> data;
    bool operator==(const PkSignRaw&) const = default;
};
struct PkDecrypt
{
    std::string reader;
    std::string cert;
    std::vector<std::uint8_t> data;
    bool operator==(const PkDecrypt&) const = default;
};
// Credentials1 seam requests (PIN/signing-key lifecycle). Gated behind the
// "credentials" HelloAck feature token + the PinManagement capability bit; this
// wire never carries a secret (pinId is a record id from the last listing).
struct ListCredentials
{
    std::string card;
    bool operator==(const ListCredentials&) const = default;
};
struct ManagePin
{
    std::string card;
    std::string pinId;               // a record id from the most recent listing (NOT a PIN)
    std::string verb;                // a cred-verb: "change" | "unblock" | "activate_pin"
    std::optional<bool> activateKey; // legal only with verb "activate_pin"
    bool operator==(const ManagePin&) const = default;
};
struct ActivateSigningKey
{
    std::string card;
    bool operator==(const ActivateSigningKey&) const = default;
};
// Card-independent, synchronous visible-signature layout preview — no
// card, no Operation object. x/y/width/height are PDF user units (float64),
// mirroring VisualSignatureOpts' rectangle minus the page index (this call
// has no page). Validated at method entry via
// LibreSCRS::Agent::Operations::SignatureParams::isValidLayoutRect before
// this struct is ever handed to the Operations::layoutVisualSignature seam.
struct LayoutVisual
{
    std::string text;
    double x{0.0};
    double y{0.0};
    double width{0.0};
    double height{0.0};
    bool operator==(const LayoutVisual&) const = default;
};
// The embedded appearance font (Liberation Sans Regular TTF), served as a
// fd-carrying reply exactly like Sign's artifact / GetPhoto's items.
struct GetAppearanceFont
{
    bool operator==(const GetAppearanceFont&) const = default;
};

using Request =
    std::variant<Hello, GetState, ReadIdentity, GetPhoto, ReadCertificates, ReadTokenInfo, Sign, SignBatch, GetCertDer,
                 GetConfig, SetConfig, ResetConfig, CancelOp, GetSignResult, PkLogin, PkLogout, PkPublicKey, PkSignRaw,
                 PkDecrypt, ListCredentials, ManagePin, ActivateSigningKey, LayoutVisual, GetAppearanceFont>;

struct RequestEnvelope
{
    std::uint64_t req{0};
    Request body;
    bool operator==(const RequestEnvelope&) const = default;
};

// Parse one request frame body: canonical-decode the CBOR, require a map with a
// `req` id + a known `t` tag, and strictly model the body. Fail closed.
[[nodiscard]] std::expected<RequestEnvelope, WireError> parseRequest(std::span<const std::uint8_t> body);

// Round-trip helper (tests + symmetry): encode a request envelope to a CBOR map.
[[nodiscard]] CborValue toCbor(const RequestEnvelope& env);

// ---- reply arms (agent -> client) -------------------------------------------

struct HelloAck
{
    std::string agentVer;
    std::vector<std::string> features;
    bool operator==(const HelloAck&) const = default;
};
struct OpStarted
{
    std::uint64_t op{0};
    bool operator==(const OpStarted&) const = default;
};
struct StateReply
{
    std::vector<ReaderState> readers;
    std::vector<CardState> cards;
    bool operator==(const StateReply&) const = default;
};
struct CertListReply
{
    std::vector<CertInfo> certs;
    bool operator==(const CertListReply&) const = default;
};
struct CertDerReply
{
    std::vector<std::uint8_t> der;
    bool operator==(const CertDerReply&) const = default;
};
// Pkcs11.PublicKey: RSA served (n/e); EC reserved (crv/x/y) — not produced in v0.1.
struct RsaPublicKey
{
    std::vector<std::uint8_t> n;
    std::vector<std::uint8_t> e;
    bool operator==(const RsaPublicKey&) const = default;
};
struct EcPublicKey
{
    std::string crv;
    std::vector<std::uint8_t> x;
    std::vector<std::uint8_t> y;
    bool operator==(const EcPublicKey&) const = default;
};
using PublicKeyReply = std::variant<RsaPublicKey, EcPublicKey>;
struct ConfigReply
{
    std::map<std::string, CborValue> entries; // config-key -> any
    bool operator==(const ConfigReply&) const = default;
};
struct AckReply
{
    bool operator==(const AckReply&) const = default;
};
struct RawSignatureReply
{
    std::vector<std::uint8_t> sig;
    bool operator==(const RawSignatureReply&) const = default;
};
// LayoutVisualSignature's reply — see Operations::VisualLayoutResult
// (LmSeams.h), which this mirrors field-for-field. `clipped` is
// pixel-parity load-bearing: see the CDDL `layout` arm's own comment.
struct LayoutReply
{
    double fontSize{0.0};
    double lineHeight{0.0};
    std::vector<std::string> lines;
    bool clipped{false};
    bool operator==(const LayoutReply&) const = default;
};
// GetAppearanceFont's reply: the embedded font's bytes, ridden as an
// fd-index exactly like SignResult::artifact / PhotoItem::fd.
struct AppearanceFontReply
{
    std::uint64_t fd{0};
    bool operator==(const AppearanceFontReply&) const = default;
};

struct ErrInfo
{
    std::variant<ErrorCode, SyncError> code; // async numeric OR sync named
    std::optional<std::string> msgKey;
    std::optional<std::string> msgFallback;
    bool operator==(const ErrInfo&) const = default;
};

// ---- op-result payloads (OpResultReady / GetSignResult) ----------------------

struct IdentityField
{
    std::string labelKey;
    std::string labelFallback;
    std::string type;                                           // "text" | "date" | "binary"
    std::variant<std::string, std::vector<std::uint8_t>> value; // tstr for text/date, bstr for binary
    bool operator==(const IdentityField&) const = default;
};
struct IdentityResult
{
    std::map<std::string, std::map<std::string, IdentityField>> fields; // group -> field -> cell
    bool operator==(const IdentityResult&) const = default;
};
struct PhotoItem
{
    std::string key; // "group:field"
    std::uint64_t fd{0};
    bool operator==(const PhotoItem&) const = default;
};
struct PhotoResult
{
    std::vector<PhotoItem> photos;
    bool operator==(const PhotoResult&) const = default;
};
struct CertListResult
{
    std::vector<CertInfo> certs;
    bool operator==(const CertListResult&) const = default;
};
struct SignResult
{
    std::uint64_t artifact{0}; // fd-index
    SignMeta meta;
    bool operator==(const SignResult&) const = default;
};
// One row of a SignBatch result, index-aligned with the request's `docs`.
// `artifact` is an fd-index exactly like SignResult's own field; a failed
// row's fd resolves to the wire's pinned zero-length-sealed-memfd
// convention (a non-nullable fd still resolves, to zero bytes) rather than
// being absent. `code` is None on a successful row; every row from the halt
// point onward (inclusive of the row that triggered it) carries the SAME
// halt code.
struct SignBatchRow
{
    std::string displayName;
    std::uint64_t artifact{0}; // fd-index
    SignMeta meta;
    ErrorCode code{ErrorCode::None};
    bool operator==(const SignBatchRow&) const = default;
};
struct SignBatchResult
{
    std::vector<SignBatchRow> rows;
    bool operator==(const SignBatchResult&) const = default;
};
// Credentials op result: holds the wire-shape credential types directly — the
// codec (not the caller) maps the outcome enum + record fields to their wire
// tokens/keys. A mutation's records are always empty; a completed-Ok listing
// carries them.
struct CredentialsResult
{
    CredentialOpResult result;
    std::vector<CredentialRecord> records;
    bool operator==(const CredentialsResult&) const = default;
};
using OpResult =
    std::variant<IdentityResult, PhotoResult, CertListResult, SignResult, SignBatchResult, CredentialsResult>;

// Build a full reply CBOR map ({t:"Reply", req, <arm keys>}) for each arm, or an
// error reply ({t:"Reply", req, err:{...}}).
[[nodiscard]] CborValue makeReply(std::uint64_t req, const HelloAck&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const OpStarted&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const StateReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const CertListReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const CertDerReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const PublicKeyReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const ConfigReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const AckReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const RawSignatureReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const LayoutReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const AppearanceFontReply&);
[[nodiscard]] CborValue makeSignRecoveryReply(std::uint64_t req, const SignResult&); // sign-recovery arm
[[nodiscard]] CborValue makeErrorReply(std::uint64_t req, const ErrInfo&);

// ---- events (agent -> client, unsolicited) ----------------------------------

struct ReaderAdded
{
    ReaderState reader;
    bool operator==(const ReaderAdded&) const = default;
};
struct ReaderRemoved
{
    std::string handle;
    bool operator==(const ReaderRemoved&) const = default;
};
struct CardAdded
{
    CardState card;
    bool operator==(const CardAdded&) const = default;
};
struct CardRemoved
{
    std::string handle;
    bool operator==(const CardRemoved&) const = default;
};
struct PropertyChanged
{
    std::string handle;
    std::string iface;
    std::map<std::string, CborValue> props;
    bool operator==(const PropertyChanged&) const = default;
};
struct ConfigChanged
{
    std::string key;
    bool operator==(const ConfigChanged&) const = default;
};
struct OpProgress
{
    std::uint64_t op{0};
    OperationPhase phase{OperationPhase::Created};
    std::optional<double> progress;
    std::optional<bool> indeterminate;
    std::optional<std::uint64_t> watchdogSecs;
    bool operator==(const OpProgress&) const = default;
};
// Progressive per-group delivery, strictly ahead of the eventual
// OpResultReady for the SAME op (see the CDDL `op-identity-group` comment for
// the full ordering/tolerance contract). `fields` mirrors IdentityResult's
// own per-group map (fieldKey -> cell) — one group's worth, not the whole
// grouped dict.
struct OpIdentityGroup
{
    std::uint64_t op{0};
    std::string groupKey;
    std::map<std::string, IdentityField> fields;
    bool operator==(const OpIdentityGroup&) const = default;
};
struct OpResultReady
{
    std::uint64_t op{0};
    OpResult result;
    bool operator==(const OpResultReady&) const = default;
};
struct OpFinished
{
    std::uint64_t op{0};
    OperationStatus status{OperationStatus::Ok};
    ErrorCode code{ErrorCode::None};
    std::string msgKey;
    std::string msgFallback;
    bool operator==(const OpFinished&) const = default;
};
struct AgentQuiesced
{
    QuiesceReason reason{QuiesceReason::SystemSleep};
    bool operator==(const AgentQuiesced&) const = default;
};

[[nodiscard]] CborValue toCbor(const ReaderAdded&);
[[nodiscard]] CborValue toCbor(const ReaderRemoved&);
[[nodiscard]] CborValue toCbor(const CardAdded&);
[[nodiscard]] CborValue toCbor(const CardRemoved&);
[[nodiscard]] CborValue toCbor(const PropertyChanged&);
[[nodiscard]] CborValue toCbor(const ConfigChanged&);
[[nodiscard]] CborValue toCbor(const OpProgress&);
[[nodiscard]] CborValue toCbor(const OpIdentityGroup&);
[[nodiscard]] CborValue toCbor(const OpResultReady&);
[[nodiscard]] CborValue toCbor(const OpFinished&);
[[nodiscard]] CborValue toCbor(const AgentQuiesced&);

} // namespace LibreSCRS::Agent::Wire
