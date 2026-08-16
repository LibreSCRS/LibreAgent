// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "SocketTransport.h"

#include "SocketPath.h"

#include "../CertFieldsExtra.h"
#include "../ConfigKeys.h"
#include "../FieldExtraKeys.h"
#include "../dbus/AgentDBus.h"    // shared object/interface name spellings (constants only, no QtDBus)
#include "../dbus/ErrorNameMap.h" // the short-name half doubles as the socket sync-error map

#include <LibreSCRS/AgentClient/ClientTimeouts.h>
#include <LibreSCRS/AgentClient/CredentialTypes.h>

#include <LibreSCRS/Agent/wire/Framing.h>

#include <QDateTime>
#include <QDeadlineTimer>
#include <QFile>
#include <QFileInfo>
#include <QLoggingCategory>
#include <QSocketNotifier>
#include <QTimer>
#include <QVariant>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>

namespace {
Q_LOGGING_CATEGORY(lcSocket, "librescrs.agentclient.socket")
} // namespace

namespace LibreSCRS::AgentClient {

namespace Wire = LibreSCRS::Agent::Wire;

namespace {

QString fromStd(const std::string& s)
{
    return QString::fromStdString(s);
}

QByteArray toByteArray(const std::vector<std::uint8_t>& bytes)
{
    return QByteArray(reinterpret_cast<const char*>(bytes.data()), static_cast<qsizetype>(bytes.size()));
}

/// O_CLOEXEC dup of a frame-owned fd into an owning FdHandle (invalid on
/// failure). Duplicating — rather than stealing the frame's descriptor —
/// keeps every fd single-owner even if a malformed payload referenced the
/// same index twice; the frame closes its originals after dispatch.
FdHandle dupFd(int fd)
{
    if (fd < 0) {
        return {};
    }
    return FdHandle{::fcntl(fd, F_DUPFD_CLOEXEC, 0)};
}

std::vector<int> rawFds(const std::vector<Wire::UniqueFd>& fds)
{
    std::vector<int> raw;
    raw.reserve(fds.size());
    for (const Wire::UniqueFd& fd : fds) {
        raw.push_back(fd.get());
    }
    return raw;
}

QString preAuthToken(Wire::PreReadAuth preAuth)
{
    switch (preAuth) {
    case Wire::PreReadAuth::None:
        return QStringLiteral("None");
    case Wire::PreReadAuth::Mrz:
        return QStringLiteral("Mrz");
    case Wire::PreReadAuth::Can:
        return QStringLiteral("Can");
    }
    return QStringLiteral("None");
}

/// The canonical seam property vocabulary (the SAME keys the D-Bus transport
/// forwards) built from a wire reader-state. `Card` is always present — an
/// empty string when no card is inserted — so a reconcile snapshot resets a
/// stale card reference instead of leaving it behind.
QVariantMap readerProps(const Wire::ReaderState& reader)
{
    QVariantMap props;
    props.insert(QStringLiteral("Name"), fromStd(reader.name));
    props.insert(QStringLiteral("HasCard"), reader.hasCard);
    props.insert(QStringLiteral("Card"), reader.card ? fromStd(*reader.card) : QString());
    return props;
}

QVariantMap cardProps(const Wire::CardState& card)
{
    QVariantMap props;
    props.insert(QStringLiteral("Capabilities"), static_cast<uint>(card.caps));
    props.insert(QStringLiteral("PreReadAuthMethod"), preAuthToken(card.preAuth));
    props.insert(QStringLiteral("Reader"), fromStd(card.reader));
    // Optional on the wire (absent == not yet known / an older agent); the
    // canonical seam vocabulary always carries the key, empty when absent, so
    // AgentCard::applyProps sees the same shape regardless of transport.
    props.insert(QStringLiteral("CardType"), card.cardType ? fromStd(*card.cardType) : QString());
    props.insert(QStringLiteral("Atr"), card.atr ? fromStd(*card.atr) : QString());
    return props;
}

QVariant cborToVariant(const Wire::CborValue& value)
{
    switch (value.type()) {
    case Wire::CborType::Null:
        return {};
    case Wire::CborType::Bool:
        return *value.asBool();
    case Wire::CborType::UInt:
        return QVariant::fromValue<qulonglong>(*value.asUInt());
    case Wire::CborType::Int:
        return QVariant::fromValue<qlonglong>(*value.asInt());
    case Wire::CborType::Double:
        return *value.asDouble();
    case Wire::CborType::Text:
        return fromStd(*value.asText());
    case Wire::CborType::Bytes:
        return toByteArray(*value.asBytes());
    case Wire::CborType::Array: {
        QVariantList list;
        for (const Wire::CborValue& element : *value.asArray()) {
            list.append(cborToVariant(element));
        }
        return list;
    }
    case Wire::CborType::Map: {
        QVariantMap map;
        for (const auto& [key, element] : *value.asMap()) {
            map.insert(fromStd(key), cborToVariant(element));
        }
        return map;
    }
    }
    return {};
}

// ---- Config1 values --------------------------------------------------------------

/// `TslSources` as it arrives on THIS wire, normalized to the canonical
/// three-entry rows `configSnapshot()` promises.
///
/// The grammar types every config value as bare `any` (CDDL `config`), unlike
/// D-Bus's declared `a(sbb)`, so the shape a consumer sees is this client's
/// guarantee rather than the wire's — and this function is where the
/// guarantee is made. Two encodings are accepted because both are lawful
/// under `any` and an agent is free to pick either: an array of three-entry
/// arrays (what this client itself emits on SetConfig) and an array of maps
/// keyed url/lotl/eager (the shape a JSON-derived serializer naturally
/// produces). An entry matching neither is DROPPED rather than half-decoded:
/// a row with an empty URL would read as a configured-but-broken trusted
/// list, which is worse than one the agent will re-report on the next read.
QVariant normalizeTslSources(const QVariant& raw)
{
    QVariantList rows;
    for (const QVariant& entry : raw.toList()) {
        if (entry.metaType().id() == QMetaType::QVariantMap) {
            const QVariantMap fields = entry.toMap();
            const QVariant url = fields.value(QStringLiteral("url"));
            if (!url.isValid()) {
                continue;
            }
            rows.append(tslSourceRow(url.toString(), fields.value(QStringLiteral("lotl")).toBool(),
                                     fields.value(QStringLiteral("eager")).toBool()));
            continue;
        }
        const QVariantList cells = entry.toList();
        if (cells.size() != 3) {
            continue;
        }
        rows.append(tslSourceRow(cells.at(0).toString(), cells.at(1).toBool(), cells.at(2).toBool()));
    }
    return rows;
}

/// One entry of the `config` reply arm in the canonical client vocabulary.
QVariant configValueToVariant(const QString& key, const Wire::CborValue& value)
{
    const QVariant generic = cborToVariant(value);
    if (key == kConfigTslSources) {
        return normalizeTslSources(generic);
    }
    if (key == kConfigTsaUrls) {
        return generic.toStringList(); // `as` on the other wire; a CBOR array here
    }
    return generic;
}

/// The per-key marshal table for `SetConfig`, the socket twin of the D-Bus
/// `marshalConfigValue`. Only reached for a `settable-config-key` — the
/// grammar admits nothing else, and setConfig() refuses the rest before
/// building a frame — so there is no unknown-key fallthrough here.
Wire::CborValue configValueToCbor(const QString& key, const QVariant& value)
{
    if (key == kConfigTslSources) {
        Wire::CborValue::Array rows;
        for (const QVariant& row : value.toList()) {
            const QVariantList cells = row.toList();
            if (cells.size() != 3) {
                continue; // not a [url, isLotl, eager] row — see the API doc
            }
            rows.push_back(Wire::CborValue(Wire::CborValue::Array{Wire::CborValue(cells.at(0).toString().toStdString()),
                                                                  Wire::CborValue(cells.at(1).toBool()),
                                                                  Wire::CborValue(cells.at(2).toBool())}));
        }
        return Wire::CborValue(std::move(rows));
    }
    if (key == kConfigTsaUrls) {
        Wire::CborValue::Array urls;
        for (const QString& url : value.toStringList()) {
            urls.push_back(Wire::CborValue(url.toStdString()));
        }
        return Wire::CborValue(std::move(urls));
    }
    return Wire::CborValue(value.toString().toStdString());
}

// ---- wire err-info -> SeamError ------------------------------------------------

SeamError mapErrInfo(const Wire::ErrInfo& err)
{
    QString message;
    if (err.msgFallback) {
        message = fromStd(*err.msgFallback);
    } else if (err.msgKey) {
        message = fromStd(*err.msgKey);
    }
    if (const auto* sync = std::get_if<Wire::SyncError>(&err.code)) {
        // The named sync-error vocabulary IS the D-Bus short-name vocabulary
        // (the spellings after "org.librescrs.Agent.Error."), so the existing
        // classification table applies verbatim — and that table now also hands
        // back the named-error axis, decoded from the name below.
        //
        // That round trip recovers `*sync` exactly, so there is nothing to
        // overwrite here and no drift hazard to guard against. `*sync` did not
        // come off the wire raw: err-info's named alternative has exactly ONE
        // producer, the client-role decoder's own decodeSyncError() call, so any
        // token this build does not know was ALREADY degraded to
        // CommunicationError before this function ran. Re-deriving it composes
        // decodeSyncError with syncErrorName, which is the identity on the enum
        // (pinned for every enumerator by the wire contract guard), so the
        // second decode is idempotent on an already-degraded value.
        const std::string_view name = Wire::syncErrorName(*sync);
        return mapAgentErrorShortName(QString::fromLatin1(name.data(), static_cast<qsizetype>(name.size())), message);
    }
    // The numeric async taxonomy on a synchronous reply: the agent ANSWERED
    // with a wire-taxonomy refusal — same two-axis rule as the named half. No
    // named error: `wireName`'s synthetic "code:N" is a diagnostic spelling,
    // not a wire token, and nothing in the sync-error vocabulary corresponds
    // to it.
    SeamError e;
    e.errorCode = std::get<ErrorCode>(err.code);
    e.wireName = QStringLiteral("code:%1").arg(static_cast<uint>(e.errorCode));
    e.message = message;
    return e;
}

// ---- typed op-result payloads -> public value types -----------------------------

// One group's field map (fieldKey -> id-field cell) -> a public FieldGroup
// keyed by @p groupKey. Shared by toFieldGroups' per-group loop below and by
// dispatchEvent's OpIdentityGroup case, so the two conversions of this SAME
// cell shape can never drift apart.
FieldGroup toFieldGroup(const QString& groupKey, const std::map<std::string, Wire::IdentityField>& cells)
{
    FieldGroup group;
    group.key = groupKey;
    for (const auto& [fieldKey, cell] : cells) {
        Field field;
        field.key = fromStd(fieldKey);
        const QString type = fromStd(cell.type);
        field.extra.insert(kFieldExtraLabelKey, fromStd(cell.labelKey));
        field.extra.insert(kFieldExtraLabelFallback, fromStd(cell.labelFallback));
        field.extra.insert(kFieldExtraType, type);
        if (type == kFieldTypeBinary) {
            // Binary payloads are not display text: the bytes ride
            // `detail`, the display value stays empty (Marshal.cpp's rule).
            if (const auto* bytes = std::get_if<std::vector<std::uint8_t>>(&cell.value)) {
                field.detail = toByteArray(*bytes);
            } else {
                field.detail = fromStd(std::get<std::string>(cell.value)).toUtf8();
            }
        } else if (const auto* text = std::get_if<std::string>(&cell.value)) {
            field.value = fromStd(*text);
        }
        group.fields.append(std::move(field));
    }
    return group;
}

QList<FieldGroup> toFieldGroups(const Wire::IdentityResult& result)
{
    QList<FieldGroup> groups;
    for (const auto& [groupKey, cells] : result.fields) {
        groups.append(toFieldGroup(fromStd(groupKey), cells));
    }
    return groups;
}

QString certFieldValue(const Wire::CertInfo& cert, const char* group, const char* field)
{
    const auto groupIt = cert.fields.find(group);
    if (groupIt == cert.fields.end()) {
        return {};
    }
    const auto fieldIt = groupIt->second.find(field);
    if (fieldIt == groupIt->second.end()) {
        return {};
    }
    return fromStd(fieldIt->second.value);
}

// Security-status tokens riding the "security" fields-group (dict-key growth,
// not its own Wire::CertInfo member) -- one per field, read from each cell's
// VALUE (not its map key) to stay agnostic of the exact key scheme the agent
// uses, mirroring Marshal.cpp's D-Bus-side extraction of the same group.
std::vector<std::string> securityTokens(const Wire::CertInfo& cert)
{
    std::vector<std::string> out;
    const auto groupIt = cert.fields.find("security");
    if (groupIt == cert.fields.end()) {
        return out;
    }
    out.reserve(groupIt->second.size());
    for (const auto& [fieldKey, cell] : groupIt->second) {
        out.push_back(cell.value);
    }
    return out;
}

QStringList toStringList(const std::vector<std::string>& values)
{
    QStringList out;
    out.reserve(static_cast<qsizetype>(values.size()));
    for (const std::string& value : values) {
        out.append(fromStd(value));
    }
    return out;
}

QList<CertificateInfo> toCertificateInfos(const std::vector<Wire::CertInfo>& certs)
{
    QList<CertificateInfo> out;
    out.reserve(static_cast<qsizetype>(certs.size()));
    for (const Wire::CertInfo& cert : certs) {
        CertificateInfo info;
        info.id = fromStd(cert.certId);
        info.signingCapable = cert.signingCapable;
        info.subject = certFieldValue(cert, "subject", "cn");
        info.issuer = certFieldValue(cert, "issuer", "cn");
        info.notBefore = QDateTime::fromString(certFieldValue(cert, "validity", "notBefore"), Qt::ISODate);
        info.notAfter = QDateTime::fromString(certFieldValue(cert, "validity", "notAfter"), Qt::ISODate);
        // Wire trust verdict -> the client-facing display set; the raw value
        // rides `extra` (the same collapse Marshal.cpp applies). Revoked (5)
        // maps to the client's own Revoked case; OfflineUnverified (6) and any
        // value this build does not yet know about both collapse to Unknown --
        // the finer "why unknown" distinction rides securityStatus below.
        switch (cert.trustStatus) {
        case 0U:
            info.trust = TrustStatus::Trusted;
            break;
        case 1U:
        case 2U:
        case 3U:
            info.trust = TrustStatus::Untrusted;
            break;
        case 4U:
            info.trust = TrustStatus::Expired;
            break;
        case 5U:
            info.trust = TrustStatus::Revoked;
            break;
        default:
            info.trust = TrustStatus::Unknown;
            break;
        }
        info.securityStatus = toStringList(securityTokens(cert));
        // Certificate metadata: TYPED members, and deliberately NOT also an
        // `extra` entry -- one source of truth, so a consumer cannot read a
        // duplicate that nothing keeps in step. Marshal.cpp's D-Bus-side
        // toCertificateInfos populates the same three members from its own
        // wire shape; the shared parity scenario asserts both against one
        // body, because a change made here alone would leave the D-Bus side
        // populated and this one silently empty.
        info.keyUsageBits = cert.keyUsageBits;
        info.extendedKeyUsageOids = toStringList(cert.ekus);
        info.chainSubjectCns = toStringList(cert.chainSubjectCns);
        // trustStatusWire has no typed member to land in: `trust` above
        // collapses several wire verdicts into one display value, so the raw
        // number is the only way back to the cause. It stays in `extra`.
        info.extra.insert(QStringLiteral("trustStatusWire"), static_cast<uint>(cert.trustStatus));
        // The grouped fields dict, whole -- the same surface Marshal.cpp
        // produces from the D-Bus container, through the same builder, because
        // the consumer renders one shape and does not know which wire it came
        // over. The four cells extracted above are in here too; extraction and
        // surfacing are additive, never alternatives.
        CertFieldsExtra fieldsExtra;
        for (const auto& [groupKey, cells] : cert.fields) {
            for (const auto& [fieldKey, cell] : cells) {
                fieldsExtra.add(fromStd(groupKey), fromStd(fieldKey), fromStd(cell.labelKey),
                                fromStd(cell.labelFallback), fromStd(cell.value));
            }
        }
        fieldsExtra.installInto(info.extra);
        out.append(std::move(info));
    }
    return out;
}

const char* credOutcomeToken(Wire::CredentialOutcome outcome)
{
    switch (outcome) {
    case Wire::CredentialOutcome::Unspecified:
        return "unspecified";
    case Wire::CredentialOutcome::Ok:
        return "ok";
    case Wire::CredentialOutcome::UserCancelled:
        return "userCancelled";
    case Wire::CredentialOutcome::MissingFields:
        return "missingFields";
    case Wire::CredentialOutcome::InvalidPin:
        return "invalidPin";
    case Wire::CredentialOutcome::Blocked:
        return "blocked";
    case Wire::CredentialOutcome::PluginError:
        return "pluginError";
    case Wire::CredentialOutcome::Unsupported:
        return "unsupported";
    case Wire::CredentialOutcome::KeyActivationFailed:
        return "keyActivationFailed";
    case Wire::CredentialOutcome::CardRemoved:
        return "cardRemoved";
    }
    return "unspecified";
}

/// The typed wire credential result, respelled into the frozen snake_case
/// record vocabulary the public parsers (PinResult/CredentialRecord
/// ::fromVariantMap) consume — ONE parsing path for both transports.
QVariantMap credResultToMap(const Wire::CredentialOpResult& result)
{
    QVariantMap map;
    map.insert(QStringLiteral("outcome"), QLatin1String(credOutcomeToken(result.outcome)));
    if (result.retriesLeft) {
        map.insert(QStringLiteral("retries_left"), *result.retriesLeft);
    }
    map.insert(QStringLiteral("blocked"), result.blocked);
    if (result.pinActivated) {
        map.insert(QStringLiteral("pin_activated"), *result.pinActivated);
    }
    if (result.keyActivated) {
        map.insert(QStringLiteral("key_activated"), *result.keyActivated);
    }
    return map;
}

QVariantMap credRecordToMap(const Wire::CredentialRecord& record)
{
    QVariantMap map;
    map.insert(QStringLiteral("id"), fromStd(record.id));
    map.insert(QStringLiteral("label"), fromStd(record.label));
    // kind/state/unblockStyle/recovery already carry their shared token
    // strings on the wire struct — forwarded verbatim.
    map.insert(QStringLiteral("kind"), fromStd(record.kind));
    map.insert(QStringLiteral("state"), fromStd(record.state));
    const auto optInt = [&map](const char* key, const std::optional<int>& value) {
        if (value) {
            map.insert(QLatin1String(key), *value);
        }
    };
    optInt("retries_left", record.retriesLeft);
    optInt("retries_max", record.retriesMax);
    optInt("uses_left", record.usesLeft);
    optInt("uses_max", record.usesMax);
    optInt("unblocks_left", record.unblocksLeft);
    optInt("min_length", record.minLength);
    optInt("max_length", record.maxLength);
    map.insert(QStringLiteral("can_change"), record.canChange);
    map.insert(QStringLiteral("unblockable"), record.unblockable);
    map.insert(QStringLiteral("unblock_style"), fromStd(record.unblockStyle));
    map.insert(QStringLiteral("activatable"), record.activatable);
    map.insert(QStringLiteral("key_activation_pending"), record.keyActivationPending);
    map.insert(QStringLiteral("key_activatable"), record.keyActivatable);
    map.insert(QStringLiteral("recovery"), fromStd(record.recovery));
    map.insert(QStringLiteral("probe_safe"), record.probeSafe);
    const auto optStr = [&map](const char* key, const std::optional<std::string>& value) {
        if (value) {
            map.insert(QLatin1String(key), fromStd(*value));
        }
    };
    optStr("blocked_guidance_key", record.blockedGuidanceKey);
    optStr("blocked_guidance_fallback", record.blockedGuidanceFallback);
    optStr("key_activation_guidance_key", record.keyActivationGuidanceKey);
    optStr("key_activation_guidance_fallback", record.keyActivationGuidanceFallback);
    return map;
}

/// One decoded op-result payload -> the seam's scrubbed OperationPayload.
/// fd indices were bounds-checked by the codec; each referenced fd is dup'd
/// out of the frame.
OperationPayload toPayload(Wire::OpResult&& result, const std::vector<Wire::UniqueFd>& fds)
{
    OperationPayload payload;
    if (auto* identity = std::get_if<Wire::IdentityResult>(&result)) {
        payload.kind = OperationKind::Identity;
        payload.identity = toFieldGroups(*identity);
    } else if (auto* photo = std::get_if<Wire::PhotoResult>(&result)) {
        payload.kind = OperationKind::Photo;
        payload.photos.reserve(photo->photos.size());
        for (const Wire::PhotoItem& item : photo->photos) {
            PhotoItem out;
            out.key = fromStd(item.key);
            out.fd = dupFd(fds[static_cast<std::size_t>(item.fd)].get());
            payload.photos.push_back(std::move(out));
        }
    } else if (auto* certs = std::get_if<Wire::CertListResult>(&result)) {
        payload.kind = OperationKind::Certificates;
        payload.certificates = toCertificateInfos(certs->certs);
    } else if (auto* sign = std::get_if<Wire::SignResult>(&result)) {
        payload.kind = OperationKind::Sign;
        payload.signedArtifact = dupFd(fds[static_cast<std::size_t>(sign->artifact)].get());
        payload.signMeta.insert(QStringLiteral("format"), fromStd(sign->meta.format));
        payload.signMeta.insert(QStringLiteral("level"), fromStd(sign->meta.level));
        payload.signMeta.insert(QStringLiteral("tsaUsed"), sign->meta.tsaUsed);
        payload.signMeta.insert(QStringLiteral("chainComplete"), sign->meta.chainComplete);
    } else if (auto* batch = std::get_if<Wire::SignBatchResult>(&result)) {
        payload.kind = OperationKind::BatchSign;
        payload.batchRows.reserve(batch->rows.size());
        for (const Wire::SignBatchRow& row : batch->rows) {
            BatchSignRow item;
            item.displayName = fromStd(row.displayName);
            item.artifact = dupFd(fds[static_cast<std::size_t>(row.artifact)].get());
            item.meta.insert(QStringLiteral("format"), fromStd(row.meta.format));
            item.meta.insert(QStringLiteral("level"), fromStd(row.meta.level));
            item.meta.insert(QStringLiteral("tsaUsed"), row.meta.tsaUsed);
            item.meta.insert(QStringLiteral("chainComplete"), row.meta.chainComplete);
            item.error = row.code; // Wire::ErrorCode IS LibreSCRS::AgentClient::ErrorCode (a using-alias)
            payload.batchRows.push_back(std::move(item));
        }
    } else if (auto* credentials = std::get_if<Wire::CredentialsResult>(&result)) {
        payload.kind = OperationKind::Credentials;
        payload.pinResult = PinResult::fromVariantMap(credResultToMap(credentials->result));
        payload.credentials.reserve(static_cast<qsizetype>(credentials->records.size()));
        for (const Wire::CredentialRecord& record : credentials->records) {
            payload.credentials.append(CredentialRecord::fromVariantMap(credRecordToMap(record)));
        }
    }
    return payload;
}

/// The seam's wire-keyed `visualSignature` QVariantMap -> the wire's
/// `visual-sig-opts` shape (all six keys required — see SignOptions.h's
/// doc comment for the exact key set/types this map must carry).
Wire::VisualSignatureOpts toVisualSignatureOpts(const QVariantMap& v)
{
    Wire::VisualSignatureOpts opts;
    opts.page = v.value(QStringLiteral("page")).toULongLong();
    opts.x = v.value(QStringLiteral("x")).toDouble();
    opts.y = v.value(QStringLiteral("y")).toDouble();
    opts.width = v.value(QStringLiteral("width")).toDouble();
    opts.height = v.value(QStringLiteral("height")).toDouble();
    opts.text = v.value(QStringLiteral("text")).toString().toStdString();
    return opts;
}

/// The seam's wire-keyed sign-option map -> the CLOSED sign-opts shape of
/// this wire. Every key the CDDL's sign-opts vocabulary defines — including
/// tsaUrl and visualSignature — forwards identically to both transports;
/// this used to drop tsaUrl/visualSignature here with a warning (the wire had
/// no field for them), a documented, pinned asymmetry retired once the socket
/// wire's sign-opts grew both fields. A key outside the vocabulary entirely
/// is still dropped with a warning — that part of the contract is unchanged.
Wire::SignOpts toSignOpts(const QVariantMap& options)
{
    Wire::SignOpts opts;
    for (auto it = options.constBegin(); it != options.constEnd(); ++it) {
        const QString& key = it.key();
        if (key == QLatin1String("format")) {
            opts.format = it->toString().toStdString();
        } else if (key == QLatin1String("level")) {
            opts.level = it->toString().toStdString();
        } else if (key == QLatin1String("packaging")) {
            opts.packaging = it->toString().toStdString();
        } else if (key == QLatin1String("allowExpired")) {
            opts.allowExpired = it->toBool();
        } else if (key == QLatin1String("displayName")) {
            opts.displayName = it->toString().toStdString();
        } else if (key == QLatin1String("reason")) {
            opts.reason = it->toString().toStdString();
        } else if (key == QLatin1String("location")) {
            opts.location = it->toString().toStdString();
        } else if (key == QLatin1String("tsaUrl")) {
            opts.tsaUrl = it->toString().toStdString();
        } else if (key == QLatin1String("visualSignature")) {
            opts.visualSignature = toVisualSignatureOpts(it->toMap());
        } else {
            qCWarning(lcSocket) << "sign option" << key << "has no sign-opts field on the socket wire; dropped";
        }
    }
    // This wire's sign-opts REQUIRES the field, so absence has to be spelled.
    // Spell it with the contract's sentinel rather than the empty string
    // default-construction would leave: the frontend accepts both, but only
    // "auto" is in the CDDL's requested-level group.
    if (!options.contains(QStringLiteral("level"))) {
        opts.level = "auto";
    }
    return opts;
}

} // namespace

// ---- construction ----------------------------------------------------------------

SocketTransport::SocketTransport() : SocketTransport(resolveAgentSocketPath()) {}

SocketTransport::SocketTransport(QString socketPath) : m_socketPath(std::move(socketPath)) {}

SocketTransport::~SocketTransport() = default;

// ---- availability ------------------------------------------------------------------

void SocketTransport::setRegistryListener(RegistryListener* listener)
{
    m_registry = listener;
}

bool SocketTransport::probeAvailability()
{
    if (!m_fd.valid()) {
        return connectAndHandshake();
    }
    if (m_quiesced) {
        // No resume event exists on this wire: the bounded GetState
        // round-trip IS the probe — the agent answering again means card
        // access resumed.
        SyncResult result = callSync(Wire::GetState{}, kHandshakeTimeoutMs);
        if (result.failure == CallError::None && std::holds_alternative<Wire::StateReply>(result.reply)) {
            m_quiesced = false;
            return true;
        }
        return false;
    }
    return true;
}

bool SocketTransport::agentInstalled()
{
    if (m_fd.valid()) {
        return true;
    }
    // Not connected — but a bound socket on disk means an agent is installed
    // (running, or resumable): the socket analogue of a D-Bus-activatable
    // name.
    return !m_socketPath.isEmpty() && QFileInfo::exists(m_socketPath);
}

bool SocketTransport::isConnected() const
{
    return m_fd.valid() && m_established;
}

QString SocketTransport::agentVersion() const
{
    return m_agentVersion;
}

QStringList SocketTransport::agentFeatures() const
{
    return m_features;
}

bool SocketTransport::hasFeature(QLatin1StringView token) const
{
    return m_features.contains(QString(token));
}

QStringList SocketTransport::features() const
{
    // TransportSeam's public-facing surface: identical to agentFeatures()
    // (the two names coexist because SocketIntegrationTest.cpp's white-box
    // suite predates the seam method and asserts on the transport directly).
    return agentFeatures();
}

// ---- agent configuration (Config1) ------------------------------------------------

void SocketTransport::refreshConfig()
{
    SyncResult result = callSync(Wire::GetConfig{}, kHandshakeTimeoutMs);
    m_config.clear();
    if (result.failure != CallError::None) {
        return;
    }
    const auto* config = std::get_if<Wire::ConfigReply>(&result.reply);
    if (config == nullptr) {
        return; // err-info (an agent without the request family), or an unexpected arm
    }
    for (const auto& [key, value] : config->entries) {
        const QString name = fromStd(key);
        m_config.insert(name, configValueToVariant(name, value));
    }
}

QVariantMap SocketTransport::configSnapshot()
{
    if (!m_configFetched) {
        // "Once per connect", lazily, same posture as appearanceFont() above
        // (and this transport's re-handshake-per-reconnect makes the
        // connection the natural invalidation boundary).
        m_configFetched = true;
        refreshConfig();
    }
    return m_config;
}

std::optional<SyncError> SocketTransport::setConfig(const QString& key, const QVariant& value)
{
    // MANDATORY local refusal, not an optimization: this wire's `set-config`
    // grammar takes a `settable-config-key` ONLY, so a read-only key has no
    // encodable form here at all. The refusal has to name the same enumerator
    // the D-Bus agent would have answered — that transport CAN marshal the
    // key and lets the agent refuse it — or the same call would mean
    // different things to a caller depending on which wire it took.
    if (!isKnownConfigKey(key)) {
        return SyncError::UnknownConfigKey;
    }
    if (!isSettableConfigKey(key)) {
        return SyncError::ReadOnlyConfig;
    }
    Wire::SetConfig request;
    request.key = key.toStdString();
    request.value = configValueToCbor(key, value);
    SyncResult result = callSync(request, kHandshakeTimeoutMs);
    if (result.failure != CallError::None) {
        return SyncError::CommunicationError; // the write never arrived — the retryable class
    }
    if (const auto* err = std::get_if<Wire::ErrInfo>(&result.reply)) {
        return mapErrInfo(*err).syncError.value_or(SyncError::CommunicationError);
    }
    if (!std::holds_alternative<Wire::AckReply>(result.reply)) {
        return SyncError::CommunicationError; // a reply outside this request's contract
    }
    return std::nullopt;
}

std::optional<SyncError> SocketTransport::resetConfig(const QString& key)
{
    // `reset-config` takes the FULL `config-key` set, unlike set-config
    // above, so only an UNKNOWN key is unencodable and refused locally. A
    // read-only key IS encodable, so it goes to the agent and earns the
    // agent's own ReadOnlyConfig — the client does not pre-empt a refusal the
    // grammar leaves to the peer.
    if (!isKnownConfigKey(key)) {
        return SyncError::UnknownConfigKey;
    }
    Wire::ResetConfig request;
    request.key = key.toStdString();
    SyncResult result = callSync(request, kHandshakeTimeoutMs);
    if (result.failure != CallError::None) {
        return SyncError::CommunicationError;
    }
    if (const auto* err = std::get_if<Wire::ErrInfo>(&result.reply)) {
        return mapErrInfo(*err).syncError.value_or(SyncError::CommunicationError);
    }
    if (!std::holds_alternative<Wire::AckReply>(result.reply)) {
        return SyncError::CommunicationError;
    }
    return std::nullopt;
}

// ---- registry ------------------------------------------------------------------------

std::optional<RegistrySnapshot> SocketTransport::fetchRegistry()
{
    SyncResult result = callSync(Wire::GetState{}, kHandshakeTimeoutMs);
    if (result.failure != CallError::None) {
        return std::nullopt;
    }
    const auto* state = std::get_if<Wire::StateReply>(&result.reply);
    if (state == nullptr) {
        return std::nullopt;
    }
    RegistrySnapshot snapshot;
    for (const Wire::CardState& card : state->cards) {
        snapshot.cards.append({fromStd(card.handle), cardProps(card)});
    }
    for (const Wire::ReaderState& reader : state->readers) {
        snapshot.readers.append({fromStd(reader.handle), readerProps(reader)});
    }
    return snapshot;
}

// ---- Visual-signature layout preview -----------------------------------------------

std::optional<LayoutResult> SocketTransport::layoutVisualSignature(const QString& text, QRectF box)
{
    Wire::LayoutVisual request;
    request.text = text.toStdString();
    request.x = box.x();
    request.y = box.y();
    request.width = box.width();
    request.height = box.height();
    // Bounded like every other cheap, card-independent synchronous round-trip.
    SyncResult result = callSync(request, kHandshakeTimeoutMs);
    if (result.failure != CallError::None) {
        return std::nullopt;
    }
    const auto* layout = std::get_if<Wire::LayoutReply>(&result.reply);
    if (layout == nullptr) {
        return std::nullopt; // err-info (entry rejection) or an unexpected arm
    }
    LayoutResult out;
    out.fontSize = layout->fontSize;
    out.lineHeight = layout->lineHeight;
    for (const std::string& line : layout->lines) {
        out.lines.append(fromStd(line));
    }
    out.clipped = layout->clipped;
    return out;
}

FdHandle SocketTransport::appearanceFont()
{
    if (!m_appearanceFontFetched) {
        // "Once per connect" (this transport's re-handshake-per-reconnect
        // posture makes that the natural cache-invalidation boundary — see
        // this member's own doc comment in the header). A failure here
        // degrades to an invalid cached handle, same posture as m_features.
        m_appearanceFontFetched = true;
        SyncResult result = callSync(Wire::GetAppearanceFont{}, kHandshakeTimeoutMs);
        if (result.failure == CallError::None) {
            if (const auto* reply = std::get_if<Wire::AppearanceFontReply>(&result.reply)) {
                if (reply->fd < result.fds.size()) {
                    m_appearanceFont = dupFd(result.fds[reply->fd].get());
                }
            }
        }
    }
    if (!m_appearanceFont.valid()) {
        return {};
    }
    // Dup a fresh handle per call: the cache keeps sole ownership of
    // m_appearanceFont's descriptor for the connection's lifetime.
    return dupFd(m_appearanceFont.get());
}

// ---- per-object property tracking ------------------------------------------------------

void SocketTransport::subscribeProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener)
{
    m_propertyWatches.insert(listener, PropertyWatch{objectId, kind});
}

void SocketTransport::unsubscribeProperties(const QString& objectId, PropertyListener* listener)
{
    Q_UNUSED(objectId)
    // Removing the watch also kills any requestProperties reply still in
    // flight for it — the delivery path re-checks this hash.
    m_propertyWatches.remove(listener);
}

quint64 SocketTransport::requestProperties(const QString& objectId, ObjectKind kind, PropertyListener* listener)
{
    const quint64 token = ++m_nextPropsToken;
    // The wire has no per-object property read; a full GetState is the fetch
    // and the reply is reduced to the one object's map. Failure (or a lost
    // connection) answers nullopt THROUGH THE EVENT LOOP — this call never
    // delivers synchronously.
    const auto queueFailure = [this, token, objectId, listener]() {
        QMetaObject::invokeMethod(
            this,
            [this, token, objectId, listener]() {
                const auto it = m_propertyWatches.constFind(listener);
                if (it == m_propertyWatches.cend() || it->objectId != objectId) {
                    return; // dead/rebound subscription — drop the reply
                }
                listener->onPropertiesFetched(token, std::nullopt);
            },
            Qt::QueuedConnection);
    };
    if (!isConnected()) {
        queueFailure();
        return token;
    }
    const quint64 requestId = ++m_nextRequestId;
    const std::vector<std::uint8_t> body = Wire::encodeRequest(Wire::GetState{}, requestId);
    if (!Wire::sendFrame(m_fd.get(), body, {})) {
        dropConnection();
        queueFailure();
        return token;
    }
    auto* timer = new QTimer(this);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [this, requestId]() {
        const auto it = m_pendingProps.constFind(requestId);
        if (it == m_pendingProps.cend()) {
            return;
        }
        const PendingProps pending = it.value();
        m_pendingProps.erase(it);
        pending.timer->deleteLater();
        const auto watchIt = m_propertyWatches.constFind(pending.listener);
        if (watchIt == m_propertyWatches.cend() || watchIt->objectId != pending.objectId) {
            return;
        }
        pending.listener->onPropertiesFetched(pending.token, std::nullopt);
    });
    timer->start(kDefaultCallTimeoutMs);
    m_pendingProps.insert(requestId, PendingProps{token, objectId, kind, listener, timer});
    return token;
}

// ---- operations -----------------------------------------------------------------------

StartOutcome SocketTransport::startOperation(const QString& cardId, OperationRequest request)
{
    StartOutcome outcome;
    const std::string card = cardId.toStdString();
    Wire::RequestVariant wire = Wire::GetState{};
    std::vector<int> passFds;

    const bool credentialsMethod = request.method == OperationRequest::Method::ListCredentials ||
                                   request.method == OperationRequest::Method::ManagePin ||
                                   request.method == OperationRequest::Method::ActivateSigningKey;
    if (credentialsMethod && !hasFeature(QLatin1StringView("credentials"))) {
        // Mandatory HelloAck gate (CDDL): an agent without the token answers
        // an unknown request tag by dropping the whole connection, so the
        // refusal happens HERE, mapped exactly like the agent's own
        // NotSupported entry refusal.
        outcome.error = mapAgentErrorShortName(QStringLiteral("NotSupported"),
                                               QStringLiteral("agent does not advertise the credentials feature"));
        qCWarning(lcSocket) << "credentials request refused locally for" << cardId
                            << ": agent lacks the credentials feature token";
        return outcome;
    }
    // NOTE: ReadTokenInfo's "token-info" feature-token gate used to live here
    // too (a socket-only special case); it is now enforced transport-neutrally
    // in AgentCard::startOperation, BEFORE this method is ever called -- see
    // that function's comment. This transport never sees a ReadTokenInfo
    // request the client-side gate would have refused.

    switch (request.method) {
    case OperationRequest::Method::ReadIdentity:
        wire = Wire::ReadIdentity{card};
        break;
    case OperationRequest::Method::GetPhoto:
        wire = Wire::GetPhoto{card};
        break;
    case OperationRequest::Method::ReadCertificates:
        wire = Wire::ReadCertificates{card};
        break;
    case OperationRequest::Method::ReadTokenInfo:
        wire = Wire::ReadTokenInfo{card};
        break;
    case OperationRequest::Method::Sign: {
        if (!request.document.valid()) {
            outcome.error.callError = CallError::InvalidArguments;
            outcome.error.message = QStringLiteral("sign requires a document file descriptor");
            return outcome;
        }
        Wire::Sign sign;
        sign.card = card;
        sign.cert = request.certId.toStdString();
        sign.inFd = 0; // index into this frame's SCM_RIGHTS vector
        sign.opts = toSignOpts(request.options);
        passFds.push_back(request.document.get());
        wire = std::move(sign);
        break;
    }
    case OperationRequest::Method::SignBatch: {
        Wire::SignBatch batch;
        batch.card = card;
        batch.cert = request.certId.toStdString();
        batch.opts = toSignOpts(request.options);
        batch.docs.reserve(request.documents.size());
        for (const BatchDocument& doc : request.documents) {
            if (!doc.fd.valid()) {
                outcome.error.callError = CallError::InvalidArguments;
                outcome.error.message = QStringLiteral("signBatch requires every document to carry a file descriptor");
                return outcome;
            }
            Wire::BatchDocument wireDoc;
            wireDoc.name = doc.displayName.toStdString();
            wireDoc.fdIndex = static_cast<std::uint64_t>(passFds.size());
            batch.docs.push_back(std::move(wireDoc));
            passFds.push_back(doc.fd.get());
        }
        wire = std::move(batch);
        break;
    }
    case OperationRequest::Method::ListCredentials:
        wire = Wire::ListCredentials{card};
        break;
    case OperationRequest::Method::ManagePin: {
        Wire::ManagePin manage;
        manage.card = card;
        manage.pinId = request.pinId.toStdString();
        manage.verb = request.verb.toStdString();
        const auto activateKey = request.options.constFind(QStringLiteral("activateKey"));
        if (activateKey != request.options.cend()) {
            manage.activateKey = activateKey->toBool();
        }
        wire = std::move(manage);
        break;
    }
    case OperationRequest::Method::ActivateSigningKey:
        wire = Wire::ActivateSigningKey{card};
        break;
    }

    // Bounded synchronous method entry, exactly like the D-Bus transport's
    // capped Block: the agent mints the operation and replies op-started
    // immediately; the long card work arrives as events. The request (and
    // with it the Sign document fd) stays alive until the send completed.
    SyncResult result = callSync(wire, kDefaultCallTimeoutMs, passFds);
    if (result.failure != CallError::None) {
        outcome.error.callError = result.failure;
        outcome.error.message = QStringLiteral("method entry produced no reply");
        return outcome;
    }
    if (const auto* started = std::get_if<Wire::OpStarted>(&result.reply)) {
        outcome.operationId = QString::number(started->op);
        return outcome;
    }
    if (const auto* err = std::get_if<Wire::ErrInfo>(&result.reply)) {
        // Method refused at entry — the agent's error name/message is the
        // only record of why; never swallow it.
        outcome.error = mapErrInfo(*err);
        qCWarning(lcSocket).noquote() << "method entry refused for" << cardId << ':' << outcome.error.wireName
                                      << outcome.error.message;
        return outcome;
    }
    outcome.error.callError = CallError::ProtocolError;
    outcome.error.message = QStringLiteral("method entry returned an unexpected reply arm");
    return outcome;
}

void SocketTransport::subscribeOperation(const QString& operationId, OperationKind kind, OperationListener* listener)
{
    bool ok = false;
    const quint64 op = operationId.toULongLong(&ok);
    if (!ok) {
        return;
    }
    m_operationWatches.insert(listener, OperationWatch{op, kind, listener});
}

void SocketTransport::unsubscribeOperation(const QString& operationId, OperationListener* listener)
{
    Q_UNUSED(operationId)
    m_operationWatches.remove(listener);
}

std::optional<TerminalSnapshot> SocketTransport::fetchOperationState(const QString& operationId)
{
    Q_UNUSED(operationId)
    // The wire has no operation-state read, and none is needed: every frame
    // of an operation is written to the connection that issued it, in order
    // (the unicast-FIFO delivery invariant), and this transport queues frames
    // arriving mid-call for the next event-loop turn — a subscriber installed
    // synchronously after op-started therefore cannot miss its terminal. The
    // live events drive the operation.
    return std::nullopt;
}

std::optional<OperationPayload> SocketTransport::fetchOperationResult(const QString& operationId, OperationKind kind)
{
    if (kind != OperationKind::Sign) {
        // Pull-based recovery is Sign-only on this wire (get-sign-result);
        // the FIFO delivery invariant replaces it for every other kind.
        return std::nullopt;
    }
    bool ok = false;
    const quint64 op = operationId.toULongLong(&ok);
    if (!ok) {
        return std::nullopt;
    }
    SyncResult result = callSync(Wire::GetSignResult{op}, kDefaultCallTimeoutMs);
    if (result.failure != CallError::None) {
        return std::nullopt;
    }
    auto* recovered = std::get_if<Wire::SignResult>(&result.reply);
    if (recovered == nullptr) {
        return std::nullopt; // err-info (nothing retained / window elapsed), or an unexpected arm
    }
    OperationPayload payload = toPayload(Wire::OpResult{std::move(*recovered)}, result.fds);
    if (!payload.signedArtifact.valid()) {
        return std::nullopt;
    }
    return payload;
}

void SocketTransport::cancelOperation(const QString& operationId)
{
    bool ok = false;
    const quint64 op = operationId.toULongLong(&ok);
    if (!ok || !isConnected()) {
        return;
    }
    // Fire-and-forget: the ack lands as an unmatched reply and is dropped.
    const quint64 requestId = ++m_nextRequestId;
    const std::vector<std::uint8_t> body = Wire::encodeRequest(Wire::CancelOp{op}, requestId);
    if (!Wire::sendFrame(m_fd.get(), body, {})) {
        dropConnection();
    }
}

void SocketTransport::warmCertificates(const QString& cardId)
{
    Q_UNUSED(cardId)
    // DELIBERATE NO-OP on this wire, not an unfinished implementation. The
    // seam permits it (see TransportSeam::warmCertificates) and the parity
    // suite pins it, so a future reader can tell this apart from an oversight.
    //
    // Sending the frame would be trivial -- cancelOperation() a few lines
    // above already fire-and-forgets a request and drops its ack -- and that
    // is exactly what makes the omission worth spelling out, because the easy
    // version is the wrong one:
    //
    //   * A read-certificates entry makes the agent MINT a server-side
    //     operation, and its id comes back only in the reply a warm throws
    //     away. On the D-Bus wire that costs nothing: the agent reaps the
    //     operation together with the card object that owns it. This wire has
    //     no such ownership edge and, more to the point, no release verb at
    //     all: the only request that names an existing operation without
    //     consuming its result is the cancel, which would ABORT the very read
    //     the warm exists to perform. So there is no way to issue a warm here
    //     and then let go of it -- "fire and forget" would strand a live
    //     operation on the agent for every warm, and a warm is meant to be
    //     cheap enough to call on every plausible trigger.
    //
    //   * Nothing loses a feature by this. The warm is best-effort by
    //     contract: skipping it costs one cold read on the next real
    //     readCertificates(), which is precisely the cost a caller would have
    //     paid without any warm at all. No consumer's correctness depends on
    //     it, and the public API says so.
    //
    // What would have to change before this becomes real: the wire needs a way
    // to hand an operation back without cancelling it -- either a release/
    // detach request, or a warm-shaped request the agent answers without
    // minting an operation at all. Add that first; do not just start sending
    // the entry frame.
}

// ---- public-data primitive -----------------------------------------------------------

quint64 SocketTransport::requestCertificateDer(const QString& readerId, const QString& certId, DerListener* listener)
{
    const quint64 token = m_derListeners.add(listener);
    const auto queueFailure = [this, token](CallError error) {
        QMetaObject::invokeMethod(
            this,
            [this, token, error]() {
                DerListener* target = m_derListeners.takeIfPresent(token);
                if (target == nullptr) {
                    return; // cancelled — the operation is gone
                }
                DerOutcome outcome;
                outcome.error.callError = error;
                outcome.error.message = QStringLiteral("the agent socket is not connected");
                target->onCertificateDer(token, std::move(outcome));
            },
            Qt::QueuedConnection);
    };
    if (!isConnected()) {
        queueFailure(CallError::AgentUnavailable);
        return token;
    }
    Wire::GetCertDer request;
    request.reader = readerId.toStdString();
    request.cert = certId.toStdString();
    const quint64 requestId = ++m_nextRequestId;
    const std::vector<std::uint8_t> body = Wire::encodeRequest(request, requestId);
    if (!Wire::sendFrame(m_fd.get(), body, {})) {
        dropConnection();
        queueFailure(CallError::AgentUnavailable);
        return token;
    }
    auto* timer = new QTimer(this);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [this, requestId]() {
        const auto it = m_pendingDer.constFind(requestId);
        if (it == m_pendingDer.cend()) {
            return;
        }
        const PendingDer pending = it.value();
        m_pendingDer.erase(it);
        pending.timer->deleteLater();
        DerListener* target = m_derListeners.takeIfPresent(pending.token);
        if (target == nullptr) {
            return;
        }
        DerOutcome outcome;
        outcome.error.callError = CallError::Timeout;
        outcome.error.message = QStringLiteral("no GetCertDer reply within the call budget");
        target->onCertificateDer(pending.token, std::move(outcome));
    });
    timer->start(kDefaultCallTimeoutMs);
    m_pendingDer.insert(requestId, PendingDer{token, timer});
    return token;
}

void SocketTransport::cancelCertificateDer(quint64 token, DerListener* listener)
{
    Q_UNUSED(listener) // keyed strictly by token; kept for interface symmetry
    m_derListeners.cancel(token);
    // Any pending wire request stays registered; its reply/timeout resolves
    // to a cancelled token and is dropped by takeIfPresent.
}

// ---- connection lifecycle ---------------------------------------------------------------

bool SocketTransport::connectAndHandshake()
{
    if (m_socketPath.isEmpty()) {
        return false;
    }
    const QByteArray encoded = QFile::encodeName(m_socketPath);
    sockaddr_un address{};
    if (static_cast<std::size_t>(encoded.size()) + 1 > sizeof(address.sun_path)) {
        qCWarning(lcSocket) << "agent socket path too long for sockaddr_un:" << m_socketPath;
        return false;
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, encoded.constData(), static_cast<std::size_t>(encoded.size()));

    Wire::UniqueFd fd(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (!fd.valid()) {
        return false;
    }
    // FD_CLOEXEC via fcntl: SOCK_CLOEXEC is not portable to every supported
    // host (and the contract requires the flag either way).
    ::fcntl(fd.get(), F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    // No MSG_NOSIGNAL on this platform (Darwin): suppress SIGPIPE at the
    // socket instead, so a write against a just-died agent fails the call
    // with EPIPE -> FrameError::Io -> CallError::AgentUnavailable rather
    // than killing the process (Wire::sendFrame's other half of the same
    // contract).
    const int noSigPipe = 1;
    ::setsockopt(fd.get(), SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));
#endif
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        return false; // refused / absent — the agent is not reachable
    }
    const int flags = ::fcntl(fd.get(), F_GETFL, 0);
    ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK);

    m_fd = std::move(fd);
    m_reassembler = std::make_unique<Wire::FrameReassembler>();
    m_notifier = std::make_unique<QSocketNotifier>(m_fd.get(), QSocketNotifier::Read);
    connect(m_notifier.get(), &QSocketNotifier::activated, this, [this]() { onReadable(); });

    // Hello/HelloAck, bounded by the handshake budget. m_established stays
    // false until the ack landed, so a failure here never announces an
    // unregistration for a connection nobody ever saw as available.
    Wire::Hello hello;
    hello.proto = Wire::kProtocolVersion;
    hello.client = "librescrs-agentclient-qt";
    SyncResult result = callSync(hello, kHandshakeTimeoutMs);
    if (result.failure != CallError::None || !std::holds_alternative<Wire::HelloAck>(result.reply)) {
        qCWarning(lcSocket) << "agent handshake failed on" << m_socketPath;
        m_notifier.reset();
        m_fd.reset();
        m_reassembler.reset();
        return false;
    }
    const auto& ack = std::get<Wire::HelloAck>(result.reply);
    m_agentVersion = fromStd(ack.agentVer);
    m_features.clear();
    for (const std::string& feature : ack.features) {
        m_features.append(fromStd(feature));
    }
    // Forget any previously cached appearance-font fd — a fresh
    // connection may be a different-generation agent serving a different
    // font, and appearanceFont() re-fetches lazily on next use. Same for the
    // settings snapshot: a different-generation agent may be configured
    // differently, and configSnapshot() likewise re-fetches lazily.
    m_appearanceFontFetched = false;
    m_appearanceFont = FdHandle{};
    m_configFetched = false;
    m_config.clear();
    m_established = true;
    m_quiesced = false;
    // A new connection generation: any ConnectionLost notice still queued
    // for an OLDER connection must not be announced against this one.
    ++m_generation;
    return true;
}

void SocketTransport::dropConnection()
{
    if (!m_fd.valid()) {
        return;
    }
    // The drop may run from inside the notifier's own activated handler
    // (onReadable), and Qt forbids deleting a signal's sender mid-emission:
    // disable it now, delete it on the next event-loop turn.
    if (m_notifier != nullptr) {
        m_notifier->setEnabled(false);
        m_notifier.release()->deleteLater();
    }
    m_fd.reset();
    m_reassembler.reset();
    const bool wasEstablished = m_established;
    m_established = false;
    m_quiesced = false;
    // The HelloAck's version described THAT connection's peer. Forget it here
    // rather than only overwriting it at the next handshake: between the drop
    // and a reconnect there is no agent, and TransportSeam::agentVersion()'s
    // contract is empty-while-unreachable — a consumer rendering "connected
    // to 4.3.0" for a process that died is exactly the lie the contract
    // exists to prevent. Unconditional, before the wasEstablished gate: a
    // mid-handshake drop must not leave a half-seeded value behind either.
    m_agentVersion.clear();
    // The feature tokens are the SAME HelloAck capture with the same
    // lifetime, and were the half that had been getting it wrong: they were
    // cleared only on the next handshake, so between an agent's death and a
    // reconnect features() still listed the dead agent's tokens —
    // contradicting the seam's own "cached until the agent is lost" and
    // diverging from D-Bus, which clears them on the name's unregistration.
    // Consequential, not cosmetic: a client gates its optional surfaces on
    // features(), so a stale set offers capabilities nothing is behind.
    m_features.clear();
    // Ditto the settings snapshot — it described THAT agent's configuration.
    m_configFetched = false;
    m_config.clear();
    if (!wasEstablished) {
        return; // mid-handshake failure: nothing was ever announced
    }
    DeferredItem item;
    item.kind = DeferredItem::Kind::ConnectionLost;
    // Stamp the dead connection's generation and detach ITS in-flight async
    // requests now: a reconnect before the drain starts a fresh pending set,
    // and the stale notice must neither touch that set nor be announced
    // against the fresh connection (deliverConnectionLost's guard).
    item.generation = m_generation;
    item.lostProps.swap(m_pendingProps);
    item.lostDer.swap(m_pendingDer);
    m_deferred.push_back(std::move(item));
    // ALWAYS queued, even at sync depth 0: a failing send inside
    // callSync/cancelOperation/requestProperties/requestCertificateDer runs
    // on the consumer's own call stack, and an inline onServiceUnregistered
    // there would let the consumer tear down the registry underneath the
    // very object making the call (use-after-free). Queued delivery is
    // correct from the event-pump context too.
    scheduleDrain();
}

void SocketTransport::deliverConnectionLost(DeferredItem& item)
{
    // Answer the dead connection's in-flight asynchronous requests with
    // their failure outcomes (same liveness rules as a real reply). This
    // half is unconditional: no connection can ever answer them.
    for (const PendingProps& pending : std::as_const(item.lostProps)) {
        if (pending.timer != nullptr) {
            pending.timer->deleteLater();
        }
        const auto watchIt = m_propertyWatches.constFind(pending.listener);
        if (watchIt == m_propertyWatches.cend() || watchIt->objectId != pending.objectId) {
            continue;
        }
        pending.listener->onPropertiesFetched(pending.token, std::nullopt);
    }
    for (const PendingDer& pending : std::as_const(item.lostDer)) {
        if (pending.timer != nullptr) {
            pending.timer->deleteLater();
        }
        DerListener* target = m_derListeners.takeIfPresent(pending.token);
        if (target == nullptr) {
            continue;
        }
        DerOutcome outcome;
        outcome.error.callError = CallError::AgentUnavailable;
        outcome.error.message = QStringLiteral("the agent connection was lost");
        target->onCertificateDer(pending.token, std::move(outcome));
    }
    // The availability push is generation-guarded: a consumer that
    // reconnected before this notice drained (probe -> fresh handshake in
    // the same stack) has a LIVE registry — announcing the stale death
    // would clear it.
    if (item.generation != m_generation) {
        return;
    }
    if (m_registry != nullptr) {
        m_registry->onServiceUnregistered();
    }
}

// ---- frame pump ---------------------------------------------------------------------------

void SocketTransport::onReadable()
{
    if (!m_fd.valid() || m_syncDepth > 0) {
        return; // a synchronous wait owns the socket (its poll loop pumps)
    }
    Wire::PumpResult pumped = m_reassembler->pump(m_fd.get());
    bool protocolFailure = false;
    for (Wire::Frame& frame : pumped.frames) {
        if (!absorbFrame(std::move(frame), 0, nullptr)) {
            protocolFailure = true;
            break;
        }
    }
    if (protocolFailure) {
        qCWarning(lcSocket) << "malformed/non-canonical frame from the agent; failing the connection closed";
        dropConnection();
    } else if (pumped.status != Wire::PumpStatus::Ok) {
        dropConnection();
    }
    drainDeferred();
}

bool SocketTransport::absorbFrame(Wire::Frame&& frame, quint64 awaitedId, SyncResult* awaited)
{
    const std::vector<int> frameFds = rawFds(frame.fds);
    // Replies and events are distinguished by shape: every reply carries
    // t:"Reply", every event its own tag — a body that is neither is
    // malformed (or non-canonical) and fails the connection closed.
    if (auto reply = Wire::parseReply(frame.body, frameFds)) {
        if (awaited != nullptr && reply->requestId == awaitedId) {
            awaited->failure = CallError::None;
            awaited->reply = std::move(reply->reply);
            awaited->fds = std::move(frame.fds);
            return true;
        }
        DeferredItem item;
        item.kind = DeferredItem::Kind::Reply;
        item.reply = std::move(*reply);
        item.fds = std::move(frame.fds);
        m_deferred.push_back(std::move(item));
        scheduleDrain();
        return true;
    }
    if (auto event = Wire::parseEvent(frame.body, frameFds)) {
        DeferredItem item;
        item.kind = DeferredItem::Kind::Event;
        item.event = std::move(*event);
        item.fds = std::move(frame.fds);
        m_deferred.push_back(std::move(item));
        scheduleDrain();
        return true;
    }
    return false;
}

void SocketTransport::scheduleDrain()
{
    if (m_drainQueued) {
        return;
    }
    m_drainQueued = true;
    QMetaObject::invokeMethod(this, &SocketTransport::drainDeferred, Qt::QueuedConnection);
}

void SocketTransport::drainDeferred()
{
    m_drainQueued = false;
    if (m_draining || m_syncDepth > 0) {
        // Mid-wait (the wait's epilogue reschedules) or re-entered from a
        // consumer's own nested processEvents — the outer drain finishes.
        return;
    }
    m_draining = true;
    while (!m_deferred.empty()) {
        DeferredItem item = std::move(m_deferred.front());
        m_deferred.pop_front();
        switch (item.kind) {
        case DeferredItem::Kind::Event:
            dispatchEvent(std::move(item.event), item.fds);
            break;
        case DeferredItem::Kind::Reply:
            dispatchAsyncReply(std::move(item.reply));
            break;
        case DeferredItem::Kind::ConnectionLost:
            deliverConnectionLost(item);
            break;
        }
        // A dispatched callback may have re-entered a seam call and deferred
        // more items; the loop drains those too, in arrival order.
    }
    m_draining = false;
}

void SocketTransport::dispatchEvent(Wire::DecodedEvent&& decoded, std::vector<Wire::UniqueFd>& fds)
{
    Wire::EventVariant& event = decoded.event;

    if (const auto* readerAdded = std::get_if<Wire::ReaderAdded>(&event)) {
        if (m_registry != nullptr) {
            m_registry->onReaderAdded(fromStd(readerAdded->reader.handle), readerProps(readerAdded->reader));
        }
        return;
    }
    if (const auto* readerRemoved = std::get_if<Wire::ReaderRemoved>(&event)) {
        if (m_registry != nullptr) {
            m_registry->onReaderRemoved(fromStd(readerRemoved->handle));
        }
        return;
    }
    if (const auto* cardAdded = std::get_if<Wire::CardAdded>(&event)) {
        if (m_registry != nullptr) {
            m_registry->onCardAdded(fromStd(cardAdded->card.handle), cardProps(cardAdded->card));
        }
        return;
    }
    if (const auto* cardRemoved = std::get_if<Wire::CardRemoved>(&event)) {
        if (m_registry != nullptr) {
            m_registry->onCardRemoved(fromStd(cardRemoved->handle));
        }
        return;
    }
    if (const auto* propertyChanged = std::get_if<Wire::PropertyChanged>(&event)) {
        const QString objectId = fromStd(propertyChanged->handle);
        std::optional<ObjectKind> kind;
        if (propertyChanged->iface == kReaderIface) {
            kind = ObjectKind::Reader;
        } else if (propertyChanged->iface == kCardIface) {
            kind = ObjectKind::Card;
        }
        if (!kind) {
            return; // an interface this client does not track
        }
        QVariantMap changed;
        for (const auto& [key, value] : propertyChanged->props) {
            changed.insert(fromStd(key), cborToVariant(value));
        }
        // Snapshot the matching listeners first: a callback may unsubscribe
        // (mutating the hash mid-iteration); re-check membership per call.
        QList<PropertyListener*> targets;
        for (auto it = m_propertyWatches.cbegin(); it != m_propertyWatches.cend(); ++it) {
            if (it.value().objectId == objectId && it.value().kind == *kind) {
                targets.append(it.key());
            }
        }
        for (PropertyListener* listener : targets) {
            const auto it = m_propertyWatches.constFind(listener);
            if (it == m_propertyWatches.cend() || it->objectId != objectId) {
                continue;
            }
            // The socket wire always ships full values — never an
            // invalidation, so the invalidated list is empty by construction.
            listener->onPropertiesChanged(changed, {});
        }
        return;
    }
    if (const auto* progress = std::get_if<Wire::OpProgress>(&event)) {
        if (OperationListener* listener = operationListenerFor(progress->op)) {
            listener->onPhaseChanged(progress->phase, progress->progress.value_or(0.0));
        }
        return;
    }
    if (const auto* group = std::get_if<Wire::OpIdentityGroup>(&event)) {
        // Progressive delivery, strictly ahead of the SAME op's eventual
        // OpResultReady below -- the client does not gate this on the
        // "identity-stream" feature token (unlike a request-side gate): an
        // agent that does not advertise it simply never writes this frame,
        // so there is nothing here to refuse.
        if (OperationListener* listener = operationListenerFor(group->op)) {
            listener->onGroupReady(toFieldGroup(fromStd(group->groupKey), group->fields));
        }
        return;
    }
    if (auto* resultReady = std::get_if<Wire::OpResultReady>(&event)) {
        if (OperationListener* listener = operationListenerFor(resultReady->op)) {
            listener->onResult(toPayload(std::move(resultReady->result), fds));
        }
        return;
    }
    if (const auto* finished = std::get_if<Wire::OpFinished>(&event)) {
        if (OperationListener* listener = operationListenerFor(finished->op)) {
            listener->onFinished(finished->status, finished->code, fromStd(finished->msgKey),
                                 fromStd(finished->msgFallback));
        }
        return;
    }
    if (const auto* configChanged = std::get_if<Wire::ConfigChanged>(&event)) {
        // The event carries ONLY the key, so the freshness debt is the
        // transport's: re-read, THEN announce, so a consumer reading
        // configSnapshot() from its slot sees the new value. This wire has no
        // per-key read, so the refresh is the whole set — one bounded
        // round-trip, and only when a snapshot was already cached (nothing to
        // keep fresh otherwise; the first read will fetch everything).
        //
        // The nested callSync is safe here despite running inside an event
        // dispatch: it polls the socket on a deadline rather than spinning an
        // event loop, so nothing foreign re-enters a consumer, and a drop
        // discovered mid-call defers its notice exactly as dropConnection
        // guarantees.
        if (m_configFetched) {
            refreshConfig();
        }
        if (m_registry != nullptr) {
            m_registry->onConfigChanged(fromStd(configChanged->key));
        }
        return;
    }
    if (const auto* quiesced = std::get_if<Wire::AgentQuiesced>(&event)) {
        // Availability semantics: card access is quiesced (sleep / lock /
        // user switch), so the agent counts as unavailable — in-flight
        // operations are terminalized by the consumer exactly like an agent
        // death — while the connection itself stays open for the re-probe.
        Q_UNUSED(quiesced)
        m_quiesced = true;
        if (m_registry != nullptr) {
            m_registry->onServiceUnregistered();
        }
        return;
    }
    // UnknownEvent (the forward-compatibility escape): tolerated, ignored.
}

void SocketTransport::dispatchAsyncReply(Wire::DecodedReply&& reply)
{
    const quint64 requestId = reply.requestId;
    if (const auto propsIt = m_pendingProps.constFind(requestId); propsIt != m_pendingProps.cend()) {
        const PendingProps pending = propsIt.value();
        m_pendingProps.erase(propsIt);
        if (pending.timer != nullptr) {
            pending.timer->deleteLater();
        }
        const auto watchIt = m_propertyWatches.constFind(pending.listener);
        if (watchIt == m_propertyWatches.cend() || watchIt->objectId != pending.objectId) {
            return; // dead/rebound subscription — a stale reply is dropped
        }
        std::optional<QVariantMap> props;
        if (const auto* state = std::get_if<Wire::StateReply>(&reply.reply)) {
            const std::string wanted = pending.objectId.toStdString();
            if (pending.kind == ObjectKind::Reader) {
                for (const Wire::ReaderState& reader : state->readers) {
                    if (reader.handle == wanted) {
                        props = readerProps(reader);
                        break;
                    }
                }
            } else {
                for (const Wire::CardState& card : state->cards) {
                    if (card.handle == wanted) {
                        props = cardProps(card);
                        break;
                    }
                }
            }
        }
        pending.listener->onPropertiesFetched(pending.token, props);
        return;
    }
    if (const auto derIt = m_pendingDer.constFind(requestId); derIt != m_pendingDer.cend()) {
        const PendingDer pending = derIt.value();
        m_pendingDer.erase(derIt);
        if (pending.timer != nullptr) {
            pending.timer->deleteLater();
        }
        DerListener* target = m_derListeners.takeIfPresent(pending.token);
        if (target == nullptr) {
            return; // cancelled — the operation is gone
        }
        DerOutcome outcome;
        if (const auto* der = std::get_if<Wire::CertDerReply>(&reply.reply)) {
            outcome.der = toByteArray(der->der);
        } else if (const auto* err = std::get_if<Wire::ErrInfo>(&reply.reply)) {
            outcome.error = mapErrInfo(*err);
        } else {
            outcome.error.callError = CallError::ProtocolError;
            outcome.error.message = QStringLiteral("unexpected reply arm for GetCertDer");
        }
        target->onCertificateDer(pending.token, std::move(outcome));
        return;
    }
    // Unmatched: a late reply to a timed-out request, or the ack of a
    // fire-and-forget CancelOp — dropped by design.
}

OperationListener* SocketTransport::operationListenerFor(quint64 op, OperationKind* kindOut) const
{
    for (auto it = m_operationWatches.cbegin(); it != m_operationWatches.cend(); ++it) {
        if (it.value().op == op) {
            if (kindOut != nullptr) {
                *kindOut = it.value().kind;
            }
            return it.value().listener;
        }
    }
    return nullptr;
}

// ---- bounded synchronous exchange ----------------------------------------------------------

SocketTransport::SyncResult SocketTransport::callSync(const Wire::RequestVariant& request, int timeoutMs,
                                                      std::span<const int> passFds)
{
    SyncResult out;
    if (!m_fd.valid()) {
        out.failure = CallError::AgentUnavailable;
        return out;
    }
    const quint64 requestId = ++m_nextRequestId;
    const std::vector<std::uint8_t> body = Wire::encodeRequest(request, requestId);
    if (!Wire::sendFrame(m_fd.get(), body, passFds)) {
        dropConnection();
        out.failure = CallError::AgentUnavailable;
        return out;
    }

    // Deadline poll on the socket alone — deliberately NOT a nested event
    // loop (see the header's dispatch discipline): nothing foreign can
    // re-enter a consumer mid-call, and everything that arrives besides the
    // awaited reply is queued for the next event-loop turn.
    out.failure = CallError::Timeout;
    QDeadlineTimer deadline(timeoutMs);
    ++m_syncDepth;
    while (true) {
        const qint64 remaining = deadline.remainingTime();
        if (remaining <= 0) {
            break; // Timeout stands
        }
        pollfd pfd{};
        pfd.fd = m_fd.get();
        pfd.events = POLLIN;
        const int pollMs = static_cast<int>(std::min<qint64>(remaining, std::numeric_limits<int>::max()));
        const int rc = ::poll(&pfd, 1, pollMs);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            dropConnection();
            out.failure = CallError::TransportFailure;
            break;
        }
        if (rc == 0) {
            continue; // the deadline check above terminates the loop
        }
        Wire::PumpResult pumped = m_reassembler->pump(m_fd.get());
        bool protocolFailure = false;
        for (Wire::Frame& frame : pumped.frames) {
            const bool stillAwaiting = out.failure != CallError::None;
            if (!absorbFrame(std::move(frame), stillAwaiting ? requestId : 0, stillAwaiting ? &out : nullptr)) {
                protocolFailure = true;
                break;
            }
        }
        if (protocolFailure) {
            qCWarning(lcSocket) << "malformed/non-canonical frame from the agent; failing the connection closed";
            dropConnection();
            // Like the PeerClosed/Error branches below: a malformed TRAILING
            // frame in the same batch as the awaited reply still costs the
            // connection, but must not clobber the success already received.
            if (out.failure != CallError::None) {
                out.failure = CallError::ProtocolError;
            }
            break;
        }
        if (pumped.status == Wire::PumpStatus::PeerClosed) {
            dropConnection();
            if (out.failure != CallError::None) {
                out.failure = CallError::AgentUnavailable;
            }
            break;
        }
        if (pumped.status == Wire::PumpStatus::Error) {
            dropConnection();
            if (out.failure != CallError::None) {
                out.failure =
                    pumped.error == Wire::FrameError::Io ? CallError::TransportFailure : CallError::ProtocolError;
            }
            break;
        }
        if (out.failure == CallError::None) {
            break; // the awaited reply arrived
        }
    }
    --m_syncDepth;
    if (!m_deferred.empty()) {
        scheduleDrain(); // everything displaced by this wait lands on the next loop turn
    }
    return out;
}

} // namespace LibreSCRS::AgentClient
