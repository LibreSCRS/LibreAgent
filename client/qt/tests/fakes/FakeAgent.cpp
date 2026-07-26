// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "FakeAgent.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusUnixFileDescriptor>
#include <QTimer>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace LibreSCRS::AgentClient::Fakes {

namespace {
constexpr const char* kOperationIface = "org.librescrs.Agent.Operation1";
constexpr const char* kSignIface = "org.librescrs.Agent.Operation.Sign1";
constexpr const char* kSignBatchIface = "org.librescrs.Agent.Operation.SignBatch1";
constexpr const char* kIdentityIface = "org.librescrs.Agent.Operation.Identity1";
constexpr const char* kCertificatesIface = "org.librescrs.Agent.Operation.Certificates1";
constexpr const char* kPhotoIface = "org.librescrs.Agent.Operation.Photo1";

void ensureMetatypes()
{
    static bool done = false;
    if (done) {
        return;
    }
    // Every wire-shape mirror (Identity/Cert/Photo/CredentialRecords/
    // AgentInterfaceProps) the client itself registers — the fake speaks the
    // SAME registered types, so its hand-built signals demarshal exactly like
    // a real agent's.
    LibreSCRS::AgentClient::ensureDBusMetatypes();
    qDBusRegisterMetaType<FakeInterfaceProps>();
    qDBusRegisterMetaType<FakeManagedObjects>();
    done = true;
}

// Build a sealed memfd with the given content; returns an owned fd.
int makeSealedArtifact(const QByteArray& content)
{
    int fd = memfd_create("fake-artifact", MFD_ALLOW_SEALING);
    if (fd < 0) {
        return -1;
    }
    if (!content.isEmpty()) {
        ssize_t w = ::write(fd, content.constData(), static_cast<size_t>(content.size()));
        (void)w;
    }
    ::lseek(fd, 0, SEEK_SET);
    return fd;
}
} // namespace

// --- Operation1 adaptor ----------------------------------------------------
class FakeOperationAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation1")
    Q_PROPERTY(uint Phase READ phase)
    Q_PROPERTY(double Progress READ progress)
    Q_PROPERTY(bool IsIndeterminate READ isIndeterminate)
    Q_PROPERTY(uint WatchdogTimeoutSeconds READ watchdogTimeoutSeconds)
    Q_PROPERTY(bool Completed READ completed)
    Q_PROPERTY(uint Status READ status)
    Q_PROPERTY(uint ErrorCode READ errorCode)
public:
    explicit FakeOperationAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

    [[nodiscard]] uint phase() const
    {
        return m_op->m_completed ? 7u : 4u;
    }
    [[nodiscard]] double progress() const
    {
        return m_op->m_completed ? 1.0 : 0.0;
    }
    [[nodiscard]] bool isIndeterminate() const
    {
        return true;
    }
    [[nodiscard]] uint watchdogTimeoutSeconds() const
    {
        return 30u;
    }
    [[nodiscard]] bool completed() const
    {
        return m_op->m_completed;
    }
    [[nodiscard]] uint status() const
    {
        return m_op->m_finalStatus;
    }
    [[nodiscard]] uint errorCode() const
    {
        return m_op->m_finalErrorCode;
    }

public Q_SLOTS:
    void Cancel()
    {
        // Record the cancel on the minting agent — the observable seam for
        // "an abandoned op was cancelled agent-side" (ops are parented to it).
        if (auto* agent = qobject_cast<FakeAgent*>(m_op->parent())) {
            agent->noteOperationCancelled();
        }
        m_op->m_finalStatus = 1u; // Cancelled
        m_op->fire();
    }

Q_SIGNALS:
    void Finished(uint status, uint errorCode, const QString& msgKey, const QString& msgFallback);

private:
    FakeOperation* m_op;
};

// --- Sign1 adaptor ---------------------------------------------------------
class FakeSignAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.Sign1")
public:
    explicit FakeSignAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->(h signedArtifact, a{sv} meta). The first out-arg is the
    // function return value (the fd), the second a trailing reference param —
    // matching the XML's (signedArtifact, meta) ordering.
    QDBusUnixFileDescriptor GetResult(QVariantMap& meta)
    {
        if (!m_op->m_completed || m_op->m_finalStatus != 0u || m_op->m_keptArtifactFd < 0) {
            // Frozen Sign1 contract: NoResult is a D-Bus error, not a null fd —
            // returning an invalid `h` would be unmarshalable and hang the peer.
            m_op->replyNoResult();
            meta = QVariantMap{};
            return QDBusUnixFileDescriptor();
        }
        meta = m_op->effectiveSignMeta();
        return QDBusUnixFileDescriptor(m_op->m_keptArtifactFd);
    }

Q_SIGNALS:
    void Result(const QDBusUnixFileDescriptor& signedArtifact, const QVariantMap& meta);

private:
    FakeOperation* m_op;
};

// --- SignBatch1 adaptor -----------------------------------------------------
class FakeSignBatchAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.SignBatch1")
public:
    explicit FakeSignBatchAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->a(sha{sv}u): re-serve the retained rows (the late-
    // subscriber recovery pull), re-sealing every row fresh from the kept
    // fds. NoResult is a D-Bus error, mirroring the frozen contract +
    // FakeSignAdaptor.
    LibreSCRS::AgentClient::SignBatchRowsWire GetResult()
    {
        if (!m_op->m_resultRetained) {
            m_op->replyNoResult();
            return {};
        }
        return m_op->buildBatchRows();
    }

Q_SIGNALS:
    void Result(const LibreSCRS::AgentClient::SignBatchRowsWire& rows);

private:
    FakeOperation* m_op;
};

// --- Identity1 adaptor -----------------------------------------------------
class FakeIdentityAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.Identity1")
public:
    explicit FakeIdentityAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->a{sa{s(sssv)}}: re-serve the retained identity field map (the
    // late-subscriber recovery pull). NoResult is a D-Bus error, not an empty
    // map, mirroring the frozen contract + FakeSignAdaptor.
    LibreSCRS::AgentClient::IdentityFieldsWire GetResult()
    {
        if (!m_op->m_resultRetained) {
            m_op->replyNoResult();
            return {};
        }
        return m_op->buildIdentityFields();
    }

Q_SIGNALS:
    void Result(const LibreSCRS::AgentClient::IdentityFieldsWire& fields);
    // Progressive per-group delivery, strictly ahead of Result above.
    void Group(const QString& groupKey, const LibreSCRS::AgentClient::IdentityFieldGroupWire& fields);

private:
    FakeOperation* m_op;
};

// --- Photo1 adaptor --------------------------------------------------------
// Emits the real wire shape a{sh} (group:field -> sealed memfd) so the client's
// PhotoMapWire demarshaller (the production code under test) parses it exactly
// as it would a real agent's sealed-memfd payload.
class FakePhotoAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.Photo1")
public:
    explicit FakePhotoAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->a{sh}: re-serve the retained photo(s) as FRESH sealed-memfd
    // dups (the agent retains raw bytes it re-seals per call). NoResult is a
    // D-Bus error, mirroring the frozen contract + FakeSignAdaptor.
    LibreSCRS::AgentClient::PhotoMapWire GetResult()
    {
        if (!m_op->m_resultRetained) {
            m_op->replyNoResult();
            return {};
        }
        m_op->retainPhotoFd(); // idempotent — ensure the sealed source fd exists
        LibreSCRS::AgentClient::PhotoMapWire photos;
        if (m_op->m_keptPhotoFd >= 0) {
            const int dup = ::dup(m_op->m_keptPhotoFd);
            photos.insert(QStringLiteral("personal:photo"), QDBusUnixFileDescriptor(dup));
            if (dup >= 0) {
                ::close(dup);
            }
        }
        return photos;
    }

Q_SIGNALS:
    void Result(const LibreSCRS::AgentClient::PhotoMapWire& photos);

private:
    FakeOperation* m_op;
};

// --- Certificates1 adaptor -------------------------------------------------
// Emits the real wire struct a(sba{sa{s(ssv)}}uasasu); the marshaller below
// builds it from the scripted FakeCertList so the client's CertInfoWire
// demarshaller (the production code under test) parses it exactly as it would
// a real agent's payload — subject/cn drives the chooser label.
class FakeCertificatesAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.Certificates1")
public:
    explicit FakeCertificatesAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->a(sba{sa{s(ssv)}}uasasu): re-serve the retained certificate
    // list (the late-subscriber recovery pull). NoResult is a D-Bus error,
    // mirroring the frozen contract + FakeSignAdaptor.
    LibreSCRS::AgentClient::CertListWire GetResult()
    {
        if (!m_op->m_resultRetained) {
            m_op->replyNoResult();
            return {};
        }
        return m_op->buildCertificateList();
    }

Q_SIGNALS:
    void Result(const LibreSCRS::AgentClient::CertListWire& certificates);

private:
    FakeOperation* m_op;
};

// --- Operation.Credentials1 adaptor ----------------------------------------
// Emits the real wire shape (a{sv} result, aa{sv} records) so the client's
// two-arg onCredentialsResult slot + fetchOperationResult's Credentials pull
// (the production code under test) parse it exactly as they would a real
// agent's payload. Unlike the Ok-only Sign/Identity/Certificates/Photo
// results, the credentials Result fires for EVERY completed attempt (Ok AND
// the soft-fail invalidPin/blocked outcomes that finish Error).
class FakeCredentialsAdaptor : public QDBusAbstractAdaptor
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.librescrs.Agent.Operation.Credentials1")
public:
    explicit FakeCredentialsAdaptor(FakeOperation* op) : QDBusAbstractAdaptor(op), m_op(op) {}

public Q_SLOTS:
    // GetResult()->(a{sv} result, aa{sv} records): re-serve the retained payload
    // (the late-subscriber recovery pull). The first out-arg is the function
    // return value (result), the second a trailing reference param (records) —
    // matching the XML's (result, records) ordering + FakeSignAdaptor. NoResult
    // is a D-Bus error, not an empty map, mirroring the frozen contract.
    QVariantMap GetResult(LibreSCRS::AgentClient::CredentialRecordsWire& records)
    {
        if (!m_op->m_resultRetained) {
            m_op->replyNoResult();
            records = {};
            return {};
        }
        records = m_op->m_credRecords;
        return m_op->m_credResult;
    }

Q_SIGNALS:
    void Result(const QVariantMap& result, const LibreSCRS::AgentClient::CredentialRecordsWire& records);

private:
    FakeOperation* m_op;
};

// --- FakeOperation ---------------------------------------------------------
FakeOperation::FakeOperation(QObject* parent, QDBusConnection connection, QString path, Kind kind, int delayMs,
                             uint finalStatus, uint finalErrorCode, bool suppressResult, FakeCertList certScript,
                             bool rawCertResult, QByteArray photoBytes, bool photoEmptyMap, bool announceConsentPhase,
                             bool lostSignalRecoverable, QVariantMap credResult,
                             LibreSCRS::AgentClient::CredentialRecordsWire credRecords, QByteArray signArtifactBytes,
                             QVariantMap signMeta, bool tokenInfoEmpty, QList<FakeIdentityGroup> identityGroupScript,
                             QStringList batchDisplayNames, int batchHaltAtIndex, uint batchHaltErrorCode)
    : QObject(parent), m_connection(connection), m_path(std::move(path)), m_kind(kind), m_delayMs(delayMs),
      m_finalStatus(finalStatus), m_finalErrorCode(finalErrorCode), m_suppressResult(suppressResult),
      m_lostSignalRecoverable(lostSignalRecoverable), m_certScript(std::move(certScript)),
      m_rawCertResult(rawCertResult), m_photoBytes(std::move(photoBytes)), m_photoEmptyMap(photoEmptyMap),
      m_announceConsentPhase(announceConsentPhase), m_credResult(std::move(credResult)),
      m_credRecords(std::move(credRecords)), m_signArtifactBytes(std::move(signArtifactBytes)),
      m_signMeta(std::move(signMeta)), m_tokenInfoEmpty(tokenInfoEmpty),
      m_identityGroupScript(std::move(identityGroupScript)), m_batchDisplayNames(std::move(batchDisplayNames)),
      m_batchHaltAtIndex(batchHaltAtIndex), m_batchHaltErrorCode(batchHaltErrorCode)
{
    m_opAdaptor = std::make_unique<FakeOperationAdaptor>(this);
    if (m_kind == Kind::Sign) {
        m_resultAdaptor.reset(new FakeSignAdaptor(this));
    } else if (m_kind == Kind::BatchSign) {
        m_resultAdaptor.reset(new FakeSignBatchAdaptor(this));
    } else if (m_kind == Kind::Certificates) {
        m_resultAdaptor.reset(new FakeCertificatesAdaptor(this));
    } else if (m_kind == Kind::Photo) {
        m_resultAdaptor.reset(new FakePhotoAdaptor(this));
    } else if (m_kind == Kind::Credentials) {
        m_resultAdaptor.reset(new FakeCredentialsAdaptor(this));
    } else {
        m_resultAdaptor.reset(new FakeIdentityAdaptor(this));
    }
    m_connection.registerObject(m_path, this);
}

FakeOperation::~FakeOperation()
{
    if (m_keptArtifactFd >= 0) {
        ::close(m_keptArtifactFd);
    }
    if (m_keptPhotoFd >= 0) {
        ::close(m_keptPhotoFd);
    }
    for (int fd : m_keptBatchFds) {
        if (fd >= 0) {
            ::close(fd);
        }
    }
}

QString FakeOperation::path() const
{
    return m_path;
}

void FakeOperation::replyNoResult()
{
    setDelayedReply(true); // discard the adaptor's (null-fd) return value
    QDBusContext::connection().send(message().createErrorReply(QStringLiteral("org.librescrs.Agent.Error.NoResult"),
                                                               QStringLiteral("grace window elapsed / not Ok")));
}

void FakeOperation::start()
{
    // Announce AwaitingConsent AFTER a short delay so the signal lands once the
    // client has subscribed to this op's PropertiesChanged (the client only
    // connects after Card1.<Method> returns this op's path). 50 ms comfortably
    // clears the local-bus AddMatch latency and stays well under any test's
    // injected op-stall timeout.
    if (m_announceConsentPhase) {
        QTimer::singleShot(50, this, [this]() { emitPhase(2u /* OperationPhase::AwaitingConsent */); });
    }
    if (m_delayMs <= 0) {
        fire();
    } else {
        QTimer::singleShot(m_delayMs, this, [this]() { fire(); });
    }
}

void FakeOperation::emitPhase(uint phase)
{
    QDBusMessage sig = QDBusMessage::createSignal(m_path, QStringLiteral("org.freedesktop.DBus.Properties"),
                                                  QStringLiteral("PropertiesChanged"));
    QVariantMap changed;
    changed.insert(QStringLiteral("Phase"), phase);
    sig << QStringLiteral("org.librescrs.Agent.Operation1") << changed << QStringList{};
    m_connection.send(sig);
}

void FakeOperation::fire()
{
    if (m_completed) {
        return;
    }

    // An Ok op RETAINS its payload (so GetResult can re-serve it, mirroring the
    // agent's recovery store published on emitResult) and normally EMITS the
    // typed Result BEFORE Finished (strict ordering). Two loss modes:
    //   * suppressResult      — no retain, no signal, GetResult -> NoResult
    //                           (the "GetResult also unavailable" negative case).
    //   * lostSignalRecoverable — RETAIN but do NOT signal: the deterministic
    //                           lost-signal race the client recovers via GetResult.
    if (m_kind == Kind::Credentials) {
        // The Credentials Result fires for EVERY completed attempt — Ok AND the
        // soft-fail invalidPin/blocked outcomes that finish Error — because the
        // a{sv} payload carries the per-attempt outcome, unlike the Ok-only
        // Sign/Identity/Certificates/Photo results. Retain it for GetResult
        // unless total loss (suppressResult -> NoResult); emit the live signal
        // unless the deterministic lost-signal race (lostSignalRecoverable:
        // retain but do NOT signal).
        const bool credRetained = !m_suppressResult;
        const bool credEmitSignal = credRetained && !m_lostSignalRecoverable;
        if (credRetained) {
            m_resultRetained = true; // GetResult now serves (retained payload)
            if (credEmitSignal) {
                Q_EMIT static_cast<FakeCredentialsAdaptor*>(m_resultAdaptor.get())->Result(m_credResult, m_credRecords);
            }
        }
    } else if (m_kind == Kind::BatchSign) {
        // Mirrors the real agent's Operation.SignBatch1.Result contract: the
        // Result fires whenever at least one document was attempted --
        // reached here, that is ALWAYS true (an operation is only minted
        // with a non-empty document list) -- regardless of the aggregate
        // Finished status (a fully-independently-failed or fully-halted
        // batch still delivers its per-row detail). suppressResult models
        // the SAME "GetResult also unavailable" negative case every other
        // kind's gate does.
        const bool batchRetained = !m_suppressResult;
        const bool batchEmitSignal = batchRetained && !m_lostSignalRecoverable;
        if (batchRetained) {
            retainBatchFds(); // idempotent -- seals every row so GetResult can re-serve them
            m_resultRetained = true;
            if (batchEmitSignal) {
                Q_EMIT static_cast<FakeSignBatchAdaptor*>(m_resultAdaptor.get())->Result(buildBatchRows());
            }
        }
    } else {
        const bool okResult = (m_finalStatus == 0u && !m_suppressResult);
        const bool emitSignal = okResult && !m_lostSignalRecoverable;
        if (okResult) {
            m_resultRetained = true; // GetResult now serves (retained payload)
            if (m_kind == Kind::Sign) {
                m_keptArtifactFd = makeSealedArtifact(m_signArtifactBytes);
                if (emitSignal) {
                    const QVariantMap meta = effectiveSignMeta();
                    int dup = m_keptArtifactFd >= 0 ? ::dup(m_keptArtifactFd) : -1;
                    Q_EMIT static_cast<FakeSignAdaptor*>(m_resultAdaptor.get())
                        ->Result(QDBusUnixFileDescriptor(dup), meta);
                    if (dup >= 0) {
                        ::close(dup);
                    }
                }
            } else if (m_kind == Kind::Certificates) {
                if (emitSignal) {
                    if (m_rawCertResult) {
                        emitRawCertResult();
                    } else {
                        Q_EMIT static_cast<FakeCertificatesAdaptor*>(m_resultAdaptor.get())
                            ->Result(buildCertificateList());
                    }
                }
            } else if (m_kind == Kind::Photo) {
                retainPhotoFd(); // seal the bytes so GetResult can re-dup, signal or not
                if (emitSignal) {
                    emitPhotoResult();
                }
            } else {
                // Identity/TokenInfo: a{sa{s(sssv)}} via the typed adaptor
                // signal (auto-relayed using the registered metatype).
                // Progressive delivery (Kind::Identity only): stream every
                // scripted group, in order, strictly before the Result signal
                // below.
                if (m_kind == Kind::Identity) {
                    for (int i = 0; i < m_identityGroupScript.size(); ++i) {
                        const FakeIdentityGroup& g = m_identityGroupScript.at(i);
                        Q_EMIT static_cast<FakeIdentityAdaptor*>(m_resultAdaptor.get())->Group(g.key, g.fields);
                    }
                }
                if (emitSignal) {
                    Q_EMIT static_cast<FakeIdentityAdaptor*>(m_resultAdaptor.get())->Result(buildIdentityFields());
                }
            }
        }
    }

    m_completed = true;

    // Finished.
    QString msgKey = m_finalStatus == 2u ? QStringLiteral("err.key") : QString();
    QString msgFallback = m_finalStatus == 2u ? QStringLiteral("agent fallback") : QString();
    Q_EMIT m_opAdaptor->Finished(m_finalStatus, m_finalErrorCode, msgKey, msgFallback);
}

void FakeOperation::emitRawCertResult()
{
    // Hand-build a(sba{sa{s(ssv)}}uasasu) with raw beginStructure/beginMap calls
    // — deliberately NOT the client's operator<<, so operator>> is exercised
    // against a foreign-marshalled payload. Sent over the real bus so Qt's
    // marshaller produces a genuine demarshalable message (a standalone
    // QDBusArgument does not round-trip write->read).
    // One (fieldKey, labelKey, labelFallback, value) tuple within a group's
    // inner a{s(ssv)} map.
    struct FieldEntry
    {
        QString fieldKey;
        QString labelKey;
        QString labelFallback;
        QString value;
    };
    const auto writeField = [](QDBusArgument& a, const QString& labelKey, const QString& fallback,
                               const QString& value) {
        a.beginStructure();
        a << labelKey << fallback << QDBusVariant(value);
        a.endStructure();
    };
    // Writes ONE outer map entry for @p group holding ALL of @p fields as
    // separate inner map entries (e.g. "validity" carries BOTH notBefore AND
    // notAfter) — a single group name emitted as more than one outer entry
    // would be a duplicate wire key, which Qt's demarshaller resolves by
    // keeping only the LAST one it reads, silently dropping the others.
    // No-ops (never opens the entry) when @p fields is empty.
    const auto writeGroup = [&writeField](QDBusArgument& a, const QString& group, const QList<FieldEntry>& fields) {
        if (fields.isEmpty()) {
            return;
        }
        a.beginMapEntry();
        a << group;
        a.beginMap(QMetaType::fromType<QString>().id(), qMetaTypeId<LibreSCRS::AgentClient::CertFieldWire>());
        for (const FieldEntry& f : fields) {
            a.beginMapEntry();
            a << f.fieldKey;
            writeField(a, f.labelKey, f.labelFallback, f.value);
            a.endMapEntry();
        }
        a.endMap();
        a.endMapEntry();
    };

    QDBusArgument arg;
    arg.beginArray(qMetaTypeId<LibreSCRS::AgentClient::CertInfoWire>());
    for (const FakeCert& fc : m_certScript) {
        arg.beginStructure(); // ( s b a{sa{s(ssv)}} u as as u )
        arg << fc.certId;
        arg << fc.signingCapable;

        arg.beginMap(QMetaType::fromType<QString>().id(), qMetaTypeId<LibreSCRS::AgentClient::CertFieldGroupWire>());
        if (!fc.subjectCn.isEmpty()) {
            writeGroup(arg, QStringLiteral("subject"),
                       {FieldEntry{QStringLiteral("cn"), QStringLiteral("label_subject_cn"),
                                   QStringLiteral("Subject CN"), fc.subjectCn}});
        }
        if (!fc.issuerCn.isEmpty()) {
            writeGroup(arg, QStringLiteral("issuer"),
                       {FieldEntry{QStringLiteral("cn"), QStringLiteral("label_issuer_cn"), QStringLiteral("Issuer CN"),
                                   fc.issuerCn}});
        }
        QList<FieldEntry> validity;
        if (!fc.notBefore.isEmpty()) {
            validity.append({QStringLiteral("notBefore"), QStringLiteral("label_not_before"),
                             QStringLiteral("Not before"), fc.notBefore});
        }
        if (!fc.notAfter.isEmpty()) {
            validity.append({QStringLiteral("notAfter"), QStringLiteral("label_not_after"), QStringLiteral("Not after"),
                             fc.notAfter});
        }
        writeGroup(arg, QStringLiteral("validity"), validity);
        QList<FieldEntry> security;
        security.reserve(fc.securityStatus.size());
        for (const QString& token : fc.securityStatus) {
            security.append({token, QStringLiteral("cert.security.") + token, token, token});
        }
        writeGroup(arg, QStringLiteral("security"), security);
        arg.endMap();

        arg << fc.keyUsageBits;
        arg << fc.extendedKeyUsageOids;
        arg << fc.chainSubjectCns;
        arg << fc.trustStatus;
        arg.endStructure();
    }
    arg.endArray();

    QDBusMessage sig = QDBusMessage::createSignal(m_path, QStringLiteral("org.librescrs.Agent.Operation.Certificates1"),
                                                  QStringLiteral("Result"));
    sig << QVariant::fromValue(arg);
    m_connection.send(sig);
}

LibreSCRS::AgentClient::IdentityFieldsWire FakeOperation::buildIdentityFields() const
{
    if (m_kind == Kind::TokenInfo) {
        // "token" group — label/serial_number/manufacturer, matching the
        // Card1.ReadTokenInfo wire result (rides the SAME Identity1 shape as
        // ReadIdentity; only the group content differs). m_tokenInfoEmpty
        // scripts the unsupported-plugin case: a present-but-EMPTY group,
        // a SUCCESS with zero fields, never an error. An empty inner group
        // is modeled as the group key being ABSENT from the outer map (the
        // real agent's own CardReadSnapshot -> wire mapping never inserts a
        // group whose fields ended up empty — see
        // Operation1Adaptor.cpp::buildIdentity1Wire), so the client's group
        // iteration sees zero groups either way.
        LibreSCRS::AgentClient::IdentityFieldsWire fields;
        if (!m_tokenInfoEmpty) {
            LibreSCRS::AgentClient::IdentityFieldGroupWire group;
            group.insert(QStringLiteral("label"),
                         LibreSCRS::AgentClient::IdentityFieldWire{QStringLiteral("field.label"),
                                                                   QStringLiteral("Label"), QStringLiteral("text"),
                                                                   QDBusVariant(QStringLiteral("Fake Token"))});
            group.insert(QStringLiteral("serial_number"),
                         LibreSCRS::AgentClient::IdentityFieldWire{
                             QStringLiteral("field.serial_number"), QStringLiteral("Serial Number"),
                             QStringLiteral("text"), QDBusVariant(QStringLiteral("0123456789"))});
            group.insert(QStringLiteral("manufacturer"),
                         LibreSCRS::AgentClient::IdentityFieldWire{
                             QStringLiteral("field.manufacturer"), QStringLiteral("Manufacturer"),
                             QStringLiteral("text"), QDBusVariant(QStringLiteral("LibreSCRS Fake"))});
            fields.insert(QStringLiteral("token"), group);
        }
        return fields;
    }
    // Progressive-streaming scripts (Kind::Identity only, m_identityGroupScript
    // non-empty): the Result/GetResult payload is the UNION of every scripted
    // group — the exact wire-level invariant this feature is built on ("final
    // result == union" of whatever streamed), so a test can assert the two
    // against each other without hand-duplicating the script.
    if (m_kind == Kind::Identity && !m_identityGroupScript.isEmpty()) {
        LibreSCRS::AgentClient::IdentityFieldsWire fields;
        for (const FakeIdentityGroup& g : m_identityGroupScript) {
            fields.insert(g.key, g.fields);
        }
        return fields;
    }
    // a{sa{s(sssv)}} with one group/one field — the deterministic payload the
    // Identity1.Result signal AND Identity1.GetResult both serve.
    LibreSCRS::AgentClient::IdentityFieldWire field{QStringLiteral("label_given_name"), QStringLiteral("Given name"),
                                                    QStringLiteral("text"), QDBusVariant(QStringLiteral("Ana"))};
    LibreSCRS::AgentClient::IdentityFieldGroupWire group;
    group.insert(QStringLiteral("given_name"), field);
    LibreSCRS::AgentClient::IdentityFieldsWire fields;
    fields.insert(QStringLiteral("personal"), group);
    return fields;
}

QVariantMap FakeOperation::effectiveSignMeta() const
{
    if (!m_signMeta.isEmpty()) {
        return m_signMeta;
    }
    QVariantMap meta;
    meta.insert(QStringLiteral("format"), QStringLiteral("pades"));
    meta.insert(QStringLiteral("level"), QStringLiteral("b-b"));
    meta.insert(QStringLiteral("tsaUsed"), false);
    meta.insert(QStringLiteral("chainComplete"), false);
    return meta;
}

LibreSCRS::AgentClient::CertListWire FakeOperation::buildCertificateList() const
{
    LibreSCRS::AgentClient::CertListWire certs;
    for (const FakeCert& fc : m_certScript) {
        LibreSCRS::AgentClient::CertInfoWire ci;
        ci.certId = fc.certId;
        ci.signingCapable = fc.signingCapable;
        ci.subjectCn = fc.subjectCn;
        ci.issuerCn = fc.issuerCn;
        ci.notBefore = fc.notBefore;
        ci.notAfter = fc.notAfter;
        ci.keyUsageBits = fc.keyUsageBits;
        ci.extendedKeyUsageOids = fc.extendedKeyUsageOids;
        ci.chainSubjectCns = fc.chainSubjectCns;
        ci.trustStatus = fc.trustStatus;
        ci.securityStatus = fc.securityStatus;
        certs.append(ci);
    }
    return certs;
}

void FakeOperation::retainPhotoFd()
{
    // Seal m_photoBytes into m_keptPhotoFd (shrink|grow|write) once, mirroring
    // the agent retaining raw bytes it re-seals per GetResult. Idempotent and
    // a no-op for the empty-map mode (no photo to retain).
    if (m_photoEmptyMap || m_keptPhotoFd >= 0) {
        return;
    }
    m_keptPhotoFd = memfd_create("fake-photo", MFD_ALLOW_SEALING);
    if (m_keptPhotoFd >= 0) {
        if (!m_photoBytes.isEmpty()) {
            ssize_t w = ::write(m_keptPhotoFd, m_photoBytes.constData(), static_cast<size_t>(m_photoBytes.size()));
            (void)w;
        }
        ::lseek(m_keptPhotoFd, 0, SEEK_SET);
        ::fcntl(m_keptPhotoFd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    }
}

void FakeOperation::emitPhotoResult()
{
    // A genuinely EMPTY a{sh} (no entries): exercises the consumer's empty-MAP
    // guard (a card with no photo at all), distinct from the empty-FD guard (a
    // present-but-empty memfd entry) below.
    if (m_photoEmptyMap) {
        Q_EMIT static_cast<FakePhotoAdaptor*>(m_resultAdaptor.get())->Result(LibreSCRS::AgentClient::PhotoMapWire{});
        return;
    }
    // One-entry a{sh}: "personal:photo" -> a dup of the sealed source fd
    // (m_keptPhotoFd, sealed by retainPhotoFd on the retain path). The local
    // dup must outlive the send like the Sign artifact path (QDBusUnixFileDescriptor
    // dups on copy).
    retainPhotoFd();
    int dup = m_keptPhotoFd >= 0 ? ::dup(m_keptPhotoFd) : -1;
    LibreSCRS::AgentClient::PhotoMapWire photos;
    photos.insert(QStringLiteral("personal:photo"), QDBusUnixFileDescriptor(dup));
    Q_EMIT static_cast<FakePhotoAdaptor*>(m_resultAdaptor.get())->Result(photos);
    if (dup >= 0) {
        ::close(dup);
    }
}

void FakeOperation::retainBatchFds()
{
    // Idempotent, mirroring retainPhotoFd(): one sealed memfd per scripted
    // document, built ONCE regardless of how many times fire()/GetResult()
    // calls this. A row at or past m_batchHaltAtIndex seals ZERO bytes -- the
    // frozen failed-row convention (a real, sealed, empty descriptor, never
    // an invalid one).
    if (!m_keptBatchFds.empty() || m_batchDisplayNames.isEmpty()) {
        return;
    }
    m_keptBatchFds.reserve(static_cast<std::size_t>(m_batchDisplayNames.size()));
    for (int i = 0; i < m_batchDisplayNames.size(); ++i) {
        const bool halted = m_batchHaltAtIndex >= 0 && i >= m_batchHaltAtIndex;
        m_keptBatchFds.push_back(makeSealedArtifact(halted ? QByteArray() : m_signArtifactBytes));
    }
}

LibreSCRS::AgentClient::SignBatchRowsWire FakeOperation::buildBatchRows() const
{
    LibreSCRS::AgentClient::SignBatchRowsWire rows;
    rows.reserve(m_batchDisplayNames.size());
    for (int i = 0; i < m_batchDisplayNames.size(); ++i) {
        const bool halted = m_batchHaltAtIndex >= 0 && i >= m_batchHaltAtIndex;
        LibreSCRS::AgentClient::SignBatchRowWire row;
        row.displayName = m_batchDisplayNames.at(i);
        // QDBusUnixFileDescriptor's ctor dups internally (mirrors
        // FakeSignAdaptor::GetResult's simpler posture, not fire()'s
        // Sign-artifact belt-and-suspenders pre-dup): the kept fd stays open
        // and valid for a later call.
        const int keptFd =
            i < static_cast<int>(m_keptBatchFds.size()) ? m_keptBatchFds[static_cast<std::size_t>(i)] : -1;
        row.artifact = QDBusUnixFileDescriptor(keptFd);
        row.meta = halted ? QVariantMap{} : effectiveSignMeta();
        row.errorCode = halted ? m_batchHaltErrorCode : 0u;
        rows.push_back(std::move(row));
    }
    return rows;
}

// --- WedgedPropertiesAdaptor -----------------------------------------------
void WedgedPropertiesAdaptor::scriptGetAllReply(int delayMs, const QVariantMap& props)
{
    m_replyDelayMs = delayMs;
    m_scriptedProps = props;
}

int WedgedPropertiesAdaptor::getAllCallCount() const
{
    return m_getAllCalls;
}

QVariantMap WedgedPropertiesAdaptor::GetAll(const QString& /*iface*/)
{
    ++m_getAllCalls;
    // Default (unscripted): never answer — mark the call a delayed reply and
    // drop it on the floor. The client's capped GetAll must time out (a hung
    // agent), not wait out the multi-second default D-Bus timeout. When
    // scripted, answer after the scripted delay with the scripted a{sv} (a
    // SLOW agent, not a hung one) — the delayed reply is sent off a QTimer on
    // this (server) thread, so the client's loop never blocks. The
    // QDBusContext lives on the registered parent ContextObject, NOT on this
    // adaptor (an adaptor's own context is never populated for plain method
    // calls — same pattern as Pkcs11Adaptor/CardAdaptor). Either way the return
    // value below is discarded by setDelayedReply.
    auto* ctx = qobject_cast<ContextObject*>(parent());
    if (ctx != nullptr && ctx->calledFromDBus()) {
        ctx->setDelayedReply(true);
        if (m_replyDelayMs >= 0) {
            const QDBusMessage call = ctx->message();
            const QDBusConnection replyConnection = ctx->connection();
            const QVariantMap props = m_scriptedProps;
            QTimer::singleShot(m_replyDelayMs, this, [call, replyConnection, props]() {
                QDBusConnection conn(replyConnection);
                conn.send(call.createReply(QVariant::fromValue(props)));
            });
        }
    }
    return QVariantMap{};
}

// --- Pkcs11Adaptor ---------------------------------------------------------
Pkcs11Adaptor::Pkcs11Adaptor(QObject* parent, FakeAgent* agent) : QDBusAbstractAdaptor(parent), m_agent(agent) {}

QByteArray Pkcs11Adaptor::CertDer(const QDBusObjectPath& reader, const QString& certId)
{
    m_agent->captureCertDer(reader.path(), certId);
    if (m_agent->config().certDerKeyNotFound) {
        // Mirror the agent's public-data error vocabulary: an unknown certId is
        // …Error.KeyNotFound. The QDBusContext lives on the registered root
        // object (our parent ContextObject), not on the adaptor; setDelayedReply
        // there discards this return value.
        auto* ctx = qobject_cast<ContextObject*>(parent());
        if (ctx && ctx->calledFromDBus()) {
            ctx->setDelayedReply(true);
            ctx->connection().send(ctx->message().createErrorReply(
                QStringLiteral("org.librescrs.Agent.Error.KeyNotFound"), QStringLiteral("unknown certId")));
        }
        return {};
    }
    return m_agent->config().certDerBytes;
}

// --- ObjectManagerAdaptor --------------------------------------------------
ObjectManagerAdaptor::ObjectManagerAdaptor(QObject* parent, FakeAgent* agent)
    : QDBusAbstractAdaptor(parent), m_agent(agent)
{}

FakeManagedObjects ObjectManagerAdaptor::GetManagedObjects()
{
    // Wedge: mark the call a delayed reply and never answer, so the client's
    // discovery call must time out on ITS side (the never-hang invariant) rather
    // than stall forever. The QDBusContext lives on the registered root object
    // (our parent ContextObject), not on this adaptor — mirrors WedgedPropertiesAdaptor.
    if (m_agent->config().wedgeGetManagedObjects) {
        auto* ctx = qobject_cast<ContextObject*>(parent());
        if (ctx != nullptr && ctx->calledFromDBus()) {
            ctx->setDelayedReply(true);
        }
        return FakeManagedObjects{}; // discarded by setDelayedReply
    }
    return m_agent->managedObjects();
}

// --- ManagerAdaptor ---------------------------------------------------------
ManagerAdaptor::ManagerAdaptor(QObject* parent, QString version, QStringList features, FakeAgent* agent)
    : QDBusAbstractAdaptor(parent), m_version(std::move(version)), m_features(std::move(features)), m_agent(agent)
{}
QString ManagerAdaptor::version() const
{
    return m_version;
}
QStringList ManagerAdaptor::features() const
{
    return m_features;
}

double ManagerAdaptor::LayoutVisualSignature(const QString& /*text*/, double /*x*/, double /*y*/, double /*width*/,
                                             double /*height*/, double& lineHeight, QStringList& lines, bool& clipped)
{
    ++m_layoutCalls;
    // Card-independent and scripted: the fake never actually lays out `text`
    // against the box (that's the agent-side LM call this scripts a stand-in
    // for), it just serves Config's fixed reply — the point of this fake is
    // exercising the WIRE round trip, not re-implementing LM.
    const FakeAgent::Config& config = m_agent->config();
    lineHeight = config.layoutLineHeight;
    lines = config.layoutLines;
    clipped = config.layoutClipped;
    return config.layoutFontSize;
}

QDBusUnixFileDescriptor ManagerAdaptor::GetAppearanceFont()
{
    ++m_appearanceFontCalls;
    // Fresh sealed memfd per call (mirrors the Photo adaptor's GetResult
    // re-seal-per-call posture above): the constructor dup's internally, so
    // the source fd must still be closed here.
    const int fd = makeSealedArtifact(m_agent->config().appearanceFontBytes);
    QDBusUnixFileDescriptor out(fd);
    if (fd >= 0) {
        ::close(fd);
    }
    return out;
}

// --- ReaderAdaptor ---------------------------------------------------------
ReaderAdaptor::ReaderAdaptor(QObject* parent, QString name, bool hasCard, QDBusObjectPath card)
    : QDBusAbstractAdaptor(parent), m_name(std::move(name)), m_hasCard(hasCard), m_card(std::move(card))
{}
QString ReaderAdaptor::name() const
{
    return m_name;
}
bool ReaderAdaptor::hasCard() const
{
    return m_hasCard;
}
QDBusObjectPath ReaderAdaptor::card() const
{
    return m_card;
}
void ReaderAdaptor::setHasCard(bool v)
{
    m_hasCard = v;
}
void ReaderAdaptor::setCard(QDBusObjectPath v)
{
    m_card = std::move(v);
}

// --- CardAdaptor -----------------------------------------------------------
CardAdaptor::CardAdaptor(QObject* parent, FakeAgent* agent, uint capabilities, QDBusObjectPath reader,
                         QString preReadAuth, QString cardType, QString atrHex)
    : QDBusAbstractAdaptor(parent), m_agent(agent), m_capabilities(capabilities), m_reader(std::move(reader)),
      m_preReadAuth(std::move(preReadAuth)), m_cardType(std::move(cardType)), m_atrHex(std::move(atrHex))
{}
uint CardAdaptor::capabilities() const
{
    return m_capabilities;
}
QDBusObjectPath CardAdaptor::reader() const
{
    return m_reader;
}
QString CardAdaptor::preReadAuthMethod() const
{
    return m_preReadAuth;
}
QString CardAdaptor::cardType() const
{
    return m_cardType;
}
QString CardAdaptor::atr() const
{
    return m_atrHex;
}
void CardAdaptor::setCapabilities(uint v)
{
    m_capabilities = v;
}
void CardAdaptor::setPreReadAuthMethod(QString v)
{
    m_preReadAuth = std::move(v);
}
void CardAdaptor::setCardType(QString v)
{
    m_cardType = std::move(v);
}

QDBusObjectPath CardAdaptor::sendMethodEntryError()
{
    // Mirror the agent's polkit-style precondition gate: throw at method entry
    // (no Operation minted). The QDBusContext lives on the registered ContextObject
    // (our parent), not on the adaptor; setDelayedReply discards this return.
    auto* ctx = qobject_cast<ContextObject*>(parent());
    if (ctx && ctx->calledFromDBus()) {
        ctx->setDelayedReply(true);
        ctx->connection().send(
            ctx->message().createErrorReply(QStringLiteral("org.librescrs.Agent.Error.UnsupportedOnThisCard"),
                                            QStringLiteral("not supported on this card")));
    }
    return QDBusObjectPath();
}

QDBusObjectPath CardAdaptor::ReadIdentity()
{
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }
    return m_agent->mintOperation(FakeOperation::Kind::Identity);
}
QDBusObjectPath CardAdaptor::GetPhoto()
{
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }
    return m_agent->mintOperation(FakeOperation::Kind::Photo);
}
QDBusObjectPath CardAdaptor::ReadCertificates()
{
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }
    return m_agent->mintOperation(FakeOperation::Kind::Certificates);
}

bool CardAdaptor::lacksPkiCapability() const
{
    // Bit 0 == LibreSCRS::Plugin::CardCapabilities::Pki (AgentCapabilities.h's
    // Cap::Pki mirror). Token info is PKI-adjacent (pkcs15), so it shares
    // ReadCertificates' real-agent gate bit.
    return (m_capabilities & 1u) == 0u;
}

QDBusObjectPath CardAdaptor::ReadTokenInfo()
{
    if (lacksPkiCapability()) {
        return sendMethodEntryError();
    }
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }
    return m_agent->mintOperation(FakeOperation::Kind::TokenInfo);
}
QDBusObjectPath CardAdaptor::Sign(const QString& certId, const QDBusUnixFileDescriptor& inputFd,
                                  const QVariantMap& options)
{
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }

    // Honor the in-args: dup + read inputFd synchronously NOW — the client
    // closes its fd as soon as Sign() unwinds, so a deferred read would race a
    // closed descriptor. Capture certId + options verbatim for the test to
    // assert exact forwarding.
    QByteArray inputBytes;
    if (inputFd.isValid()) {
        int dup = ::dup(inputFd.fileDescriptor());
        if (dup >= 0) {
            ::lseek(dup, 0, SEEK_SET);
            char buf[4096];
            ssize_t n = 0;
            while ((n = ::read(dup, buf, sizeof(buf))) > 0) {
                inputBytes.append(buf, static_cast<int>(n));
            }
            ::close(dup);
        }
    }
    m_agent->captureSign(certId, inputBytes, options);
    return m_agent->mintOperation(FakeOperation::Kind::Sign);
}

QDBusObjectPath CardAdaptor::SignBatch(const LibreSCRS::AgentClient::BatchDocumentsWire& documents,
                                       const QString& certId, const QVariantMap& options)
{
    if (m_agent->config().failMethodEntry) {
        return sendMethodEntryError();
    }

    // Honor the in-args exactly like Sign(): dup + read every document fd
    // synchronously NOW (the client closes its copies as soon as SignBatch()
    // unwinds), capturing the verbatim per-document names + bytes + the
    // shared certId/options for the test to assert exact forwarding.
    QStringList names;
    QList<QByteArray> allBytes;
    names.reserve(documents.size());
    allBytes.reserve(documents.size());
    for (const LibreSCRS::AgentClient::BatchDocumentWire& doc : documents) {
        names.append(doc.name);
        QByteArray bytes;
        if (doc.fd.isValid()) {
            int dup = ::dup(doc.fd.fileDescriptor());
            if (dup >= 0) {
                ::lseek(dup, 0, SEEK_SET);
                char buf[4096];
                ssize_t n = 0;
                while ((n = ::read(dup, buf, sizeof(buf))) > 0) {
                    bytes.append(buf, static_cast<int>(n));
                }
                ::close(dup);
            }
        }
        allBytes.append(bytes);
    }
    m_agent->captureSignBatch(certId, names, allBytes, options);
    return m_agent->mintOperation(FakeOperation::Kind::BatchSign, /*withCredRecords=*/true, names);
}

// --- CredentialsAdaptor -----------------------------------------------------
CredentialsAdaptor::CredentialsAdaptor(QObject* parent, FakeAgent* agent, CardAdaptor* cardAdaptor)
    : QDBusAbstractAdaptor(parent), m_agent(agent), m_cardAdaptor(cardAdaptor)
{}

QDBusObjectPath CredentialsAdaptor::sendEntryError(const QString& errorName)
{
    // Mirror CardAdaptor::sendMethodEntryError: the QDBusContext lives on the
    // registered ContextObject (our parent), not on the adaptor.
    auto* ctx = qobject_cast<ContextObject*>(parent());
    if (ctx && ctx->calledFromDBus()) {
        ctx->setDelayedReply(true);
        ctx->connection().send(ctx->message().createErrorReply(errorName, QStringLiteral("credential entry error")));
    }
    return QDBusObjectPath();
}

bool CredentialsAdaptor::lacksPinManagement() const
{
    // The real agent's capability entry gate (Credentials1.xml): all three
    // methods require Card1.Capabilities bit 3 (PinManagement, value 8); when it
    // is absent they throw UnsupportedOnThisCard at entry and mint NO Operation.
    // Read THIS card's sibling Card1 adaptor's LIVE caps, not the
    // construction-time Config (per-card gating, exactly like the real agent).
    return m_cardAdaptor == nullptr || (m_cardAdaptor->capabilities() & 8u) == 0u;
}

QDBusObjectPath CredentialsAdaptor::ManagePin(const QString& pinId, const QString& verb, const QVariantMap& options)
{
    if (lacksPinManagement()) {
        return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.UnsupportedOnThisCard"));
    }
    if (m_agent->config().credEntryError) {
        return sendEntryError(m_agent->config().credEntryErrorName);
    }
    // Request-side wire vocabulary (agent-side entry validation, before any id
    // resolution — the request shape is judged first, and a refusal never
    // reaches the card, so the listing cache survives):
    //   - verb is the CLOSED set change | unblock | activate_pin;
    //   - options is the CLOSED key set {activateKey: bool}, legal only with
    //     activate_pin (there is no open options container on this wire).
    // A client that misspells a verb, invents an option, or mistypes a value
    // fails the suite here instead of passing against a permissive double.
    static const QStringList kVerbs = {QStringLiteral("change"), QStringLiteral("unblock"),
                                       QStringLiteral("activate_pin")};
    if (!kVerbs.contains(verb)) {
        return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.InvalidRequest"));
    }
    for (auto it = options.constBegin(); it != options.constEnd(); ++it) {
        const bool knownKey = it.key() == QLatin1StringView("activateKey");
        const bool wellTyped = it.value().typeId() == QMetaType::Bool;
        const bool legalHere = verb == QLatin1StringView("activate_pin");
        if (!knownKey || !wellTyped || !legalHere) {
            return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.InvalidRequest"));
        }
    }
    // List-before-mutate (agent-side): an id can only come from
    // a CURRENT listing. No listing yet — or a previous mutation dropped the
    // cache — means the id is stale by definition: refused UnknownCredential
    // until a fresh ListCredentials. A conforming client (mandatory re-list
    // after every mutation) never sees this. An id OUTSIDE the current
    // listing's snapshot is equally unresolvable (ids exist only in listings);
    // the refusal itself does not drop the listing.
    if (!m_agent->hasCurrentListing() || !m_agent->isListedId(pinId)) {
        return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.UnknownCredential"));
    }
    m_agent->invalidateListing(); // the mutation invalidates the listing cache
    // A mutation Result carries only the a{sv} outcome — never records.
    return m_agent->mintOperation(FakeOperation::Kind::Credentials, /*withCredRecords=*/false);
}
QDBusObjectPath CredentialsAdaptor::ActivateSigningKey()
{
    if (lacksPinManagement()) {
        return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.UnsupportedOnThisCard"));
    }
    if (m_agent->config().credEntryError) {
        return sendEntryError(m_agent->config().credEntryErrorName);
    }
    // Id-less: per the XML it can never draw UnknownCredential (a call with no
    // activatable key is a VALID call answered via outcome=unsupported), so no
    // listing gate — but it IS a mutation, so it drops the listing cache.
    m_agent->invalidateListing();
    // A mutation Result carries only the a{sv} outcome — never records.
    return m_agent->mintOperation(FakeOperation::Kind::Credentials, /*withCredRecords=*/false);
}
QDBusObjectPath CredentialsAdaptor::ListCredentials()
{
    if (lacksPinManagement()) {
        return sendEntryError(QStringLiteral("org.librescrs.Agent.Error.UnsupportedOnThisCard"));
    }
    // credEntryError models an id-bearing refusal (UnknownCredential / RateLimited
    // against a specific pinId), so it scopes to the MUTATION methods only —
    // ListCredentials is id-less and cannot draw those, and must stay live so the
    // client's mandatory post-mutation / UnknownCredential recovery re-list works.
    m_agent->noteListingIssued(); // the agent's listing cache is (re)populated
    return m_agent->mintOperation(FakeOperation::Kind::Credentials);
}

// --- FakeAgent -------------------------------------------------------------
FakeAgent::FakeAgent(QDBusConnection connection, Config config, QObject* parent)
    : QObject(parent), m_connection(connection), m_config(std::move(config))
{
    ensureMetatypes();
    exportTree();
}

FakeAgent::~FakeAgent()
{
    m_connection.unregisterObject(m_cardPath);
    m_connection.unregisterObject(m_readerPath);
    m_connection.unregisterObject(m_rootPath);
}

void FakeAgent::exportTree()
{
    // Root object hosts the ObjectManager AND the Pkcs11_1 broker surface
    // (which the real agent also hosts once, on the manager path). It is a
    // ContextObject so it carries a QDBusContext the Pkcs11Adaptor uses to mint
    // a CertDer error reply (an adaptor's own context is not populated for
    // plain method calls).
    m_rootObject = new ContextObject(this);
    m_objectManager = new ObjectManagerAdaptor(m_rootObject, this);
    m_pkcs11Adaptor = new Pkcs11Adaptor(m_rootObject, this);
    if (m_config.exportManager1) {
        m_managerAdaptor = new ManagerAdaptor(m_rootObject, m_config.agentVersion, m_config.features, this);
    }
    m_connection.registerObject(m_rootPath, m_rootObject);

    // Reader. A ContextObject (not a plain QObject) so an optional
    // WedgedPropertiesAdaptor can attach to it exactly like the card's.
    m_readerObject = new ContextObject(this);
    m_readerAdaptor =
        new ReaderAdaptor(m_readerObject, m_config.readerName, m_config.hasCard, QDBusObjectPath(m_cardPath));
    if (m_config.wedgeReaderProperties) {
        m_readerPropsWedge = new WedgedPropertiesAdaptor(m_readerObject);
    }
    m_connection.registerObject(m_readerPath, m_readerObject);

    // Card (only when present).
    if (m_config.hasCard) {
        m_cardObject = new ContextObject(this);
        m_cardAdaptor = new CardAdaptor(m_cardObject, this, m_config.capabilities, QDBusObjectPath(m_readerPath),
                                        m_config.preReadAuth, m_config.cardType, m_config.atrHex);
        new CredentialsAdaptor(m_cardObject, this, m_cardAdaptor);
        if (m_config.wedgeCardProperties) {
            // Attached AFTER CardAdaptor: it shadows Card1's auto-exported
            // org.freedesktop.DBus.Properties, so GetAll goes through the
            // wedge (scriptable / hangs by default) instead of reflecting the
            // adaptor's live Q_PROPERTY values.
            m_cardPropsWedge = new WedgedPropertiesAdaptor(m_cardObject);
        }
        m_connection.registerObject(m_cardPath, m_cardObject);
    }
}

QDBusConnection FakeAgent::connection() const
{
    return m_connection;
}
QString FakeAgent::service() const
{
    return m_config.service;
}
QString FakeAgent::rootPath() const
{
    return m_rootPath;
}
QString FakeAgent::readerPath() const
{
    return m_readerPath;
}
QString FakeAgent::cardPath() const
{
    return m_cardPath;
}
FakeAgent::Config& FakeAgent::config()
{
    return m_config;
}

void FakeAgent::scriptCardGetAll(int delayMs, const QVariantMap& props)
{
    if (m_cardPropsWedge != nullptr) {
        m_cardPropsWedge->scriptGetAllReply(delayMs, props);
    }
}

int FakeAgent::cardGetAllCallCount() const
{
    return m_cardPropsWedge != nullptr ? m_cardPropsWedge->getAllCallCount() : 0;
}

void FakeAgent::scriptReaderGetAll(int delayMs, const QVariantMap& props)
{
    if (m_readerPropsWedge != nullptr) {
        m_readerPropsWedge->scriptGetAllReply(delayMs, props);
    }
}

int FakeAgent::readerGetAllCallCount() const
{
    return m_readerPropsWedge != nullptr ? m_readerPropsWedge->getAllCallCount() : 0;
}

void FakeAgent::emitCardPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated)
{
    QDBusMessage sig = QDBusMessage::createSignal(m_cardPath, QStringLiteral("org.freedesktop.DBus.Properties"),
                                                  QStringLiteral("PropertiesChanged"));
    sig << QStringLiteral("org.librescrs.Agent.Card1") << changed << invalidated;
    m_connection.send(sig);
}

void FakeAgent::emitReaderPropertiesChanged(const QVariantMap& changed, const QStringList& invalidated)
{
    QDBusMessage sig = QDBusMessage::createSignal(m_readerPath, QStringLiteral("org.freedesktop.DBus.Properties"),
                                                  QStringLiteral("PropertiesChanged"));
    sig << QStringLiteral("org.librescrs.Agent.Reader1") << changed << invalidated;
    m_connection.send(sig);
}

FakeManagedObjects FakeAgent::managedObjects() const
{
    FakeManagedObjects out;

    FakeInterfaceProps readerIfaces;
    QVariantMap readerProps;
    readerProps.insert(QStringLiteral("Name"), m_readerAdaptor->name());
    readerProps.insert(QStringLiteral("HasCard"), m_readerAdaptor->hasCard());
    readerProps.insert(QStringLiteral("Card"), QVariant::fromValue(m_readerAdaptor->card()));
    readerIfaces.insert(QStringLiteral("org.librescrs.Agent.Reader1"), readerProps);
    out.insert(QDBusObjectPath(m_readerPath), readerIfaces);

    if (m_cardAdaptor) {
        FakeInterfaceProps cardIfaces;
        QVariantMap cardProps;
        cardProps.insert(QStringLiteral("Capabilities"), m_cardAdaptor->capabilities());
        cardProps.insert(QStringLiteral("Reader"), QVariant::fromValue(m_cardAdaptor->reader()));
        cardProps.insert(QStringLiteral("PreReadAuthMethod"), m_cardAdaptor->preReadAuthMethod());
        cardProps.insert(QStringLiteral("CardType"), m_cardAdaptor->cardType());
        cardProps.insert(QStringLiteral("Atr"), m_cardAdaptor->atr());
        cardIfaces.insert(QStringLiteral("org.librescrs.Agent.Card1"), cardProps);
        out.insert(QDBusObjectPath(m_cardPath), cardIfaces);
    }

    // A real agent's GetManagedObjects enumerates EVERY exported object, so a
    // second reader (however it was surfaced — announced or registered silently)
    // is part of the snapshot. Include it so a discovery re-run recovers a reader
    // the client's live signal path missed.
    if (m_reader2Adaptor) {
        FakeInterfaceProps reader2Ifaces;
        QVariantMap reader2Props;
        reader2Props.insert(QStringLiteral("Name"), m_reader2Adaptor->name());
        reader2Props.insert(QStringLiteral("HasCard"), m_reader2Adaptor->hasCard());
        reader2Props.insert(QStringLiteral("Card"), QVariant::fromValue(m_reader2Adaptor->card()));
        reader2Ifaces.insert(QStringLiteral("org.librescrs.Agent.Reader1"), reader2Props);
        out.insert(QDBusObjectPath(m_reader2Path), reader2Ifaces);
    }
    if (m_card2Adaptor) {
        FakeInterfaceProps card2Ifaces;
        QVariantMap card2Props;
        card2Props.insert(QStringLiteral("Capabilities"), m_card2Adaptor->capabilities());
        card2Props.insert(QStringLiteral("Reader"), QVariant::fromValue(m_card2Adaptor->reader()));
        card2Props.insert(QStringLiteral("PreReadAuthMethod"), m_card2Adaptor->preReadAuthMethod());
        card2Props.insert(QStringLiteral("CardType"), m_card2Adaptor->cardType());
        card2Props.insert(QStringLiteral("Atr"), m_card2Adaptor->atr());
        card2Ifaces.insert(QStringLiteral("org.librescrs.Agent.Card1"), card2Props);
        out.insert(QDBusObjectPath(m_card2Path), card2Ifaces);
    }
    return out;
}

void FakeAgent::captureSign(const QString& certId, const QByteArray& inputBytes, const QVariantMap& options)
{
    m_lastSignCertId = certId;
    m_lastSignInputBytes = inputBytes;
    m_lastSignOptions = options;
    // A nested map value inside an incoming a{sv} (here: "visualSignature")
    // arrives as a raw QDBusArgument, NOT a QVariantMap -- Qt's automatic
    // slot-argument demarshalling only converts the OUTER a{sv} to
    // QVariantMap, leaving nested complex values undemarshaled. Replace it
    // with the fully demarshaled QVariantMap (the same scrub Marshal.h's
    // demarshalVariantMap already applies elsewhere) so a test asserting on
    // lastSignOptions() can call .toMap() directly, like any other key.
    if (m_lastSignOptions.contains(QStringLiteral("visualSignature"))) {
        m_lastSignOptions.insert(QStringLiteral("visualSignature"),
                                 demarshalVariantMap(m_lastSignOptions.value(QStringLiteral("visualSignature"))));
    }
}

QString FakeAgent::lastSignCertId() const
{
    return m_lastSignCertId;
}

QVariantMap FakeAgent::lastSignOptions() const
{
    return m_lastSignOptions;
}

QByteArray FakeAgent::lastSignInputBytes() const
{
    return m_lastSignInputBytes;
}

void FakeAgent::captureSignBatch(const QString& certId, const QStringList& displayNames,
                                 const QList<QByteArray>& documentBytes, const QVariantMap& options)
{
    m_lastSignBatchCertId = certId;
    m_lastSignBatchDisplayNames = displayNames;
    m_lastSignBatchDocumentBytes = documentBytes;
    m_lastSignBatchOptions = options;
    // Same nested-a{sv}-demarshal scrub captureSign() applies: a nested
    // "visualSignature" value arrives as a raw QDBusArgument, not a
    // QVariantMap, under Qt's automatic slot-argument demarshalling.
    if (m_lastSignBatchOptions.contains(QStringLiteral("visualSignature"))) {
        m_lastSignBatchOptions.insert(
            QStringLiteral("visualSignature"),
            demarshalVariantMap(m_lastSignBatchOptions.value(QStringLiteral("visualSignature"))));
    }
}

QString FakeAgent::lastSignBatchCertId() const
{
    return m_lastSignBatchCertId;
}

QVariantMap FakeAgent::lastSignBatchOptions() const
{
    return m_lastSignBatchOptions;
}

QStringList FakeAgent::lastSignBatchDisplayNames() const
{
    return m_lastSignBatchDisplayNames;
}

QList<QByteArray> FakeAgent::lastSignBatchDocumentBytes() const
{
    return m_lastSignBatchDocumentBytes;
}

void FakeAgent::captureCertDer(const QString& reader, const QString& certId)
{
    m_lastCertDerReader = reader;
    m_lastCertDerCertId = certId;
}
QString FakeAgent::lastCertDerReader() const
{
    return m_lastCertDerReader;
}
QString FakeAgent::lastCertDerCertId() const
{
    return m_lastCertDerCertId;
}

QDBusObjectPath FakeAgent::mintOperation(FakeOperation::Kind kind, bool withCredRecords, QStringList batchDisplayNames)
{
    const QString opPath = QStringLiteral("/org/librescrs/Agent/op/%1").arg(m_opCounter++);
    const int delay = m_config.raceResultBeforeReturn ? 0 : m_config.operationDelayMs;
    // Photo-specific no-photo modes apply ONLY to the best-effort GetPhoto op, so
    // the preceding ReadIdentity op still succeeds (Ok + Result) and the handler
    // reaches its identity surface before the no-photo path is exercised.
    const bool suppressResult =
        m_config.suppressResult || (kind == FakeOperation::Kind::Photo && m_config.photoSuppressResult);
    const bool photoEmptyMap = (kind == FakeOperation::Kind::Photo) && m_config.photoEmptyMap;
    // A Credentials MUTATION result carries no records (withCredRecords=false):
    // records ride ListCredentials results alone, exactly like the real agent.
    const LibreSCRS::AgentClient::CredentialRecordsWire credRecords =
        withCredRecords ? m_config.credRecords : LibreSCRS::AgentClient::CredentialRecordsWire{};
    auto* op = new FakeOperation(this, m_connection, opPath, kind, delay, m_config.finalStatus, m_config.finalErrorCode,
                                 suppressResult, m_config.certScript, m_config.rawCertResult, m_config.photoBytes,
                                 photoEmptyMap, m_config.announceConsentPhase, m_config.lostSignalRecoverable,
                                 m_config.credResult, credRecords, m_config.signArtifactBytes, m_config.signMeta,
                                 m_config.tokenInfoEmpty, m_config.identityGroupScript, std::move(batchDisplayNames),
                                 m_config.batchHaltAtIndex, m_config.batchHaltErrorCode);
    m_operations.append(op);
    // When raceResultBeforeReturn is set, delay is 0 so start() fires Result +
    // Finished synchronously here, BEFORE we return the path — the client
    // subscribes only after it receives the path, so it MUST recover via
    // GetResult / the terminal triple. Otherwise start() arms a QTimer and the
    // signals arrive after the client has subscribed.
    op->start();
    return QDBusObjectPath(opPath);
}

int FakeAgent::operationCount() const
{
    return m_opCounter;
}

int FakeAgent::layoutCallCount() const
{
    return m_managerAdaptor != nullptr ? m_managerAdaptor->layoutCallCount() : 0;
}

int FakeAgent::appearanceFontCallCount() const
{
    return m_managerAdaptor != nullptr ? m_managerAdaptor->appearanceFontCallCount() : 0;
}

void FakeAgent::emitCardCapabilitiesChanged(uint capabilities)
{
    if (!m_cardAdaptor) {
        return;
    }
    m_cardAdaptor->setCapabilities(capabilities);
    emitCardPropertiesChanged(QVariantMap{{QStringLiteral("Capabilities"), capabilities}});
}

void FakeAgent::emitCardTypeChanged(const QString& cardType)
{
    if (!m_cardAdaptor) {
        return;
    }
    m_cardAdaptor->setCardType(cardType);
    emitCardPropertiesChanged(QVariantMap{{QStringLiteral("CardType"), cardType}});
}

void FakeAgent::invalidateCardCapabilities(uint capabilities)
{
    if (!m_cardAdaptor) {
        return;
    }
    // The GetAll fallback will read this value back through the auto-exported
    // Properties interface (or the scripted wedge, if attached).
    m_cardAdaptor->setCapabilities(capabilities);
    emitCardPropertiesChanged(QVariantMap{}, QStringList{QStringLiteral("Capabilities")});
}

void FakeAgent::setCardCapabilitiesSilently(uint capabilities)
{
    if (!m_cardAdaptor) {
        return;
    }
    // Deliberately NO PropertiesChanged: the client's cached caps stay stale,
    // modelling a client-vs-agent capability desync.
    m_cardAdaptor->setCapabilities(capabilities);
}

int FakeAgent::cancelledOperationCount() const
{
    return m_cancelledOps;
}

void FakeAgent::noteOperationCancelled()
{
    ++m_cancelledOps;
}

bool FakeAgent::hasCurrentListing() const
{
    return m_hasCurrentListing;
}

void FakeAgent::noteListingIssued()
{
    m_hasCurrentListing = true;
    // Snapshot the ids THIS listing returns: ManagePin resolves pinIds against
    // exactly what was last listed, mirroring the real agent's per-listing map.
    m_currentListingIds.clear();
    for (const QVariantMap& record : std::as_const(m_config.credRecords)) {
        const QString id = record.value(QStringLiteral("id")).toString();
        if (!id.isEmpty()) {
            m_currentListingIds.append(id);
        }
    }
}

void FakeAgent::invalidateListing()
{
    m_hasCurrentListing = false;
    m_currentListingIds.clear();
}

bool FakeAgent::isListedId(const QString& pinId) const
{
    return m_currentListingIds.contains(pinId);
}

void FakeAgent::reAddCardWithCapabilities(uint capabilities)
{
    if (!m_cardAdaptor) {
        return;
    }
    m_cardAdaptor->setCapabilities(capabilities);

    FakeInterfaceProps cardIfaces;
    QVariantMap cardProps;
    cardProps.insert(QStringLiteral("Capabilities"), capabilities);
    cardProps.insert(QStringLiteral("Reader"), QVariant::fromValue(m_cardAdaptor->reader()));
    cardProps.insert(QStringLiteral("PreReadAuthMethod"), m_cardAdaptor->preReadAuthMethod());
    cardIfaces.insert(QStringLiteral("org.librescrs.Agent.Card1"), cardProps);
    Q_EMIT m_objectManager->InterfacesAdded(QDBusObjectPath(m_cardPath), cardIfaces);
}

void FakeAgent::emitReaderArrivesEmpty()
{
    // (a) A brand-new reader appears, EMPTY: HasCard=false, Card="/". The real
    // agent never announces a reader with HasCard already true.
    m_reader2Object = new QObject(this);
    m_reader2Adaptor = new ReaderAdaptor(m_reader2Object, m_config.reader2Name, /*hasCard=*/false,
                                         QDBusObjectPath(QStringLiteral("/")));
    m_connection.registerObject(m_reader2Path, m_reader2Object);

    FakeInterfaceProps readerIfaces;
    QVariantMap readerProps;
    readerProps.insert(QStringLiteral("Name"), m_reader2Adaptor->name());
    readerProps.insert(QStringLiteral("HasCard"), false);
    readerProps.insert(QStringLiteral("Card"), QVariant::fromValue(QDBusObjectPath(QStringLiteral("/"))));
    readerIfaces.insert(QStringLiteral("org.librescrs.Agent.Reader1"), readerProps);
    Q_EMIT m_objectManager->InterfacesAdded(QDBusObjectPath(m_reader2Path), readerIfaces);
}

QString FakeAgent::emitArrivedReaderCardAdded(uint capabilities, const QString& preReadAuth)
{
    // (b) The card object appears under its own path — with the full per-card
    // surface (Card1 + Credentials1), exactly like the real agent's cards.
    m_card2Object = new ContextObject(this);
    m_card2Adaptor = new CardAdaptor(m_card2Object, this, capabilities, QDBusObjectPath(m_reader2Path), preReadAuth);
    new CredentialsAdaptor(m_card2Object, this, m_card2Adaptor);
    m_connection.registerObject(m_card2Path, m_card2Object);

    FakeInterfaceProps cardIfaces;
    QVariantMap cardProps;
    cardProps.insert(QStringLiteral("Capabilities"), capabilities);
    cardProps.insert(QStringLiteral("Reader"), QVariant::fromValue(QDBusObjectPath(m_reader2Path)));
    cardProps.insert(QStringLiteral("PreReadAuthMethod"), preReadAuth);
    cardIfaces.insert(QStringLiteral("org.librescrs.Agent.Card1"), cardProps);
    Q_EMIT m_objectManager->InterfacesAdded(QDBusObjectPath(m_card2Path), cardIfaces);
    return m_card2Path;
}

void FakeAgent::emitArrivedReaderHasCard()
{
    // (c) The reader flips HasCard=true AND Card=<cardPath> together, exactly as
    // the real agent's presence model does (both full values in `changed`).
    m_reader2Adaptor->setHasCard(true);
    m_reader2Adaptor->setCard(QDBusObjectPath(m_card2Path));
    QDBusMessage sig = QDBusMessage::createSignal(m_reader2Path, QStringLiteral("org.freedesktop.DBus.Properties"),
                                                  QStringLiteral("PropertiesChanged"));
    QVariantMap changed;
    changed.insert(QStringLiteral("HasCard"), true);
    changed.insert(QStringLiteral("Card"), QVariant::fromValue(QDBusObjectPath(m_card2Path)));
    sig << QStringLiteral("org.librescrs.Agent.Reader1") << changed << QStringList{};
    m_connection.send(sig);
}

void FakeAgent::emitReaderHasCardChanged(bool hasCard)
{
    // Mirror the real agent's presence model: a card insert/removal flips the
    // owning Reader1's HasCard *and* Card together in a single
    // Properties.PropertiesChanged carrying the full new values in the
    // `changed` map (Card -> the card path on insert, -> "/" on remove).
    emitReaderPropertiesChanged(QVariantMap{{QStringLiteral("HasCard"), hasCard},
                                            {QStringLiteral("Card"), QVariant::fromValue(m_readerAdaptor->card())}});
}

void FakeAgent::setCardPresent(bool present)
{
    // A removal/insertion is a new card session: the listing cache never
    // survives it (the real agent's cache is per card session).
    invalidateListing();
    if (present && !m_cardAdaptor) {
        m_cardObject = new ContextObject(this);
        m_cardAdaptor = new CardAdaptor(m_cardObject, this, m_config.capabilities, QDBusObjectPath(m_readerPath),
                                        m_config.preReadAuth, m_config.cardType, m_config.atrHex);
        new CredentialsAdaptor(m_cardObject, this, m_cardAdaptor); // a re-inserted card keeps its Credentials1 surface
        if (m_config.wedgeCardProperties) {
            m_cardPropsWedge = new WedgedPropertiesAdaptor(m_cardObject);
        }
        m_connection.registerObject(m_cardPath, m_cardObject);
        m_readerAdaptor->setHasCard(true);

        FakeInterfaceProps cardIfaces;
        QVariantMap cardProps;
        cardProps.insert(QStringLiteral("Capabilities"), m_cardAdaptor->capabilities());
        cardProps.insert(QStringLiteral("Reader"), QVariant::fromValue(m_cardAdaptor->reader()));
        cardProps.insert(QStringLiteral("PreReadAuthMethod"), m_cardAdaptor->preReadAuthMethod());
        cardProps.insert(QStringLiteral("CardType"), m_cardAdaptor->cardType());
        cardProps.insert(QStringLiteral("Atr"), m_cardAdaptor->atr());
        cardIfaces.insert(QStringLiteral("org.librescrs.Agent.Card1"), cardProps);
        Q_EMIT m_objectManager->InterfacesAdded(QDBusObjectPath(m_cardPath), cardIfaces);
        m_readerAdaptor->setCard(QDBusObjectPath(m_cardPath));
        emitReaderHasCardChanged(true);
    } else if (!present && m_cardAdaptor) {
        m_connection.unregisterObject(m_cardPath);
        m_readerAdaptor->setHasCard(false);
        Q_EMIT m_objectManager->InterfacesRemoved(QDBusObjectPath(m_cardPath),
                                                  {QStringLiteral("org.librescrs.Agent.Card1")});
        m_readerAdaptor->setCard(QDBusObjectPath(QStringLiteral("/")));
        emitReaderHasCardChanged(false);
        m_cardObject->deleteLater();
        m_cardObject = nullptr;
        m_cardAdaptor = nullptr;
        m_cardPropsWedge = nullptr;
    }
}

void FakeAgent::registerSecondReaderSilently()
{
    // A second reader hot-plugged, but its InterfacesAdded is DROPPED (the live
    // signal the client's discovery path missed on hardware). The Reader1 object
    // IS registered so GetManagedObjects returns it — a manual refresh recovers
    // it. Present with no card, like a freshly-plugged empty reader.
    if (m_reader2Adaptor) {
        return;
    }
    m_reader2Object = new QObject(this);
    m_reader2Adaptor = new ReaderAdaptor(m_reader2Object, m_config.reader2Name, /*hasCard=*/false,
                                         QDBusObjectPath(QStringLiteral("/")));
    m_connection.registerObject(m_reader2Path, m_reader2Object);
    // Deliberately NO ObjectManager InterfacesAdded emission.
}

void FakeAgent::exportCardSilently()
{
    // Deferred-publish window / dropped InterfacesAdded: the Card1 object exists
    // on the tree (so GetManagedObjects returns it) and the owning Reader1
    // reports HasCard=true / Card=<path>, but the Card1 InterfacesAdded is NOT
    // emitted. A client that discovered this reader while it was empty therefore
    // sees a card it cannot resolve until it re-runs discovery.
    if (m_cardAdaptor) {
        return; // precondition: no card yet (construct with hasCard=false)
    }
    m_cardObject = new ContextObject(this);
    m_cardAdaptor =
        new CardAdaptor(m_cardObject, this, m_config.capabilities, QDBusObjectPath(m_readerPath), m_config.preReadAuth);
    new CredentialsAdaptor(m_cardObject, this, m_cardAdaptor);
    m_connection.registerObject(m_cardPath, m_cardObject);
    m_readerAdaptor->setHasCard(true);
    m_readerAdaptor->setCard(QDBusObjectPath(m_cardPath));
    // Reader1 PropertiesChanged (HasCard + Card) fires — but NO Card1
    // InterfacesAdded. This is the whole point: the reader claims a card the
    // client has not been told how to reach.
    emitReaderHasCardChanged(true);
}

void FakeAgent::dropCardSilently()
{
    if (!m_cardAdaptor) {
        return;
    }
    // Unregister the Card1 object (GetManagedObjects stops returning it) and flip
    // the reader to card-less — but emit NO InterfacesRemoved and NO Reader1
    // PropertiesChanged. The client keeps its now-stale card until a discovery
    // re-run reconciles it away.
    m_connection.unregisterObject(m_cardPath);
    m_readerAdaptor->setHasCard(false);
    m_readerAdaptor->setCard(QDBusObjectPath(QStringLiteral("/")));
    m_cardObject->deleteLater();
    m_cardObject = nullptr;
    m_cardAdaptor = nullptr;
    m_cardPropsWedge = nullptr;
}

} // namespace LibreSCRS::AgentClient::Fakes

#include "FakeAgent.moc"
