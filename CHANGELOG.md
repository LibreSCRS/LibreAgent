# LibreAgent Changelog

Notable user-visible changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/) loosely.

## [Unreleased] — 5.0.0

### Added

- **`encodeCscaAnchorState()`: the country-signing anchor state as a value.**
  The fields of the import's reply without the reply around it, so a host
  that reports the state elsewhere (a configuration read) writes it with the
  same names and the same absent fields.

- **`writeSignedFile()`: one way to save a signed document.** Beside
  `signedOutputPath()`, it claims the name with an exclusive create (asking
  for the next numbered name when another signer took it meanwhile), then
  commits the artifact over the claim in one step, so the name never holds
  half a signature, and a failure leaves nothing behind. It reads a
  descriptor or a `QIODevice` from its start; an empty artifact is an error,
  never a file.

- **`OperationLauncher`: one place a host starts a card operation.** The host
  gives where the operation runs and who asked, how to build its result
  channel on the host's own transport, and the arguments of that one
  operation (`OperationLauncher::Sign{params}`, …). The prompter, the caches,
  the card seams, the reader's session, the consent-prompt category, the
  keep-alives and the shutdown binding come from the core, and a full reader
  queue answers `RateLimited`. A dependency added to an operation is filled
  in one place instead of once per host and operation.

- **One quiesce policy for sleep, user switch and screen lock.**
  `AgentCore::quiesce(reason)` is where a host reports that the holder's
  session went away; the agent then forgets the same things on every
  platform: on sleep, a user switch or a stop every cached CAN/MRZ, every card
  session (secure channel included) and every PKCS#11 login, on a screen lock
  the PKCS#11 logins only. The reason goes to clients as D-Bus
  `Manager1.Quiesced` (new) and socket `AgentQuiesced`, and reaches
  `AgentClient::quiesced()` from both.

- **Every reader carries its label: model and interface.** The agent reads
  the PC/SC name once and publishes a short model ("OMNIKEY 5422") and which
  interface the slot is (`unknown`, `contact`, `contactless`) on every reader:
  D-Bus `Reader1.Model`/`Reader1.Interface`, socket `reader-state.model`/
  `.interface`, `AgentReader::model()`/`interface()`. A client says the
  interface in its own language and no longer parses reader names. One rule
  now covers what the desktop clients showed: a lone PICC/NFC/contactless
  reader is contactless, a trailing "Reader" is dropped from the model, and
  two readers that would read alike get a short serial suffix. The label is
  decided over all readers, so it is updated when a reader arrives or leaves
  beside it.

- **`CardResolutionPolicy`: one rule for a freshly inserted card.** Probe it
  on its reader's worker, ask again only when the probe could not open it,
  within a retry budget and for the failures the host chooses, and hold the
  reader only for a served card on the contact slot of a dual-interface unit.
  With `PresenceRoster`, `identityForCardIn()` and
  `releaseReaderOnCardRemoved()`, every host retries and holds a card the
  same way.

- **The agent's settings keys are public to clients.** `ConfigKeys.h`
  carries the agent's settings vocabulary (which keys exist, which a client
  may write, the canonical `TslSources`/`CscaSources` row shapes) and
  `CscaAnchorKeys.h` the CSCA anchor state keys, so a desktop client stops
  spelling them itself.

- **The agent's D-Bus introspection XML ships with LibreAgent.** The 14
  interface files that define the bus are installed to
  `share/librescrs/dbus/` and named by `LIBREAGENT_DBUS_XML_DIR` (in the
  installed package and in a subproject build), so the bus host and every
  client read one copy. A test holds the Qt client's interface names, calls,
  properties and signal argument types against them.

- **`describeFailure()`: which part of a failure a user reads.** A failed
  operation reports a code, a call class, a message key and the agent's
  English message; the order in which a client prefers them is now one
  function (`FailureCopy.h`) instead of one per client, and
  `kLocalizedMessageKeys` lists the keys a client gives its own sentence, so
  a cancelled or expired operation reads in the user's language everywhere.

- **`AgentClient::agentState()` and `installHelpUrl()`.** One answer to "is
  there an agent, and does it run" (`Ready`, `Stopped`, `Missing`) for every
  client, read without touching the bus, plus the address of the install
  guide for the platform and language. `agentInstalled()` no longer asks the
  bus on every call: it ran a nested event loop inside the very signal
  handlers that read it.

- **`Authorizer::authorizeAsync`: authorization without a waiting dispatcher.**
  An authority that holds its answer while a person decides (a polkit
  password dialog) no longer has to stop the thread serving every other
  client; the PKCS#11 login asks this way and defers its reply. Authorities
  that answer at once keep implementing `authorize()` only.

- **`signedOutputPath()`: one name for a signed document's output.** Every
  client now derives where a signature is written the same way
  (`<stem>-signed.pdf`, `<name>.xsig`, `<name>.p7s`/`.p7m`, `<name>.jose`,
  `<stem>.asice`) and never names an existing file: a taken name gets the
  first free numbered sibling, `report-signed (2).pdf`.

- **`Pkcs11.LoginState` and the `login-state` feature token:** whether a
  caller's login on the card in a reader still holds, asked without extending
  it (`AgentClient::loginActive` in the PKCS#11 facade).

- **`CertificateInfo::alwaysAuthenticate` and the `cert-info` wire key
  `alwaysAuthenticate`:** whether the card asks for the PIN before every
  operation with a certificate's key.

- **EC keys end to end.** Every certificate reports its key's `keyId` (the
  card's own PKCS#11 `CKA_ID`), `keyType`, `keyBits` and `canDerive`
  (`cert-info`, `CertificateInfo`, whose key type is the new public enum
  `LibreSCRS::AgentClient::KeyType`); the `public-key` reply serves EC points;
  the `Pkcs11.Derive` request runs ECDH with the card's key (the raw secret at
  the curve's field width, CKD_NULL); the `ec-keys` feature token. The PKCS#11
  module offers EC keys with `CKA_EC_PARAMS`/`CKA_EC_POINT`, `CKM_ECDSA` and
  `CKM_ECDH1_DERIVE`, and holds derived secret keys as session objects; a
  template asking for more bytes than the secret has is refused before the
  card is asked.

- **One zeroization routine for the agent stack.** `LibreSCRS/Agent/SecureZero.h`
  provides `secureZero` (it replaces the wire library's own) and
  `SecureZeroOnExit`, which wipes a byte buffer on every way out of a scope.

- **`SocketAgentClient` can check who serves the agent socket.** It takes an
  optional check of the serving process, run on every connect before any byte
  is sent, so a host that knows what the agent should look like (a code
  signature, say) can refuse an impostor listening on the socket before a
  credential or a request reaches it. Without the check, behaviour is as
  before.

- **The PKCS#11 facade is built and tested on macOS in CI**, alongside Linux.

- **Every release carries a source tarball this project built.** The Arch
  recipe fetches that asset instead of the archive GitHub generates for a tag:
  the generated one omits every submodule tree, and its bytes are not ours to
  assert, so the recipe's `sha256sums` line said nothing about what was
  actually built. The published tarball is a function of the commit — every
  member carries the commit's own timestamp, owner `0/0` and a mode no umask
  can widen — so a packager who rebuilds it gets the same bytes back, up to the
  gzip implementation. It is named so that one file can serve as the `.orig`
  for `dpkg-source`; the `deb` and `rpm` builds still build from the checkout
  and do not consume it yet.

- **Distribution packages for the agent libraries.** `deb` for Debian 13 and
  Ubuntu 26.04 LTS, `rpm` for Fedora 43. Four binary packages where Arch has
  three: the shared Qt client library keeps its runtime and its development
  files apart, which both layouts require and pacman does not. The core packages
  ship static archives with no shared counterpart, so they have no runtime
  sibling at all and a host depends on them only to build.


The country-signing anchor import now accepts what the ICAO Public Key
Directory actually publishes. The portal serves a directory export (an
LDIF file) carrying dozens of master lists, each signed by a different
country; until now the agent could take in one list at a time, so a
person following the instructions in their own settings dialog was
refused the file they had just been told to download. One selection is
still one import, and the agent decides what the file is: a client hands
over bytes and never has to know what counts as a master list.

Every list in a collection is verified on its own, against its own
signer, and the anchors installed are the union of the ones that
survived. The rules that already governed a single list now apply per
publisher: each is remembered separately, a publisher's lawful key
rotation is followed on its own evidence, and a list is refused as a
replay when it is not strictly newer than the one already accepted FROM
THAT PUBLISHER — so one country publishing rarely no longer looks like a
rollback. A signer with no record behind it must additionally beat the
newest publisher the import displaces, which is what keeps a rotation
from being a way to carry an old list in.

An import takes what verifies rather than refusing everything: two stale
lists among twenty-eight no longer deny a person the other twenty-six,
and nothing is installed that was not verified. What did not make it is
reported alongside what did, so a surface can say how many of how many
were installed and why the rest were not. An import that admits no list
at all is still a refusal and still leaves the stored anchors untouched.
Whether a later collection can be checked for rollback is now reported
honestly for the whole: one undated list among the accepted ones makes
it false, because that publisher's anchors can be rolled back freely.

A never-configured installation now seeds a working timestamp-authority
and trusted-list configuration on first start. Startup stays
network-free (no seeded list is fetched eagerly), but the first DEFAULT
signature on a fresh installation changes shape: with timestamp
authorities configured, an auto-level sign resolves to B-T, so it is
timestamped and contacts a seeded TSA at signing time.

First public release of LibreAgent: the platform-neutral, Qt-free core
of the LibreSCRS smart-card agent, the shared wire vocabulary both of
its transports speak, and the Qt client library desktop frontends use to
talk to it. Platform hosts (LibreLinux today, a macOS host to follow)
build on the core to provide the per-user card broker without
re-implementing the neutral state machine; GUI clients build on the Qt
client library instead of re-implementing an agent protocol per desktop.

Three targets ship, each independently usable:

| Target | Links | For |
| --- | --- | --- |
| `LibreAgent::Core` | LibreMiddleware, OpenSSL | platform hosts |
| `LibreAgent::Wire` | nothing first-party | anything speaking the agent wire |
| `LibreAgent::ClientQt` | Qt6 | Qt/KDE desktop clients |

### Added

- **Platform-neutral agent core.** A single static library
  (`LibreAgent::Core`) owning the backend-agnostic agent logic every
  host needs: reader/card presence tracking, a bounded operation
  scheduler, read and credential caches, the PKCS#11 lease/broker
  model, and the LibreMiddleware-backed card flows (identity, photo and
  certificate reads plus AdES / raw-crypto signing). The core links no
  D-Bus, systemd, polkit or Qt.
- **Five backend interfaces** through which a host plugs in its IPC and
  desktop stack: `Prompter` (PIN / CAN / MRZ collection, returning a
  cleansing secret rather than a raw fd), `Authorizer` (per-operation
  gate, with a fail-closed default shipped in-tree), `AgentTransport`,
  `OperationChannel`, and `LogSink` (LibreMiddleware's
  `LibreSCRS::log` facade, which the agent core logs through).
- **Stable error taxonomy** carried on each finished operation. Codes
  are wire-frozen and append-only so clients can branch on the numeric
  value across releases. This release adds two signing-related codes:
  `EngineUnavailable` (the signing engine could not be started — a
  deployment problem) and `InvalidDocument` (the document
  submitted for signing is invalid or unreadable — a client-input
  problem), each distinct from a generic engine failure so clients can
  give the user an accurate, actionable message.
- **Certificate read caching per card insertion**, so repeated
  certificate reads within a single card session avoid redundant card
  I/O; the cache is bound to the card's presence.
- **Card credential management.** Beyond reading and signing, the core
  can enumerate a card's PINs and keys together with their current state
  — retry counts, whether a PIN is still in transport state or has been
  blocked, and whether a signing key is awaiting activation — and can
  change a card PIN. The same surface additionally exposes unblocking a
  blocked PIN and activating a dormant signing key for cards and plugins
  that support them; on the hardware supported in this release those
  requests return an unsupported result. Each operation collects the
  PIN(s) it needs through the prompter and never caches them. When a card
  reports that a blocked PIN or a dormant key can only be recovered
  through the card issuer, that guidance is forwarded to the client so
  the user learns the correct next step.
- **Shared wire vocabulary** (`LibreAgent::Wire`): the message types,
  canonical CBOR codec and framing both agent transports carry, plus the
  frozen error vocabularies — the numeric operation taxonomy and the
  named synchronous-method vocabulary — so a host and a client cannot
  drift apart on what a message or a refusal means. It links nothing
  first-party, so a consumer that only needs to speak the protocol takes
  on neither LibreMiddleware nor Qt.
- **A sign request may defer the conformance level to the agent**, and
  that is what `SignOptions` does by default (`SignatureLevel::Auto`).
  The agent then applies the level it is configured with, including that
  value's upgrade to a timestamped one when a timestamp authority is
  set. Naming a level overrides the deployment's own policy, which is
  occasionally right and easy to do by accident: a client that always
  asked for the baseline produced baseline signatures everywhere,
  successfully and silently, no matter how the site was configured. To
  ask for a specific level anyway, set it: `options.level =
  SignatureLevel::BB`. `Auto` is request-only — a result always reports
  the level actually produced and never reports `Auto`.
- **Qt client library** (`LibreAgent::ClientQt`): a transport-neutral,
  typed client for Qt/KDE desktop frontends. It exposes the agent as
  live `AgentClient` / `AgentReader` / `AgentCard` / `AgentOperation`
  objects — reader and card discovery with live add/remove, the card
  read/sign/credential operations with typed results, and the
  no-consent public-data fetches. It is written against an internal
  transport seam with two implementations, D-Bus and the AF_UNIX socket
  wire, so no transport type appears anywhere in the public API.
  **This release's public API picks the transport per platform and
  offers no way to override it** — `AgentClient` has a single
  constructor, which builds the D-Bus transport on Linux and the
  App-Group socket transport on macOS; a platform with neither yet gets
  an inert client that is never available. Every call that reaches the
  agent is bounded by a call-timeout budget, so a slow or wedged agent
  cannot hang a caller indefinitely; the budget is 3 s by default, so a
  synchronous call is bounded rather than instant. Public value types
  are plain Qt/std aggregates, and file descriptors cross the boundary
  as a move-only owning handle rather than a raw `int`.
- **The Qt client can now reach the agent on macOS.** Building for
  macOS previously left `AgentClient` with no transport at all, so a
  Qt application reported itself permanently unavailable and read no
  cards. It now opens the same App-Group socket connection the macOS
  agent host listens on, the same way the Linux build already opens a
  D-Bus connection — no application code changes to pick it up.
  The App Group that holds that socket is named after the Apple team
  the client is built for, set with the `LIBRESCRS_TEAM_ID` CMake cache
  variable (`<TEAM>.org.librescrs.LibreMac`; empty, the default, keeps
  `group.org.librescrs.LibreMac`). macOS 27 refuses an unprovisioned
  `group.` container to a sandboxed process, so a release build must
  name the same team as the agent it talks to.
- **Country-signing (CSCA) trust-anchor import is platform-neutral.**
  Turning a signed ICAO master list into trust anchors — and the
  trust-on-first-use, signer-pinning and rotation judgement that
  decides whether a later list should be believed — now lives in the
  shared agent core instead of a single platform host, so every host
  applies the same policy against a travel document's issuing country
  rather than each carrying its own copy that could quietly disagree.
- **Best-effort certificate cache warm** (`AgentCard::warmCertificates()`):
  asks the agent to pre-read a card's certificates so a later real read
  finds them warm, for frontends that can predict a read shortly before
  it happens. It returns immediately whatever state the agent is in,
  mints nothing to observe or cancel, debounces itself, and reports no
  outcome — a warm that did not happen simply leaves the next read to
  pay the cold cost it would have paid anyway. On a transport that
  cannot express it without stranding agent-side state it is a no-op,
  which no consumer needs to handle: correctness never depends on a warm
  having happened.

### Changed

- **The installed agent doubles carry only what they speak.**
  `ClientQtTestSupport` no longer installs the client's transport seam,
  its wire conversions or its bus constants; besides the doubles it installs
  the D-Bus wire shapes alone (`AgentClientTestSupport/dbus/WireShapes.h`).
  Hosts that include `TestBus.h`, `FakeAgent.h` or `FakeSocketAgent.h` are
  unaffected.

- **A suite's private session bus starts nothing installed on the machine.**
  `libreagent_private_session_bus()` runs the bus from a configuration with
  no service directories, so a suite that starts the agent can no longer
  launch the real one; `SERVICE_DIR <dir>` names the one directory a suite
  puts its own activation files in.

- **The Qt client library exports only its API.** `liblibrescrs-agentclient-qt`
  no longer exports the Qt and standard-library template code it instantiates
  internally, nor its classes' private implementations; programs built
  against it are unaffected. Without the unique symbols those exports carried,
  a process that loads the library through a plugin can unload it again.

- **Test-only code left the agent's API.** `AllowAllAuthorizer` ships with
  the test support component (`LibreSCRS/AgentTestSupport/AllowAllAuthorizer.h`)
  instead of `backend/Authorizer.h`; `CredentialCache::hasCan`/`hasMrz` and
  `CardKeyTracker::currentKey`, which only tests called, are gone (`getCan`/
  `getMrz` answer the same question). The PKCS#11 facade's `publicKey()`
  returns `std::expected` over the agent's own RSA/EC key types instead of a
  structure carrying both families' fields at once.

- **A document signature reads the card's certificates once.** The agent
  chooses the signing key and hands it, with the certificates it read, to
  the middleware's signing service, which no longer reads the card a second
  time or chooses again by its own rule. A certificate the card lists without
  a key of its own is reported as no key found instead of reaching the
  signing service.

- **`LIBRESCRS_WERROR` replaces `LIBRESCRS_AGENT_WERROR`.** The option that
  turns warnings into errors has the name every LibreSCRS repository uses,
  and one CMake function gives every library here its warning flags.

- **An unknown pre-read unlock method now means "unlock required".**
  `preReadAuthFromToken()` returns `std::optional<PreReadAuth>`: a method
  this build does not name is `std::nullopt`, no longer `None`, and
  `preReadUnlockRequired()` gives the one answer every client should act on.
  The socket transport forwards such a method as an unknown token instead of
  `None`.

- **One log facade.** The agent core logs through LibreMiddleware's
  `LibreSCRS::log` (`<LibreSCRS/Logging.h>`); its own
  `LibreSCRS/Agent/backend/Logging.h` is gone. A host installs one sink and
  receives the middleware's and the agent's lines alike.

- **Every client operation now gives up on a silent agent by itself.** An
  `AgentOperation` that hears nothing from a working agent for
  `kLongOperationTimeoutMs` is cancelled at the agent and finishes with
  `CallError::Timeout`; the clock stops while a person is at the agent's
  prompt. `setStallBudget()` changes or turns off the bound. Before, each
  client had to run this timer itself, and those that did not stayed busy
  forever after a lost terminal signal.

- **The PKCS#11 module advertises `CKA_ALWAYS_AUTHENTICATE` per key, from the
  card,** instead of TRUE on every private key. The agent asks for the PIN
  again for every raw signature or decryption with a key the card marks,
  whatever the client does (document batch signing still asks once per
  batch), and every PIN prompt counts against the caller's prompt budget. A
  session the agent refuses as not logged in reads as public again.
  The `Certificates1` D-Bus result gained a trailing boolean.

- **An empty answer to a PIN, CAN, MRZ or PIN-change prompt is a dismissed
  prompt.** Nothing reaches the card; key activation used to send an empty
  VERIFY.

- **Raw signature and decryption requests carry a required `mech`**; the agent
  runs exactly that mechanism, and checks it against the key, the input's
  length and a key agreement's peer point. A mismatch — and an RSA mechanism
  the key's card does not take: a caller-built PKCS#1 block for the key of a
  PACE card, which hashes the message itself, or a message to hash for any
  other RSA key — is refused with `InvalidRequest` before any PIN prompt. A refused
  request leaves the lease's verified state as it was; on a lease that has not
  asked for the PIN yet, it still counts against the caller's prompt budget. `CKA_ID` is the card's own key ID instead of a per-card
  counter. Every certificate's key type decides its PKCS#11 attributes and
  mechanisms; the hash-on-card mechanism applies to RSA keys only; a key of
  another type (`OTHER`) is not published by the PKCS#11 module, while
  document signing through the agent is unchanged.

- **A certificate a card plugin lists under two different keys is refused as
  `KeyAmbiguous`** instead of signed with the first key found. Two plugins
  that expose the same certificate still sign with the first in priority
  order: they expose the same key. A raw PKCS#11 signature or decryption
  answers such a certificate with `KeyNotFound`, PKCS#11 having no answer for
  an ambiguous key.

- **A card no plugin serves is released right after the insertion probe**,
  instead of being held for the 45 s idle window, so another process can take
  the reader at once. The probe now tells a card it could not open from a card
  no plugin serves (`CardSessionHolder::fullResolution()` returns the
  `OpenError` for the first), and a host asks again only for the first.

- **Minimum CMake is now 3.28** (was 3.24), for
  `FetchContent_Declare(... EXCLUDE_FROM_ALL)` — which is what keeps the
  vendored QCBOR dependency's own install rules out of the installed
  tree. Consumers building against an older CMake must upgrade.
- **Dual-interface readers: the contact slot is kept powered while a card
  sits in it.** A dual-interface card in the contact slot of a reader such as
  the OMNIKEY 5422 couples weakly to the reader's contactless coupler, so the
  contactless slot reported it as an endless insert/remove flap (reader LED
  never at rest, a full card probe per flap). The agent now keeps that contact
  slot's one session open while a card it serves is present. After 45 s idle
  the session is emptied of every secret — what the card plugins held for it,
  the cached PACE secrets, the secure channel — and kept only to hold the card
  powered; the next operation reuses it. No second connection is opened on a
  reader, so nothing lives longer in memory than it did before.
  Consequence: a PC/SC client that asks for EXCLUSIVE access to that contact
  slot (GnuPG's scdaemon does by default) is refused while the card is
  present; SHARED clients, including OpenSC tools, are unaffected. On such a
  slot, and for cards whose PIN state is not bound to a secure channel, the
  card's own verified state survives the 45 s idle window, so within a
  PKCS#11 login a signature after a longer pause no longer re-prompts before
  the login's own idle limit; that on-card state is visible to any other local
  shared PC/SC client while the card stays powered.

### Removed

- **`CardSessionHolder` no longer carries a `SmartCard::CardMap`.** Nothing
  read the map it handed out with every acquired card. The constructor takes
  the reader, the session factory, the candidate resolver and an optional
  clock; `AcquiredCard` holds the session and its candidates.

- **The credential listing no longer checks guidance for placeholders.** No
  card plugin puts `LocalizedText` placeholders into PIN guidance, and the
  wire record never carried them; the guidance's key and default text are
  copied as they are.

- **`errorCodeFor(Plugin::ReadResult::Status)`.** No operation mapped a
  plugin's read status through it; the overloads for a secure-channel error
  and a credential outcome stay.

- **`SeamStatus::ParseError`.** Its one source was LibreMiddleware's parse-error
  read status, which no plugin returned and which is gone; a read that fails
  still ends with the error the plugin reported.

- **The `Mechanism` values nothing runs.** `RsaPssSign`, `RsaOaepDecrypt`,
  `RsaPkcs1Encrypt`, `RsaOaepEncrypt` and `MechParamsRsaOaep` had no wire
  token, no seam and no caller; every path refused them. The enumerators
  that remain are the five the agent runs.

- **The `trust-status` and `identity-stream` feature tokens.** No client
  checks either: a certificate's trust verdict is a field every agent
  sends, and the per-group identity events are handled whenever they
  arrive. The agent advertises nine tokens; the events and the field are
  unchanged.

### Fixed

- **A second "start the agent" while one is starting asks for nothing.**
  Starting the agent waits in a local event loop, so a second click, a timer
  or a settings read can arrive inside it. Such a call now starts nothing
  and `requestAgentStart()` answers `Requested`; the start in flight reports
  how it ended.

- **"Start service" and "Refresh" can no longer delete the button under its
  own click.** Both wait on the agent in local event loops, and a view swapped
  inside one of them (the agent came up, a card was inserted) was deleted in
  the next one, while the button's click handler was still running.
  `requestAgentStartLater()` (its result arrives as `agentStartFinished()`)
  and `refreshDiscoveryLater()` do the same from the event loop once the
  handler has returned; a control the outcome may replace calls those.

- **An idle card that ran secure messaging is no longer kept powered
  mid-session.** Keeping a reader's connection for the next operation
  cleared only the agent's side of a PACE/BAC channel while the chip still
  expected protected commands; such a session is now closed, and the next
  operation starts from a fresh connection. A card whose plugin probe failed
  once is also probed again on the next attempt instead of being served
  with no plugin.

- **A slow answer from the agent no longer freezes every PKCS#11 call in the
  browser.** Refreshing the slot list held the module's lock across the round
  trip to the agent, so while the agent read a card for one thread, every
  other thread's call waited too. The refresh now runs unlocked and publishes
  its result under the lock.

- **A large request to the macOS agent no longer reads as a dead agent.** The
  Qt client's socket is non-blocking for its reader, and a request bigger than
  the socket buffer while the agent was busy failed on the first full buffer
  and dropped the connection. Sends now wait for room, within the call's own
  time budget.

- **On Linux, a desktop client could not start the agent.** The agent is a
  session service started on demand, but the Qt client only ever asked whether
  it was already running, so after a fresh login every client reported the
  service as unavailable and "try again" could never succeed. Retrying,
  opening the settings, fetching a certificate or asking for a layout preview
  now start an installed agent first; merely constructing a client does not.
  `AgentClient::requestAgentStart()` starts it explicitly (on macOS by
  launching the LibreMac host in the background), and `configChanged` with an
  empty key tells a client holding settings to read them again once the agent
  is up.

- **Firefox stopped completing TLS client authentication once the agent's
  login had idled out, until the PKCS#11 module was reloaded.** The module kept
  the login per session: when a signature came back "not logged in", only the
  signing session went public, while the session Firefox asks on still read as
  logged in, so Firefox never asked for the PIN again. A login now covers every
  session of the token (PKCS#11 v2.40 section 5.6), and `C_GetSessionInfo` asks
  the agent, at most once a second and never waiting behind a PIN prompt,
  whether the login still holds, so Firefox asks for the PIN before the
  signature instead of failing it.

- **Firefox showed the PKCS#11 tokens as uninitialized and would not log in.** The
  token info now reports the user PIN as initialized.

- **A refused handshake no longer leaves the client unable to reconnect for the
  rest of the process.** The socket stayed open after the agent refused the
  handshake, so every later attempt failed on it; it is now closed.

- **The PKCS#11 module's agent socket is no longer inherited by a child of
  the process that loaded it**, so a spawned helper cannot keep alive a
  connection that holds the loader's lease. A peer check that throws now
  counts as a refusal instead of leaking the socket.

- **Two cards seated at once now show up as two PKCS#11 tokens.** Every token
  was labelled "LibreSCRS Token" with an empty serial number, so a loader such
  as Firefox could not tell one from the other. The label is now the holder
  named by the card's signing certificate, or the reader's name for a card
  whose certificate names no holder; the serial number is the agent's
  per-insertion handle for the card. A label longer than the 32-byte field is
  cut where a character starts, never inside one.

- **A PKCS#11 slot is described by its reader's name**, not by the agent's
  internal handle for the reader (`obj/1`).

### Security

- **The Qt client on macOS checks who serves the agent socket.** Before the
  first byte is sent it now requires the process behind `agent.sock` to be the
  agent (its signing identifier, the App Group and, in a team-signed build,
  the designated requirement), the same check the Swift clients and the
  PKCS#11 module make; anything else reads as no agent. The socket path no
  longer comes from `LIBRESCRS_AGENT_SOCK` or `$HOME`, both of which any
  process running as the user can set for every other one; the home directory
  is the one the password database records. The check itself now lives in the
  wire library (`wire/darwin/PeerCodeSigning.h`) and the container rule in
  `wire/SocketLocation.h`, so every end uses one copy.

- **Secrets never outlive the card.** The credential cache holds no
  PIN by construction, and both the read cache and credential cache are
  scrubbed the moment the card is removed. Collected secrets use
  cleansing storage that zeroizes on drop, and cached read data is
  zeroized on drop as well.
- **Bounded, rate-limited operation scheduling** with watchdog-driven
  cancellation and a per-reader backlog cap, so a misbehaving or
  hostile client cannot exhaust the agent.
- **Exclusive card-access arbitration** between the agent's own flows
  and external PKCS#11 clients via the lease/broker model, with the
  first PKCS#11 cold-lease PIN prompt rate-limited.
- **A decrypted block and a derived secret are wiped from every copy the
  agent and the PKCS#11 module hold**, on every way out an exception included:
  the plugin's buffer, the agent's result (also when the agent shuts down
  mid-operation), the broker's copy once the reply has its own, the module's
  received frame and decoded reply, and a derived key's value when the key is
  destroyed.
- **Encoding a floating-point value no longer runs into undefined behaviour in
  the CBOR library's shortest-form reduction.** QCBOR shifted by an
  out-of-range amount for most values that do not shorten (0.1 among them),
  and the decoder's canonical re-encode reached that from any peer's request.
  The encoder now picks the width up front for exactly those values; the
  bytes on the wire are unchanged.

### Packaging

- **The Qt client's agent doubles are no longer packaged.** No package ships
  `ClientQtTestSupport` (the in-process fake agents for testing a desktop
  client) any more; it stays a build option for development trees. The Qt
  client's packages therefore no longer depend on the agent core, and the
  shared library no longer exports a way to construct a client over a
  substituted transport: that test seam now exists only in this
  repository's own test build.

- **This release is 5.0.0, and the Qt client library's soname moves with
  it** — `liblibrescrs-agentclient-qt.so.5`, out of a file named
  `.so.5.0.0`. The number is declared once: the version file feeds the
  project version, and the soname is that version's major. Consequences
  worth knowing before you upgrade — a distribution package that carries
  the number in its name changes name; an already-linked consumer has to
  be rebuilt; and a `find_package(LibreAgent 4.2 ...)` floor no longer
  resolves this package at all, because the exported package declares
  same-major compatibility. Raise such a floor to `5.0`.
- **Installed CONFIG package** with five components — `Core`, `Wire`,
  `ClientQt`, `Pkcs11Facade` and `Pkcs11SocketClient`. Ask for what you
  need and nothing else:

  ```cmake
  find_package(LibreAgent 5.0 REQUIRED CONFIG COMPONENTS ClientQt)
  target_link_libraries(my_gui PRIVATE LibreAgent::ClientQt)
  ```

  Each component re-exposes only its own dependencies — `Core` brings
  LibreMiddleware and OpenSSL, `ClientQt` brings Qt6::Core, `Wire`
  brings nothing — so a Qt client never has to discover LibreMiddleware
  and a platform host never has to discover Qt. Naming components is the
  supported spelling; a componentless `find_package` still resolves, but
  it probes for every component that happens to be installed and so
  drags in dependencies the caller may not want.
- **Public-ABI snapshot gate** in CI freezing the exported surface;
  minor-version additions are tracked, while removals or signature drift
  are rejected. It gates the exported symbols of **the three components
  whose ABI is snapshotted** (`Core`, `Wire` and `ClientQt`), AND the
  memory layout of the Qt client's public value
  types — size, alignment, member count and per-member offsets —
  because those types are copied by value into consumers, so a member
  added, removed or reordered breaks an already-built consumer without
  moving a single symbol name.

  Two limits are worth knowing rather than discovering. Demangling
  collapses the constructor/destructor ABI variants, so the symbol
  sections record fewer lines than the linker emits and a change
  affecting only one variant would not move them.

  And the Qt client's shared library exports a good deal that is not
  its API. Of 279 exported symbols, 113 are the API; the remaining
  **166 are not API**, and of those **164 are not gated** — the two
  that are, are the error-vocabulary functions a public header
  re-exports. The ungated 164 are the statically folded wire library
  (47) and its vendored CBOR dependency (117), left out because gating
  them would be pure churn. The vendored 117 are the ones to know
  about: they are unversioned C symbols, so a consumer that also links
  that CBOR library can end up with symbols bound across two copies of
  it. Giving them hidden visibility is tracked as follow-up work.
