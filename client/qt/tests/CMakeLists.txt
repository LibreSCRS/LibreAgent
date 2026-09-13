# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# --- the one target in this directory a consumer may ask for ----------------
#
# The in-process agent doubles are a component of this package, not a test: the
# D-Bus FakeAgent, the socket FakeSocketAgent, and the two-connection Harness
# that stands either of them up on a private bus. A desktop host driving this
# client library needs the same double this library's own suite drives -- a
# host that keeps its own copy ends up with a second, drifting understanding of
# one bus surface, and a green suite on each side of the drift.
#
# Defined ABOVE the top-level guard on purpose, exactly like the fixture
# archive in tests/CMakeLists.txt: a consumer pulls this repository in as a
# subproject, so PROJECT_IS_TOP_LEVEL is false for it, and a target that only
# ever comes into existence inside a block the consumer never enters would
# leave LibreAgent::ClientQtTestSupport undefined and the consumer unable to
# link.
if(PROJECT_IS_TOP_LEVEL OR LIBREAGENT_BUILD_CLIENT_QT_TEST_SUPPORT)
    # Marshal.cpp and MemfdSource.cpp are INTERNAL, hidden-visibility TUs of
    # the client library: their symbols are not resolvable from the installed
    # .so, so the doubles that call them carry them here. This repository's own
    # suites keep compiling their own copies of those TUs (see the D-Bus and
    # socket blocks below); a static archive member is pulled only for a symbol
    # nothing else defines, so the two never collide.
    # The D-Bus half of the doubles is Linux-only, for the same reason the root
    # CMakeLists.txt only looks for Qt6::DBus there: D-Bus is LibreLinux's
    # transport. Listing FakeAgent/TestBus/Marshal unconditionally made this
    # target -- and therefore the whole configure -- require a Qt6::DBus that is
    # never found off Linux, so the macOS client leg could not configure at all:
    # "Target ClientQtTestSupport links to Qt6::DBus but the target was not
    # found". Nothing had noticed because that leg has never run.
    set(clientqt_testsupport_sources
        fakes/FakeSocketAgent.cpp
        fakes/FakeSocketAgent.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/MemfdSource.cpp)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND clientqt_testsupport_sources
            fakes/FakeAgent.cpp
            fakes/FakeAgent.h
            fakes/TestBus.h
            ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/Marshal.cpp)
    endif()
    add_library(ClientQtTestSupport STATIC ${clientqt_testsupport_sources})
    add_library(LibreAgent::ClientQtTestSupport ALIAS ClientQtTestSupport)
    set_target_properties(ClientQtTestSupport PROPERTIES
        AUTOMOC ON
        EXPORT_NAME ClientQtTestSupport
        # The archive lands in a shared libdir, so it carries the project's
        # own prefix there rather than the bare target name.
        OUTPUT_NAME librescrs-agentclient-qt-testsupport
        POSITION_INDEPENDENT_CODE ON)
    # BUILD_INTERFACE/INSTALL_INTERFACE split: an exported target whose PUBLIC
    # include directory is an absolute path into this source tree generates a
    # Targets.cmake naming a directory the consumer does not have. The single
    # installed root carries dbus/ and socket/ subdirectories, so the quoted
    # includes inside these headers resolve there unchanged.
    target_include_directories(ClientQtTestSupport PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/fakes>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentClientTestSupport>)
    # GTest is PUBLIC because TestBus.h asserts with EXPECT_TRUE in the harness
    # constructor -- a consumer of that header compiles gtest into its own TU.
    # Qt6::Test supplies QSignalSpy to the same header set; Qt6::DBus is the
    # bus the D-Bus double is a peer on; LibreAgent::Wire is the framing the
    # socket double speaks.
    target_link_libraries(ClientQtTestSupport PUBLIC
        LibreAgent::ClientQt
        LibreAgent::Wire
        Qt6::Core
        Qt6::Test
        GTest::gtest)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(ClientQtTestSupport PUBLIC Qt6::DBus)
    endif()
    target_compile_features(ClientQtTestSupport PUBLIC cxx_std_23)

    # Installing and exporting the component is gated on the OPTION, not merely
    # on being top level -- the same lesson the fixture archive already carries:
    # gating on top level alone makes the switch a lie, because an agent
    # configured with the doubles explicitly turned off still ships the
    # Targets.cmake that lets a consumer find them.
    if(PROJECT_IS_TOP_LEVEL AND LIBREAGENT_BUILD_CLIENT_QT_TEST_SUPPORT)
        include(GNUInstallDirs)
        install(TARGETS ClientQtTestSupport
            EXPORT LibreAgentClientQtTestSupportTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(FILES
                fakes/FakeAgent.h
                fakes/FakeSocketAgent.h
                fakes/TestBus.h
                fakes/FakeCertFields.h
                fakes/FakeConfig.h
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/ConfigKeys.h
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/CscaAnchorKeys.h
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/TransportSeam.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentClientTestSupport)
        # The six internal headers below are not public client surface and are
        # installed HERE, under this component's own root, rather than beside
        # the client's installed headers: the doubles include them by the same
        # quoted paths the in-tree build uses, and a consumer of the doubles is
        # the only consumer that ever sees them.
        install(FILES
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/Marshal.h
                ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/AgentDBus.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentClientTestSupport/dbus)
        install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/MemfdSource.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentClientTestSupport/socket)
        install(EXPORT LibreAgentClientQtTestSupportTargets
            FILE LibreAgentClientQtTestSupportTargets.cmake
            NAMESPACE LibreAgent::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibreAgent)
    endif()
endif()

# Everything below is this repository's own test suite. A consumer that asked
# for the doubles above does not inherit a foreign test package: entering this
# directory must not register a single ctest target in the consumer's build.
if(PROJECT_IS_TOP_LEVEL)

# FdHandle's move-only RAII contract + default-value sanity for the plain
# value-type aggregates. Links the real LibreAgentClientQt shared library --
# FdHandle IS exported (LIBRESCRS_AGENTCLIENT_EXPORT), so its symbols are
# visible in the .so's dynamic symbol table despite the target's hidden
# CXX_VISIBILITY_PRESET.
add_executable(ClientQtTypesTest TypesTest.cpp)
target_link_libraries(ClientQtTypesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtTypesTest COMMAND ClientQtTypesTest)

# The annex reading order, which two desktop hosts used to each keep their own
# byte-identical copy of. Exported from the shared library, so this links it.
add_executable(ClientQtFieldOrderTest FieldOrderTest.cpp)
target_link_libraries(ClientQtFieldOrderTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtFieldOrderTest COMMAND ClientQtFieldOrderTest)

# The two-shape card-date rule, which both desktop hosts used to write out for
# themselves. Exported from the shared library, so this links it.
add_executable(ClientQtCardDateTest CardDateTest.cpp)
target_link_libraries(ClientQtCardDateTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtCardDateTest COMMAND ClientQtCardDateTest)

# The security vocabulary's decoders, which used to live in a desktop host
# where nothing tested them.
add_executable(ClientQtSecurityVocabularyTest SecurityVocabularyTest.cpp)
target_link_libraries(ClientQtSecurityVocabularyTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtSecurityVocabularyTest COMMAND ClientQtSecurityVocabularyTest)

# TokenMap round-trip coverage. TokenMap.{h,cpp} is an INTERNAL, hidden-
# visibility TU with no export macro on any of its functions -- linking the
# shared library would not resolve its symbols. Compiling TokenMap.cpp
# directly into this test executable (a second, independent object file
# from the one folded into LibreAgentClientQt.so) is the standard way to
# unit-test a library's non-exported internals; still links
# LibreAgent::ClientQt for its public include dirs + Qt6::Core (SignOptions.h,
# which TokenMap.h depends on for the four enum types).
add_executable(ClientQtTokenMapTest
    TokenMapTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/TokenMap.cpp)
target_link_libraries(ClientQtTokenMapTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtTokenMapTest COMMAND ClientQtTokenMapTest)

# Adapted from the KDE client's FakeAgent-free suite: the pure capability /
# UI-state resolvers plus the new public token vocabulary. Links the shared
# library (everything tested is a public inline/constexpr header surface).
add_executable(ClientQtCapabilitiesTest AgentCapabilitiesTest.cpp)
target_link_libraries(ClientQtCapabilitiesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtCapabilitiesTest COMMAND ClientQtCapabilitiesTest)

# The credential record/result parsers (public, exported) including the
# contract-verbatim key-set drift guard and the extra pass-through.
add_executable(ClientQtCredentialTypesTest CredentialTypesTest.cpp)
target_link_libraries(ClientQtCredentialTypesTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtCredentialTypesTest COMMAND ClientQtCredentialTypesTest)

# The structural identity-row flatten (public, exported): skip-binary /
# stringify / empty-retained rules over the canonical Field::extra keys.
add_executable(ClientQtIdentityRowsTest IdentityRowsTest.cpp)
target_link_libraries(ClientQtIdentityRowsTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtIdentityRowsTest COMMAND ClientQtIdentityRowsTest)

# The verdict-group reader (public, exported): one entry per security check,
# both wire spellings of a check, and the aggregate verdicts carried through
# untouched. Owned here because BOTH desktop clients render this group -- a
# private reader in each is how three incompatible understandings of the same
# fields came to be live at once, each with its own passing test.
add_executable(ClientQtSecurityChecksTest SecurityChecksTest.cpp)
target_link_libraries(ClientQtSecurityChecksTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtSecurityChecksTest COMMAND ClientQtSecurityChecksTest)

# ConfigKeys.h's isSettableConfigKey() mirror, checked in both directions
# against the published `settable-config-key` vocabulary in
# wire/wire-vocabulary.json -- see ConfigKeyMirrorTest.cpp for why neither
# direction alone is sufficient. ConfigKeys.h is INTERNAL (src/, never
# installed), so this needs the -I src include path like the other
# internal-header suites in this file; it is header-only (inline functions),
# so no extra TU has to be compiled in alongside it. The manifest path is
# handed in as a compile definition rather than copied into the test tree, so
# this reads the one committed copy of the file.
add_executable(ClientQtConfigKeyMirrorTest ConfigKeyMirrorTest.cpp)
target_include_directories(ClientQtConfigKeyMirrorTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtConfigKeyMirrorTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
target_compile_definitions(ClientQtConfigKeyMirrorTest PRIVATE
    LIBRESCRS_AGENT_WIRE_VOCABULARY_JSON="${CMAKE_SOURCE_DIR}/wire/wire-vocabulary.json"
    # The header itself, so the probe list below can be checked for completeness
    # rather than trusted. A probe list that silently misses a constant would
    # reintroduce, one level down, the drift this whole test exists to catch.
    LIBRESCRS_AGENT_CONFIG_KEYS_HEADER="${CMAKE_CURRENT_SOURCE_DIR}/../src/ConfigKeys.h")
add_test(NAME ClientQtConfigKeyMirrorTest COMMAND ClientQtConfigKeyMirrorTest)

# The bounded fd-payload reader (public, exported -- so this links the shared
# library rather than recompiling the TU, unlike the internal-TU suites above
# and below). Covers the three-state descriptor contract, the byte cap and its
# exact boundary, and the empty-versus-failure distinction. The seal-shape
# cases are guarded inside the source by __linux__, not here: the cap, the
# empty case and the ordinary-file case are portable and must run on every
# platform this component builds on.
add_executable(ClientQtSealedPayloadTest SealedPayloadTest.cpp)
target_link_libraries(ClientQtSealedPayloadTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtSealedPayloadTest COMMAND ClientQtSealedPayloadTest)

# The bounded reader's two internal decision helpers. They carry branches the
# public entry point cannot reach on a sane kernel -- a negative reported size,
# and a premature end of file mid-read -- so they are driven directly here.
# Neither is exported (no export macro, hidden visibility), so
# SealedPayloadInternal.cpp is compiled straight into this executable, the same
# pattern TokenMapTest and ErrorNameMapTest already use for this library's other
# non-exported internals; it still links LibreAgent::ClientQt for the public
# include dirs + Qt6::Core.
#
# It compiles SealedPayloadInternal.cpp and NOT SealedPayload.cpp, which is why
# the sentence above is true rather than approximately true: SealedPayload.cpp
# is a mixed TU carrying the exported readBoundedPayload(), so pulling it in
# here would give this executable its own definition of a symbol the linked
# shared library also exports -- harmless in practice, but a duplicate
# definition that no reader should have to discover with nm. The two helpers
# were split into their own pure-internal TU precisely so this target defines
# zero exported symbols, exactly like the two it claims kinship with.
add_executable(ClientQtSealedPayloadInternalTest
    SealedPayloadInternalTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/SealedPayloadInternal.cpp)
target_include_directories(ClientQtSealedPayloadInternalTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtSealedPayloadInternalTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtSealedPayloadInternalTest COMMAND ClientQtSealedPayloadInternalTest)

# The public API driven over a minimal in-process TransportSeam fake (not the
# FakeAgent): request mapping, entry refusal, terminal recovery, availability
# sweeps. Needs the INTERNAL seam headers (-I src) and the exported
# ClientTestAccess factory; runs under a QCoreApplication main because the
# queued terminal emits deliver through the event loop.
add_executable(ClientQtSeamTest
    SeamMappingTest.cpp
    ClientTestMain.cpp)
target_include_directories(ClientQtSeamTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtSeamTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest)
add_test(NAME ClientQtSeamTest COMMAND ClientQtSeamTest)

# The D-Bus error-name -> CallError/ErrorCode mapping table. ErrorNameMap.cpp
# is an INTERNAL, hidden-visibility TU (no export macro), so it is compiled
# directly into this test executable -- the same pattern as TokenMapTest
# above. Pure string classification: no bus, no QtDBus types.
add_executable(ClientQtErrorNameMapTest
    ErrorNameMapTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/ErrorNameMap.cpp)
target_include_directories(ClientQtErrorNameMapTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus)
target_link_libraries(ClientQtErrorNameMapTest PRIVATE
    LibreAgent::ClientQt
    LibreAgent::Wire
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtErrorNameMapTest COMMAND ClientQtErrorNameMapTest)

# The sync-error AXIS of that same table: which failures carry a named wire
# error onward and which carry none. Its own target rather than more cases in
# ErrorNameMapTest.cpp, so that file stays the untouched proof that the
# CallError/ErrorCode mapping did not move. Same internal-TU compilation as
# above; LibreAgent::Wire is an explicit link because the table now calls the
# wire library's own name decoder (the shared library happens to re-export
# Wire's symbols today, but relying on that would make this target break
# silently the day Wire gains a visibility preset).
add_executable(ClientQtSyncErrorTest
    SyncErrorTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/ErrorNameMap.cpp)
target_include_directories(ClientQtSyncErrorTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus)
target_link_libraries(ClientQtSyncErrorTest PRIVATE
    LibreAgent::ClientQt
    LibreAgent::Wire
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtSyncErrorTest COMMAND ClientQtSyncErrorTest)

# The token-keyed DER-listener registration bookkeeping (the fix for the
# cancel + listener-pointer-reuse race that used to silently drop a second
# operation's delivery forever): pure QHash/QSet logic, no D-Bus, no event
# loop -- the cheapest layer where remove-by-identity vs remove-by-token is
# directly assertable. Needs the INTERNAL seam headers (-I src) for
# TransportSeam::DerListener.
add_executable(ClientQtDerListenerRegistryTest DerListenerRegistryTest.cpp)
target_include_directories(ClientQtDerListenerRegistryTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(ClientQtDerListenerRegistryTest PRIVATE
    LibreAgent::ClientQt
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtDerListenerRegistryTest COMMAND ClientQtDerListenerRegistryTest)

# D-Bus integration tests: a REAL DBusTransport driven against an in-process
# FakeAgent (fakes/FakeAgent.{h,cpp}, lifted from the KDE client's own
# FakeAgent + scrubbed) on a PRIVATE session bus. Each binary runs under
# dbus-run-session, which gives each suite an isolated session bus (standard
# ctest wrapper pattern in this project), headless (QT_QPA_PLATFORM=offscreen).
# Linux-only, matching the Linux-only Qt6::DBus dependency (client/qt/
# CMakeLists.txt's own DBusTransport.cpp block, and the root CMakeLists.txt's
# find_package(Qt6 ...) split -- Qt6::DBus is never found on a non-Linux
# configuration, so this whole block would fail to configure there).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # DBusTransport.{h,cpp} (+ its CappedCall/ErrorNameMap/Marshal dependencies)
    # are INTERNAL, hidden-visibility TUs with no export macro -- linking
    # LibreAgent::ClientQt would not resolve their symbols outside the .so.
    # Compiling them directly into each test executable is the same pattern
    # TokenMapTest/ErrorNameMapTest already use for the library's other
    # non-exported internals (a second, independent set of object files from
    # the ones folded into LibreAgentClientQt.so). Qt6::DBus is PRIVATE on the
    # library target, so a test driving the fake's own D-Bus surface links it
    # directly; Qt6::Test supplies QSignalSpy.
    find_program(DBUS_RUN_SESSION dbus-run-session REQUIRED)

    set(_client_dbus_transport_src
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/CappedCall.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/DBusTransport.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/DBusTransport.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/ErrorNameMap.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/Marshal.cpp)
    set(_fake_agent_src fakes/FakeAgent.h fakes/FakeAgent.cpp)

    function(libreagent_add_client_dbus_test name source)
        add_executable(${name} ${source} ${_fake_agent_src} ${_client_dbus_transport_src} ClientTestMain.cpp)
        set_target_properties(${name} PROPERTIES AUTOMOC ON)
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
        # LibreAgent::Wire: ErrorNameMap.cpp (in the source list above) calls
        # the wire library's sync-error name decoder, so every target that
        # compiles that TU must link it rather than lean on the shared library
        # happening to re-export Wire's symbols.
        target_link_libraries(${name} PRIVATE
            LibreAgent::ClientQt
            LibreAgent::Wire
            Qt6::DBus
            Qt6::Test
            GTest::gtest)
        add_test(NAME ${name} COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:${name}>)
        # A wedged test under dbus-run-session must fail in minutes, not consume the runner's whole wall.
        set_tests_properties(${name} PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
    endfunction()

    # Adapted from the lifted KDE suites of the same name (see fakes/FakeAgent.h's
    # file comment): AgentCard/AgentReader typed proxies, ObjectManager discovery
    # + live add/remove + availability, and AgentOperation's Finished/Result race
    # + recovery + Cancel(), all now mediated through AgentClient (AgentCard has
    # no public constructor in the scrubbed API).
    # Moved here from the KDE client, whose own copy of this fake it pinned.
    # The ctest name is deliberately NOT given this directory's ClientQt prefix:
    # the proof that the case travelled rather than being rewritten is a diff of
    # the two repositories' ctest listings, and a rename would turn that diff
    # into "one gone, one new" and hide whatever else moved with it.
    libreagent_add_client_dbus_test(FakeAgentWireShapeTest FakeAgentWireShapeTest.cpp)

    libreagent_add_client_dbus_test(ClientQtAgentCardTest AgentCardTest.cpp)
    libreagent_add_client_dbus_test(ClientQtAgentDiscoveryTest AgentDiscoveryTest.cpp)
    libreagent_add_client_dbus_test(ClientQtAgentOperationTest AgentOperationTest.cpp)

    # The end-to-end corpus: availability appear/vanish, discovery, identity,
    # photo content-hash round trip, certificates, sign (typed options ->
    # wire dict, fd in/out), credentials list/manage/re-list, cancel, the op-stall
    # contract, and lost-Result recovery when Finished fires before the subscriber.
    libreagent_add_client_dbus_test(ClientQtDBusIntegrationTest DBusIntegrationTest.cpp)

    # Pins the typed Result D-Bus signatures to the frozen agent XML -- no bus
    # needed (QDBusMetaType::typeToSignature works off the registered type alone),
    # so NOT run under dbus-run-session, and needs only Marshal.cpp (no transport).
    add_executable(ClientQtAgentResultSignatureTest
        AgentResultSignatureTest.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/Marshal.cpp)
    target_include_directories(ClientQtAgentResultSignatureTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(ClientQtAgentResultSignatureTest PRIVATE
        LibreAgent::ClientQt
        Qt6::DBus
        GTest::gtest
        GTest::gtest_main)
    add_test(NAME ClientQtAgentResultSignatureTest COMMAND ClientQtAgentResultSignatureTest)

    # The process-wide shared-client accessor. Links ONLY the shared library:
    # sharedAgentClient() and the AgentClient constructor behind it are both
    # exported public surface, so unlike the suites above nothing internal has
    # to be recompiled into this executable, and no fake is involved. Runs
    # under dbus-run-session because that constructor builds this platform's
    # default transport, which touches the session bus -- hence its place
    # inside this Linux-gated block, beside the other bus-touching targets and
    # after the find_program that resolves the wrapper. ClientTestMain.cpp
    # supplies the QCoreApplication the transport expects.
    add_executable(ClientQtSharedAgentClientTest SharedAgentClientTest.cpp ClientTestMain.cpp)
    target_link_libraries(ClientQtSharedAgentClientTest PRIVATE
        LibreAgent::ClientQt
        GTest::gtest)
    add_test(NAME ClientQtSharedAgentClientTest
        COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:ClientQtSharedAgentClientTest>)
    set_tests_properties(ClientQtSharedAgentClientTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif() # CMAKE_SYSTEM_NAME STREQUAL "Linux"

# Socket integration tests: the REAL SocketTransport driven against an
# in-process FakeSocketAgent on a temp AF_UNIX path. Most of the suite needs
# no bus -- the whole wire is this repo's own framing + canonical CBOR
# (LibreAgent::Wire) -- but the production-ctor cases build a real
# AgentClient, which on Linux constructs a DBusTransport and touches the
# session bus, same as ClientQtSharedAgentClientTest above; hence the
# dbus-run-session wrap on Linux below. Linux + Darwin gated: the fake's
# document/artifact source (src/socket/MemfdSource.{h,cpp}) has a real
# backend on both — memfd_create on Linux, mkstemp + unlink on Darwin (see
# that file) — but no portable fallback beyond them, so this stays gated
# rather than unconditional. The transport TU itself compiles into the
# library on every platform. SocketTransport/SocketPath/ErrorNameMap are
# INTERNAL, hidden-visibility TUs — compiled directly into the test
# executable, the same pattern as the D-Bus suites above.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_executable(ClientQtSocketIntegrationTest
        SocketIntegrationTest.cpp
        fakes/FakeSocketAgent.h
        fakes/FakeSocketAgent.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/dbus/ErrorNameMap.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/MemfdSource.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketPath.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketTransport.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketTransport.h
        ClientTestMain.cpp)
    set_target_properties(ClientQtSocketIntegrationTest PROPERTIES AUTOMOC ON)
    target_include_directories(ClientQtSocketIntegrationTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(ClientQtSocketIntegrationTest PRIVATE
        LibreAgent::ClientQt
        LibreAgent::Wire
        GTest::gtest)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # See the file comment above: a production AgentClient here builds a
        # DBusTransport, which needs a session bus to connect to.
        add_test(NAME ClientQtSocketIntegrationTest
            COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:ClientQtSocketIntegrationTest>)
    else()
        add_test(NAME ClientQtSocketIntegrationTest COMMAND ClientQtSocketIntegrationTest)
    endif()
    # The real SocketTransport wedges the same way a real DBusTransport does -- same ceiling.
    set_tests_properties(ClientQtSocketIntegrationTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif()

# Transport parity suite: ONE shared gtest-typed-test scenario corpus
# (identity, photo, certificates, sign, credentials list/manage/re-list,
# cancel, method-entry refusal, agent-loss mid-op, availability appear/
# vanish) run twice -- once over the REAL DBusTransport + FakeAgent, once
# over the REAL SocketTransport + FakeSocketAgent -- asserting identical
# client-visible outcomes. Needs both fakes and both transports in ONE
# binary, so it reuses the D-Bus sources/fake list assembled above
# (_fake_agent_src / _client_dbus_transport_src) plus the socket sources the
# block above compiles directly. The whole binary runs under
# dbus-run-session (only the D-Bus half needs the bus; the socket half is
# unaffected by the private session). Linux-gated, matching both halves'
# own Linux-only gates above.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ClientQtTransportParityTest
        TransportParityTest.cpp
        ${_fake_agent_src}
        ${_client_dbus_transport_src}
        fakes/FakeSocketAgent.h
        fakes/FakeSocketAgent.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/MemfdSource.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketPath.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketTransport.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/socket/SocketTransport.h
        ClientTestMain.cpp)
    set_target_properties(ClientQtTransportParityTest PROPERTIES AUTOMOC ON)
    target_include_directories(ClientQtTransportParityTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_link_libraries(ClientQtTransportParityTest PRIVATE
        LibreAgent::ClientQt
        LibreAgent::Wire
        Qt6::DBus
        GTest::gtest)
    add_test(NAME ClientQtTransportParityTest COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:ClientQtTransportParityTest>)
    set_tests_properties(ClientQtTransportParityTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 120)
endif()

# The header-self-sufficiency / no-Qt-DBus-KF6-LM-QCBOR-leak acceptance
# harness -- its own subdirectory, see that CMakeLists.txt.
add_subdirectory(HeaderAcceptance)

# The shipped library must export NOTHING from the vendored CBOR library it
# folds in. ELF resolves an unmangled C name process-wide by first definition,
# so exporting those names lets a process that also carries its own copy
# cross-bind the two -- on the path that decodes data coming off a card. The
# check reads the real built library's dynamic symbol table, so it is a
# statement about the artifact rather than about the source that produced it.
#
# ...and nothing from the wire library it folds in either, beyond the two
# functions a public client header re-exports. Same mechanism, different
# hazard: mangled C++ names cannot cross-bind, they are ABI surface a consumer
# can bind to and no gate would watch. That one asserts BOTH directions -- the
# two present, the rest of the namespace absent -- because a hidden-visibility
# preset would otherwise pass it by hiding the API along with everything else.
#
# The vendored check is ELF-only by nature: Mach-O records the defining library
# in each reference (two-level namespace), so that hazard does not exist there.
# The wire one is gated only because it reads ELF `nm` output.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME ClientQtVendoredExportsTest
             COMMAND ${PROJECT_SOURCE_DIR}/ci/scripts/check-vendored-exports.sh
                     $<TARGET_FILE:LibreAgentClientQt>)
    add_test(NAME ClientQtWireExportsTest
             COMMAND ${PROJECT_SOURCE_DIR}/ci/scripts/check-wire-exports.sh
                     $<TARGET_FILE:LibreAgentClientQt>)
endif()

endif() # PROJECT_IS_TOP_LEVEL -- this repository's own test suite
