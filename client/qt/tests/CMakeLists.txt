# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

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
        set_tests_properties(${name} PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    endfunction()

    # Adapted from the lifted KDE suites of the same name (see fakes/FakeAgent.h's
    # file comment): AgentCard/AgentReader typed proxies, ObjectManager discovery
    # + live add/remove + availability, and AgentOperation's Finished/Result race
    # + recovery + Cancel(), all now mediated through AgentClient (AgentCard has
    # no public constructor in the scrubbed API).
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
    set_tests_properties(ClientQtSharedAgentClientTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif() # CMAKE_SYSTEM_NAME STREQUAL "Linux"

# Socket integration tests: the REAL SocketTransport driven against an
# in-process FakeSocketAgent on a temp AF_UNIX path. No bus, no
# dbus-run-session — the whole wire is this repo's own framing + canonical
# CBOR (LibreAgent::Wire), so the suite also runs on a D-Bus-less
# configuration. Linux-gated for now because the fake's document/artifact
# source is memfd_create (src/socket/MemfdSource.{h,cpp}, the Linux-test-only
# helper); the transport TU itself compiles into the library on every
# platform. SocketTransport/SocketPath/ErrorNameMap are INTERNAL,
# hidden-visibility TUs — compiled directly into the test executable, the
# same pattern as the D-Bus suites above.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
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
    add_test(NAME ClientQtSocketIntegrationTest COMMAND ClientQtSocketIntegrationTest)
    set_tests_properties(ClientQtSocketIntegrationTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
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
    set_tests_properties(ClientQtTransportParityTest PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
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
