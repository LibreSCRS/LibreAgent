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
    GTest::gtest
    GTest::gtest_main)
add_test(NAME ClientQtErrorNameMapTest COMMAND ClientQtErrorNameMapTest)

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
        target_link_libraries(${name} PRIVATE
            LibreAgent::ClientQt
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
