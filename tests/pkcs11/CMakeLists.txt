# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Tests for the PKCS#11 facade and its socket transport. Reachable in a
# Core-less configuration on purpose: the facade must be buildable and testable
# in exactly the shape it ships in, with no card stack and no crypto library in
# the tree.
find_package(GTest REQUIRED)

# The Qt-free agent double. It is a compiled library rather than a header
# included per suite so that the suites cannot each end up with their own
# slightly different copy of it.
add_library(LibreAgentPkcs11TestFake STATIC ${CMAKE_CURRENT_SOURCE_DIR}/../fakes/FakeSocketAgent.cpp)
target_include_directories(LibreAgentPkcs11TestFake PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(LibreAgentPkcs11TestFake PUBLIC LibreAgent::Wire)
target_compile_features(LibreAgentPkcs11TestFake PUBLIC cxx_std_23)
set_target_properties(LibreAgentPkcs11TestFake PROPERTIES POSITION_INDEPENDENT_CODE ON)

function(agent_pkcs11_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE
        LibreAgentPkcs11TestFake
        LibreAgent::Pkcs11Facade
        GTest::gtest
        GTest::gtest_main)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# A double that stopped resembling an agent takes every suite that uses it with
# it, quietly, so it has a suite of its own.
agent_pkcs11_test(FakeSocketAgentTest)

if(LIBREAGENT_BUILD_PKCS11_SOCKET_CLIENT)
    # The module itself. The shared core had no module of its own, so the two
    # properties a loader cares about -- what it can see, and what it must find
    # first -- were only ever checked on one platform backend's build. Building
    # one here gives the C-ABI suites a real file to open.
    add_library(librescrs-pkcs11-agent MODULE TestSocketAgentClientFactory.cpp)
    set_target_properties(librescrs-pkcs11-agent PROPERTIES
        PREFIX ""
        OUTPUT_NAME "librescrs-pkcs11-agent")
    target_link_libraries(librescrs-pkcs11-agent PRIVATE LibreAgent::Pkcs11SocketClient)
    # Never by bare name: that builds and installs a module with no entry point.
    librescrs_pkcs11_module_link(librescrs-pkcs11-agent)

    # The suites that dlopen it.
    function(agent_pkcs11_module_test name)
        agent_pkcs11_test(${name})
        target_link_libraries(${name} PRIVATE ${CMAKE_DL_LIBS})
        target_compile_definitions(${name} PRIVATE
            LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11-agent>")
        add_dependencies(${name} librescrs-pkcs11-agent)
    endfunction()

    agent_pkcs11_test(SocketAgentClientTest)
    target_link_libraries(SocketAgentClientTest PRIVATE LibreAgent::Pkcs11SocketClient)
    # A human-paced login is parked behind a delay longer than the public-data
    # budget on purpose; the suite must outlive that, and only that.
    set_tests_properties(SocketAgentClientTest PROPERTIES TIMEOUT 180)

    agent_pkcs11_test(SnapshotParityTest)
    target_link_libraries(SnapshotParityTest PRIVATE LibreAgent::Pkcs11SocketClient)

    # The shared client contract, instantiated over this transport. The claims
    # come from the INSTALLED header (Pkcs11Facade carries include/ as an
    # interface property), which is the same path the other host's tree reaches
    # them by -- so this target also proves that path resolves inside this
    # project, where a break is cheap to see.
    agent_pkcs11_test(SocketAgentClientContractTest)
    target_link_libraries(SocketAgentClientContractTest PRIVATE LibreAgent::Pkcs11SocketClient)

    # --- suites that arrived with the core they cover -----------------------
    # Pure slot/token/object/mechanism mapping. No socket, no module, no card:
    # it compiled the mapping source directly where it used to live, and links
    # the component that carries it now.
    agent_pkcs11_test(ObjectModelTest)

    # dlopen the built module and exercise the C ABI surface standalone.
    agent_pkcs11_module_test(LoadModuleTest)

    # Full C_* ABI driven against the built module + the socket double.
    agent_pkcs11_module_test(ModuleAbiTest)
    target_link_libraries(ModuleAbiTest PRIVATE LibreAgent::Pkcs11SocketClient)
    # Higher ceiling than the default used elsewhere here: this suite is
    # deliberately slow. One case parks a signature behind a 27 s delay to ride
    # past the budget a single-deadline client would have used, and two more add
    # 3 s and 2 s, so the floor is already around 33 s.
    set_tests_properties(ModuleAbiTest PROPERTIES TIMEOUT 180)

    # Module-side security properties (no-PIN-on-wire, mechanism rejection,
    # non-extractable keys, capability gating) over the real C_* ABI.
    agent_pkcs11_module_test(SecurityTest)
    set_tests_properties(SecurityTest PROPERTIES TIMEOUT 120)

    # Env-gated MANUAL real-card smoke. Talks to the LIVE agent + card; skips
    # entirely unless LIBRESCRS_HW_SMOKE=1, so it never blocks a CI run and
    # never burns a card retry counter. This TU is libcrypto-FREE by policy.
    agent_pkcs11_module_test(RealCardSmokeTest)

    # The libcrypto-LINKING companion: same hardware gate, same PIN latch, but
    # it does the real arithmetic. Kept a separate TU on purpose.
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    agent_pkcs11_module_test(RealCardCryptoVerifyTest)
    target_link_libraries(RealCardCryptoVerifyTest PRIVATE OpenSSL::Crypto)

    # RPC integration: drive the EXTERNAL consumer pkcs11-tool against the real
    # module with the socket double as the card backend. A suite that only ever
    # drives the ABI from inside this tree cannot show that a stranger's loader
    # can open the file.
    add_executable(FakeSocketAgentMain FakeSocketAgentMain.cpp)
    target_link_libraries(FakeSocketAgentMain PRIVATE LibreAgentPkcs11TestFake)
    add_dependencies(FakeSocketAgentMain librescrs-pkcs11-agent)

    add_test(NAME Pkcs11ToolRpcSocketTest
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_tool_rpc_socket.sh
                $<TARGET_FILE:FakeSocketAgentMain> $<TARGET_FILE:librescrs-pkcs11-agent>)
    set_tests_properties(Pkcs11ToolRpcSocketTest PROPERTIES
        SKIP_RETURN_CODE 77
        TIMEOUT 120)
endif()
