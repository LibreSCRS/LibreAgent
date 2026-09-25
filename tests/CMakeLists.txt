# SPDX-License-Identifier: LGPL-2.1-or-later

# --- the one target in this directory a consumer may ask for ----------------
#
# The synthetic master-list fixture is a component of this package, not a test.
# The platform backend needs exactly this fixture to drive its own D-Bus import
# test, and used to carry a byte-identical copy of it; it now links this one.
#
# It is defined ABOVE the top-level guard on purpose. A consumer pulls this
# repository in as a subproject, so PROJECT_IS_TOP_LEVEL is false for it, and a
# switch that only ever turned on inside a block the consumer never enters
# would leave LibreAgent::TestSupport undefined and the consumer unable to
# link — which is the shape this replaces, not a fix for it.
if(LIBREAGENT_BUILD_CORE AND (PROJECT_IS_TOP_LEVEL OR LIBREAGENT_BUILD_TEST_SUPPORT))
    # The fixture mints its certificates with the system OpenSSL directly.
    # That dependency is the fixture's alone: the code under test consumes only
    # the published LibreMiddleware trust API.
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

    add_library(SyntheticMasterList STATIC SyntheticMasterList.cpp)
    add_library(LibreAgent::TestSupport ALIAS SyntheticMasterList)
    set_target_properties(SyntheticMasterList PROPERTIES
        EXPORT_NAME TestSupport
        POSITION_INDEPENDENT_CODE ON)
    # BUILD_INTERFACE/INSTALL_INTERFACE split: an exported target whose PUBLIC
    # include directory is an absolute path into this source tree generates a
    # Targets.cmake naming a directory the consumer does not have.
    target_include_directories(SyntheticMasterList PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentTestSupport>)
    target_link_libraries(SyntheticMasterList PUBLIC OpenSSL::Crypto)
    target_compile_features(SyntheticMasterList PUBLIC cxx_std_23)

    # Installing and exporting the component is gated on the OPTION, not merely
    # on being top level. Gating it on top level alone makes the switch a lie:
    # an agent configured with the fixture explicitly turned off still shipped
    # LibreAgentTestSupportTargets.cmake, so a consumer that named the
    # component found it and the refusal this component exists to make could
    # not happen. Measured that way before it was written this way.
    #
    # The TARGET above stays reachable regardless, because this repository's
    # own anchor-import test links it and must keep building with the export
    # turned off.
    if(PROJECT_IS_TOP_LEVEL AND LIBREAGENT_BUILD_TEST_SUPPORT)
        include(GNUInstallDirs)
        install(TARGETS SyntheticMasterList
            EXPORT LibreAgentTestSupportTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(FILES SyntheticMasterList.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentTestSupport)
        install(EXPORT LibreAgentTestSupportTargets
            FILE LibreAgentTestSupportTargets.cmake
            NAMESPACE LibreAgent::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibreAgent)
    endif()
endif()

# Everything below is this repository's own test suite. A consumer that asked
# for the fixture does not inherit a foreign test package: that is what the
# top-level guard around this directory used to buy, and it is kept here now
# that the directory itself is reachable from a subproject build.
# BUILD_TESTING as well as the top-level check. include(CTest) in the root file
# defines it and defaults it ON, so a developer build is unchanged; a
# distribution package is built with it OFF and now stops here, having defined
# the fixture archive above and nothing else. That is worth having twice over:
# a package build was compiling seven hundred targets it would never run, and on
# Ubuntu 26.04 with gcc 15 two of those test executables fail to link against
# libstdc++ symbols -- in code the package does not ship.
if(NOT PROJECT_IS_TOP_LEVEL OR NOT BUILD_TESTING)
    return()
endif()

find_package(GTest REQUIRED)

# Dependency-free wire-header compile guard (no LibreAgent::Core link, no LM
# on its include path) — see tests/wire/CMakeLists.txt.
add_subdirectory(wire)

# SCM_RIGHTS + memfd fd-passing spike (early de-risk for the macOS client's
# AF_UNIX transport) — pure POSIX, no LibreAgent::Core, no Qt. Temporary
# location: adopted by the client transport tests once that work lands. See
# tests/spike/CMakeLists.txt and tests/spike/ScmRightsSpikeTest.cpp.
add_subdirectory(spike)

# The PKCS#11 facade's own suites. Above the LIBREAGENT_BUILD_CORE gate below,
# because the facade has to be testable in the Core-less configuration it ships
# in -- a suite that only ever runs alongside the card stack cannot show that
# the module does not need it.
if(LIBREAGENT_BUILD_PKCS11_FACADE)
    add_subdirectory(pkcs11)
endif()

# Everything below this point links LibreAgent::Core (directly, or via a flow
# TU folded into it) and is therefore only reachable in a LIBREAGENT_BUILD_CORE
# configuration — see the caller (root CMakeLists.txt) which now also
# add_subdirectory()s here whenever LIBREAGENT_BUILD_WIRE alone is on, purely
# to reach tests/wire/ and tests/spike/ above.
if(LIBREAGENT_BUILD_CORE)

# All tests here are platform-neutral: they link only LibreAgent::Core + the
# shared fakes under tests/fakes/ (the five backend doubles). No private session
# bus, no wire-XML codegen, no polkit, no hardware — the D-Bus/backend tests stay
# in the platform backend (LibreLinux).
function(agent_core_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE
        LibreAgent::Core
        GTest::gtest
        GTest::gtest_main)
    # ${CMAKE_CURRENT_SOURCE_DIR} makes "fakes/Fake*.h" and the local
    # Pkcs11BrokerTestSupport.h resolvable from every test TU.
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# Compile-and-behaviour lock for the five shared fakes.
agent_core_test(AddressedCancelTest)
agent_core_test(FakeBackendsTest)

# Owning aggregate: construction wiring, live-member accessors, teardown order.
agent_core_test(AgentCoreWiringTest)

# --- platform-neutral unit tests ------------------------------------------
agent_core_test(AgentShutdownUnderLoadTest)
agent_core_test(AttemptContextTest)
agent_core_test(AuthorizerTest)
agent_core_test(CacheScrubOnRemovalTest)
agent_core_test(CallerLabelTest)
agent_core_test(CardKeyTrackerTest)
agent_core_test(CardPluginRoutingTest)
agent_core_test(CardReadCacheTest)
agent_core_test(CardReadSnapshotTest)
agent_core_test(CardSessionHolderTest)
agent_core_test(CertDerExportTest)
agent_core_test(CertReadFlowTest)
agent_core_test(ConfigStoreTest)
agent_core_test(CredentialCacheRequestTest)
agent_core_test(CredentialCacheTest)
agent_core_test(ErrorTaxonomyTest)
agent_core_test(FieldKeyParityTest)
agent_core_test(IdentityReadFlowTest)
agent_core_test(IdentityTest)
agent_core_test(LeaseManagerTest)
agent_core_test(LmCertReaderKatTest)
agent_core_test(LmRawCryptoTest)
agent_core_test(LmSeamsCompileTest)
agent_core_test(LmSeamsRoutingTest)
agent_core_test(LmSigningRequestBuilderTest)
agent_core_test(LmTrustVerifierTest)
agent_core_test(LoggingTest)
agent_core_test(MrzPayloadTest)
agent_core_test(ObjectRegistryTest)
agent_core_test(OperationBaseTest)
agent_core_test(OperationManagerTest)
agent_core_test(OperationPhaseTest)
agent_core_test(PresenceModelTest)
agent_core_test(PresenceTypesTest)
agent_core_test(PromptBudgetChainTest)
agent_core_test(PromptFieldWiringTest)
agent_core_test(PromptIdMinterTest)
agent_core_test(PromptPolicyTest)
agent_core_test(PromptSerializerTest)
agent_core_test(PromptStampTest)
agent_core_test(PrompterConformanceTest)
agent_core_test(PropertyEmissionThrottlerTest)
agent_core_test(RateLimiterTest)
agent_core_test(RawCryptoFlowTest)
agent_core_test(ReaderLabelsTest)
agent_core_test(BatchSignFlowTest)
agent_core_test(RsaPublicKeyTest)
agent_core_test(SeamsCompileTest)
agent_core_test(Sha256HexTest)
agent_core_test(SignatureParamsTest)
agent_core_test(SignFlowPhaseTest)
agent_core_test(SignFlowTest)
agent_core_test(SignGateTest)
agent_core_test(SigningEngineProviderTest)
agent_core_test(TokenInfoReadFlowTest)
agent_core_test(WatchdogTest)
agent_core_test(ZombieWorkerDrainTest)
agent_core_test(PrompterKeepAliveDrainTest)
agent_core_test(SignSeamKeepAliveDrainTest)
agent_core_test(RawCryptoCaptureGuardTest)
agent_core_test(Pkcs11BrokerTest)
agent_core_test(Pkcs11LeaseInvalidationTest)
agent_core_test(Pkcs11SecurityTest)

# The OpenSSL-KAT TUs mint keys/certs with OpenSSL directly (LibreAgent::Core links it
# PRIVATE, so its headers are not propagated) — link Crypto explicitly.
foreach(_kat IN ITEMS LmCertReaderKatTest LmRawCryptoTest LmTrustVerifierTest RsaPublicKeyTest)
    target_link_libraries(${_kat} PRIVATE OpenSSL::Crypto)
endforeach()

# These tests construct a stable per-session key via the LM-internal detached
# card-session factory (LibreSCRS::SmartCard::detail::makeDetachedCardSession),
# whose prototype in <LibreSCRS/SmartCard/CardSession.h> is guarded behind
# LIBRESCRS_INTERNAL_BUILD — the same opt-in LibreMiddleware's own tests use.
foreach(_internal IN ITEMS
        OperationManagerTest
        PromptBudgetChainTest
        LmRawCryptoTest
        CardSessionHolderTest
        FakeBackendsTest
        FieldKeyParityTest
        IdentityReadFlowTest
        LmSeamsRoutingTest
        CertReadFlowTest
        TokenInfoReadFlowTest
        RawCryptoFlowTest
        BatchSignFlowTest
        SignFlowPhaseTest
        SignFlowTest
        PrompterKeepAliveDrainTest)
    target_compile_definitions(${_internal} PRIVATE LIBRESCRS_INTERNAL_BUILD)
endforeach()

# OperationManager exposes a test-only accessor behind LIBRESCRS_AGENT_TESTING;
# only this neutral-core test build defines it.
target_compile_definitions(OperationManagerTest PRIVATE LIBRESCRS_AGENT_TESTING)

# Source-grep guard: reads the shipped AgentCore.cpp + Pkcs11Broker.cpp to lock the
# raw-crypto worker closure's shared serializer + prompter + credential co-ownership
# and shutdown skip, and the broker pinState's lease-share co-ownership.
target_compile_definitions(RawCryptoCaptureGuardTest PRIVATE
    LIBREAGENT_AGENTCORE_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/AgentCore.cpp"
    LIBREAGENT_PKCS11BROKER_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/pkcs11/Pkcs11Broker.cpp")

# Source-grep guard (same idiom as above): the prompt-chain budget bounds the
# three seams this suite drives, which bounds the agent only if they are all of
# them -- a fourth caller of CredentialCache::requestCredential raises no dialog
# in the test binary and would sit behind a green run, so the suite counts the
# call sites on disk.
target_compile_definitions(PromptBudgetChainTest PRIVATE
    LIBREAGENT_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../src")

# Source-grep guard (same idiom as above): reads the shipped LmSeams.cpp so the
# credential depositor's PURE, no-card-I/O registry lookup survives refactors.
# The plugin registry is a concrete class that loads shared objects off disk, so
# it admits no test double -- the structural half of that pin reads the source.
target_compile_definitions(IdentityReadFlowTest PRIVATE
    LIBREAGENT_LMSEAMS_CPP="${CMAKE_CURRENT_SOURCE_DIR}/../src/operations/LmSeams.cpp")

# Credential lifecycle wire types: record/outcome mapping tables, id rule,
# narrowing + placeholders guards.
agent_core_test(CredentialRecordTest)

# Credential seam routing + multi-secret prompter seam; needs the LM-internal
# detached card-session factory (same opt-in as the seam routing tests above).
agent_core_test(CredentialSeamTest)
target_compile_definitions(CredentialSeamTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# Credential list flow: open + install-provider prelude, map/disambiguate into a
# CredentialSnapshot, empty/CardRemoved classification. Uses the LM-internal
# detached card-session factory (markDead drives the transport-loss case).
agent_core_test(CredentialListFlowTest)
target_compile_definitions(CredentialListFlowTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# Signing-key activation flow (increment #1: Unsupported passthrough). Needs the
# LM-internal detached card-session factory for its held-session harness. The
# flow TU is in the top-level Core source list, so the test links it from
# LibreAgent::Core.
agent_core_test(KeyActivationFlowTest)
target_compile_definitions(KeyActivationFlowTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# PIN-management flow (increment #1: change drives the seam; unblock/activate_pin
# short-circuit to Unsupported) + entry validation. Needs the LM-internal
# detached card-session factory for its held-session harness. The flow TU is in
# the top-level Core source list, so the test links it from LibreAgent::Core.
agent_core_test(PinChangeFlowTest)
target_compile_definitions(PinChangeFlowTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# Credential outcome -> (finish status, wire ErrorCode) mapping: the verbatim
# contract table plus a compile-guarded exhaustive oracle over CredentialOutcome.
agent_core_test(CredentialErrorMappingTest)

# Per-card credential-snapshot cache (monotonic version, scrub-on-drop, idle
# window) + the post-mutation invalidation rule (reached-card drops snapshot +
# read cache; secret cache untouched). Pure value/cache types — no LM-internal
# card session, so no LIBRESCRS_INTERNAL_BUILD.
agent_core_test(CredentialSnapshotCacheTest)

# Country-signing anchor import: trust-on-first-import, pin, rotation, and the
# refusals — including the link certificate a self-signed-only filter would
# drop. The fixture mints its certificates with the system OpenSSL directly,
# which is the fixture's dependency alone; the code under test consumes only
# the published LibreMiddleware trust API.
add_executable(CscaAnchorImportTest CscaAnchorImportTest.cpp)
target_link_libraries(CscaAnchorImportTest PRIVATE
    LibreAgent::Core
    SyntheticMasterList
    GTest::gtest_main)
add_test(NAME CscaAnchorImportTest COMMAND CscaAnchorImportTest)
set_tests_properties(CscaAnchorImportTest PROPERTIES TIMEOUT 120)

# --- the card operations' own suites ---------------------------------------
#
# These arrived with the nine operation classes: each drives one operation
# through a fake channel and fake seams, on the test thread, with no bus and no
# card. Two of them were split rather than moved -- a sealed-descriptor round
# trip and a result-recovery store stayed with the backend that can seal one.
agent_core_test(ReadIdentityOperationTest)
agent_core_test(GetPhotoOperationTest)
agent_core_test(ReadCertificatesOperationTest)
agent_core_test(ReadTokenInfoOperationTest)
agent_core_test(SignBatchOperationTest)
agent_core_test(CredentialOperationContractTest)
agent_core_test(SignFlowOrchestrationTest)
agent_core_test(CardTypeArbitrationTest)

# All but the arbitration test build a held card session through the LM-internal
# detached factory, whose prototype is guarded behind LIBRESCRS_INTERNAL_BUILD.
# Without the define they COMPILE and do not RUN what they claim to, which no
# test count can see.
foreach(_op_internal IN ITEMS
        ReadIdentityOperationTest
        GetPhotoOperationTest
        ReadCertificatesOperationTest
        ReadTokenInfoOperationTest
        SignBatchOperationTest
        CredentialOperationContractTest
        SignFlowOrchestrationTest)
    target_compile_definitions(${_op_internal} PRIVATE LIBRESCRS_INTERNAL_BUILD)
endforeach()

# LM-parity oracle for Manager1.LayoutVisualSignature/GetAppearanceFont —
# needs BOTH LibreAgent::Core (the LM-linked layout/font seam in LmSeams.h)
# AND LibreAgent::Wire (Messages.h/ClientCodec.h's codec), so it's the one
# test in this file with an ADDITIONAL LIBREAGENT_BUILD_WIRE guard (every
# other agent_core_test() above needs Core alone). Proves the wire-served
# values decode identically to a direct LM call — see the test file's own
# header comment.
if(LIBREAGENT_BUILD_WIRE)
    add_executable(VisualLayoutServiceTest VisualLayoutServiceTest.cpp)
    target_link_libraries(VisualLayoutServiceTest PRIVATE
        LibreAgent::Core
        LibreAgent::Wire
        GTest::gtest
        GTest::gtest_main)
    target_include_directories(VisualLayoutServiceTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    add_test(NAME VisualLayoutServiceTest COMMAND VisualLayoutServiceTest)
endif()

endif() # LIBREAGENT_BUILD_CORE
