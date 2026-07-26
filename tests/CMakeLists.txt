# SPDX-License-Identifier: LGPL-2.1-or-later
find_package(GTest REQUIRED)

# Dependency-free wire-header compile guard (no LibreAgent::Core link, no LM
# on its include path) — see tests/wire/CMakeLists.txt.
add_subdirectory(wire)

# SCM_RIGHTS + memfd fd-passing spike (early de-risk for the macOS client's
# AF_UNIX transport) — pure POSIX, no LibreAgent::Core, no Qt. Temporary
# location: adopted by the client transport tests once that work lands. See
# tests/spike/CMakeLists.txt and tests/spike/ScmRightsSpikeTest.cpp.
add_subdirectory(spike)

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
agent_core_test(FakeBackendsTest)

# Owning aggregate: construction wiring, live-member accessors, teardown order.
agent_core_test(AgentCoreWiringTest)

# --- platform-neutral unit tests ------------------------------------------
agent_core_test(AgentShutdownUnderLoadTest)
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
agent_core_test(ObjectRegistryTest)
agent_core_test(OperationBaseTest)
agent_core_test(OperationManagerTest)
agent_core_test(OperationPhaseTest)
agent_core_test(PresenceModelTest)
agent_core_test(PresenceTypesTest)
agent_core_test(PromptSerializerTest)
agent_core_test(PrompterConformanceTest)
agent_core_test(PropertyEmissionThrottlerTest)
agent_core_test(RateLimiterTest)
agent_core_test(RawCryptoFlowTest)
agent_core_test(BatchSignFlowTest)
agent_core_test(RsaPublicKeyTest)
agent_core_test(SeamsCompileTest)
agent_core_test(Sha256HexTest)
agent_core_test(SignatureParamsTest)
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
        CardSessionHolderTest
        FieldKeyParityTest
        IdentityReadFlowTest
        LmSeamsRoutingTest
        CertReadFlowTest
        TokenInfoReadFlowTest
        RawCryptoFlowTest
        BatchSignFlowTest
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
