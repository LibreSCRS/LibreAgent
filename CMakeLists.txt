# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.24)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GitVersion)

set(PROJECT_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${GIT_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${GIT_VERSION_PATCH})
set(PROJECT_VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

project(LibreAgent VERSION ${PROJECT_VERSION} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(GNUInstallDirs)
find_package(LibreMiddleware 4.2 REQUIRED CONFIG)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# Platform-neutral agent core: card-read/sign flows, scheduler, presence model,
# caches, lease/broker policy, LM-backed seams, and the 5 backend interfaces.
# No sdbus-c++ / systemd / polkit here — those live in the platform backend.
add_library(LibreAgentCore STATIC
    # value/
    src/value/ErrorTaxonomy.cpp
    # util/
    src/util/Sha256Hex.cpp
    # cache/
    src/cache/CardReadCache.cpp
    src/cache/CredentialCache.cpp
    src/cache/CredentialSnapshotCache.cpp
    # presence/
    src/presence/ObjectRegistry.cpp
    src/presence/PresenceModel.cpp
    src/presence/PluginCapabilityResolver.cpp
    src/presence/MonitorBridge.cpp
    src/presence/CardKeyTracker.cpp
    # config/
    src/config/ConfigStore.cpp
    # pkcs11/
    src/pkcs11/LeaseManager.cpp
    src/pkcs11/Pkcs11Broker.cpp
    # operations/
    src/operations/LmSeams.cpp
    src/operations/LmRawCrypto.cpp
    src/operations/FlowPrelude.cpp
    src/operations/CardSessionHolder.cpp
    src/operations/IdentityReadFlow.cpp
    src/operations/CertReadFlow.cpp
    src/operations/CredentialListFlow.cpp
    src/operations/PinChangeFlow.cpp
    src/operations/KeyActivationFlow.cpp
    src/operations/SignFlow.cpp
    src/operations/RawCryptoFlow.cpp
    src/operations/PropertyEmissionThrottler.cpp
    src/operations/RateLimiter.cpp
    src/operations/SigningEngineProvider.cpp
    src/operations/CertDerExport.cpp
    src/operations/RsaPublicKey.cpp
    src/operations/PromptSerializer.cpp
    src/operations/OperationBase.cpp
    src/operations/OperationManager.cpp
    # backend/ log facade
    src/backend/Logging.cpp
    # owning aggregate for the neutral core
    src/AgentCore.cpp)
add_library(LibreAgent::Core ALIAS LibreAgentCore)
target_include_directories(LibreAgentCore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(LibreAgentCore PUBLIC cxx_std_23)
set_target_properties(LibreAgentCore PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(LibreAgentCore
    PUBLIC
        LibreMiddleware::SmartCard
        LibreMiddleware::Plugin
    PRIVATE
        # PRIVATE: only the Lm* seam .cpp files + SigningEngineProvider.cpp
        # consume LM X.509/Certificate + Signing/Trust types; no public header
        # includes them, which keeps consumers of this lib free of those symbols
        # (the seam-boundary invariant).
        LibreMiddleware::Certificate
        LibreMiddleware::Signing
        LibreMiddleware::Trust
        OpenSSL::Crypto)

# Strict warnings by default; treat as errors only in CI builds.
option(LIBRESCRS_AGENT_WERROR "Treat compiler warnings as errors" OFF)
target_compile_options(LibreAgentCore PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
    -Wdouble-promotion -Wformat=2)
if(LIBRESCRS_AGENT_WERROR)
    target_compile_options(LibreAgentCore PRIVATE -Werror)
endif()
# GCC 16's -Warray-bounds raises a false positive on the inlined
# shared_ptr<std::atomic<bool>> control-block teardown in the credential-flow
# TUs. It is emitted during optimization, so a source-level diagnostic pragma
# cannot suppress it; disable the single warning for just these flows.
set_source_files_properties(
    src/operations/IdentityReadFlow.cpp
    src/operations/CertReadFlow.cpp
    src/operations/CredentialListFlow.cpp
    src/operations/PinChangeFlow.cpp
    src/operations/KeyActivationFlow.cpp
    src/operations/SignFlow.cpp
    src/operations/RawCryptoFlow.cpp
    # AgentCore.cpp inlines the raw-crypto flow (make_shared over the same
    # credential-flow teardown), so it inherits the same GCC 16 false positive.
    src/AgentCore.cpp
    PROPERTIES COMPILE_OPTIONS -Wno-array-bounds)

# The installed CONFIG package and the platform-neutral test suite are only
# built when this repo is the top-level project. When it is pulled in as a
# subproject (FetchContent from a platform backend such as LibreLinux), the
# consumer wants just the LibreAgent::Core library: the neutral tests run in
# this repo's own CI, and the backend provides its own install/export rules.
if(PROJECT_IS_TOP_LEVEL)
    # Installed CONFIG package: LibreAgent{,Config,ConfigVersion,Targets}.cmake
    # so downstream find_package(LibreAgent CONFIG) resolves LibreAgent::Core.
    include(cmake/InstallExport.cmake)

    # Platform-neutral unit tests + the five shared backend fakes.
    enable_testing()
    add_subdirectory(tests)
endif()
