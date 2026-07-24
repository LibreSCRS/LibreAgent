# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreAgent::ClientQt -- the transport-neutral Qt client library LibreCelik
# and (later) LibreKDE consume: the public value types plus the lifted client
# API (AgentClient/AgentReader/AgentCard/AgentOperation/SharedAgentClient)
# over the internal TransportSeam. The D-Bus transport (src/dbus/, Linux-only)
# is the first seam implementation; the socket transport is a later task.
#
# Included from the root CMakeLists.txt's `if(LIBREAGENT_BUILD_CLIENT_QT)`
# block, AFTER that block's find_package(Qt6 ...) call -- Qt enters this
# whole repo's build ONLY there; LibreAgent::Core/::Wire never see it.

# The four public QObject headers are listed as target sources so AUTOMOC
# scans them (their generated moc TUs are compiled into this library -- the
# QObject types must never be duplicated across .so boundaries).
qt_add_library(LibreAgentClientQt SHARED
    src/AgentClient.cpp
    src/AgentCard.cpp
    src/AgentOperation.cpp
    src/AgentReader.cpp
    src/CredentialTypes.cpp
    src/FdHandle.cpp
    src/IdentityRows.cpp
    src/SharedAgentClient.cpp
    src/TokenMap.cpp
    include/LibreSCRS/AgentClient/AgentClient.h
    include/LibreSCRS/AgentClient/AgentCard.h
    include/LibreSCRS/AgentClient/AgentOperation.h
    include/LibreSCRS/AgentClient/AgentReader.h)
add_library(LibreAgent::ClientQt ALIAS LibreAgentClientQt)

# The D-Bus transport: Linux-only, matching the Linux-only Qt6::DBus
# dependency below (the macOS transport is POSIX sockets, a later task).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(LibreAgentClientQt PRIVATE
        src/dbus/CappedCall.cpp
        src/dbus/DBusTransport.cpp
        src/dbus/DBusTransport.h
        src/dbus/ErrorNameMap.cpp
        src/dbus/Marshal.cpp)
endif()

set_target_properties(LibreAgentClientQt PROPERTIES
    OUTPUT_NAME librescrs-agentclient-qt
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    AUTOMOC ON
    POSITION_INDEPENDENT_CODE ON)

include(GenerateExportHeader)
# EXPORT_FILE_NAME is an addition to the brief's literal snippet (which left
# generate_export_header() at its default output -- a flat
# librescrs_agentclient_export.h next to the target's other build-tree
# files): the brief's own public-header list names this file
# client/qt/include/LibreSCRS/AgentClient/Export.h, the same
# <LibreSCRS/AgentClient/...> spelling every hand-written header here uses,
# and client/qt/tests/HeaderAcceptance/ needs it to sit under that exact
# logical path to test it like every other public header. BASE_NAME (hence
# the LIBRESCRS_AGENTCLIENT_EXPORT macro FdHandle.h uses) is unchanged.
generate_export_header(LibreAgentClientQt
    BASE_NAME LIBRESCRS_AGENTCLIENT
    EXPORT_FILE_NAME include/LibreSCRS/AgentClient/Export.h)

# The repo's top-level include/ is on the PUBLIC surface too: the std-only
# wire enum headers (ErrorCode/OperationPhase/PreReadAuth) are re-exported by
# public client headers, so a consumer of THIS target must resolve them even
# though LibreAgent::Wire itself stays a PRIVATE link (its install rules put
# those headers under the same installed include root).
target_include_directories(LibreAgentClientQt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(LibreAgentClientQt PUBLIC cxx_std_23)

target_link_libraries(LibreAgentClientQt
    PUBLIC
        Qt6::Core
    PRIVATE
        $<$<PLATFORM_ID:Linux>:Qt6::DBus>
        LibreAgent::Wire)

target_compile_options(LibreAgentClientQt PRIVATE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
    -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference
    -Wdouble-promotion -Wformat=2)
if(LIBRESCRS_AGENT_WERROR)
    target_compile_options(LibreAgentClientQt PRIVATE -Werror)
endif()

# Exposed to cmake/InstallExport.cmake (install() the generated header) and
# to client/qt/tests/HeaderAcceptance/ (the exact include-path set the brief
# requires) without either having to re-derive generate_export_header()'s
# output location by hand.
set(LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
set(LIBREAGENT_CLIENTQT_EXPORT_HEADER
    ${LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR}/LibreSCRS/AgentClient/Export.h)
# add_subdirectory() scoping is one-way (parent -> child): client/qt/tests/
# and its own HeaderAcceptance/ subdirectory automatically inherit the three
# variables above with no extra step, but cmake/InstallExport.cmake is
# include()'d back at the ROOT scope (the root CMakeLists.txt that called
# add_subdirectory(client/qt) in the first place) and would otherwise never
# see them -- PARENT_SCOPE pushes them back up one level to exactly that
# root scope. (Caught the hard way: a first pass at this file left Export.h
# out of every install tree with no configure/build-time error -- the
# install(FILES ${LIBREAGENT_CLIENTQT_EXPORT_HEADER} ...) call in
# InstallExport.cmake silently expanded to an empty path and installed
# nothing.)
set(LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR ${LIBREAGENT_CLIENTQT_PUBLIC_INCLUDE_DIR} PARENT_SCOPE)
set(LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR ${LIBREAGENT_CLIENTQT_EXPORT_INCLUDE_DIR} PARENT_SCOPE)
set(LIBREAGENT_CLIENTQT_EXPORT_HEADER ${LIBREAGENT_CLIENTQT_EXPORT_HEADER} PARENT_SCOPE)

# This component's own tests (TypesTest/TokenMapTest/HeaderAcceptance) live
# under client/qt/tests/ rather than the top-level tests/ directory Core/Wire
# share -- ClientQt is meant to stay a self-contained subtree. Same
# FetchContent-consumer gate as the root CMakeLists.txt's own
# `if(PROJECT_IS_TOP_LEVEL) ... add_subdirectory(tests)`: a platform backend
# pulling this repo in via FetchContent gets the library, not its test suite.
# enable_testing() is safe to call again here even though the root
# CMakeLists.txt may already have called it -- add_subdirectory(client/qt)
# runs BEFORE that root call (this block sits above the WIRE-gated
# `if(PROJECT_IS_TOP_LEVEL)` block that includes InstallExport.cmake and
# enables testing), so this component needs its own call for ctest to
# discover add_test() registrations made below it.
if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(tests)
endif()
