# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Install + export rules for the LibreAgent CONFIG package. Included from the
# root CMakeLists.txt after the enabled component targets are defined.
# Materialises, for each enabled component (LIBREAGENT_BUILD_CORE today;
# LIBREAGENT_BUILD_WIRE / LIBREAGENT_BUILD_CLIENT_QT once their targets land):
#   - the static archive + public headers under the install prefix,
#   - LibreAgent<Component>Targets.cmake (the imported target, namespaced
#     LibreAgent:: to match the in-tree ALIAS, e.g. LibreAgent::Core),
# plus, unconditionally:
#   - LibreAgentConfig.cmake + …ConfigVersion.cmake (SameMajorVersion)
# so a downstream find_package(LibreAgent CONFIG) always resolves the
# package — even a configuration with every component disabled produces a
# valid (if component-empty) install; LibreAgentConfig.cmake.in's
# check_required_components() then reports any COMPONENTS a consumer actually
# requested as not found.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(_cfgdir ${CMAKE_INSTALL_LIBDIR}/cmake/LibreAgent)

if(LIBREAGENT_BUILD_CORE)
    # In-tree target LibreAgentCore -> imported LibreAgent::Core.
    set_target_properties(LibreAgentCore PROPERTIES EXPORT_NAME Core)

    install(TARGETS LibreAgentCore EXPORT LibreAgentCoreTargets
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(EXPORT LibreAgentCoreTargets
        FILE LibreAgentCoreTargets.cmake
        NAMESPACE LibreAgent::
        DESTINATION ${_cfgdir})

    # Core installs the WHOLE include/LibreSCRS tree, so a Core+Wire build's
    # single install(DIRECTORY) call already covers Wire's headers too
    # (include/LibreSCRS/Agent/wire/) — the block below only has to cover the
    # CORE=OFF, WIRE=ON case where this install() never runs.
    install(DIRECTORY include/LibreSCRS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
endif()

if(LIBREAGENT_BUILD_WIRE)
    # In-tree target LibreAgentWire -> imported LibreAgent::Wire.
    set_target_properties(LibreAgentWire PROPERTIES EXPORT_NAME Wire)

    install(TARGETS LibreAgentWire EXPORT LibreAgentWireTargets
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(EXPORT LibreAgentWireTargets
        FILE LibreAgentWireTargets.cmake
        NAMESPACE LibreAgent::
        DESTINATION ${_cfgdir})

    # The wire contract (CBOR/CDDL) is installed alongside the library so
    # clients can pin against it. The canonical semantic source stays the
    # D-Bus interface surface; this schema mirrors it rather than forking it.
    install(FILES wire/librescrs-agent.cddl
        DESTINATION ${CMAKE_INSTALL_DATADIR}/librescrs)

    if(NOT LIBREAGENT_BUILD_CORE)
        # Core's install(DIRECTORY include/LibreSCRS ...) above already ships
        # Wire's headers when Core is enabled. When Core is OFF, that call
        # never runs, so a CORE=OFF, WIRE=ON install would otherwise ship the
        # LibreAgentWire archive with NO public headers at all — install
        # Wire's own subtree (include/LibreSCRS/Agent/wire/) plus the other
        # std-only top-level headers this component's tests sit alongside:
        # OperationPhase.h (wire-stable enums) and FeatureTokens.h (the
        # feature-token catalog — LM-free like Wire itself, so a Wire-only
        # consumer, e.g. the LibreDarwin socket daemon, can still reach it).
        install(FILES
                include/LibreSCRS/Agent/OperationPhase.h
                include/LibreSCRS/Agent/FeatureTokens.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/Agent)
        install(DIRECTORY include/LibreSCRS/Agent/wire
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/Agent
            FILES_MATCHING PATTERN "*.h")
    endif()
endif()

if(LIBREAGENT_BUILD_CLIENT_QT)
    # In-tree target LibreAgentClientQt -> imported LibreAgent::ClientQt.
    set_target_properties(LibreAgentClientQt PROPERTIES EXPORT_NAME ClientQt)

    install(TARGETS LibreAgentClientQt EXPORT LibreAgentClientQtTargets
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(EXPORT LibreAgentClientQtTargets
        FILE LibreAgentClientQtTargets.cmake
        NAMESPACE LibreAgent::
        DESTINATION ${_cfgdir})

    # ClientQt's public headers live under client/qt/include/LibreSCRS/AgentClient/
    # -- a separate subtree from Core/Wire's include/LibreSCRS/Agent/, so
    # neither of the install(DIRECTORY include/LibreSCRS ...) calls above
    # ever reaches them; this component always installs its own headers
    # regardless of which other components are enabled.
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/client/qt/include/LibreSCRS
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")

    # generate_export_header()'s output (client/qt/CMakeLists.txt sets
    # LIBREAGENT_CLIENTQT_EXPORT_HEADER to its exact path) lands in the build
    # tree, not the source tree, so the install(DIRECTORY ...) above never
    # sees it -- install it into the same LibreSCRS/AgentClient/ subdir as
    # the hand-written public headers.
    install(FILES ${LIBREAGENT_CLIENTQT_EXPORT_HEADER}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/AgentClient)
endif()

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibreAgentConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/LibreAgentConfig.cmake
    INSTALL_DESTINATION ${_cfgdir})

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/LibreAgentConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/LibreAgentConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/LibreAgentConfigVersion.cmake
    DESTINATION ${_cfgdir})
