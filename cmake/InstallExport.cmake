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

    if(NOT LIBREAGENT_BUILD_CORE)
        # Core's install(DIRECTORY include/LibreSCRS ...) above already ships
        # Wire's headers when Core is enabled. When Core is OFF, that call
        # never runs, so a CORE=OFF, WIRE=ON install would otherwise ship the
        # LibreAgentWire archive with NO public headers at all — install
        # Wire's own subtree (include/LibreSCRS/Agent/wire/) plus
        # OperationPhase.h (the other wire-stable enum header this component's
        # headers/tests sit alongside) specifically.
        install(FILES include/LibreSCRS/Agent/OperationPhase.h
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/Agent)
        install(DIRECTORY include/LibreSCRS/Agent/wire
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/LibreSCRS/Agent
            FILES_MATCHING PATTERN "*.h")
    endif()
endif()

# ClientQt (Qt client library) lands in a later task; its own
#   install(TARGETS ... EXPORT LibreAgentClientQtTargets)
#   install(EXPORT LibreAgentClientQtTargets ...)
# blocks join here, gated behind LIBREAGENT_BUILD_CLIENT_QT, once that target
# exists.

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
