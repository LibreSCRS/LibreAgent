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

    install(DIRECTORY include/LibreSCRS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")
endif()

# Wire (socket-wire protocol library) and ClientQt (Qt client library) land in
# later tasks; their own
#   install(TARGETS ... EXPORT LibreAgentWireTargets / LibreAgentClientQtTargets)
#   install(EXPORT LibreAgentWireTargets / LibreAgentClientQtTargets ...)
# blocks join here, each gated the same way behind its LIBREAGENT_BUILD_WIRE /
# LIBREAGENT_BUILD_CLIENT_QT option, once those targets exist.

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
