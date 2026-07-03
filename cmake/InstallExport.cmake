# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Install + export rules for the LibreAgent::Core CONFIG package. Included
# from the root CMakeLists.txt after the target is defined. Materialises:
#   - the static archive + public headers under the install prefix,
#   - LibreAgentTargets.cmake (the imported target, namespaced
#     LibreAgent::Core to match the in-tree ALIAS),
#   - LibreAgentConfig.cmake + …ConfigVersion.cmake (SameMajorVersion),
# so a downstream find_package(LibreAgent CONFIG) resolves.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(_cfgdir ${CMAKE_INSTALL_LIBDIR}/cmake/LibreAgent)

# In-tree target LibreAgentCore -> imported LibreAgent::Core.
set_target_properties(LibreAgentCore PROPERTIES EXPORT_NAME Core)

install(TARGETS LibreAgentCore EXPORT LibreAgentTargets
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT LibreAgentTargets
    FILE LibreAgentTargets.cmake
    NAMESPACE LibreAgent::
    DESTINATION ${_cfgdir})

install(DIRECTORY include/LibreSCRS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")

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
