# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Subdirectory-consumption version smoke: proves LibreAgent resolves ITS OWN
# version from cmake/GitVersion.cmake even when add_subdirectory()'d beneath a
# project() that already set its own PROJECT_VERSION -- exactly the shape a
# platform backend (e.g. LibreKDE's client/qt wrapper, PROJECT_VERSION 0.1.0)
# uses, and unlike tests/pkgsmoke's own CMakeLists.txt one directory up, which
# instead walks the INSTALLED find_package(LibreAgent CONFIG) path.
#
# LIBREAGENT_BUILD_CORE is forced OFF (Core ON would demand LibreMiddleware,
# which this smoke has no business acquiring); WIRE/CLIENT_QT stay ON because
# LIBREAGENT_BUILD_CLIENT_QT requires WIRE and this is also where the
# eventual soname on the Qt client library gets exercised.
#
# Reading LibreAgent_VERSION (or PROJECT_VERSION) back in THIS wrapper's own
# scope after add_subdirectory() returns would prove nothing: project()'s
# PROJECT_VERSION / <name>_VERSION variables live in the CHILD directory's own
# scope, and add_subdirectory() scoping is parent -> child only -- this file
# would silently read back its own unchanged "0.1.0" (or an empty string)
# regardless of what LibreAgent resolved internally, passing identically
# before and after any fix and proving nothing.
# get_directory_property(... DEFINITION ...) is the supported API for reading
# a variable as it was actually DEFINED in a specific child directory's own
# scope, so it is the one call here that observes what
# cmake/GitVersion.cmake actually resolved inside LibreAgent's own directory.
cmake_minimum_required(VERSION 3.24)
project(wrapper VERSION 0.1.0 LANGUAGES CXX)

set(LIBREAGENT_BUILD_CORE OFF CACHE BOOL "" FORCE)
set(LIBREAGENT_BUILD_WIRE ON CACHE BOOL "" FORCE)
set(LIBREAGENT_BUILD_CLIENT_QT ON CACHE BOOL "" FORCE)

get_filename_component(LIBREAGENT_SUBDIR_VERSION_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
add_subdirectory("${LIBREAGENT_SUBDIR_VERSION_ROOT}" libreagent-build)

get_directory_property(LIBREAGENT_INNER_VERSION
    DIRECTORY "${LIBREAGENT_SUBDIR_VERSION_ROOT}"
    DEFINITION PROJECT_VERSION)

if(NOT LIBREAGENT_INNER_VERSION STREQUAL "4.2.0")
    message(FATAL_ERROR
        "LibreAgent's own PROJECT_VERSION, as add_subdirectory()'d beneath this wrapper's project(wrapper VERSION 0.1.0 ...), resolved to \"${LIBREAGENT_INNER_VERSION}\" -- expected \"4.2.0\" (this repo's own VERSION file). LibreAgent is adopting the enclosing project's version instead of its own; see cmake/GitVersion.cmake.")
endif()

message(STATUS "subdir-version smoke: LibreAgent resolved its own PROJECT_VERSION to \"${LIBREAGENT_INNER_VERSION}\" while add_subdirectory()'d beneath wrapper 0.1.0")
