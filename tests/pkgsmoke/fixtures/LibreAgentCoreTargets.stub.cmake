# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Fixture, not a real export file. The pkgsmoke ClientQt-only case builds
# LibreAgent with Core disabled, so no genuine LibreAgentCoreTargets.cmake is
# ever produced by that build; this stub is copied by hand into the staged
# install's lib/cmake/LibreAgent/ directory to reproduce the one situation a
# real machine can still land in on its own -- a Core package and a
# ClientQt-only package sharing that same directory (e.g. two components of
# one distribution unpacked into a common prefix). LibreAgentConfig.cmake.in
# must resolve only the components a consumer's find_package(LibreAgent
# COMPONENTS ...) actually named, so it must never include() this file, and
# must never run Core's find_dependency(LibreMiddleware ...) /
# find_dependency(OpenSSL ...) calls, when the request did not include Core --
# the mere on-disk presence of this file must not matter.
#
# If it DOES get include()'d, that is the regression this fixture exists to
# catch, and the message below says so plainly rather than failing on some
# unrelated syntax error further down.
message(FATAL_ERROR
    "LibreAgentCoreTargets.cmake stub was include()'d by a consumer that did not request the Core component -- component filtering in LibreAgentConfig.cmake.in has regressed")
