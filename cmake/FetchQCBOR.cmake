# SPDX-License-Identifier: LGPL-2.1-or-later
#
# CBOR codec for the socket wire transport. QCBOR is a small, zero-dep, BSD-3
# C codec (BSD-3 -> LGPL/facade compatible) used for raw CBOR encode/decode
# only: RFC 8949 §4.2 canonical map-key ordering and strict decoding are
# enforced by LibreDarwin's own Cbor.cpp (CanonicalKeyLess), NOT by QCBOR
# (v1.6.1 has no map-key sorting). Pinned by immutable commit SHA and built
# static from source via FetchContent (mirrors FindOrUseLibreAgent.cmake).
# Provides the imported target qcbor::qcbor, linked PRIVATE by the wire layer
# and the card-less PKCS#11 facade. Dev builds may re-point it with
#   -DFETCHCONTENT_SOURCE_DIR_QCBOR=/path/to/QCBOR
include(FetchContent)

# Build QCBOR the way the wire layer needs it: static, no test suite. Scope
# the option overrides to the FetchContent
# subdirectory (CMP0077 NEW honors normal variables in option()/BUILD_SHARED_LIBS)
# and RESTORE BUILD_SHARED_LIBS afterwards so we never FORCE a project-global cache
# var onto the sibling targets (the pkcs11 facade IS a dylib) or nested deps.
set(_libredarwin_saved_shared "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(BUILD_QCBOR_TEST "OFF")
set(BUILD_QCBOR_WARN OFF)

FetchContent_Declare(qcbor
    GIT_REPOSITORY https://github.com/laurencelundblade/QCBOR.git
    # Immutable SHA the (mutable) tag v1.6.1 resolves to.
    GIT_TAG 930708bb86481e88879eb1d87fd4d664f1d69503
    # Without this, QCBOR's own install(TARGETS)/install(EXPORT) rules stay
    # live and a DESTDIR package build claims /usr/lib/libqcbor.a and
    # /usr/lib/cmake/qcbor/ that no consumer asked for -- this project folds
    # qcbor's objects straight into libLibreAgentWire.a (see the
    # $<TARGET_OBJECTS:qcbor> use in the root CMakeLists.txt) and never wants
    # a standalone qcbor package on disk. Requires CMake >= 3.28 (see this
    # project's cmake_minimum_required); below that the keyword is silently
    # forwarded to ExternalProject_Add and does nothing.
    EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(qcbor) # provides qcbor::qcbor

set(BUILD_SHARED_LIBS "${_libredarwin_saved_shared}")
unset(_libredarwin_saved_shared)

# QCBOR is a C library with no ABI-affecting C++ concerns; keep it out of the
# project's -fexperimental-library / C++23 flags (it compiles as C).

# Compile qcbor's objects with hidden visibility, so that nothing carrying them
# re-exports its C names.
#
# These objects are folded straight into libLibreAgentWire.a, which in turn is
# folded into the shared Qt client library -- and ELF resolves an unmangled C
# name process-wide by first definition. A desktop session loads many plugins,
# several of which may carry their own copy of this same C library; exporting
# ours lets the two cross-bind, in whichever direction load order decides, on
# the path that decodes data arriving from a smart card. Hiding the names
# closes it in both directions at once: nothing outside can bind to ours, and
# ours can no longer be preempted from outside.
#
# Set on the qcbor target rather than on a consumer, because visibility is
# decided when the object is COMPILED. The consumers' own
# `CXX_VISIBILITY_PRESET hidden` cannot reach these: it applies to this
# project's C++ sources, not to pre-compiled objects arriving from a
# dependency, and not to C at all.
#
# This does not affect linking against the static archive. Hidden visibility
# constrains what a SHARED object re-exports; a symbol stays fully linkable
# within whatever shared object or executable folds the archive in, which is
# exactly how every consumer here uses it.
#
# Held by ClientQtVendoredExportsTest, which reads the built library's dynamic
# symbol table rather than trusting this setting to have had its intended
# effect.
if(TARGET qcbor)
    set_target_properties(qcbor PROPERTIES C_VISIBILITY_PRESET hidden)
endif()
