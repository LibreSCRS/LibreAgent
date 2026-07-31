# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Downstream find_package smoke: a standalone consumer project that proves the
# installed LibreAgent CONFIG package resolves, exposes the namespaced
# imported target(s) for the requested component(s), and makes the public
# headers reachable under <LibreSCRS/...>. Built out-of-tree against an
# install prefix, not part of the core build.
#
# PKGSMOKE_COMPONENTS picks which component(s) the consumer requests:
#   - unset (the default): reproduces today's componentless
#     find_package(LibreAgent CONFIG) call and links LibreAgent::Core. This is
#     exactly what ci.yml's "Installed CONFIG package smoke" step drives, and
#     what build-linux depends on — its meaning must not change.
#   - ClientQt: requests just that component, proving the CONFIG package
#     resolves it without also running an unrelated component's
#     find_dependency() calls (e.g. Core's LibreMiddleware/OpenSSL). See
#     fixtures/LibreAgentCoreTargets.stub.cmake for the co-installation case
#     this guards against.
cmake_minimum_required(VERSION 3.24)
project(pkgsmoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(PKGSMOKE_COMPONENTS)
    find_package(LibreAgent 4.2 REQUIRED CONFIG COMPONENTS ${PKGSMOKE_COMPONENTS})
else()
    find_package(LibreAgent 4.2 REQUIRED CONFIG)
endif()

if(PKGSMOKE_COMPONENTS STREQUAL "ClientQt")
    add_executable(pkgsmoke main_clientqt.cpp)
    target_link_libraries(pkgsmoke PRIVATE LibreAgent::ClientQt)
else()
    add_executable(pkgsmoke main.cpp)
    target_link_libraries(pkgsmoke PRIVATE LibreAgent::Core)
endif()
