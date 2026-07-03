# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Downstream find_package smoke: a standalone consumer project that proves the
# installed LibreAgent CONFIG package resolves, exposes the namespaced
# LibreAgent::Core imported target, and makes the public headers reachable
# under <LibreSCRS/Agent/...>. Built out-of-tree against an install prefix, not
# part of the core build.
cmake_minimum_required(VERSION 3.24)
project(pkgsmoke LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(LibreAgent 4.3 REQUIRED CONFIG)
add_executable(pkgsmoke main.cpp)
target_link_libraries(pkgsmoke PRIVATE LibreAgent::Core)
