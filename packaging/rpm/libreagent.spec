# The bundled OpenSSL that the middleware links carries x86_64 objects only,
# and this repository links the middleware.
%global _lto_cflags %{nil}

Name:           libreagent
Version:        5.0.0
Release:        1%{?dist}
Summary:        Core, wire format and Qt client library for the LibreSCRS smart-card agent

License:        LGPL-2.1-or-later AND BSD-3-Clause
URL:            https://github.com/LibreSCRS/LibreAgent
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64

BuildRequires:  cmake >= 3.28
BuildRequires:  ninja-build
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconf-pkg-config
# cmake/GitVersion.cmake calls find_package(Git REQUIRED) before project().
BuildRequires:  git
BuildRequires:  qt6-qtbase-devel
BuildRequires:  openssl-devel
BuildRequires:  librescrs-middleware-devel >= 5.0
# Configure-time, not check-time. The neutral test tree is added whenever this
# project is the top-level one, so find_package(GTest REQUIRED) and
# find_program(dbus-run-session REQUIRED) both run even with testing disabled.
BuildRequires:  gtest-devel
BuildRequires:  dbus-daemon

%description
LibreAgent is the platform-neutral core of the LibreSCRS smart-card agent: the
agent brain, the CBOR wire encoder and decoder, the PKCS#11 facade and the Qt client library
desktop front-ends link against.

This source package produces the component packages below and no package of its
own name.

%package -n librescrs-agent-common-devel
Summary:        Shared CMake package and wire contract for the LibreSCRS agent
# Not noarch: the CMake package lives under the architecture's library
# directory, where find_package() looks for it.

%description -n librescrs-agent-common-devel
The CMake CONFIG package, the platform-neutral public headers and the wire
description shared by the agent and by every client of it.

One package has to own the CMake config and its version file, because they are
installed from every configuration. Making either component package own them
would drag Qt into the agent's dependency closure or the smart-card library into
every Qt client's, so a third, dependency-free package holds what both need.

%package -n librescrs-agent-core-devel
Summary:        LibreSCRS agent core, wire format and PKCS#11 facade (static)
Requires:       librescrs-agent-common-devel = %{version}-%{release}
Requires:       librescrs-middleware-devel%{?_isa} >= 5.0

%description -n librescrs-agent-core-devel
The platform-neutral agent brain and everything a host links against it: the
wire format, the PKCS#11 facade and its socket transport, and the test-support
archive.

These are static archives with no shared counterpart, so this package has no
runtime sibling and a host depends on it only to build. The Fedora guideline
that static archives belong in a -static package is deliberately not applied
here: there is no shared library beside them, so a -static package would
leave this development package empty.

%package -n librescrs-agent-client-qt
Summary:        Qt client library for the LibreSCRS smart-card agent

%description -n librescrs-agent-client-qt
The library desktop front-ends link against to talk to the agent over its
session-bus interface.

%package -n librescrs-agent-client-qt-devel
Summary:        Development files for the LibreSCRS agent Qt client library
Requires:       librescrs-agent-client-qt%{?_isa} = %{version}-%{release}
Requires:       librescrs-agent-common-devel = %{version}-%{release}
# The ClientQtTestSupport component shipped here links LibreAgent::Wire, which
# the core development package carries.
Requires:       librescrs-agent-core-devel = %{version}-%{release}
Requires:       qt6-qtbase-devel

%description -n librescrs-agent-client-qt-devel
Headers, the symbolic link the linker resolves and the CMake component targets
for building against the Qt client library.

%prep
%autosetup -n %{name}-%{version}

%build
test -f thirdparty/QCBOR/CMakeLists.txt || \
  { echo "thirdparty/QCBOR is missing; the source tarball has to carry it"; exit 1; }
%cmake -GNinja \
    -DBUILD_TESTING=OFF \
    -DINSTALL_GTEST=OFF \
    -DLIBREAGENT_BUILD_CORE=ON \
    -DLIBREAGENT_BUILD_WIRE=ON \
    -DLIBREAGENT_BUILD_CLIENT_QT=ON \
    -DLIBREAGENT_BUILD_PKCS11_FACADE=ON \
    -DLIBREAGENT_BUILD_PKCS11_SOCKET_CLIENT=ON \
    -DLIBREAGENT_INSTALL_WIRE_ARCHIVE=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_QCBOR=%{_builddir}/%{name}-%{version}/thirdparty/QCBOR
# Assert the fetch did not happen, and say which source was used. _deps itself
# exists on every correct build -- FetchContent_MakeAvailable does
# add_subdirectory into _deps/qcbor-build even with nothing downloaded -- so the
# directory to look for is the one only a download step creates.
test ! -e %{_vpath_builddir}/_deps/qcbor-subbuild || \
  { echo "the build fetched QCBOR; every source must come from the tarball"; exit 1; }
grep -q '^FETCHCONTENT_SOURCE_DIR_QCBOR:.*/thirdparty/QCBOR$' %{_vpath_builddir}/CMakeCache.txt || \
  { echo "QCBOR source dir is not the one shipped in the tarball"; exit 1; }
%cmake_build

%install
%cmake_install

%files -n librescrs-agent-common-devel
%license LICENSE
%dir %{_libdir}/cmake/LibreAgent
%{_libdir}/cmake/LibreAgent/LibreAgentConfig.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentConfigVersion.cmake
%{_libdir}/cmake/LibreAgent/Pkcs11ModuleExport.cmake
%{_includedir}/LibreSCRS/Agent/
%dir %{_datadir}/librescrs
%{_datadir}/librescrs/librescrs-agent.cddl
%{_datadir}/librescrs/pkcs11/

%files -n librescrs-agent-core-devel
%{_libdir}/libLibreAgentCore.a
%{_libdir}/libLibreAgentWire.a
%{_libdir}/libLibreAgentPkcs11Facade.a
%{_libdir}/libLibreAgentPkcs11SocketClient.a
%{_libdir}/libSyntheticMasterList.a
%{_libdir}/cmake/LibreAgent/LibreAgentCoreTargets*.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentWireTargets*.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentPkcs11FacadeTargets*.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentPkcs11SocketClientTargets*.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentTestSupportTargets*.cmake
%{_includedir}/LibreSCRS/AgentTestSupport/

%files -n librescrs-agent-client-qt
%license LICENSE
%{_libdir}/liblibrescrs-agentclient-qt.so.*

%files -n librescrs-agent-client-qt-devel
%{_libdir}/liblibrescrs-agentclient-qt.so
%{_libdir}/liblibrescrs-agentclient-qt-testsupport.a
%{_libdir}/cmake/LibreAgent/LibreAgentClientQtTargets*.cmake
%{_libdir}/cmake/LibreAgent/LibreAgentClientQtTestSupportTargets*.cmake
%{_includedir}/LibreSCRS/AgentClient/
%{_includedir}/LibreSCRS/AgentClientTestSupport/

%changelog
* Fri Sep 04 2026 LibreSCRS <librescrs@proton.me> - 5.0.0-1
- Initial RPM packaging of the LibreSCRS agent libraries.
