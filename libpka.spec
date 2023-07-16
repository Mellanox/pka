%global _hardened_build 1

Name: libpka
Version: 2.0
Release: 1%{?dist}
Summary: Nvidia BlueField Public Key Acceleration (PKA) library
Group: Development/Libraries
License: BSD-3-Clause AND OpenSSL
URL: https://github.com/Mellanox/pka
Source: %{name}-%{version}.tar.gz

ExclusiveArch: aarch64
BuildRequires: automake, autoconf, doxygen, pkgconfig
%if 0%{?rhel} > 7
BuildRequires: openssl-devel
Requires: openssl-libs
%else
BuildRequires: openssl11-devel
Requires: openssl11-libs
%endif

%description
This package provides Public Key Acceleration (PKA) API implementation for Nvidia BlueField

%package devel
Summary: Development files for libpka
Group: Development/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}

%description devel
Provides header files for linking with libpka

%package engine
Summary: OpenSSL dynamic engine for Nvidia BlueField PKA
Group: Development/Libraries
ExclusiveArch: aarch64
Requires: %{name} = %{epoch}:%{version}-%{release}
%if 0%{?rhel} > 7
BuildRequires: openssl-devel
Requires: openssl-libs
%else
BuildRequires: openssl11-devel
Requires: openssl11-libs
%endif

%description engine
This package provides OpenSSL dynamic engine component to support hardware implementation of
RSA, DSA, DH, ECDH and ECDSA operations with the BlueField PKA hardware.

%package testutils
Summary: Test utilities for Nvidia BlueField PKA
Group: Development/Libraries
ExclusiveArch: aarch64
Requires: %{name} = %{epoch}:%{version}-%{release}

%description testutils
This package provides validation utilities for testing libpka functionality with Nvidia BlueField PKA hardware.

%package doc
Summary: Documentation for libpka package
Group: Documentation

%description doc
Provides libpka API documentation and PDF API specification for libpka package

%prep
%autosetup

%build
autoreconf -fiv
%if 0%{?rhel} > 7
%configure
%else
%configure --with-libcrypto=libcrypto11
%endif

%make_build

%install
%make_install
find %{buildroot} -name "*.la" -delete

%files
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/README
%{_libdir}/*.so*

%files engine
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/README.engine
%{_libdir}/engine*/*.so*

%files testutils
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/README.tests
%{_bindir}/pka_*

%files devel
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%{_includedir}/*.h

%files doc
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/html
%doc %{_pkgdocdir}/pdf
