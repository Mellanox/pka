%global _hardened_build 1
%{!?rhel: %global rhel 8}

%if 0%{?rhel} < 8
%global openssl_ver 11
%global engine_symlink %{_libdir}/openssl/engines/libpka.so
%global configure_flags --with-libcrypto=libcrypto11 LIBCRYPTO_LIBS="-l:libcrypto.so.1.1"
%endif

Name: libpka
Epoch: 1
Version: 2.0
Release: 1%{?dist}
Summary: NVIDIA BlueField Public Key Acceleration (PKA) library
Group: Development/Libraries
License: BSD-3-Clause AND OpenSSL
URL: https://github.com/Mellanox/pka
Source: %{name}-%{version}.tar.gz

ExclusiveArch: aarch64
BuildRequires: automake, autoconf, doxygen, libtool, pkgconfig
BuildRequires: openssl%{?openssl_ver}-devel
Requires: openssl%{?openssl_ver}-libs

%description
This package provides Public Key Acceleration (PKA) API implementation for NVIDIA BlueField

%package devel
Summary: Development files for libpka
Group: Development/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}

%description devel
Provides header files for linking with libpka

%package engine
Summary: OpenSSL dynamic engine for NVIDIA BlueField PKA
Group: Development/Libraries
ExclusiveArch: aarch64
Requires: %{name} = %{epoch}:%{version}-%{release}, openssl%{?openssl_ver}-libs

%description engine
This package provides OpenSSL dynamic engine component to support hardware implementation of
RSA, DSA, DH, ECDH and ECDSA operations with the BlueField PKA hardware.

%package testutils
Summary: Test utilities for NVIDIA BlueField PKA
Group: Development/Libraries
ExclusiveArch: aarch64
Requires: %{name} = %{epoch}:%{version}-%{release}

%description testutils
This package provides validation utilities for testing libpka functionality with NVIDIA BlueField PKA hardware.

%package doc
Summary: Documentation for libpka package
Group: Documentation

%description doc
Provides libpka API documentation and PDF API specification for libpka package

%prep
%autosetup

%build
autoreconf -fiv
%configure --docdir=%{_pkgdocdir} %{?configure_flags}
%make_build

%install
%make_install
find %{buildroot} -name "*.la" -delete
#Create engine symlink because strongswan openssl.cnf tries to load library in different places depending on disto
%if 0%{?rhel} < 8
%{__mkdir_p} %{dirname:%{buildroot}%{engine_symlink}}
%{__ln_s} %{_libdir}/engines-1.1/libbfengine.so %{buildroot}%{engine_symlink}
%else
%{__ln_s} libbfengine.so `find %{buildroot}%{_libdir} -iname 'libbfengine.so' -printf '%%h/pka.so'`
%endif

%files
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/README
%{_libdir}/*.so*

%files engine
%defattr(-, root, root)
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/README.engine
%{_libdir}/engine*/*.so
%{?engine_symlink}

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
