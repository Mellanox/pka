%global _hardened_build 1
%{!?rhel: %global rhel 8}

%if 0%{?rhel} < 8
%global openssl_ver 11
%global configure_flags --with-libcrypto=libcrypto11 LIBCRYPTO_LIBS="-l:libcrypto.so.1.1"
%endif

Name: libpka
Epoch: 1
Version: 2.0
Release: 3%{?dist}
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
Summary: OpenSSL PKA crypto module for NVIDIA BlueField PKA
Group: Development/Libraries
ExclusiveArch: aarch64
Requires: %{name} = %{epoch}:%{version}-%{release}, openssl%{?openssl_ver}-libs

%description engine
This package provides OpenSSL crypto module support for BlueField PKA hardware
(legacy ENGINE where available, and Provider API on OpenSSL versions that removed ENGINE).

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
%configure --docdir=%{_docdir}/%{name} %{?configure_flags}
%make_build

%install
%make_install
find %{buildroot} -name "*.la" -delete
engine_so_path=`find %{buildroot}%{_libdir} -iname 'libbfengine.so' -print -quit`
if [ -n "$engine_so_path" ]; then
    engine_link_target=`find %{buildroot}%{_libdir} -iname 'libbfengine.so' -printf '%%h/pka.so' -quit`
    %{__ln_s} libbfengine.so "$engine_link_target"
fi

%files
%defattr(-, root, root)
%license %{_docdir}/%{name}/COPYING
%doc %{_docdir}/%{name}/README
%{_libdir}/*.so*

%files engine
%defattr(-, root, root)
%license %{_docdir}/%{name}/COPYING
%doc %{_docdir}/%{name}/README.engine
%if 0%{?rhel} >= 10
%{_libdir}/ossl-modules/libbfprovider.so
%else
%{_libdir}/engine*/*.so
%endif

%files testutils
%defattr(-, root, root)
%license %{_docdir}/%{name}/COPYING
%doc %{_docdir}/%{name}/README.tests
%{_bindir}/pka_*

%files devel
%defattr(-, root, root)
%license %{_docdir}/%{name}/COPYING
%{_includedir}/*.h

%files doc
%defattr(-, root, root)
%license %{_docdir}/%{name}/COPYING
%doc %{_docdir}/%{name}/html
%doc %{_docdir}/%{name}/pdf
