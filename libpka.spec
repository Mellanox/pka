Name: libpka
Version: 1.4
Release: 1%{?dist}
Summary: Mellanox BlueField Public Key Acceleration (PKA) Package

License: BSD
Url: https://mellanox.com
Source: %{name}-%{version}.tgz

BuildRequires: binutils
BuildRequires: openssl-devel
BuildRequires: gcc

%description
The PKA software package consists of (1) an API specification, which
is the application writer's view (this is also intended to provide
complete interfaces to use with OpenSSL), (2) an API implementation
for BlueField, (3) validation test suite, an independant set of
test routines that run against the API implementation and verifies
that it correctly implements all of the defined APIs at a functional
level, and (4) a dynamic OpenSSL engine component to support RSA,
DSA, DH, ECDH and ECDSA operations and interfaces with the BlueField
PKA hardware.

%prep
%setup

%build
%configure
%make_build

%install
%make_install
%if 0%{?rhel} == 7
    mkdir -p $RPM_BUILD_ROOT%{_libdir}/openssl/engines
    cp $RPM_BUILD_ROOT%{_libdir}/libbfengine.so.*.*.* $RPM_BUILD_ROOT%{_libdir}/openssl/engines/
%endif
%if 0%{?rhel} == 8
    mkdir -p $RPM_BUILD_ROOT%{_libdir}/engines-1.1
    cp $RPM_BUILD_ROOT%{_libdir}/libbfengine.so.*.*.* $RPM_BUILD_ROOT%{_libdir}/engines-1.1/
%endif

%preun
%if 0%{?rhel} == 7
    rm -f %{_libdir}/openssl/engines/libpka.so
%endif
%if 0%{?rhel} == 8
    rm -f %{_libdir}/engines-1.1/pka.so
%endif

%post
%if 0%{?rhel} == 7
    ln -s %{_libdir}/openssl/engines/libbfengine.so.*.*.* %{_libdir}/openssl/engines/libpka.so
%endif
%if 0%{?rhel} == 8
    ln -s %{_libdir}/engines-1.1/libbfengine.so.*.*.* %{_libdir}/engines-1.1/pka.so
%endif


%files
%defattr(-, root, root)
%{_prefix}/share/*
%{_libdir}/libPKA*
%{_libdir}/libbfengine*
%{_bindir}/*
%if 0%{?rhel} == 7
    %{_libdir}/openssl/engines/libbfengine*
%endif
%if 0%{?rhel} == 8
    %{_libdir}/engines-1.1/libbfengine*
%endif

%doc COPYING
