Name: libpka
Version: 1.0
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
level, and (4) a dynamic OpenSSL engine component to support RSA
operations and interfaces with the BlueField PKA hardware.

%prep
%setup

%build
%configure
%make_build

%install
%make_install

%files
%defattr(-, root, root)
%{_prefix}/share/*
%{_libdir}/libPKA*
%{_libdir}/libbfengine*
%{_bindir}/*

%doc COPYING
