AC_PREREQ([2.69])
m4_define([libpka_VERSION], [2.0])
AC_INIT([libpka], m4_defn([libpka_VERSION]), [networking-support@nvidia.com], [libpka-]m4_defn([libpka_VERSION]), [https://github.com/Mellanox/pka])
AC_CONFIG_SRCDIR([engine/e_bluefield.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CANONICAL_HOST
AC_MSG_CHECKING([host architecture])
AS_IF(
    [test x"${host_cpu}" == x"aarch64"],
    [AC_MSG_RESULT([ok])],
    [AC_MSG_ERROR([only aarch64 is supported])]
)

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AS
PKG_PROG_PKG_CONFIG

AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h sys/ioctl.h sys/time.h unistd.h])
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([gettimeofday memset munmap strcasecmp strrchr strtol])

AX_PTHREAD


LT_INIT([shared disable-static pic-only])

enabled_subdirs=lib

dnl Checks for tests utils
AC_ARG_ENABLE([testutils],
    [AS_HELP_STRING([--enable-testutils], [Disable building PKA tests utilities])]
)

AS_IF([test x"$enable_testutils" != x"no"],
    [enabled_subdirs="$enabled_subdirs tests"]
)

dnl Checks if need to enable openssl pka engine
AC_ARG_WITH([libcrypto],
    [AS_HELP_STRING([--with-libcrypto], [Build PKA openssl engine if libcrypto is present and have version no less than 1.1. This requires pkg-config program and pc file for libcrypto (Default: libcrypto)])],
    [with_libcrypto="${withval}"],
    [with_libcrypto="libcrypto"])

AS_IF([test x"with_libcrypto" != x"no"],
    [PKG_CHECK_MODULES([LIBCRYPTO],
        ["${with_libcrypto}" >= 1.1.0],[],
        [AC_MSG_ERROR([libcrypto library is either not found or its version less than 1.1 (to disable use --without-libcrypto)])]
    )
    enabled_subdirs="$enabled_subdirs engine"
    cryptoenginesdir="`$PKG_CONFIG --variable=enginesdir --silence-errors ${with_libcrypto}`"

    AC_SUBST([cryptoenginesdir])
    AC_SUBST([LIBCRYPTO_CFLAGS])
    AC_SUBST([LIBCRYPTO_LIBS])
    ]
)


dnl Documentation
AC_ARG_WITH([doxygen],
    [AS_HELP_STRING([--with-doxygen], [Generate documentation. This requires doxygen program (Default: yes)])],
    [],
    [with_doxygen=yes])

AC_PATH_TOOL([DOXYGEN],[doxygen])

AS_IF([test x"$with_doxygen" != x"no" -a x"$DOXYGEN" != x""],
    [enabled_subdirs="$enabled_subdirs doc"],
    [AC_MSG_ERROR([doxygen not found (to disable use --without-doxygen)])]
)

AC_SUBST([DOXYGEN])
AC_SUBST([AM_CPPFLAGS],["-I\$(top_srcdir)/lib -I\$(top_srcdir)/include"])
AC_SUBST([ENABLED_SUBDIRS],[$enabled_subdirs])
AC_CONFIG_FILES([Makefile lib/Makefile engine/Makefile tests/Makefile doc/Makefile])
AC_OUTPUT
