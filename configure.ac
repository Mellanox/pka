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
    [test x"$host_cpu" = x"aarch64"],
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

ENABLED_SUBDIRS=lib

dnl Checks for tests utils
AC_ARG_ENABLE([testutils],
    [AS_HELP_STRING([--disable-testutils], [Disable building PKA tests utilities (Default: yes)])],
    [],
    [enable_testutils=yes])

AS_IF([test x"$enable_testutils" != x"no"],
    [ENABLED_SUBDIRS="$ENABLED_SUBDIRS tests"]
)

AC_ARG_WITH([libcrypto],
    [AS_HELP_STRING([--with-libcrypto], [Use specific libcrypto library. Must be at least version 1.1. Library search is done using pkg-config. (Default: libcrypto)])],
    [],
    [with_libcrypto=libcrypto])

PKG_CHECK_MODULES([LIBCRYPTO],
    ["$with_libcrypto" >= 1.1.0],[],
    [AC_MSG_ERROR([libcrypto library is either not found or its version less than 1.1])])

dnl Checks if need to enable openssl pka engine
AC_ARG_ENABLE([engine],
    [AS_HELP_STRING([--disable-engine], [Build PKA openssl engine (Default: yes)])],
    [],
    [enable_engine=yes])

AS_IF([test x"$enable_engine" != x"no"],
    [ENABLED_SUBDIRS="$ENABLED_SUBDIRS engine"

    cryptoenginesdir=$($PKG_CONFIG --variable=enginesdir --silence-errors $with_libcrypto)
    AC_SUBST([cryptoenginesdir])
    ]
)

dnl Documentation
AC_ARG_WITH([doxygen],
    [AS_HELP_STRING([--with-doxygen], [Generate documentation. This requires doxygen program (Default: doxygen)])],
    [],
    [with_doxygen=doxygen])

AS_IF([test x"$with_doxygen" != x"no"],
    [AC_PATH_TOOL([DOXYGEN],["$with_doxygen"])
    AS_IF([test x"$DOXYGEN" = x""],
        [AC_MSG_ERROR([documentation requested but doxygen is not found (to disable use --without-doxygen)])]
    )
    ENABLED_SUBDIRS="$ENABLED_SUBDIRS doc"
    AC_SUBST([DOXYGEN])
    ]
)

AC_SUBST([AM_CPPFLAGS],["-I\$(top_srcdir)/lib -I\$(top_srcdir)/include"])
AC_SUBST([ENABLED_SUBDIRS])
AC_CONFIG_FILES([Makefile lib/Makefile engine/Makefile tests/Makefile doc/Makefile])
AC_OUTPUT
