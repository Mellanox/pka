AC_INIT([pka], [2.0], [shihyic@nvidia.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_PROG_CC
AM_PROG_AS
AM_PROG_AR
AM_PROG_CC_C_O

LT_INIT([shared disable-static])

dnl Checks for doxygen
AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])

dnl Checks for openssl
AC_ARG_ENABLE([engine],
              [AS_HELP_STRING([--disable-engine],
                              [Disable support for PKA engine])],
              [],
              [enable_engine=yes])
FOUND_SSL_LIB="no"
if test "x$enable_engine" != xno;
   then
    AC_SEARCH_LIBS([crypto], CRYPTO_new_ex_data, [],
                   [AC_MSG_WARN([can't find library 'crypto'])])
    AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [FOUND_SSL_LIB="yes"])
    AC_CHECK_LIB([ssl], [SSL_library_init], [FOUND_SSL_LIB="yes"])
    AC_CHECK_FILE(/usr/include/openssl11, OPENSSLV=11, [])
    AS_IF([test "x$FOUND_SSL_LIB" = xno],
            AC_MSG_ERROR([can't find library 'ssl']))
fi
AM_CONDITIONAL(OPENSSL11, test "x$OPENSSLV" = x11)
AM_CONDITIONAL([HAVE_SSL_LIB], [test "x$FOUND_SSL_LIB" = xyes])
AM_COND_IF([HAVE_SSL_LIB], [AC_CONFIG_FILES([engine/Makefile])])

dnl Checks for tests suite
AC_ARG_ENABLE([tests],
              AS_HELP_STRING([--disable-tests],
                             [Disable support for PKA tests]),
              [],
              [enable_tests=yes])
AM_CONDITIONAL([MAKE_TESTS], [test "x$enable_tests" != xno])
AM_COND_IF([MAKE_TESTS], [AC_CONFIG_FILES([tests/Makefile])])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  doc/Makefile
])
AC_OUTPUT
