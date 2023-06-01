lib_LTLIBRARIES = libbfengine.la

libbfengine_la_SOURCES = e_bluefield.c helper/pka_helper.c
libbfengine_la_LIBADD = $(top_builddir)/lib/libPKA.la

if OPENSSL11
libbfengine_la_CFLAGS = \
        -fPIC -O3 -g -Wall -Werror \
        -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/engine/helper \
        -DOPENSSL_API_COMPAT=0x10100000L -I/usr/include/openssl11
else
libbfengine_la_CFLAGS = \
        -fPIC -O3 -g -Wall -Werror \
        -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/engine/helper \
        -DOPENSSL_API_COMPAT=0x10100000L
endif


libbfengine_la_LDFLAGS = -lcrypto -version-info 2:0:1
