lib_LTLIBRARIES = libbfengine.la

libbfengine_la_SOURCES = e_bluefield.c helper/pka_helper.c
libbfengine_la_LIBADD = $(top_builddir)/lib/libPKA.la

libbfengine_la_CFLAGS = \
	-fPIC -O3 -g -Wall -Werror \
	-I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/engine/helper

libbfengine_la_LDFLAGS = -lcrypto -version-info 1
