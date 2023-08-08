cryptoengines_LTLIBRARIES = libbfengine.la
libbfengine_la_SOURCES = \
	e_bluefield.c \
	helper/pka_helper.c
libbfengine_la_CPPFLAGS = -I$(srcdir)/helper/ $(AM_CPPFLAGS)
libbfengine_la_CFLAGS = -DOPENSSL_API_COMPAT=0x10100000L $(LIBCRYPTO_CFLAGS)
libbfengine_la_LIBADD = $(top_builddir)/lib/libPKA.la $(LIBCRYPTO_LIBS)
libbfengine_la_LDFLAGS = $(AM_LDFLAGS) -module -shared -avoid-version -export-symbols "$(srcdir)/engine.exports"
