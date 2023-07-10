bin_PROGRAMS = \
	pka_test_validation \
	pka_test_performance

pka_test_validation_SOURCES = validation/pka_test_validation.c pka_test_utils.c

pka_test_performance_SOURCES = performance/pka_test_performance.c pka_test_utils.c

if OPENSSL11
pka_test_validation_LDADD = $(top_builddir)/lib/libPKA.la -L/usr/lib64/openssl11 -l:libcrypto.so.1.1
pka_test_performance_LDADD = $(top_builddir)/lib/libPKA.la -L/usr/lib64/openssl11 -l:libcrypto.so.1.1
else
pka_test_validation_LDADD = $(top_builddir)/lib/libPKA.la -lcrypto
pka_test_performance_LDADD = $(top_builddir)/lib/libPKA.la -lcrypto
endif

AM_CFLAGS = \
	-std=gnu99 -O2 -g -Wall -Werror -Wno-unused-but-set-variable \
	-I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(srcdir)

AM_LDFLAGS = -lrt -lpthread
