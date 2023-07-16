AM_CFLAGS = $(PTHREAD_CFLAGS)
LDADD = $(top_builddir)/lib/libPKA.la $(PTHREAD_LIBS)

bin_PROGRAMS = pka_test_validation pka_test_performance
pka_test_validation_SOURCES = validation/pka_test_validation.c pka_test_utils.c
pka_test_performance_SOURCES = performance/pka_test_performance.c pka_test_utils.c
