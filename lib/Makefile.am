lib_LTLIBRARIES = libPKA.la
libPKA_la_SOURCES = \
	pka.c \
	pka_dev.c \
	pka_mem.c \
	pka_ring.c \
	pka_queue.c \
	../include/pka_lock.S

libPKA_la_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS)
libPKA_la_LIBADD = $(PTHREAD_LIBS) $(LIBCRYPTO_LIBS)
libPKA_la_LDFLAGS = -shared -version-info 2:0:1
