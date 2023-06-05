lib_LTLIBRARIES = libPKA.la

libPKA_la_SOURCES = \
	pka.c \
	pka_dev.c \
	pka_mem.c \
	pka_ring.c \
	pka_queue.c \
	../include/pka_lock.S

if OPENSSL11
libPKA_la_CFLAGS = \
	-std=gnu99 -O3 -g -Wall -Werror -fpic \
	-I$(top_srcdir)/include -I$(srcdir) -I/usr/include/openssl11
else
libPKA_la_CFLAGS = \
	-std=gnu99 -O3 -g -Wall -Werror -fpic \
	-I$(top_srcdir)/include -I$(srcdir)
endif

libPKA_la_LDFLAGS = -lrt -lpthread -shared -version-info 2:0:1
