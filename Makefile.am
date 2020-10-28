SUBDIRS = lib doc

if HAVE_SSL_LIB
SUBDIRS += engine
endif

if MAKE_TESTS
SUBDIRS += tests
endif

dist_doc_DATA = README README.tests README.engine
