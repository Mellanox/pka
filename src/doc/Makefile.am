if HAVE_DOXYGEN

doxyfile.stamp: Doxyfile
	$(DOXYGEN) $^
	echo Timestamp > $@

CLEANFILES = doxyfile.stamp

install-html: doxyfile.stamp
	@if [ -z "$(NO_DOXYGEN)" ]; then \
		(echo "Installing HTML documentation in $(DESTDIR)$(docdir)"; \
		$(INSTALL) -d $(DESTDIR)$(docdir)/html/search; \
		for f in `find html -type f` ; do \
			$(INSTALL_DATA) $$f $(DESTDIR)$(docdir)/$$f; \
		done) \
	fi

all-local: doxyfile.stamp

install-data-local: install-html

clean-local:
	$(RM) -r $(top_srcdir)/doc/html

endif
