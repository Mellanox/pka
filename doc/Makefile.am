.PHONY: html
.INTERMEDIATE: html

DX_CONFIG=Doxyfile
DX_HTML_OUTPUT=html
DOCDIR=$(srcdir)
SRCDIR=$(top_srcdir)
OUTPUT_DIRS=pdf html

$(DOCDIR)/$(PACKAGE).tag: $(DX_CONFIG)
	PKGVER=$(PACKAGE_VERSION) DOCDIR=$(DOCDIR) HTML_OUTPUT=$(DX_HTML_OUTPUT) SRCDIR=$(SRCDIR) $(DOXYGEN) $(DX_CONFIG)
	$(AM_V_at)echo Timestamp >$@

clean-local:
	-rm -rf $(DOCDIR)/html $(DOCDIR)/$(PACKAGE).tag

install-data-local:
	@for d in $(OUTPUT_DIRS); do \
	  if ! test -d "$(DESTDIR)$(docdir)"$$d; then \
	    echo "$(mkinstalldirs) '$(DESTDIR)$(docdir)/'$$d"; \
	    $(mkinstalldirs) '$(DESTDIR)$(docdir)/'$$d; \
	  fi; \
	  echo "cp -pR $(srcdir)/$$d '$(DESTDIR)$(docdir)/'"; \
	  cp -pR $(srcdir)/$$d '$(DESTDIR)$(docdir)/' || exit $$?; \
	done

uninstall-local:
	@for d in $(OUTPUT_DIRS); do \
	  echo "test ! -d '$(DESTDIR)$(docdir)/'$$d || \
	  { find '$(DESTDIR)$(docdir)/'$$d -type d ! -perm -200 -exec chmod u+w '{}' ';' && \
	  rm -rf '$(DESTDIR)$(docdir)/'$$d; }"; \
	  test ! -d '$(DESTDIR)$(docdir)/'$$d || \
	  { find '$(DESTDIR)$(docdir)/'$$d -type d ! -perm -200 -exec chmod u+w '{}' ';' && \
	  rm -rf '$(DESTDIR)$(docdir)/'$$d; }; \
	done

html: $(DOCDIR)/$(PACKAGE).tag
all: html
