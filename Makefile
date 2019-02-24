#
# PKA
#

ifneq ($(filter pka, $(PACKAGES)),)

PKA__SRC := $(CTOP)/src

$(call install_shipping_sources, $(CROOT)/stamp_source, \
	$(CROOT), $(PKA__SRC))

PKA__PKALIB_VER = 1.0
PKA__PKALIB_SRC := $(INSTALL_LOCAL_SRC_DIR)/pkalib-$(PKA__PKALIB_VER)

$(call install_shipping_sources, \
  $(CROOT)/stamp_install_source, $(PKA__PKALIB_SRC), $(PKA__SRC))

# PKA Library

$(CROOT)/stamp_autogen: $(CROOT)/stamp_source
	($(TARG_ENV_SETUP); cd $(@D); ./autogen.sh)
	touch $@

$(CROOT)/stamp_configure: $(CROOT)/stamp_autogen
	($(TARG_ENV_SETUP); cd $(@D);	\
		./configure --host=$(TARG_NAME)	\
			    --prefix=$(call globalize, $(@D)/build) \
			    --disable-engine)
	touch $@

$(CROOT)/stamp_build: $(CROOT)/stamp_configure $(root)/linux/build/stamp_headers
	($(TARG_ENV_SETUP); cd $(@D);	\
		$(MAKE) && $(MAKE) install)
	touch $@

# PKA tests

PKA__TESTS := $(CTOP)/tests

PKA__DST := $(call globalize, $(CROOT))/build

PKA__TESTS_VARS := \
	LIB=$(PKA__DST)/lib \
	BIN=$(PKA__DST)/bin \
	SRC=$(PKA__SRC)

$(CROOT)/tests/pka_tests.testok: $(TEST_DEPS) $(CROOT)/stamp_build
	($(TARG_ENV_SETUP); \
		PATH=$(call globalize, $(INSTALL_DIR)/bin):$$PATH \
		$(MAKE) $(PKA__TESTS_VARS) \
			-f $(PKA__TESTS)/Makefile -C $(@D) test)
	touch $@

PKA__TESTS_SIM := $(CROOT)/tests/pka_tests.testok

TEST_GROUP_test += $(PKA__TESTS_SIM)

all: $(CROOT)/stamp_build

endif  # $(PACKAGES)

