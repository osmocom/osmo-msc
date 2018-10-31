if BUILD_MANUALS
  ASCIIDOC = osmomsc-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmomsc-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
