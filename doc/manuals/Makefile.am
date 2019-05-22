EXTRA_DIST = osmomsc-usermanual.adoc \
    osmomsc-usermanual-docinfo.xml \
    osmomsc-vty-reference.xml \
    chapters \
    images \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmomsc-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmomsc-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-msc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
