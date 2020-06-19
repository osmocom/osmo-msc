EXTRA_DIST = osmomsc-usermanual.adoc \
    osmomsc-usermanual-docinfo.xml \
    osmomsc-vty-reference.xml \
    regen_doc.sh \
    chapters \
    images \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmomsc-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmomsc-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  BUILT_REFERENCE_XML = $(builddir)/vty/msc_vty_reference.xml
  $(builddir)/vty/msc_vty_reference.xml: $(top_builddir)/src/osmo-msc/osmo-msc
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/osmo-msc/osmo-msc --vty-ref-xml > $@

  OSMO_REPOSITORY = osmo-msc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
