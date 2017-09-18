# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

topdir = .
msc_reference = $(topdir)/osmomsc-vty-reference.xml
manuals = $(msc_reference)
# types = pdf txt rtf ps xhtml html man tex texi dvi
# types = pdf txt
types = $(docbooktotypes)
docbooktotypes = pdf
# htmlcssfile =
# htmlcss =

TOPDIR := ..
ASCIIDOCS := osmomsc-usermanual

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmomsc-usermanual.pdf: chapters/*.adoc generated/docbook_vty.xml

clean:
	-rm -rf $(cleanfiles)
	-rm osmomsc-usermanual__*.svg
	-rm osmomsc-usermanual__*.png
	-rm osmomsc-usermanual.check

generated/docbook_vty.xml: osmomsc-vty-reference.xml vty/*xml ../common/vty_additions.xml ../vty_reference.xsl
	$(call command,xsltproc -o generated/combined1.xml \
		--stringparam with $(PWD)/../common/vty_additions.xml \
		$(MERGE_DOC) vty/msc_vty_reference.xml, \
		XSLTPROC,Merging Common VTY)
	$(call command,xsltproc -o generated/combined2.xml \
		--stringparam with $(PWD)/../common/bsc_vty_additions.xml \
		$(MERGE_DOC) generated/combined1.xml, \
		XSLTPROC,Merging Common BSC VTY)
	$(call command,xsltproc -o generated/combined3.xml \
		--stringparam with $(PWD)/vty/msc_vty_additions.xml \
		$(MERGE_DOC) generated/combined2.xml, \
		XSLTPROC,Merging MSC VTY)
	$(call command,xsltproc ../vty_reference.xsl generated/combined3.xml > generated/docbook_vty.xml, \
		XSLTPROC,Converting MSC VTY to DocBook)
