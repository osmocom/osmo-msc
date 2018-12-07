all: msc dot

msc: \
	$(builddir)/mncc_fsm.png \
	$(builddir)/inter_bsc_ho.png \
	$(builddir)/inter_msc_ho.png \
	$(NULL)

dot: \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
