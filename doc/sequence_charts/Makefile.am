all:
	echo "built only on manual invocation, needs mscgen and dot (graphviz) programs: invoke 'make charts'"

charts: msc dot

EXTRA_DIST = \
	inter_bsc_ho.msc \
	inter_msc_ho.msc \
	mncc_call_fsm.msc \
	$(NULL)

CLEANFILES = \
	inter_bsc_ho.png \
	inter_msc_ho.png \
	mncc_call_fsm.png \
	voice_call_full.png \
	$(NULL)

msc: \
	$(builddir)/mncc_call_fsm.png \
	$(builddir)/inter_bsc_ho.png \
	$(builddir)/inter_msc_ho.png \
	$(builddir)/voice_call_full.png \
	$(NULL)

dot: \
	$(NULL)

$(builddir)/%.png: %.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
