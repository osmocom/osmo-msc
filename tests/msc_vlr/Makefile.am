AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-Wl,--wrap=osmo_gsup_client_create2 \
	-Wl,--wrap=osmo_gsup_client_send \
	-Wl,--wrap=gsm340_gen_scts \
	-Wl,--wrap=osmo_get_rand_id \
	-Wl,--wrap=ran_peers_down_paging \
	-Wl,--wrap=call_leg_ensure_ci \
	$(NULL)

LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBRARY_GSM) \
	-ldbi \
	-lrt \
	$(NULL)

noinst_HEADERS = \
	msc_vlr_tests.h \
	stubs.h \
	$(NULL)

EXTRA_DIST = \
	msc_vlr_test_no_authen.ok \
	msc_vlr_test_no_authen.err \
	msc_vlr_test_gsm_authen.ok \
	msc_vlr_test_gsm_authen.err \
	msc_vlr_test_gsm_ciph.ok \
	msc_vlr_test_gsm_ciph.err \
	msc_vlr_test_umts_authen.ok \
	msc_vlr_test_umts_authen.err \
	msc_vlr_test_authen_reuse.ok \
	msc_vlr_test_authen_reuse.err \
	msc_vlr_test_hlr_reject.ok \
	msc_vlr_test_hlr_reject.err \
	msc_vlr_test_hlr_timeout.ok \
	msc_vlr_test_hlr_timeout.err \
	msc_vlr_test_ms_timeout.ok \
	msc_vlr_test_ms_timeout.err \
	msc_vlr_test_reject_concurrency.ok \
	msc_vlr_test_reject_concurrency.err \
	msc_vlr_test_call.ok \
	msc_vlr_test_call.err \
	msc_vlr_test_rest.ok \
	msc_vlr_test_rest.err \
	msc_vlr_test_ss.ok \
	msc_vlr_test_ss.err \
	$(NULL)

noinst_PROGRAMS = \
	msc_vlr_test_no_authen \
	msc_vlr_test_gsm_authen \
	msc_vlr_test_gsm_ciph \
	msc_vlr_test_umts_authen \
	msc_vlr_test_authen_reuse \
	msc_vlr_test_hlr_reject \
	msc_vlr_test_hlr_timeout \
	msc_vlr_test_ms_timeout \
	msc_vlr_test_reject_concurrency \
	msc_vlr_test_call \
	msc_vlr_test_rest \
	msc_vlr_test_ss \
	$(NULL)

msc_vlr_test_no_authen_SOURCES = \
	msc_vlr_test_no_authen.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_gsm_authen_SOURCES = \
	msc_vlr_test_gsm_authen.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_gsm_ciph_SOURCES = \
	msc_vlr_test_gsm_ciph.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_umts_authen_SOURCES = \
	msc_vlr_test_umts_authen.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_authen_reuse_SOURCES = \
	msc_vlr_test_authen_reuse.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_hlr_reject_SOURCES = \
	msc_vlr_test_hlr_reject.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_hlr_timeout_SOURCES = \
	msc_vlr_test_hlr_timeout.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_ms_timeout_SOURCES = \
	msc_vlr_test_ms_timeout.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_reject_concurrency_SOURCES = \
	msc_vlr_test_reject_concurrency.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_call_SOURCES = \
	msc_vlr_test_call.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_rest_SOURCES = \
	msc_vlr_test_rest.c \
	msc_vlr_tests.c \
	$(NULL)

msc_vlr_test_ss_SOURCES = \
	msc_vlr_test_ss.c \
	msc_vlr_tests.c \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/msc_vlr_test_no_authen >$(srcdir)/msc_vlr_test_no_authen.ok 2>$(srcdir)/msc_vlr_test_no_authen.err
	$(builddir)/msc_vlr_test_gsm_authen >$(srcdir)/msc_vlr_test_gsm_authen.ok 2>$(srcdir)/msc_vlr_test_gsm_authen.err
	$(builddir)/msc_vlr_test_gsm_ciph >$(srcdir)/msc_vlr_test_gsm_ciph.ok 2>$(srcdir)/msc_vlr_test_gsm_ciph.err
	$(builddir)/msc_vlr_test_umts_authen >$(srcdir)/msc_vlr_test_umts_authen.ok 2>$(srcdir)/msc_vlr_test_umts_authen.err
	$(builddir)/msc_vlr_test_authen_reuse >$(srcdir)/msc_vlr_test_authen_reuse.ok 2>$(srcdir)/msc_vlr_test_authen_reuse.err
	$(builddir)/msc_vlr_test_hlr_reject >$(srcdir)/msc_vlr_test_hlr_reject.ok 2>$(srcdir)/msc_vlr_test_hlr_reject.err
	$(builddir)/msc_vlr_test_hlr_timeout >$(srcdir)/msc_vlr_test_hlr_timeout.ok 2>$(srcdir)/msc_vlr_test_hlr_timeout.err
	$(builddir)/msc_vlr_test_ms_timeout >$(srcdir)/msc_vlr_test_ms_timeout.ok 2>$(srcdir)/msc_vlr_test_ms_timeout.err
	$(builddir)/msc_vlr_test_reject_concurrency >$(srcdir)/msc_vlr_test_reject_concurrency.ok 2>$(srcdir)/msc_vlr_test_reject_concurrency.err
	$(builddir)/msc_vlr_test_call >$(srcdir)/msc_vlr_test_call.ok 2>$(srcdir)/msc_vlr_test_call.err
	$(builddir)/msc_vlr_test_rest >$(srcdir)/msc_vlr_test_rest.ok 2>$(srcdir)/msc_vlr_test_rest.err
	$(builddir)/msc_vlr_test_ss >$(srcdir)/msc_vlr_test_ss.ok 2>$(srcdir)/msc_vlr_test_ss.err
