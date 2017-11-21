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
	$(LIBCRYPTO_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	-Wl,--wrap=gsup_client_create \
	-Wl,--wrap=gsup_client_send \
	-Wl,--wrap=a_iface_tx_dtap \
	-Wl,--wrap=a_iface_tx_clear_cmd \
	-Wl,--wrap=a_iface_tx_paging \
	-Wl,--wrap=ranap_iu_tx \
	-Wl,--wrap=ranap_iu_tx_release \
	-Wl,--wrap=ranap_iu_tx_common_id \
	-Wl,--wrap=ranap_iu_page_cs \
	-Wl,--wrap=msc_stop_paging \
	-Wl,--wrap=gsm340_gen_scts \
	-Wl,--wrap=RAND_bytes \
	-Wl,--wrap=msc_call_assignment \
	-Wl,--wrap=msc_call_release \
	$(NULL)

LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBRARY_GSM) \
	-ldbi \
	-lrt \
	$(NULL)

noinst_HEADERS = \
	msc_vlr_tests.h \
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
