AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(LIBSQLITE3_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	sms_queue_test.ok \
	sms_queue_test.err \
	$(NULL)

check_PROGRAMS = \
	sms_queue_test \
	$(NULL)

sms_queue_test_SOURCES = \
	sms_queue_test.c \
	$(srcdir)/../stubs.c \
	$(NULL)

sms_queue_test_LDADD = \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBSQLITE3_LIBS) \
	$(LIBRARY_GSM) \
	$(NULL)

sms_queue_test_LDFLAGS = \
	-Wl,--wrap=db_sms_get_next_unsent_rr_msisdn \
	$(AM_LDFLAGS) \
	$(NULL)
