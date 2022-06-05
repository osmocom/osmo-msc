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
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	sms_storage_test.ok \
	sms_storage_test.err \
	$(NULL)

check_PROGRAMS = \
	sms_storage_test \
	$(NULL)

sms_storage_test_SOURCES = \
	sms_storage_test.c \
	$(NULL)

sms_storage_test_LDADD = \
	-lsctp \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBRARY_GSM) \
	$(NULL)

sms_storage_test_LDFLAGS = \
	-Wl,--wrap=db_sms_get_next_unsent_rr_msisdn \
	$(NULL)
