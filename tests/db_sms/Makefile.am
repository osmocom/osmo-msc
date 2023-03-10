AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(LIBSQLITE3_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	db_sms_test.ok \
	db_sms_test.err \
	$(NULL)

check_PROGRAMS = \
	db_sms_test \
	$(NULL)

db_sms_test_SOURCES = \
	db_sms_test.c \
	$(srcdir)/../stubs.c \
	$(NULL)

db_sms_test_LDADD = \
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
