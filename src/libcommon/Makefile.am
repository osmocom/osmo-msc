AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libcommon.a \
	$(NULL)

libcommon_a_SOURCES = \
	gsm_data.c \
	gsup_client.c \
	oap_client.c \
	$(NULL)

noinst_PROGRAMS = \
	gsup_test_client \
	$(NULL)

gsup_test_client_SOURCES = \
	gsup_test_client.c \
	$(NULL)
gsup_test_client_LDADD = \
	libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	-lrt \
	$(NULL)
