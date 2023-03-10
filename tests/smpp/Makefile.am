AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/libmsc \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	-no-install \
	$(NULL)

EXTRA_DIST = \
	smpp_test.ok \
	smpp_test.err \
	$(NULL)

check_PROGRAMS = \
	smpp_test \
	$(NULL)

smpp_test_SOURCES = \
	smpp_test.c \
	$(NULL)

smpp_test_LDADD = \
	$(top_builddir)/src/libsmpputil/libsmpputil.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(NULL)
