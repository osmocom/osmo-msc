AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS= \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

noinst_HEADERS = \
	$(NULL)

noinst_LIBRARIES = libsmpputil.a

libsmpputil_a_SOURCES = \
	smpp_utils.c \
	smpp_vty.c \
	smpp_msc.c \
	smpp_smsc.c \
	$(NULL)
