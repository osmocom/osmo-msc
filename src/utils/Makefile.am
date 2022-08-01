AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_HEADERS = \
	$(NULL)

bin_PROGRAMS = \
	$(NULL)

if BUILD_SMPP
noinst_PROGRAMS = \
	smpp_mirror \
	$(NULL)

smpp_mirror_SOURCES = \
	smpp_mirror.c \
	$(NULL)

smpp_mirror_CFLAGS = \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

smpp_mirror_LDADD = \
	$(top_builddir)/src/libsmpputil/libsmpputil.a \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMOMGCPCLIENT_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBSQLITE3_LIBS) \
	-lsctp \
	$(NULL)
endif
