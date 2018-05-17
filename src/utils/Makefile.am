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
	$(SQLITE3_CFLAGS) \
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
	$(LIBSMPP34_CFLAGS) \
	$(NULL)

smpp_mirror_LDADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBSMPP34_LIBS) \
	$(NULL)
endif
