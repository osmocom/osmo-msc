AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

# Libraries
SUBDIRS = \
	libcommon \
	libvlr \
	libmgcp \
	libmsc \
	libcommon-cs \
	$(NULL)

# Programs
SUBDIRS += \
	osmo-msc \
	osmo-bsc_mgcp \
	utils \
	$(NULL)
