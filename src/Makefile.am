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

# Libraries
SUBDIRS = \
	libvlr \
	libmsc \
	$(NULL)

if BUILD_SMPP

SUBDIRS += \
	libsmpputil \
	utils \
	$(NULL)

endif

# Programs
SUBDIRS += \
	osmo-msc \
	$(NULL)
