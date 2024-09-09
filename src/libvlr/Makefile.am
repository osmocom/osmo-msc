AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS= \
	   -Wall \
	   $(LIBOSMOCORE_CFLAGS) \
	   $(LIBOSMOVTY_CFLAGS) \
	   $(LIBOSMOSIGTRAN_CFLAGS) \
	   $(LIBOSMOMGCPCLIENT_CFLAGS) \
	   $(LIBOSMOGSUPCLIENT_CFLAGS) \
	   $(LIBOSMOABIS_CFLAGS) \
	   $(LIBOSMORANAP_CFLAGS) \
	   $(LIBOSMOGSM_CFLAGS) \
	   $(COVERAGE_CFLAGS) \
	   $(NULL)

noinst_HEADERS = \
	vlr_access_req_fsm.h \
	vlr_auth_fsm.h \
	vlr_core.h \
	vlr_lu_fsm.h \
	vlr_sgs_fsm.h \
	$(NULL)

noinst_LIBRARIES = libvlr.a

libvlr_a_SOURCES = \
	vlr.c \
	vlr_access_req_fsm.c \
	vlr_auth_fsm.c \
	vlr_lu_fsm.c \
	vlr_sgs.c \
	vlr_sgs_fsm.c \
	$(NULL)
