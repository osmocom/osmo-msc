AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMOSCCP_CFLAGS) \
	$(LIBOSMOMGCPCLIENT_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)

noinst_HEADERS = \
	$(NULL)

noinst_LIBRARIES = \
	libmsc.a \
	$(NULL)

libmsc_a_SOURCES = \
	a_iface.c \
	a_iface_bssap.c \
	a_reset.c \
	msc_vty.c \
	db.c \
	gsm_04_08.c \
	gsm_04_08_cc.c \
	gsm_04_11.c \
	gsm_04_14.c \
	gsm_04_80.c \
	gsm_09_11.c \
	gsm_subscriber.c \
	mncc.c \
	mncc_builtin.c \
	mncc_sock.c \
	msc_ifaces.c \
	msc_mgcp.c \
	rrlp.c \
	silent_call.c \
	sms_queue.c \
	transaction.c \
	osmo_msc.c \
	ctrl_commands.c \
	subscr_conn.c \
	$(NULL)
if BUILD_IU
libmsc_a_SOURCES += \
	iucs.c \
	iucs_ranap.c \
	$(NULL)
else
libmsc_a_SOURCES += \
	iu_dummy.c \
	$(NULL)
endif

if BUILD_SMPP
noinst_HEADERS += \
	smpp_smsc.h \
	$(NULL)

libmsc_a_SOURCES += \
	smpp_smsc.c \
	smpp_openbsc.c \
	smpp_vty.c \
	smpp_utils.c \
	$(NULL)
endif
