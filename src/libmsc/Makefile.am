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
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libmsc.a \
	$(NULL)

libmsc_a_SOURCES = \
	call_leg.c \
	cell_id_list.c \
	codec_filter.c \
	codec_mapping.c \
	csd_bs.c \
	csd_filter.c \
	sccp_ran.c \
	msc_vty.c \
	db.c \
	e_link.c \
	gsm_04_08.c \
	gsm_04_08_cc.c \
	gsm_04_11.c \
	gsm_04_11_gsup.c \
	gsm_04_14.c \
	gsm_04_80.c \
	gsm_09_11.c \
	gsup_client_mux.c \
	mncc.c \
	mncc_builtin.c \
	mncc_sock.c \
	mncc_call.c \
	msub.c \
	msc_a.c \
	msc_a_remote.c \
	msc_i.c \
	msc_i_remote.c \
	msc_t.c \
	msc_t_remote.c \
	msc_ho.c \
	msc_vgcs.c \
	neighbor_ident.c \
	neighbor_ident_vty.c \
	paging.c \
	ran_conn.c \
	ran_infra.c \
	ran_msg.c \
	ran_msg_a.c \
	ran_peer.c \
	rrlp.c \
	rtp_stream.c \
	sdp_msg.c \
	silent_call.c \
	sms_queue.c \
	smsc_vty.c \
	transaction.c \
	transaction_cc.c \
	msc_net_init.c \
	ctrl_commands.c \
	sgs_iface.c \
	sgs_server.c \
	sgs_vty.c \
	asci_gcr.c \
	asci_vty.c \
	$(NULL)

if BUILD_IU
libmsc_a_SOURCES += \
	ran_msg_iu.c \
	$(NULL)
endif
