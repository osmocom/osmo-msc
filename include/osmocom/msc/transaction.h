#pragma once

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/codec_filter.h>
#include <osmocom/msc/csd_filter.h>
#include <osmocom/gsm/gsm0411_smc.h>
#include <osmocom/gsm/gsm0411_smr.h>

struct vty;

/* Used for late TID assignment */
#define TRANS_ID_UNASSIGNED 0xff

#define LOG_TRANS_CAT_SRC(trans, subsys, level, file, line, fmt, args...) \
	LOGPSRC(subsys, level, file, line, \
		"trans(%s %s callref-0x%x tid-%u%s) " fmt, \
		(trans) ? trans_name(trans) : "NULL", \
		(trans) ? ((trans)->msc_a ? (trans)->msc_a->c.fi->id : vlr_subscr_name((trans)->vsub)) : "NULL", \
		(trans) ? (trans)->callref : 0, \
		(trans) ? (trans)->transaction_id : 0, \
		(trans) && (trans)->paging_request ? ",PAGING" : "", \
		##args)

#define LOG_TRANS_CAT(trans, subsys, level, fmt, args...) \
	LOG_TRANS_CAT_SRC(trans, subsys, level, __FILE__, __LINE__, fmt, ##args)

#define LOG_TRANS(trans, level, fmt, args...) \
	     LOG_TRANS_CAT(trans, (trans) ? (trans)->log_subsys : DMSC, level, fmt, ##args)

enum bridge_state {
	BRIDGE_STATE_NONE,
	BRIDGE_STATE_LOOPBACK_PENDING,
	BRIDGE_STATE_LOOPBACK_ESTABLISHED,
	BRIDGE_STATE_BRIDGE_PENDING,
	BRIDGE_STATE_BRIDGE_ESTABLISHED,
};

enum trans_type {
	TRANS_GCC = GSM48_PDISC_GROUP_CC,
	TRANS_BCC = GSM48_PDISC_BCAST_CC,
	TRANS_CC = GSM48_PDISC_CC,
	TRANS_SMS = GSM48_PDISC_SMS,
	TRANS_USSD = GSM48_PDISC_NC_SS,
	TRANS_SILENT_CALL,
};

extern const struct value_string trans_type_names[];
static inline const char *trans_type_name(enum trans_type val)
{ return get_value_string(trans_type_names, val); }

uint8_t trans_type_to_gsm48_proto(enum trans_type type);

/* One transaction */
struct gsm_trans {
	/* Entry in list of all transactions */
	struct llist_head entry;

	/* Back pointer to the network struct */
	struct gsm_network *net;

	/* What kind of transaction */
	enum trans_type type;
	/* Which category to log on, for LOG_TRANS(). */
	int log_subsys;

	/* The current transaction ID */
	uint8_t transaction_id;

	/* The DLCI (DCCH/ACCH + SAPI) of this transaction */
	uint8_t dlci;

	/* To whom we belong, unique identifier of remote MM entity */
	struct vlr_subscr *vsub;

	/* The associated connection we are using to transmit messages */
	struct msc_a *msc_a;

	/* reference from MNCC or other application */
	uint32_t callref;

	/* reference that may be used by MGW to identify a call */
	uint32_t call_id;

	/* if traffic channel receive was requested */
	int tch_recv;

	/* is thats one paging? */
	struct paging_request *paging_request;

	/* bearer capabilities (rate and codec) */
	struct gsm_mncc_bearer_cap bearer_cap;

	union {
		struct {
			/* State machine of setup process towards BSS */
			struct osmo_fsm_inst *fi;
			/* BSS list with all VGCS/VBS calls */
			struct llist_head bss_list;
			/* Inactivity timeout and timer */
			int inactivity_to;
			struct osmo_timer_list timer_inactivity;
			/* If talker's downlink shall be muted */
			bool mute_talker;
			/* Indicator, if Uplink is used in one cell */
			bool uplink_busy;
			/* BSS that uses the uplink */
			struct vgcs_bss *uplink_bss;
			/* Cell that uses the uplink */
			struct vgcs_bss_cell *uplink_cell;
			/* If uplink is used by the originator */
			bool uplink_originator;
		} gcc;
		struct {

			/* current call state */
			int state;

			/* current timer and message queue */
			int Tcurrent;		/* current CC timer */
			int T308_second;	/* used to send release again */
			struct osmo_timer_list timer;
			struct osmo_timer_list timer_guard;
			struct gsm_mncc msg;	/* stores setup/disconnect/release message */
			bool mncc_initiated;	/* Whether an MNCC Release is necessary on failure */
			struct osmo_lcls *lcls;
			/* SDP as last received from the remote call leg. */
			struct sdp_msg remote;
			/* Track codec/CSD choices from BSS and remote call leg */
			struct codec_filter codecs;
			struct csd_filter csd;
			/* Resulting choice from codecs/bearer services and the
			 * local RTP address to be sent to the remote call leg. */
			struct sdp_msg local;
		} cc;
		struct {
			struct gsm411_smc_inst smc_inst;
			struct gsm411_smr_inst smr_inst;

			/* SM-RP-MR, Message Reference (see GSM TS 04.11, section 8.2.3) */
			uint8_t sm_rp_mr;
			/* More Messages to Send (see 3GPP TS 29.002, section 7.6.8.7) */
			bool sm_rp_mmts_ind;

			struct gsm_sms *sms;

			uint8_t *gsup_source_name;
			size_t gsup_source_name_len;
		} sms;
		struct {
			/**
			 * Stores a GSM 04.80 message to be sent to
			 * a subscriber after successful Paging Response
			 */
			struct msgb *msg;
			/* Inactivity timer, triggers transaction release */
			struct osmo_timer_list timer_guard;
		} ss;
		struct {
			struct gsm0808_channel_type ct;
			struct osmo_sockaddr_str rtp_cn;
			struct vty *from_vty;
		} silent_call;
	};

	struct {
		struct gsm_trans *peer;
		enum bridge_state state;
	} bridge;
};



struct gsm_trans *trans_find_by_type(const struct msc_a *msc_a, enum trans_type type);
struct gsm_trans *trans_find_by_id(const struct msc_a *msc_a,
				   enum trans_type type, uint8_t trans_id);
struct gsm_trans *trans_find_by_callref(const struct gsm_network *net, enum trans_type type,
					uint32_t callref);
struct gsm_trans *trans_find_by_sm_rp_mr(const struct gsm_network *net,
					 const struct vlr_subscr *vsub,
					 uint8_t sm_rp_mr);

struct osmo_lcls *trans_lcls_compose(const struct gsm_trans *trans, bool use_lac);

struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct vlr_subscr *vsub,
			      enum trans_type type, uint8_t trans_id,
			      uint32_t callref);
void trans_free(struct gsm_trans *trans);

int trans_assign_trans_id(const struct gsm_network *net, const struct vlr_subscr *vsub,
			  enum trans_type type);
struct gsm_trans *trans_has_conn(const struct msc_a *msc_a);
void trans_conn_closed(const struct msc_a *msc_a);

static inline int trans_log_subsys(enum trans_type type)
{
	switch (type) {
	case TRANS_GCC:
		return DGCC;
	case TRANS_BCC:
		return DBCC;
	case TRANS_CC:
	case TRANS_SILENT_CALL:
		return DCC;
	case TRANS_SMS:
		return DLSMS;
	case TRANS_USSD:
		return DSS;
	default:
		break;
	}
	return DMSC;
}

const char *trans_name(const struct gsm_trans *trans);
