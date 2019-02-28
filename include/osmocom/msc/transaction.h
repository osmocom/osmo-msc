#pragma once

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/debug.h>
#include <osmocom/gsm/gsm0411_smc.h>
#include <osmocom/gsm/gsm0411_smr.h>

/* Used for late TID assignment */
#define TRANS_ID_UNASSIGNED 0xff

#define LOG_TRANS_CAT(trans, subsys, level, fmt, args...) \
	LOGP(subsys, level, \
	     "trans(%s %s callref-0x%x tid-%u%s) " fmt, \
	     (trans) ? gsm48_pdisc_name((trans)->protocol) : "NULL", \
	     (trans) ? ((trans)->conn ? (trans)->conn->fi->id : vlr_subscr_name((trans)->vsub)) : "NULL", \
	     (trans) ? (trans)->callref : 0, \
	     (trans) ? (trans)->transaction_id : 0, \
	     (trans) && (trans)->paging_request ? ",PAGING" : "", \
	     ##args)

#define LOG_TRANS(trans, level, fmt, args...) \
	     LOG_TRANS_CAT(trans, trans_log_subsys(trans), level, fmt, ##args)

enum bridge_state {
	BRIDGE_STATE_NONE,
	BRIDGE_STATE_LOOPBACK_PENDING,
	BRIDGE_STATE_LOOPBACK_ESTABLISHED,
	BRIDGE_STATE_BRIDGE_PENDING,
	BRIDGE_STATE_BRIDGE_ESTABLISHED,
};

/* One transaction */
struct gsm_trans {
	/* Entry in list of all transactions */
	struct llist_head entry;

	/* Back pointer to the network struct */
	struct gsm_network *net;

	/* The protocol within which we live */
	uint8_t protocol;

	/* The current transaction ID */
	uint8_t transaction_id;

	/* The DLCI (DCCH/ACCH + SAPI) of this transaction */
	uint8_t dlci;

	/* To whom we belong, unique identifier of remote MM entity */
	struct vlr_subscr *vsub;

	/* The associated connection we are using to transmit messages */
	struct ran_conn *conn;

	/* reference from MNCC or other application */
	uint32_t callref;

	/* if traffic channel receive was requested */
	int tch_recv;

	/* is thats one paging? */
	struct subscr_request *paging_request;

	/* bearer capabilities (rate and codec) */
	struct gsm_mncc_bearer_cap bearer_cap;

	/* if true, TCH_RTP_CREATE is sent after the
	 * assignment is done */
	bool tch_rtp_create;

	union {
		struct {

			/* current call state */
			int state;

			/* current timer and message queue */
			int Tcurrent;		/* current CC timer */
			int T308_second;	/* used to send release again */
			struct osmo_timer_list timer;
			struct osmo_timer_list timer_guard;
			struct gsm_mncc msg;	/* stores setup/disconnect/release message */
			bool assignment_started;
		} cc;
		struct {
			struct gsm411_smc_inst smc_inst;
			struct gsm411_smr_inst smr_inst;

			/* SM-RP-MR, Message Reference (see GSM TS 04.11, section 8.2.3) */
			uint8_t sm_rp_mr;

			struct gsm_sms *sms;
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
	};

	struct {
		struct gsm_trans *peer;
		enum bridge_state state;
	} bridge;
};



struct gsm_trans *trans_find_by_id(const struct ran_conn *conn,
				   uint8_t proto, uint8_t trans_id);
struct gsm_trans *trans_find_by_callref(const struct gsm_network *net,
					uint32_t callref);
struct gsm_trans *trans_find_by_sm_rp_mr(const struct gsm_network *net,
					 const struct vlr_subscr *vsub,
					 uint8_t sm_rp_mr);

struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct vlr_subscr *vsub,
			      uint8_t protocol, uint8_t trans_id,
			      uint32_t callref);
void trans_free(struct gsm_trans *trans);

int trans_assign_trans_id(const struct gsm_network *net, const struct vlr_subscr *vsub,
			  uint8_t protocol);
struct gsm_trans *trans_has_conn(const struct ran_conn *conn);
void trans_conn_closed(const struct ran_conn *conn);

static inline int trans_log_subsys(const struct gsm_trans *trans)
{
	if (!trans)
		return DMSC;
	switch (trans->protocol) {
	case GSM48_PDISC_CC:
		return DCC;
	case GSM48_PDISC_SMS:
		return DLSMS;
	default:
		break;
	}
	return DMSC;
}
