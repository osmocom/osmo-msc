#ifndef _TRANSACT_H
#define _TRANSACT_H

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/gsm/gsm0411_smc.h>
#include <osmocom/gsm/gsm0411_smr.h>

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
	struct gsm_subscriber_connection *conn;

	/* reference from MNCC or other application */
	uint32_t callref;

	/* if traffic channel receive was requested */
	int tch_recv;

	/* is thats one paging? */
	struct subscr_request *paging_request;

	/* bearer capabilities (rate and codec) */
	struct gsm_mncc_bearer_cap bearer_cap;

	/* status of the assignment, true when done */
	bool assignment_done;

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
		} ss;
	};

	struct {
		struct gsm_trans *peer;
		enum bridge_state state;
	} bridge;
};



struct gsm_trans *trans_find_by_id(struct gsm_subscriber_connection *conn,
				   uint8_t proto, uint8_t trans_id);
struct gsm_trans *trans_find_by_callref(struct gsm_network *net,
					uint32_t callref);
struct gsm_trans *trans_find_by_sm_rp_mr(struct gsm_subscriber_connection *conn,
					 uint8_t sm_rp_mr);

struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct vlr_subscr *vsub,
			      uint8_t protocol, uint8_t trans_id,
			      uint32_t callref);
void trans_free(struct gsm_trans *trans);

int trans_assign_trans_id(struct gsm_network *net, struct vlr_subscr *vsub,
			  uint8_t protocol, uint8_t ti_flag);
struct gsm_trans *trans_has_conn(const struct gsm_subscriber_connection *conn);
void trans_conn_closed(struct gsm_subscriber_connection *conn);

#endif
