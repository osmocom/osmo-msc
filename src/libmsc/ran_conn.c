/* MSC RAN connection implementation */

/*
 * (C) 2016-2018 by sysmocom s.m.f.c. <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>

#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/iucs.h>

#include "../../bscconfig.h"
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#else
#include <osmocom/msc/iu_dummy.h>
#endif

#define RAN_CONN_TIMEOUT 5 /* seconds */

static const struct value_string ran_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(RAN_CONN_E_COMPLETE_LAYER_3),
	OSMO_VALUE_STRING(RAN_CONN_E_CLASSMARK_UPDATE),
	OSMO_VALUE_STRING(RAN_CONN_E_ACCEPTED),
	OSMO_VALUE_STRING(RAN_CONN_E_COMMUNICATING),
	OSMO_VALUE_STRING(RAN_CONN_E_RELEASE_WHEN_UNUSED),
	OSMO_VALUE_STRING(RAN_CONN_E_MO_CLOSE),
	OSMO_VALUE_STRING(RAN_CONN_E_CN_CLOSE),
	OSMO_VALUE_STRING(RAN_CONN_E_UNUSED),
	{ 0, NULL }
};

static void update_counters(struct osmo_fsm_inst *fi, bool conn_accepted)
{
	struct ran_conn *conn = fi->priv;
	switch (conn->complete_layer3_type) {
	case COMPLETE_LAYER3_LU:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[
				conn_accepted ? MSC_CTR_LOC_UPDATE_COMPLETED
					      : MSC_CTR_LOC_UPDATE_FAILED]);
		break;
	case COMPLETE_LAYER3_CM_SERVICE_REQ:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[
				conn_accepted ? MSC_CTR_CM_SERVICE_REQUEST_ACCEPTED
					      : MSC_CTR_CM_SERVICE_REQUEST_REJECTED]);
		break;
	case COMPLETE_LAYER3_PAGING_RESP:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[
				conn_accepted ? MSC_CTR_PAGING_RESP_ACCEPTED
					      : MSC_CTR_PAGING_RESP_REJECTED]);
		break;
	default:
		break;
	}
}

static void evaluate_acceptance_outcome(struct osmo_fsm_inst *fi, bool conn_accepted)
{
	struct ran_conn *conn = fi->priv;

	update_counters(fi, conn_accepted);

	/* Trigger transactions that we paged for */
	if (conn->complete_layer3_type == COMPLETE_LAYER3_PAGING_RESP) {
		subscr_paging_dispatch(GSM_HOOK_RR_PAGING,
				       conn_accepted ? GSM_PAGING_SUCCEEDED : GSM_PAGING_EXPIRED,
				       NULL, conn, conn->vsub);
	}

	if (conn->complete_layer3_type == COMPLETE_LAYER3_CM_SERVICE_REQ
	    && conn_accepted) {
		conn->received_cm_service_request = true;
		ran_conn_get(conn, RAN_CONN_USE_CM_SERVICE);
	}

	if (conn_accepted)
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_ATTACHED, conn->vsub);
}

static void log_close_event(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	enum gsm48_reject_value *cause = data;
	/* The close event itself is logged by the FSM. We can only add the cause value, if present. */
	if (!cause || !*cause)
		return;
	LOGPFSML(fi, LOGL_NOTICE, "Close event, cause: %s\n", gsm48_reject_value_name(*cause));
}

static void ran_conn_fsm_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case RAN_CONN_E_COMPLETE_LAYER_3:
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_AUTH_CIPH, RAN_CONN_TIMEOUT, 0);
		return;

	case RAN_CONN_E_ACCEPTED:
		evaluate_acceptance_outcome(fi, true);
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_ACCEPTED, RAN_CONN_TIMEOUT, 0);
		return;

	case RAN_CONN_E_MO_CLOSE:
	case RAN_CONN_E_CN_CLOSE:
		log_close_event(fi, event, data);
		evaluate_acceptance_outcome(fi, false);
		/* fall through */
	case RAN_CONN_E_UNUSED:
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASING, RAN_CONN_TIMEOUT, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ran_conn_fsm_auth_ciph(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	/* If accepted, transition the state, all other cases mean failure. */
	switch (event) {
	case RAN_CONN_E_ACCEPTED:
		evaluate_acceptance_outcome(fi, true);
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_ACCEPTED, RAN_CONN_TIMEOUT, 0);
		return;

	case RAN_CONN_E_UNUSED:
		LOGPFSML(fi, LOGL_DEBUG, "Awaiting results for Auth+Ciph, overruling event %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		return;

	case RAN_CONN_E_MO_CLOSE:
	case RAN_CONN_E_CN_CLOSE:
		log_close_event(fi, event, data);
		evaluate_acceptance_outcome(fi, false);
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASING, RAN_CONN_TIMEOUT, 0);
		return;


	default:
		OSMO_ASSERT(false);
	}
}

int ran_conn_classmark_request_then_cipher_mode_cmd(struct ran_conn *conn, bool umts_aka,
					       bool retrieve_imeisv)
{
	int rc;
	conn->geran_set_cipher_mode.umts_aka = umts_aka;
	conn->geran_set_cipher_mode.retrieve_imeisv = retrieve_imeisv;

	rc = a_iface_tx_classmark_request(conn);
	if (rc) {
		LOGP(DMM, LOGL_ERROR, "%s: cannot send BSSMAP Classmark Request\n",
		     vlr_subscr_name(conn->vsub));
		return -EIO;
	}

	osmo_fsm_inst_state_chg(conn->fi, RAN_CONN_S_WAIT_CLASSMARK_UPDATE, RAN_CONN_TIMEOUT, 0);
	return 0;
}

static void ran_conn_fsm_wait_classmark_update(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ran_conn *conn = fi->priv;
	switch (event) {
	case RAN_CONN_E_CLASSMARK_UPDATE:
		/* Theoretically, this event can be used for requesting Classmark in various situations.
		 * So far though, the only time we send a Classmark Request is during Ciphering. As soon
		 * as more such situations arise, we need to add state to indicate what action should
		 * follow after a Classmark Update is received (e.g.
		 * ran_conn_classmark_request_then_cipher_mode_cmd() sets an enum value to indicate that
		 * Ciphering should continue afterwards). But right now, it is accurate to always
		 * continue with Ciphering: */

		/* During Ciphering, we needed Classmark information. The Classmark Update has come in,
		 * go back into the Set Ciphering Command procedure. */
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_AUTH_CIPH, RAN_CONN_TIMEOUT, 0);
		if (ran_conn_geran_set_cipher_mode(conn, conn->geran_set_cipher_mode.umts_aka,
					      conn->geran_set_cipher_mode.retrieve_imeisv)) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Sending Cipher Mode Command failed, aborting attach\n");
			vlr_subscr_cancel_attach_fsm(conn->vsub, OSMO_FSM_TERM_ERROR,
						     GSM48_REJECT_NETWORK_FAILURE);
		}
		return;

	case RAN_CONN_E_UNUSED:
		LOGPFSML(fi, LOGL_DEBUG, "Awaiting results for Auth+Ciph, overruling event %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		return;

	case RAN_CONN_E_MO_CLOSE:
	case RAN_CONN_E_CN_CLOSE:
		log_close_event(fi, event, data);
		evaluate_acceptance_outcome(fi, false);
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASING, RAN_CONN_TIMEOUT, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static bool ran_conn_fsm_has_active_transactions(struct osmo_fsm_inst *fi)
{
	struct ran_conn *conn = fi->priv;
	struct gsm_trans *trans;

	if (conn->silent_call) {
		LOGPFSML(fi, LOGL_DEBUG, "%s: silent call still active\n", __func__);
		return true;
	}

	if (conn->received_cm_service_request) {
		LOGPFSML(fi, LOGL_DEBUG, "%s: still awaiting first request after a CM Service Request\n",
			 __func__);
		return true;
	}

	if (conn->vsub && !llist_empty(&conn->vsub->cs.requests)) {
		struct subscr_request *sr;
		if (!log_check_level(fi->fsm->log_subsys, LOGL_DEBUG)) {
			llist_for_each_entry(sr, &conn->vsub->cs.requests, entry) {
				LOGPFSML(fi, LOGL_DEBUG, "%s: still active: %s\n",
					 __func__, sr->label);
			}
		}
		return true;
	}

	if ((trans = trans_has_conn(conn))) {
		LOGPFSML(fi, LOGL_DEBUG,
			 "%s: connection still has active transaction: %s\n",
			 __func__, gsm48_pdisc_name(trans->protocol));
		return true;
	}

	return false;
}

static void ran_conn_fsm_accepted_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ran_conn *conn = fi->priv;

	/* Stop Location Update expiry for this subscriber. While the subscriber
	 * has an open connection the LU expiry timer must remain disabled.
	 * Otherwise we would kick the subscriber off the network when the timer
	 * expires e.g. during a long phone call.
	 * The LU expiry timer will restart once the connection is closed. */
	conn->vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;

	if (!ran_conn_fsm_has_active_transactions(fi))
		osmo_fsm_inst_dispatch(fi, RAN_CONN_E_UNUSED, NULL);
}

static void ran_conn_fsm_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case RAN_CONN_E_COMPLETE_LAYER_3:
		/* When Authentication is off, we may already be in the Accepted state when the code
		 * evaluates the Compl L3. Simply ignore. This just cosmetically mutes the error log
		 * about the useless event. */
		return;

	case RAN_CONN_E_COMMUNICATING:
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_COMMUNICATING, 0, 0);
		return;

	case RAN_CONN_E_MO_CLOSE:
	case RAN_CONN_E_CN_CLOSE:
		log_close_event(fi, event, data);
		/* fall through */
	case RAN_CONN_E_UNUSED:
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASING, RAN_CONN_TIMEOUT, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ran_conn_fsm_communicating(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case RAN_CONN_E_COMMUNICATING:
		/* no-op */
		return;

	case RAN_CONN_E_MO_CLOSE:
	case RAN_CONN_E_CN_CLOSE:
		log_close_event(fi, event, data);
		/* fall through */
	case RAN_CONN_E_UNUSED:
		osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASING, RAN_CONN_TIMEOUT, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static int ran_conn_fsm_timeout(struct osmo_fsm_inst *fi)
{
	struct ran_conn *conn = fi->priv;
	if (ran_conn_in_release(conn)) {
		LOGPFSML(fi, LOGL_ERROR, "Timeout while releasing, discarding right now\n");
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_TIMEOUT, NULL);
	} else {
		enum gsm48_reject_value cause = GSM48_REJECT_CONGESTION;
		osmo_fsm_inst_dispatch(fi, RAN_CONN_E_CN_CLOSE, &cause);
	}
	return 0;
}

static void ran_conn_fsm_releasing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ran_conn *conn = fi->priv;

	/* The SGs interface needs to access vsub struct members to send the
	 * release message, however the following release procedures will
	 * remove conn->vsub, so we need to send the release right now. */
	if (conn->via_ran == OSMO_RAT_EUTRAN_SGS) {
		sgs_iface_tx_release(conn);
	}

	/* Use count for either conn->a.waiting_for_clear_complete or
	 * conn->iu.waiting_for_release_complete. 'get' it early, so we don't deallocate after tearing
	 * down active transactions. Safeguard against double-get (though it shouldn't happen). */
	if (!ran_conn_used_by(conn, RAN_CONN_USE_RELEASE))
		ran_conn_get(conn, RAN_CONN_USE_RELEASE);

	/* Cancel pending CM Service Requests */
	if (conn->received_cm_service_request) {
		conn->received_cm_service_request = false;
		ran_conn_put(conn, RAN_CONN_USE_CM_SERVICE);
	}

	/* Cancel all VLR FSMs, if any */
	vlr_subscr_cancel_attach_fsm(conn->vsub, OSMO_FSM_TERM_ERROR, GSM48_REJECT_CONGESTION);

	if (conn->vsub) {
		/* The subscriber has no active connection anymore.
		 * Restart the periodic Location Update expiry timer for this subscriber. */
		vlr_subscr_enable_expire_lu(conn->vsub);
	}

	/* If we're closing in a middle of a trans, we need to clean up */
	trans_conn_closed(conn);

	switch (conn->via_ran) {
	case OSMO_RAT_GERAN_A:
		a_iface_tx_clear_cmd(conn);
		if (conn->a.waiting_for_clear_complete) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Unexpected: conn is already waiting for BSSMAP Clear Complete\n");
			break;
		}
		conn->a.waiting_for_clear_complete = true;
		break;
	case OSMO_RAT_UTRAN_IU:
		ranap_iu_tx_release(conn->iu.ue_ctx, NULL);
		if (conn->iu.waiting_for_release_complete) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Unexpected: conn is already waiting for Iu Release Complete\n");
			break;
		}
		conn->iu.waiting_for_release_complete = true;
		break;
	case OSMO_RAT_EUTRAN_SGS:
		/* Release message is already sent at the beginning of this
		 * functions (see above), but we still need to notify the
		 * conn that a release has been sent / is in progress. */
		ran_conn_sgs_release_sent(conn);
		break;
	default:
		LOGP(DMM, LOGL_ERROR, "%s: Unknown RAN type, cannot tx release/clear\n",
		     vlr_subscr_name(conn->vsub));
		break;
	}
}

static void ran_conn_fsm_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	OSMO_ASSERT(event == RAN_CONN_E_UNUSED);
	osmo_fsm_inst_state_chg(fi, RAN_CONN_S_RELEASED, 0, 0);
}

static void ran_conn_fsm_released(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* Terminate, deallocate and also deallocate the ran_conn, which is allocated as
	 * a talloc child of fi. Also calls the cleanup function. */
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state ran_conn_fsm_states[] = {
	[RAN_CONN_S_NEW] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_NEW),
		.in_event_mask = S(RAN_CONN_E_COMPLETE_LAYER_3) |
				 S(RAN_CONN_E_ACCEPTED) |
				 S(RAN_CONN_E_MO_CLOSE) |
				 S(RAN_CONN_E_CN_CLOSE) |
				 S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_AUTH_CIPH) |
				  S(RAN_CONN_S_ACCEPTED) |
				  S(RAN_CONN_S_RELEASING),
		.action = ran_conn_fsm_new,
	},
	[RAN_CONN_S_AUTH_CIPH] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_AUTH_CIPH),
		.in_event_mask = S(RAN_CONN_E_ACCEPTED) |
				 S(RAN_CONN_E_MO_CLOSE) |
				 S(RAN_CONN_E_CN_CLOSE) |
				 S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_WAIT_CLASSMARK_UPDATE) |
				  S(RAN_CONN_S_ACCEPTED) |
				  S(RAN_CONN_S_RELEASING),
		.action = ran_conn_fsm_auth_ciph,
	},
	[RAN_CONN_S_WAIT_CLASSMARK_UPDATE] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_WAIT_CLASSMARK_UPDATE),
		.in_event_mask = S(RAN_CONN_E_CLASSMARK_UPDATE) |
				 S(RAN_CONN_E_MO_CLOSE) |
				 S(RAN_CONN_E_CN_CLOSE) |
				 S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_AUTH_CIPH) |
				  S(RAN_CONN_S_RELEASING),
		.action = ran_conn_fsm_wait_classmark_update,
	},
	[RAN_CONN_S_ACCEPTED] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_ACCEPTED),
		/* allow everything to release for any odd behavior */
		.in_event_mask = S(RAN_CONN_E_COMPLETE_LAYER_3) |
				 S(RAN_CONN_E_COMMUNICATING) |
				 S(RAN_CONN_E_RELEASE_WHEN_UNUSED) |
				 S(RAN_CONN_E_ACCEPTED) |
				 S(RAN_CONN_E_MO_CLOSE) |
				 S(RAN_CONN_E_CN_CLOSE) |
				 S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_RELEASING) |
				  S(RAN_CONN_S_COMMUNICATING),
		.onenter = ran_conn_fsm_accepted_enter,
		.action = ran_conn_fsm_accepted,
	},
	[RAN_CONN_S_COMMUNICATING] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_COMMUNICATING),
		/* allow everything to release for any odd behavior */
		.in_event_mask = S(RAN_CONN_E_RELEASE_WHEN_UNUSED) |
				 S(RAN_CONN_E_ACCEPTED) |
				 S(RAN_CONN_E_COMMUNICATING) |
				 S(RAN_CONN_E_MO_CLOSE) |
				 S(RAN_CONN_E_CN_CLOSE) |
				 S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_RELEASING),
		.action = ran_conn_fsm_communicating,
	},
	[RAN_CONN_S_RELEASING] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_RELEASING),
		.in_event_mask = S(RAN_CONN_E_UNUSED),
		.out_state_mask = S(RAN_CONN_S_RELEASED),
		.onenter = ran_conn_fsm_releasing_onenter,
		.action = ran_conn_fsm_releasing,
	},
	[RAN_CONN_S_RELEASED] = {
		.name = OSMO_STRINGIFY(RAN_CONN_S_RELEASED),
		.onenter = ran_conn_fsm_released,
	},
};

static void ran_conn_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause);

static struct osmo_fsm ran_conn_fsm = {
	.name = "RAN_conn",
	.states = ran_conn_fsm_states,
	.num_states = ARRAY_SIZE(ran_conn_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DMM,
	.event_names = ran_conn_fsm_event_names,
	.cleanup = ran_conn_fsm_cleanup,
	.timer_cb = ran_conn_fsm_timeout,
};

/* Return statically allocated string of the ran_conn RAT type and id. */
const char *ran_conn_get_conn_id(struct ran_conn *conn)
{
	static char id[42];
	int rc;
	uint32_t conn_id;

	switch (conn->via_ran) {
	case OSMO_RAT_GERAN_A:
		conn_id = conn->a.conn_id;
		break;
	case OSMO_RAT_UTRAN_IU:
		conn_id = iu_get_conn_id(conn->iu.ue_ctx);
		break;
	default:
		return "ran-unknown";
	}

	rc = snprintf(id, sizeof(id), "%s-%u", osmo_rat_type_name(conn->via_ran), conn_id);
	/* < 0 is error, == 0 is empty, >= size means truncation. Not really expecting this to catch on in any practical
	 * situation. */
	if (rc <= 0 || rc >= sizeof(id)) {
		LOGP(DMM, LOGL_ERROR, "Error with conn id; rc=%d\n", rc);
		return "conn-id-error";
	}
	return id;
}

/* Tidy up before the FSM deallocates */
static void ran_conn_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ran_conn *conn = fi->priv;

	if (ran_conn_fsm_has_active_transactions(fi)) {
		LOGPFSML(fi, LOGL_ERROR, "Deallocating despite active transactions\n");
		trans_conn_closed(conn);
	}

	if (!conn) {
		LOGP(DRLL, LOGL_ERROR, "Freeing NULL RAN connection\n");
		return;
	}

	if (conn->vsub) {
		DEBUGP(DRLL, "%s: Freeing RAN connection\n", vlr_subscr_name(conn->vsub));
		conn->vsub->lu_fsm = NULL;
		conn->vsub->msc_conn_ref = NULL;
		vlr_subscr_put(conn->vsub, VSUB_USE_CONN);
		conn->vsub = NULL;
	} else
		DEBUGP(DRLL, "Freeing RAN connection with NULL subscriber\n");

	llist_del(&conn->entry);
}

/* Signal success of Complete Layer 3. Allow to keep the conn open for Auth and Ciph. */
void ran_conn_complete_layer_3(struct ran_conn *conn)
{
	if (!conn)
		return;
	osmo_fsm_inst_dispatch(conn->fi, RAN_CONN_E_COMPLETE_LAYER_3, NULL);
}

void ran_conn_release_when_unused(struct ran_conn *conn)
{
	if (!conn)
		return;
	if (ran_conn_in_release(conn)) {
		DEBUGP(DMM, "%s: %s: conn already in release (%s)\n",
		       vlr_subscr_name(conn->vsub), __func__,
		       osmo_fsm_inst_state_name(conn->fi));
		return;
	}
	if (conn->fi->state == RAN_CONN_S_NEW) {
		DEBUGP(DMM, "%s: %s: conn still being established (%s)\n",
		       vlr_subscr_name(conn->vsub), __func__,
		       osmo_fsm_inst_state_name(conn->fi));
		return;
	}
	osmo_fsm_inst_dispatch(conn->fi, RAN_CONN_E_RELEASE_WHEN_UNUSED, NULL);
}

static void conn_close(struct ran_conn *conn, uint32_t cause, uint32_t event)
{
	if (!conn) {
		LOGP(DMM, LOGL_ERROR, "Cannot release NULL connection\n");
		return;
	}
	if (ran_conn_in_release(conn)) {
		DEBUGP(DMM, "%s(vsub=%s, cause=%u): already in release, ignore.\n",
		       __func__, vlr_subscr_name(conn->vsub), cause);
		return;
	}
	osmo_fsm_inst_dispatch(conn->fi, event, &cause);
}

void ran_conn_close(struct ran_conn *conn, uint32_t cause)
{
	return conn_close(conn, cause, RAN_CONN_E_CN_CLOSE);
}

void ran_conn_mo_close(struct ran_conn *conn, uint32_t cause)
{
	return conn_close(conn, cause, RAN_CONN_E_MO_CLOSE);
}

bool ran_conn_in_release(struct ran_conn *conn)
{
	if (!conn || !conn->fi)
		return true;
	if (conn->fi->state == RAN_CONN_S_RELEASING)
		return true;
	if (conn->fi->state == RAN_CONN_S_RELEASED)
		return true;
	return false;
}

bool ran_conn_is_accepted(const struct ran_conn *conn)
{
	if (!conn)
		return false;
	if (!conn->vsub)
		return false;
	if (!(conn->fi->state == RAN_CONN_S_ACCEPTED
	      || conn->fi->state == RAN_CONN_S_COMMUNICATING))
		return false;
	return true;
}

/* Indicate that *some* communication is happening with the phone, so that the conn FSM no longer times
 * out to release within a few seconds. */
void ran_conn_communicating(struct ran_conn *conn)
{
	osmo_fsm_inst_dispatch(conn->fi, RAN_CONN_E_COMMUNICATING, NULL);
}

void ran_conn_init(void)
{
	osmo_fsm_register(&ran_conn_fsm);
}

/* Allocate a new RAN conn and FSM.
 * Deallocation is by ran_conn_put(): when the use count reaches zero, the
 * RAN_CONN_E_RELEASE_COMPLETE event is dispatched, the FSM terminates and deallocates both FSM and
 * conn. As long as the FSM is waiting for responses from the subscriber, it will itself hold a use count
 * on the conn. */
struct ran_conn *ran_conn_alloc(struct gsm_network *network,
							enum osmo_rat_type via_ran, uint16_t lac)
{
	struct ran_conn *conn;
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(&ran_conn_fsm, network, NULL, LOGL_DEBUG, NULL);
	if (!fi) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate conn FSM\n");
		return NULL;
	}

	conn = talloc_zero(fi, struct ran_conn);
	if (!conn) {
		osmo_fsm_inst_free(fi);
		return NULL;
	}

	*conn = (struct ran_conn){
		.network = network,
		.via_ran = via_ran,
		.lac = lac,
		.fi = fi,
	};

	switch (via_ran) {
	case OSMO_RAT_GERAN_A:
		conn->log_subsys = DBSSAP;
		break;
	case OSMO_RAT_UTRAN_IU:
		conn->log_subsys = DRANAP;
		break;
	case OSMO_RAT_EUTRAN_SGS:
		conn->log_subsys = DSGS;
		break;
	default:
		conn->log_subsys = DMSC;
		break;
	}

	fi->priv = conn;
	llist_add_tail(&conn->entry, &network->ran_conns);
	return conn;
}

bool ran_conn_is_establishing_auth_ciph(const struct ran_conn *conn)
{
	if (!conn)
		return false;
	return conn->fi->state == RAN_CONN_S_AUTH_CIPH;
}


const struct value_string complete_layer3_type_names[] = {
	{ COMPLETE_LAYER3_NONE, "NONE" },
	{ COMPLETE_LAYER3_LU, "LU" },
	{ COMPLETE_LAYER3_CM_SERVICE_REQ, "CM_SERVICE_REQ" },
	{ COMPLETE_LAYER3_PAGING_RESP, "PAGING_RESP" },
	{ 0, NULL }
};

static void _ran_conn_update_id(struct ran_conn *conn, const char *subscr_identity)
{
	struct vlr_subscr *vsub = conn->vsub;

	if (osmo_fsm_inst_update_id_f(conn->fi, "%s:%s:%s",
				      subscr_identity,
				      ran_conn_get_conn_id(conn),
				      complete_layer3_type_name(conn->complete_layer3_type))
	    != 0)
		return; /* osmo_fsm_inst_update_id_f() will log an error. */

	if (vsub) {
		if (vsub->lu_fsm)
			osmo_fsm_inst_update_id(vsub->lu_fsm, conn->fi->id);
		if (vsub->auth_fsm)
			osmo_fsm_inst_update_id(vsub->auth_fsm, conn->fi->id);
		if (vsub->proc_arq_fsm)
			osmo_fsm_inst_update_id(vsub->proc_arq_fsm, conn->fi->id);
	}

	LOGPFSML(conn->fi, LOGL_DEBUG, "Updated ID\n");
}

/* Compose an ID almost like gsm48_mi_to_string(), but print the MI type along, and print a TMSI as hex. */
void ran_conn_update_id_from_mi(struct ran_conn *conn, const uint8_t *mi, uint8_t mi_len)
{
	_ran_conn_update_id(conn, osmo_mi_name(mi, mi_len));
}

/* Update ran_conn->fi id string from current conn->vsub and conn->complete_layer3_type. */
void ran_conn_update_id(struct ran_conn *conn)
{
	_ran_conn_update_id(conn, vlr_subscr_name(conn->vsub));
}

/* Iterate all ran_conn instances that are relevant for this subscriber, and update FSM ID strings for all of the FSM
 * instances. */
void ran_conn_update_id_for_vsub(struct vlr_subscr *for_vsub)
{
	struct gsm_network *network;
	struct ran_conn *conn;
	if (!for_vsub)
		return;

	network = for_vsub->vlr->user_ctx;
	OSMO_ASSERT(network);

	llist_for_each_entry(conn, &network->ran_conns, entry) {
		if (conn->vsub == for_vsub)
			ran_conn_update_id(conn);
	}
}

static void rx_close_complete(struct ran_conn *conn, const char *label, bool *flag)
{
	if (!conn)
		return;
	if (!ran_conn_in_release(conn)) {
		LOGPFSML(conn->fi, LOGL_ERROR, "Received unexpected %s, discarding right now\n",
			 label);
		trans_conn_closed(conn);
		osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_ERROR, NULL);
		return;
	}
	if (*flag) {
		*flag = false;
		ran_conn_put(conn, RAN_CONN_USE_RELEASE);
	}
}

void ran_conn_rx_bssmap_clear_complete(struct ran_conn *conn)
{
	rx_close_complete(conn, "BSSMAP Clear Complete", &conn->a.waiting_for_clear_complete);
}

void ran_conn_rx_iu_release_complete(struct ran_conn *conn)
{
	rx_close_complete(conn, "Iu Release Complete", &conn->iu.waiting_for_release_complete);
}

void ran_conn_sgs_release_sent(struct ran_conn *conn)
{
	bool dummy_waiting_for_release_complete = true;

	/* Note: In SGsAP there is no confirmation of a release. */
	rx_close_complete(conn, "SGs Release Complete", &dummy_waiting_for_release_complete);
}

const struct value_string ran_conn_use_names[] = {
	{ RAN_CONN_USE_UNTRACKED,	"UNTRACKED" },
	{ RAN_CONN_USE_COMPL_L3,	"compl_l3" },
	{ RAN_CONN_USE_DTAP,		"dtap" },
	{ RAN_CONN_USE_AUTH_CIPH,	"auth+ciph" },
	{ RAN_CONN_USE_CM_SERVICE,	"cm_service" },
	{ RAN_CONN_USE_TRANS_CC,	"trans_cc" },
	{ RAN_CONN_USE_TRANS_SMS,	"trans_sms" },
	{ RAN_CONN_USE_TRANS_NC_SS,	"trans_nc_ss" },
	{ RAN_CONN_USE_SILENT_CALL,	"silent_call" },
	{ RAN_CONN_USE_RELEASE,		"release" },
	{ 0, NULL }
};

static const char *used_ref_counts_str(struct ran_conn *conn)
{
	static char buf[256];
	int bit_nr;
	char *pos = buf;
	*pos = '\0';

	if (conn->use_tokens < 0)
		return "invalid";

#define APPEND_STR(fmt, args...) do { \
		int remain = sizeof(buf) - (pos - buf) - 1; \
		int l = -1; \
		if (remain > 0) \
		    l = snprintf(pos, remain, "%s" fmt, (pos == buf? "" : ","), ##args); \
		if (l < 0 || l > remain) { \
			buf[sizeof(buf) - 1] = '\0'; \
			return buf; \
		} \
		pos += l; \
	} while(0)

	for (bit_nr = 0; (1 << bit_nr) <= conn->use_tokens; bit_nr++) {
		if (conn->use_tokens & (1 << bit_nr)) {
			APPEND_STR("%s", get_value_string(ran_conn_use_names, bit_nr));
		}
	}
	return buf;
#undef APPEND_STR
}

/* increment the ref-count. Needs to be called by every user */
struct ran_conn *_ran_conn_get(struct ran_conn *conn, enum ran_conn_use balance_token,
			       const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (balance_token != RAN_CONN_USE_UNTRACKED) {
		uint32_t flag = 1 << balance_token;
		OSMO_ASSERT(balance_token < 32);
		if (conn->use_tokens & flag)
			LOGPSRC(DREF, LOGL_ERROR, file, line,
				"%s: MSC conn use error: using an already used token: %s\n",
				vlr_subscr_name(conn->vsub),
				ran_conn_use_name(balance_token));
		conn->use_tokens |= flag;
	}

	conn->use_count++;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"%s: MSC conn use + %s == %u (0x%x: %s)\n",
		vlr_subscr_name(conn->vsub), ran_conn_use_name(balance_token),
		conn->use_count, conn->use_tokens, used_ref_counts_str(conn));

	return conn;
}

/* decrement the ref-count. Once it reaches zero, we release */
void _ran_conn_put(struct ran_conn *conn, enum ran_conn_use balance_token,
		   const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (balance_token != RAN_CONN_USE_UNTRACKED) {
		uint32_t flag = 1 << balance_token;
		OSMO_ASSERT(balance_token < 32);
		if (!(conn->use_tokens & flag))
			LOGPSRC(DREF, LOGL_ERROR, file, line,
				"%s: MSC conn use error: freeing an unused token: %s\n",
				vlr_subscr_name(conn->vsub),
				ran_conn_use_name(balance_token));
		conn->use_tokens &= ~flag;
	}

	if (conn->use_count == 0) {
		LOGPSRC(DREF, LOGL_ERROR, file, line,
			"%s: MSC conn use - %s failed: is already 0\n",
			vlr_subscr_name(conn->vsub),
			ran_conn_use_name(balance_token));
		return;
	}

	conn->use_count--;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"%s: MSC conn use - %s == %u (0x%x: %s)\n",
		vlr_subscr_name(conn->vsub), ran_conn_use_name(balance_token),
		conn->use_count, conn->use_tokens, used_ref_counts_str(conn));

	if (conn->use_count == 0)
		osmo_fsm_inst_dispatch(conn->fi, RAN_CONN_E_UNUSED, NULL);
}

bool ran_conn_used_by(struct ran_conn *conn, enum ran_conn_use token)
{
	return conn && (conn->use_tokens & (1 << token));
}
