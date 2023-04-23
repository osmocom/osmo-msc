/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
 *
 * All Rights Reserved
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

/**
 * MSC-specific handling of call independent Supplementary
 * Services messages (NC_SS) according to GSM TS 09.11
 * "Signalling interworking for supplementary services".
 */

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/paging.h>
#include <osmocom/msc/gsup_client_mux.h>

/* FIXME: choose a proper range */
static uint32_t new_callref = 0x20000001;

static void ncss_session_timeout_handler(void *_trans)
{
	struct gsm_trans *trans = (struct gsm_trans *) _trans;
	struct osmo_gsup_message gsup_msg;

	/* The timeout might be disabled from the VTY */
	if (trans->net->ncss_guard_timeout == 0)
		return;

	LOG_TRANS(trans, LOGL_NOTICE, "SS/USSD session timeout, releasing\n");

	/* Indicate connection release to subscriber (if active) */
	if (trans->msc_a != NULL) {
		/* This pair of cause location and value is used by commercial networks */
		msc_send_ussd_release_complete_cause(trans->msc_a, trans->transaction_id,
			GSM48_CAUSE_LOC_PUN_S_LU, GSM48_CC_CAUSE_NORMAL_UNSPEC);
	}

	/* Terminate GSUP session with EUSE */
	gsup_msg = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_PROC_SS_ERROR,

		.session_state = OSMO_GSUP_SESSION_STATE_END,
		.session_id = trans->callref,
		.cause = GMM_CAUSE_NET_FAIL,

		.message_class = OSMO_GSUP_MESSAGE_CLASS_USSD,
	};

	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, trans->vsub->imsi);

	gsup_client_mux_tx(trans->net->gcm, &gsup_msg);

	/* Finally, release this transaction */
	trans_free(trans);
}

/* Entry point for call independent MO SS messages */
int gsm0911_rcv_nc_ss(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm_network *net;
	struct vlr_subscr *vsub;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct osmo_gsup_message gsup_msg;
	struct gsm_trans *trans;
	uint16_t facility_ie_len;
	uint8_t *facility_ie;
	uint8_t tid;
	uint8_t msg_type;
	int rc;

	net = msc_a_net(msc_a);
	OSMO_ASSERT(net);

	vsub = msc_a_vsub(msc_a);
	if (!vsub) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "No vlr_subscr set for this conn\n");
		return -EINVAL;
	}

	msg_type = gsm48_hdr_msg_type(gh);
	tid = gsm48_hdr_trans_id_flip_ti(gh);

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

	/* Reuse existing transaction, or create a new one */
	trans = trans_find_by_id(msc_a, TRANS_USSD, tid);
	if (!trans) {
		/* Count MS-initiated attempts to establish a NC SS/USSD session */
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, MSC_CTR_NC_SS_MO_REQUESTS));

		/**
		 * According to GSM TS 04.80, section 2.4.2 "Register
		 * (mobile station to network direction)", the REGISTER
		 * message is sent by the mobile station to the network
		 * to assign a new transaction identifier for call independent
		 * supplementary service control and to request or acknowledge
		 * a supplementary service.
		 */
		if (msg_type != GSM0480_MTYPE_REGISTER) {
			LOGP(DSS, LOGL_ERROR, "Rx %s message for non-existing transaction (tid-%u)\n",
				  gsm48_pdisc_msgtype_name(GSM48_PDISC_NC_SS, msg_type),
				  gsm48_hdr_trans_id(gh));
			gsm48_tx_simple(msc_a,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -EINVAL;
		}

		trans = trans_alloc(net, vsub, TRANS_USSD, tid, new_callref++);
		if (!trans) {
			LOGP(DSS, LOGL_ERROR, " -> No memory for trans\n");
			gsm48_tx_simple(msc_a,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -ENOMEM;
		}

		/* Init inactivity timer */
		osmo_timer_setup(&trans->ss.timer_guard,
			ncss_session_timeout_handler, trans);

		/* Count active NC SS/USSD sessions */
		osmo_stat_item_inc(osmo_stat_item_group_get_item(net->statg, MSC_STAT_ACTIVE_NC_SS), 1);

		trans->dlci = OMSC_LINKID_CB(msg);
		trans->msc_a = msc_a;
		msc_a_get(msc_a, MSC_A_USE_NC_SS);

		osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_TRANSACTION_ACCEPTED, trans);

		/* An earlier CM Service Request for this SS message now has concluded */
		if (!osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_SS))
			LOG_MSC_A(msc_a, LOGL_ERROR,
				  "Creating new MO SS transaction without prior CM Service Request\n");
		else
			msc_a_put(msc_a, MSC_A_USE_CM_SERVICE_SS);
	}

	LOG_TRANS(trans, LOGL_DEBUG, "Received SS/USSD msg %s\n",
		  gsm48_pdisc_msgtype_name(GSM48_PDISC_NC_SS, msg_type));

	/* (Re)schedule the inactivity timer */
	if (net->ncss_guard_timeout > 0) {
		osmo_timer_schedule(&trans->ss.timer_guard, net->ncss_guard_timeout, 0);
	}

	/* Attempt to extract Facility IE */
	rc = gsm0480_extract_ie_by_tag(gh, msgb_l3len(msg),
		&facility_ie, &facility_ie_len, GSM0480_IE_FACILITY);
	if (rc) {
		LOG_TRANS(trans, LOGL_ERROR, "GSM 04.80 message parsing error, couldn't extract Facility IE\n");
		goto error;
	}

	/* Facility IE is optional for RELEASE COMPLETE */
	if (msg_type != GSM0480_MTYPE_RELEASE_COMPLETE) {
		if (!facility_ie || facility_ie_len < 2) {
			LOG_TRANS(trans, LOGL_ERROR, "GSM 04.80 message parsing error,"
				  " missing mandatory Facility IE\n");
			rc = -EINVAL;
			goto error;
		}
	}

	/* Compose a mew GSUP message */
	gsup_msg = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_PROC_SS_REQUEST,
		.session_id = trans->callref,
		.message_class = OSMO_GSUP_MESSAGE_CLASS_USSD,
	};

	/**
	 * Perform A-interface to GSUP-interface mapping,
	 * according to GSM TS 09.11, table 4.2.
	 */
	switch (msg_type) {
	case GSM0480_MTYPE_REGISTER:
		gsup_msg.session_state = OSMO_GSUP_SESSION_STATE_BEGIN;
		break;
	case GSM0480_MTYPE_FACILITY:
		gsup_msg.session_state = OSMO_GSUP_SESSION_STATE_CONTINUE;
		break;
	case GSM0480_MTYPE_RELEASE_COMPLETE:
		gsup_msg.session_state = OSMO_GSUP_SESSION_STATE_END;
		break;
	}

	/* Fill in the (optional) message payload */
	if (facility_ie) {
		gsup_msg.ss_info_len = facility_ie_len;
		gsup_msg.ss_info = facility_ie;
	}

	/* Fill in subscriber's IMSI */
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, vsub->imsi);

	rc = gsup_client_mux_tx(trans->net->gcm, &gsup_msg);

	/* Should we release connection? Or wait for response? */
	if (msg_type == GSM0480_MTYPE_RELEASE_COMPLETE)
		trans_free(trans);

	/* Count established MS-initiated NC SS/USSD sessions */
	if (msg_type == GSM0480_MTYPE_REGISTER)
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, MSC_CTR_NC_SS_MO_ESTABLISHED));

	return rc;

error:
	/* Abort transaction on DTAP-interface */
	msc_send_ussd_reject(msc_a, tid, -1,
		GSM_0480_PROBLEM_CODE_TAG_GENERAL,
		GSM_0480_GEN_PROB_CODE_UNRECOGNISED);
	if (trans)
		trans_free(trans);

	/* TODO: abort transaction on GSUP interface if any */
	return rc;
}

/* Call-back from paging the B-end of the connection */
static void ss_paging_cb(struct msc_a *msc_a, struct gsm_trans *trans)
{
	struct gsm48_hdr *gh;
	struct msgb *ss_msg;

	if (trans->msc_a) {
		LOG_MSC_A_CAT(msc_a, DPAG, LOGL_ERROR,
			      "Handle paging error: transaction already associated with subscriber,"
			      " apparently it was already handled. Skip.\n");
		return;
	}
	OSMO_ASSERT(trans->ss.msg);

	if (msc_a) {
		struct gsm_network *net = msc_a_net(msc_a);
		LOG_MSC_A_CAT(msc_a, DSS, LOGL_DEBUG, "Paging succeeded\n");

		/* Assign connection */
		msc_a_get(msc_a, MSC_A_USE_NC_SS);
		trans->msc_a = msc_a;
		trans->paging_request = NULL;

		/* (Re)schedule the inactivity timer */
		if (net->ncss_guard_timeout > 0) {
			osmo_timer_schedule(&trans->ss.timer_guard, net->ncss_guard_timeout, 0);
		}

		/* Send stored message */
		ss_msg = trans->ss.msg;
		gh = (struct gsm48_hdr *) msgb_push(ss_msg, sizeof(*gh));
		gh->proto_discr  = GSM48_PDISC_NC_SS;
		gh->proto_discr |= trans->transaction_id << 4;
		gh->msg_type = GSM0480_MTYPE_REGISTER;

		/* Sent to the MS, give ownership of ss_msg */
		msc_a_tx_dtap_to_i(msc_a, ss_msg);
		trans->ss.msg = NULL;

		/* Count established network-initiated NC SS/USSD sessions */
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, MSC_CTR_NC_SS_MT_ESTABLISHED));
	} else {
		struct osmo_gsup_message gsup_msg;

		LOG_MSC_A_CAT(msc_a, DSS, LOGL_DEBUG, "Paging expired\n");

		gsup_msg = (struct osmo_gsup_message){
			.message_class = OSMO_GSUP_MESSAGE_CLASS_USSD,
			.message_type = OSMO_GSUP_MSGT_PROC_SS_ERROR,

			.session_state = OSMO_GSUP_SESSION_STATE_END,
			.session_id = trans->callref,
			/* FIXME: we need message class specific cause values */
			.cause = GMM_CAUSE_IMPL_DETACHED,
		};

		/* Fill in subscriber's IMSI */
		OSMO_STRLCPY_ARRAY(gsup_msg.imsi, trans->vsub->imsi);

		/* Inform HLR/EUSE about the failure */
		gsup_client_mux_tx(trans->net->gcm, &gsup_msg);

		msgb_free(trans->ss.msg);
		trans->ss.msg = NULL;

		trans->callref = 0;
		trans->paging_request = NULL;
		trans_free(trans);
	}
}

static struct gsm_trans *establish_nc_ss_trans(struct gsm_network *net,
	struct vlr_subscr *vsub, const struct osmo_gsup_message *gsup_msg)
{
	struct msc_a *msc_a;
	struct gsm_trans *trans;
	int tid;

	if (gsup_msg->session_state != OSMO_GSUP_SESSION_STATE_BEGIN) {
		LOGP(DSS, LOGL_ERROR, "Received non-BEGIN message for non-existing transaction\n");
		return NULL;
	}

	LOGP(DSS, LOGL_DEBUG, "(%s) Establishing a network-originated session (id=0x%x)\n",
			      vlr_subscr_name(vsub), gsup_msg->session_id);

	if (!gsup_msg->ss_info || gsup_msg->ss_info_len < 2) {
		LOGP(DSS, LOGL_ERROR, "Missing mandatory Facility IE\n");
		return NULL;
	}

	/* Obtain an unused transaction ID */
	tid = trans_assign_trans_id(net, vsub, TRANS_USSD);
	if (tid < 0) {
		LOGP(DSS, LOGL_ERROR, "No free transaction ID\n");
		return NULL;
	}

	/* Allocate a new NCSS transaction */
	trans = trans_alloc(net, vsub, TRANS_USSD, tid, gsup_msg->session_id);
	if (!trans) {
		LOGP(DSS, LOGL_ERROR, " -> No memory for trans\n");
		return NULL;
	}

	/* Count active NC SS/USSD sessions */
	osmo_stat_item_inc(osmo_stat_item_group_get_item(net->statg, MSC_STAT_ACTIVE_NC_SS), 1);

	/* Init inactivity timer */
	osmo_timer_setup(&trans->ss.timer_guard,
		ncss_session_timeout_handler, trans);

	/* Attempt to find connection */
	msc_a = msc_a_for_vsub(vsub, true);
	if (msc_a) {
		/* Assign connection */
		msc_a_get(msc_a, MSC_A_USE_NC_SS);
		trans->msc_a = msc_a;
		trans->dlci = 0x00; /* SAPI=0, not SACCH */
		return trans;
	}

	LOG_TRANS(trans, LOGL_DEBUG, "Triggering Paging Request\n");

	/* Trigger Paging Request */
	trans->paging_request = paging_request_start(vsub, PAGING_CAUSE_SIGNALLING_HIGH_PRIO,
						     ss_paging_cb, trans, "GSM 09.11 SS/USSD");
	if (!trans->paging_request) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to allocate paging token\n");
		trans_free(trans);
		return NULL;
	}

	/* Store the Facility IE to be sent */
	OSMO_ASSERT(trans->ss.msg == NULL);
	trans->ss.msg = gsm48_msgb_alloc_name("GSM 04.08 SS/USSD");
	msgb_tlv_put(trans->ss.msg, GSM0480_IE_FACILITY,
		gsup_msg->ss_info_len, gsup_msg->ss_info);

	return trans;
}

/* NC SS specific transaction release.
 * Gets called by trans_free, DO NOT CALL YOURSELF! */
void _gsm911_nc_ss_trans_free(struct gsm_trans *trans)
{
	/**
	 * TODO: if transaction wasn't properly terminated,
	 * we need to do it here by releasing the subscriber
	 * connection and sending notification via GSUP...
	 */
	if (trans->ss.msg != NULL)
		msgb_free(trans->ss.msg);

	/* Stop inactivity timer */
	osmo_timer_del(&trans->ss.timer_guard);

	/* One session less */
	osmo_stat_item_dec(osmo_stat_item_group_get_item(trans->net->statg, MSC_STAT_ACTIVE_NC_SS),
			   1);
}

int gsm0911_gsup_rx(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *gsup_msg)
{
	struct gsm_network *net = (struct gsm_network *) data;
	struct gsm_trans *trans;
	struct gsm48_hdr *gh;
	struct msgb *ss_msg;
	bool trans_end;
	struct msc_a *msc_a;
	struct vlr_subscr *vsub;

	vsub = vlr_subscr_find_by_imsi(net->vlr, gsup_msg->imsi, __func__);
	if (!vsub) {
		LOGP(DSS, LOGL_ERROR, "Rx %s for unknown subscriber, rejecting\n",
		     osmo_gsup_message_type_name(gsup_msg->message_type));
		gsup_client_mux_tx_error_reply(gcm, gsup_msg, GMM_CAUSE_IMSI_UNKNOWN);
		return -GMM_CAUSE_IMSI_UNKNOWN;
	}

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

	/* Attempt to find DTAP-transaction */
	trans = trans_find_by_callref(net, TRANS_USSD, gsup_msg->session_id);

	/* Handle errors */
	if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DSS, LOGL_NOTICE, "Rx %s from HLR/EUSE (cause=0x%02x, sid=0x%x)\n",
		     osmo_gsup_message_type_name(gsup_msg->message_type),
		     gsup_msg->cause, gsup_msg->session_id);

		/* We don't need subscriber info anymore */
		vlr_subscr_put(vsub, __func__);

		if (!trans) {
			LOGP(DSS, LOGL_ERROR, "No transaction found for "
			     "sid=0x%x, nothing to abort\n", gsup_msg->session_id);
			return -ENODEV;
		}

		LOG_TRANS(trans, LOGL_NOTICE, "Aborting the session: sending RELEASE COMPLETE\n");

		/* Indicate connection release to subscriber (if active) */
		if (trans->msc_a != NULL) {
			/* TODO: implement GSUP - GSM 04.80 cause mapping */
			msc_send_ussd_release_complete_cause(trans->msc_a, trans->transaction_id,
				GSM48_CAUSE_LOC_PUN_S_LU, GSM48_CC_CAUSE_TEMP_FAILURE);
		}

		/* Terminate transaction */
		trans_free(trans);

		return 0;
	}

	if (!trans) {
		/* Count network-initiated attempts to establish a NC SS/USSD session */
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, MSC_CTR_NC_SS_MT_REQUESTS));

		/* Attempt to establish a new transaction */
		trans = establish_nc_ss_trans(net, vsub, gsup_msg);
		if (!trans) {
			LOGP(DSS, LOGL_ERROR, "Failed to establish a network-originated "
					      "SS/USSD transaction, rejecting %s\n",
					      osmo_gsup_message_type_name(gsup_msg->message_type));
			gsup_client_mux_tx_error_reply(gcm, gsup_msg, GMM_CAUSE_NET_FAIL);
			vlr_subscr_put(vsub, __func__);
			return -EINVAL;
		}

		/* Wait for Paging Response */
		if (trans->paging_request) {
			vlr_subscr_put(vsub, __func__);
			return 0;
		}
	}

	/* We don't need subscriber info anymore */
	vlr_subscr_put(vsub, __func__);

	/* (Re)schedule the inactivity timer */
	if (net->ncss_guard_timeout > 0) {
		osmo_timer_schedule(&trans->ss.timer_guard,
			net->ncss_guard_timeout, 0);
	}

	/* Allocate and prepare a new MT message */
	ss_msg = gsm48_msgb_alloc_name("GSM 04.08 SS/USSD");
	gh = (struct gsm48_hdr *) msgb_push(ss_msg, sizeof(*gh));
	gh->proto_discr  = GSM48_PDISC_NC_SS;
	gh->proto_discr |= trans->transaction_id << 4;

	/**
	 * Perform GSUP-interface to A-interface mapping,
	 * according to GSM TS 09.11, table 4.1.
	 *
	 * TODO: see (note 3), both CONTINUE and END may
	 * be also mapped to REGISTER if a new transaction
	 * has to be established.
	 */
	switch (gsup_msg->session_state) {
	case OSMO_GSUP_SESSION_STATE_BEGIN:
		gh->msg_type = GSM0480_MTYPE_REGISTER;
		break;
	case OSMO_GSUP_SESSION_STATE_CONTINUE:
		gh->msg_type = GSM0480_MTYPE_FACILITY;
		break;
	case OSMO_GSUP_SESSION_STATE_END:
		gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;
		break;

	/* Missing or incorrect session state */
	case OSMO_GSUP_SESSION_STATE_NONE:
	default:
		LOG_TRANS(trans, LOGL_ERROR, "Unexpected session state %d\n",
			gsup_msg->session_state);
		gsup_client_mux_tx_error_reply(gcm, gsup_msg, GMM_CAUSE_MSGT_INCOMP_P_STATE);
		msgb_free(ss_msg);
		return -EINVAL;
	}

	/* Facility IE is optional only for RELEASE COMPLETE */
	if (gh->msg_type != GSM0480_MTYPE_RELEASE_COMPLETE) {
		if (!gsup_msg->ss_info || gsup_msg->ss_info_len < 2) {
			LOG_TRANS(trans, LOGL_ERROR, "Missing mandatory Facility IE "
				"for mapped 0x%02x message\n", gh->msg_type);
			gsup_client_mux_tx_error_reply(gcm, gsup_msg, GMM_CAUSE_INV_MAND_INFO);
			msgb_free(ss_msg);
			return -EINVAL;
		}
	}

	/* Append Facility IE if preset */
	if (gsup_msg->ss_info && gsup_msg->ss_info_len > 2) {
		/* Facility IE carries LV, others carry TLV */
		if (gh->msg_type == GSM0480_MTYPE_FACILITY)
			msgb_lv_put(ss_msg, gsup_msg->ss_info_len, gsup_msg->ss_info);
		else
			msgb_tlv_put(ss_msg, GSM0480_IE_FACILITY,
				gsup_msg->ss_info_len, gsup_msg->ss_info);
	}

	/* Should we release the transaction? */
	trans_end = (gh->msg_type == GSM0480_MTYPE_RELEASE_COMPLETE);

	/* Sent to the MS, give ownership of ss_msg */
	msc_a = trans->msc_a;
	if (!msc_a) {
		LOG_TRANS(trans, LOGL_ERROR, "Cannot send SS message, no local MSC-A role defined for subscriber\n");
		gsup_client_mux_tx_error_reply(gcm, gsup_msg, GMM_CAUSE_NET_FAIL);
		msgb_free(ss_msg);
		return -EINVAL;
	}
	msc_a_tx_dtap_to_i(msc_a, ss_msg);

	/* Release transaction if required */
	if (trans_end)
		trans_free(trans);

	/* Count established network-initiated NC SS/USSD sessions */
	if (gsup_msg->session_state == OSMO_GSUP_SESSION_STATE_BEGIN)
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, MSC_CTR_NC_SS_MT_ESTABLISHED));

	return 0;
}
