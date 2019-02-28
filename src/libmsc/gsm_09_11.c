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
#include <osmocom/msc/msc_ifaces.h>

/* FIXME: choose a proper range */
static uint32_t new_callref = 0x20000001;

static void ncss_session_timeout_handler(void *_trans)
{
	struct gsm_trans *trans = (struct gsm_trans *) _trans;
	struct osmo_gsup_message gsup_msg = { 0 };

	/* The timeout might be disabled from the VTY */
	if (trans->net->ncss_guard_timeout == 0)
		return;

	LOG_TRANS(trans, LOGL_NOTICE, "SS/USSD session timeout, releasing\n");

	/* Indicate connection release to subscriber (if active) */
	if (trans->conn != NULL) {
		/* This pair of cause location and value is used by commercial networks */
		msc_send_ussd_release_complete_cause(trans->conn, trans->transaction_id,
			GSM48_CAUSE_LOC_PUN_S_LU, GSM48_CC_CAUSE_NORMAL_UNSPEC);
	}

	/* Terminate GSUP session with EUSE */
	gsup_msg.message_type = OSMO_GSUP_MSGT_PROC_SS_ERROR;
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, trans->vsub->imsi);

	gsup_msg.session_state = OSMO_GSUP_SESSION_STATE_END;
	gsup_msg.session_id = trans->callref;
	gsup_msg.cause = GMM_CAUSE_NET_FAIL;

	osmo_gsup_client_enc_send(trans->net->vlr->gsup_client, &gsup_msg);

	/* Finally, release this transaction */
	trans_free(trans);
}

/* Entry point for call independent MO SS messages */
int gsm0911_rcv_nc_ss(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct osmo_gsup_message gsup_msg;
	struct gsm_trans *trans;
	struct msgb *gsup_msgb;
	uint16_t facility_ie_len;
	uint8_t *facility_ie;
	uint8_t tid;
	uint8_t msg_type;
	int rc;

	msg_type = gsm48_hdr_msg_type(gh);
	tid = gsm48_hdr_trans_id_flip_ti(gh);

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, conn->vsub);

	/* Reuse existing transaction, or create a new one */
	trans = trans_find_by_id(conn, GSM48_PDISC_NC_SS, tid);
	if (!trans) {
		/* Count MS-initiated attempts to establish a NC SS/USSD session */
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_REQUESTS]);

		/**
		 * According to GSM TS 04.80, section 2.4.2 "Register
		 * (mobile station to network direction)", the REGISTER
		 * message is sent by the mobile station to the network
		 * to assign a new transaction identifier for call independent
		 * supplementary service control and to request or acknowledge
		 * a supplementary service.
		 */
		if (msg_type != GSM0480_MTYPE_REGISTER) {
			LOG_TRANS(trans, LOGL_ERROR, "Rx wrong SS/USSD message type for new transaction: %s\n",
				  gsm48_pdisc_msgtype_name(GSM48_PDISC_NC_SS, msg_type));
			gsm48_tx_simple(conn,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -EINVAL;
		}

		trans = trans_alloc(conn->network, conn->vsub,
				    GSM48_PDISC_NC_SS, tid, new_callref++);
		if (!trans) {
			LOG_TRANS(trans, LOGL_ERROR, " -> No memory for trans\n");
			gsm48_tx_simple(conn,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -ENOMEM;
		}

		/* Init inactivity timer */
		osmo_timer_setup(&trans->ss.timer_guard,
			ncss_session_timeout_handler, trans);

		/* Count active NC SS/USSD sessions */
		osmo_counter_inc(conn->network->active_nc_ss);

		trans->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_NC_SS);
		trans->dlci = OMSC_LINKID_CB(msg);
		cm_service_request_concludes(conn, msg);
	}

	LOG_TRANS(trans, LOGL_DEBUG, "Received SS/USSD msg %s\n",
		  gsm48_pdisc_msgtype_name(GSM48_PDISC_NC_SS, msg_type));

	/* (Re)schedule the inactivity timer */
	if (conn->network->ncss_guard_timeout > 0) {
		osmo_timer_schedule(&trans->ss.timer_guard,
			conn->network->ncss_guard_timeout, 0);
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
	memset(&gsup_msg, 0x00, sizeof(gsup_msg));
	gsup_msg.message_type = OSMO_GSUP_MSGT_PROC_SS_REQUEST;
	gsup_msg.session_id = trans->callref;

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
	OSMO_STRLCPY_ARRAY(gsup_msg.imsi, conn->vsub->imsi);

	/* Allocate GSUP message buffer */
	gsup_msgb = osmo_gsup_client_msgb_alloc();
	if (!gsup_msgb) {
		LOG_TRANS(trans, LOGL_ERROR, "Couldn't allocate GSUP message\n");
		rc = -ENOMEM;
		goto error;
	}

	/* Encode GSUP message */
	rc = osmo_gsup_encode(gsup_msgb, &gsup_msg);
	if (rc) {
		LOG_TRANS(trans, LOGL_ERROR, "Couldn't encode GSUP message\n");
		goto error;
	}

	/* Finally send */
	rc = osmo_gsup_client_send(conn->network->vlr->gsup_client, gsup_msgb);
	if (rc) {
		LOG_TRANS(trans, LOGL_ERROR, "Couldn't send GSUP message\n");
		goto error;
	}

	/* Should we release connection? Or wait for response? */
	if (msg_type == GSM0480_MTYPE_RELEASE_COMPLETE)
		trans_free(trans);
	else
		ran_conn_communicating(conn);

	/* Count established MS-initiated NC SS/USSD sessions */
	if (msg_type == GSM0480_MTYPE_REGISTER)
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_ESTABLISHED]);

	return 0;

error:
	/* Abort transaction on DTAP-interface */
	msc_send_ussd_reject(conn, tid, -1,
		GSM_0480_PROBLEM_CODE_TAG_GENERAL,
		GSM_0480_GEN_PROB_CODE_UNRECOGNISED);
	if (trans)
		trans_free(trans);

	/* TODO: abort transaction on GSUP interface if any */
	return rc;
}

/* Call-back from paging the B-end of the connection */
static int handle_paging_event(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_conn, void *_transt)
{
	struct ran_conn *conn = _conn;
	enum gsm_paging_event paging_event = event;
	struct gsm_trans *transt = _transt;
	struct gsm48_hdr *gh;
	struct msgb *ss_msg;

	OSMO_ASSERT(!transt->conn);
	OSMO_ASSERT(transt->ss.msg);

	switch (paging_event) {
	case GSM_PAGING_SUCCEEDED:
		DEBUGP(DMM, "Paging subscr %s succeeded!\n",
			vlr_subscr_msisdn_or_name(transt->vsub));

		/* Assign connection */
		transt->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_NC_SS);
		transt->paging_request = NULL;

		/* (Re)schedule the inactivity timer */
		if (conn->network->ncss_guard_timeout > 0) {
			osmo_timer_schedule(&transt->ss.timer_guard,
				conn->network->ncss_guard_timeout, 0);
		}

		/* Send stored message */
		ss_msg = transt->ss.msg;
		gh = (struct gsm48_hdr *) msgb_push(ss_msg, sizeof(*gh));
		gh->proto_discr  = GSM48_PDISC_NC_SS;
		gh->proto_discr |= transt->transaction_id << 4;
		gh->msg_type = GSM0480_MTYPE_REGISTER;

		/* Sent to the MS, give ownership of ss_msg */
		msc_tx_dtap(transt->conn, ss_msg);
		transt->ss.msg = NULL;

		/* Count established network-initiated NC SS/USSD sessions */
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_ESTABLISHED]);
		break;
	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_BUSY:
		DEBUGP(DMM, "Paging subscr %s %s!\n",
			vlr_subscr_msisdn_or_name(transt->vsub),
			paging_event == GSM_PAGING_EXPIRED ? "expired" : "busy");

		/* TODO: inform HLR about this failure */

		msgb_free(transt->ss.msg);
		transt->ss.msg = NULL;

		transt->callref = 0;
		transt->paging_request = NULL;
		trans_free(transt);
		break;
	}

	return 0;
}

static struct gsm_trans *establish_nc_ss_trans(struct gsm_network *net,
	struct vlr_subscr *vsub, struct osmo_gsup_message *gsup_msg)
{
	struct ran_conn *conn;
	struct gsm_trans *trans, *transt;
	int tid;

	/* Allocate transaction first, for log context */
	trans = trans_alloc(net, vsub, GSM48_PDISC_NC_SS,
		TRANS_ID_UNASSIGNED, gsup_msg->session_id);

	if (!trans) {
		LOG_TRANS(trans, LOGL_ERROR, " -> No memory for trans\n");
		return NULL;
	}

	if (gsup_msg->session_state != OSMO_GSUP_SESSION_STATE_BEGIN) {
		LOG_TRANS(trans, LOGL_ERROR, "Received non-BEGIN message "
			"for non-existing transaction\n");
		trans_free(trans);
		return NULL;
	}

	if (!gsup_msg->ss_info || gsup_msg->ss_info_len < 2) {
		LOG_TRANS(trans, LOGL_ERROR, "Missing mandatory Facility IE\n");
		trans_free(trans);
		return NULL;
	}

	/* If subscriber is not "attached" */
	if (!vsub->cgi.lai.lac) {
		LOG_TRANS(trans, LOGL_ERROR, "Network-originated session "
			"rejected - subscriber is not attached\n");
		trans_free(trans);
		return NULL;
	}

	LOG_TRANS(trans, LOGL_DEBUG, "Establishing network-originated session\n");

	/* Count active NC SS/USSD sessions */
	osmo_counter_inc(net->active_nc_ss);

	/* Assign transaction ID */
	tid = trans_assign_trans_id(trans->net, trans->vsub, GSM48_PDISC_NC_SS);
	if (tid < 0) {
		LOG_TRANS(trans, LOGL_ERROR, "No free transaction ID\n");
		/* TODO: inform HLR about this */
		/* TODO: release connection with subscriber */
		trans->callref = 0;
		trans_free(trans);
		return NULL;
	}
	trans->transaction_id = tid;

	/* Init inactivity timer */
	osmo_timer_setup(&trans->ss.timer_guard,
		ncss_session_timeout_handler, trans);

	/* Attempt to find connection */
	conn = connection_for_subscr(vsub);
	if (conn) {
		/* Assign connection */
		trans->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_NC_SS);
		trans->dlci = 0x00; /* SAPI=0, not SACCH */
		return trans;
	}

	LOG_TRANS(trans, LOGL_DEBUG, "Triggering Paging Request\n");

	/* Find transaction with this subscriber already paging */
	llist_for_each_entry(transt, &net->trans_list, entry) {
		/* Transaction of our conn? */
		if (transt == trans || transt->vsub != vsub)
			continue;

		LOG_TRANS(trans, LOGL_ERROR, "Paging already started, "
			"rejecting message...\n");
		trans_free(trans);
		return NULL;
	}

	/* Trigger Paging Request */
	trans->paging_request = subscr_request_conn(vsub,
		&handle_paging_event, trans, "GSM 09.11 SS/USSD",
	        SGSAP_SERV_IND_CS_CALL);
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

	return NULL;
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
	osmo_counter_dec(trans->net->active_nc_ss);
}

int gsm0911_gsup_handler(struct vlr_subscr *vsub,
			 struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr;
	struct gsm_network *net;
	struct gsm_trans *trans;
	struct gsm48_hdr *gh;
	struct msgb *ss_msg;
	bool trans_end;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

	/* Obtain pointer to vlr_instance */
	vlr = vsub->vlr;
	OSMO_ASSERT(vlr);

	/* Obtain pointer to gsm_network */
	net = (struct gsm_network *) vlr->user_ctx;
	OSMO_ASSERT(net);

	/* Handle errors */
	if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		/* FIXME: handle this error somehow! */
		return 0;
	}

	/* Attempt to find DTAP-transaction */
	trans = trans_find_by_callref(net, gsup_msg->session_id);
	if (!trans) {
		/* Count network-initiated attempts to establish a NC SS/USSD session */
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_REQUESTS]);

		/* Attempt to establish a new transaction */
		trans = establish_nc_ss_trans(net, vsub, gsup_msg);
		if (!trans) {
			/* FIXME: send ERROR back to the HLR */
			return -EINVAL;
		}

		/* Wait for Paging Response */
		if (trans->paging_request)
			return 0;
	}

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
		/* FIXME: send ERROR back to the HLR */
		msgb_free(ss_msg);
		return -EINVAL;
	}

	/* Facility IE is optional only for RELEASE COMPLETE */
	if (gh->msg_type != GSM0480_MTYPE_RELEASE_COMPLETE) {
		if (!gsup_msg->ss_info || gsup_msg->ss_info_len < 2) {
			LOG_TRANS(trans, LOGL_ERROR, "Missing mandatory Facility IE "
				"for mapped 0x%02x message\n", gh->msg_type);
			/* FIXME: send ERROR back to the HLR */
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
	msc_tx_dtap(trans->conn, ss_msg);

	/* Release transaction if required */
	if (trans_end)
		trans_free(trans);

	/* Count established network-initiated NC SS/USSD sessions */
	if (gsup_msg->session_state == OSMO_GSUP_SESSION_STATE_BEGIN)
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_ESTABLISHED]);

	return 0;
}
