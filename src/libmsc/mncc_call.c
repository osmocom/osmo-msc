/* Handle an MNCC managed call (external MNCC). */
/* At the time of writing, this is only used for inter-MSC handover: forward a voice stream to a remote MSC.
 * Maybe it makes sense to also use it for all "normal" external call management at some point. */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
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
 */

#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/msc/mncc_call.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/codec_mapping.h>

struct osmo_fsm mncc_call_fsm;
static bool mncc_call_tx_rtp_create(struct mncc_call *mncc_call);

LLIST_HEAD(mncc_call_list);

static const struct osmo_tdef_state_timeout mncc_call_fsm_timeouts[32] = {
	/* TODO */
};

struct gsm_network *gsmnet = NULL;

/* Transition to a state, using the T timer defined in msc_a_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define mncc_call_fsm_state_chg(MNCC, STATE) \
	osmo_tdef_fsm_inst_state_chg((MNCC)->fi, STATE, mncc_call_fsm_timeouts, gsmnet->mncc_tdefs, 5)

#define mncc_call_error(MNCC, FMT, ARGS...) do { \
		LOG_MNCC_CALL(MNCC, LOGL_ERROR, FMT, ##ARGS); \
		osmo_fsm_inst_term((MNCC)->fi, OSMO_FSM_TERM_REGULAR, 0); \
	} while(0)

void mncc_call_fsm_init(struct gsm_network *net)
{
	OSMO_ASSERT(osmo_fsm_register(&mncc_call_fsm) == 0);
	gsmnet = net;
}

void mncc_call_fsm_update_id(struct mncc_call *mncc_call)
{
	osmo_fsm_inst_update_id_f_sanitize(mncc_call->fi, '-', "%s:callref-0x%x%s%s",
					   vlr_subscr_name(mncc_call->vsub), mncc_call->callref,
					   mncc_call->remote_msisdn_present ? ":to-msisdn-" : "",
					   mncc_call->remote_msisdn_present ? mncc_call->remote_msisdn.number : "");
}

/* Invoked by the socket read callback in case the given MNCC call instance is responsible for the given callref. */
void mncc_call_rx(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg)
{
	if (!mncc_call)
		return;
	LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Rx %s\n", get_mncc_name(mncc_msg->msg_type));
	osmo_fsm_inst_dispatch(mncc_call->fi, MNCC_CALL_EV_RX_MNCC_MSG, (void*)mncc_msg);
}

/* Send an MNCC message (associated with this MNCC call). */
int mncc_call_tx(struct mncc_call *mncc_call, union mncc_msg *mncc_msg)
{
	struct msgb *msg;
	unsigned char *data;

	LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "tx %s\n", get_mncc_name(mncc_msg->msg_type));

	msg = msgb_alloc(sizeof(*mncc_msg), "MNCC-tx");
	OSMO_ASSERT(msg);

	data = msgb_put(msg, sizeof(*mncc_msg));
	memcpy(data, mncc_msg, sizeof(*mncc_msg));

	if (gsmnet->mncc_recv(gsmnet, msg)) {
		mncc_call_error(mncc_call, "Failed to send MNCC message %s\n", get_mncc_name(mncc_msg->msg_type));
		return -EIO;
	}
	return 0;
}

/* Send a trivial MNCC message with just a message type (associated with this MNCC call). */
int mncc_call_tx_msgt(struct mncc_call *mncc_call, uint32_t msg_type)
{
	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = msg_type,
			.callref = mncc_call->callref,
		},
	};
	return mncc_call_tx(mncc_call, &mncc_msg);
}

/* Allocate an MNCC FSM as child of the given MSC role FSM.
 * parent_event_call_released is mandatory and is passed as the parent_term_event.
 * parent_event_call_setup_complete is dispatched when the MNCC FSM enters the MNCC_CALL_ST_TALKING state.
 * parent_event_call_setup_complete is optional, pass a negative number to avoid dispatching.
 *
 * If non-NULL, message_cb is invoked whenever an MNCC message is received from the the MNCC socket, which is useful to
 * forward things like DTMF to CC or to another MNCC call.
 *
 * After mncc_call_alloc(), call either mncc_call_outgoing_start() or mncc_call_incoming_start().
 */
struct mncc_call *mncc_call_alloc(struct vlr_subscr *vsub,
				  struct osmo_fsm_inst *parent,
				  int parent_event_call_setup_complete,
				  uint32_t parent_event_call_released,
				  mncc_call_message_cb_t message_cb, void *forward_cb_data)
{
	struct mncc_call *mncc_call;
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&mncc_call_fsm, parent, parent_event_call_released);
	OSMO_ASSERT(fi);
	OSMO_ASSERT(vsub);

	mncc_call = talloc(fi, struct mncc_call);
	OSMO_ASSERT(mncc_call);
	fi->priv = mncc_call;

	*mncc_call = (struct mncc_call){
		.fi = fi,
		.vsub = vsub,
		.parent_event_call_setup_complete = parent_event_call_setup_complete,
		.message_cb = message_cb,
		.forward_cb_data = forward_cb_data,
	};

	llist_add(&mncc_call->entry, &mncc_call_list);
	mncc_call_fsm_update_id(mncc_call);

	return mncc_call;
}

void mncc_call_reparent(struct mncc_call *mncc_call,
			struct osmo_fsm_inst *new_parent,
			int parent_event_call_setup_complete,
			uint32_t parent_event_call_released,
			mncc_call_message_cb_t message_cb, void *forward_cb_data)
{
	LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Reparenting from parent %s to parent %s\n",
		      mncc_call->fi->proc.parent->name, new_parent->name);
	osmo_fsm_inst_change_parent(mncc_call->fi, new_parent, parent_event_call_released);
	talloc_steal(new_parent, mncc_call->fi);
	mncc_call->parent_event_call_setup_complete = parent_event_call_setup_complete;
	mncc_call->message_cb = message_cb;
	mncc_call->forward_cb_data = forward_cb_data;
}

/* Associate an rtp_stream with this MNCC call instance (optional).
 * Can be called directly after mncc_call_alloc(). If an rtp_stream is set, upon receiving the MNCC_RTP_CONNECT containing
 * the PBX's RTP IP and port, pass the IP:port information to rtp_stream_set_remote_addr() and rtp_stream_commit() to
 * update the MGW connection.  If no rtp_stream is associated, the caller is responsible to manually extract the RTP
 * IP:port from the MNCC_RTP_CONNECT message forwarded to mncc_call_message_cb_t (see mncc_call_alloc()).
 * When an rtp_stream is set, call rtp_stream_release() when the MNCC call ends; call mncc_call_detach_rtp_stream() before
 * the MNCC call releases if that is not desired.
 */
int mncc_call_set_rtp_stream(struct mncc_call *mncc_call, struct rtp_stream *rtps)
{
	if (mncc_call->rtps && mncc_call->rtps != rtps) {
		LOG_MNCC_CALL(mncc_call, LOGL_ERROR,
			      "Cannot associate with RTP stream %s, already associated with %s\n",
			      rtps ? rtps->fi->name : "NULL", mncc_call->rtps->fi->name);
		return -ENOSPC;
	}

	mncc_call->rtps = rtps;
	LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Associated with RTP stream %s\n", mncc_call->rtps->fi->name);
	return 0;
}

/* Disassociate the rtp_stream from this MNCC call instance, and clear the remote RTP IP:port info.
 * When the MNCC FSM ends for any reason, it will release the RTP stream (which usually triggers complete tear down of
 * the call_leg and CC transaction). If the RTP stream should still remain in use, e.g. during Subsequent inter-MSC
 * Handover where this MNCC was a forwarding to a remote MSC that is no longer needed, this function must be called
 * before the MNCC FSM instance terminates. Call this *before* setting a new remote RTP address on the rtp_stream, since
 * this clears the rtp_stream->remote ip:port information. */
void mncc_call_detach_rtp_stream(struct mncc_call *mncc_call)
{
	struct rtp_stream *rtps = mncc_call->rtps;
	struct osmo_sockaddr_str clear = { 0 };
	if (!rtps)
		return;
	mncc_call->rtps = NULL;
	rtp_stream_set_remote_addr(rtps, &clear);
}

static void mncc_call_tx_setup_ind(struct mncc_call *mncc_call)
{
	union mncc_msg mncc_msg;
	mncc_msg.signal = mncc_call->outgoing_req;
	mncc_msg.signal.msg_type = MNCC_SETUP_IND;
	mncc_msg.signal.callref = mncc_call->callref;

	OSMO_STRLCPY_ARRAY(mncc_msg.signal.imsi, mncc_call->vsub->imsi);

	if (!(mncc_call->outgoing_req.fields & MNCC_F_CALLING)) {
		/* No explicit calling number set, use the local subscriber */
		mncc_msg.signal.fields |= MNCC_F_CALLING;
		OSMO_STRLCPY_ARRAY(mncc_msg.signal.calling.number, mncc_call->vsub->msisdn);

	}
	mncc_call->local_msisdn_present = true;
	mncc_call->local_msisdn = mncc_msg.signal.calling;

	rate_ctr_inc(rate_ctr_group_get_ctr(gsmnet->msc_ctrs, MSC_CTR_CALL_MO_SETUP));

	mncc_call_tx(mncc_call, &mncc_msg);
}

static void mncc_call_rx_setup_req(struct mncc_call *mncc_call, const struct gsm_mncc *incoming_req)
{
	mncc_call->callref = incoming_req->callref;

	if (incoming_req->fields & MNCC_F_CALLED) {
		mncc_call->local_msisdn_present = true;
		mncc_call->local_msisdn = incoming_req->called;
	}

	if (incoming_req->fields & MNCC_F_CALLING) {
		mncc_call->remote_msisdn_present = true;
		mncc_call->remote_msisdn = incoming_req->calling;
	}

	mncc_call_fsm_update_id(mncc_call);
}

/* Remote PBX asks for RTP_CREATE. This merely asks us to create an RTP stream, and does not actually contain any useful
 * information like the remote RTP IP:port (these follow in the RTP_CONNECT from the SIP side) */
static bool mncc_call_rx_rtp_create(struct mncc_call *mncc_call)
{
	mncc_call->received_rtp_create = true;

	if (!mncc_call->rtps) {
		LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Got RTP_CREATE, but no RTP stream associated\n");
		return true;
	}

	if (!osmo_sockaddr_str_is_nonzero(&mncc_call->rtps->local)) {
		LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Got RTP_CREATE, but RTP stream has no local address\n");
		return true;
	}

	if (!mncc_call->rtps->codecs_known) {
		LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Got RTP_CREATE, but RTP stream has no codec set\n");
		return true;
	}

	LOG_MNCC_CALL(mncc_call, LOGL_DEBUG, "Got RTP_CREATE, responding with " OSMO_SOCKADDR_STR_FMT " %s\n",
		      OSMO_SOCKADDR_STR_FMT_ARGS(&mncc_call->rtps->local),
		      sdp_audio_codecs_to_str(&mncc_call->rtps->codecs));
	/* Already know what RTP IP:port to tell the MNCC. Send it. */
	return mncc_call_tx_rtp_create(mncc_call);
}

static bool mncc_call_tx_rtp_create(struct mncc_call *mncc_call)
{
	if (!mncc_call->rtps || !osmo_sockaddr_str_is_nonzero(&mncc_call->rtps->local)) {
		mncc_call_error(mncc_call, "Cannot send RTP_CREATE, no local RTP address set up\n");
		return false;
	}
	struct osmo_sockaddr_str *rtp_local = &mncc_call->rtps->local;
	union mncc_msg mncc_msg = {
		.rtp = {
			.msg_type = MNCC_RTP_CREATE,
			.callref = mncc_call->callref,
		},
	};

	if (osmo_sockaddr_str_to_sockaddr(rtp_local, &mncc_msg.rtp.addr)) {
		mncc_call_error(mncc_call, "Failed to compose IP address " OSMO_SOCKADDR_STR_FMT "\n",
				OSMO_SOCKADDR_STR_FMT_ARGS(rtp_local));
		return false;
	}

	if (mncc_call->rtps->codecs_known) {
		struct sdp_audio_codec *codec = &mncc_call->rtps->codecs.codec[0];
		const struct codec_mapping *m = codec_mapping_by_subtype_name(codec->subtype_name);

		if (!m) {
			mncc_call_error(mncc_call, "Failed to resolve audio codec '%s'\n",
					sdp_audio_codec_to_str(codec));
			return false;
		}
		mncc_msg.rtp.payload_type = codec->payload_type;
		mncc_msg.rtp.payload_msg_type = m->mncc_payload_msg_type;
	}

	if (mncc_call_tx(mncc_call, &mncc_msg))
		return false;
	return true;
}

static bool mncc_call_rx_rtp_connect(struct mncc_call *mncc_call, const struct gsm_mncc_rtp *mncc_msg)
{
	struct osmo_sockaddr_str rtp;

	if (!mncc_call->rtps) {
		/* The user has not associated an RTP stream, hence we're not supposed to take any action here. */
		return true;
	}

	if (osmo_sockaddr_str_from_sockaddr(&rtp, &mncc_msg->addr)) {
		mncc_call_error(mncc_call, "Cannot RTP-CONNECT, invalid RTP IP:port in incoming MNCC message\n");
		return false;
	}

	rtp_stream_set_remote_addr(mncc_call->rtps, &rtp);
	if (rtp_stream_commit(mncc_call->rtps)) {
		mncc_call_error(mncc_call, "RTP-CONNECT, failed, RTP stream is not properly set up: %s\n",
				mncc_call->rtps->fi->id);
		return false;
	}
	return true;
}

/* Return true if the FSM instance still exists after this call, false if it was terminated. */
static bool mncc_call_rx_release_msg(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg)
{
	switch (mncc_msg->msg_type) {
	case MNCC_DISC_REQ:
		/* Remote call leg ended the call, MNCC tells us to DISC. We ack with a REL. */
		mncc_call_tx_msgt(mncc_call, MNCC_REL_IND);
		osmo_fsm_inst_term(mncc_call->fi, OSMO_FSM_TERM_REGULAR, 0);
		return false;

	case MNCC_REL_REQ:
		/* MNCC acks with a REL to a previous DISC IND we have (probably) sent.
		 * We ack with a REL CNF. */
		mncc_call_tx_msgt(mncc_call, MNCC_REL_CNF);
		osmo_fsm_inst_term(mncc_call->fi, OSMO_FSM_TERM_REGULAR, 0);
		return false;

	default:
		return true;
	}
}

/* Return true if the FSM instance still exists after this call, false if it was terminated. */
static bool mncc_call_rx_common_msg(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg)
{
	switch (mncc_msg->msg_type) {
	case MNCC_RTP_CREATE:
		mncc_call_rx_rtp_create(mncc_call);
		return true;

	case MNCC_RTP_CONNECT:
		mncc_call_rx_rtp_connect(mncc_call, &mncc_msg->rtp);
		return true;

	default:
		return mncc_call_rx_release_msg(mncc_call, mncc_msg);
	}
}

static void mncc_call_forward(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg)
{
	if (!mncc_call || !mncc_call->message_cb)
		return;
	mncc_call->message_cb(mncc_call, mncc_msg, mncc_call->forward_cb_data);
}

/* Initiate an outgoing call.
 * The outgoing_req represents the details for the MNCC_SETUP_IND message sent to initiate the outgoing call. Pass at
 * least a called number (set outgoing_req->fields |= MNCC_F_CALLED and populate outgoing_req->called). All other items
 * are optional and can be included if required. The message type, callref and IMSI from this struct are ignored,
 * instead they are determined internally upon sending the MNCC message. If no calling number is set in the message
 * struct, it will be set from mncc_call->vsub->msisdn.
 */
int mncc_call_outgoing_start(struct mncc_call *mncc_call, const struct gsm_mncc *outgoing_req)
{
	if (!mncc_call)
		return -EINVAL;
	/* By dispatching an event instead of taking direct action, make sure that the FSM permits starting an outgoing
	 * call. */
	return osmo_fsm_inst_dispatch(mncc_call->fi, MNCC_CALL_EV_OUTGOING_START, (void*)outgoing_req);
}

/* Handle an incoming call.
 * When the MNCC recv callback (not included in this mncc_call_fsm API) detects an incoming call (MNCC_SETUP_REQ), take over
 * handling of the incoming call by the given mncc_call instance.
 * In incoming_req->setup_req_msg, pass the struct gsm_mncc message containing the received MNCC_SETUP_REQ.
 * mncc_call_incoming_start() will immediately respond with a MNCC_CALL_CONF_IND; in incoming_req->bearer_cap, pass the
 * bearer capabilities that should be included in this MNCC_CALL_CONF_IND message; in incoming_req->cccap, pass the
 * CCCAP to be sent, if any.
 */
int mncc_call_incoming_start(struct mncc_call *mncc_call, const struct mncc_call_incoming_req *incoming_req)
{
	if (!mncc_call)
		return -EINVAL;
	/* By dispatching an event instead of taking direct action, make sure that the FSM permits starting an incoming
	 * call. */
	return osmo_fsm_inst_dispatch(mncc_call->fi, MNCC_CALL_EV_INCOMING_START, (void*)incoming_req);
}

static void mncc_call_incoming_tx_call_conf_ind(struct mncc_call *mncc_call, const struct gsm_mncc_bearer_cap *bearer_cap)
{
	if (mncc_call->fi->state != MNCC_CALL_ST_INCOMING_WAIT_COMPLETE) {
		LOG_MNCC_CALL(mncc_call, LOGL_ERROR, "%s not allowed in this state\n", __func__);
		return;
	}

	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = MNCC_CALL_CONF_IND,
			.callref = mncc_call->callref,
		},
	};

	if (bearer_cap) {
		mncc_msg.signal.fields |= MNCC_F_BEARER_CAP;
		mncc_msg.signal.bearer_cap = *bearer_cap;
	}

	mncc_call_tx(mncc_call, &mncc_msg);
}

/* Send an MNCC_SETUP_CNF message. Typically after the local side is ready to receive the call and RTP (e.g. for a GSM
 * CC call, the lchan and RTP should be ready and the CC call should have been confirmed and alerting).
 * For inter-MSC call forwarding, this can happen immediately upon the MNCC_RTP_CREATE.
 */
int mncc_call_incoming_tx_setup_cnf(struct mncc_call *mncc_call, const struct gsm_mncc_number *connected_number)
{
	if (mncc_call->fi->state != MNCC_CALL_ST_INCOMING_WAIT_COMPLETE) {
		LOG_MNCC_CALL(mncc_call, LOGL_ERROR, "%s not allowed in this state\n", __func__);
		return -EINVAL;
	}

	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = MNCC_SETUP_CNF,
			.callref = mncc_call->callref,
		},
	};

	if (connected_number) {
		mncc_msg.signal.fields |= MNCC_F_CONNECTED;
		mncc_msg.signal.connected = *connected_number;
	}

	return mncc_call_tx(mncc_call, &mncc_msg);
}

static void mncc_call_fsm_not_started(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const struct gsm_mncc *outgoing_req;
	const struct mncc_call_incoming_req *incoming_req;

	switch (event) {
	case MNCC_CALL_EV_OUTGOING_START:
		outgoing_req = data;
		mncc_call->outgoing_req = *outgoing_req;
		mncc_call->callref = msc_cc_next_outgoing_callref();
		mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_OUTGOING_WAIT_PROCEEDING);
		mncc_call_tx_setup_ind(mncc_call);
		return;

	case MNCC_CALL_EV_INCOMING_START:
		incoming_req = data;
		mncc_call_rx_setup_req(mncc_call, &incoming_req->setup_req_msg);
		mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_INCOMING_WAIT_COMPLETE);
		mncc_call_incoming_tx_call_conf_ind(mncc_call, incoming_req->bearer_cap_present ? &incoming_req->bearer_cap : NULL);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void mncc_call_fsm_outgoing_wait_proceeding(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_CALL_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_call_rx_common_msg(mncc_call, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_CALL_PROC_REQ:
			mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_OUTGOING_WAIT_COMPLETE);
			break;
		default:
			break;
		}

		mncc_call_forward(mncc_call, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_call_fsm_outgoing_wait_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_CALL_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_call_rx_common_msg(mncc_call, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_SETUP_RSP:
			mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_TALKING);
			mncc_call_tx_msgt(mncc_call, MNCC_SETUP_COMPL_IND);
			break;
		default:
			break;
		}

		mncc_call_forward(mncc_call, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_call_fsm_incoming_wait_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_CALL_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_call_rx_common_msg(mncc_call, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_SETUP_COMPL_REQ:
			mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_TALKING);
			break;
		default:
			break;
		}

		mncc_call_forward(mncc_call, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_call_fsm_talking(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_CALL_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_call_rx_common_msg(mncc_call, mncc_msg))
			return;
		mncc_call_forward(mncc_call, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_call_fsm_wait_release_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc_call *mncc_call = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_CALL_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_call_rx_release_msg(mncc_call, mncc_msg))
			return;
		mncc_call_forward(mncc_call, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_call_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mncc_call *mncc_call = fi->priv;

	switch (fi->state) {
	case MNCC_CALL_ST_NOT_STARTED:
	case MNCC_CALL_ST_WAIT_RELEASE_ACK:
		break;
	default:
		/* Make sure we did indicate some sort of release */
		mncc_call_tx_msgt(mncc_call, MNCC_REL_IND);
		break;
	}

	/* Releasing the RTP stream should trigger completely tearing down the call leg as well as the CC transaction.
	 * In case of an inter-MSC handover where this MNCC connection is replaced by another MNCC / another BSC
	 * connection, the caller needs to detach the RTP stream from this FSM before terminating it. */
	if (mncc_call->rtps) {
		rtp_stream_release(mncc_call->rtps);
		mncc_call->rtps = NULL;
	}

	llist_del(&mncc_call->entry);
}

static int mncc_call_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 1;
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state mncc_call_fsm_states[] = {
	[MNCC_CALL_ST_NOT_STARTED] = {
		.name = "NOT_STARTED",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_OUTGOING_START)
			| S(MNCC_CALL_EV_INCOMING_START)
			,
		.out_state_mask = 0
			| S(MNCC_CALL_ST_OUTGOING_WAIT_PROCEEDING)
			| S(MNCC_CALL_ST_INCOMING_WAIT_COMPLETE)
			,
		.action = mncc_call_fsm_not_started,
	},
	[MNCC_CALL_ST_OUTGOING_WAIT_PROCEEDING] = {
		.name = "OUTGOING_WAIT_PROCEEDING",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_CALL_ST_OUTGOING_WAIT_COMPLETE)
			| S(MNCC_CALL_ST_WAIT_RELEASE_ACK)
			,
		.action = mncc_call_fsm_outgoing_wait_proceeding,
	},
	[MNCC_CALL_ST_OUTGOING_WAIT_COMPLETE] = {
		.name = "OUTGOING_WAIT_COMPLETE",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_CALL_ST_TALKING)
			| S(MNCC_CALL_ST_WAIT_RELEASE_ACK)
			,
		.action = mncc_call_fsm_outgoing_wait_complete,
	},
	[MNCC_CALL_ST_INCOMING_WAIT_COMPLETE] = {
		.name = "INCOMING_WAIT_COMPLETE",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_CALL_ST_TALKING)
			| S(MNCC_CALL_ST_WAIT_RELEASE_ACK)
			,
		.action = mncc_call_fsm_incoming_wait_complete,
	},
	[MNCC_CALL_ST_TALKING] = {
		.name = "TALKING",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_CALL_ST_WAIT_RELEASE_ACK)
			,
		.action = mncc_call_fsm_talking,
	},
	[MNCC_CALL_ST_WAIT_RELEASE_ACK] = {
		.name = "WAIT_RELEASE_ACK",
		.in_event_mask = 0
			| S(MNCC_CALL_EV_RX_MNCC_MSG)
			,
		.action = mncc_call_fsm_wait_release_ack,
	},
};

static const struct value_string mncc_call_fsm_event_names[] = {
	OSMO_VALUE_STRING(MNCC_CALL_EV_RX_MNCC_MSG),

	OSMO_VALUE_STRING(MNCC_CALL_EV_OUTGOING_START),
	OSMO_VALUE_STRING(MNCC_CALL_EV_OUTGOING_ALERTING),
	OSMO_VALUE_STRING(MNCC_CALL_EV_OUTGOING_SETUP_COMPLETE),

	OSMO_VALUE_STRING(MNCC_CALL_EV_INCOMING_START),
	OSMO_VALUE_STRING(MNCC_CALL_EV_INCOMING_SETUP),
	OSMO_VALUE_STRING(MNCC_CALL_EV_INCOMING_SETUP_COMPLETE),

	OSMO_VALUE_STRING(MNCC_CALL_EV_CN_RELEASE),
	OSMO_VALUE_STRING(MNCC_CALL_EV_MS_RELEASE),
	{}
};

struct osmo_fsm mncc_call_fsm = {
	.name = "mncc_call",
	.states = mncc_call_fsm_states,
	.num_states = ARRAY_SIZE(mncc_call_fsm_states),
	.log_subsys = DMNCC,
	.event_names = mncc_call_fsm_event_names,
	.timer_cb = mncc_call_fsm_timer_cb,
	.cleanup = mncc_call_fsm_cleanup,
};

struct mncc_call *mncc_call_find_by_callref(uint32_t callref)
{
	struct mncc_call *mncc_call;
	llist_for_each_entry(mncc_call, &mncc_call_list, entry) {
		if (mncc_call->callref == callref)
			return mncc_call;
	}
	return NULL;
}

void mncc_call_release(struct mncc_call *mncc_call)
{
	if (!mncc_call)
		return;
	mncc_call_tx_msgt(mncc_call, MNCC_DISC_IND);
	mncc_call_fsm_state_chg(mncc_call, MNCC_CALL_ST_WAIT_RELEASE_ACK);
}
