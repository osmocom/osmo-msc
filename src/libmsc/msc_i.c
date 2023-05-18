/* Code to manage a subscriber's MSC-I role */
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

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/mncc_call.h>

static struct osmo_fsm msc_i_fsm;

struct ran_infra *msc_i_ran(struct msc_i *msc_i)
{
	OSMO_ASSERT(msc_i
		    && msc_i->ran_conn
		    && msc_i->ran_conn->ran_peer
		    && msc_i->ran_conn->ran_peer->sri
		    && msc_i->ran_conn->ran_peer->sri->ran);
	return msc_i->ran_conn->ran_peer->sri->ran;
}

static int msc_i_ran_enc(struct msc_i *msc_i, const struct ran_msg *ran_enc_msg)
{
	struct msgb *l3 = msc_role_ran_encode(msc_i->c.fi, ran_enc_msg);
	if (!l3)
		return -EIO;
	return msc_i_down_l2(msc_i, l3);
}

struct msc_i *msc_i_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_i_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

int msc_i_ready_decode_cb(struct osmo_fsm_inst *msc_i_fi, void *data, const struct ran_msg *msg)
{
	struct msc_i *msc_i = msc_i_priv(msc_i_fi);
	struct msc_a *msc_a = msub_msc_a(msc_i->c.msub);
	const struct an_apdu *an_apdu = data;
	uint32_t event;

	event = MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST;

	switch (msg->msg_type) {
	case RAN_MSG_HANDOVER_REQUIRED:
		if (msc_a->c.remote_to) {
			/* We're already a remote MSC-B, this hence must be a "subsequent" handover.
			 * There is not much difference really from dispatching a Process Access Signalling Request,
			 * only that 3GPP TS 29.010 specifies the different message type. */
			event = MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST;
		}
		break;
	default:
		break;
	}

	return msub_role_dispatch(msc_i->c.msub, MSC_ROLE_A, event, an_apdu);
}

void msc_i_fsm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_i *msc_i = msc_i_priv(fi);
	struct msc_a *msc_a = msub_msc_a(msc_i->c.msub);
	struct an_apdu *an_apdu;

	if (!msc_a) {
		LOG_MSC_I(msc_i, LOGL_ERROR, "No MSC-A role\n");
		return;
	}

	switch (event) {

	case MSC_EV_FROM_RAN_COMPLETE_LAYER_3:
		an_apdu = data;
		msub_role_dispatch(msc_i->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_I_COMPLETE_LAYER_3, an_apdu);
		break;

	case MSC_EV_FROM_RAN_UP_L2:
		an_apdu = data;
		/* To send the correct event types like MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST and hence
		 * reflect the correct GSUP message type on an inter-MSC link, need to decode the message here. */
		msc_role_ran_decode(msc_i->c.fi, an_apdu, msc_i_ready_decode_cb, an_apdu);
		break;

	case MSC_EV_FROM_RAN_CONN_RELEASED:
		msc_i_cleared(msc_i);
		break;

	case MSC_EV_CALL_LEG_TERM:
		msc_i->inter_msc.call_leg = NULL;
		if (msc_i->inter_msc.mncc_forwarding_to_remote_cn)
			msc_i->inter_msc.mncc_forwarding_to_remote_cn->rtps = NULL;
		break;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_i->inter_msc.mncc_forwarding_to_remote_cn = NULL;
		break;

	case MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST:
	case MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT:
	case MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR:
		an_apdu = data;
		if (an_apdu->an_proto != msc_i_ran(msc_i)->an_proto) {
			LOG_MSC_I(msc_i, LOGL_ERROR, "Mismatching AN-APDU proto: %s -- Dropping message\n",
				  an_proto_name(an_apdu->an_proto));
			msgb_free(an_apdu->msg);
			an_apdu->msg = NULL;
			return;
		}
		msc_i_down_l2(msc_i, an_apdu->msg);
		break;

	case MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE:
		msc_i_clear(msc_i);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

void msc_i_fsm_clearing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_i *msc_i = msc_i_priv(fi);
	struct ran_msg msg = {
		.msg_type = RAN_MSG_CLEAR_COMMAND,
		/* Concerning CSFB (Circuit-Switched FallBack from LTE), for a final Clear Command that might indicate
		 * CSFB, the MSC-A has to send the Clear Command. This Clear Command is about detaching an MSC-I when a
		 * new MSC-I has shown up after an inter-BSC or inter-MSC Handover succeeded. So never CSFB here. */
	};
	msc_i_ran_enc(msc_i, &msg);
}

int msc_i_clearing_decode_cb(struct osmo_fsm_inst *msc_i_fi, void *data, const struct ran_msg *msg)
{
	struct msc_i *msc_i = msc_i_fi->priv;

	switch (msg->msg_type) {

	case RAN_MSG_CLEAR_COMPLETE:
		switch (msc_i->c.fi->state) {
		case MSC_I_ST_CLEARING:
			osmo_fsm_inst_state_chg(msc_i->c.fi, MSC_I_ST_CLEARED, 0, 0);
			return 0;
		case MSC_I_ST_CLEARED:
			return 0;
		default:
			LOG_MSC_I(msc_i, LOGL_ERROR, "Received Clear Complete, but did not send Clear Command\n");
			{
				struct msc_a *msc_a = msub_msc_a(msc_i->c.msub);
				if (msc_a)
					osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_MO_CLOSE, NULL);
			}
			return 0;
		}

	default:
		LOG_MSC_I(msc_i, LOGL_ERROR, "Message not handled: %s\n", ran_msg_type_name(msg->msg_type));
		return -ENOTSUP;
	}
}

void msc_i_fsm_clearing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_i *msc_i = msc_i_priv(fi);
	struct an_apdu *an_apdu;

	/* We expect a Clear Complete and nothing else. */
	switch (event) {
	case MSC_EV_FROM_RAN_UP_L2:
		an_apdu = data;
		msc_role_ran_decode(msc_i->c.fi, an_apdu, msc_i_clearing_decode_cb, NULL);
		return;

	case MSC_EV_FROM_RAN_CONN_RELEASED:
		msc_i_cleared(msc_i);
		return;

	case MSC_EV_CALL_LEG_TERM:
		msc_i->inter_msc.call_leg = NULL;
		if (msc_i->inter_msc.mncc_forwarding_to_remote_cn)
			msc_i->inter_msc.mncc_forwarding_to_remote_cn->rtps = NULL;
		break;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_i->inter_msc.mncc_forwarding_to_remote_cn = NULL;
		break;
	}
}

void msc_i_fsm_cleared_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, fi);
}

void msc_i_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_i *msc_i = msc_i_priv(fi);

	call_leg_release(msc_i->inter_msc.call_leg);
	mncc_call_release(msc_i->inter_msc.mncc_forwarding_to_remote_cn);

	if (msc_i->ran_conn)
		ran_conn_msc_role_gone(msc_i->ran_conn, msc_i->c.fi);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_i_fsm_states[] = {
	[MSC_I_ST_READY] = {
		.name = "READY",
		.action = msc_i_fsm_ready,
		.in_event_mask = 0
			| S(MSC_EV_FROM_RAN_COMPLETE_LAYER_3)
			| S(MSC_EV_FROM_RAN_UP_L2)
			| S(MSC_EV_FROM_RAN_CONN_RELEASED)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT)
			| S(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR)
			| S(MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE)
			,
		.out_state_mask = 0
			| S(MSC_I_ST_CLEARING)
			| S(MSC_I_ST_CLEARED)
			,
	},
	[MSC_I_ST_CLEARING] = {
		.name = "CLEARING",
		.onenter = msc_i_fsm_clearing_onenter,
		.action = msc_i_fsm_clearing,
		.in_event_mask = 0
			| S(MSC_EV_FROM_RAN_UP_L2)
			| S(MSC_EV_FROM_RAN_CONN_RELEASED)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			,
		.out_state_mask = 0
			| S(MSC_I_ST_CLEARED)
			,
	},
	[MSC_I_ST_CLEARED] = {
		.name = "CLEARED",
		.onenter = msc_i_fsm_cleared_onenter,
	},
};

const struct value_string msc_i_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSC_REMOTE_EV_RX_GSUP),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_COMPLETE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_TERM),
	OSMO_VALUE_STRING(MSC_MNCC_EV_NEED_LOCAL_RTP),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_PROCEEDING),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_COMPLETE),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_ENDED),

	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_COMPLETE_LAYER_3),
	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_UP_L2),
	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_CONN_RELEASED),

	OSMO_VALUE_STRING(MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST),
	OSMO_VALUE_STRING(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT),
	OSMO_VALUE_STRING(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR),
	OSMO_VALUE_STRING(MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE),
	{}
};

static struct osmo_fsm msc_i_fsm = {
	.name = "msc_i",
	.states = msc_i_fsm_states,
	.num_states = ARRAY_SIZE(msc_i_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_i_fsm_event_names,
	.cleanup = msc_i_fsm_cleanup,
};

static __attribute__((constructor)) void msc_i_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_i_fsm) == 0);
}

/* Send connection-oriented L3 message to RAN peer (MSC->[BSC|RNC]) */
int msc_i_down_l2(struct msc_i *msc_i, struct msgb *l3)
{
	int rc;
	if (!msc_i->ran_conn) {
		LOG_MSC_I(msc_i, LOGL_ERROR, "Cannot Tx L2 message: no RAN conn\n");
		return -EIO;
	}

	rc = ran_conn_down_l2_co(msc_i->ran_conn, l3, false);
	if (rc)
		LOG_MSC_I(msc_i, LOGL_ERROR, "Failed to transfer message down to subscriber (rc=%d)\n", rc);
	return rc;
}

struct gsm_network *msc_i_net(const struct msc_i *msc_i)
{
	return msub_net(msc_i->c.msub);
}

struct vlr_subscr *msc_i_vsub(const struct msc_i *msc_i)
{
	if (!msc_i)
		return NULL;
	return msub_vsub(msc_i->c.msub);
}

struct msc_i *msc_i_alloc(struct msub *msub, struct ran_infra *ran)
{
	return msub_role_alloc(msub, MSC_ROLE_I, &msc_i_fsm, struct msc_i, ran);
}

/* Send Clear Command and wait for Clear Complete autonomously. "Normally", the MSC-A handles Clear Command and receives
 * Clear Complete, and then terminates MSC-I directly. This is useful to replace an MSC-I with another MSC-I during
 * Handover. */
void msc_i_clear(struct msc_i *msc_i)
{
	if (!msc_i)
		return;
	/* sanity timeout */
	osmo_fsm_inst_state_chg(msc_i->c.fi, MSC_I_ST_CLEARING, 60, 0);
}

void msc_i_cleared(struct msc_i *msc_i)
{
	if (!msc_i)
		return;
	osmo_fsm_inst_state_chg(msc_i->c.fi, MSC_I_ST_CLEARED, 0, 0);
}

void msc_i_set_ran_conn(struct msc_i *msc_i, struct ran_conn *new_conn)
{
	struct ran_conn *old_conn = msc_i->ran_conn;

	if (old_conn == new_conn)
		return;

	msc_i->ran_conn = NULL;
	if (old_conn) {
		old_conn->msc_role = NULL;
		ran_conn_close(old_conn);
	}

	/* Taking a conn over from another MSC role? Make sure the other side forgets about it. */
	if (new_conn->msc_role)
		msc_role_forget_conn(new_conn->msc_role, new_conn);

	msc_i->ran_conn = new_conn;
	msc_i->ran_conn->msc_role = msc_i->c.fi;

	/* Add the RAN conn info to the msub logging */
	msub_update_id(msc_i->c.msub);
}
