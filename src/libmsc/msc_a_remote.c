/* The MSC-A role implementation variant that forwards requests to/from a remote MSC. */
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

#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_a_remote.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/e_link.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/ran_peer.h>

static struct osmo_fsm msc_a_remote_fsm;

static struct msc_a *msc_a_remote_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_a_remote_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

/* The idea is that this msc_a role is event-compatible to the "real" msc_a.c FSM, but instead of acting on the events
 * directly, it forwards the events to a remote MSC-A role, via E-over-GSUP.
 *
 *     [MSC-A---------------------]            [MSC-B---------------------]
 *      msc_a <-- msc_{i,t}_remote <---GSUP---- msc_a_remote <-- msc_{i,t} <--BSSMAP--- [BSS]
 *                                            ^you are here
 */
static int msc_a_remote_msg_up_to_remote_msc(struct msc_a *msc_a,
					     enum msc_role from_role,
					     enum osmo_gsup_message_type message_type,
					     struct an_apdu *an_apdu)
{
	struct osmo_gsup_message m;
	struct e_link *e = msc_a->c.remote_to;

	if (!e) {
		LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "No E link to remote MSC, cannot send AN-APDU\n");
		return -1;
	}

	if (e_prep_gsup_msg(e, &m)) {
		LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "Error composing E-interface GSUP message\n");
		return -1;
	}
	m.message_type = message_type;
	if (an_apdu) {
		if (gsup_msg_assign_an_apdu(&m, an_apdu)) {
			LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "Error composing E-interface GSUP message\n");
			return -1;
		}
	}

	return e_tx(e, &m);
}

/*     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a --> msc_t_remote ----GSUP---> msc_a_remote --> msc_t ---BSSMAP--> [BSS]
 *                                        ^you are here
 */
static void msc_a_remote_rx_gsup_to_msc_t(struct msc_a *msc_a, const struct osmo_gsup_message *gsup_msg)
{
	uint32_t event;
	struct an_apdu an_apdu;

	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST:
		event = MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST:
	case OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST:
		event = MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_CLOSE:
	case OSMO_GSUP_MSGT_E_ABORT:
	case OSMO_GSUP_MSGT_E_ROUTING_ERROR:
		/* TODO: maybe some non-"normal" release with error cause? */
		msc_a_release_cn(msc_a);
		return;

	default:
		LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "Unhandled GSUP message type: %s\n",
				 osmo_gsup_message_type_name(gsup_msg->message_type));
		return;
	};

	gsup_msg_to_an_apdu(&an_apdu, gsup_msg);
	msub_role_dispatch(msc_a->c.msub, MSC_ROLE_T, event, &an_apdu);
	if (an_apdu.msg)
		msgb_free(an_apdu.msg);
}

/*     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
 *                                        ^you are here
 */
static void msc_a_remote_rx_gsup_to_msc_i(struct msc_a *msc_a, const struct osmo_gsup_message *gsup_msg)
{
	uint32_t event;
	struct an_apdu an_apdu;

	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST:
		event = MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_ERROR:
	case OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_RESULT:
		event = MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE;
		break;

	case OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_RESULT:
	case OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_ERROR:
		event = MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT;
		break;

	case OSMO_GSUP_MSGT_E_CLOSE:
	case OSMO_GSUP_MSGT_E_ABORT:
	case OSMO_GSUP_MSGT_E_ROUTING_ERROR:
		/* TODO: maybe some non-"normal" release with error cause? */
		msc_a_release_cn(msc_a);
		return;

	default:
		LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "Unhandled GSUP message type: %s\n",
				 osmo_gsup_message_type_name(gsup_msg->message_type));
		return;
	};

	gsup_msg_to_an_apdu(&an_apdu, gsup_msg);
	msub_role_dispatch(msc_a->c.msub, MSC_ROLE_I, event, &an_apdu);
	if (an_apdu.msg)
		msgb_free(an_apdu.msg);
}

static void msc_a_remote_send_handover_failure(struct msc_a *msc_a, enum gsm0808_cause cause)
{
	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_HANDOVER_FAILURE,
		.handover_failure = {
			.cause = cause,
		},
	};
	struct an_apdu an_apdu = {
		.an_proto = msc_a->c.ran->an_proto,
		.msg = msc_role_ran_encode(msc_a->c.fi, &ran_enc_msg),
	};
	if (!an_apdu.msg)
		return;

	msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T, OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_ERROR, &an_apdu);
}

/*     [MSC-A---------------------]            [MSC-B---------------------]
 *      msc_a --> msc_{i,t}_remote ----GSUP---> msc_a_remote --> msc_{i,t} ---BSSMAP--> [BSS]
 *                                            ^you are here
 */
static void msc_a_remote_rx_gsup(struct msc_a *msc_a, const struct osmo_gsup_message *gsup_msg)
{
	struct msc_t *msc_t = msc_a_msc_t(msc_a);
	struct msc_i *msc_i = msc_a_msc_i(msc_a);

	/* If starting a new Handover, this subscriber *must* be new and completely unattached. Create a new msc_t role
	 * to receive below event. */
	if (gsup_msg->message_type == OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST) {
		if (msc_t || msc_i) {
			LOG_MSC_A_REMOTE_CAT(msc_a, DLGSUP, LOGL_ERROR,
					     "Already have an MSC-T or -I role, cannot Rx %s from remote MSC\n",
					     osmo_gsup_message_type_name(gsup_msg->message_type));
			msc_a_remote_send_handover_failure(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE);
			return;
		}

		msc_t = msc_t_alloc_without_ran_peer(msc_a->c.msub, msc_a->c.ran);
	}

	/* We are on a remote MSC-B. If an msub has an MSC-T role, this is the remote target of a handover, and all
	 * messages from MSC-A *must* be intended for the MSC-T role. As soon as the Handover is successful, the MSC-T
	 * role disappears and an MSC-I role appears. */
	if (msc_t) {
		LOG_MSC_A_REMOTE_CAT(msc_a, DLGSUP, LOGL_DEBUG, "Routing to MSC-T: %s\n",
				     osmo_gsup_message_type_name(gsup_msg->message_type));
		msc_a_remote_rx_gsup_to_msc_t(msc_a, gsup_msg);
	} else if (msc_i) {
		LOG_MSC_A_REMOTE_CAT(msc_a, DLGSUP, LOGL_DEBUG, "Routing to MSC-I: %s\n",
				     osmo_gsup_message_type_name(gsup_msg->message_type));
		msc_a_remote_rx_gsup_to_msc_i(msc_a, gsup_msg);
	} else {
		LOG_MSC_A_REMOTE_CAT(msc_a, DLGSUP, LOGL_ERROR,
				     "No MSC-T nor MSC-I role present, cannot Rx GSUP %s\n",
				     osmo_gsup_message_type_name(gsup_msg->message_type));
	}
}

static void msc_a_remote_fsm_communicating(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = msc_a_remote_priv(fi);
	struct an_apdu *an_apdu;

	switch (event) {

	case MSC_REMOTE_EV_RX_GSUP:
		/*     [MSC-A---------------------]            [MSC-B---------------------]
		 *      msc_a --> msc_{i,t}_remote ----GSUP---> msc_a_remote --> msc_{i,t} ---BSSMAP--> [BSS]
		 *                                            ^you are here
		 */
		msc_a_remote_rx_gsup(msc_a, (const struct osmo_gsup_message*)data);
		return;

	/* For all remaining cases:
	 *     [MSC-A---------------------]            [MSC-B---------------------]
	 *      msc_a <-- msc_{i,t}_remote <---GSUP---- msc_a_remote <-- msc_{i,t} <--BSSMAP--- [BSS]
	 *                                               you are here^
	 */

	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_I,
						  OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST, an_apdu);
		return;

	case MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_I,
						  OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_REQUEST, an_apdu);
		return;

	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_I,
						  OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST, an_apdu);
		return;

	case MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T,
						  OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_RESULT, an_apdu);
		return;

	case MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T,
						  OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_ERROR, an_apdu);
		return;

	case MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T,
						  OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST, an_apdu);
		return;

	case MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST:
		an_apdu = data;
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T,
						  OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST, an_apdu);
		return;

	case MSC_A_EV_CN_CLOSE:
	case MSC_A_EV_MO_CLOSE:
		osmo_fsm_inst_state_chg(msc_a->c.fi, MSC_A_ST_RELEASING, 0, 0);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void msc_a_remote_fsm_releasing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, fi);
}

static void msc_a_remote_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_a *msc_a = msc_a_remote_priv(fi);
	if (msc_a->c.msub->role[MSC_ROLE_I])
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_I, OSMO_GSUP_MSGT_E_CLOSE, NULL);
	if (msc_a->c.msub->role[MSC_ROLE_T])
		msc_a_remote_msg_up_to_remote_msc(msc_a, MSC_ROLE_T, OSMO_GSUP_MSGT_E_CLOSE, NULL);
}

#define S(x)	(1 << (x))

/* FSM events are by definition compatible with msc_a_fsm. States could be a separate enum, but so that
 * msc_a_is_accepted() also works on remote msc_a, this FSM shares state numbers with the msc_a_fsm_states. */
static const struct osmo_fsm_state msc_a_remote_fsm_states[] = {
	/* Whichever MSC_A_ST would be the first for the real MSC-A implementation, a fresh FSM instance will start in
	 * state == 0 and we just need to be able to transition out of it. */
	[0] = {
		.name = "INIT-REMOTE",
		.out_state_mask = 0
			| S(MSC_A_ST_COMMUNICATING)
			| S(MSC_A_ST_RELEASING)
			,
	},
	[MSC_A_ST_COMMUNICATING] = {
		.name = "COMMUNICATING",
		.action = msc_a_remote_fsm_communicating,
		.in_event_mask = 0
			| S(MSC_REMOTE_EV_RX_GSUP)
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE)
			| S(MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE)
			| S(MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_CN_CLOSE)
			| S(MSC_A_EV_MO_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_RELEASING)
			,
	},
	[MSC_A_ST_RELEASING] = {
		.name = "RELEASING",
		.onenter = msc_a_remote_fsm_releasing_onenter,
	},
};

static struct osmo_fsm msc_a_remote_fsm = {
	.name = "msc_a_remote",
	.states = msc_a_remote_fsm_states,
	.num_states = ARRAY_SIZE(msc_a_remote_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_a_fsm_event_names,
	.cleanup = msc_a_remote_fsm_cleanup,
};

static __attribute__((constructor)) void msc_a_remote_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_a_remote_fsm) == 0);
}

struct msc_a *msc_a_remote_alloc(struct msub *msub, struct ran_infra *ran,
				 const uint8_t *remote_msc_name, size_t remote_msc_name_len)
{
	struct msc_a *msc_a;

	msub_role_alloc(msub, MSC_ROLE_A, &msc_a_remote_fsm, struct msc_a, ran);
	msc_a = msub_msc_a(msub);
	if (!msc_a) {
		LOG_MSUB(msub, LOGL_ERROR, "Error setting up MSC-A remote role\n");
		return NULL;
	}

	msc_a->c.remote_to = e_link_alloc(msub_net(msub)->gcm, msc_a->c.fi, remote_msc_name, remote_msc_name_len);
	if (!msc_a->c.remote_to) {
		LOG_MSC_A_REMOTE(msc_a, LOGL_ERROR, "Failed to set up E link\n");
		msc_a_release_cn(msc_a);
		return NULL;
	}

	msc_a_update_id(msc_a);

	/* Immediately get out of state 0. */
	osmo_fsm_inst_state_chg(msc_a->c.fi, MSC_A_ST_COMMUNICATING, 0, 0);

	return msc_a;
}
