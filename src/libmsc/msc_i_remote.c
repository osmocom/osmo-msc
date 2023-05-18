/* The MSC-I role implementation variant that forwards requests to/from a remote MSC. */
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

#include <osmocom/core/fsm.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_i_remote.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/e_link.h>

static struct osmo_fsm msc_i_remote_fsm;

static struct msc_i *msc_i_remote_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_i_remote_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

/* The idea is that this msc_i role is event-compatible to the "real" msc_i.c FSM, but instead of acting on the events
 * directly, it forwards the events to a remote MSC-I role, via E-over-GSUP.
 *
 *     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
 *                 you are here^
 */
static int msc_i_remote_msg_down_to_remote_msc(struct msc_i *msc_i,
					       enum osmo_gsup_message_type message_type,
					       struct an_apdu *an_apdu)
{
	struct osmo_gsup_message m;
	struct e_link *e = msc_i->c.remote_to;

	if (!e) {
		LOG_MSC_I_REMOTE(msc_i, LOGL_ERROR, "No E link to remote MSC, cannot send AN-APDU\n");
		return -1;
	}

	if (e_prep_gsup_msg(e, &m)) {
		LOG_MSC_I_REMOTE(msc_i, LOGL_ERROR, "Error composing E-interface GSUP message\n");
		return -1;
	}
	m.message_type = message_type;
	if (an_apdu) {
		if (gsup_msg_assign_an_apdu(&m, an_apdu)) {
			LOG_MSC_I_REMOTE(msc_i, LOGL_ERROR, "Error composing E-interface GSUP message\n");
			return -1;
		}
	}

	return e_tx(e, &m);
}

/*     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a <-- msc_i_remote <---GSUP---- msc_a_remote <-- msc_i <--BSSMAP--- [BSS]
 *                 you are here^
 */
static int msc_i_remote_rx_gsup(struct msc_i *msc_i, const struct osmo_gsup_message *gsup_msg)
{
	uint32_t event;
	struct an_apdu an_apdu;
	int rc;

	/* MSC_A_EV_FROM_I_COMPLETE_LAYER_3 will never occur with a remote MSC-I, since all Complete Layer 3 will happen
	 * between a local MSC-A and local MSC-I roles. Only after an inter-MSC Handover will there possibly exist a
	 * remote MSC-I, which is long after Complete Layer 3. */

	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_REQUEST:
		event = MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST:
		event = MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_CLOSE:
	case OSMO_GSUP_MSGT_E_ABORT:
	case OSMO_GSUP_MSGT_E_ROUTING_ERROR:
		msc_i_clear(msc_i);
		return 0;

	default:
		LOG_MSC_I_REMOTE(msc_i, LOGL_ERROR, "Unhandled GSUP message type: %s\n",
				 osmo_gsup_message_type_name(gsup_msg->message_type));
		return -1;
	};

	/*     [MSC-A-----------------]            [MSC-B-----------------]
	 *      msc_a <-- msc_i_remote <---GSUP---- msc_a_remote <-- msc_i <--BSSMAP--- [BSS]
	 *              ^you are here
	 */
	gsup_msg_to_an_apdu(&an_apdu, gsup_msg);
	rc = msub_role_dispatch(msc_i->c.msub, MSC_ROLE_A, event, &an_apdu);
	if (an_apdu.msg)
		msgb_free(an_apdu.msg);
	return rc;
}

static void msc_i_remote_fsm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_i *msc_i = msc_i_remote_priv(fi);
	struct an_apdu *an_apdu;

	switch (event) {

	case MSC_REMOTE_EV_RX_GSUP:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a <-- msc_i_remote <---GSUP---- msc_a_remote <-- msc_i <--BSSMAP--- [BSS]
		 *                 you are here^
		 */
		msc_i_remote_rx_gsup(msc_i, (const struct osmo_gsup_message*)data);
		return;

	case MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
		 *              ^you are here
		 */
		an_apdu = data;
		msc_i_remote_msg_down_to_remote_msc(msc_i, OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST, an_apdu);
		return;

	case MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
		 *              ^you are here
		 */
		an_apdu = data;
		msc_i_remote_msg_down_to_remote_msc(msc_i, OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_RESULT, an_apdu);
		return;

	case MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
		 *              ^you are here
		 */
		an_apdu = data;
		msc_i_remote_msg_down_to_remote_msc(msc_i, OSMO_GSUP_MSGT_E_PREPARE_SUBSEQUENT_HANDOVER_ERROR, an_apdu);
		return;

	case MSC_I_EV_FROM_A_SEND_END_SIGNAL_RESPONSE:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_i_remote ----GSUP---> msc_a_remote --> msc_i ---BSSMAP--> [BSS]
		 *              ^you are here
		 */
		an_apdu = data;
		msc_i_remote_msg_down_to_remote_msc(msc_i, OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_RESULT, an_apdu);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void msc_i_remote_fsm_clearing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, fi);
}

static void msc_i_remote_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_i *msc_i = msc_i_remote_priv(fi);
	msc_i_remote_msg_down_to_remote_msc(msc_i, OSMO_GSUP_MSGT_E_CLOSE, NULL);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_i_remote_fsm_states[] = {
	[MSC_I_ST_READY] = {
		.name = "READY",
		.action = msc_i_remote_fsm_ready,
		.in_event_mask = 0
			| S(MSC_REMOTE_EV_RX_GSUP)
			| S(MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT)
			| S(MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR)
			,
		.out_state_mask = 0
			| S(MSC_I_ST_CLEARING)
			,
	},
	[MSC_I_ST_CLEARING] = {
		.name = "CLEARING",
		.onenter = msc_i_remote_fsm_clearing_onenter,
	},
};

static struct osmo_fsm msc_i_remote_fsm = {
	.name = "msc_i_remote",
	.states = msc_i_remote_fsm_states,
	.num_states = ARRAY_SIZE(msc_i_remote_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_i_fsm_event_names,
	.cleanup = msc_i_remote_fsm_cleanup,
};

static __attribute__((constructor)) void msc_i_remote_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_i_remote_fsm) == 0);
}

struct msc_i *msc_i_remote_alloc(struct msub *msub, struct ran_infra *ran, struct e_link *e)
{
	struct msc_i *msc_i;

	msub_role_alloc(msub, MSC_ROLE_I, &msc_i_remote_fsm, struct msc_i, ran);
	msc_i = msub_msc_i(msub);
	if (!msc_i)
		return NULL;

	e_link_assign(e, msc_i->c.fi);
	if (!msc_i->c.remote_to) {
		LOG_MSC_I_REMOTE(msc_i, LOGL_ERROR, "Failed to set up E link over GSUP to remote MSC\n");
		msc_i_clear(msc_i);
		return NULL;
	}

	return msc_i;
}
