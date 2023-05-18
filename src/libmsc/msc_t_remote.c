/* The MSC-T role implementation variant that forwards requests to/from a remote MSC. */
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
#include <osmocom/msc/msc_t_remote.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/e_link.h>

static struct osmo_fsm msc_t_remote_fsm;

static struct msc_t *msc_t_remote_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_t_remote_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

/* The idea is that this msc_t role is event-compatible to the "real" msc_t.c FSM, but instead of acting on the events
 * directly, it forwards the events to a remote MSC-T role, via E-over-GSUP.
 *
 *     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a --> msc_t_remote ----GSUP---> msc_a_remote --> msc_t ---BSSMAP--> [BSS]
 *                 you are here^
 */
static int msc_t_remote_msg_down_to_remote_msc(struct msc_t *msc_t,
					       enum osmo_gsup_message_type message_type,
					       struct an_apdu *an_apdu)
{
	struct osmo_gsup_message m;
	struct e_link *e = msc_t->c.remote_to;

	if (!e) {
		LOG_MSC_T_REMOTE(msc_t, LOGL_ERROR, "No E link to remote MSC, cannot send AN-APDU\n");
		return -1;
	}

	if (e_prep_gsup_msg(e, &m)) {
		LOG_MSC_T_REMOTE(msc_t, LOGL_ERROR, "Error composing E-interface GSUP message\n");
		return -1;
	}
	m.message_type = message_type;
	if (an_apdu) {
		if (gsup_msg_assign_an_apdu(&m, an_apdu)) {
			LOG_MSC_T_REMOTE(msc_t, LOGL_ERROR, "Error composing E-interface GSUP message\n");
			return -1;
		}
	}

	return e_tx(e, &m);
}

/*     [MSC-A-----------------]            [MSC-B-----------------]
 *      msc_a <-- msc_t_remote <---GSUP---- msc_a_remote <-- msc_t <--BSSMAP--- [BSS]
 *                 you are here^
 */
static int msc_t_remote_rx_gsup(struct msc_t *msc_t, const struct osmo_gsup_message *gsup_msg)
{
	uint32_t event;
	struct an_apdu an_apdu;
	int rc;

	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_E_PROCESS_ACCESS_SIGNALLING_REQUEST:
		event = MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_ERROR:
	case OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_RESULT:
		event = MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE;
		break;

	case OSMO_GSUP_MSGT_E_SEND_END_SIGNAL_REQUEST:
		event = MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST;
		break;

	case OSMO_GSUP_MSGT_E_CLOSE:
	case OSMO_GSUP_MSGT_E_ABORT:
	case OSMO_GSUP_MSGT_E_ROUTING_ERROR:
		msc_t_clear(msc_t);
		return 0;

	default:
		LOG_MSC_T_REMOTE(msc_t, LOGL_ERROR, "Unhandled GSUP message type: %s\n",
				 osmo_gsup_message_type_name(gsup_msg->message_type));
		return -1;
	};

	/*     [MSC-A-----------------]            [MSC-B-----------------]
	 *      msc_a <-- msc_t_remote <---GSUP---- msc_a_remote <-- msc_t <--BSSMAP--- [BSS]
	 *              ^you are here
	 */
	gsup_msg_to_an_apdu(&an_apdu, gsup_msg);
	rc = msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, event, &an_apdu);
	if (an_apdu.msg)
		msgb_free(an_apdu.msg);
	return rc;
}

static void msc_t_remote_fsm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_t *msc_t = msc_t_remote_priv(fi);
	struct an_apdu *an_apdu;

	switch (event) {

	case MSC_REMOTE_EV_RX_GSUP:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a <-- msc_t_remote <---GSUP---- msc_a_remote <-- msc_t <--BSSMAP--- [BSS]
		 *                 you are here^
		 */
		msc_t_remote_rx_gsup(msc_t, (const struct osmo_gsup_message*)data);
		return;

	case MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_t_remote ----GSUP---> going to create an msc_t if the request succeeds
		 *              ^you are here
		 */
		an_apdu = data;
		msc_t_remote_msg_down_to_remote_msc(msc_t, OSMO_GSUP_MSGT_E_PREPARE_HANDOVER_REQUEST, an_apdu);
		return;

	case MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST:
		/*     [MSC-A-----------------]            [MSC-B-----------------]
		 *      msc_a --> msc_t_remote ----GSUP---> msc_a_remote --> msc_t ---BSSMAP--> [BSS]
		 *              ^you are here
		 */
		an_apdu = data;
		msc_t_remote_msg_down_to_remote_msc(msc_t, OSMO_GSUP_MSGT_E_FORWARD_ACCESS_SIGNALLING_REQUEST, an_apdu);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void msc_t_remote_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_t *msc_t = msc_t_remote_priv(fi);
	if (msc_t->c.remote_to)
		msc_t_remote_msg_down_to_remote_msc(msc_t, OSMO_GSUP_MSGT_E_CLOSE, NULL);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_t_remote_fsm_states[] = {
	/* An FSM instance always starts in state 0. Define one just to be able to state_chg out of it. Root reason is
	 * that we're using MSC_T_ST_* enum values from msc_t.c, but don't need the first
	 * MSC_T_ST_PENDING_FIRST_CO_INITIAL_MSG. */
	[0] = {
		.name = "0",
		.out_state_mask = 0
			| S(MSC_T_ST_WAIT_HO_COMPLETE)
			,
	},
	[MSC_T_ST_WAIT_HO_COMPLETE] = {
		.name = "WAIT_HO_COMPLETE",
		.action = msc_t_remote_fsm_ready,
		.in_event_mask = 0
			| S(MSC_REMOTE_EV_RX_GSUP)
			| S(MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST)
			| S(MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST)
			,
	},
};

static struct osmo_fsm msc_t_remote_fsm = {
	.name = "msc_t_remote",
	.states = msc_t_remote_fsm_states,
	.num_states = ARRAY_SIZE(msc_t_remote_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_t_fsm_event_names,
	.cleanup = msc_t_remote_fsm_cleanup,
};

static __attribute__((constructor)) void msc_t_remote_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_t_remote_fsm) == 0);
}

struct msc_t *msc_t_remote_alloc(struct msub *msub, struct ran_infra *ran,
				 const uint8_t *remote_msc_name, size_t remote_msc_name_len)
{
	struct msc_t *msc_t;

	msub_role_alloc(msub, MSC_ROLE_T, &msc_t_remote_fsm, struct msc_t, ran);
	msc_t = msub_msc_t(msub);
	if (!msc_t)
		return NULL;

	msc_t->c.remote_to = e_link_alloc(msub_net(msub)->gcm, msc_t->c.fi, remote_msc_name, remote_msc_name_len);
	if (!msc_t->c.remote_to) {
		LOG_MSC_T_REMOTE(msc_t, LOGL_ERROR, "Failed to set up E link over GSUP to remote MSC\n");
		msc_t_clear(msc_t);
		return NULL;
	}

	osmo_fsm_inst_state_chg(msc_t->c.fi, MSC_T_ST_WAIT_HO_COMPLETE, 0, 0);
	return msc_t;
}
