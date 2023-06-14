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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/cell_id_list.h>
#include <osmocom/msc/msc_vgcs.h>

static struct osmo_fsm ran_peer_fsm;

static __attribute__((constructor)) void ran_peer_init()
{
	OSMO_ASSERT( osmo_fsm_register(&ran_peer_fsm) == 0);
}

/* Allocate a RAN peer with FSM instance. To deallocate, call osmo_fsm_inst_term(ran_peer->fi). */
static struct ran_peer *ran_peer_alloc(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *peer_addr)
{
	struct ran_peer *rp;
	struct osmo_fsm_inst *fi;
	char *sccp_addr;
	char *pos;

	fi = osmo_fsm_inst_alloc(&ran_peer_fsm, sri, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	/* Unfortunately, osmo_sccp_inst_addr_name() returns "RI=SSN_PC,PC=0.24.1,SSN=BSSAP" but neither commas nor
	 * full-stops are allowed as FSM inst id. Make it "RI=SSN_PC:PC-0-24-1:SSN-BSSAP". */
	sccp_addr = osmo_sccp_inst_addr_name(sri->sccp, peer_addr);
	for (pos = sccp_addr; *pos; pos++) {
		if (*pos == ',')
			*pos = ':';
		else if (*pos == '.' || *pos == '=')
			*pos = '-';
	}
	osmo_fsm_inst_update_id_f(fi, "%s:%s", osmo_rat_type_name(sri->ran->type), sccp_addr);

	rp = talloc_zero(fi, struct ran_peer);
	OSMO_ASSERT(rp);
	*rp = (struct ran_peer){
		.sri = sri,
		.peer_addr = *peer_addr,
		.fi = fi,
	};
	INIT_LLIST_HEAD(&rp->cells_seen);
	fi->priv = rp;

	llist_add(&rp->entry, &sri->ran_peers);

	return rp;
}

struct ran_peer *ran_peer_find_or_create(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *peer_addr)
{
	struct ran_peer *rp = ran_peer_find_by_addr(sri, peer_addr);
	if (rp)
		return rp;
	return ran_peer_alloc(sri, peer_addr);
}

struct ran_peer *ran_peer_find_by_addr(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *peer_addr)
{
	struct ran_peer *rp;
	llist_for_each_entry(rp, &sri->ran_peers, entry) {
		if (osmo_sccp_addr_ri_cmp(peer_addr, &rp->peer_addr))
			continue;
		return rp;
	}
	return NULL;
}

void ran_peer_cells_seen_add(struct ran_peer *ran_peer, const struct gsm0808_cell_id *cid)
{
	if (!cell_id_list_add_cell(ran_peer, &ran_peer->cells_seen, cid))
		return;
	LOG_RAN_PEER_CAT(ran_peer, DPAG, LOGL_NOTICE, "Added seen cell to this RAN peer: %s\n",
			 gsm0808_cell_id_name(cid));
}

static const struct osmo_tdef_state_timeout ran_peer_fsm_timeouts[32] = {
	[RAN_PEER_ST_WAIT_RX_RESET_ACK] = { .T = -1 },
	[RAN_PEER_ST_DISCARDING] = { .T = -2 },
};

#define ran_peer_state_chg(RAN_PEER, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg((RAN_PEER)->fi, NEXT_STATE, ran_peer_fsm_timeouts, g_sccp_tdefs, 5)

void ran_peer_discard_all_conns(struct ran_peer *rp)
{
	struct ran_conn *conn, *next;

	ran_peer_for_each_ran_conn_safe(conn, next, rp) {
		/* Tell VGCS FSM that the connections have been cleared. */
		if (conn->vgcs.bss)
			vgcs_vbs_clear_cpl(conn->vgcs.bss, NULL);
		else if (conn->vgcs.cell)
			vgcs_vbs_clear_cpl_channel(conn->vgcs.cell, NULL);
		else ran_conn_discard(conn);
	}
}

static void ran_peer_update_osmux_support(struct ran_peer *rp, int supports_osmux)
{
	bool old_value = rp->remote_supports_osmux;

	switch (supports_osmux) {
	case 1:
		rp->remote_supports_osmux = true;
		break;
	case -1:
		rp->remote_supports_osmux = false;
		break;
	default:
		return;
	}

	if (old_value != rp->remote_supports_osmux)
		LOG_RAN_PEER(rp, LOGL_INFO, "BSC detected AoIP Osmux support changed: %d->%d\n",
		     old_value, rp->remote_supports_osmux);
}

/* Drop all SCCP connections for this ran_peer, respond with RESET ACKNOWLEDGE and move to READY state. */
static void ran_peer_rx_reset(struct ran_peer *rp, struct msgb* msg)
{
	struct msgb *reset_ack;

	ran_peer_discard_all_conns(rp);

	reset_ack = rp->sri->ran->sccp_ran_ops.make_reset_msg(rp->sri, SCCP_RAN_MSG_RESET_ACK);

	if (!reset_ack) {
		LOG_RAN_PEER(rp, LOGL_ERROR, "Failed to compose RESET ACKNOWLEDGE message\n");
		ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET);
		return;
	}

	if (sccp_ran_down_l2_cl(rp->sri, &rp->peer_addr, reset_ack)) {
		LOG_RAN_PEER(rp, LOGL_ERROR, "Failed to send RESET ACKNOWLEDGE message\n");
		ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET);
		msgb_free(reset_ack);
		return;
	}

	LOG_RAN_PEER(rp, LOGL_INFO, "Sent RESET ACKNOWLEDGE\n");

	/* sccp_ran_down_l2_cl() doesn't free msgb */
	msgb_free(reset_ack);

	ran_peer_state_chg(rp, RAN_PEER_ST_READY);
}

static void ran_peer_rx_reset_ack(struct ran_peer *rp, struct msgb* msg)
{
	ran_peer_state_chg(rp, RAN_PEER_ST_READY);
}

void ran_peer_reset(struct ran_peer *rp)
{
	struct msgb *reset;

	ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET_ACK);
	ran_peer_discard_all_conns(rp);

	reset = rp->sri->ran->sccp_ran_ops.make_reset_msg(rp->sri, SCCP_RAN_MSG_RESET);

	if (!reset) {
		LOG_RAN_PEER(rp, LOGL_ERROR, "Failed to compose RESET message\n");
		ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET);
		return;
	}

	if (sccp_ran_down_l2_cl(rp->sri, &rp->peer_addr, reset)) {
		LOG_RAN_PEER(rp, LOGL_ERROR, "Failed to send RESET message\n");
		ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET);
		return;
	}
}

void ran_peer_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ran_peer *rp = fi->priv;
	struct ran_peer_ev_ctx *ctx = data;
	struct msgb *msg = ctx->msg;
	enum reset_msg_type is_reset;
	int supports_osmux;

	switch (event) {
	case RAN_PEER_EV_MSG_UP_CL:
		is_reset = rp->sri->ran->sccp_ran_ops.is_reset_msg(rp->sri, fi, msg, &supports_osmux);
		ran_peer_update_osmux_support(rp, supports_osmux);
		switch (is_reset) {
		case SCCP_RAN_MSG_RESET:
			osmo_fsm_inst_dispatch(fi, RAN_PEER_EV_RX_RESET, msg);
			return;
		case SCCP_RAN_MSG_RESET_ACK:
			osmo_fsm_inst_dispatch(fi, RAN_PEER_EV_RX_RESET_ACK, msg);
			return;
		default:
			LOG_RAN_PEER(rp, LOGL_ERROR, "Unhandled ConnectionLess message received: %s\n",
				     rp->sri->ran->sccp_ran_ops.msg_name(rp->sri, msg));
			return;
		}

	default:
		LOG_RAN_PEER(rp, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&ran_peer_fsm, event));
		return;
	}
}

void clear_and_disconnect(struct ran_peer *rp, uint32_t conn_id)
{
	struct msgb *clear;
	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_CLEAR_COMMAND,
		.clear_command = {
			.gsm0808_cause = GSM0808_CAUSE_EQUIPMENT_FAILURE,
		},
	};

	clear = rp->sri->ran->ran_encode(rp->fi, &ran_enc_msg);
	if (!clear
	    || sccp_ran_down_l2_co(rp->sri, conn_id, clear))
		LOG_RAN_PEER(rp, LOGL_ERROR, "Cannot sent Clear command\n");

	sccp_ran_disconnect(rp->sri, conn_id, 0);
}

void ran_peer_st_wait_rx_reset(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ran_peer *rp = fi->priv;
	struct ran_peer_ev_ctx *ctx;
	struct msgb *msg;

	switch (event) {

	case RAN_PEER_EV_MSG_UP_CO:
	case RAN_PEER_EV_MSG_UP_CO_INITIAL:
		ctx = data;
		OSMO_ASSERT(ctx);

		if (rp->sri->ignore_missing_reset) {
			LOG_RAN_PEER(rp, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
				     " Accepting RAN peer implicitly (legacy compat)\n");
			ran_peer_state_chg(rp, RAN_PEER_ST_READY);
			osmo_fsm_inst_dispatch(rp->fi, event, data);
			return;
		}

		LOG_RAN_PEER(rp, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
			     " Disconnecting on incoming message, sending RESET to RAN peer.\n");
		/* No valid RESET procedure has happened here yet. Usually, we're expecting the RAN peer (BSC,
		 * RNC) to first send a RESET message before sending Connection Oriented messages. So if we're
		 * getting a CO message, likely we've just restarted or something. Send a RESET to the peer. */

		/* Make sure the MS / UE properly disconnects. */
		clear_and_disconnect(rp, ctx->conn_id);

		ran_peer_reset(rp);
		return;

	case RAN_PEER_EV_RX_RESET:
		msg = (struct msgb*)data;
		ran_peer_rx_reset(rp, msg);
		return;

	default:
		LOG_RAN_PEER(rp, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&ran_peer_fsm, event));
		return;
	}
}

void ran_peer_st_wait_rx_reset_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ran_peer *rp = fi->priv;
	struct ran_peer_ev_ctx *ctx;
	struct msgb *msg;

	switch (event) {

	case RAN_PEER_EV_RX_RESET_ACK:
		msg = (struct msgb*)data;
		ran_peer_rx_reset_ack(rp, msg);
		return;

	case RAN_PEER_EV_MSG_UP_CO:
	case RAN_PEER_EV_MSG_UP_CO_INITIAL:
		ctx = data;
		OSMO_ASSERT(ctx);
		LOG_RAN_PEER(rp, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
			     " Disconnecting on incoming message, sending RESET to RAN peer.\n");
		sccp_ran_disconnect(rp->sri, ctx->conn_id, 0);
		/* No valid RESET procedure has happened here yet. */
		ran_peer_reset(rp);
		return;

	case RAN_PEER_EV_RX_RESET:
		msg = (struct msgb*)data;
		ran_peer_rx_reset(rp, msg);
		return;

	default:
		LOG_RAN_PEER(rp, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&ran_peer_fsm, event));
		return;
	}
}

static struct ran_conn *new_incoming_conn(struct ran_peer *rp, uint32_t conn_id)
{
	struct gsm_network *net = rp->sri->user_data;
	struct msub *msub;
	struct msc_i *msc_i;
	struct msc_a *msc_a;
	struct ran_conn *ran_conn;

	msub = msub_alloc(net);
	OSMO_ASSERT(msub);
	msc_i = msc_i_alloc(msub, rp->sri->ran);
	OSMO_ASSERT(msc_i);

	ran_conn = ran_conn_create_incoming(rp, conn_id);
	if (!ran_conn) {
		LOG_RAN_PEER(rp, LOGL_ERROR, "Cannot allocate ran_conn\n");
		return NULL;
	}
	msc_i_set_ran_conn(msc_i, ran_conn);

	msc_a = msc_a_alloc(msub, rp->sri->ran);
	OSMO_ASSERT(msc_a);

	return msc_i->ran_conn;
}

void ran_peer_st_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ran_peer *rp = fi->priv;
	struct ran_peer_ev_ctx *ctx;
	struct ran_conn *conn;
	struct an_apdu an_apdu;
	struct msgb *msg;

	switch (event) {

	case RAN_PEER_EV_MSG_UP_CO_INITIAL:
		ctx = data;
		OSMO_ASSERT(ctx);
		OSMO_ASSERT(!ctx->conn);
		OSMO_ASSERT(ctx->msg);

		conn = new_incoming_conn(rp, ctx->conn_id);
		if (!conn)
			return;
		if (!conn->msc_role) {
			LOG_RAN_PEER(rp, LOGL_ERROR,
				     "Rx CO Initial message on conn that is not associated with any MSC role\n");
			return;
		}


		an_apdu = (struct an_apdu){
			.an_proto = rp->sri->ran->an_proto,
			.msg = ctx->msg,
		};

		osmo_fsm_inst_dispatch(conn->msc_role, MSC_EV_FROM_RAN_COMPLETE_LAYER_3, &an_apdu);
		return;

	case RAN_PEER_EV_MSG_UP_CO:
		ctx = data;
		OSMO_ASSERT(ctx);
		OSMO_ASSERT(ctx->conn);
		OSMO_ASSERT(ctx->msg);

		if (ctx->conn->msc_role) {
			/* "normal" A connection, dispatch to MSC-I or MSC-T */
			an_apdu = (struct an_apdu){
				.an_proto = rp->sri->ran->an_proto,
				.msg = ctx->msg,
			};
			osmo_fsm_inst_dispatch(ctx->conn->msc_role, MSC_EV_FROM_RAN_UP_L2, &an_apdu);
		} else if (ctx->conn->vgcs.bss) {
			/* VGCS call related */
			msc_a_rx_vgcs_bss(ctx->conn->vgcs.bss, ctx->conn, ctx->msg);
		} else if (ctx->conn->vgcs.cell) {
			/* VGCS channel related */
			msc_a_rx_vgcs_cell(ctx->conn->vgcs.cell, ctx->conn, ctx->msg);
		} else
			LOG_RAN_PEER(rp, LOGL_ERROR,
				     "Rx CO message on conn that is not associated with any MSC role\n");
		return;

	case RAN_PEER_EV_MSG_DOWN_CO_INITIAL:
		ctx = data;
		OSMO_ASSERT(ctx);
		OSMO_ASSERT(ctx->msg);
		sccp_ran_down_l2_co_initial(rp->sri, &rp->peer_addr, ctx->conn_id, ctx->msg);
		return;

	case RAN_PEER_EV_MSG_DOWN_CO:
		ctx = data;
		OSMO_ASSERT(ctx);
		OSMO_ASSERT(ctx->msg);
		sccp_ran_down_l2_co(rp->sri, ctx->conn_id, ctx->msg);
		return;

	case RAN_PEER_EV_MSG_DOWN_CL:
		OSMO_ASSERT(data);
		sccp_ran_down_l2_cl(rp->sri, &rp->peer_addr, (struct msgb*)data);
		return;

	case RAN_PEER_EV_RX_RESET:
		msg = (struct msgb*)data;
		ran_peer_rx_reset(rp, msg);
		return;

	default:
		LOG_RAN_PEER(rp, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&ran_peer_fsm, event));
		return;
	}
}

static int ran_peer_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ran_peer *rp = fi->priv;
	ran_peer_state_chg(rp, RAN_PEER_ST_WAIT_RX_RESET);
	return 0;
}

void ran_peer_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ran_peer *rp = fi->priv;
	ran_peer_discard_all_conns(rp);
	llist_del(&rp->entry);
}

static const struct value_string ran_peer_fsm_event_names[] = {
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_UP_CL),
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_UP_CO_INITIAL),
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_UP_CO),
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_DOWN_CL),
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_DOWN_CO_INITIAL),
	OSMO_VALUE_STRING(RAN_PEER_EV_MSG_DOWN_CO),
	OSMO_VALUE_STRING(RAN_PEER_EV_RX_RESET),
	OSMO_VALUE_STRING(RAN_PEER_EV_RX_RESET_ACK),
	OSMO_VALUE_STRING(RAN_PEER_EV_CONNECTION_SUCCESS),
	OSMO_VALUE_STRING(RAN_PEER_EV_CONNECTION_TIMEOUT),
	{}
};

#define S(x)	(1 << (x))

static const struct osmo_fsm_state ran_peer_fsm_states[] = {
	[RAN_PEER_ST_WAIT_RX_RESET] = {
		.name = "WAIT_RX_RESET",
		.action = ran_peer_st_wait_rx_reset,
		.in_event_mask = 0
			| S(RAN_PEER_EV_RX_RESET)
			| S(RAN_PEER_EV_MSG_UP_CO_INITIAL)
			| S(RAN_PEER_EV_MSG_UP_CO)
			| S(RAN_PEER_EV_CONNECTION_TIMEOUT)
			,
		.out_state_mask = 0
			| S(RAN_PEER_ST_WAIT_RX_RESET)
			| S(RAN_PEER_ST_WAIT_RX_RESET_ACK)
			| S(RAN_PEER_ST_READY)
			| S(RAN_PEER_ST_DISCARDING)
			,
	},
	[RAN_PEER_ST_WAIT_RX_RESET_ACK] = {
		.name = "WAIT_RX_RESET_ACK",
		.action = ran_peer_st_wait_rx_reset_ack,
		.in_event_mask = 0
			| S(RAN_PEER_EV_RX_RESET)
			| S(RAN_PEER_EV_RX_RESET_ACK)
			| S(RAN_PEER_EV_MSG_UP_CO_INITIAL)
			| S(RAN_PEER_EV_MSG_UP_CO)
			| S(RAN_PEER_EV_CONNECTION_TIMEOUT)
			,
		.out_state_mask = 0
			| S(RAN_PEER_ST_WAIT_RX_RESET)
			| S(RAN_PEER_ST_WAIT_RX_RESET_ACK)
			| S(RAN_PEER_ST_READY)
			| S(RAN_PEER_ST_DISCARDING)
			,
	},
	[RAN_PEER_ST_READY] = {
		.name = "READY",
		.action = ran_peer_st_ready,
		.in_event_mask = 0
			| S(RAN_PEER_EV_RX_RESET)
			| S(RAN_PEER_EV_MSG_UP_CO_INITIAL)
			| S(RAN_PEER_EV_MSG_UP_CO)
			| S(RAN_PEER_EV_MSG_DOWN_CO_INITIAL)
			| S(RAN_PEER_EV_MSG_DOWN_CO)
			| S(RAN_PEER_EV_MSG_DOWN_CL)
			,
		.out_state_mask = 0
			| S(RAN_PEER_ST_WAIT_RX_RESET)
			| S(RAN_PEER_ST_WAIT_RX_RESET_ACK)
			| S(RAN_PEER_ST_READY)
			| S(RAN_PEER_ST_DISCARDING)
			,
	},
	[RAN_PEER_ST_DISCARDING] = {
		.name = "DISCARDING",
	},
};

static struct osmo_fsm ran_peer_fsm = {
	.name = "ran_peer",
	.states = ran_peer_fsm_states,
	.num_states = ARRAY_SIZE(ran_peer_fsm_states),
	.log_subsys = DRR,
	.event_names = ran_peer_fsm_event_names,
	.timer_cb = ran_peer_fsm_timer_cb,
	.cleanup = ran_peer_fsm_cleanup,
	.allstate_action = ran_peer_allstate_action,
	.allstate_event_mask = 0
		| S(RAN_PEER_EV_MSG_UP_CL)
		,
};

int ran_peer_up_l2(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *calling_addr, bool co, uint32_t conn_id,
		   struct msgb *l2)
{
	struct ran_peer *ran_peer = NULL;
	uint32_t event;
	struct ran_peer_ev_ctx ctx = {
		.conn_id = conn_id,
		.msg = l2,
	};

	if (co) {
		struct ran_conn *conn;
		llist_for_each_entry(conn, &sri->ran_conns, entry) {
			if (conn->sccp_conn_id == conn_id) {
				ran_peer = conn->ran_peer;
				ctx.conn = conn;
				break;
			}
		}

		if (ran_peer && calling_addr) {
			LOG_SCCP_RAN_CO(sri, calling_addr, conn_id, LOGL_ERROR,
					"Connection-Oriented Initial message for already existing conn_id."
					" Dropping message.\n");
			return -EINVAL;
		}

		if (!ran_peer && !calling_addr) {
			LOG_SCCP_RAN_CO(sri, calling_addr, conn_id, LOGL_ERROR,
					"Connection-Oriented non-Initial message for unknown conn_id %u."
					" Dropping message.\n", conn_id);
			return -EINVAL;
		}
	}

	if (calling_addr) {
		ran_peer = ran_peer_find_or_create(sri, calling_addr);
		if (!ran_peer) {
			LOG_SCCP_RAN_CL(sri, calling_addr, LOGL_ERROR, "Cannot register RAN peer\n");
			return -EIO;
		}
	}

	OSMO_ASSERT(ran_peer && ran_peer->fi);

	if (co)
		event = calling_addr ? RAN_PEER_EV_MSG_UP_CO_INITIAL : RAN_PEER_EV_MSG_UP_CO;
	else
		event = RAN_PEER_EV_MSG_UP_CL;

	return osmo_fsm_inst_dispatch(ran_peer->fi, event, &ctx);
}

void ran_peer_disconnect(struct sccp_ran_inst *sri, uint32_t conn_id)
{
	struct ran_conn *conn;
	llist_for_each_entry(conn, &sri->ran_conns, entry) {
		if (conn->sccp_conn_id == conn_id) {
			ran_conn_discard(conn);
			return;
		}
	}
}

struct ran_peer *ran_peer_find_by_cell_id(struct sccp_ran_inst *sri, const struct gsm0808_cell_id *cid,
					  bool expecting_single_match)
{
	struct ran_peer *rp;
	struct ran_peer *found = NULL;

	llist_for_each_entry(rp, &sri->ran_peers, entry) {
		if (cell_id_list_find(&rp->cells_seen, cid, 0, false)) {
			if (!expecting_single_match)
				return rp;
			/* Otherwise continue iterating and log errors for multiple matches... */
			if (found) {
				LOG_RAN_PEER(found, LOGL_ERROR, "Cell appears in more than one RAN peer:"
					     " %s also appears in %s\n",
					     gsm0808_cell_id_name(cid), rp->fi->id);
			} else
				found = rp;
		}
	}
	return found;
}

int ran_peers_down_paging(struct sccp_ran_inst *sri, enum CELL_IDENT page_where, struct vlr_subscr *vsub,
			  enum paging_cause cause)
{
	struct ran_peer *rp;
	int ret = 0;
	struct gsm0808_cell_id page_id;
	gsm0808_cell_id_from_cgi(&page_id, page_where, &vsub->cgi);

	switch (page_where) {
	case CELL_IDENT_NO_CELL:
		LOG_SCCP_RAN_CAT(sri, DPAG, LOGL_ERROR, "Asked to page on NO_CELL, which doesn't make sense.\n");
		return 0;

	case CELL_IDENT_UTRAN_PLMN_LAC_RNC:
	case CELL_IDENT_UTRAN_RNC:
	case CELL_IDENT_UTRAN_LAC_RNC:
		LOG_SCCP_RAN_CAT(sri, DPAG, LOGL_ERROR, "Don't know how to page on %s\n",
				 gsm0808_cell_id_name(&page_id));
		return 0;

	default:
		break;
	};

	llist_for_each_entry(rp, &sri->ran_peers, entry) {
		ret += ran_peer_down_paging(rp, &page_id, vsub, cause);
	}

	if (!ret)
		LOG_SCCP_RAN_CAT(sri, DPAG, LOGL_ERROR, "Paging failed, no RAN peers found for %s\n",
				 gsm0808_cell_id_name(&page_id));
	return ret;
}

/* If the given vsub->cgi matches this ran_peer with respect to page_where, page and return 1.
 * Otherwise return 0. (Return value: number of pagings sent) */
int ran_peer_down_paging(struct ran_peer *rp, const struct gsm0808_cell_id *page_id, struct vlr_subscr *vsub,
			 enum paging_cause cause)
{
	struct msgb *l2;

	/* There are also the RAN peers that are configured in the neighbor ident for Handover, but if those aren't
	 * connected, then we can't Page there. */
	if (!cell_id_list_find(&rp->cells_seen, page_id, 0, false))
		return 0;

	LOG_RAN_PEER_CAT(rp, DPAG, LOGL_DEBUG, "Paging for %s on %s\n", vlr_subscr_name(vsub),
			 gsm0808_cell_id_name(page_id));
	l2 = rp->sri->ran->sccp_ran_ops.make_paging_msg(rp->sri, page_id, vsub->imsi, vsub->tmsi, cause);
	if (osmo_fsm_inst_dispatch(rp->fi, RAN_PEER_EV_MSG_DOWN_CL, l2)) {
		/* Not allowed to send messages, the peer is not properly connected yet/anymore */
		LOG_RAN_PEER_CAT(rp, DPAG, LOGL_ERROR,
				 "Paging for %s matched this RAN peer, but emitting a Paging failed\n",
				 gsm0808_cell_id_name(page_id));
		msgb_free(l2);
		return 0;
	}

	/* The RAN_PEER_EV_MSG_DOWN_CL handler calls sccp_ran_down_l2_cl(),
	 * which doesn't free msgb. We have to do this ourselves. */
	msgb_free(l2);

	return 1;
}
