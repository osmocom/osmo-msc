/* Implementation to manage two RTP streams that make up an MO or MT call leg's RTP forwarding. */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <osmocom/core/fsm.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_a.h>

#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>

#define LOG_CALL_LEG(cl, level, fmt, args...) \
	LOGPFSML(cl ? cl->fi : NULL, level, fmt, ##args)

static struct gsm_network *gsmnet = NULL;

enum call_leg_state {
	CALL_LEG_ST_ESTABLISHING,
	CALL_LEG_ST_ESTABLISHED,
	CALL_LEG_ST_RELEASING,
};

struct osmo_tdef g_mgw_tdefs[] = {
	{ .T=-2427, .default_val=4, .desc="MGCP response timeout" },
	{ .T=-2, .default_val=30, .desc="RTP stream establishing timeout" },
	{}
};

static const struct osmo_tdef_state_timeout call_leg_fsm_timeouts[32] = {
	[CALL_LEG_ST_ESTABLISHING] = { .T = -2 },
	[CALL_LEG_ST_RELEASING] = { .T = -2 },
};

#define call_leg_state_chg(cl, state) \
	osmo_tdef_fsm_inst_state_chg((cl)->fi, state, call_leg_fsm_timeouts, g_mgw_tdefs, 10)

static struct osmo_fsm call_leg_fsm;

void call_leg_init(struct gsm_network *net)
{
	gsmnet = net;
	OSMO_ASSERT( osmo_fsm_register(&call_leg_fsm) == 0 );
}

/* Allocate a call leg FSM instance as child of an arbitrary other FSM instance.
 * The call leg FSM dispatches events to its parent FSM instance on specific events:
 * - parent_event_term: dispatch this to the parent FI when the call leg terminates (call ended, either planned or by
 *   failure).
 * - parent_event_rtp_addr_available: one of the rtp_stream instances managed by the call leg has received an RTP
 *   address from the MGW. The struct rtp_stream instance is passed as data argument for the event dispatch.
 * - parent_event_rtp_complete: one of the rtp_stream instances entered the RTP_STREAM_ST_ESTABLISHED state.
 */
struct call_leg *call_leg_alloc(struct osmo_fsm_inst *parent_fi,
				uint32_t parent_event_term,
				uint32_t parent_event_rtp_addr_available,
				uint32_t parent_event_rtp_complete)
{
	struct call_leg *cl;
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&call_leg_fsm, parent_fi, parent_event_term);

	OSMO_ASSERT(fi);

	cl = talloc(fi, struct call_leg);
	OSMO_ASSERT(cl);
	fi->priv = cl;
	*cl = (struct call_leg){
		.fi = fi,
		.parent_event_rtp_addr_available = parent_event_rtp_addr_available,
		.parent_event_rtp_complete = parent_event_rtp_complete,
	};

	return cl;
}

void call_leg_reparent(struct call_leg *cl,
		       struct osmo_fsm_inst *new_parent_fi,
		       uint32_t parent_event_term,
		       uint32_t parent_event_rtp_addr_available,
		       uint32_t parent_event_rtp_complete)
{
	LOG_CALL_LEG(cl, LOGL_DEBUG, "Reparenting from parent %s to parent %s\n",
		     cl->fi->proc.parent->name, new_parent_fi->name);
	osmo_fsm_inst_change_parent(cl->fi, new_parent_fi, parent_event_term);
	talloc_steal(new_parent_fi, cl->fi);
	cl->parent_event_rtp_addr_available = parent_event_rtp_addr_available;
	cl->parent_event_rtp_complete = parent_event_rtp_complete;
}

static int call_leg_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct call_leg *cl = fi->priv;
	call_leg_release(cl);
	return 0;
}

void call_leg_release(struct call_leg *cl)
{
	if (!cl)
		return;
	if (cl->fi->state == CALL_LEG_ST_RELEASING)
		return;
	call_leg_state_chg(cl, CALL_LEG_ST_RELEASING);
}

static void call_leg_mgw_endpoint_gone(struct call_leg *cl)
{
	struct mgcp_client *mgcp_client;
	int i;

	/* Put MGCP client back into MGW pool */
	mgcp_client = osmo_mgcpc_ep_client(cl->mgw_endpoint);
	mgcp_client_pool_put(mgcp_client);

	cl->mgw_endpoint = NULL;
	for (i = 0; i < ARRAY_SIZE(cl->rtp); i++) {
		if (!cl->rtp[i])
			continue;
		cl->rtp[i]->ci = NULL;
	}
}

static void call_leg_fsm_establishing_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct call_leg *cl = fi->priv;
	struct rtp_stream *rtps;
	int i;
	bool established;

	switch (event) {

	case CALL_LEG_EV_RTP_STREAM_ESTABLISHED:
		/* An rtp_stream says it is established. If all are now established, change to state
		 * CALL_LEG_ST_ESTABLISHED. */
		established = true;
		for (i = 0; i < ARRAY_SIZE(cl->rtp); i++) {
			if (!rtp_stream_is_established(cl->rtp[i])) {
				established = false;
				break;
			}
		}
		if (!established)
			break;
		call_leg_state_chg(cl, CALL_LEG_ST_ESTABLISHED);
		break;

	case CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE:
		rtps = data;
		osmo_fsm_inst_dispatch(fi->proc.parent, cl->parent_event_rtp_addr_available, rtps);
		break;

	case CALL_LEG_EV_RTP_STREAM_GONE:
		call_leg_release(cl);
		break;

	case CALL_LEG_EV_MGW_ENDPOINT_GONE:
		call_leg_mgw_endpoint_gone(cl);
		call_leg_release(cl);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

void call_leg_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct call_leg *cl = fi->priv;
	osmo_fsm_inst_dispatch(fi->proc.parent, cl->parent_event_rtp_complete, cl);
}

void call_leg_fsm_releasing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* Trigger termination of children FSMs (rtp_stream(s)) before
	 * terminating ourselves, otherwise we are not able to receive
	 * CALL_LEG_EV_MGW_ENDPOINT_GONE from cl->mgw_endpoint (call_leg =>
	 * rtp_stream => mgw_endpoint), because osmo_fsm disabled dispatching
	 * events to an FSM in process of terminating. */
	osmo_fsm_inst_term_children(fi, OSMO_FSM_TERM_PARENT, NULL);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void call_leg_fsm_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct call_leg *cl = fi->priv;

	switch (event) {

	case CALL_LEG_EV_RTP_STREAM_GONE:
		/* We're already terminating, child RTP streams will also terminate, there is nothing left to do. */
		break;

	case CALL_LEG_EV_MGW_ENDPOINT_GONE:
		call_leg_mgw_endpoint_gone(cl);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static const struct value_string call_leg_fsm_event_names[] = {
	OSMO_VALUE_STRING(CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE),
	OSMO_VALUE_STRING(CALL_LEG_EV_RTP_STREAM_ESTABLISHED),
	OSMO_VALUE_STRING(CALL_LEG_EV_RTP_STREAM_GONE),
	OSMO_VALUE_STRING(CALL_LEG_EV_MGW_ENDPOINT_GONE),
	{}
};

#define S(x)	(1 << (x))

static const struct osmo_fsm_state call_leg_fsm_states[] = {
	[CALL_LEG_ST_ESTABLISHING] = {
		.name = "ESTABLISHING",
		.in_event_mask = 0
			| S(CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE)
			| S(CALL_LEG_EV_RTP_STREAM_ESTABLISHED)
			| S(CALL_LEG_EV_RTP_STREAM_GONE)
			| S(CALL_LEG_EV_MGW_ENDPOINT_GONE)
			,
		.out_state_mask = 0
			| S(CALL_LEG_ST_ESTABLISHED)
			| S(CALL_LEG_ST_RELEASING)
			,
		.action = call_leg_fsm_establishing_established,
	},
	[CALL_LEG_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.in_event_mask = 0
			| S(CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE)
			| S(CALL_LEG_EV_RTP_STREAM_ESTABLISHED)
			| S(CALL_LEG_EV_RTP_STREAM_GONE)
			| S(CALL_LEG_EV_MGW_ENDPOINT_GONE)
			,
		.out_state_mask = 0
			| S(CALL_LEG_ST_ESTABLISHING)
			| S(CALL_LEG_ST_RELEASING)
			,
		.onenter = call_leg_fsm_established_onenter,
		.action = call_leg_fsm_establishing_established, /* same action function as above */
	},
	[CALL_LEG_ST_RELEASING] = {
		.name = "RELEASING",
		.in_event_mask = 0
			| S(CALL_LEG_EV_RTP_STREAM_GONE)
			| S(CALL_LEG_EV_MGW_ENDPOINT_GONE)
			,
		.onenter = call_leg_fsm_releasing_onenter,
		.action = call_leg_fsm_releasing,
	},
};

static struct osmo_fsm call_leg_fsm = {
	.name = "call_leg",
	.states = call_leg_fsm_states,
	.num_states = ARRAY_SIZE(call_leg_fsm_states),
	.log_subsys = DCC,
	.event_names = call_leg_fsm_event_names,
	.timer_cb = call_leg_fsm_timer_cb,
};

const struct value_string rtp_direction_names[] = {
	OSMO_VALUE_STRING(RTP_TO_RAN),
	OSMO_VALUE_STRING(RTP_TO_CN),
	{}
};

int call_leg_ensure_rtp_alloc(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id, struct gsm_trans *for_trans)
{
	if (cl->rtp[dir])
		return 0;

	if (!cl->mgw_endpoint) {
		struct mgcp_client *mgcp_client = mgcp_client_pool_get(gsmnet->mgw.mgw_pool);
		if (!mgcp_client) {
			LOG_CALL_LEG(cl, LOGL_ERROR,
				     "cannot ensure MGW endpoint -- no MGW configured, check configuration!\n");
			return -ENODEV;
		}
		cl->mgw_endpoint = osmo_mgcpc_ep_alloc(cl->fi, CALL_LEG_EV_MGW_ENDPOINT_GONE,
						       mgcp_client, gsmnet->mgw.tdefs, cl->fi->id,
						       "%s", mgcp_client_rtpbridge_wildcard(mgcp_client));
	}
	if (!cl->mgw_endpoint) {
		LOG_CALL_LEG(cl, LOGL_ERROR, "failed to setup MGW endpoint\n");
		return -EIO;
	}

	cl->rtp[dir] = rtp_stream_alloc(cl->fi, CALL_LEG_EV_RTP_STREAM_GONE, CALL_LEG_EV_RTP_STREAM_ADDR_AVAILABLE,
					CALL_LEG_EV_RTP_STREAM_ESTABLISHED, dir, call_id, for_trans);
	OSMO_ASSERT(cl->rtp[dir]);
	return 0;
}

struct osmo_sockaddr_str *call_leg_local_ip(struct call_leg *cl, enum rtp_direction dir)
{
	struct rtp_stream *rtps;
	if (!cl)
		return NULL;
	rtps = cl->rtp[dir];
	if (!rtps)
		return NULL;
	if (!osmo_sockaddr_str_is_nonzero(&rtps->local))
		return NULL;
	return &rtps->local;
}

/* Make sure an MGW endpoint CI is set up for an RTP connection.
 * This is the one-stop for all to either completely set up a new endpoint connection, or to modify an existing one.
 * If not yet present, allocate the rtp_stream for the given direction.
 * Then, call rtp_stream_set_codecs() if codecs_if_known is non-NULL, and/or rtp_stream_set_remote_addr() if
 * remote_addr_if_known is non-NULL.
 * Finally make sure that a CRCX is sent out for this direction, if this has not already happened.
 * If the CRCX has already happened but new codec / remote_addr data was passed, call rtp_stream_commit() to trigger an
 * MDCX.
 */
int call_leg_ensure_ci(struct call_leg *cl, enum rtp_direction dir, uint32_t call_id, struct gsm_trans *for_trans,
		       const struct sdp_audio_codecs *codecs_if_known,
		       const struct osmo_sockaddr_str *remote_addr_if_known)
{
	if (call_leg_ensure_rtp_alloc(cl, dir, call_id, for_trans))
		return -EIO;
	rtp_stream_set_mode(cl->rtp[dir], cl->crcx_conn_mode[dir]);
	if (dir == RTP_TO_RAN && cl->ran_peer_supports_osmux) {
		cl->rtp[dir]->use_osmux = true;
		cl->rtp[dir]->remote_osmux_cid = -1; /* wildcard */
	}
	if (codecs_if_known)
		rtp_stream_set_codecs(cl->rtp[dir], codecs_if_known);
	if (remote_addr_if_known && osmo_sockaddr_str_is_nonzero(remote_addr_if_known))
		rtp_stream_set_remote_addr(cl->rtp[dir], remote_addr_if_known);
	return rtp_stream_ensure_ci(cl->rtp[dir], cl->mgw_endpoint);
}

int call_leg_local_bridge(struct call_leg *cl1, uint32_t call_id1, struct gsm_trans *trans1,
			  struct call_leg *cl2, uint32_t call_id2, struct gsm_trans *trans2)
{
	struct sdp_audio_codecs *cn_codecs = NULL;

	cl1->local_bridge = cl2;
	cl2->local_bridge = cl1;

	/* Marry the two CN sides of the call legs. Call establishment should have made all efforts for these to be
	 * compatible. However, for local bridging, the codecs and payload type numbers must be exactly identical on
	 * both sides. Both sides may so far have different payload type numbers or slightly differing codecs, but it
	 * will only work when the SDP on the RTP_TO_CN sides of the call legs talk the same payload type numbers.
	 * So, simply take the SDP from one RTP_TO_CN side, and overwrite the other RTP_TO_CN side's SDP with it.
	 * If all goes to plan, the codecs will be identical, or possibly the MGW will do a conversion like AMR-BE to
	 * AMR-OA. In the worst case, the other call leg cannot transcode, and the call fails -- because codec
	 * negotiation did not do a good enough job.
	 *
	 * Copy one call leg's CN config to the other:
	 *
	 *     call leg 1         call leg 2
	 *     ---MGW-ep-------   ---MGW-ep-------
	 *     RAN      CN        CN       RAN
	 *     AMR:112  AMR:112   AMR:96   AMR:96
	 *                 |
	 *                 +-------+
	 *                         |
	 *                         V
	 *     AMR:112  AMR:112   AMR:112  AMR:96
	 *                               ^MGW-endpoint converts payload type numbers between 112 and 96.
	 */
	if (cl1->rtp[RTP_TO_CN] && cl1->rtp[RTP_TO_CN]->codecs_known)
		cn_codecs = &cl1->rtp[RTP_TO_CN]->codecs;
	else if (cl2->rtp[RTP_TO_CN] && cl2->rtp[RTP_TO_CN]->codecs_known)
		cn_codecs = &cl2->rtp[RTP_TO_CN]->codecs;
	if (!cn_codecs) {
		LOG_CALL_LEG(cl1, LOGL_ERROR, "RAN-side CN stream codec is not known, not ready for bridging\n");
		LOG_CALL_LEG(cl2, LOGL_ERROR, "RAN-side CN stream codec is not known, not ready for bridging\n");
		return -EINVAL;
	}

	call_leg_ensure_ci(cl1, RTP_TO_CN, call_id1, trans1,
			   cn_codecs, &cl2->rtp[RTP_TO_CN]->local);
	call_leg_ensure_ci(cl2, RTP_TO_CN, call_id2, trans2,
			   cn_codecs, &cl1->rtp[RTP_TO_CN]->local);
	return 0;
}
