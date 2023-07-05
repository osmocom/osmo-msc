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

#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/codec_mapping.h>

#define LOG_RTPS(rtps, level, fmt, args...) \
	LOGPFSML(rtps->fi, level, fmt, ##args)

enum rtp_stream_event {
	RTP_STREAM_EV_CRCX_OK,
	RTP_STREAM_EV_CRCX_FAIL,
	RTP_STREAM_EV_MDCX_OK,
	RTP_STREAM_EV_MDCX_FAIL,
};

enum rtp_stream_state {
	RTP_STREAM_ST_UNINITIALIZED,
	RTP_STREAM_ST_ESTABLISHING,
	RTP_STREAM_ST_ESTABLISHED,
	RTP_STREAM_ST_DISCARDING,
};

static struct osmo_fsm rtp_stream_fsm;

static struct osmo_tdef_state_timeout rtp_stream_fsm_timeouts[32] = {
	[RTP_STREAM_ST_ESTABLISHING] = { .T = -2 },
};

#define rtp_stream_state_chg(rtps, state) \
	osmo_tdef_fsm_inst_state_chg((rtps)->fi, state, rtp_stream_fsm_timeouts, g_mgw_tdefs, 5)

static __attribute__((constructor)) void rtp_stream_init()
{
	OSMO_ASSERT(osmo_fsm_register(&rtp_stream_fsm) == 0);
}

void rtp_stream_update_id(struct rtp_stream *rtps)
{
	char buf[256];
	char *p;
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	OSMO_STRBUF_PRINTF(sb, "%s", rtps->fi->proc.parent->id);
	if (rtps->for_trans)
		OSMO_STRBUF_PRINTF(sb, ":trans-%u", rtps->for_trans->transaction_id);
	OSMO_STRBUF_PRINTF(sb, ":call-%u", rtps->call_id);
	OSMO_STRBUF_PRINTF(sb, ":%s", rtp_direction_name(rtps->dir));
	if (!osmo_mgcpc_ep_ci_id(rtps->ci)) {
		OSMO_STRBUF_PRINTF(sb, ":no-CI");
	} else {
		OSMO_STRBUF_PRINTF(sb, ":CI-%s", osmo_mgcpc_ep_ci_id(rtps->ci));
		if (!osmo_sockaddr_str_is_nonzero(&rtps->remote))
			OSMO_STRBUF_PRINTF(sb, ":no-remote-port");
		else if (!rtps->remote_sent_to_mgw)
			OSMO_STRBUF_PRINTF(sb, ":remote-port-not-sent");
		if (!rtps->codecs_known)
			OSMO_STRBUF_PRINTF(sb, ":no-codecs");
		else if (!rtps->codecs_sent_to_mgw)
			OSMO_STRBUF_PRINTF(sb, ":codecs-not-sent");
		if (!rtps->codecs_sent_to_mgw)
			OSMO_STRBUF_PRINTF(sb, ":mode-not-sent");
		if (rtps->use_osmux) {
			if (rtps->remote_osmux_cid < 0)
				OSMO_STRBUF_PRINTF(sb, ":no-remote-osmux-cid");
			else if (!rtps->remote_osmux_cid_sent_to_mgw)
				OSMO_STRBUF_PRINTF(sb, ":remote-osmux-cid-not-sent");
		}
	}
	if (osmo_sockaddr_str_is_nonzero(&rtps->local))
		OSMO_STRBUF_PRINTF(sb, ":local-%s-%u", rtps->local.ip, rtps->local.port);
	if (osmo_sockaddr_str_is_nonzero(&rtps->remote))
		OSMO_STRBUF_PRINTF(sb, ":remote-%s-%u", rtps->remote.ip, rtps->remote.port);
	if (rtps->use_osmux)
		OSMO_STRBUF_PRINTF(sb, ":osmux-%d-%d", rtps->local_osmux_cid, rtps->remote_osmux_cid);

	/* Replace any dots in the IP address, dots not allowed as FSM instance name */
	for (p = buf; *p; p++)
		if (*p == '.')
			*p = '-';

	osmo_fsm_inst_update_id_f(rtps->fi, "%s", buf);
}

/* Allocate RTP stream under a call leg. This is one RTP connection from some remote entity with address and port to a
 * local RTP address and port. call_id is stored for sending in MGCP transactions and as logging context. for_trans is
 * optional, merely stored for reference by callers, and appears as log context if not NULL. */
struct rtp_stream *rtp_stream_alloc(struct osmo_fsm_inst *parent_fi, uint32_t event_gone, uint32_t event_avail,
				    uint32_t event_estab, enum rtp_direction dir, uint32_t call_id,
				    struct gsm_trans *for_trans)
{
	struct osmo_fsm_inst *fi;
	struct rtp_stream *rtps;

	fi = osmo_fsm_inst_alloc_child(&rtp_stream_fsm, parent_fi, event_gone);
	OSMO_ASSERT(fi);

	rtps = talloc(fi, struct rtp_stream);
	OSMO_ASSERT(rtps);
	fi->priv = rtps;
	*rtps = (struct rtp_stream){
		.fi = fi,
		.event_avail = event_avail,
		.event_estab = event_estab,
		.call_id = call_id,
		.for_trans = for_trans,
		.dir = dir,
		.local_osmux_cid = -2,
		.remote_osmux_cid = -2,
		.crcx_conn_mode = MGCP_CONN_NONE, /* Use connection's default mode. */
	};

	rtp_stream_update_id(rtps);

	return rtps;
}

static void check_established(struct rtp_stream *rtps)
{
	if (rtps->fi->state != RTP_STREAM_ST_ESTABLISHED
	    && osmo_sockaddr_str_is_nonzero(&rtps->local)
	    && osmo_sockaddr_str_is_nonzero(&rtps->remote)
	    && rtps->remote_sent_to_mgw
	    && (!rtps->use_osmux || rtps->remote_osmux_cid_sent_to_mgw)
	    && rtps->codecs_known)
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHED);
}

static void rtp_stream_fsm_establishing_established(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct rtp_stream *rtps = fi->priv;
	const struct mgcp_conn_peer *crcx_info;
	switch (event) {
	case RTP_STREAM_EV_CRCX_OK:
		crcx_info = osmo_mgcpc_ep_ci_get_rtp_info(rtps->ci);
		if (!crcx_info) {
			LOG_RTPS(rtps, LOGL_ERROR, "osmo_mgcpc_ep_ci_get_rtp_info() has "
				 "failed, ignoring %s\n", osmo_fsm_event_name(fi->fsm, event));
			return;
		}

		osmo_sockaddr_str_from_str(&rtps->local, crcx_info->addr, crcx_info->port);
		if (rtps->use_osmux != crcx_info->x_osmo_osmux_use) {
			LOG_RTPS(rtps, LOGL_ERROR, "Osmux usage request and response don't match: %d vs %d",
				 rtps->use_osmux, crcx_info->x_osmo_osmux_use);
			/* TODO: proper failure path */
			OSMO_ASSERT(rtps->use_osmux != crcx_info->x_osmo_osmux_use);
		}
		if (crcx_info->x_osmo_osmux_use)
			rtps->local_osmux_cid = crcx_info->x_osmo_osmux_cid;
		rtp_stream_update_id(rtps);
		osmo_fsm_inst_dispatch(fi->proc.parent, rtps->event_avail, rtps);
		check_established(rtps);

		if ((!rtps->remote_sent_to_mgw || !rtps->codecs_sent_to_mgw || !rtps->mode_sent_to_mgw)
		    && osmo_sockaddr_str_is_nonzero(&rtps->remote)
		    && (!rtps->use_osmux || rtps->remote_osmux_cid_sent_to_mgw)
		    && rtps->codecs_known) {
			LOG_RTPS(rtps, LOGL_DEBUG,
				 "local ip:port set;%s%s%s%s triggering MDCX to send the new settings\n",
				 (!rtps->remote_sent_to_mgw) ? " remote ip:port not yet sent," : "",
				 (!rtps->codecs_sent_to_mgw) ? " codecs not yet sent," : "",
				 (!rtps->mode_sent_to_mgw) ? " mode not yet sent," : "",
				 (rtps->use_osmux && !rtps->remote_osmux_cid_sent_to_mgw) ? "Osmux CID not yet sent,": "");
			rtp_stream_do_mdcx(rtps);
		}
		return;

	case RTP_STREAM_EV_MDCX_OK:
		rtp_stream_update_id(rtps);
		check_established(rtps);
		return;

	case RTP_STREAM_EV_CRCX_FAIL:
	case RTP_STREAM_EV_MDCX_FAIL:
		rtps->remote_sent_to_mgw = false;
		rtps->codecs_sent_to_mgw = false;
		rtps->mode_sent_to_mgw = false;
		rtps->remote_osmux_cid_sent_to_mgw = false;
		rtp_stream_update_id(rtps);
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_DISCARDING);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

void rtp_stream_fsm_established_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct rtp_stream *rtps = fi->priv;
	osmo_fsm_inst_dispatch(fi->proc.parent, rtps->event_estab, rtps);
}

static int rtp_stream_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct rtp_stream *rtps = fi->priv;
	rtp_stream_state_chg(rtps, RTP_STREAM_ST_DISCARDING);
	return 0;
}

static void rtp_stream_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct rtp_stream *rtps = fi->priv;
	if (rtps->ci) {
		osmo_mgcpc_ep_cancel_notify(osmo_mgcpc_ep_ci_ep(rtps->ci), fi);
		osmo_mgcpc_ep_ci_dlcx(rtps->ci);
		rtps->ci = NULL;
	}
}

void rtp_stream_fsm_discarding_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct value_string rtp_stream_fsm_event_names[] = {
	OSMO_VALUE_STRING(RTP_STREAM_EV_CRCX_OK),
	OSMO_VALUE_STRING(RTP_STREAM_EV_CRCX_FAIL),
	OSMO_VALUE_STRING(RTP_STREAM_EV_MDCX_OK),
	OSMO_VALUE_STRING(RTP_STREAM_EV_MDCX_FAIL),
	{}
};

#define S(x)	(1 << (x))

static const struct osmo_fsm_state rtp_stream_fsm_states[] = {
	[RTP_STREAM_ST_UNINITIALIZED] = {
		.name = "UNINITIALIZED",
		.out_state_mask = 0
			| S(RTP_STREAM_ST_ESTABLISHING)
			| S(RTP_STREAM_ST_DISCARDING)
			,
	},
	[RTP_STREAM_ST_ESTABLISHING] = {
		.name = "ESTABLISHING",
		.in_event_mask = 0
			| S(RTP_STREAM_EV_CRCX_OK)
			| S(RTP_STREAM_EV_CRCX_FAIL)
			| S(RTP_STREAM_EV_MDCX_OK)
			| S(RTP_STREAM_EV_MDCX_FAIL)
			,
		.out_state_mask = 0
			| S(RTP_STREAM_ST_ESTABLISHED)
			| S(RTP_STREAM_ST_DISCARDING)
			,
		.action = rtp_stream_fsm_establishing_established,
	},
	[RTP_STREAM_ST_ESTABLISHED] = {
		.name = "ESTABLISHED",
		.out_state_mask = 0
			| S(RTP_STREAM_ST_ESTABLISHING)
			| S(RTP_STREAM_ST_DISCARDING)
			,
		.onenter = rtp_stream_fsm_established_onenter,
		.action = rtp_stream_fsm_establishing_established,
	},
	[RTP_STREAM_ST_DISCARDING] = {
		.name = "DISCARDING",
		.onenter = rtp_stream_fsm_discarding_onenter,
		.out_state_mask = 0
			| S(RTP_STREAM_ST_DISCARDING)
			,
	},
};

static struct osmo_fsm rtp_stream_fsm = {
	.name = "rtp_stream",
	.states = rtp_stream_fsm_states,
	.num_states = ARRAY_SIZE(rtp_stream_fsm_states),
	.log_subsys = DCC,
	.event_names = rtp_stream_fsm_event_names,
	.timer_cb = rtp_stream_fsm_timer_cb,
	.cleanup = rtp_stream_fsm_cleanup,
};

static int rtp_stream_do_mgcp_verb(struct rtp_stream *rtps, enum mgcp_verb verb, uint32_t ok_event, uint32_t fail_event)
{
	struct mgcp_conn_peer verb_info;

	if (!rtps->ci) {
		LOG_RTPS(rtps, LOGL_ERROR, "Cannot send %s, no endpoint CI allocated\n", osmo_mgcp_verb_name(verb));
		return -EINVAL;
	}

	verb_info = (struct mgcp_conn_peer){
		.call_id = rtps->call_id,
		.ptime = 20,
		.x_osmo_osmux_use = rtps->use_osmux,
		.x_osmo_osmux_cid = rtps->remote_osmux_cid,
	};

	verb_info.conn_mode = rtps->crcx_conn_mode;

	if (rtps->codecs_known) {
		/* Send the list of codecs to the MGW. Ideally we would just feed the SDP directly, but for legacy
		 * reasons we still need to translate to a struct mgcp_conn_peer representation to send it. */
		struct sdp_audio_codec *codec;
		int i = 0;
		foreach_sdp_audio_codec(codec, &rtps->codecs) {
			const struct codec_mapping *m = codec_mapping_by_subtype_name(codec->subtype_name);
			if (!m) {
				LOG_RTPS(rtps, LOGL_ERROR, "Cannot map codec '%s' to MGCP: codec is unknown\n",
					 codec->subtype_name);
				continue;
			}
			verb_info.codecs[i] = m->mgcp;
			verb_info.ptmap[i] = (struct ptmap){
				.codec = m->mgcp,
				.pt = codec->payload_type,
			};
			i++;
			verb_info.codecs_len = i;
			verb_info.ptmap_len = i;
		}
		rtps->codecs_sent_to_mgw = true;
	}
	if (osmo_sockaddr_str_is_nonzero(&rtps->remote)) {
		int rc = osmo_strlcpy(verb_info.addr, rtps->remote.ip, sizeof(verb_info.addr));
		if (rc <= 0 || rc >= sizeof(verb_info.addr)) {
			LOG_RTPS(rtps, LOGL_ERROR, "Failure to write IP address to MGCP message (rc=%d)\n", rc);
			return -ENOSPC;
		}
		verb_info.port = rtps->remote.port;
		rtps->remote_sent_to_mgw = true;
	}
	rtps->mode_sent_to_mgw = true;
	if (rtps->use_osmux && rtps->remote_osmux_cid >= 0)
		rtps->remote_osmux_cid_sent_to_mgw = true;
	rtp_stream_update_id(rtps);

	osmo_mgcpc_ep_ci_request(rtps->ci, verb, &verb_info, rtps->fi, ok_event, fail_event, NULL);
	return 0;
}

int rtp_stream_ensure_ci(struct rtp_stream *rtps, struct osmo_mgcpc_ep *at_endpoint)
{
	if (rtps->ci)
		return rtp_stream_commit(rtps);

	rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHING);

	rtps->ci = osmo_mgcpc_ep_ci_add(at_endpoint, "%s", rtp_direction_name(rtps->dir));
	if (!rtps->ci)
		return -ENODEV;

	return rtp_stream_do_mgcp_verb(rtps, MGCP_VERB_CRCX, RTP_STREAM_EV_CRCX_OK, RTP_STREAM_EV_CRCX_FAIL);
}

int rtp_stream_do_mdcx(struct rtp_stream *rtps)
{
	return rtp_stream_do_mgcp_verb(rtps, MGCP_VERB_MDCX, RTP_STREAM_EV_MDCX_OK, RTP_STREAM_EV_MDCX_FAIL);
}

void rtp_stream_release(struct rtp_stream *rtps)
{
	if (!rtps)
		return;

	rtp_stream_state_chg(rtps, RTP_STREAM_ST_DISCARDING);
}

/* After setting up a remote RTP address or a new codec, call this to trigger an MDCX.
 * The MDCX will only trigger if all data needed by an endpoint is available (RTP address, codecs and mode) and if at
 * least one of them has not yet been sent to the MGW in a previous CRCX or MDCX. */
int rtp_stream_commit(struct rtp_stream *rtps)
{
	if (!osmo_sockaddr_str_is_nonzero(&rtps->remote)) {
		LOG_RTPS(rtps, LOGL_DEBUG, "Not committing: no remote RTP address known\n");
		return -1;
	}
	if (!rtps->codecs_known) {
		LOG_RTPS(rtps, LOGL_DEBUG, "Not committing: no codecs known\n");
		return -1;
	}
	if (rtps->remote_sent_to_mgw && rtps->codecs_sent_to_mgw && rtps->mode_sent_to_mgw) {
		LOG_RTPS(rtps, LOGL_DEBUG,
			 "Not committing: remote RTP address, codecs and mode are already set up at MGW\n");
		return 0;
	}
	if (!rtps->ci) {
		LOG_RTPS(rtps, LOGL_DEBUG, "Not committing: no MGW endpoint CI set up\n");
		return -1;
	}

	LOG_RTPS(rtps, LOGL_DEBUG, "Committing: Tx MDCX to update the MGW: updating%s%s%s%s\n",
		 rtps->remote_sent_to_mgw ? "" : " remote-RTP-IP-port",
		 rtps->codecs_sent_to_mgw ? "" : " codecs",
		 rtps->mode_sent_to_mgw ? "" : " mode",
		 (!rtps->use_osmux || rtps->remote_osmux_cid_sent_to_mgw) ? "" : " remote-Osmux-CID");
	return rtp_stream_do_mdcx(rtps);
}

void rtp_stream_set_codecs(struct rtp_stream *rtps, const struct sdp_audio_codecs *codecs)
{
	if (!codecs || !codecs->count)
		return;
	if (sdp_audio_codecs_cmp(&rtps->codecs, codecs, false, true) == 0) {
		LOG_RTPS(rtps, LOGL_DEBUG, "no change: codecs already set to %s\n",
			 sdp_audio_codecs_to_str(&rtps->codecs));
		return;
	}
	if (rtps->fi->state == RTP_STREAM_ST_ESTABLISHED)
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHING);
	LOG_RTPS(rtps, LOGL_DEBUG, "setting codecs to %s\n", sdp_audio_codecs_to_str(codecs));
	rtps->codecs = *codecs;
	rtps->codecs_known = true;
	rtps->codecs_sent_to_mgw = false;
	rtp_stream_update_id(rtps);
}

void rtp_stream_set_mode(struct rtp_stream *rtps, enum mgcp_connection_mode mode)
{
	if (rtps->crcx_conn_mode == mode)
		return;
	if (rtps->fi->state == RTP_STREAM_ST_ESTABLISHED)
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHING);
	LOG_RTPS(rtps, LOGL_DEBUG, "setting mode to %s\n", mgcp_client_cmode_name(mode));
	rtps->mode_sent_to_mgw = false;
	rtps->crcx_conn_mode = mode;
	rtp_stream_update_id(rtps);
}

/* Convenience shortcut to call rtp_stream_set_codecs() with a list of only one sdp_audio_codec record. */
void rtp_stream_set_one_codec(struct rtp_stream *rtps, const struct sdp_audio_codec *codec)
{
	struct sdp_audio_codecs codecs = {};
	sdp_audio_codecs_add_copy(&codecs, codec);
	rtp_stream_set_codecs(rtps, &codecs);
}

/* For legacy, rather use rtp_stream_set_codecs() with a full codecs list. */
bool rtp_stream_set_codecs_from_mgcp_codec(struct rtp_stream *rtps, enum mgcp_codecs codec)
{
	struct sdp_audio_codecs codecs = {};
	if (!sdp_audio_codecs_add_mgcp_codec(&codecs, codec))
		return false;
	rtp_stream_set_codecs(rtps, &codecs);
	return true;
}

void rtp_stream_set_remote_addr(struct rtp_stream *rtps, const struct osmo_sockaddr_str *r)
{
	if (osmo_sockaddr_str_cmp(&rtps->remote, r) == 0) {
		LOG_RTPS(rtps, LOGL_DEBUG, "remote addr already " OSMO_SOCKADDR_STR_FMT ", no change\n",
			 OSMO_SOCKADDR_STR_FMT_ARGS(r));
		return;
	}
	if (rtps->fi->state == RTP_STREAM_ST_ESTABLISHED)
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHING);
	LOG_RTPS(rtps, LOGL_DEBUG, "setting remote addr to " OSMO_SOCKADDR_STR_FMT "\n", OSMO_SOCKADDR_STR_FMT_ARGS(r));
	rtps->remote = *r;
	rtps->remote_sent_to_mgw = false;
	rtp_stream_update_id(rtps);
}

void rtp_stream_set_remote_addr_and_codecs(struct rtp_stream *rtps, const struct sdp_msg *sdp)
{
	rtp_stream_set_codecs(rtps, &sdp->audio_codecs);
	if (osmo_sockaddr_str_is_nonzero(&sdp->rtp))
		rtp_stream_set_remote_addr(rtps, &sdp->rtp);
}

void rtp_stream_set_remote_osmux_cid(struct rtp_stream *rtps, uint8_t osmux_cid)
{
	if (rtps->fi->state == RTP_STREAM_ST_ESTABLISHED)
		rtp_stream_state_chg(rtps, RTP_STREAM_ST_ESTABLISHING);
	LOG_RTPS(rtps, LOGL_DEBUG, "setting remote Osmux CID to %u\n", osmux_cid);
	rtps->remote_osmux_cid = osmux_cid;
	rtps->remote_osmux_cid_sent_to_mgw = false;
	rtp_stream_update_id(rtps);
}

bool rtp_stream_is_established(struct rtp_stream *rtps)
{
	if (!rtps)
		return false;
	if (!rtps->fi)
		return false;
	if (rtps->fi->state != RTP_STREAM_ST_ESTABLISHED)
		return false;
	if (!rtps->remote_sent_to_mgw
	    || !rtps->codecs_sent_to_mgw
	    || !rtps->mode_sent_to_mgw
	    || (rtps->use_osmux && !rtps->remote_osmux_cid_sent_to_mgw))
		return false;
	return true;
}
