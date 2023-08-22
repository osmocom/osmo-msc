/* MSC Handover implementation */
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
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/msc/msc_ho.h>
#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/e_link.h>
#include <osmocom/msc/msc_i_remote.h>
#include <osmocom/msc/msc_t_remote.h>
#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/mncc_call.h>
#include <osmocom/msc/codec_mapping.h>

struct osmo_fsm msc_ho_fsm;

#define MSC_A_USE_HANDOVER "Handover"

static const struct osmo_tdef_state_timeout msc_ho_fsm_timeouts[32] = {
	[MSC_HO_ST_REQUIRED] = { .keep_timer = true, .T = -3 },
	[MSC_HO_ST_WAIT_REQUEST_ACK] = { .keep_timer = true },
	[MSC_HO_ST_WAIT_COMPLETE] = { .T = -3 },
};

/* Transition to a state, using the T timer defined in msc_a_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define msc_ho_fsm_state_chg(msc_a, state) \
	osmo_tdef_fsm_inst_state_chg((msc_a)->ho.fi, state, msc_ho_fsm_timeouts, (msc_a)->c.ran->tdefs, 5)

static __attribute__((constructor)) void msc_ho_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&msc_ho_fsm) == 0);
}

void msc_ho_down_required_reject(struct msc_a *msc_a, enum gsm0808_cause cause)
{
	struct msc_i *msc_i;
	uint32_t event;

	msc_i = msc_a_msc_i(msc_a);
	OSMO_ASSERT(msc_i);

	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_HANDOVER_REQUIRED_REJECT,
		.handover_required_reject = {
			.cause = cause,
		},
	};

	if (msc_i->c.remote_to)
		event = MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_ERROR;
	else
		event = MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST;

	msc_a_msg_down(msc_a, MSC_ROLE_I, event, &ran_enc_msg);
}

/* Even though this is using the 3GPP TS 48.008 definitions and naming, the intention is to be RAN implementation agnostic.
 * For other RAN types, the 48.008 items shall be translated to their respective counterparts. */
void msc_ho_start(struct msc_a *msc_a, const struct ran_handover_required *ho_req)
{
	if (msc_a->ho.fi) {
		LOG_HO(msc_a, LOGL_ERROR, "Rx Handover Required, but Handover is still ongoing\n");
		msc_ho_down_required_reject(msc_a, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		return;
	}

	if (!ho_req->cil.id_list_len) {
		LOG_HO(msc_a, LOGL_ERROR, "Rx Handover Required without a Cell Identifier List\n");
		msc_ho_down_required_reject(msc_a, GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING);
		return;
	}

	if (msc_a_msc_t(msc_a)) {
		LOG_HO(msc_a, LOGL_ERROR,
		       "Rx Handover Required, but this subscriber still has an active MSC-T role: %s\n",
		       msc_a_msc_t(msc_a)->c.fi->id);
		/* Protocol error because the BSS is not supposed to send another Handover Required before the previous
		 * attempt has concluded. */
		msc_ho_down_required_reject(msc_a, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		return;
	}

	/* Paranoia: make sure we start with clean state */
	msc_a->ho = (struct msc_ho_state){};

	msc_a->ho.fi = osmo_fsm_inst_alloc_child(&msc_ho_fsm, msc_a->c.fi, MSC_A_EV_HANDOVER_END);
	OSMO_ASSERT(msc_a->ho.fi);

	msc_a->ho.fi->priv = msc_a;
	msc_a->ho.info = *ho_req;
	msc_a->ho.next_cil_idx = 0;

	/* Start the timeout */
	msc_ho_fsm_state_chg(msc_a, MSC_HO_ST_REQUIRED);
}

static void msc_ho_rtp_rollback_to_old_cell(struct msc_a *msc_a);

static void msc_ho_end(struct msc_a *msc_a, bool success, enum gsm0808_cause cause)
{
	struct msc_i *msc_i;
	struct msc_t *msc_t = msc_a_msc_t(msc_a);

	if (!success) {
		msc_ho_rtp_rollback_to_old_cell(msc_a);
		msc_ho_down_required_reject(msc_a, cause);
	}

	if (success) {
		/* Any previous call forwarding to a remote MSC becomes obsolete. */
		if (msc_a->cc.mncc_forwarding_to_remote_ran) {
			mncc_call_release(msc_a->cc.mncc_forwarding_to_remote_ran);
			msc_a->cc.mncc_forwarding_to_remote_ran = NULL;
		}

		/* Replace MSC-I with new MSC-T */
		if (msc_t->c.remote_to) {
			/* Inter-MSC Handover. */

			/* The MNCC forwarding set up for inter-MSC handover, so far transitional in msc_a->ho now
			 * becomes the "officially" active MNCC forwarding for this call. */
			msc_a->cc.mncc_forwarding_to_remote_ran = msc_a->ho.new_cell.mncc_forwarding_to_remote_ran;
			msc_a->ho.new_cell.mncc_forwarding_to_remote_ran = NULL;
			mncc_call_reparent(msc_a->cc.mncc_forwarding_to_remote_ran,
					   msc_a->c.fi, -1, MSC_MNCC_EV_CALL_ENDED, NULL, NULL);

			/* inter-MSC link. msc_i_remote_alloc() properly "steals" the e_link from msc_t. */
			msc_i = msc_i_remote_alloc(msc_a->c.msub, msc_t->c.ran, msc_t->c.remote_to);
			OSMO_ASSERT(msc_t->c.remote_to == NULL);
		} else {
			/* local BSS */
			msc_i = msc_i_alloc(msc_a->c.msub, msc_t->c.ran);
			/* msc_i_set_ran_conn() properly "steals" the ran_conn from msc_t */
			msc_i_set_ran_conn(msc_i, msc_t->ran_conn);
		}
	}

	osmo_fsm_inst_term(msc_a->ho.fi, OSMO_FSM_TERM_REGULAR, NULL);
}

#define msc_ho_failed(msc_a, cause, fmt, args...) do { \
		LOG_HO(msc_a, LOGL_ERROR, fmt, ##args); \
		msc_ho_end(msc_a, false, cause); \
	} while(0)
#define msc_ho_try_next_cell(msc_a, fmt, args...) do {\
		LOG_HO(msc_a, LOGL_ERROR, fmt, ##args); \
		msc_ho_fsm_state_chg(msc_a, MSC_HO_ST_REQUIRED); \
	} while(0)
#define msc_ho_success(msc_a) msc_ho_end(msc_a, true, 0)

enum msc_neighbor_type msc_ho_find_target_cell(struct msc_a *msc_a, const struct gsm0808_cell_id *cid,
					       const struct neighbor_ident_entry **remote_msc,
					       struct ran_peer **ran_peer_from_neighbor_ident,
					       struct ran_peer **ran_peer_from_seen_cells)
{
	struct gsm_network *net = msc_a_net(msc_a);
	const struct neighbor_ident_entry *e;
	struct sccp_ran_inst *sri;
	struct ran_peer *rp_from_neighbor_ident = NULL;
	struct ran_peer *rp_from_cell_id = NULL;
	struct ran_peer *rp;
	int i;

	OSMO_ASSERT(remote_msc);
	OSMO_ASSERT(ran_peer_from_neighbor_ident);
	OSMO_ASSERT(ran_peer_from_seen_cells);

	e = neighbor_ident_find_by_cell(&net->neighbor_ident_list, msc_a->c.ran->type, cid);

	if (e && e->addr.type == MSC_NEIGHBOR_TYPE_REMOTE_MSC) {
		*remote_msc = e;
		return MSC_NEIGHBOR_TYPE_REMOTE_MSC;
	}

	/* It is not a remote MSC target. Figure out local RAN peers. */

	if (e && e->addr.type == MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER) {
		/* Find local RAN peer in neighbor config. If anything is wrong with that, just keep
		 * rp_from_neighbor_ident == NULL. */

		struct sccp_ran_inst *sri_from_neighbor_ident = NULL;
		struct osmo_ss7_instance *ss7 = NULL;

		/* Get the sccp_ran_inst with sanity checkin. If anything is fishy, just keep
		 * sri_from_neighbor_ident == NULL and below code will notice the error. */
		if (e->addr.ran_type < msc_ran_infra_len) {
			sri_from_neighbor_ident = msc_ran_infra[e->addr.ran_type].sri;
			ss7 = osmo_sccp_get_ss7(sri_from_neighbor_ident->sccp);
			if (!ss7)
				sri_from_neighbor_ident = NULL;
		}

		if (!sri_from_neighbor_ident) {
			LOG_HO(msc_a, LOGL_ERROR, "Cannot handover to RAN type %s\n", osmo_rat_type_name(e->addr.ran_type));
		} else {
			/* Interpret the point-code string placed in the neighbors config. */
			int pc = osmo_ss7_pointcode_parse(ss7, e->addr.local_ran_peer_pc_str);

			if (pc < 0) {
				LOG_HO(msc_a, LOGL_ERROR, "Invalid point code string: %s\n",
				       osmo_quote_str(e->addr.local_ran_peer_pc_str, -1));
			} else {
				struct osmo_sccp_addr addr = {};
				osmo_sccp_make_addr_pc_ssn(&addr, pc, sri_from_neighbor_ident->ran->ssn);
				rp_from_neighbor_ident = ran_peer_find_by_addr(sri_from_neighbor_ident, &addr);
			}
		}

		if (!rp_from_neighbor_ident) {
			LOG_HO(msc_a, LOGL_ERROR, "Target RAN peer from neighbor config is not connected:"
			       " Cell ID %s resolves to target address %s\n",
			       gsm0808_cell_id_name(cid), e->addr.local_ran_peer_pc_str);
		} else if (rp_from_neighbor_ident->fi->state != RAN_PEER_ST_READY) {
			LOG_HO(msc_a, LOGL_ERROR, "Target RAN peer in invalid state: %s (%s)\n",
			       osmo_fsm_inst_state_name(rp_from_neighbor_ident->fi),
			       rp_from_neighbor_ident->fi->id);
			rp_from_neighbor_ident = NULL;
		}
	}

	/* Figure out actually connected RAN peers for this cell ID.
	 * If no cell has been found yet at all, this might determine a Handover target,
	 * otherwise this is for sanity checking. If none is found, just keep rp_from_cell_id == NULL. */

	/* Iterate all connected RAN peers. Possibly, more than one RAN peer has advertised a match for this Cell ID.
	 * For example, if the handover target is identified as LAC=23 but there are multiple cells with distinct CIs
	 * serving in LAC=23, we have an ambiguity. It's up to the user to configure correctly, help with logging. */
	for (i = 0; i < msc_ran_infra_len; i++) {
		sri = msc_ran_infra[i].sri;
		if (!sri)
			continue;

		rp = ran_peer_find_by_cell_id(sri, cid, true);
		if (rp && rp->fi && rp->fi->state == RAN_PEER_ST_READY) {
			if (rp_from_cell_id) {
				LOG_HO(msc_a, LOGL_ERROR,
				       "Ambiguous match for cell ID %s: more than one RAN type is serving this cell"
				       " ID: %s and %s\n",
				       gsm0808_cell_id_name(cid),
				       rp_from_cell_id->fi->id,
				       rp->fi->id);
				/* But logging is all we're going to do about it. */
			}

			/* Use the first found RAN peer, but if multiple matches are found, favor the one that matches
			 * the current RAN type. */
			if (!rp_from_cell_id || rp->sri == msc_a->c.ran->sri)
				rp_from_cell_id = rp;
		}
	}

	/* Did we find mismatching targets from neighbor config and from connected cells? */
	if (rp_from_neighbor_ident && rp_from_cell_id
	    && rp_from_neighbor_ident != rp_from_cell_id) {
		LOG_HO(msc_a, LOGL_ERROR, "Ambiguous match for cell ID %s:"
		       " neighbor config points at %s; a matching cell is also served by connected RAN peer %s\n",
		       gsm0808_cell_id_name(cid), rp_from_neighbor_ident->fi->id, rp_from_cell_id->fi->id);
		/* But logging is all we're going to do about it. */
	}

	if (rp_from_neighbor_ident && rp_from_neighbor_ident->sri != msc_a->c.ran->sri) {
		LOG_HO(msc_a, LOGL_ERROR,
		       "Neighbor config indicates inter-RAT Handover, which is not implemented. Ignoring target %s\n",
		       rp_from_neighbor_ident->fi->id);
		rp_from_neighbor_ident = NULL;
	}

	if (rp_from_cell_id && rp_from_cell_id->sri != msc_a->c.ran->sri) {
		LOG_HO(msc_a, LOGL_ERROR,
		       "Target RAN peer indicates inter-RAT Handover, which is not implemented. Ignoring target %s\n",
		       rp_from_cell_id->fi->id);
		rp_from_cell_id = NULL;
	}

	*ran_peer_from_neighbor_ident = rp_from_neighbor_ident;
	*ran_peer_from_seen_cells = rp_from_cell_id;

	return rp_from_neighbor_ident || rp_from_cell_id ? MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER : MSC_NEIGHBOR_TYPE_NONE;
}

static bool msc_ho_find_next_target_cell(struct msc_a *msc_a)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct ran_handover_required *info = &msc_a->ho.info;
	struct gsm0808_cell_id *cid = &msc_a->ho.new_cell.cid;
	const struct neighbor_ident_entry *e;
	struct ran_peer *rp_from_neighbor_ident = NULL;
	struct ran_peer *rp_from_cell_id = NULL;
	struct ran_peer *rp;

	unsigned int cil_idx = msc_a->ho.next_cil_idx;
	msc_a->ho.next_cil_idx++;

	msc_a->ho.new_cell.type = MSC_NEIGHBOR_TYPE_NONE;

	if (cil_idx >= info->cil.id_list_len)
		return false;

	*cid = (struct gsm0808_cell_id){
		.id_discr = info->cil.id_discr,
		.id = info->cil.id_list[cil_idx],
	};

	msc_a->ho.new_cell.cgi = (struct osmo_cell_global_id){
		.lai = vsub->cgi.lai,
	};
	gsm0808_cell_id_to_cgi(&msc_a->ho.new_cell.cgi, cid);

	switch (msc_ho_find_target_cell(msc_a, cid, &e, &rp_from_neighbor_ident, &rp_from_cell_id)) {
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		OSMO_ASSERT(e);
		msc_a->ho.new_cell.ran_type = e->addr.ran_type;
		msc_a->ho.new_cell.type = MSC_NEIGHBOR_TYPE_REMOTE_MSC;
		msc_a->ho.new_cell.msc_ipa_name = e->addr.remote_msc_ipa_name.buf;
		return true;

	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		rp = rp_from_neighbor_ident ? : rp_from_cell_id;
		OSMO_ASSERT(rp);
		msc_a->ho.new_cell.type = MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER;
		msc_a->ho.new_cell.ran_peer = rp;
		return true;

	default:
		break;
	}

	LOG_HO(msc_a, LOGL_DEBUG, "Cannot find target peer for cell ID %s\n", gsm0808_cell_id_name(cid));
	/* Try the next cell id, if any. */
	return msc_ho_find_next_target_cell(msc_a);
}

static void msc_ho_fsm_required_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_a *msc_a = fi->priv;

	if (!msc_ho_find_next_target_cell(msc_a)) {
		int tried = msc_a->ho.next_cil_idx - 1;
		msc_ho_failed(msc_a, GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
			      "Attempted Handover to %u cells without success\n", tried);
		return;
	}

	msc_ho_fsm_state_chg(msc_a, MSC_HO_ST_WAIT_REQUEST_ACK);
}

static void msc_ho_send_handover_request(struct msc_a *msc_a)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct gsm_network *net = msc_a_net(msc_a);
	struct gsm0808_channel_type channel_type;
	struct gsm0808_speech_codec_list scl;
	struct gsm_trans *cc_trans = msc_a->cc.active_trans;
	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_HANDOVER_REQUEST,
		.handover_request = {
			.imsi = vsub->imsi,
			.classmark = &vsub->classmark,
			.geran = {
				.chosen_encryption = &msc_a->geran_encr,
				.a5_encryption_mask = net->a5_encryption_mask,
			},
			.bssap_cause = GSM0808_CAUSE_BETTER_CELL,
			.current_channel_type_1_present = msc_a->ho.info.current_channel_type_1_present,
			.current_channel_type_1 = msc_a->ho.info.current_channel_type_1,
			.speech_version_used = msc_a->ho.info.speech_version_used,
			.old_bss_to_new_bss_info_raw = msc_a->ho.info.old_bss_to_new_bss_info_raw,
			.old_bss_to_new_bss_info_raw_len = msc_a->ho.info.old_bss_to_new_bss_info_raw_len,

			/* Don't send AoIP Transport Layer Address for inter-MSC Handover */
			.rtp_ran_local = (msc_a->ho.new_cell.type == MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER)
				? call_leg_local_ip(msc_a->cc.call_leg, RTP_TO_RAN) : NULL,
		},
	};

	if (msc_a->geran_encr.key_len)
		LOG_MSC_A(msc_a, LOGL_DEBUG, "HO Request with ciphering: A5/%d kc %s kc128 %s\n",
			  msc_a->geran_encr.alg_id - 1,
			  osmo_hexdump_nospc_c(OTC_SELECT, msc_a->geran_encr.key, msc_a->geran_encr.key_len),
			  msc_a->geran_encr.kc128_present ?
			    osmo_hexdump_nospc_c(OTC_SELECT, msc_a->geran_encr.kc128, sizeof(msc_a->geran_encr.kc128))
			    : "-");

	if (cc_trans) {
		switch (cc_trans->bearer_cap.transfer) {
		case GSM48_BCAP_ITCAP_SPEECH:
			if (sdp_audio_codecs_to_gsm0808_channel_type(&channel_type,
								     &cc_trans->cc.local.audio_codecs)) {
				msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
					      "Failed to determine Channel Type for Handover Request message (speech)\n");
				return;
			}
			break;
		case GSM48_BCAP_ITCAP_UNR_DIG_INF:
			if (csd_bs_list_to_gsm0808_channel_type(&channel_type, &cc_trans->cc.local.bearer_services)) {
				msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
					      "Failed to determine Channel Type for Handover Request message (CSD)\n");
				return;
			}
			break;
		default:
			msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "Failed to create"
				      " Handover Request message for information transfer capability %d\n",
				      cc_trans->bearer_cap.transfer);
			return;
		}

		ran_enc_msg.handover_request.geran.channel_type = &channel_type;
		ran_enc_msg.handover_request.call_id_present = true;
		ran_enc_msg.handover_request.call_id = cc_trans->call_id;

		sdp_audio_codecs_to_speech_codec_list(&scl, &cc_trans->cc.local.audio_codecs);
		if (!scl.len) {
			msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "Failed to compose"
				      " Codec List (MSC Preferred) for Handover Request message\n");
			return;
		}
		ran_enc_msg.handover_request.codec_list_msc_preferred = &scl;
	}

	gsm0808_cell_id_from_cgi(&ran_enc_msg.handover_request.cell_id_serving, CELL_IDENT_WHOLE_GLOBAL, &vsub->cgi);
	ran_enc_msg.handover_request.cell_id_target = msc_a->ho.new_cell.cid;

	if (msc_a_msg_down(msc_a, MSC_ROLE_T, MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST, &ran_enc_msg))
		msc_ho_try_next_cell(msc_a, "Failed to send Handover Request message\n");
}

static void msc_ho_fsm_wait_request_ack_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_a *msc_a = fi->priv;
	struct msc_i *msc_i = msc_a_msc_i(msc_a);
	struct msc_t *msc_t;
	struct ran_peer *rp;
	const char *ipa_name;

	msc_t = msc_a_msc_t(msc_a);
	if (msc_t) {
		/* All the other code should prevent this from happening, ever. */
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
			      "Cannot initiate Handover Request, there still is an active MSC-T role: %s\n",
			      msc_t->c.fi->id);
		return;
	}

	if (!msc_i) {
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
			      "Cannot initiate Handover Request, there is no MSC-I role\n");
		return;
	}

	if (!msc_i->c.remote_to
	    && !(msc_i->ran_conn && msc_i->ran_conn->ran_peer)) {
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
			      "Cannot initiate Handover Request, MSC-I role has no connection\n");
		return;
	}

	switch (msc_a->ho.new_cell.type) {
	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		rp = msc_a->ho.new_cell.ran_peer;
		OSMO_ASSERT(rp && rp->fi);

		if (msc_i->c.remote_to) {
			LOG_HO(msc_a, LOGL_INFO,
			       "Starting inter-MSC Subsequent Handover from remote MSC %s to local %s\n",
			       msc_i->c.remote_to->remote_name, rp->fi->id);
			msc_a->ho.subsequent_ho = true;
		} else {
			LOG_HO(msc_a, LOGL_INFO, "Starting inter-BSC Handover from %s to %s\n",
			       msc_i->ran_conn->ran_peer->fi->id, rp->fi->id);
		}

		msc_t = msc_t_alloc(msc_a->c.msub, rp);
		break;

	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		ipa_name = msc_a->ho.new_cell.msc_ipa_name;
		OSMO_ASSERT(ipa_name);

		if (msc_i->c.remote_to) {
			LOG_HO(msc_a, LOGL_INFO,
			       "Starting inter-MSC Subsequent Handover from remote MSC %s to remote MSC at %s\n",
			       msc_i->c.remote_to->remote_name, osmo_quote_str(ipa_name, -1));
			msc_a->ho.subsequent_ho = true;
		} else {
			LOG_HO(msc_a, LOGL_INFO, "Starting inter-MSC Handover from local %s to remote MSC at %s\n",
			       msc_i->ran_conn->ran_peer->fi->id,
			       osmo_quote_str(ipa_name, -1));
		}

		msc_t = msc_t_remote_alloc(msc_a->c.msub, msc_a->c.ran,
					   (const uint8_t *) ipa_name,
					   strlen(ipa_name));
		break;

	default:
		msc_ho_try_next_cell(msc_a, "unknown Handover target type %d\n", msc_a->ho.new_cell.type);
		return;
	}

	if (!msc_t) {
		/* There should definitely be one now. */
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE,
			      "Cannot initiate Handover Request, failed to set up a target MSC-T\n");
		return;
	}

	msc_ho_send_handover_request(msc_a);
}

static void msc_ho_rx_request_ack(struct msc_a *msc_a, struct msc_a_ran_dec_data *hra);

static void msc_ho_fsm_wait_request_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	switch (event) {

	case MSC_HO_EV_RX_REQUEST_ACK:
		msc_ho_rx_request_ack(msc_a, (struct msc_a_ran_dec_data*)data);
		return;

	case MSC_HO_EV_RX_FAILURE:
		msc_ho_failed(msc_a, GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
			      "Received Handover Failure message\n");
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void msc_ho_rtp_switch_to_new_cell(struct msc_a *msc_a);

void msc_ho_mncc_forward_cb(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg, void *data)
{
	struct msc_a *msc_a = data;
	switch (mncc_msg->msg_type) {
	case MNCC_RTP_CONNECT:
		msc_a->ho.rtp_switched_to_new_cell = true;
		return;
	default:
		return;
	}
}

/* Initiate call forwarding via MNCC: call the Handover Number that the other MSC assigned. */
static int msc_ho_start_inter_msc_call_forwarding(struct msc_a *msc_a, struct msc_t *msc_t,
						  const struct msc_a_ran_dec_data *hra)
{
	const struct osmo_gsup_message *e_info = hra->an_apdu->e_info;
	struct gsm_mncc outgoing_call_req = {};
	struct call_leg *cl = msc_a->cc.call_leg;
	struct rtp_stream *rtp_to_ran = cl ? cl->rtp[RTP_TO_RAN] : NULL;
	struct mncc_call *mncc_call;

	if (!e_info || !e_info->msisdn_enc || !e_info->msisdn_enc_len) {
		msc_ho_try_next_cell(msc_a,
				     "No Handover Number in Handover Request Acknowledge from remote MSC\n");
		return -EINVAL;
	}

	if (!rtp_to_ran) {
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "Unexpected: no RTP stream is set up\n");
		return -EINVAL;
	}

	/* Backup old cell's RTP IP:port and codec data */
	msc_a->ho.old_cell.ran_remote_rtp = rtp_to_ran->remote;
	msc_a->ho.old_cell.codecs = rtp_to_ran->codecs;

	/* Blindly taken over from an MNCC trace of existing code: send an all-zero CCCAP: */
	outgoing_call_req.fields |= MNCC_F_CCCAP;

	/* Called number */
	outgoing_call_req.fields |= MNCC_F_CALLED;
	outgoing_call_req.called.plan = 1; /* Empirical magic number. There seem to be no enum or defines for this.
					    * The only other place setting this apparently is gsm48_decode_called(). */
	if (gsm48_decode_bcd_number2(outgoing_call_req.called.number, sizeof(outgoing_call_req.called.number),
				     e_info->msisdn_enc, e_info->msisdn_enc_len, 0)) {
		msc_ho_try_next_cell(msc_a,
				     "Failed to decode Handover Number in Handover Request Acknowledge"
				     " from remote MSC\n");
		return -EINVAL;
	}

	if (msc_a->cc.active_trans) {
		outgoing_call_req.fields |= MNCC_F_BEARER_CAP;
		outgoing_call_req.bearer_cap = msc_a->cc.active_trans->bearer_cap;
	}

	mncc_call = mncc_call_alloc(msc_a_vsub(msc_a),
				    msc_a->ho.fi,
				    MSC_HO_EV_MNCC_FORWARDING_COMPLETE,
				    MSC_HO_EV_MNCC_FORWARDING_FAILED,
				    msc_ho_mncc_forward_cb, msc_a);

	mncc_call_set_rtp_stream(mncc_call, rtp_to_ran);
	msc_a->ho.new_cell.mncc_forwarding_to_remote_ran = mncc_call;
	return mncc_call_outgoing_start(mncc_call, &outgoing_call_req);
}

static void msc_ho_rx_request_ack(struct msc_a *msc_a, struct msc_a_ran_dec_data *hra)
{
	struct msc_t *msc_t = msc_a_msc_t(msc_a);
	struct ran_msg ran_enc_msg;

	OSMO_ASSERT(hra->ran_dec);
	OSMO_ASSERT(hra->an_apdu);

	if (!msc_t) {
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "MSC-T role missing\n");
		return;
	}

	if (!hra->ran_dec->handover_request_ack.rr_ho_command
	    || !hra->ran_dec->handover_request_ack.rr_ho_command_len) {
		msc_ho_try_next_cell(msc_a, "Missing mandatory IE in Handover Request Acknowledge:"
				     " L3 Info (RR Handover Command)\n");
		return;
	}

	if (!hra->ran_dec->handover_request_ack.chosen_channel_present) {
		LOG_HO(msc_a, LOGL_DEBUG, "No 'Chosen Channel' IE in Handover Request Ack\n");
		msc_t->geran.chosen_channel = 0;
	} else
		msc_t->geran.chosen_channel = hra->ran_dec->handover_request_ack.chosen_channel;

	if (!hra->ran_dec->handover_request_ack.chosen_encr_alg) {
		LOG_HO(msc_a, LOGL_DEBUG, "No 'Chosen Encryption Algorithm' IE in Handover Request Ack\n");
		msc_t->geran.chosen_encr_alg = 0;
	} else {
		msc_t->geran.chosen_encr_alg = hra->ran_dec->handover_request_ack.chosen_encr_alg;
		if (msc_t->geran.chosen_encr_alg < 1 || msc_t->geran.chosen_encr_alg > 8) {
			msc_ho_try_next_cell(msc_a, "Handover Request Ack: Invalid 'Chosen Encryption Algorithm': %u\n",
					     msc_t->geran.chosen_encr_alg);
			return;
		}
	}

	msc_t->geran.chosen_speech_version = hra->ran_dec->handover_request_ack.chosen_speech_version;
	if (!msc_t->geran.chosen_speech_version)
		LOG_HO(msc_a, LOGL_DEBUG, "No 'Chosen Speech Version' IE in Handover Request Ack\n");

	/* Inter-MSC call forwarding? */
	if (msc_a->ho.new_cell.type == MSC_NEIGHBOR_TYPE_REMOTE_MSC) {
		if (msc_ho_start_inter_msc_call_forwarding(msc_a, msc_t, hra))
			return;
	}

	msc_ho_fsm_state_chg(msc_a, MSC_HO_ST_WAIT_COMPLETE);

	/* Forward the RR Handover Command composed by the new RAN peer down to the old RAN peer */
	ran_enc_msg = (struct ran_msg){
		.msg_type = RAN_MSG_HANDOVER_COMMAND,
		.handover_command = {
			.rr_ho_command = hra->ran_dec->handover_request_ack.rr_ho_command,
			.rr_ho_command_len = hra->ran_dec->handover_request_ack.rr_ho_command_len,
		},
	};

	if (msc_a_msg_down(msc_a, MSC_ROLE_I,
			   msc_a->ho.subsequent_ho ? MSC_I_EV_FROM_A_PREPARE_SUBSEQUENT_HANDOVER_RESULT
						   : MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST,
			   &ran_enc_msg)) {
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "Failed to send Handover Command\n");
		return;
	}

	msc_a->ho.new_cell.ran_remote_rtp = hra->ran_dec->handover_request_ack.remote_rtp;
	if (osmo_sockaddr_str_is_nonzero(&msc_a->ho.new_cell.ran_remote_rtp)) {
		LOG_HO(msc_a, LOGL_DEBUG, "Request Ack contains cell's RTP address " OSMO_SOCKADDR_STR_FMT "\n",
		       OSMO_SOCKADDR_STR_FMT_ARGS(&msc_a->ho.new_cell.ran_remote_rtp));
	}

	msc_a->ho.new_cell.codec_present = hra->ran_dec->handover_request_ack.codec_present;
	msc_a->ho.new_cell.codec = hra->ran_dec->handover_request_ack.codec;
	if (hra->ran_dec->handover_request_ack.codec_present) {
		LOG_HO(msc_a, LOGL_DEBUG, "Request Ack contains codec %s\n",
		       gsm0808_speech_codec_type_name(msc_a->ho.new_cell.codec.type));
	}
}

static void msc_ho_rtp_switch_to_new_cell(struct msc_a *msc_a)
{
	struct call_leg *cl = msc_a->cc.call_leg;
	struct rtp_stream *rtp_to_ran = cl ? cl->rtp[RTP_TO_RAN] : NULL;

	if (!rtp_to_ran) {
		LOG_HO(msc_a, LOGL_DEBUG, "No RTP stream, nothing to switch\n");
		return;
	}

	if (!osmo_sockaddr_str_is_nonzero(&msc_a->ho.new_cell.ran_remote_rtp)) {
		LOG_HO(msc_a, LOGL_DEBUG, "New cell's RTP IP:port not yet known, not switching RTP stream\n");
		return;
	}

	if (msc_a->ho.rtp_switched_to_new_cell) {
		LOG_HO(msc_a, LOGL_DEBUG, "Already switched RTP to new cell\n");
		return;
	}
	msc_a->ho.rtp_switched_to_new_cell = true;

	/* Backup old cell's RTP IP:port and codec data */
	msc_a->ho.old_cell.ran_remote_rtp = rtp_to_ran->remote;
	msc_a->ho.old_cell.codecs = rtp_to_ran->codecs;

	LOG_HO(msc_a, LOGL_DEBUG, "Switching RTP stream to new cell: from " OSMO_SOCKADDR_STR_FMT " to " OSMO_SOCKADDR_STR_FMT "\n",
	       OSMO_SOCKADDR_STR_FMT_ARGS(&msc_a->ho.old_cell.ran_remote_rtp),
	       OSMO_SOCKADDR_STR_FMT_ARGS(&msc_a->ho.new_cell.ran_remote_rtp));

	/* If a previous forwarding to a remote MSC is still active, this now becomes no longer responsible for the RTP
	 * stream. */
	if (msc_a->cc.mncc_forwarding_to_remote_ran) {
		if (msc_a->cc.mncc_forwarding_to_remote_ran->rtps != rtp_to_ran) {
			LOG_HO(msc_a, LOGL_ERROR,
			       "Unexpected state: previous MNCC forwarding not using RTP-to-RAN stream\n");
			/* That would be weird, but carry on anyway... */
		}
		mncc_call_detach_rtp_stream(msc_a->cc.mncc_forwarding_to_remote_ran);
	}

	/* Switch over to the new peer */
	rtp_stream_set_remote_addr(rtp_to_ran, &msc_a->ho.new_cell.ran_remote_rtp);
	if (msc_a->ho.new_cell.codec_present) {
		const struct codec_mapping *m;
		m = codec_mapping_by_gsm0808_speech_codec_type(msc_a->ho.new_cell.codec.type);
		/* TODO: use codec_mapping_by_gsm0808_speech_codec() to also match on codec.cfg */
		if (!m)
			LOG_HO(msc_a, LOGL_ERROR, "Cannot resolve codec: %s\n",
			       gsm0808_speech_codec_type_name(msc_a->ho.new_cell.codec.type));
		else
			rtp_stream_set_one_codec(rtp_to_ran, &m->sdp);
	} else {
		LOG_HO(msc_a, LOGL_ERROR, "No codec is set\n");
	}
	rtp_stream_commit(rtp_to_ran);
}

static void msc_ho_rtp_rollback_to_old_cell(struct msc_a *msc_a)
{
	struct call_leg *cl = msc_a->cc.call_leg;
	struct rtp_stream *rtp_to_ran = cl ? cl->rtp[RTP_TO_RAN] : NULL;

	if (!msc_a->ho.rtp_switched_to_new_cell) {
		LOG_HO(msc_a, LOGL_DEBUG, "Not switched RTP to new cell yet, no need to roll back\n");
		return;
	}

	if (!rtp_to_ran) {
		LOG_HO(msc_a, LOGL_DEBUG, "No RTP stream, nothing to switch\n");
		return;
	}

	if (!osmo_sockaddr_str_is_nonzero(&msc_a->ho.old_cell.ran_remote_rtp)) {
		LOG_HO(msc_a, LOGL_DEBUG, "Have no RTP IP:port for the old cell, not switching back to\n");
		return;
	}

	/* The new call forwarding to a remote MSC is no longer needed because the handover failed */
	if (msc_a->ho.new_cell.mncc_forwarding_to_remote_ran)
		mncc_call_detach_rtp_stream(msc_a->ho.new_cell.mncc_forwarding_to_remote_ran);

	/* If before this handover, there was a call forwarding to a remote MSC in place, this now goes back into
	 * responsibility. */
	if (msc_a->cc.mncc_forwarding_to_remote_ran)
		mncc_call_set_rtp_stream(msc_a->cc.mncc_forwarding_to_remote_ran, rtp_to_ran);

	msc_a->ho.rtp_switched_to_new_cell = false;
	msc_a->ho.ready_to_switch_rtp = false;
	LOG_HO(msc_a, LOGL_NOTICE, "Switching RTP back to old cell\n");

	/* Switch back to the old cell */
	rtp_stream_set_remote_addr(rtp_to_ran, &msc_a->ho.old_cell.ran_remote_rtp);
	rtp_stream_set_codecs(rtp_to_ran, &msc_a->ho.old_cell.codecs);
	rtp_stream_commit(rtp_to_ran);
}

static void msc_ho_send_handover_succeeded(struct msc_a *msc_a)
{
	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_HANDOVER_SUCCEEDED,
	};

	if (msc_a_msg_down(msc_a, MSC_ROLE_I, MSC_I_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST, &ran_enc_msg))
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "Failed to send Handover Succeeded message\n");
}

static void msc_ho_fsm_wait_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	switch (event) {

	case MSC_HO_EV_RX_DETECT:
		msc_a->ho.ready_to_switch_rtp = true;
		/* For inter-MSC, the mncc_fsm switches the rtp_stream upon MNCC_RTP_CONNECT.
		 * For inter-BSC, need to switch here to the address obtained from Handover Request Ack. */
		if (msc_a->ho.new_cell.type == MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER)
			msc_ho_rtp_switch_to_new_cell(msc_a);
		msc_ho_send_handover_succeeded(msc_a);
		return;

	case MSC_HO_EV_RX_COMPLETE:
		msc_ho_success(msc_a);
		return;

	case MSC_HO_EV_RX_FAILURE:
		msc_ho_failed(msc_a, GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
			      "Received Handover Failure message\n");
		return;

	case MSC_HO_EV_MNCC_FORWARDING_FAILED:
		msc_ho_failed(msc_a, GSM0808_CAUSE_EQUIPMENT_FAILURE, "MNCC Forwarding failed\n");
		return;

	case MSC_HO_EV_MNCC_FORWARDING_COMPLETE:
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void msc_ho_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_a *msc_a = fi->priv;
	struct msc_t *msc_t = msc_a_msc_t(msc_a);

	/* paranoia */
	if (msc_a->ho.fi != fi)
		return;

	/* Completely clear all handover state */
	msc_a->ho = (struct msc_ho_state){};

	if (msc_t)
		msc_t_clear(msc_t);
}

static int msc_ho_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 1;
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_ho_fsm_states[] = {
	[MSC_HO_ST_REQUIRED] = {
		.name = OSMO_STRINGIFY(MSC_HO_ST_REQUIRED),
		.out_state_mask = 0
			| S(MSC_HO_ST_REQUIRED)
			| S(MSC_HO_ST_WAIT_REQUEST_ACK)
			,
		.onenter = msc_ho_fsm_required_onenter,
	},
	[MSC_HO_ST_WAIT_REQUEST_ACK] = {
		.name = OSMO_STRINGIFY(MSC_HO_ST_WAIT_REQUEST_ACK),
		.in_event_mask = 0
			| S(MSC_HO_EV_RX_REQUEST_ACK)
			| S(MSC_HO_EV_RX_FAILURE)
			,
		.out_state_mask = 0
			| S(MSC_HO_ST_REQUIRED)
			| S(MSC_HO_ST_WAIT_COMPLETE)
			,
		.onenter = msc_ho_fsm_wait_request_ack_onenter,
		.action = msc_ho_fsm_wait_request_ack,
	},
	[MSC_HO_ST_WAIT_COMPLETE] = {
		.name = OSMO_STRINGIFY(MSC_HO_ST_WAIT_COMPLETE),
		.in_event_mask = 0
			| S(MSC_HO_EV_RX_DETECT)
			| S(MSC_HO_EV_RX_COMPLETE)
			| S(MSC_HO_EV_RX_FAILURE)
			| S(MSC_HO_EV_MNCC_FORWARDING_COMPLETE)
			| S(MSC_HO_EV_MNCC_FORWARDING_FAILED)
			,
		.action = msc_ho_fsm_wait_complete,
	},
};

static const struct value_string msc_ho_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSC_HO_EV_RX_REQUEST_ACK),
	OSMO_VALUE_STRING(MSC_HO_EV_RX_DETECT),
	OSMO_VALUE_STRING(MSC_HO_EV_RX_COMPLETE),
	OSMO_VALUE_STRING(MSC_HO_EV_RX_FAILURE),
	{}
};

struct osmo_fsm msc_ho_fsm = {
	.name = "handover",
	.states = msc_ho_fsm_states,
	.num_states = ARRAY_SIZE(msc_ho_fsm_states),
	.log_subsys = DHO,
	.event_names = msc_ho_fsm_event_names,
	.timer_cb = msc_ho_fsm_timer_cb,
	.cleanup = msc_ho_fsm_cleanup,
};
