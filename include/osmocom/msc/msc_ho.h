/* MSC Handover API */
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

#pragma once

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/ran_msg.h>
#include <osmocom/msc/mncc_call.h>
#include <osmocom/msc/sdp_msg.h>

struct gsm0808_handover_required;

struct msc_a;
struct ran_dec_handover_required;

#define LOG_HO(msc_a, level, fmt, args...) \
	LOGPFSML((msc_a)? ((msc_a)->ho.fi ? : (msc_a)->c.fi) : NULL, \
		 level, "%s" fmt, (msc_a->ho.fi ? "" : "HO: "), ##args)

enum msc_ho_fsm_state {
	MSC_HO_ST_REQUIRED,
	MSC_HO_ST_WAIT_REQUEST_ACK,
	MSC_HO_ST_WAIT_COMPLETE,
};

enum msc_ho_fsm_event {
	MSC_HO_EV_RX_REQUEST_ACK,
	MSC_HO_EV_RX_DETECT,
	MSC_HO_EV_RX_COMPLETE,
	MSC_HO_EV_RX_FAILURE,
	MSC_HO_EV_MNCC_FORWARDING_COMPLETE,
	MSC_HO_EV_MNCC_FORWARDING_FAILED,
};

struct msc_ho_state {
	struct osmo_fsm_inst *fi;
	struct ran_handover_required info;
	unsigned int next_cil_idx;
	bool subsequent_ho;
	bool ready_to_switch_rtp;
	bool rtp_switched_to_new_cell;

	struct {
		enum osmo_rat_type ran_type;
		struct gsm0808_cell_id cid;
		struct osmo_cell_global_id cgi;
		enum msc_neighbor_type type;
		union {
			struct ran_peer *ran_peer;
			const char *msc_ipa_name;
		};

		/* The RTP address from Handover Request Acknowledge.
		 * Might be from AoIP Transport Layer Address from a BSC RAN peer,
		 * or from MNCC forwarding for inter-MSC handover. */
		struct osmo_sockaddr_str ran_remote_rtp;
		/* The codec from Handover Request Acknowledge. */
		bool codec_present;
		struct gsm0808_speech_codec codec;

		/* Inter-MSC voice forwarding via MNCC, to the remote MSC. The Prepare Handover Response sent us the
		 * Handover Number the remote MSC assigned. This is a call to that Handover Number, via PBX.
		 * (NULL if not an inter-MSC Handover) */
		struct mncc_call *mncc_forwarding_to_remote_ran;
	} new_cell;

	struct {
		/* Saved RTP IP:port and codec in case we need to roll back */
		struct osmo_sockaddr_str ran_remote_rtp;
		struct sdp_audio_codecs codecs;
	} old_cell;
};

void msc_ho_start(struct msc_a *msc_a, const struct ran_handover_required *ho_req);

enum msc_neighbor_type msc_ho_find_target_cell(struct msc_a *msc_a, const struct gsm0808_cell_id *cid,
					       const struct neighbor_ident_entry **remote_msc,
					       struct ran_peer **ran_peer_from_neighbor_ident,
					       struct ran_peer **ran_peer_from_seen_cells);
