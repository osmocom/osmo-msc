/* Filter/overlay codec selections for a voice call, across MS, RAN and CN limitations */
/*
 * (C) 2019-2022 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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
#pragma once

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/mncc.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/sdp_msg.h>

struct osmo_sockaddr;
struct gsm0808_speech_codec_list;

/* Combine various codec selections to obtain a resulting set of codecs allowed by all of them.
 * Members reflect the different entities/stages that select codecs in a voice call.
 * Call codec_filter_run() and obtain the resulting set of codecs in codec_filter.result. */
struct codec_filter {
	/* The fixed set of codecs available on the RAN type, per definition. */
	struct sdp_audio_codecs ran;
	/* The codecs advertised by the MS Bearer Capabilities */
	struct sdp_audio_codecs ms;
	/* If known, the set of codecs the current RAN cell allows / has available.
	 * This may not be available if the BSC does not issue this information early enough.
	 * Should be ignored if empty. */
	struct sdp_audio_codecs bss;

	/* SDP as last received from the remote call leg. */
	struct sdp_msg remote;

	/* After a channel was assigned, this reflects the chosen codec. */
	struct sdp_audio_codec assignment;

	/* Resulting choice of supported codecs, usually the intersection of the above,
	 * and the local RTP address to be sent to the remote call leg.
	 * The RTP address:port in result.rtp is not modified by codec_filter_run() -- set it once. */
	struct sdp_msg result;
};

void codec_filter_init(struct codec_filter *codec_filter);
void codec_filter_set_ran(struct codec_filter *codec_filter, enum osmo_rat_type ran_type);
void codec_filter_set_ms_from_bc(struct codec_filter *codec_filter, const struct gsm_mncc_bearer_cap *ms_bearer_cap);
void codec_filter_set_bss(struct codec_filter *codec_filter,
			  const struct gsm0808_speech_codec_list *codec_list_bss_supported);
int codec_filter_set_remote(struct codec_filter *codec_filter, const char *remote_sdp);
int codec_filter_set_remote_rtp_osa(struct codec_filter *codec_filter, const struct osmo_sockaddr *rtp);
int codec_filter_set_remote_codec_pt(struct codec_filter *codec_filter, enum mgcp_codecs pt);
void codec_filter_set_local_rtp(struct codec_filter *codec_filter, const struct osmo_sockaddr_str *rtp);
int codec_filter_run(struct codec_filter *codec_filter);

int codec_filter_to_str_buf(char *buf, size_t buflen, const struct codec_filter *codec_filter);
char *codec_filter_to_str_c(void *ctx, const struct codec_filter *codec_filter);
const char *codec_filter_to_str(const struct codec_filter *codec_filter);
