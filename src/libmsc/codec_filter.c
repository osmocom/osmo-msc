/* Filter/overlay codec selections for a voice call, across MS, RAN and CN limitations */
/*
 * (C) 2019-2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: AGPL-3.0+
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

#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/msc/codec_filter.h>
#include <osmocom/msc/codec_mapping.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/debug.h>

static void ensure_empty_list(void *ctx, struct osmo_sdp_codec_list **codecs)
{
	if (*codecs)
		osmo_sdp_codec_list_free_items(*codecs);
	else
		*codecs = osmo_sdp_codec_list_alloc(ctx);
}

void codec_filter_set_ran(struct codec_filter *codec_filter, const struct osmo_sdp_codec_list *codecs)
{
	const struct osmo_sdp_codec *c;
	ensure_empty_list(codec_filter, &codec_filter->ran);
	/* Add codecs one by one, to resolve any payload type number conflicts or duplicates. */
	osmo_sdp_codec_list_foreach (c, codecs)
		osmo_sdp_codec_list_add(codec_filter->ran, c, &osmo_sdp_codec_cmp_equivalent, true);
}

void codec_filter_set_bss(struct codec_filter *codec_filter,
			  const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	ensure_empty_list(codec_filter, &codec_filter->bss);
	if (codec_list_bss_supported)
		sdp_audio_codecs_from_speech_codec_list(codec_filter->bss, codec_list_bss_supported);
}

/* Render intersections of all known audio codec constraints to reach a resulting choice of favorite audio codec, plus
 * possible set of alternative audio codecs, in codec_filter->result. (The result.rtp address remains unchanged.) */
int codec_filter_run(struct codec_filter *codec_filter, struct osmo_sdp_msg *result, const struct osmo_sdp_msg *remote)
{
	struct osmo_sdp_codec_list *r;
	struct osmo_sdp_codec *c;
	struct osmo_sdp_codec *a = codec_filter->assignment;

	ensure_empty_list(result, &result->codecs);
	r = result->codecs;
	osmo_sdp_codec_list_foreach (c, codec_filter->ran) {
		osmo_sdp_codec_list_add(r, c, &osmo_sdp_codec_cmp_equivalent, true);
	}

	if (!osmo_sdp_codec_list_is_empty(codec_filter->ms))
		osmo_sdp_codec_list_intersection(r, codec_filter->ms, &osmo_sdp_codec_cmp_equivalent, false);
	if (!osmo_sdp_codec_list_is_empty(codec_filter->bss))
		osmo_sdp_codec_list_intersection(r, codec_filter->bss, &osmo_sdp_codec_cmp_equivalent, false);
	if (!osmo_sdp_codec_list_is_empty(remote->codecs))
		osmo_sdp_codec_list_intersection(r, remote->codecs, &osmo_sdp_codec_cmp_equivalent, false);

	if (osmo_sdp_codec_is_set(a)) {
		/* Assignment has completed, the chosen codec should be the first of the resulting SDP.
		 * If present, make sure this is listed in first place.
		 * If the assigned codec is not present in the intersection of possible choices for TrFO, just omit the
		 * assigned codec from the filter result, and it is the CC code's responsibility to detect this and
		 * assign a working codec instead. */
		osmo_sdp_codec_list_move_to_first(r, a, &osmo_sdp_codec_cmp_equivalent);
	} else if (remote && !osmo_sdp_codec_list_is_empty(remote->codecs)) {
		/* If we haven't assigned yet, favor remote's first pick. Assume that the remote side has placed its
		 * favorite codec up first. Remote may already have assigned a codec, and picking a different one might
		 * trigger a change of codec mode (Re-Assignment). So try to adhere to the first codec listed. */
		osmo_sdp_codec_list_move_to_first(r, osmo_sdp_codec_list_first(remote->codecs),
						  &osmo_sdp_codec_cmp_equivalent);
	}
	return 0;
}

int codec_filter_to_str_buf(char *buf, size_t buflen, const struct codec_filter *codec_filter,
			    const struct osmo_sdp_msg *result, const struct osmo_sdp_msg *remote)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_APPEND(sb, osmo_sdp_msg_to_str_buf, result, false);
	OSMO_STRBUF_PRINTF(sb, " (from:");

	if (osmo_sdp_codec_is_set(codec_filter->assignment)) {
		OSMO_STRBUF_PRINTF(sb, " assigned=");
		OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_to_str_buf, codec_filter->assignment);
	}

	if (!osmo_sdp_codec_list_is_empty(remote->codecs)
	    || osmo_sockaddr_str_is_nonzero(&remote->rtp)) {
		OSMO_STRBUF_PRINTF(sb, " remote=");
		OSMO_STRBUF_APPEND(sb, osmo_sdp_msg_to_str_buf, remote, true);
	}

	if (!osmo_sdp_codec_list_is_empty(codec_filter->ms)) {
		OSMO_STRBUF_PRINTF(sb, " MS={");
		OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_list_to_str_buf, codec_filter->ms, true);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	if (!osmo_sdp_codec_list_is_empty(codec_filter->bss)) {
		OSMO_STRBUF_PRINTF(sb, " bss={");
		OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_list_to_str_buf, codec_filter->bss, true);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	OSMO_STRBUF_PRINTF(sb, " RAN={");
	OSMO_STRBUF_APPEND(sb, osmo_sdp_codec_list_to_str_buf, codec_filter->ran, true);
	OSMO_STRBUF_PRINTF(sb, "}");

	OSMO_STRBUF_PRINTF(sb, ")");

	return sb.chars_needed;
}

char *codec_filter_to_str_c(void *ctx, const struct codec_filter *codec_filter, const struct osmo_sdp_msg *result,
			    const struct osmo_sdp_msg *remote)
{
	OSMO_NAME_C_IMPL(ctx, 128, "codec_filter_to_str_c-ERROR", codec_filter_to_str_buf, codec_filter, result, remote)
}

const char *codec_filter_to_str(const struct codec_filter *codec_filter, const struct osmo_sdp_msg *result,
				const struct osmo_sdp_msg *remote)
{
	return codec_filter_to_str_c(OTC_SELECT, codec_filter, result, remote);
}
