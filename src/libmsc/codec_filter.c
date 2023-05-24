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
#include <osmocom/msc/debug.h>

/* Add all known payload types encountered in GSM networks */
static void sdp_add_all_geran_codecs(struct sdp_audio_codecs *ac)
{
	/* In order of preference. TODO: make configurable */
	static const enum gsm48_bcap_speech_ver mobile_codecs[] = {
		GSM48_BCAP_SV_AMR_F	/*!< 4   GSM FR V3 (FR AMR) */,
		GSM48_BCAP_SV_AMR_H	/*!< 5   GSM HR V3 (HR_AMR) */,
		GSM48_BCAP_SV_EFR	/*!< 2   GSM FR V2 (GSM EFR) */,
		GSM48_BCAP_SV_FR	/*!< 0   GSM FR V1 (GSM FR) */,
		GSM48_BCAP_SV_HR	/*!< 1   GSM HR V1 (GSM HR) */,
	};
	int i;
	for (i = 0; i < ARRAY_SIZE(mobile_codecs); i++)
		sdp_audio_codecs_add_speech_ver(ac, mobile_codecs[i]);
}

/* Add all known AMR payload types encountered in UTRAN networks */
static void sdp_add_all_utran_codecs(struct sdp_audio_codecs *ac)
{
	/* In order of preference. TODO: make configurable */
	static const enum gsm48_bcap_speech_ver utran_codecs[] = {
		GSM48_BCAP_SV_AMR_F	/*!< 4   GSM FR V3 (FR AMR) */,
		GSM48_BCAP_SV_AMR_H	/*!< 5   GSM HR V3 (HR_AMR) */,
		GSM48_BCAP_SV_AMR_OH	/*!< 11  GSM HR V6 (OHR AMR) */,
		GSM48_BCAP_SV_AMR_FW	/*!< 8   GSM FR V5 (FR AMR-WB) */,
		GSM48_BCAP_SV_AMR_OFW	/*!< 6   GSM FR V4 (OFR AMR-WB) */,
		GSM48_BCAP_SV_AMR_OHW	/*!< 7   GSM HR V4 (OHR AMR-WB) */,
	};
	int i;
	for (i = 0; i < ARRAY_SIZE(utran_codecs); i++)
		sdp_audio_codecs_add_speech_ver(ac, utran_codecs[i]);
}

void codec_filter_set_ran(struct codec_filter *codec_filter, enum osmo_rat_type ran_type)
{
	codec_filter->ran = (struct sdp_audio_codecs){};

	switch (ran_type) {
	default:
	case OSMO_RAT_GERAN_A:
		sdp_add_all_geran_codecs(&codec_filter->ran);
		break;

	case OSMO_RAT_UTRAN_IU:
		sdp_add_all_utran_codecs(&codec_filter->ran);
		break;
	}
}

void codec_filter_set_bss(struct codec_filter *codec_filter,
			  const struct gsm0808_speech_codec_list *codec_list_bss_supported)
{
	codec_filter->bss = (struct sdp_audio_codecs){};
	if (codec_list_bss_supported)
		sdp_audio_codecs_from_speech_codec_list(&codec_filter->bss, codec_list_bss_supported);
}

/* Render intersections of all known audio codec constraints to reach a resulting choice of favorite audio codec, plus
 * possible set of alternative audio codecs, in codec_filter->result. (The result.rtp address remains unchanged.) */
int codec_filter_run(struct codec_filter *codec_filter, struct sdp_msg *result, const struct sdp_msg *remote)
{
	struct sdp_audio_codecs *r = &result->audio_codecs;
	struct sdp_audio_codec *a = &codec_filter->assignment;
	*r = codec_filter->ran;
	if (codec_filter->ms.count)
		sdp_audio_codecs_intersection(r, &codec_filter->ms, false);
	if (codec_filter->bss.count)
		sdp_audio_codecs_intersection(r, &codec_filter->bss, false);
	if (remote->audio_codecs.count)
		sdp_audio_codecs_intersection(r, &remote->audio_codecs, true);

#if 0
	/* Future: If osmo-msc were able to trigger a re-assignment after the remote side has picked a codec mismatching
	 * the initial Assignment, then this code here would make sense: keep the other codecs as available to choose
	 * from, but put the currently assigned codec in the first position. So far we only offer the single assigned
	 * codec, because we have no way to deal with the remote side picking a different codec.
	 * Another approach would be to postpone assignment until we know the codecs from the remote side. */
	if (sdp_audio_codec_is_set(a)) {
		/* Assignment has completed, the chosen codec should be the first of the resulting SDP.
		 * Make sure this is actually listed in the result SDP and move to first place. */
		struct sdp_audio_codec *select = sdp_audio_codecs_by_descr(r, a);

		if (!select) {
			/* Not present. Add. */
			if (sdp_audio_codec_by_payload_type(r, a->payload_type, false)) {
				/* Oh crunch, that payload type number is already in use.
				 * Find an unused one. */
				for (a->payload_type = 96; a->payload_type <= 127; a->payload_type++) {
					if (!sdp_audio_codec_by_payload_type(r, a->payload_type, false))
						break;
				}

				if (a->payload_type > 127)
					return -ENOSPC;
			}
			select = sdp_audio_codecs_add_copy(r, a);
		}

		sdp_audio_codecs_select(r, select);
	}
#else
	/* Currently, osmo-msc does not trigger re-assignment if the remote side has picked a codec that is different
	 * from the already assigned codec.
	 * So, if locally, Assignment has already chosen a codec, this is the single definitive result to be used
	 * towards the CN. */
	if (sdp_audio_codec_is_set(a)) {
		/* Assignment has completed, the chosen codec should be the the only possible one. */
		*r = (struct sdp_audio_codecs){};
		sdp_audio_codecs_add_copy(r, a);
	}
#endif
	return 0;
}

int codec_filter_to_str_buf(char *buf, size_t buflen, const struct codec_filter *codec_filter,
			    const struct sdp_msg *result, const struct sdp_msg *remote)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_APPEND(sb, sdp_msg_to_str_buf, result);
	OSMO_STRBUF_PRINTF(sb, " (from:");

	if (sdp_audio_codec_is_set(&codec_filter->assignment)) {
		OSMO_STRBUF_PRINTF(sb, " assigned=");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codec_to_str_buf, &codec_filter->assignment);
	}

	if (remote->audio_codecs.count
	    || osmo_sockaddr_str_is_nonzero(&remote->rtp)) {
		OSMO_STRBUF_PRINTF(sb, " remote=");
		OSMO_STRBUF_APPEND(sb, sdp_msg_to_str_buf, remote);
	}

	if (codec_filter->ms.count) {
		OSMO_STRBUF_PRINTF(sb, " MS={");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_to_str_buf, &codec_filter->ms);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	if (codec_filter->bss.count) {
		OSMO_STRBUF_PRINTF(sb, " bss={");
		OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_to_str_buf, &codec_filter->bss);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	OSMO_STRBUF_PRINTF(sb, " RAN={");
	OSMO_STRBUF_APPEND(sb, sdp_audio_codecs_to_str_buf, &codec_filter->ran);
	OSMO_STRBUF_PRINTF(sb, "}");

	OSMO_STRBUF_PRINTF(sb, ")");

	return sb.chars_needed;
}

char *codec_filter_to_str_c(void *ctx, const struct codec_filter *codec_filter, const struct sdp_msg *result,
			    const struct sdp_msg *remote)
{
	OSMO_NAME_C_IMPL(ctx, 128, "codec_filter_to_str_c-ERROR", codec_filter_to_str_buf, codec_filter, result, remote)
}

const char *codec_filter_to_str(const struct codec_filter *codec_filter, const struct sdp_msg *result,
				const struct sdp_msg *remote)
{
	return codec_filter_to_str_c(OTC_SELECT, codec_filter, result, remote);
}
