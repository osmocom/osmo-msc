/* Filter/overlay bearer service selections across MS, RAN and CN limitations */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Oliver Smith
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

#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/csd_filter.h>

static void add_all_geran_bs(struct csd_bs_list *list)
{
	/* See 3GPP TS 122.002 Bearer Services */
	/* In order of preference. TODO: make configurable */

	/* GSM-R */
	csd_bs_list_add_bs(list, CSD_BS_24_T_V110_2k4);
	csd_bs_list_add_bs(list, CSD_BS_25_T_V110_4k8);
	csd_bs_list_add_bs(list, CSD_BS_26_T_V110_9k6);

	/* Other */
	csd_bs_list_add_bs(list, CSD_BS_21_T_V110_0k3);
	csd_bs_list_add_bs(list, CSD_BS_22_T_V110_1k2);
	csd_bs_list_add_bs(list, CSD_BS_21_NT_V110_0k3);
	csd_bs_list_add_bs(list, CSD_BS_22_NT_V110_1k2);
	csd_bs_list_add_bs(list, CSD_BS_24_NT_V110_2k4);
	csd_bs_list_add_bs(list, CSD_BS_25_NT_V110_4k8);
	csd_bs_list_add_bs(list, CSD_BS_26_NT_V110_9k6);
	csd_bs_list_add_bs(list, CSD_BS_31_T_V110_1k2);
	csd_bs_list_add_bs(list, CSD_BS_32_T_V110_2k4);
	csd_bs_list_add_bs(list, CSD_BS_33_T_V110_4k8);
	csd_bs_list_add_bs(list, CSD_BS_34_T_V110_9k6);
}

static void add_all_utran_bs(struct csd_bs_list *list)
{
	/* See 3GPP TS 122.002 Bearer Services */
	/* In order of preference. TODO: make configurable */
	csd_bs_list_add_bs(list, CSD_BS_21_NT_V110_0k3);
	csd_bs_list_add_bs(list, CSD_BS_22_NT_V110_1k2);
	csd_bs_list_add_bs(list, CSD_BS_24_NT_V110_2k4);
	csd_bs_list_add_bs(list, CSD_BS_25_NT_V110_4k8);
	csd_bs_list_add_bs(list, CSD_BS_26_NT_V110_9k6);
}

void csd_filter_set_ran(struct csd_filter *filter, enum osmo_rat_type ran_type)
{
	filter->ran = (struct csd_bs_list){};

	switch (ran_type) {
	default:
	case OSMO_RAT_GERAN_A:
		add_all_geran_bs(&filter->ran);
		break;
	case OSMO_RAT_UTRAN_IU:
		add_all_utran_bs(&filter->ran);
		break;
	}
}

int csd_filter_run(struct csd_filter *filter, struct sdp_msg *result, const struct sdp_msg *remote)
{
	struct csd_bs_list *r = &result->bearer_services;
	enum csd_bs a = filter->assignment;

	*r = filter->ran;

	if (filter->ms.count)
		csd_bs_list_intersection(r, &filter->ms);
	if (filter->bss.count)
		csd_bs_list_intersection(r, &filter->bss);
	if (remote->bearer_services.count)
		csd_bs_list_intersection(r, &remote->bearer_services);

	/* Future: If osmo-msc were able to trigger a re-assignment [...] see
	 * comment in codec_filter_run(). */

	if (a) {
		*r = (struct csd_bs_list){};
		csd_bs_list_add_bs(r, a);
	}

	result->audio_codecs.count = 1;
	result->audio_codecs.codec[0] = (struct sdp_audio_codec){
		.payload_type = CODEC_CLEARMODE,
		.subtype_name = "CLEARMODE",
		.rate = 8000,
	};

	return 0;
}


int csd_filter_to_str_buf(char *buf, size_t buflen, const struct csd_filter *filter,
			    const struct sdp_msg *result, const struct sdp_msg *remote)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_APPEND(sb, sdp_msg_to_str_buf, result);
	OSMO_STRBUF_PRINTF(sb, " (from:");

	if (filter->assignment) {
		OSMO_STRBUF_PRINTF(sb, " assigned=");
		OSMO_STRBUF_APPEND(sb, csd_bs_to_str_buf, filter->assignment);
	}

	if (remote->bearer_services.count || osmo_sockaddr_str_is_nonzero(&remote->rtp)) {
		OSMO_STRBUF_PRINTF(sb, " remote=");
		OSMO_STRBUF_APPEND(sb, sdp_msg_to_str_buf, remote);
	}

	if (filter->ms.count) {
		OSMO_STRBUF_PRINTF(sb, " MS={");
		OSMO_STRBUF_APPEND(sb, csd_bs_list_to_str_buf, &filter->ms);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	if (filter->bss.count) {
		OSMO_STRBUF_PRINTF(sb, " bss={");
		OSMO_STRBUF_APPEND(sb, csd_bs_list_to_str_buf, &filter->bss);
		OSMO_STRBUF_PRINTF(sb, "}");
	}

	OSMO_STRBUF_PRINTF(sb, " RAN={");
	OSMO_STRBUF_APPEND(sb, csd_bs_list_to_str_buf, &filter->ran);
	OSMO_STRBUF_PRINTF(sb, "}");

	OSMO_STRBUF_PRINTF(sb, ")");

	return sb.chars_needed;
}

char *csd_filter_to_str_c(void *ctx, const struct csd_filter *filter, const struct sdp_msg *result, const struct sdp_msg *remote)
{
	OSMO_NAME_C_IMPL(ctx, 128, "csd_filter_to_str_c-ERROR", csd_filter_to_str_buf, filter, result, remote)
}

const char *csd_filter_to_str(const struct csd_filter *filter, const struct sdp_msg *result, const struct sdp_msg *remote)
{
	return csd_filter_to_str_c(OTC_SELECT, filter, result, remote);
}
