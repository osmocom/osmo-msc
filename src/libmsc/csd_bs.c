/* 3GPP TS 122.002 Bearer Services */
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
#include <errno.h>

#include <osmocom/msc/csd_bs.h>
#include <osmocom/msc/debug.h>

/* csd_bs related below */

struct csd_bs_map {
	/* BS number (20, 21, ...) */
	unsigned int num;
	/* Access Structure (1: asynchronous, 0: synchronous) */
	bool async;
	/* QoS Attribute (1: transparent, 0: non-transparent) */
	bool transp;
	/* Rate Adaption (V110, V120 etc.) */
	enum gsm48_bcap_ra ra;
	/* Fixed Network User Rate */
	unsigned int rate;
};

static const struct csd_bs_map bs_map[] = {
	/* 3.1.1.1.2 */
	[CSD_BS_21_T_V110_0k3] = {
		.num = 21,
		.async = true,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 300,
	},
	[CSD_BS_22_T_V110_1k2] = {
		.num = 22,
		.async = true,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 1200,
	},
	[CSD_BS_24_T_V110_2k4] = {
		.num = 24,
		.async = true,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 2400,
	},
	[CSD_BS_25_T_V110_4k8] = {
		.num = 25,
		.async = true,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 4800,
	},
	[CSD_BS_26_T_V110_9k6] = {
		.num = 26,
		.async = true,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 9600,
	},

	/* 3.1.1.2.2 */
	[CSD_BS_21_NT_V110_0k3] = {
		.num = 21,
		.async = true,
		.transp = false,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 300,
	},
	[CSD_BS_22_NT_V110_1k2] = {
		.num = 22,
		.async = true,
		.transp = false,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 1200,
	},
	[CSD_BS_24_NT_V110_2k4] = {
		.num = 24,
		.async = true,
		.transp = false,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 2400,
	},
	[CSD_BS_25_NT_V110_4k8] = {
		.num = 25,
		.async = true,
		.transp = false,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 4800,
	},
	[CSD_BS_26_NT_V110_9k6] = {
		.num = 26,
		.async = true,
		.transp = false,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 9600,
	},

	/* 3.1.2.1.2 */
	[CSD_BS_31_T_V110_1k2] = {
		.num = 31,
		.async = false,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 1200,
	},
	[CSD_BS_32_T_V110_2k4] = {
		.num = 32,
		.async = false,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 2400,
	},
	[CSD_BS_33_T_V110_4k8] = {
		.num = 33,
		.async = false,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 4800,
	},
	[CSD_BS_34_T_V110_9k6] = {
		.num = 34,
		.async = false,
		.transp = true,
		.ra = GSM48_BCAP_RA_V110_X30,
		.rate = 9600,
	},
};

osmo_static_assert(ARRAY_SIZE(bs_map) == CSD_BS_MAX, _invalid_size_bs_map);

bool csd_bs_is_transp(enum csd_bs bs)
{
	return bs_map[bs].transp;
}

/* Short single-line representation, convenient for logging.
 * Like "BS25NT" */
int csd_bs_to_str_buf(char *buf, size_t buflen, enum csd_bs bs)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	const struct csd_bs_map *map = &bs_map[bs];

	OSMO_STRBUF_PRINTF(sb, "BS%u%s",
			   map->num,
			   map->transp ? "T" : "NT");

	if (map->ra != GSM48_BCAP_RA_V110_X30)
		OSMO_STRBUF_PRINTF(sb, "-RA=%d", map->ra);

	return sb.chars_needed;
}

char *csd_bs_to_str_c(void *ctx, enum csd_bs bs)
{
	OSMO_NAME_C_IMPL(ctx, 32, "csd_bs_to_str_c-ERROR", csd_bs_to_str_buf, bs)
}

const char *csd_bs_to_str(enum csd_bs bs)
{
	return csd_bs_to_str_c(OTC_SELECT, bs);
}

static int csd_bs_to_gsm0808_data_rate_transp(enum csd_bs bs, uint8_t *ch_rate_type)
{
	switch (bs_map[bs].rate) {
	case 300:
		*ch_rate_type = GSM0808_DATA_FULL_PREF;
		return GSM0808_DATA_RATE_TRANSP_600;
	case 1200:
		*ch_rate_type = GSM0808_DATA_FULL_PREF;
		return GSM0808_DATA_RATE_TRANSP_1k2;
	case 2400:
		*ch_rate_type = GSM0808_DATA_FULL_PREF;
		return GSM0808_DATA_RATE_TRANSP_2k4;
	case 4800:
		*ch_rate_type = GSM0808_DATA_FULL_PREF;
		return GSM0808_DATA_RATE_TRANSP_4k8;
	case 9600:
		*ch_rate_type = GSM0808_DATA_FULL_BM;
		return GSM0808_DATA_RATE_TRANSP_9k6;
	}
	return -EINVAL;
}

static int csd_bs_to_gsm0808_data_rate_non_transp(enum csd_bs bs, uint8_t *ch_rate_type)
{
	uint16_t rate = bs_map[bs].rate;

	if (rate < 6000) {
		*ch_rate_type = GSM0808_DATA_FULL_PREF;
		return GSM0808_DATA_RATE_NON_TRANSP_6k0;
	}
	if (rate < 12000) {
		*ch_rate_type = GSM0808_DATA_FULL_BM;
		return GSM0808_DATA_RATE_NON_TRANSP_12k0;
	}

	return -EINVAL;
}

static int csd_bs_to_gsm0808_data_rate_non_transp_allowed(enum csd_bs bs)
{
	uint16_t rate = bs_map[bs].rate;

	if (rate < 6000)
		return GSM0808_DATA_RATE_NON_TRANSP_ALLOWED_6k0;
	if (rate < 12000)
		return GSM0808_DATA_RATE_NON_TRANSP_ALLOWED_12k0;

	return -EINVAL;
}

enum csd_bs csd_bs_from_bearer_cap(const struct gsm_mncc_bearer_cap *cap, bool transp)
{
	enum gsm48_bcap_ra ra = cap->data.rate_adaption;
	enum gsm48_bcap_user_rate rate = cap->data.user_rate;
	bool async = cap->data.async;

	if (ra == GSM48_BCAP_RA_V110_X30 && async && transp) {
		switch (rate) {
		case GSM48_BCAP_UR_300:
			return CSD_BS_21_T_V110_0k3;
		case GSM48_BCAP_UR_1200:
			return CSD_BS_22_T_V110_1k2;
		case GSM48_BCAP_UR_2400:
			return CSD_BS_24_T_V110_2k4;
		case GSM48_BCAP_UR_4800:
			return CSD_BS_25_T_V110_4k8;
		case GSM48_BCAP_UR_9600:
			return CSD_BS_26_T_V110_9k6;
		default:
			return CSD_BS_NONE;
		}
	}

	if (ra == GSM48_BCAP_RA_V110_X30 && async && !transp) {
		switch (rate) {
		case GSM48_BCAP_UR_300:
			return CSD_BS_21_NT_V110_0k3;
		case GSM48_BCAP_UR_1200:
			return CSD_BS_22_NT_V110_1k2;
		case GSM48_BCAP_UR_2400:
			return CSD_BS_24_NT_V110_2k4;
		case GSM48_BCAP_UR_4800:
			return CSD_BS_25_NT_V110_4k8;
		case GSM48_BCAP_UR_9600:
			return CSD_BS_26_NT_V110_9k6;
		default:
			return CSD_BS_NONE;
		}
	}

	if (ra == GSM48_BCAP_RA_V110_X30 && !async && transp) {
		switch (rate) {
		case GSM48_BCAP_UR_1200:
			return CSD_BS_31_T_V110_1k2;
		case GSM48_BCAP_UR_2400:
			return CSD_BS_32_T_V110_2k4;
		case GSM48_BCAP_UR_4800:
			return CSD_BS_33_T_V110_4k8;
		case GSM48_BCAP_UR_9600:
			return CSD_BS_34_T_V110_9k6;
		default:
			return CSD_BS_NONE;
		}
	}

	return CSD_BS_NONE;
}

/* csd_bs_list related below */

int csd_bs_list_to_str_buf(char *buf, size_t buflen, const struct csd_bs_list *list)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	int i;

	if (!list->count)
		OSMO_STRBUF_PRINTF(sb, "(no-bearer-services)");

	for (i = 0; i < list->count; i++) {
		if (i)
			OSMO_STRBUF_PRINTF(sb, ",");

		OSMO_STRBUF_APPEND(sb, csd_bs_to_str_buf, list->bs[i]);
	}
	return sb.chars_needed;
}

char *csd_bs_list_to_str_c(void *ctx, const struct csd_bs_list *list)
{
	OSMO_NAME_C_IMPL(ctx, 128, "csd_bs_list_to_str_c-ERROR", csd_bs_list_to_str_buf, list)
}

const char *csd_bs_list_to_str(const struct csd_bs_list *list)
{
	return csd_bs_list_to_str_c(OTC_SELECT, list);
}

bool csd_bs_list_has_bs(const struct csd_bs_list *list, enum csd_bs bs)
{
	int i;

	for (i = 0; i < list->count; i++) {
		if (list->bs[i] == bs)
			return true;
	}

	return false;
}

void csd_bs_list_add_bs(struct csd_bs_list *list, enum csd_bs bs)
{
	int i;

	if (!bs)
		return;

	for (i = 0; i < list->count; i++) {
		if (list->bs[i] == bs)
			return;
	}

	list->bs[i] = bs;
	list->count++;
}

void csd_bs_list_remove(struct csd_bs_list *list, enum csd_bs bs)
{
	int i;
	bool found = false;

	for (i = 0; i < list->count; i++) {
		if (list->bs[i] == bs)
			found = true;
		if (found && i + 1 < list->count)
			list->bs[i] = list->bs[i + 1];
	}

	if (found)
		list->count--;
}

void csd_bs_list_intersection(struct csd_bs_list *dest, const struct csd_bs_list *other)
{
	int i;

	for (i = 0; i < dest->count; i++) {
		if (csd_bs_list_has_bs(other, dest->bs[i]))
			continue;
		csd_bs_list_remove(dest, dest->bs[i]);
		i--;
	}
}

int csd_bs_list_to_gsm0808_channel_type(struct gsm0808_channel_type *ct, const struct csd_bs_list *list)
{
	int i;
	int rc;

	*ct = (struct gsm0808_channel_type){
		.ch_indctr = GSM0808_CHAN_DATA,
	};

	if (!list->count)
		return -EINVAL;

	if (csd_bs_is_transp(list->bs[0])) {
		ct->data_transparent = true;
		rc = csd_bs_to_gsm0808_data_rate_transp(list->bs[0], &ct->ch_rate_type);
	} else {
		rc = csd_bs_to_gsm0808_data_rate_non_transp(list->bs[0], &ct->ch_rate_type);
	}

	if (rc < 0)
		return -EINVAL;

	ct->data_rate = rc;

	/* Other possible data rates allowed (3GPP TS 48.008 § 3.2.2.11, 5a) */
	if (!ct->data_transparent && list->count > 1) {
		for (i = 1; i < list->count; i++) {
			if (!csd_bs_is_transp(list->bs[i]))
				continue;

			rc = csd_bs_to_gsm0808_data_rate_non_transp_allowed(list->bs[i]);
			if (rc < 0) {
				LOGP(DMSC, LOGL_DEBUG, "Failed to convert %s to allowed r i/f rate\n",
				     csd_bs_to_str(list->bs[i]));
				continue;
			}

			ct->data_rate_allowed |= rc;
		}
		if (ct->data_rate_allowed)
			ct->data_rate_allowed_is_set = true;
	}

	return 0;
}

int csd_bs_list_to_bearer_cap(struct gsm_mncc_bearer_cap *cap, const struct csd_bs_list *list)
{
	*cap = (struct gsm_mncc_bearer_cap){
		.transfer = GSM_MNCC_BCAP_UNR_DIG,
		.mode = GSM48_BCAP_TMOD_CIRCUIT,
		.coding = GSM48_BCAP_CODING_GSM_STD,
		.radio = GSM48_BCAP_RRQ_FR_ONLY,
	};
	enum csd_bs bs;
	int i;

	for (i = 0; i < list->count; i++) {
		bs = list->bs[i];

		cap->data.rate_adaption = GSM48_BCAP_RA_V110_X30;
		cap->data.sig_access = GSM48_BCAP_SA_I440_I450;
		cap->data.async = bs_map[bs].async;
		if (bs_map[bs].transp)
			cap->data.transp = GSM48_BCAP_TR_TRANSP;
		else
			cap->data.transp = GSM48_BCAP_TR_RLP;

		/* FIXME: proper values for sync/async (current: 8N1) */
		cap->data.nr_data_bits = 8;
		cap->data.parity = GSM48_BCAP_PAR_NONE;
		cap->data.nr_stop_bits = 1;
		cap->data.modem_type = GSM48_BCAP_MT_NONE;

		switch (bs_map[bs].rate) {
		case 300:
			cap->data.user_rate = GSM48_BCAP_UR_300;
			cap->data.interm_rate = GSM48_BCAP_IR_8k;
			break;
		case 1200:
			cap->data.user_rate = GSM48_BCAP_UR_1200;
			cap->data.interm_rate = GSM48_BCAP_IR_8k;
			break;
		case 2400:
			cap->data.user_rate = GSM48_BCAP_UR_2400;
			cap->data.interm_rate = GSM48_BCAP_IR_8k;
			break;
		case 4800:
			cap->data.user_rate = GSM48_BCAP_UR_4800;
			cap->data.interm_rate = GSM48_BCAP_IR_8k;
			break;
		case 9600:
			cap->data.user_rate = GSM48_BCAP_UR_9600;
			cap->data.interm_rate = GSM48_BCAP_IR_16k;
			break;
		default:
			LOGP(DMSC, LOGL_ERROR,
			     "%s(): bs=%d (rate=%u) is not implemented\n",
			     __func__, bs, bs_map[bs].rate);
			continue;
		}

		/* FIXME: handle more than one list entry */
		return 1;
	}

	return 0;
}

void csd_bs_list_from_bearer_cap(struct csd_bs_list *list, const struct gsm_mncc_bearer_cap *cap)
{
	*list = (struct csd_bs_list){};

	switch (cap->data.transp) {
	case GSM48_BCAP_TR_TRANSP:
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, true));
		break;
	case GSM48_BCAP_TR_RLP: /* NT */
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, false));
		break;
	case GSM48_BCAP_TR_TR_PREF:
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, true));
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, false));
		break;
	case GSM48_BCAP_TR_RLP_PREF:
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, false));
		csd_bs_list_add_bs(list, csd_bs_from_bearer_cap(cap, true));
		break;
	}

	if (!list->count) {
		LOGP(DMSC, LOGL_ERROR, "Failed to get bearer service from bearer capabilities ra=%d, async=%d,"
		     " transp=%d, user_rate=%d\n", cap->data.rate_adaption, cap->data.async, cap->data.transp,
		     cap->data.user_rate);
		return;
	}
}
