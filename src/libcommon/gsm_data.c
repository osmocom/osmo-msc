/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
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
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/bsc_msc_data.h>
#include <osmocom/msc/abis_nm.h>

void *tall_bsc_ctx;

static LLIST_HEAD(bts_models);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss)
{
	ts->e1_link.e1_nr = e1_nr;
	ts->e1_link.e1_ts = e1_ts;
	ts->e1_link.e1_ts_ss = e1_ts_ss;
}

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"sysmocom sysmoBTS" },
	{ 0,				NULL }
};

struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->nr == nr)
			return trx;
	}
	return NULL;
}

/* Search for a BTS in the given Location Area; optionally start searching
 * with start_bts (for continuing to search after the first result) */
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts)
{
	int i;
	struct gsm_bts *bts;
	int skip = 0;

	if (start_bts)
		skip = 1;

	for (i = 0; i < net->num_bts; i++) {
		bts = gsm_bts_num(net, i);

		if (skip) {
			if (start_bts == bts)
				skip = 0;
			continue;
		}

		if (lac == GSM_LAC_RESERVED_ALL_BTS || bts->location_area_code == lac)
			return bts;
	}
	return NULL;
}

static const struct value_string auth_policy_names[] = {
	{ GSM_AUTH_POLICY_CLOSED,	"closed" },
	{ GSM_AUTH_POLICY_ACCEPT_ALL,	"accept-all" },
	{ GSM_AUTH_POLICY_TOKEN,	"token" },
	{ GSM_AUTH_POLICY_REGEXP,	"regexp" },
	{ 0,				NULL }
};

enum gsm_auth_policy gsm_auth_policy_parse(const char *arg)
{
	return get_string_value(auth_policy_names, arg);
}

const char *gsm_auth_policy_name(enum gsm_auth_policy policy)
{
	return get_value_string(auth_policy_names, policy);
}

static const struct value_string rrlp_mode_names[] = {
	{ RRLP_MODE_NONE,	"none" },
	{ RRLP_MODE_MS_BASED,	"ms-based" },
	{ RRLP_MODE_MS_PREF,	"ms-preferred" },
	{ RRLP_MODE_ASS_PREF,	"ass-preferred" },
	{ 0,			NULL }
};

enum rrlp_mode rrlp_mode_parse(const char *arg)
{
	return get_string_value(rrlp_mode_names, arg);
}

const char *rrlp_mode_name(enum rrlp_mode mode)
{
	return get_value_string(rrlp_mode_names, mode);
}

static const struct value_string bts_gprs_mode_names[] = {
	{ BTS_GPRS_NONE,	"none" },
	{ BTS_GPRS_GPRS,	"gprs" },
	{ BTS_GPRS_EGPRS,	"egprs" },
	{ 0,			NULL }
};

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid)
{
	int rc;

	rc = get_string_value(bts_gprs_mode_names, arg);
	if (valid)
		*valid = rc != -EINVAL;
	return rc;
}

const char *bts_gprs_mode_name(enum bts_gprs_mode mode)
{
	return get_value_string(bts_gprs_mode_names, mode);
}

void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts)
{
	raid->mcc = bts->network->country_code;
	raid->mnc = bts->network->network_code;
	raid->lac = bts->location_area_code;
	raid->rac = bts->gprs.rac;
}

int gsm48_ra_id_by_bts(uint8_t *buf, struct gsm_bts *bts)
{
	struct gprs_ra_id raid;

	gprs_ra_id_by_bts(&raid, bts);

	return gsm48_construct_ra(buf, &raid);
}

int gsm_parse_reg(void *ctx, regex_t *reg, char **str, int argc, const char **argv)
{
	int ret;

	ret = 0;
	if (*str) {
		talloc_free(*str);
		*str = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*str = talloc_strdup(ctx, argv[0]);
		ret = regcomp(reg, argv[0], 0);

		/* handle compilation failures */
		if (ret != 0) {
			talloc_free(*str);
			*str = NULL;
		}
	}

	return ret;
}

/* Assume there are only 256 possible bts */
osmo_static_assert(sizeof(((struct gsm_bts *) 0)->nr) == 1, _bts_nr_is_256);

bool classmark_is_r99(struct gsm_classmark *cm)
{
	int rev_lev = 0;
	if (cm->classmark1_set)
		rev_lev = cm->classmark1.rev_lev;
	else if (cm->classmark2_len > 0)
		rev_lev = (cm->classmark2[0] >> 5) & 0x3;
	return rev_lev >= 2;
}

const struct value_string ran_type_names[] = {
	OSMO_VALUE_STRING(RAN_UNKNOWN),
	OSMO_VALUE_STRING(RAN_GERAN_A),
	OSMO_VALUE_STRING(RAN_UTRAN_IU),
	{ 0, NULL }
};
