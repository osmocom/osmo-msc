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
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/msc/gsm_data.h>

void *tall_bsc_ctx;

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
