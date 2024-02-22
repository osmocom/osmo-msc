/* Minimalistic SDP parse/compose implementation, focused on GSM audio codecs */
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

#include <osmocom/msc/sdp_msg.h>

static const struct osmo_sdp_codec codec_csd = {
	.payload_type = CODEC_CLEARMODE,
	.encoding_name = "CLEARMODE",
	.rate = 8000,
};

void sdp_codecs_set_csd(void *ctx, struct osmo_sdp_codec_list *codecs)
{
	osmo_sdp_codec_list_free(codecs);
	osmo_sdp_codec_list_add(ctx, &codec_csd);
}
