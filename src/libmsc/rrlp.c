/* Radio Resource LCS (Location) Protocol, GMS TS 04.31 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>

#include <osmocom/core/utils.h>

#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/msc_a.h>

/* RRLP msPositionReq, nsBased,
 *	Accuracy=60, Method=gps, ResponseTime=2, oneSet */
static const uint8_t ms_based_pos_req[] = { 0x40, 0x01, 0x78, 0xa8 };

/* RRLP msPositionReq, msBasedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ms_pref_pos_req[]  = { 0x40, 0x02, 0x79, 0x50 };

/* RRLP msPositionReq, msAssistedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ass_pref_pos_req[] = { 0x40, 0x03, 0x79, 0x50 };

static const struct value_string rrlp_mode_names[] = {
	{ RRLP_MODE_NONE,	"none" },
	{ RRLP_MODE_MS_BASED,	"ms-based" },
	{ RRLP_MODE_MS_PREF,	"ms-preferred" },
	{ RRLP_MODE_ASS_PREF,	"ass-preferred" },
	{ 0,			NULL }
};

enum rrlp_mode msc_rrlp_mode_parse(const char *arg)
{
	return get_string_value(rrlp_mode_names, arg);
}

const char *msc_rrlp_mode_name(enum rrlp_mode mode)
{
	return get_value_string(rrlp_mode_names, mode);
}

static int send_rrlp_req(struct msc_a *msc_a)
{
	struct gsm_network *net = msc_a_net(msc_a);
	const uint8_t *req;

	switch (net->rrlp.mode) {
	case RRLP_MODE_MS_BASED:
		req = ms_based_pos_req;
		break;
	case RRLP_MODE_MS_PREF:
		req = ms_pref_pos_req;
		break;
	case RRLP_MODE_ASS_PREF:
		req = ass_pref_pos_req;
		break;
	case RRLP_MODE_NONE:
	default:
		return 0;
	}

	LOG_MSC_A_CAT(msc_a, DRR, LOGL_INFO, "Sending '%s' RRLP position request\n", msc_rrlp_mode_name(net->rrlp.mode));

	return gsm48_send_rr_app_info(msc_a, 0x00, sizeof(ms_based_pos_req), req);
}

static int subscr_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct vlr_subscr *vsub;
	struct msc_a *msc_a;

	switch (signal) {
	case S_SUBSCR_ATTACHED:
		/* A subscriber has attached. */
		vsub = signal_data;
		msc_a = msc_a_for_vsub(vsub, true);
		if (!msc_a)
			break;
		send_rrlp_req(msc_a);
		break;
	}
	return 0;
}

static int paging_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct paging_signal_data *psig_data = signal_data;

	switch (signal) {
	case S_PAGING_SUCCEEDED:
		/* A subscriber has attached. */
		send_rrlp_req(psig_data->msc_a);
		break;
	case S_PAGING_EXPIRED:
		break;
	}
	return 0;
}

void msc_rrlp_init(void)
{
	osmo_signal_register_handler(SS_SUBSCR, subscr_sig_cb, NULL);
	osmo_signal_register_handler(SS_PAGING, paging_sig_cb, NULL);
}
