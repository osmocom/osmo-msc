/* main MSC management code... */

/*
 * (C) 2010,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include "config.h"

#include <osmocom/core/tdef.h>
#include <osmocom/crypt/utran_cipher.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/gsup_client_mux.h>
#include <osmocom/msc/gsm_04_11_gsup.h>
#include <osmocom/msc/gsm_09_11.h>

/* TODO: would be great to have all timer declarations in one place */
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/call_leg.h>

struct osmo_tdef mncc_tdefs[] = {
	{}
};

struct osmo_tdef_group msc_tdef_group[] = {
	{ .name = "vlr", .tdefs = msc_tdefs_vlr, .desc = "VLR (Visitors Location Register)" },
	{ .name = "mgw", .tdefs = g_mgw_tdefs, .desc = "MGW (Media Gateway) interface" },
	{ .name = "mncc", .tdefs = mncc_tdefs, .desc = "MNCC (Mobile Network Call Control) interface" },
	{ .name = "sccp", .tdefs = g_sccp_tdefs, .desc = "SCCP (Signalling Connection Control Part)" },
	{ .name = "geran", .tdefs = msc_tdefs_geran, .desc = "GERAN (GSM EDGE Radio Access Network)" },
	{ .name = "utran", .tdefs = msc_tdefs_utran, .desc = "UTRAN (UMTS Terrestrial Radio Access Network)" },
	{ .name = "sgs", .tdefs = msc_tdefs_sgs, .desc = "SGs interface towards MME" },
	{ /* terminator */ }
};

#include <osmocom/core/stat_item.h>

struct gsm_network *gsm_network_init(void *ctx, mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net;

	net = talloc_zero(ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->plmn = (struct osmo_plmn_id){ .mcc=1, .mnc=1 };

	/* Permit a compile-time default of A5/3 and A5/1 */
	net->a5_encryption_mask = (1 << 3) | (1 << 1);
	/* Permit a compile-time default of UEA2 and UEA1 */
	net->uea_encryption_mask = (1 << OSMO_UTRAN_UEA2) | (1 << OSMO_UTRAN_UEA1);

	net->mncc_guard_timeout = 180;
	net->ncss_guard_timeout = 30;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->neighbor_ident_list);
	INIT_LLIST_HEAD(&net->asci.gcr_lists);

	/* init statistics */
	net->msc_ctrs = rate_ctr_group_alloc(net, &msc_ctrg_desc, 0);
	if (!net->msc_ctrs) {
		talloc_free(net);
		return NULL;
	}

	net->statg = osmo_stat_item_group_alloc(net, &msc_statg_desc, 0);
	if (!net->statg) {
		rate_ctr_group_free(net->msc_ctrs);
		talloc_free(net);
		return NULL;
	}

	net->mncc_tdefs = mncc_tdefs;
	net->mncc_recv = mncc_recv;

	return net;
}

void gsm_network_set_mncc_sock_path(struct gsm_network *net, const char *mncc_sock_path)
{
	if (net->mncc_sock_path)
		talloc_free(net->mncc_sock_path);
	net->mncc_sock_path = mncc_sock_path ? talloc_strdup(net, mncc_sock_path) : NULL;
}

/* Allocate net->vlr so that the VTY may configure the VLR's data structures */
int msc_vlr_alloc(struct gsm_network *net)
{
       net->vlr = vlr_alloc(net, &msc_vlr_ops);
       if (!net->vlr)
               return -ENOMEM;
       net->vlr->user_ctx = net;
       return 0;
}

/* Launch the VLR, i.e. its GSUP connection */
int msc_vlr_start(struct gsm_network *net)
{
       OSMO_ASSERT(net->vlr);
       OSMO_ASSERT(net->gcm);

       return vlr_start(net->vlr, net->gcm);
}

int msc_gsup_client_start(struct gsm_network *net)
{
	struct ipaccess_unit *ipa_dev;

	net->gcm = gsup_client_mux_alloc(net);
	OSMO_ASSERT(net->gcm);

	ipa_dev = talloc_zero(net->gcm, struct ipaccess_unit);
	ipa_dev->unit_name = "MSC";
	ipa_dev->serno = net->msc_ipa_name; /* NULL unless configured via VTY */
	ipa_dev->swversion = PACKAGE_NAME "-" PACKAGE_VERSION;

	*net->gcm = (struct gsup_client_mux){
		.rx_cb = {
			/* vlr.c sets up its own cb and data */
			/* MSC-A and MSC-B set up their own cb and data */
			[OSMO_GSUP_MESSAGE_CLASS_SMS] = { .func = gsm411_gsup_rx, .data = net },
			[OSMO_GSUP_MESSAGE_CLASS_USSD] = { .func = gsm0911_gsup_rx, .data = net },
		},
	};

	return gsup_client_mux_start(net->gcm, net->gsup_server_addr_str, net->gsup_server_port, ipa_dev);
}
