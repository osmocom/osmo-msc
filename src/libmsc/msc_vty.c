/* MSC interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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

/* NOTE: I would have liked to call this the MSC_NODE instead of the MSC_NODE,
 * but MSC_NODE already exists to configure a remote MSC for osmo-bsc. */

#include "../../bscconfig.h"

#include <inttypes.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/vty.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/vlr.h>

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

DEFUN(cfg_msc, cfg_msc_cmd,
      "msc", "Configure MSC options")
{
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_assign_tmsi, cfg_msc_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.assign_tmsi = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_no_assign_tmsi, cfg_msc_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.assign_tmsi = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_a,
      cfg_msc_cs7_instance_a_cmd,
      "cs7-instance-a <0-15>",
      "Set SS7 to be used by the A-Interface.\n" "SS7 instance reference number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->a.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_iu,
      cfg_msc_cs7_instance_iu_cmd,
      "cs7-instance-iu <0-15>",
      "Set SS7 to be used by the Iu-Interface.\n" "SS7 instance reference number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->iu.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_auth_tuple_max_reuse_count, cfg_msc_auth_tuple_max_reuse_count_cmd,
      "auth-tuple-max-reuse-count <-1-2147483647>",
      "Configure authentication tuple re-use\n"
      "0 to use each auth tuple at most once (default), >0 to limit re-use, -1 to re-use infinitely (vulnerable!).\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.auth_tuple_max_reuse_count = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_auth_tuple_reuse_on_error, cfg_msc_auth_tuple_reuse_on_error_cmd,
      "auth-tuple-reuse-on-error (0|1)",
      "Configure authentication tuple re-use when HLR is not responsive\n"
      "0 = never re-use auth tuples beyond auth-tuple-max-reuse-count (default)\n"
      "1 = if the HLR does not deliver new tuples, do re-use already available old ones.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->vlr->cfg.auth_reuse_old_sets_on_error = atoi(argv[0]) ? true : false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_paging_response_timer, cfg_msc_paging_response_timer_cmd,
      "paging response-timer (default|<1-65535>)",
      "Configure Paging\n"
      "Set Paging timeout, the minimum time to pass between (unsuccessful) Pagings sent towards"
      " BSS or RNC\n"
      "Set to default timeout (" OSMO_STRINGIFY_VAL(MSC_PAGING_RESPONSE_TIMER_DEFAULT) " seconds)\n"
      "Set paging timeout in seconds\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	if (!strcmp(argv[1], "default"))
		gsmnet->paging_response_timer = MSC_PAGING_RESPONSE_TIMER_DEFAULT;
	else
		gsmnet->paging_response_timer = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_emergency_msisdn, cfg_msc_emergency_msisdn_cmd,
      "emergency-call route-to-msisdn MSISDN",
      "Configure Emergency Call Behaviour\n"
      "MSISDN to which Emergency Calls are Dispatched\n"
      "MSISDN (E.164 Phone Number)\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	osmo_talloc_replace_string(gsmnet, &gsmnet->emergency.route_to_msisdn, argv[0]);

	return CMD_SUCCESS;
}


static int config_write_msc(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "msc%s", VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->vlr->cfg.assign_tmsi? "" : "no ", VTY_NEWLINE);

	vty_out(vty, " cs7-instance-a %u%s", gsmnet->a.cs7_instance,
		VTY_NEWLINE);
	vty_out(vty, " cs7-instance-iu %u%s", gsmnet->iu.cs7_instance,
		VTY_NEWLINE);

	if (gsmnet->vlr->cfg.auth_tuple_max_reuse_count)
		vty_out(vty, " auth-tuple-max-reuse-count %d%s",
			OSMO_MAX(-1, gsmnet->vlr->cfg.auth_tuple_max_reuse_count),
			VTY_NEWLINE);
	if (gsmnet->vlr->cfg.auth_reuse_old_sets_on_error)
		vty_out(vty, " auth-tuple-reuse-on-error 1%s",
			VTY_NEWLINE);

	if (gsmnet->paging_response_timer != MSC_PAGING_RESPONSE_TIMER_DEFAULT)
		vty_out(vty, " paging response-timer %u%s", gsmnet->paging_response_timer, VTY_NEWLINE);

	if (gsmnet->emergency.route_to_msisdn) {
		vty_out(vty, " emergency-call route-to-msisdn %s%s",
			gsmnet->emergency.route_to_msisdn, VTY_NEWLINE);
	}

	mgcp_client_config_write(vty, " ");
#ifdef BUILD_IU
	ranap_iu_vty_config_write(vty, " ");
#endif

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int i;

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %s%s", osmo_mcc_name(gsmnet->plmn.mcc), VTY_NEWLINE);
	vty_out(vty, " mobile network code %s%s",
		osmo_mnc_name(gsmnet->plmn.mnc, gsmnet->plmn.mnc_3_digits), VTY_NEWLINE);
	vty_out(vty, " short name %s%s", gsmnet->name_short, VTY_NEWLINE);
	vty_out(vty, " long name %s%s", gsmnet->name_long, VTY_NEWLINE);
	vty_out(vty, " encryption a5");
	for (i = 0; i < 8; i++) {
		if (gsmnet->a5_encryption_mask & (1 << i))
			vty_out(vty, " %u", i);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, " authentication %s%s",
		gsmnet->authentication_required ? "required" : "optional", VTY_NEWLINE);
	vty_out(vty, " rrlp mode %s%s", rrlp_mode_name(gsmnet->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, " mm info %u%s", gsmnet->send_mm_info, VTY_NEWLINE);
	if (gsmnet->tz.override != 0) {
		if (gsmnet->tz.dst)
			vty_out(vty, " timezone %d %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, gsmnet->tz.dst,
				VTY_NEWLINE);
		else
			vty_out(vty, " timezone %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, VTY_NEWLINE);
	}
	if (gsmnet->t3212 == 0)
		vty_out(vty, " no periodic location update%s", VTY_NEWLINE);
	else
		vty_out(vty, " periodic location update %u%s",
			gsmnet->t3212 * 6, VTY_NEWLINE);

	if (gsmnet->emergency.route_to_msisdn) {
		vty_out(vty, " emergency-call route-to-msisdn %s%s",
			gsmnet->emergency.route_to_msisdn, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

void msc_vty_init(struct gsm_network *msc_network)
{
	common_cs_vty_init(msc_network, config_write_net);

	install_element(CONFIG_NODE, &cfg_msc_cmd);
	install_node(&msc_node, config_write_msc);
	install_element(MSC_NODE, &cfg_msc_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_no_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_auth_tuple_max_reuse_count_cmd);
	install_element(MSC_NODE, &cfg_msc_auth_tuple_reuse_on_error_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_a_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_iu_cmd);
	install_element(MSC_NODE, &cfg_msc_paging_response_timer_cmd);
	install_element(MSC_NODE, &cfg_msc_emergency_msisdn_cmd);

	mgcp_client_vty_init(msc_network, MSC_NODE, &msc_network->mgw.conf);
#ifdef BUILD_IU
	ranap_iu_vty_init(MSC_NODE, (enum ranap_nsap_addr_enc*)&msc_network->iu.rab_assign_addr_enc);
#endif
	osmo_fsm_vty_add_cmds();
}
