/* MSC interface to quagga VTY */
/* (C) 2016-2018 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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

#include "config.h"

#include <inttypes.h>
#include <limits.h>

#include <osmocom/core/use_count.h>

#include <osmocom/gsm/protocol/gsm_08_58.h>
#include <osmocom/gsm/protocol/gsm_04_14.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/stats.h>

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/vty.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/sms_queue.h>
#include <osmocom/msc/silent_call.h>
#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_04_14.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/mncc_int.h>
#include <osmocom/msc/rrlp.h>
#include <osmocom/msc/vlr_sgs.h>
#include <osmocom/msc/sgs_vty.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/ran_peer.h>

static struct gsm_network *gsmnet = NULL;

struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(config-net)# ",
	1,
};

#define VSUB_USE_VTY "VTY"

#define NETWORK_STR "Configure the GSM network\n"
#define CODE_CMD_STR "Code commands\n"
#define NAME_CMD_STR "Name Commands\n"
#define NAME_STR "Name to use\n"

DEFUN(cfg_net,
      cfg_net_cmd,
      "network", NETWORK_STR)
{
	vty->index = gsmnet;
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_ncc,
      cfg_net_ncc_cmd,
      "network country code <1-999>",
      "Set the GSM network country code\n"
      "Country commands\n"
      CODE_CMD_STR
      "Network Country Code to use\n")
{
	gsmnet->plmn.mcc = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mnc,
      cfg_net_mnc_cmd,
      "mobile network code <0-999>",
      "Set the GSM mobile network code\n"
      "Network Commands\n"
      CODE_CMD_STR
      "Mobile Network Code to use\n")
{
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->plmn.mnc = mnc;
	gsmnet->plmn.mnc_3_digits = mnc_3_digits;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_short,
      cfg_net_name_short_cmd,
      "short name NAME",
      "Set the short GSM network name\n" NAME_CMD_STR NAME_STR)
{
	osmo_talloc_replace_string(gsmnet, &gsmnet->name_short, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_long,
      cfg_net_name_long_cmd,
      "long name NAME",
      "Set the long GSM network name\n" NAME_CMD_STR NAME_STR)
{
	osmo_talloc_replace_string(gsmnet, &gsmnet->name_long, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_encryption,
      cfg_net_encryption_cmd,
      "encryption a5 <0-3> [<0-3>] [<0-3>] [<0-3>]",
	"Encryption options\n"
	"GSM A5 Air Interface Encryption\n"
	"A5/n Algorithm Number\n"
	"A5/n Algorithm Number\n"
	"A5/n Algorithm Number\n"
	"A5/n Algorithm Number\n")
{
	unsigned int i;

	gsmnet->a5_encryption_mask = 0;
	for (i = 0; i < argc; i++)
		gsmnet->a5_encryption_mask |= (1 << atoi(argv[i]));

	return CMD_SUCCESS;
}

DEFUN(cfg_net_authentication,
      cfg_net_authentication_cmd,
      "authentication (optional|required)",
	"Whether to enforce MS authentication in 2G\n"
	"Allow MS to attach via 2G BSC without authentication\n"
	"Always do authentication\n")
{
	gsmnet->authentication_required = (argv[0][0] == 'r') ? true : false;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_rrlp_mode, cfg_net_rrlp_mode_cmd,
      "rrlp mode (none|ms-based|ms-preferred|ass-preferred)",
	"Radio Resource Location Protocol\n"
	"Set the Radio Resource Location Protocol Mode\n"
	"Don't send RRLP request\n"
	"Request MS-based location\n"
	"Request any location, prefer MS-based\n"
	"Request any location, prefer MS-assisted\n")
{
	gsmnet->rrlp.mode = msc_rrlp_mode_parse(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mm_info, cfg_net_mm_info_cmd,
      "mm info (0|1)",
	"Mobility Management\n"
	"Send MM INFO after LOC UPD ACCEPT\n"
	"Disable\n" "Enable\n")
{
	gsmnet->send_mm_info = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_timezone,
      cfg_net_timezone_cmd,
      "timezone <-19-19> (0|15|30|45)",
      "Set the Timezone Offset of the network\n"
      "Timezone offset (hours)\n"
      "Timezone offset (00 minutes)\n"
      "Timezone offset (15 minutes)\n"
      "Timezone offset (30 minutes)\n"
      "Timezone offset (45 minutes)\n"
      )
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = 0;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_timezone_dst,
      cfg_net_timezone_dst_cmd,
      "timezone <-19-19> (0|15|30|45) <0-2>",
      "Set the Timezone Offset of the network\n"
      "Timezone offset (hours)\n"
      "Timezone offset (00 minutes)\n"
      "Timezone offset (15 minutes)\n"
      "Timezone offset (30 minutes)\n"
      "Timezone offset (45 minutes)\n"
      "DST offset (hours)\n"
      )
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);
	int tzdst = atoi(argv[2]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = tzdst;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_no_timezone,
      cfg_net_no_timezone_cmd,
      "no timezone",
      NO_STR
      "Disable network timezone override, use system tz\n")
{
	struct gsm_network *net = vty->index;

	net->tz.override = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_per_loc_upd, cfg_net_per_loc_upd_cmd,
      "periodic location update <6-1530>",
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval in Minutes\n")
{
	struct gsm_network *net = vty->index;

	net->t3212 = atoi(argv[0]) / 6;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_no_per_loc_upd, cfg_net_no_per_loc_upd_cmd,
      "no periodic location update",
      NO_STR
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n")
{
	struct gsm_network *net = vty->index;

	net->t3212 = 0;

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
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
	vty_out(vty, " rrlp mode %s%s", msc_rrlp_mode_name(gsmnet->rrlp.mode),
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

#define MNCC_STR "Configure Mobile Network Call Control\n"
#define MNCC_GUARD_TIMEOUT_STR "Set global guard timer for mncc interface activity\n"
#define MNCC_GUARD_TIMEOUT_VALUE_STR "guard timer value (sec.)\n"

DEFUN(cfg_msc_mncc_internal,
      cfg_msc_mncc_internal_cmd,
      "mncc internal",
      MNCC_STR "Use internal MNCC handler (default; changes need a program restart)\n")
{
	gsm_network_set_mncc_sock_path(gsmnet, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_mncc_external,
      cfg_msc_mncc_external_cmd,
      "mncc external MNCC_SOCKET_PATH",
      MNCC_STR "Use external MNCC handler (changes need a program restart)\n"
      "File system path to create the MNCC unix domain socket at\n")
{
	gsm_network_set_mncc_sock_path(gsmnet, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_mncc_guard_timeout,
      cfg_msc_mncc_guard_timeout_cmd,
      "mncc guard-timeout <0-255>",
      MNCC_STR
      MNCC_GUARD_TIMEOUT_STR MNCC_GUARD_TIMEOUT_VALUE_STR)
{
	gsmnet->mncc_guard_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_msc_mncc_guard_timeout,
	         cfg_msc_deprecated_mncc_guard_timeout_cmd,
		 "mncc-guard-timeout <0-255>",
		 MNCC_GUARD_TIMEOUT_STR MNCC_GUARD_TIMEOUT_VALUE_STR);

#define NCSS_STR "Configure call independent Supplementary Services\n"

DEFUN(cfg_msc_ncss_guard_timeout,
      cfg_msc_ncss_guard_timeout_cmd,
      "ncss guard-timeout <0-255>",
      NCSS_STR "Set guard timer for session activity\n"
      "guard timer value (sec.), or 0 to disable\n")
{
	gsmnet->ncss_guard_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_assign_tmsi, cfg_msc_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	gsmnet->vlr->cfg.assign_tmsi = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_no_assign_tmsi, cfg_msc_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	gsmnet->vlr->cfg.assign_tmsi = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_a,
      cfg_msc_cs7_instance_a_cmd,
      "cs7-instance-a <0-15>",
      "Set SS7 to be used by the A-Interface.\n" "SS7 instance reference number\n")
{
	gsmnet->a.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_instance_iu,
      cfg_msc_cs7_instance_iu_cmd,
      "cs7-instance-iu <0-15>",
      "Set SS7 to be used by the Iu-Interface.\n" "SS7 instance reference number\n")
{
#if BUILD_IU
	gsmnet->iu.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
#else
	vty_out(vty, "WARNING: 'cs7-instance-iu' without effect: built without Iu support%s",
		VTY_NEWLINE);
	return CMD_WARNING;
#endif
}

DEFUN(cfg_msc_auth_tuple_max_reuse_count, cfg_msc_auth_tuple_max_reuse_count_cmd,
      "auth-tuple-max-reuse-count <-1-2147483647>",
      "Configure authentication tuple re-use\n"
      "0 to use each auth tuple at most once (default), >0 to limit re-use, -1 to re-use infinitely (vulnerable!).\n")
{
	gsmnet->vlr->cfg.auth_tuple_max_reuse_count = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_auth_tuple_reuse_on_error, cfg_msc_auth_tuple_reuse_on_error_cmd,
      "auth-tuple-reuse-on-error (0|1)",
      "Configure authentication tuple re-use when HLR is not responsive\n"
      "Never re-use auth tuples beyond auth-tuple-max-reuse-count (default)\n"
      "If the HLR does not deliver new tuples, do re-use already available old ones.\n")
{
	gsmnet->vlr->cfg.auth_reuse_old_sets_on_error = atoi(argv[0]) ? true : false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_check_imei_rqd, cfg_msc_check_imei_rqd_cmd,
      "check-imei-rqd (0|1)",
      "Send each IMEI to the EIR to ask if it is permitted or not. The EIR is implemented as part of OsmoHLR, "
      "and can optionally save the IMEI in the HLR.\n"
      "Do not send IMEIs to the EIR\n"
      "Send each IMEI to the EIR\n")
{
	gsmnet->vlr->cfg.check_imei_rqd = atoi(argv[0]) ? true : false;
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
	osmo_talloc_replace_string(gsmnet, &gsmnet->emergency.route_to_msisdn, argv[0]);

	return CMD_SUCCESS;
}

/* TODO: to be deprecated as soon as we rip SMS handling out (see OS#3587) */
DEFUN(cfg_msc_sms_over_gsup, cfg_msc_sms_over_gsup_cmd,
      "sms-over-gsup",
      "Enable routing of SMS messages over GSUP\n")
{
	gsmnet->sms_over_gsup = true;
	return CMD_SUCCESS;
}

/* TODO: to be deprecated as soon as we rip SMS handling out (see OS#3587) */
DEFUN(cfg_msc_no_sms_over_gsup, cfg_msc_no_sms_over_gsup_cmd,
      "no sms-over-gsup",
      NO_STR "Disable routing of SMS messages over GSUP\n")
{
	gsmnet->sms_over_gsup = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_handover_number_range, cfg_msc_handover_number_range_cmd,
      "handover-number range MSISDN_FIRST MSISDN_LAST",
      "Configure a range of MSISDN to be assigned to incoming inter-MSC Handovers for call forwarding.\n"
      "First Handover Number MSISDN\n"
      "Last Handover Number MSISDN\n")
{
	char *endp;
	uint64_t range_start;
	uint64_t range_end;

	/* FIXME leading zeros?? */

	errno = 0;
	range_start = strtoull(argv[0], &endp, 10);
	if (errno || *endp != '\0') {
		vty_out(vty, "%% Error parsing handover-number range start: %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	errno = 0;
	range_end = strtoull(argv[1], &endp, 10);
	if (errno || *endp != '\0') {
		vty_out(vty, "%% Error parsing handover-number range end: %s%s",
			argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (range_start > range_end) {
		vty_out(vty, "%% Error: handover-number range end must be > than the range start, but"
			" %"PRIu64" > %"PRIu64"%s", range_start, range_end, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->handover_number.range_start = range_start;
	gsmnet->handover_number.range_end = range_end;
	return CMD_SUCCESS;
}

static int config_write_msc(struct vty *vty)
{
	vty_out(vty, "msc%s", VTY_NEWLINE);
	if (gsmnet->mncc_sock_path)
		vty_out(vty, " mncc external %s%s", gsmnet->mncc_sock_path, VTY_NEWLINE);
	vty_out(vty, " mncc guard-timeout %i%s",
		gsmnet->mncc_guard_timeout, VTY_NEWLINE);
	vty_out(vty, " ncss guard-timeout %i%s",
		gsmnet->ncss_guard_timeout, VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->vlr->cfg.assign_tmsi? "" : "no ", VTY_NEWLINE);

	vty_out(vty, " cs7-instance-a %u%s", gsmnet->a.cs7_instance,
		VTY_NEWLINE);
#if BUILD_IU
	vty_out(vty, " cs7-instance-iu %u%s", gsmnet->iu.cs7_instance,
		VTY_NEWLINE);
#endif

	if (gsmnet->vlr->cfg.auth_tuple_max_reuse_count)
		vty_out(vty, " auth-tuple-max-reuse-count %d%s",
			OSMO_MAX(-1, gsmnet->vlr->cfg.auth_tuple_max_reuse_count),
			VTY_NEWLINE);
	if (gsmnet->vlr->cfg.auth_reuse_old_sets_on_error)
		vty_out(vty, " auth-tuple-reuse-on-error 1%s",
			VTY_NEWLINE);

	if (gsmnet->vlr->cfg.check_imei_rqd)
		vty_out(vty, " check-imei-rqd 1 %s",
			VTY_NEWLINE);

	if (gsmnet->paging_response_timer != MSC_PAGING_RESPONSE_TIMER_DEFAULT)
		vty_out(vty, " paging response-timer %u%s", gsmnet->paging_response_timer, VTY_NEWLINE);

	if (gsmnet->emergency.route_to_msisdn) {
		vty_out(vty, " emergency-call route-to-msisdn %s%s",
			gsmnet->emergency.route_to_msisdn, VTY_NEWLINE);
	}

	if (gsmnet->sms_over_gsup)
		vty_out(vty, " sms-over-gsup%s", VTY_NEWLINE);

	if (gsmnet->handover_number.range_start || gsmnet->handover_number.range_end)
		vty_out(vty, " handover-number range %"PRIu64" %"PRIu64"%s",
			gsmnet->handover_number.range_start, gsmnet->handover_number.range_end,
			VTY_NEWLINE);

	mgcp_client_config_write(vty, " ");
#ifdef BUILD_IU
	ranap_iu_vty_config_write(vty, " ");
#endif

	return CMD_SUCCESS;
}

DEFUN(show_bsc, show_bsc_cmd,
	"show bsc", SHOW_STR "BSC\n")
{
	struct ran_peer *rp;
	llist_for_each_entry(rp, &gsmnet->a.sri->ran_peers, entry) {
		vty_out(vty, "BSC %s %s%s",
			osmo_sccp_inst_addr_name(gsmnet->a.sri->sccp, &rp->peer_addr),
			osmo_fsm_inst_state_name(rp->fi),
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/*
_Subscriber_______________________________________ _LAC_ _RAN___________________ _MSC-A_state_________ _MSC-A_use_
IMSI-123456789012345:MSISDN-12345:TMSI-0x12345678  1     GERAN-A-4294967295:A5-3 WAIT_CLASSMARK_UPDATE 2=cm_service,trans_cc
IMSI-123456789012356:MSISDN-234567:TMSI-0x123ABC78 65535 UTRAN-Iu-4294967295     COMMUNICATING         2=cm_service,trans_sms
IMSI-123456789012367:MSISDN-98712345890:TMSI-0xF.. -     EUTRAN-SGs              RELEASING             0=none
IMSI-123456789012378:HONR-12345432101              2     MSC-901-700-423:9876    REMOTE_MSC_A          1=inter_msc
*/
static void vty_dump_one_conn(struct vty *vty, const struct msub *msub, int *idx)
{
	struct msc_a *msc_a = msub_msc_a(msub);
	struct vlr_subscr *vsub = msub_vsub(msub);
	char buf[128];

	if (!(*idx))
		vty_out(vty,
			"_Subscriber_______________________________________ _LAC_ _RAN___________________"
			" _MSC-A_state_________ _MSC-A_use_%s",
			VTY_NEWLINE);
	(*idx)++;

	vty_out(vty, "%50s %5u %23s %20s %d=%s%s",
		vlr_subscr_short_name(msub_vsub(msub), 50),
		vsub ? vsub->cgi.lai.lac : 0,
		msub_ran_conn_name(msub),
		osmo_fsm_inst_state_name(msc_a->c.fi),
		osmo_use_count_total(&msc_a->use_count),
		osmo_use_count_name_buf(buf, sizeof(buf), &msc_a->use_count),
		VTY_NEWLINE);
}

DEFUN(show_msc_conn, show_msc_conn_cmd,
	"show connection", SHOW_STR "Subscriber Connections\n")
{
	struct msub *msub;
	int idx = 0;
	llist_for_each_entry(msub, &msub_list, entry) {
		vty_dump_one_conn(vty, msub, &idx);
	}
	return CMD_SUCCESS;
}

static void vty_trans_hdr(struct vty *vty)
{
	if (llist_empty(&gsmnet->trans_list))
		return;

	vty_out(vty,
		"_Subscriber_______________________________________ _RAN___________________"
		" _P__ TI CallRef_ _state_%s",
		VTY_NEWLINE);
}

static const char *get_trans_proto_str(const struct gsm_trans *trans)
{
	static char buf[256];

	switch (trans->type) {
	case TRANS_CC:
		snprintf(buf, sizeof(buf), "%s %4u %4u",
			 gsm48_cc_state_name(trans->cc.state),
			 trans->cc.Tcurrent,
			 trans->cc.T308_second);
		break;
	case TRANS_SMS:
		snprintf(buf, sizeof(buf), "%s %s",
			gsm411_cp_state_name(trans->sms.smc_inst.cp_state),
			gsm411_rp_state_name(trans->sms.smr_inst.rp_state));
		break;
	default:
		buf[0] = '\0';
		break;
	}

	return buf;
}

static void vty_dump_one_trans(struct vty *vty, const struct gsm_trans *trans)
{
	vty_out(vty, "%50s %23s %4s %02u %08x %s%s",
		vlr_subscr_short_name(msc_a_vsub(trans->msc_a), 50),
		msub_ran_conn_name(trans->msc_a->c.msub),
		trans_type_name(trans->type),
		trans->transaction_id,
		trans->callref,
		get_trans_proto_str(trans),
		VTY_NEWLINE);
}

DEFUN(show_msc_transaction, show_msc_transaction_cmd,
	"show transaction", SHOW_STR "Transactions\n")
{
	struct gsm_trans *trans;

	vty_trans_hdr(vty);
	llist_for_each_entry(trans, &gsmnet->trans_list, entry)
		vty_dump_one_trans(vty, trans);

	return CMD_SUCCESS;
}

static void subscr_dump_full_vty(struct vty *vty, struct vlr_subscr *vsub)
{
	struct gsm_trans *trans;
	int reqs;
	struct llist_head *entry;
	char buf[128];

	if (strlen(vsub->name))
		vty_out(vty, "    Name: '%s'%s", vsub->name, VTY_NEWLINE);
	if (strlen(vsub->msisdn))
		vty_out(vty, "    Extension: %s%s", vsub->msisdn,
			VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		vsub->cgi.lai.lac, vsub->cgi.lai.lac, VTY_NEWLINE);
	vty_out(vty, "    RAN: %s%s",
		osmo_rat_type_name(vsub->cs.attached_via_ran), VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", vsub->imsi, VTY_NEWLINE);
	if (vsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", vsub->tmsi,
			VTY_NEWLINE);
	if (vsub->tmsi_new != GSM_RESERVED_TMSI)
		vty_out(vty, "    new TMSI: %08X%s", vsub->tmsi_new,
			VTY_NEWLINE);
	if (vsub->imei[0] != '\0')
		vty_out(vty, "    IMEI: %s%s", vsub->imei, VTY_NEWLINE);
	if (vsub->imeisv[0] != '\0')
		vty_out(vty, "    IMEISV: %s%s", vsub->imeisv, VTY_NEWLINE);

	vty_out(vty, "    Flags: %s", VTY_NEWLINE);
	vty_out(vty, "     IMSI detached:             %s%s",
		vsub->imsi_detached_flag ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     Conf. by radio contact:    %s%s",
		vsub->conf_by_radio_contact_ind ? "true" : "false",
		VTY_NEWLINE);
	vty_out(vty, "     Subscr. data conf. by HLR: %s%s",
		vsub->sub_dataconf_by_hlr_ind ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     Location conf. in HLR:     %s%s",
		vsub->loc_conf_in_hlr_ind ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     Subscriber dormant:        %s%s",
		vsub->dormant_ind ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     Received cancel locataion: %s%s",
		vsub->cancel_loc_rx ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     MS not reachable:          %s%s",
		vsub->ms_not_reachable_flag ? "true" : "false", VTY_NEWLINE);
	vty_out(vty, "     LA allowed:                %s%s",
		vsub->la_allowed ? "true" : "false", VTY_NEWLINE);

	if (vsub->last_tuple) {
		struct vlr_auth_tuple *t = vsub->last_tuple;
		vty_out(vty, "    A3A8 last tuple (used %d times):%s",
			t->use_count, VTY_NEWLINE);
		vty_out(vty, "     seq # : %d%s",
			t->key_seq, VTY_NEWLINE);
		vty_out(vty, "     RAND  : %s%s",
			osmo_hexdump(t->vec.rand, sizeof(t->vec.rand)),
			VTY_NEWLINE);
		vty_out(vty, "     SRES  : %s%s",
			osmo_hexdump(t->vec.sres, sizeof(t->vec.sres)),
			VTY_NEWLINE);
		vty_out(vty, "     Kc    : %s%s",
			osmo_hexdump(t->vec.kc, sizeof(t->vec.kc)),
			VTY_NEWLINE);
	}

	reqs = 0;
	llist_for_each(entry, &vsub->cs.requests)
		reqs += 1;
	vty_out(vty, "    Paging: %s paging for %d requests%s",
		vsub->cs.is_paging ? "is" : "not", reqs, VTY_NEWLINE);

	/* SGs related */
	vty_out(vty, "    SGs-state: %s%s",
		osmo_fsm_inst_state_name(vsub->sgs_fsm), VTY_NEWLINE);
	if (strlen(vsub->sgs.mme_name))
		vty_out(vty, "    SGs-MME: %s%s", vsub->sgs.mme_name, VTY_NEWLINE);
	else
		vty_out(vty, "    SGs-MME: (none)%s", VTY_NEWLINE);

	vty_out(vty, "    Use: %s%s", osmo_use_count_name_buf(buf, sizeof(buf), &vsub->use_count), VTY_NEWLINE);

	/* Connection */
	if (vsub->msc_conn_ref) {
		struct msub *msub = vsub->msc_conn_ref;
		int idx = 0;
		if (msub) {
			vty_dump_one_conn(vty, msub, &idx);
		}
	}

	/* Transactions */
	vty_trans_hdr(vty);
	llist_for_each_entry(trans, &gsmnet->trans_list, entry) {
		if (trans->vsub != vsub)
			continue;
		vty_dump_one_trans(vty, trans);
	}
}

/* Subscriber */
DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Show information about subscribers\n"
	"Display contents of subscriber cache\n")
{
	struct vlr_subscr *vsub;
	int count = 0;

	llist_for_each_entry(vsub, &gsmnet->vlr->subscribers, list) {
		if (++count > 100) {
			vty_out(vty, "%% More than %d subscribers in cache,"
				" stopping here.%s", count-1, VTY_NEWLINE);
			break;
		}
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, vsub);
	}

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending",
      "SMS related commands\n" "SMS Sending related commands\n"
      "Send all pending SMS")
{
	struct gsm_sms *sms;
	unsigned long long sms_id = 0;

	while (1) {
		sms = db_sms_get_next_unsent(gsmnet, sms_id, UINT_MAX);
		if (!sms)
			break;

		if (sms->receiver)
			gsm411_send_sms(gsmnet, sms->receiver, sms);

		sms_id = sms->id + 1;
	}

	return CMD_SUCCESS;
}

DEFUN(sms_delete_expired,
      sms_delete_expired_cmd,
      "sms delete expired",
      "SMS related commands\n" "SMS Database related commands\n"
      "Delete all expired SMS")
{
	struct gsm_sms *sms;
	unsigned long long sms_id = 0;
	long long num_deleted = 0;

	while (1) {
		sms = db_sms_get_next_unsent(gsmnet, sms_id, UINT_MAX);
		if (!sms)
			break;

		/* Skip SMS which are currently queued for sending. */
		if (sms_queue_sms_is_pending(gsmnet->sms_queue, sms->id))
			continue;

		/* Expiration check is performed by the DB layer. */
		if (db_sms_delete_expired_message_by_id(sms->id) == 0)
			num_deleted++;

		sms_id = sms->id + 1;
	}

	if (num_deleted == 0) {
		vty_out(vty, "No expired SMS in database%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "Deleted %llu expired SMS from database%s", num_deleted, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int _send_sms_str(struct vlr_subscr *receiver,
			 const char *sender_msisdn,
			 char *str, uint8_t tp_pid)
{
	struct gsm_network *net = receiver->vlr->user_ctx;
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, sender_msisdn, 0, str);
	sms->protocol_id = tp_pid;

	/* store in database for the queue */
	if (db_sms_store(sms) != 0) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		sms_free(sms);
		return CMD_WARNING;
	}
	LOGP(DLSMS, LOGL_DEBUG, "SMS stored in DB\n");

	sms_free(sms);
	sms_queue_trigger(net->sms_queue);
	return CMD_SUCCESS;
}

static struct vlr_subscr *get_vsub_by_argv(struct gsm_network *gsmnet,
					       const char *type,
					       const char *id)
{
	if (!strcmp(type, "extension") || !strcmp(type, "msisdn"))
		return vlr_subscr_find_by_msisdn(gsmnet->vlr, id, VSUB_USE_VTY);
	else if (!strcmp(type, "imsi") || !strcmp(type, "id"))
		return vlr_subscr_find_by_imsi(gsmnet->vlr, id, VSUB_USE_VTY);
	else if (!strcmp(type, "tmsi"))
		return vlr_subscr_find_by_tmsi(gsmnet->vlr, atoi(id), VSUB_USE_VTY);

	return NULL;
}
#define SUBSCR_TYPES "(msisdn|extension|imsi|tmsi|id)"
#define SUBSCR_HELP "Operations on a Subscriber\n"			\
	"Identify subscriber by MSISDN (phone number)\n"		\
	"Legacy alias for 'msisdn'\n"		\
	"Identify subscriber by IMSI\n"					\
	"Identify subscriber by TMSI\n"					\
	"Identify subscriber by database ID\n"				\
	"Identifier for the subscriber\n"

DEFUN(show_subscr,
      show_subscr_cmd,
      "show subscriber " SUBSCR_TYPES " ID",
	SHOW_STR SUBSCR_HELP)
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0],
						       argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* In the vty output to the user, exclude this local use count added by vlr_subscr_get() in get_vsub_by_argv().
	 * This works, because: for get_vsub_by_argv() to succeed, there *must* have been at least one use count before
	 * this, and since this is not multi-threaded, this vlr_subscr_put() cannot possibly reach a count of 0. */
	vlr_subscr_put(vsub, VSUB_USE_VTY);

	subscr_dump_full_vty(vty, vsub);

	return CMD_SUCCESS;
}

DEFUN(subscriber_create,
      subscriber_create_cmd,
      "subscriber create imsi ID",
	"Operations on a Subscriber\n" \
	"Create new subscriber\n" \
	"Identify the subscriber by his IMSI\n" \
	"Identifier for the subscriber\n")
{
	vty_out(vty, "%% 'subscriber create' now needs to be done at osmo-hlr%s",
		VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(subscriber_send_pending_sms,
      subscriber_send_pending_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms pending-send",
	SUBSCR_HELP "SMS Operations\n" "Send pending SMS\n")
{
	struct vlr_subscr *vsub;
	struct gsm_sms *sms;

	vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	sms = db_sms_get_unsent_for_subscr(vsub, UINT_MAX);
	if (sms)
		gsm411_send_sms(gsmnet, sms->receiver, sms);

	vlr_subscr_put(vsub, VSUB_USE_VTY);

	return CMD_SUCCESS;
}

DEFUN(subscriber_sms_delete_all,
      subscriber_sms_delete_all_cmd,
      "subscriber " SUBSCR_TYPES " ID sms delete-all",
      SUBSCR_HELP "SMS Operations\n"
      "Delete all SMS to be delivered to this subscriber"
      " -- WARNING: the SMS data for all unsent SMS for this subscriber"
      " WILL BE LOST.\n")
{
	struct vlr_subscr *vsub;

	vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	db_sms_delete_by_msisdn(vsub->msisdn);

	vlr_subscr_put(vsub, VSUB_USE_VTY);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_sms,
      subscriber_send_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	const char *sender_msisdn;
	char *str;
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!strcmp(argv[2], "msisdn"))
		sender_msisdn = argv[3];
	else {
		struct vlr_subscr *sender = get_vsub_by_argv(gsmnet, argv[2], argv[3]);
		if (!sender) {
			vty_out(vty, "%% No sender found for %s %s%s", argv[2], argv[3], VTY_NEWLINE);
			rc = CMD_WARNING;
			goto err;
		}
		sender_msisdn = sender->msisdn;
		vlr_subscr_put(sender, VSUB_USE_VTY);
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(vsub, sender_msisdn, str, 0);
	talloc_free(str);

err:
	if (vsub)
		vlr_subscr_put(vsub, VSUB_USE_VTY);

	return rc;
}

DEFUN(subscriber_silent_sms,
      subscriber_silent_sms_cmd,

      "subscriber " SUBSCR_TYPES " ID silent-sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "Silent SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	const char *sender_msisdn;
	char *str;
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!strcmp(argv[2], "msisdn")) {
		sender_msisdn = argv[3];
	} else {
		struct vlr_subscr *sender = get_vsub_by_argv(gsmnet, argv[2], argv[3]);
		if (!sender) {
			vty_out(vty, "%% No sender found for %s %s%s", argv[2], argv[3], VTY_NEWLINE);
			rc = CMD_WARNING;
			goto err;
		}
		sender_msisdn = sender->msisdn;
		vlr_subscr_put(sender, VSUB_USE_VTY);
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(vsub, sender_msisdn, str, 64);
	talloc_free(str);

err:
	if (vsub)
		vlr_subscr_put(vsub, VSUB_USE_VTY);

	return rc;
}

#define CHAN_TYPES "(any|tch/f|tch/h|tch/any|sdcch)"
#define CHAN_TYPE_HELP 			\
		"Any channel\n"		\
		"TCH/F channel\n"	\
		"TCH/H channel\n"	\
		"Any TCH channel\n"	\
		"SDCCH channel\n"

#define CHAN_MODES "(signalling|speech-hr|speech-fr|speech-efr|speech-amr)"
#define CHAN_MODE_HELP				\
		"Signalling only\n"		\
		"Speech with HR codec\n"	\
		"Speech with FR codec\n"	\
		"Speech with EFR codec\n"	\
		"Speech with AMR codec\n"

DEFUN(subscriber_silent_call_start,
      subscriber_silent_call_start_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call start " CHAN_TYPES " " CHAN_MODES " [IP] [<0-65535>]",
	SUBSCR_HELP "Silent call operation\n" "Start silent call\n"
	CHAN_TYPE_HELP CHAN_MODE_HELP
	"Target IP for RTP traffic (default 127.0.0.1)\n"
	"Target port for RTP traffic (default: 4000)\n")
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	struct gsm0808_channel_type ct;
	const char *ip;
	uint16_t port;
	int rc, speech;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	memset(&ct, 0x00, sizeof(ct));

	if (!strcmp(argv[3], "signalling")) {
		ct.ch_indctr = GSM0808_CHAN_SIGN;
		ct.perm_spch[0] = 0; /* Spare but required */
		ct.perm_spch_len = 1;
	} else if (!strcmp(argv[3], "speech-hr")) {
		ct.ch_indctr = GSM0808_CHAN_SPEECH;
		ct.perm_spch[0] = GSM0808_PERM_HR1;
		ct.perm_spch_len = 1;
	} else if (!strcmp(argv[3], "speech-fr")) {
		ct.ch_indctr = GSM0808_CHAN_SPEECH;
		ct.perm_spch[0] = GSM0808_PERM_FR1;
		ct.perm_spch_len = 1;
	} else if (!strcmp(argv[3], "speech-efr")) {
		ct.ch_indctr = GSM0808_CHAN_SPEECH;
		ct.perm_spch[0] = GSM0808_PERM_FR2;
		ct.perm_spch_len = 1;
	} else if (!strcmp(argv[3], "speech-amr")) {
		ct.ch_indctr = GSM0808_CHAN_SPEECH;
		ct.perm_spch[0] = GSM0808_PERM_FR3;
		ct.perm_spch[1] = GSM0808_PERM_HR3;
		ct.perm_spch_len = 2;
	}

	speech = ct.ch_indctr == GSM0808_CHAN_SPEECH;

	if (!strcmp(argv[2], "tch/f"))
		ct.ch_rate_type = speech ? GSM0808_SPEECH_FULL_BM : GSM0808_SIGN_FULL_BM;
	else if (!strcmp(argv[2], "tch/h"))
		ct.ch_rate_type = speech ? GSM0808_SPEECH_HALF_LM : GSM0808_SIGN_HALF_LM;
	else if (!strcmp(argv[2], "tch/any"))
		ct.ch_rate_type = speech ? GSM0808_SPEECH_FULL_PREF : GSM0808_SIGN_FULL_PREF;
	else if (!strcmp(argv[2], "sdcch")) {
		if (speech) {
			vty_out(vty, "Can't request speech on SDCCH%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		ct.ch_rate_type = GSM0808_SIGN_SDCCH;
	} else
		ct.ch_rate_type = speech ? GSM0808_SPEECH_FULL_PREF : GSM0808_SIGN_ANY;

	ip   = argc >= 5 ? argv[4] : "127.0.0.1";
	port = argc >= 6 ? atoi(argv[5]) : 4000;

	rc = gsm_silent_call_start(vsub, &ct, ip, port, vty);
	switch (rc) {
	case -ENODEV:
		vty_out(vty, "%% Subscriber not attached%s", VTY_NEWLINE);
		break;
	default:
		if (rc)
			vty_out(vty, "%% Cannot start silent call (rc=%d)%s", rc, VTY_NEWLINE);
		else
			vty_out(vty, "%% Silent call initiated%s", VTY_NEWLINE);
		break;
	}

	vlr_subscr_put(vsub, VSUB_USE_VTY);
	return rc ? CMD_WARNING : CMD_SUCCESS;
}

DEFUN(subscriber_silent_call_stop,
      subscriber_silent_call_stop_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call stop",
	SUBSCR_HELP "Silent call operation\n" "Stop silent call\n"
	CHAN_TYPE_HELP)
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	int rc;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gsm_silent_call_stop(vsub);
	switch (rc) {
	case -ENODEV:
		vty_out(vty, "%% No active connection for subscriber%s", VTY_NEWLINE);
		break;
	case -ENOENT:
		vty_out(vty, "%% Subscriber has no silent call active%s",
			VTY_NEWLINE);
		break;
	default:
		if (rc)
			vty_out(vty, "%% Cannot stop silent call (rc=%d)%s", rc, VTY_NEWLINE);
		else
			vty_out(vty, "%% Silent call stopped%s", VTY_NEWLINE);
		break;
	}

	vlr_subscr_put(vsub, VSUB_USE_VTY);
	return rc ? CMD_WARNING : CMD_SUCCESS;
}

DEFUN(subscriber_ussd_notify,
      subscriber_ussd_notify_cmd,
      "subscriber " SUBSCR_TYPES " ID ussd-notify (0|1|2) .TEXT",
      SUBSCR_HELP "Send a USSD notify to the subscriber\n"
      "Alerting Level 0\n"
      "Alerting Level 1\n"
      "Alerting Level 2\n"
      "Text of USSD message to send\n")
{
	char *text;
	struct msc_a *msc_a;
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	int level;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	level = atoi(argv[2]);
	text = argv_concat(argv, argc, 3);
	if (!text) {
		vlr_subscr_put(vsub, VSUB_USE_VTY);
		return CMD_WARNING;
	}

	msc_a = msc_a_for_vsub(vsub, true);
	if (!msc_a || msc_a->c.remote_to) {
		vty_out(vty, "%% An active connection and local MSC-A role is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub, VSUB_USE_VTY);
		talloc_free(text);
		return CMD_WARNING;
	}

	msc_send_ussd_notify(msc_a, level, text);
	/* FIXME: since we don't allocate a transaction here,
	 * we use dummy GSM 04.07 transaction ID. */
	msc_send_ussd_release_complete(msc_a, 0x00);

	vlr_subscr_put(vsub, VSUB_USE_VTY);
	talloc_free(text);
	return CMD_SUCCESS;
}

DEFUN(subscriber_paging,
      subscriber_paging_cmd,
      "subscriber " SUBSCR_TYPES " ID paging",
      SUBSCR_HELP "Issue an empty Paging for the subscriber (for debugging)\n")
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	struct paging_request *req;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	req = paging_request_start(vsub, PAGING_CAUSE_CALL_CONVERSATIONAL,
				   NULL, NULL, "manual Paging from VTY");
	if (req)
		vty_out(vty, "%% paging subscriber%s", VTY_NEWLINE);
	else
		vty_out(vty, "%% paging subscriber failed%s", VTY_NEWLINE);

	vlr_subscr_put(vsub, VSUB_USE_VTY);
	return req ? CMD_SUCCESS : CMD_WARNING;
}

static int loop_by_char(uint8_t ch)
{
	switch (ch) {
	case 'a':
		return GSM414_LOOP_A;
	case 'b':
		return GSM414_LOOP_B;
	case 'c':
		return GSM414_LOOP_C;
	case 'd':
		return GSM414_LOOP_D;
	case 'e':
		return GSM414_LOOP_E;
	case 'f':
		return GSM414_LOOP_F;
	case 'i':
		return GSM414_LOOP_I;
	}
	return -1;
}

DEFUN(subscriber_mstest_close,
      subscriber_mstest_close_cmd,
      "subscriber " SUBSCR_TYPES " ID ms-test close-loop (a|b|c|d|e|f|i)",
      SUBSCR_HELP "Send a TS 04.14 MS Test Command to subscriber\n"
      "Close a TCH Loop inside the MS\n"
      "Loop Type A\n"
      "Loop Type B\n"
      "Loop Type C\n"
      "Loop Type D\n"
      "Loop Type E\n"
      "Loop Type F\n"
      "Loop Type I\n")
{
	struct msc_a *msc_a;
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);
	const char *loop_str;
	int loop_mode;

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	loop_str = argv[2];
	loop_mode = loop_by_char(loop_str[0]);

	msc_a = msc_a_for_vsub(vsub, true);
	if (!msc_a) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub, VSUB_USE_VTY);
		return CMD_WARNING;
	}

	gsm0414_tx_close_tch_loop_cmd(msc_a, loop_mode);

	return CMD_SUCCESS;
}

DEFUN(subscriber_mstest_open,
      subscriber_mstest_open_cmd,
      "subscriber " SUBSCR_TYPES " ID ms-test open-loop",
      SUBSCR_HELP "Send a TS 04.14 MS Test Command to subscriber\n"
      "Open a TCH Loop inside the MS\n")
{
	struct msc_a *msc_a;
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0], argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	msc_a = msc_a_for_vsub(vsub, true);
	if (!msc_a) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		vlr_subscr_put(vsub, VSUB_USE_VTY);
		return CMD_WARNING;
	}

	gsm0414_tx_open_loop_cmd(msc_a);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_expire,
      ena_subscr_expire_cmd,
      "subscriber " SUBSCR_TYPES " ID expire",
	SUBSCR_HELP "Expire the subscriber Now\n")
{
	struct vlr_subscr *vsub = get_vsub_by_argv(gsmnet, argv[0],
						       argv[1]);

	if (!vsub) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (vlr_subscr_expire(vsub))
		vty_out(vty, "%% VLR released subscriber %s%s",
			vlr_subscr_name(vsub), VTY_NEWLINE);

	if (osmo_use_count_total(&vsub->use_count) > 1)
		vty_out(vty, "%% Subscriber %s is still in use,"
			" should be released soon%s",
			vlr_subscr_name(vsub), VTY_NEWLINE);

	vlr_subscr_put(vsub, VSUB_USE_VTY);
	return CMD_SUCCESS;
}

static int scall_cbfn(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct scall_signal_data *sigdata = signal_data;
	struct vty *vty = sigdata->vty;

	if (!vty_is_active(vty))
		return 0;

	switch (signal) {
	case S_SCALL_SUCCESS:
		vty_out(vty, "%% Silent call success%s", VTY_NEWLINE);
		break;
	case S_SCALL_FAILED:
		vty_out(vty, "%% Silent call failed%s", VTY_NEWLINE);
		break;
	case S_SCALL_DETACHED:
		vty_out(vty, "%% Silent call ended%s", VTY_NEWLINE);
		break;
	}
	return 0;
}

DEFUN(show_stats,
      show_stats_cmd,
      "show statistics",
	SHOW_STR "Display network statistics\n")
{
	vty_out(vty, "Location Update         : %" PRIu64 " attach, %" PRIu64 " normal, %" PRIu64 " periodic%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC].current,
		VTY_NEWLINE);
	vty_out(vty, "IMSI Detach Indications : %" PRIu64 "%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH].current,
		VTY_NEWLINE);
	vty_out(vty, "Location Updating Results: %" PRIu64 " completed, %" PRIu64 " failed%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_COMPLETED].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_FAILED].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MO                  : %" PRIu64 " submitted, %" PRIu64 " no receiver%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_SMS_SUBMITTED].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MT                  : %" PRIu64 " delivered, %" PRIu64 " no memory, %" PRIu64 " other error%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_MEM].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_OTHER].current,
		VTY_NEWLINE);
	vty_out(vty, "MO Calls                : %" PRIu64 " setup, %" PRIu64 " connect ack%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_CALL_MO_CONNECT_ACK].current,
		VTY_NEWLINE);
	vty_out(vty, "MT Calls                : %" PRIu64 " setup, %" PRIu64 " connect%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_CALL_MT_SETUP].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_CALL_MT_CONNECT].current,
		VTY_NEWLINE);
	vty_out(vty, "MO NC SS/USSD           : %" PRIu64 " requests, %" PRIu64 " established, %" PRIu64 " rejected%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_REQUESTS].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_ESTABLISHED].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_REQUESTS].current
			- gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MO_ESTABLISHED].current,
		VTY_NEWLINE);
	vty_out(vty, "MT NC SS/USSD           : %" PRIu64 " requests, %" PRIu64 " established, %" PRIu64 " rejected%s",
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_REQUESTS].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_ESTABLISHED].current,
		gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_REQUESTS].current
			- gsmnet->msc_ctrs->ctr[MSC_CTR_NC_SS_MT_ESTABLISHED].current,
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_smsqueue,
      show_smsqueue_cmd,
      "show sms-queue",
      SHOW_STR "Display SMSqueue statistics\n")
{
	sms_queue_stats(gsmnet->sms_queue, vty);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_trigger,
      smsqueue_trigger_cmd,
      "sms-queue trigger",
      "SMS Queue\n" "Trigger sending messages\n")
{
	sms_queue_trigger(gsmnet->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_max,
      smsqueue_max_cmd,
      "sms-queue max-pending <1-500>",
      "SMS Queue\n" "SMS to deliver in parallel\n" "Amount\n")
{
	sms_queue_set_max_pending(gsmnet->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(smsqueue_clear,
      smsqueue_clear_cmd,
      "sms-queue clear",
      "SMS Queue\n" "Clear the queue of pending SMS\n")
{
	sms_queue_clear(gsmnet->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_fail,
      smsqueue_fail_cmd,
      "sms-queue max-failure <1-500>",
      "SMS Queue\n" "Maximum amount of delivery failures\n" "Amount\n")
{
	sms_queue_set_max_failure(gsmnet->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}


DEFUN(cfg_mncc_int, cfg_mncc_int_cmd,
      "mncc-int", "Configure internal MNCC handler")
{
	vty->node = MNCC_INT_NODE;

	return CMD_SUCCESS;
}

static struct cmd_node mncc_int_node = {
	MNCC_INT_NODE,
	"%s(config-mncc-int)# ",
	1,
};

static const struct value_string tchf_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"fr" },
	{ GSM48_CMODE_SPEECH_EFR,	"efr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static const struct value_string tchh_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"hr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static int config_write_mncc_int(struct vty *vty)
{
	vty_out(vty, "mncc-int%s", VTY_NEWLINE);
	vty_out(vty, " default-codec tch-f %s%s",
		get_value_string(tchf_codec_names, mncc_int.def_codec[0]),
		VTY_NEWLINE);
	vty_out(vty, " default-codec tch-h %s%s",
		get_value_string(tchh_codec_names, mncc_int.def_codec[1]),
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_f,
      mnccint_def_codec_f_cmd,
      "default-codec tch-f (fr|efr|amr)",
      "Set default codec\n" "Codec for TCH/F\n"
      "Full-Rate\n" "Enhanced Full-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[0] = get_string_value(tchf_codec_names, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_h,
      mnccint_def_codec_h_cmd,
      "default-codec tch-h (hr|amr)",
      "Set default codec\n" "Codec for TCH/H\n"
      "Half-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[1] = get_string_value(tchh_codec_names, argv[0]);

	return CMD_SUCCESS;
}


DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct vlr_subscr *vlr_subscr;
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	if (!tgt)
		return CMD_WARNING;

	vlr_subscr = vlr_subscr_find_by_imsi(gsmnet->vlr, imsi, VSUB_USE_VTY);

	if (!vlr_subscr) {
		vty_out(vty, "%%no subscriber with IMSI(%s)%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_vlr_subscr(tgt, vlr_subscr);
	vlr_subscr_put(vlr_subscr, VSUB_USE_VTY);
	return CMD_SUCCESS;
}

static struct cmd_node hlr_node = {
	HLR_NODE,
	"%s(config-hlr)# ",
	1,
};

DEFUN(cfg_hlr, cfg_hlr_cmd,
      "hlr", "Configure connection to the HLR")
{
	vty->node = HLR_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_remote_ip, cfg_hlr_remote_ip_cmd, "remote-ip A.B.C.D",
      "Remote GSUP address of the HLR\n"
      "Remote GSUP address (default: " MSC_HLR_REMOTE_IP_DEFAULT ")")
{
	talloc_free((void*)gsmnet->gsup_server_addr_str);
	gsmnet->gsup_server_addr_str = talloc_strdup(gsmnet, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_remote_port, cfg_hlr_remote_port_cmd, "remote-port <1-65535>",
      "Remote GSUP port of the HLR\n"
      "Remote GSUP port (default: " OSMO_STRINGIFY(MSC_HLR_REMOTE_PORT_DEFAULT) ")")
{
	gsmnet->gsup_server_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_ipa_name,
      cfg_hlr_ipa_name_cmd,
      "ipa-name NAME",
      "Set the IPA name of this MSC\n"
      "A unique name for this MSC. For example: PLMN + redundancy server number: MSC-901-70-0. "
      "This name is used for GSUP routing and must be set if more than one MSC is connected to the HLR. "
      "The default is 'MSC-00-00-00-00-00-00'.\n")
{
	if (vty->type != VTY_FILE) {
		vty_out(vty, "The IPA name cannot be changed at run-time; "
			"It can only be set in the configuraton file.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->msc_ipa_name = talloc_strdup(gsmnet, argv[0]);
	return CMD_SUCCESS;
}

static int config_write_hlr(struct vty *vty)
{
	vty_out(vty, "hlr%s", VTY_NEWLINE);
	vty_out(vty, " remote-ip %s%s",
		gsmnet->gsup_server_addr_str, VTY_NEWLINE);
	vty_out(vty, " remote-port %u%s",
		gsmnet->gsup_server_port, VTY_NEWLINE);
	if (gsmnet->msc_ipa_name)
		vty_out(vty, " ipa-name %s%s", gsmnet->msc_ipa_name, VTY_NEWLINE);
	return CMD_SUCCESS;
}

void msc_vty_init(struct gsm_network *msc_network)
{
	OSMO_ASSERT(gsmnet == NULL);
	gsmnet = msc_network;

	osmo_stats_vty_add_cmds();

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_authentication_cmd);
	install_element(GSMNET_NODE, &cfg_net_rrlp_mode_cmd);
	install_element(GSMNET_NODE, &cfg_net_mm_info_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_dst_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_per_loc_upd_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_per_loc_upd_cmd);

	install_element(CONFIG_NODE, &cfg_msc_cmd);
	install_node(&msc_node, config_write_msc);
	install_element(MSC_NODE, &cfg_msc_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_mncc_internal_cmd);
	install_element(MSC_NODE, &cfg_msc_mncc_external_cmd);
	install_element(MSC_NODE, &cfg_msc_mncc_guard_timeout_cmd);
	install_element(MSC_NODE, &cfg_msc_deprecated_mncc_guard_timeout_cmd);
	install_element(MSC_NODE, &cfg_msc_ncss_guard_timeout_cmd);
	install_element(MSC_NODE, &cfg_msc_no_assign_tmsi_cmd);
	install_element(MSC_NODE, &cfg_msc_auth_tuple_max_reuse_count_cmd);
	install_element(MSC_NODE, &cfg_msc_auth_tuple_reuse_on_error_cmd);
	install_element(MSC_NODE, &cfg_msc_check_imei_rqd_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_a_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_instance_iu_cmd);
	install_element(MSC_NODE, &cfg_msc_paging_response_timer_cmd);
	install_element(MSC_NODE, &cfg_msc_emergency_msisdn_cmd);
	install_element(MSC_NODE, &cfg_msc_sms_over_gsup_cmd);
	install_element(MSC_NODE, &cfg_msc_no_sms_over_gsup_cmd);
	install_element(MSC_NODE, &cfg_msc_handover_number_range_cmd);

	neighbor_ident_vty_init(msc_network);

	mgcp_client_vty_init(msc_network, MSC_NODE, &msc_network->mgw.conf);
#ifdef BUILD_IU
	ranap_iu_vty_init(MSC_NODE, (enum ranap_nsap_addr_enc*)&msc_network->iu.rab_assign_addr_enc);
#endif
	sgs_vty_init();

	osmo_fsm_vty_add_cmds();

	osmo_signal_register_handler(SS_SCALL, scall_cbfn, NULL);

	install_element_ve(&show_subscr_cmd);
	install_element_ve(&show_subscr_cache_cmd);
	install_element_ve(&show_bsc_cmd);
	install_element_ve(&show_msc_conn_cmd);
	install_element_ve(&show_msc_transaction_cmd);

	install_element_ve(&sms_send_pend_cmd);
	install_element_ve(&sms_delete_expired_cmd);

	install_element_ve(&subscriber_create_cmd);
	install_element_ve(&subscriber_send_sms_cmd);
	install_element_ve(&subscriber_silent_sms_cmd);
	install_element_ve(&subscriber_silent_call_start_cmd);
	install_element_ve(&subscriber_silent_call_stop_cmd);
	install_element_ve(&subscriber_ussd_notify_cmd);
	install_element_ve(&subscriber_mstest_close_cmd);
	install_element_ve(&subscriber_mstest_open_cmd);
	install_element_ve(&subscriber_paging_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_smsqueue_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);

	install_element(ENABLE_NODE, &ena_subscr_expire_cmd);
	install_element(ENABLE_NODE, &smsqueue_trigger_cmd);
	install_element(ENABLE_NODE, &smsqueue_max_cmd);
	install_element(ENABLE_NODE, &smsqueue_clear_cmd);
	install_element(ENABLE_NODE, &smsqueue_fail_cmd);
	install_element(ENABLE_NODE, &subscriber_send_pending_sms_cmd);
	install_element(ENABLE_NODE, &subscriber_sms_delete_all_cmd);

	install_element(CONFIG_NODE, &cfg_mncc_int_cmd);
	install_node(&mncc_int_node, config_write_mncc_int);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_f_cmd);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_h_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);

	install_element(CONFIG_NODE, &cfg_hlr_cmd);
	install_node(&hlr_node, config_write_hlr);
	install_element(HLR_NODE, &cfg_hlr_remote_ip_cmd);
	install_element(HLR_NODE, &cfg_hlr_remote_port_cmd);
	install_element(HLR_NODE, &cfg_hlr_ipa_name_cmd);
}
