/* GCR interface to VTY */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Andreas Eversberg
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

#include <osmocom/msc/vty.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/msc_vgcs.h>
#include <osmocom/msc/asci_vty.h>
#include <osmocom/msc/asci_gcr.h>

static struct gsm_network *gsmnet;

/***********************************************************************
 * ASCI Node
 ***********************************************************************/

#define ASCI_STR "Advanced Speech Call Items\n"

static void asci_disabled(struct vty *vty)
{
       vty_out(vty, "%%Advanced Speech Call Items are disabled.%s", VTY_NEWLINE);
}

DEFUN(asci_call, asci_call_cmd,
      "asci (initiate|terminate) (vgc|vbc) CALLREF",
      ASCI_STR "Initiate a call\nTerminate a call\nVoice Group Call\nVoice Broadcast Call\nCall reference")
{
	struct gcr *gcr;
	const char *error;

	if (!gsmnet->asci.enable) {
		asci_disabled(vty);
		return CMD_WARNING;
	}

	gcr = gcr_by_group_id(gsmnet, (argv[1][1] == 'g') ? TRANS_GCC : TRANS_BCC, argv[2]);
	if (!gcr) {
		vty_out(vty, "%%Given call ref does not exist in GCR.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (argv[0][0] == 'i')
		error = vgcs_vty_initiate(gsmnet, gcr);
	else
		error = vgcs_vty_terminate(gsmnet, gcr);
	if (error) {
		vty_out(vty, "%%%s%s", error, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(asci_show, asci_show_cmd,
      "show asci calls",
      SHOW_STR ASCI_STR "Show all Voice Group/Broadcast Calls")
{
	struct gsm_trans *trans;
	const char *typestr;
	struct vgcs_bss *bss;
	struct vgcs_bss_cell *cell;

	if (!gsmnet->asci.enable) {
		asci_disabled(vty);
		return CMD_WARNING;
	}

	llist_for_each_entry(trans, &gsmnet->trans_list, entry) {
		if (trans->type == TRANS_GCC)
			typestr = "Group";
		else if (trans->type == TRANS_BCC)
			typestr = "Broadcast";
		else
			continue;
		vty_out(vty, "Call Reference %s (Voice %s Call).%s", gsm44068_group_id_string(trans->callref),
			typestr, VTY_NEWLINE);
		vty_out(vty, " Call state  : %s%s", vgcs_bcc_gcc_state_name(trans->gcc.fi), VTY_NEWLINE);
		vty_out(vty, " Uplink state: %s%s", (trans->gcc.uplink_busy) ? "busy" : "free", VTY_NEWLINE);
		if (trans->gcc.uplink_busy)
			vty_out(vty, " Talker      : %s subscriber%s",
				(trans->gcc.uplink_originator) ? "calling" : "other", VTY_NEWLINE);
		llist_for_each_entry(bss, &trans->gcc.bss_list, list) {
			vty_out(vty, " BSS %8s: listening%s%s", osmo_ss7_pointcode_print(NULL, bss->pc),
				(trans->gcc.uplink_busy && bss == trans->gcc.uplink_bss) ? "+talking" : "",
				VTY_NEWLINE);
			llist_for_each_entry(cell, &bss->cell_list, list_bss) {
				vty_out(vty, "  Cell %6d: listening%s%s", cell->cell_id,
					(trans->gcc.uplink_busy && cell == trans->gcc.uplink_cell) ? "+talking" : "",
					VTY_NEWLINE);
			}
		}
	}

	return CMD_SUCCESS;
}

/***********************************************************************
 * GCR Config Node
 ***********************************************************************/

static struct cmd_node asci_node = {
	ASCI_NODE,
	"%s(config-asci)# ",
	1,
};

static struct cmd_node gcr_node = {
	GCR_NODE,
	"%s(config-gcr)# ",
	1,
};

char conf_prompt[64];

static struct cmd_node vgc_node = {
	VGC_NODE,
	conf_prompt,
	1,
};

static struct cmd_node vbc_node = {
	VBC_NODE,
	conf_prompt,
	1,
};

DEFUN(cfg_asci, cfg_asci_cmd,
      "asci", "Enable and configure " ASCI_STR)
{
	vty->node = ASCI_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_enable_disable, cfg_enable_disable_cmd,
      "(enable|disable)", "Enable " ASCI_STR "Disable " ASCI_STR)
{
	gsmnet->asci.enable = (argv[0][0] == 'e');
	return CMD_SUCCESS;
}

DEFUN(cfg_gcr, cfg_gcr_cmd,
      "gcr", "Configure Group Call Register")
{
	vty->node = GCR_NODE;
	return CMD_SUCCESS;
}

static bool valid_group_id(const char *id, struct vty *vty)
{
	int i;

	if (strlen(id) < 1 || strlen(id) > 8) {
		vty_out(vty, "%%Given group ID is not valid. Use up to 8 numeric digits!%s", VTY_NEWLINE);
		return false;
	}
	for (i = 0; i < strlen(id); i++) {
		if (id[i] < '0' || id[i] > '9') {
			vty_out(vty, "%%Given group ID is not valid. Use numeric digits only!%s", VTY_NEWLINE);
			return false;
		}
	}

	return true;
}

DEFUN(cfg_vgc, cfg_vgc_cmd,
      "vgc ID", "Configure Voice Group Call\n" "Group ID")
{
	struct gcr *gcr;

	if (!valid_group_id(argv[0], vty))
		return CMD_WARNING;

	gcr = gcr_by_group_id(gsmnet, TRANS_GCC, argv[0]);
	if (!gcr)
		gcr = gcr_create(gsmnet, TRANS_GCC, argv[0]);
	if (!gcr)
		return CMD_WARNING;

	sprintf(conf_prompt, "%%s(vgc-%s)# ", gcr->group_id);
	vty->node = VGC_NODE;
	vty->index = gcr;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_vgc, cfg_no_vgc_cmd,
      "no vgc ID", NO_STR "Configure Voice Group Call\n" "Group ID")
{
	struct gcr *gcr;

	if (!valid_group_id(argv[0], vty))
		return CMD_WARNING;

	gcr = gcr_by_group_id(gsmnet, TRANS_GCC, argv[0]);
	if (!gcr) {
		vty_out(vty, "%%Voice group call with given group ID does not exit!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	gcr_destroy(gcr);

	return CMD_SUCCESS;
}

DEFUN(cfg_vbc, cfg_vbc_cmd,
      "vbc ID", "Configure Voice Broadcast Call\n" "Group ID")
{
	struct gcr *gcr;

	if (!valid_group_id(argv[0], vty))
		return CMD_WARNING;

	gcr = gcr_by_group_id(gsmnet, TRANS_BCC, argv[0]);
	if (!gcr)
		gcr = gcr_create(gsmnet, TRANS_BCC, argv[0]);
	if (!gcr)
		return CMD_WARNING;

	sprintf(conf_prompt, "%%s(vbc-%s)# ", gcr->group_id);
	vty->node = VBC_NODE;
	vty->index = gcr;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_vbc, cfg_no_vbc_cmd,
      "no vbc ID", NO_STR "Configure Voice Broadcast Call\n" "Group ID")
{
	struct gcr *gcr;

	if (!valid_group_id(argv[0], vty))
		return CMD_WARNING;

	gcr = gcr_by_group_id(gsmnet, TRANS_BCC, argv[0]);
	if (!gcr) {
		vty_out(vty, "%%Voice broadcast call with given group ID does not exit!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	gcr_destroy(gcr);

	return CMD_SUCCESS;
}

DEFUN(cfg_mute, cfg_mute_cmd,
      "mute-talker", "Mute talker's downlink")
{
	struct gcr *gcr = vty->index;

	gcr->mute_talker = true;

	return CMD_SUCCESS;
}

DEFUN(cfg_unmute, cfg_unmute_cmd,
      "unmute-talker", "Unmute talker's downlink")
{
	struct gcr *gcr = vty->index;

	gcr->mute_talker = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_timeout, cfg_timeout_cmd,
      "timeout <1-65535>", "Set inactivity timer\n" "Timeout in seconds")
{
	struct gcr *gcr = vty->index;

	gcr->timeout = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_no_timeout, cfg_no_timeout_cmd,
      "no timeout", NO_STR "Unset inactivity timer")
{
	struct gcr *gcr = vty->index;

	gcr->timeout = 0;

	return CMD_SUCCESS;
}

#define PC_ID_STR "Point code of MSC\nCell ID of BTS"

DEFUN(cfg_no_cell, cfg_no_cell_cmd,
      "no cell POINT_CODE [<0-65535>]", NO_STR "Remove BSS/cell from current group\n" PC_ID_STR)
{
	struct osmo_ss7_instance *ss7 = osmo_ss7_instance_find(0);
	struct gcr *gcr = vty->index;
	struct gcr_bss *bss;
	int pc = osmo_ss7_pointcode_parse(ss7, argv[0]);
	uint16_t cell_id;

	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bss = gcr_find_bss(gcr, pc);
	if (!bss) {
		vty_out(vty, "%%Given BSS point code does not exit in list!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc > 1) {
		cell_id = atoi(argv[1]);
		if (!gcr_find_cell(bss, cell_id)) {
			vty_out(vty, "%%Given cell does not exit in list!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		/* Remove cell only. Exit if there are still cells for this BSS. */
		gcr_rm_cell(bss, cell_id);
		if (!llist_empty(&bss->cell_list))
			return CMD_SUCCESS;
	}

	gcr_rm_bss(gcr, pc);

	return CMD_SUCCESS;
}

DEFUN(cfg_cell, cfg_cell_cmd,
      "cell POINT_CODE <0-65535>", "Add cell to current group\n" PC_ID_STR)
{
	struct osmo_ss7_instance *ss7 = osmo_ss7_instance_find(0);
	struct gcr *gcr = vty->index;
	struct gcr_bss *bss;
	int pc = osmo_ss7_pointcode_parse(ss7, argv[0]);
	uint16_t cell_id = atoi(argv[1]);

	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bss = gcr_find_bss(gcr, pc);
	if (!bss)
		bss = gcr_add_bss(gcr, pc);
	if (!bss)
		return CMD_WARNING;

	if (gcr_find_cell(bss, cell_id))
		return CMD_SUCCESS;

	gcr_add_cell(bss, cell_id);

	return CMD_SUCCESS;
}

static int config_write_asci(struct vty *vty)
{
	struct osmo_ss7_instance *ss7 = osmo_ss7_instance_find(0);
	struct gcr *gcr;
	struct gcr_bss *b;
	struct gcr_cell *c;

	vty_out(vty, "asci%s", VTY_NEWLINE);

	vty_out(vty, " %s%s", (gsmnet->asci.enable) ? "enable" : "disable", VTY_NEWLINE);

	vty_out(vty, " gcr%s", VTY_NEWLINE);

	llist_for_each_entry(gcr, &gsmnet->asci.gcr_lists, list) {
		vty_out(vty, "  %s %s%s", (gcr->trans_type == TRANS_GCC) ? "vgc" : "vbc", gcr->group_id, VTY_NEWLINE);
		if (gcr->trans_type == TRANS_GCC) {
			if (gcr->timeout)
				vty_out(vty, "   timeout %d%s", gcr->timeout, VTY_NEWLINE);
			else
				vty_out(vty, "   no timeout%s", VTY_NEWLINE);
		}
		if (gcr->mute_talker)
			vty_out(vty, "   mute-talker%s", VTY_NEWLINE);
		else
			vty_out(vty, "   unmute-talker%s", VTY_NEWLINE);
		if (llist_empty(&gcr->bss_list))
			vty_out(vty, "   ! Please add cell(s) here!%s", VTY_NEWLINE);
		llist_for_each_entry(b, &gcr->bss_list, list) {
			llist_for_each_entry(c, &b->cell_list, list)
				vty_out(vty, "   cell %s %d%s", osmo_ss7_pointcode_print(ss7, b->pc), c->cell_id, VTY_NEWLINE);
		}
	}

	return CMD_SUCCESS;
}

void asci_vty_init(struct gsm_network *msc_network)
{
	OSMO_ASSERT(gsmnet == NULL);
	gsmnet = msc_network;

	install_element_ve(&asci_show_cmd);
	/* enable node */
	install_element(ENABLE_NODE, &asci_call_cmd);
	/* Config node */
	install_element(CONFIG_NODE, &cfg_asci_cmd);
	install_node(&asci_node, config_write_asci);
	install_element(ASCI_NODE, &cfg_enable_disable_cmd);
	install_element(ASCI_NODE, &cfg_gcr_cmd);
	install_node(&gcr_node, NULL);
	install_element(GCR_NODE, &cfg_vgc_cmd);
	install_element(GCR_NODE, &cfg_no_vgc_cmd);
	install_node(&vgc_node, NULL);
	install_element(GCR_NODE, &cfg_vbc_cmd);
	install_element(GCR_NODE, &cfg_no_vbc_cmd);
	install_node(&vbc_node, NULL);
	install_element(VGC_NODE, &cfg_mute_cmd);
	install_element(VGC_NODE, &cfg_unmute_cmd);
	install_element(VGC_NODE, &cfg_timeout_cmd);
	install_element(VGC_NODE, &cfg_no_timeout_cmd);
	install_element(VGC_NODE, &cfg_cell_cmd);
	install_element(VGC_NODE, &cfg_no_cell_cmd);
	/* Add all VGC_NODEs again for VBC_NODEs. */
	install_element(VBC_NODE, &cfg_mute_cmd);
	install_element(VBC_NODE, &cfg_unmute_cmd);
	install_element(VBC_NODE, &cfg_cell_cmd);
	install_element(VBC_NODE, &cfg_no_cell_cmd);
}
