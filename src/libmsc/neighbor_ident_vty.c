/* Quagga VTY implementation to manage identity of neighboring BSS cells for inter-BSC handover. */
/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
#include <string.h>
#include <errno.h>

#include <osmocom/vty/command.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include <osmocom/msc/vty.h>
#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/gsm_data.h>

#define NEIGHBOR_ADD_CMD "neighbor "
#define NEIGHBOR_DEL_CMD "no neighbor "
#define NEIGHBOR_DOC "Manage neighbor BSS cells\n"
#define NEIGHBOR_ADD_DOC NEIGHBOR_DOC "Add "
#define NEIGHBOR_DEL_DOC NO_STR "Remove neighbor BSS cell\n"

#define LAC_PARAMS "lac <0-65535>"
#define LAC_DOC "Neighbor cell by LAC\n" "LAC\n"

#define LAC_CI_PARAMS "lac-ci <0-65535> <0-65535>"
#define LAC_CI_DOC "Neighbor cell by LAC and CI\n" "LAC\n" "CI\n"

#define CGI_PARAMS "cgi <0-999> <0-999> <0-65535> <0-65535>"
#define CGI_DOC "Neighbor cell by cgi\n" "MCC\n" "MNC\n" "LAC\n" "CI\n"

#define NEIGHBOR_IDENT_VTY_BSC_ADDR_PARAMS "bsc-pc POINT_CODE"
#define NEIGHBOR_IDENT_VTY_BSC_ADDR_DOC "Point code of neighbor BSC\n" "Point code value\n"
#define NEIGHBOR_IDENT_VTY_MSC_ADDR_PARAMS "msc-ipa-name IPA_NAME"
#define NEIGHBOR_IDENT_VTY_MSC_ADDR_DOC "IPA name of neighbor MSC\n" "IPA name value\n"

static struct gsm_network *g_net = NULL;

#if 0
static struct gsm0808_cell_id *neighbor_ident_vty_parse_lac(struct vty *vty, const char **argv)
{
	static struct gsm0808_cell_id cell_id;
	cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC,
		.id.lac = atoi(argv[0]),
	};
	return &cell_id;
}

static struct gsm0808_cell_id *neighbor_ident_vty_parse_lac_ci(struct vty *vty, const char **argv)
{
	static struct gsm0808_cell_id cell_id;
	cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC_AND_CI,
		.id.lac_and_ci = {
			.lac = atoi(argv[0]),
			.ci = atoi(argv[1]),
		},
	};
	return &cell_id;
}
#endif

static struct gsm0808_cell_id *neighbor_ident_vty_parse_cgi(struct vty *vty, const char **argv)
{
	static struct gsm0808_cell_id cell_id;
	cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_WHOLE_GLOBAL,
	};
	struct osmo_cell_global_id *cgi = &cell_id.id.global;
	const char *mcc = argv[0];
	const char *mnc = argv[1];
	const char *lac = argv[2];
	const char *ci = argv[3];

	if (osmo_mcc_from_str(mcc, &cgi->lai.plmn.mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", mcc, VTY_NEWLINE);
		return NULL;
	}

	if (osmo_mnc_from_str(mnc, &cgi->lai.plmn.mnc, &cgi->lai.plmn.mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", mnc, VTY_NEWLINE);
		return NULL;
	}

	cgi->lai.lac = atoi(lac);
	cgi->cell_identity = atoi(ci);
	return &cell_id;
}

static int add_neighbor(struct vty *vty, struct neighbor_ident_addr *addr, const struct gsm0808_cell_id *cell_id)
{
	struct gsm0808_cell_id_list2 cell_ids;
	int rc;

	gsm0808_cell_id_to_list(&cell_ids, cell_id);
	rc = neighbor_ident_add(g_net->neighbor_list, addr, &cell_ids);
	if (rc < 0) {
		vty_out(vty, "%% Error: cannot add cell %s to neighbor %s: %s%s",
			gsm0808_cell_id_name(cell_id), neighbor_ident_addr_name(g_net, addr),
			strerror(-rc), VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_neighbor_add_lac, cfg_neighbor_add_lac_cmd,
	NEIGHBOR_ADD_CMD LAC_PARAMS,
	NEIGHBOR_ADD_DOC LAC_DOC)
{
	return add_local_bts(vty, bts_by_cell_id(vty, neighbor_ident_vty_parse_lac(vty, argv)));
}

DEFUN(cfg_neighbor_add_lac_ci, cfg_neighbor_add_lac_ci_cmd,
	NEIGHBOR_ADD_CMD LAC_CI_PARAMS,
	NEIGHBOR_ADD_DOC LAC_CI_DOC)
{
	return add_local_bts(vty, bts_by_cell_id(vty, neighbor_ident_vty_parse_lac_ci(vty, argv)));
}
#endif

static int parse_point_code(const char *point_code_str)
{
	struct osmo_ss7_instance *ss7 = osmo_ss7_instance_find(g_net->a.cs7_instance);
	OSMO_ASSERT(ss7);
	return osmo_ss7_pointcode_parse(ss7, point_code_str);
}

DEFUN(cfg_neighbor_add_cgi_bsc, cfg_neighbor_add_cgi_bsc_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS " " NEIGHBOR_IDENT_VTY_BSC_ADDR_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC " " NEIGHBOR_IDENT_VTY_BSC_ADDR_DOC)
{
	struct neighbor_ident_addr addr;
	int point_code = parse_point_code(argv[4]);

	if (point_code < 0) {
		vty_out(vty, "Could not parse point code '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr.type = MSC_NEIGHBOR_TYPE_BSC;
	addr.a.point_code = point_code;
	return add_neighbor(vty, &addr, neighbor_ident_vty_parse_cgi(vty, argv + 1));
}

DEFUN(cfg_neighbor_add_cgi_msc, cfg_neighbor_add_cgi_msc_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS " " NEIGHBOR_IDENT_VTY_MSC_ADDR_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC " " NEIGHBOR_IDENT_VTY_MSC_ADDR_DOC)
{
	struct neighbor_ident_addr addr;

	addr.type = MSC_NEIGHBOR_TYPE_MSC;
	addr.a.ipa_name = argv[4];
	return add_neighbor(vty, &addr, neighbor_ident_vty_parse_cgi(vty, argv + 1));
}

static int del_by_addr(struct vty *vty, const struct neighbor_ident_addr *addr)
{
	int removed = 0;

	if (vty->node != MSC_NODE) {
		vty_out(vty, "%% Error: cannot remove neighbor, not on MSC node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (neighbor_ident_del(g_net->neighbor_list, addr)) {
		vty_out(vty, "%% Removed neighbor %s%s",
			neighbor_ident_addr_name(g_net, addr), VTY_NEWLINE);
		removed = 1;
	}

	if (!removed) {
		vty_out(vty, "%% Cannot remove, no such neighbor: %s%s",
			neighbor_ident_addr_name(g_net, addr), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_del_neighbor_bsc, cfg_del_neighbor_bsc_cmd,
      "del neighbor " NEIGHBOR_IDENT_VTY_BSC_ADDR_PARAMS,
      SHOW_STR "Delete a neighbor BSC\n" "BSC point code\n"
      "Delete a specified neighbor BSC\n"
      NEIGHBOR_IDENT_VTY_BSC_ADDR_DOC)
{
	struct neighbor_ident_addr addr;
	int point_code = parse_point_code(argv[0]);

	if (point_code < 0) {
		vty_out(vty, "Could not parse point code '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	addr.type = MSC_NEIGHBOR_TYPE_BSC;
	addr.a.point_code = point_code;
	return del_by_addr(vty, &addr);
}

DEFUN(cfg_del_neighbor_msc, cfg_del_neighbor_msc_cmd,
      "del neighbor " NEIGHBOR_IDENT_VTY_MSC_ADDR_PARAMS,
      SHOW_STR "Delete a neighbor MSC\n" "MSC ipa-nam\n"
      "Delete a specified neighbor MSC\n"
      NEIGHBOR_IDENT_VTY_MSC_ADDR_DOC)
{
	struct neighbor_ident_addr addr;

	addr.type = MSC_NEIGHBOR_TYPE_MSC;
	addr.a.ipa_name = argv[0];
	return del_by_addr(vty, &addr);
}

static void write_neighbor_ident(struct vty *vty, const struct neighbor_ident *ni)
{
	const struct neighbor_ident_addr *addr = &ni->addr;
	const struct gsm0808_cell_id_list2 *cell_ids = &ni->cell_ids;
	struct osmo_ss7_instance *ss7;
	int i;

	switch (cell_ids->id_discr) {
	case CELL_IDENT_LAC:
		for (i = 0; i < cell_ids->id_list_len; i++) {
			vty_out(vty, "neighbor lac %u", cell_ids->id_list[i].lac);
		}
		break;
	case CELL_IDENT_LAC_AND_CI:
		for (i = 0; i < cell_ids->id_list_len; i++) {
			vty_out(vty, "neighbor lac-ci %u %u", cell_ids->id_list[i].lac_and_ci.lac,
				cell_ids->id_list[i].lac_and_ci.ci);
		}
		break;
	case CELL_IDENT_WHOLE_GLOBAL:
		for (i = 0; i < cell_ids->id_list_len; i++) {
			const struct osmo_cell_global_id *cgi = &cell_ids->id_list[i].global;
			vty_out(vty, "neighbor cgi %s %s %u %u", osmo_mcc_name(cgi->lai.plmn.mcc),
				osmo_mnc_name(cgi->lai.plmn.mnc, cgi->lai.plmn.mnc_3_digits),
				cgi->lai.lac, cgi->cell_identity);
		}
		break;
	default:
		vty_out(vty, "%% Unsupported Cell Identity%s", VTY_NEWLINE);
		return;
	}

	switch (ni->addr.type) {
	case MSC_NEIGHBOR_TYPE_BSC:
		ss7 = osmo_ss7_instance_find(g_net->a.cs7_instance);
		OSMO_ASSERT(ss7);
		vty_out(vty, "bsc-pc %s%s", osmo_ss7_pointcode_print(ss7, addr->a.point_code), VTY_NEWLINE);
		break;
	case MSC_NEIGHBOR_TYPE_MSC:
		vty_out(vty, "msc-ipa-name %s%s", addr->a.ipa_name, VTY_NEWLINE);
		break;
	}
}

void neighbor_ident_vty_write(struct vty *vty)
{
	const struct neighbor_ident *ni;

	llist_for_each_entry(ni, &g_net->neighbor_list->list, entry)
		write_neighbor_ident(vty, ni);
}

DEFUN(show_neighbor_bsc, show_neighbor_bsc_cmd,
      "show neighbor " NEIGHBOR_IDENT_VTY_BSC_ADDR_PARAMS,
      SHOW_STR "Display information about a neighbor BSC\n" "BSC point code\n"
      "Show which cells are reachable via the specified neighbor BSC\n"
      NEIGHBOR_IDENT_VTY_BSC_ADDR_DOC)
{
	int point_code;
	struct neighbor_ident *ni;
	int found = 0;

	point_code = parse_point_code(argv[0]);
	if (point_code < 0) {
		vty_out(vty, "Could not parse point code '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(ni, &g_net->neighbor_list->list, entry) {
		if (ni->addr.type != MSC_NEIGHBOR_TYPE_BSC)
			continue;
		if (ni->addr.a.point_code == point_code) {
			vty_out(vty, "%s%s", gsm0808_cell_id_list_name(&ni->cell_ids), VTY_NEWLINE);
			found = 1;
			break;
		}
	}

	if (!found)
		vty_out(vty, "%% No entry for %s%s", argv[0], VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(show_neighbor_msc, show_neighbor_msc_cmd,
      "show neighbor " NEIGHBOR_IDENT_VTY_MSC_ADDR_PARAMS,
      SHOW_STR "Display information about a neighbor MSC\n" "MSC ipa-name\n"
      "Show which cells are reachable via the specified neighbor MSC\n"
      NEIGHBOR_IDENT_VTY_MSC_ADDR_DOC)
{
	const char *ipa_name = argv[0];
	struct neighbor_ident *ni;
	int found = 0;

	llist_for_each_entry(ni, &g_net->neighbor_list->list, entry) {
		if (ni->addr.type != MSC_NEIGHBOR_TYPE_MSC)
			continue;
		if (strcmp(ni->addr.a.ipa_name, ipa_name) == 0) {
			vty_out(vty, "%s%s", gsm0808_cell_id_list_name(&ni->cell_ids), VTY_NEWLINE);
			found = 1;
			break;
		}
	}

	if (!found)
		vty_out(vty, "%% No entry for %s%s", ipa_name, VTY_NEWLINE);

	return CMD_SUCCESS;
}

void neighbor_ident_vty_init(struct gsm_network *net)
{
	g_net = net;
	g_net->neighbor_list = neighbor_ident_init(net);
#if 0
	install_element(MSC_NODE, &cfg_neighbor_add_lac_cmd);
	install_element(MSC_NODE, &cfg_neighbor_add_lac_ci_cmd);
#endif
	install_element(MSC_NODE, &cfg_neighbor_add_cgi_bsc_cmd);
	install_element(MSC_NODE, &cfg_neighbor_add_cgi_msc_cmd);
	install_element(MSC_NODE, &cfg_del_neighbor_bsc_cmd);
	install_element(MSC_NODE, &cfg_del_neighbor_msc_cmd);
	install_element_ve(&show_neighbor_bsc_cmd);
	install_element_ve(&show_neighbor_msc_cmd);
}
