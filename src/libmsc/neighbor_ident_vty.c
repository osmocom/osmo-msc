/* Quagga VTY implementation to manage identity of neighboring BSS cells for inter-BSC handover. */
/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 * Author: Stefan Sperling <ssperling@sysmocom.de>
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
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/msc/vty.h>
#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/cell_id_list.h>

#define NEIGHBOR_ADD_CMD "neighbor"
#define NEIGHBOR_ADD_DOC "Add Handover target configuration\n"

#define NEIGHBOR_DEL_CMD "no neighbor"
#define NEIGHBOR_DEL_DOC NO_STR "Remove Handover target\n"

#define NEIGHBOR_SHOW_CMD "show neighbor"
#define NEIGHBOR_SHOW_DOC SHOW_STR "Show Handover targets\n"

#define RAN_TYPE_PARAMS "(a|iu)"
#define RAN_TYPE_DOC "Neighbor on GERAN-A\n" "Neighbor on UTRAN-Iu\n"

#define RAN_PC_TOKEN "ran-pc"
#define MSC_IPA_NAME_TOKEN "msc-ipa-name"
#define HO_TARGET_PARAMS "("RAN_PC_TOKEN"|"MSC_IPA_NAME_TOKEN") RAN_PC_OR_MSC_IPA_NAME"
#define HO_TARGET_DOC "SCCP point code of RAN peer\n" "GSUP IPA name of target MSC\n" "Point code or MSC IPA name value\n"

#define LAC_PARAMS "lac <0-65535>"
#define LAC_ARGC 1
#define LAC_DOC "Handover target cell by LAC\n" "LAC\n"

#define LAC_CI_PARAMS "lac-ci <0-65535> <0-65535>"
#define LAC_CI_ARGC 2
#define LAC_CI_DOC "Handover target cell by LAC and CI\n" "LAC\n" "CI\n"

#define CGI_PARAMS "cgi <0-999> <0-999> <0-65535> <0-65535>"
#define CGI_ARGC 4
#define CGI_DOC "Handover target cell by Cell-Global Identifier (MCC, MNC, LAC, CI)\n" "MCC\n" "MNC\n" "LAC\n" "CI\n"

static struct gsm_network *gsmnet = NULL;

static void write_neighbor_ident_cell(struct vty *vty, const struct neighbor_ident_entry *e,
				      const struct gsm0808_cell_id *cid)
{
	vty_out(vty, " " NEIGHBOR_ADD_CMD " ");

	switch (e->addr.ran_type) {
	case OSMO_RAT_GERAN_A:
		vty_out(vty, "a");
		break;
	case OSMO_RAT_UTRAN_IU:
		vty_out(vty, "iu");
		break;
	default:
		vty_out(vty, "<Unsupported-RAN-type>");
		break;
	}

	vty_out(vty, " ");

	switch (cid->id_discr) {
	case CELL_IDENT_LAC:
		vty_out(vty, "lac %u", cid->id.lac);
		break;
	case CELL_IDENT_LAC_AND_CI:
		vty_out(vty, "lac-ci %u %u",
			cid->id.lac_and_ci.lac,
			cid->id.lac_and_ci.ci);
		break;
	case CELL_IDENT_WHOLE_GLOBAL:
		vty_out(vty, "cgi %s %s %u %u",
			osmo_mcc_name(cid->id.global.lai.plmn.mcc),
			osmo_mnc_name(cid->id.global.lai.plmn.mnc, cid->id.global.lai.plmn.mnc_3_digits),
			cid->id.global.lai.lac,
			cid->id.global.cell_identity);
		break;
	default:
		vty_out(vty, "<Unsupported-Cell-Identity>");
		break;
	}

	vty_out(vty, " ");

	switch (e->addr.type) {
	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		vty_out(vty, RAN_PC_TOKEN " %s", e->addr.local_ran_peer_pc_str);
		break;
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		vty_out(vty, MSC_IPA_NAME_TOKEN " %s", osmo_escape_str(e->addr.remote_msc_ipa_name.buf,
								e->addr.remote_msc_ipa_name.len));
		break;
	default:
		vty_out(vty, "<Unsupported-target-type>");
		break;
	}

	vty_out(vty, "%s", VTY_NEWLINE);
}

static void write_neighbor_ident_entry(struct vty *vty, const struct neighbor_ident_entry *e)
{
	struct cell_id_list_entry *le;

	llist_for_each_entry(le, &e->cell_ids, entry) {
		write_neighbor_ident_cell(vty, e, &le->cell_id);
	}

}

static void write_neighbor_ident_entry_by_cell(struct vty *vty, const struct neighbor_ident_entry *e,
					       const struct gsm0808_cell_id *cid)
{
	struct cell_id_list_entry *le;

	llist_for_each_entry(le, &e->cell_ids, entry) {
		if (!gsm0808_cell_ids_match(&le->cell_id, cid, false))
			continue;
		write_neighbor_ident_cell(vty, e, &le->cell_id);
	}

}

void neighbor_ident_vty_write(struct vty *vty)
{
	const struct neighbor_ident_entry *e;

	llist_for_each_entry(e, &gsmnet->neighbor_ident_list, entry) {
		write_neighbor_ident_entry(vty, e);
	}
}

void neighbor_ident_vty_write_by_ran_type(struct vty *vty, enum osmo_rat_type ran_type)
{
	const struct neighbor_ident_entry *e;

	llist_for_each_entry(e, &gsmnet->neighbor_ident_list, entry) {
		if (e->addr.ran_type != ran_type)
			continue;
		write_neighbor_ident_entry(vty, e);
	}
}

void neighbor_ident_vty_write_by_cell(struct vty *vty, enum osmo_rat_type ran_type, const struct gsm0808_cell_id *cid)
{
	struct neighbor_ident_entry *e;

	llist_for_each_entry(e, &gsmnet->neighbor_ident_list, entry) {
		if (ran_type != OSMO_RAT_UNKNOWN
		    && e->addr.ran_type != ran_type)
			continue;
		write_neighbor_ident_entry_by_cell(vty, e, cid);
	}
}

static struct gsm0808_cell_id *parse_lac(struct vty *vty, const char **argv)
{
	static struct gsm0808_cell_id cell_id;
	cell_id = (struct gsm0808_cell_id){
		.id_discr = CELL_IDENT_LAC,
		.id.lac = atoi(argv[0]),
	};
	return &cell_id;
}

static struct gsm0808_cell_id *parse_lac_ci(struct vty *vty, const char **argv)
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

static struct gsm0808_cell_id *parse_cgi(struct vty *vty, const char **argv)
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
	if (!neighbor_ident_add(&gsmnet->neighbor_ident_list, addr, cell_id)) {
		vty_out(vty, "%% Error: cannot add cell %s to neighbor %s%s",
			gsm0808_cell_id_name(cell_id), neighbor_ident_addr_name(addr),
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

static enum osmo_rat_type parse_ran_type(struct vty *vty, const char *ran_type_str)
{
	if (!strcmp(ran_type_str, "a"))
		return OSMO_RAT_GERAN_A;
	else if (!strcmp(ran_type_str, "iu"))
		return OSMO_RAT_UTRAN_IU;
	vty_out(vty, "%% Error: cannot parse RAN type argument %s%s",
		osmo_quote_str(ran_type_str, -1), VTY_NEWLINE);
	return OSMO_RAT_UNKNOWN;
}

static enum msc_neighbor_type parse_target_type(struct vty *vty, const char *target_type_str)
{
	if (osmo_str_startswith(RAN_PC_TOKEN, target_type_str))
		return MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER;
	if (osmo_str_startswith(MSC_IPA_NAME_TOKEN, target_type_str))
		return MSC_NEIGHBOR_TYPE_REMOTE_MSC;
	vty_out(vty, "%% Unknown Handover target type: %s%s\n",
		osmo_quote_str(target_type_str, -1), VTY_NEWLINE);
	return MSC_NEIGHBOR_TYPE_NONE;
}

static int parse_ho_target_addr(struct vty *vty,
				struct neighbor_ident_addr *nia,
				enum osmo_rat_type ran_type,
				const char **argv)
{
	const char *target_type_str = argv[0];
	const char *arg_str = argv[1];
	int rc;

	*nia = (struct neighbor_ident_addr){
		.type = parse_target_type(vty, target_type_str),
		.ran_type = ran_type,
	};
	if (nia->ran_type == OSMO_RAT_UNKNOWN)
		return -1;

	switch (nia->type) {
	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		rc = osmo_strlcpy(nia->local_ran_peer_pc_str, arg_str, sizeof(nia->local_ran_peer_pc_str));
		if (rc < 1 || rc >= sizeof(nia->local_ran_peer_pc_str)) {
			vty_out(vty, "%% Invalid RAN peer point-code string: %s%s", osmo_quote_str(arg_str, -1), VTY_NEWLINE);
			return -1;
		}
		return 0;
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		if (msc_ipa_name_from_str(&nia->remote_msc_ipa_name, arg_str)) {
			vty_out(vty, "%% Invalid MSC IPA name: %s%s", osmo_quote_str(arg_str, -1), VTY_NEWLINE);
			return -1;
		}
		return 0;
	default:
		return -1;
	}
}

#define DEFUN_CELL(id_name, ID_NAME) \
 \
DEFUN(cfg_neighbor_add_##id_name, cfg_neighbor_add_##id_name##_cmd, \
	NEIGHBOR_ADD_CMD " "RAN_TYPE_PARAMS " " ID_NAME##_PARAMS " " HO_TARGET_PARAMS, \
	NEIGHBOR_ADD_DOC RAN_TYPE_DOC ID_NAME##_DOC HO_TARGET_DOC) \
{ \
	struct neighbor_ident_addr addr; \
	if (parse_ho_target_addr(vty, &addr, \
				 parse_ran_type(vty, argv[0]), \
				 argv + 1 + ID_NAME##_ARGC)) \
		return CMD_WARNING; \
	return add_neighbor(vty, &addr, parse_##id_name(vty, argv + 1)); \
} \
 \
DEFUN(show_neighbor_ran_##id_name, show_neighbor_ran_##id_name##_cmd, \
	NEIGHBOR_SHOW_CMD " " RAN_TYPE_PARAMS " " ID_NAME##_PARAMS, \
	NEIGHBOR_SHOW_DOC RAN_TYPE_DOC ID_NAME##_DOC RAN_TYPE_DOC) \
{ \
	neighbor_ident_vty_write_by_cell(vty, \
					 parse_ran_type(vty, argv[0]), \
					 parse_##id_name(vty, argv + 1)); \
	return CMD_SUCCESS; \
} \
 \
DEFUN(show_neighbor_##id_name, show_neighbor_##id_name##_cmd, \
	NEIGHBOR_SHOW_CMD " "ID_NAME##_PARAMS, \
	NEIGHBOR_SHOW_DOC ID_NAME##_DOC) \
{ \
	neighbor_ident_vty_write_by_cell(vty, OSMO_RAT_UNKNOWN, parse_##id_name(vty, argv)); \
	return CMD_SUCCESS; \
}

DEFUN_CELL(lac, LAC)
DEFUN_CELL(lac_ci, LAC_CI)
DEFUN_CELL(cgi, CGI)

static int del_by_addr(struct vty *vty, const struct neighbor_ident_addr *addr)
{
	const struct neighbor_ident_entry *e = neighbor_ident_find_by_addr(&gsmnet->neighbor_ident_list, addr);

	if (!e) {
		vty_out(vty, "%% Cannot remove, no such neighbor: %s%s",
			neighbor_ident_addr_name(addr), VTY_NEWLINE);
		return CMD_WARNING;
	}

	neighbor_ident_del(e);
	vty_out(vty, "%% Removed neighbor %s%s", neighbor_ident_addr_name(addr), VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_del_neighbor, cfg_del_neighbor_cmd,
      NEIGHBOR_DEL_CMD " " RAN_TYPE_PARAMS " "HO_TARGET_PARAMS,
      NEIGHBOR_DEL_DOC RAN_TYPE_DOC HO_TARGET_DOC)
{
	struct neighbor_ident_addr addr;
	if (parse_ho_target_addr(vty, &addr,
				 parse_ran_type(vty, argv[0]),
				 argv + 1))
		return CMD_WARNING;

	return del_by_addr(vty, &addr);
}

DEFUN(show_neighbor_all, show_neighbor_all_cmd,
      NEIGHBOR_SHOW_CMD,
      NEIGHBOR_SHOW_DOC)
{
	neighbor_ident_vty_write(vty);
	return CMD_SUCCESS;
}

DEFUN(show_neighbor_ran, show_neighbor_ran_cmd,
      NEIGHBOR_SHOW_CMD " " RAN_TYPE_PARAMS,
      NEIGHBOR_SHOW_DOC RAN_TYPE_DOC)
{
	neighbor_ident_vty_write_by_ran_type(vty, parse_ran_type(vty, argv[0]));
	return CMD_SUCCESS;
}

DEFUN(show_neighbor, show_neighbor_cmd,
      NEIGHBOR_SHOW_CMD " "RAN_TYPE_PARAMS " " HO_TARGET_PARAMS,
      NEIGHBOR_SHOW_DOC RAN_TYPE_DOC HO_TARGET_DOC)
{
	const struct neighbor_ident_entry *e;
	struct neighbor_ident_addr addr;
	if (parse_ho_target_addr(vty, &addr,
				 parse_ran_type(vty, argv[0]),
				 argv + 1))
		return CMD_WARNING;

	e = neighbor_ident_find_by_addr(&gsmnet->neighbor_ident_list, &addr);
	if (e)
		write_neighbor_ident_entry(vty, e);
	else
		vty_out(vty, "%% No such neighbor target%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

void neighbor_ident_vty_init(struct gsm_network *net)
{
	gsmnet = net;

	install_element(MSC_NODE, &cfg_neighbor_add_lac_cmd);
	install_element(MSC_NODE, &cfg_neighbor_add_lac_ci_cmd);
	install_element(MSC_NODE, &cfg_neighbor_add_cgi_cmd);
	install_element(MSC_NODE, &cfg_del_neighbor_cmd);
	install_element_ve(&show_neighbor_all_cmd);
	install_element_ve(&show_neighbor_cmd);
	install_element_ve(&show_neighbor_ran_cmd);

	install_element_ve(&show_neighbor_ran_lac_cmd);
	install_element_ve(&show_neighbor_ran_lac_ci_cmd);
	install_element_ve(&show_neighbor_ran_cgi_cmd);

	install_element_ve(&show_neighbor_lac_cmd);
	install_element_ve(&show_neighbor_lac_ci_cmd);
	install_element_ve(&show_neighbor_cgi_cmd);
}
