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

#include <osmocom/bsc/vty.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/gsm_data.h>

static struct gsm_network *g_net = NULL;
static struct neighbor_ident_list *g_neighbor_cells = NULL;

/* Parse VTY parameters matching NEIGHBOR_IDENT_VTY_KEY_PARAMS. Pass a pointer so that argv[0] is the
 * ARFCN value followed by the BSIC keyword and value. vty *must* reference a BTS_NODE. */
bool neighbor_ident_vty_parse_key_params(struct vty *vty, const char **argv,
					 struct neighbor_ident_key *key)
{
	struct gsm_bts *bts = vty->index;

	OSMO_ASSERT(vty->node == BTS_NODE);
	OSMO_ASSERT(bts);

	return neighbor_ident_bts_parse_key_params(vty, bts, argv, key);
}

/* same as neighbor_ident_vty_parse_key_params() but pass an explicit bts, so it works on any node. */
bool neighbor_ident_bts_parse_key_params(struct vty *vty, struct gsm_bts *bts, const char **argv,
					 struct neighbor_ident_key *key)
{
	const char *arfcn_str = argv[0];
	const char *bsic_str = argv[1];

	OSMO_ASSERT(bts);

	*key = (struct neighbor_ident_key){
		.from_bts = bts->nr,
		.arfcn = atoi(arfcn_str),
	};

	if (!strcmp(bsic_str, "any"))
		key->bsic = BSIC_ANY;
	else
		key->bsic = atoi(bsic_str);
	return true;
}

#define NEIGHBOR_ADD_CMD "neighbor "
#define NEIGHBOR_DEL_CMD "no neighbor "
#define NEIGHBOR_DOC "Manage local and remote-BSS neighbor cells\n"
#define NEIGHBOR_ADD_DOC NEIGHBOR_DOC "Add "
#define NEIGHBOR_DEL_DOC NO_STR "Remove local or remote-BSS neighbor cell\n"

#define LAC_PARAMS "lac <0-65535>"
#define LAC_DOC "Neighbor cell by LAC\n" "LAC\n"

#define LAC_CI_PARAMS "lac-ci <0-65535> <0-65535>"
#define LAC_CI_DOC "Neighbor cell by LAC and CI\n" "LAC\n" "CI\n"

#define CGI_PARAMS "cgi <0-999> <0-999> <0-65535> <0-65535>"
#define CGI_DOC "Neighbor cell by cgi\n" "MCC\n" "MNC\n" "LAC\n" "CI\n"

#define LOCAL_BTS_PARAMS "bts <0-255>"
#define LOCAL_BTS_DOC "Neighbor cell by local BTS number\n" "BTS number\n"

static struct gsm_bts *neighbor_ident_vty_parse_bts_nr(struct vty *vty, const char **argv)
{
	const char *bts_nr_str = argv[0];
	struct gsm_bts *bts = gsm_bts_num(g_net, atoi(bts_nr_str));
	if (!bts)
		vty_out(vty, "%% No such BTS: nr = %s%s\n", bts_nr_str, VTY_NEWLINE);
	return bts;
}

static struct gsm_bts *bts_by_cell_id(struct vty *vty, struct gsm0808_cell_id *cell_id)
{
	struct gsm_bts *bts = gsm_bts_by_cell_id(g_net, cell_id, 0);
	if (!bts)
		vty_out(vty, "%% No such BTS: %s%s\n", gsm0808_cell_id_name(cell_id), VTY_NEWLINE);
	return bts;
}

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

static int add_local_bts(struct vty *vty, struct gsm_bts *neigh)
{
	int rc;
	struct gsm_bts *bts = vty->index;
	if (vty->node != BTS_NODE) {
		vty_out(vty, "%% Error: cannot add local BTS neighbor, not on BTS node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!bts) {
		vty_out(vty, "%% Error: cannot add local BTS neighbor, no BTS on this node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!neigh) {
		vty_out(vty, "%% Error: cannot add local BTS neighbor to BTS %u, no such neighbor BTS%s"
			"%% (To add remote-BSS neighbors, pass full ARFCN and BSIC as well)%s",
			bts->nr, VTY_NEWLINE, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rc = gsm_bts_local_neighbor_add(bts, neigh);
	if (rc < 0) {
		vty_out(vty, "%% Error: cannot add local BTS %u as neighbor to BTS %u: %s%s",
			neigh->nr, bts->nr, strerror(-rc), VTY_NEWLINE);
		return CMD_WARNING;
	} else
		vty_out(vty, "%% BTS %u %s local neighbor BTS %u with LAC %u CI %u and ARFCN %u BSIC %u%s",
			bts->nr, rc? "now has" : "already had",
			neigh->nr, neigh->location_area_code, neigh->cell_identity,
			neigh->c0->arfcn, neigh->bsic, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int del_local_bts(struct vty *vty, struct gsm_bts *neigh)
{
	int rc;
	struct gsm_bts *bts = vty->index;
	if (vty->node != BTS_NODE) {
		vty_out(vty, "%% Error: cannot remove local BTS neighbor, not on BTS node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!bts) {
		vty_out(vty, "%% Error: cannot remove local BTS neighbor, no BTS on this node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!neigh) {
		vty_out(vty, "%% Error: cannot remove local BTS neighbor from BTS %u, no such neighbor BTS%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rc = gsm_bts_local_neighbor_del(bts, neigh);
	if (rc < 0) {
		vty_out(vty, "%% Error: cannot remove local BTS %u neighbor from BTS %u: %s%s",
			neigh->nr, bts->nr, strerror(-rc), VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (rc == 0)
		vty_out(vty, "%% BTS %u is no neighbor of BTS %u%s",
			neigh->nr, bts->nr, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(cfg_neighbor_add_bts_nr, cfg_neighbor_add_bts_nr_cmd,
	NEIGHBOR_ADD_CMD LOCAL_BTS_PARAMS,
	NEIGHBOR_ADD_DOC LOCAL_BTS_DOC)
{
	return add_local_bts(vty, neighbor_ident_vty_parse_bts_nr(vty, argv));
}

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

DEFUN(cfg_neighbor_add_cgi, cfg_neighbor_add_cgi_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC)
{
	return add_local_bts(vty, bts_by_cell_id(vty, neighbor_ident_vty_parse_cgi(vty, argv)));
}

bool neighbor_ident_key_matches_bts(const struct neighbor_ident_key *key, struct gsm_bts *bts)
{
	if (!bts || !key)
		return false;
	return key->arfcn == bts->c0->arfcn
		&& (key->bsic == BSIC_ANY || key->bsic == bts->bsic);
}

static int add_remote_or_local_bts(struct vty *vty, const struct gsm0808_cell_id *cell_id,
				   const struct neighbor_ident_key *key)
{
	int rc;
	struct gsm_bts *local_neigh;
	const struct gsm0808_cell_id_list2 *exists;
	struct gsm0808_cell_id_list2 cil;
	struct gsm_bts *bts = vty->index;

	if (vty->node != BTS_NODE) {
		vty_out(vty, "%% Error: cannot add BTS neighbor, not on BTS node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!bts) {
		vty_out(vty, "%% Error: cannot add BTS neighbor, no BTS on this node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Is there a local BTS that matches the cell_id? */
	local_neigh = gsm_bts_by_cell_id(g_net, cell_id, 0);
	if (local_neigh) {
		/* But do the advertised ARFCN and BSIC match as intended?
		 * The user may omit ARFCN and BSIC for local cells, but if they are provided,
		 * they need to match. */
		if (!neighbor_ident_key_matches_bts(key, local_neigh)) {
			vty_out(vty, "%% Error: bts %u: neighbor cell id %s indicates local BTS %u,"
				" but it does not match ARFCN+BSIC %s%s",
				bts->nr, gsm0808_cell_id_name(cell_id), local_neigh->nr,
				neighbor_ident_key_name(key), VTY_NEWLINE);
			/* TODO: error out fatally for non-interactive VTY? */
			return CMD_WARNING;
		}
		return add_local_bts(vty, local_neigh);
	}

	/* Allow only one cell ID per remote-BSS neighbor, see OS#3656 */
	exists = neighbor_ident_get(g_neighbor_cells, key);
	if (exists) {
		vty_out(vty, "%% Error: only one Cell Identifier entry is allowed per remote neighbor."
			" Already have: %s -> %s%s", neighbor_ident_key_name(key),
			gsm0808_cell_id_list_name(exists), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* The cell_id is not known in this BSS, so it must be a remote cell. */
	gsm0808_cell_id_to_list(&cil, cell_id);
	rc = neighbor_ident_add(g_neighbor_cells, key, &cil);

	if (rc < 0) {
		const char *reason;
		switch (rc) {
		case -EINVAL:
			reason = ": mismatching type between current and newly added cell identifier";
			break;
		case -ENOSPC:
			reason = ": list is full";
			break;
		default:
			reason = "";
			break;
		}

		vty_out(vty, "%% Error adding neighbor-BSS Cell Identifier %s%s%s",
			gsm0808_cell_id_name(cell_id), reason, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% %s now has %d remote BSS Cell Identifier List %s%s",
		neighbor_ident_key_name(key), rc, rc == 1? "entry" : "entries", VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int del_by_key(struct vty *vty, const struct neighbor_ident_key *key)
{
	int removed = 0;
	int rc;
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_ref *neigh, *safe;

	if (vty->node != BTS_NODE) {
		vty_out(vty, "%% Error: cannot remove BTS neighbor, not on BTS node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!bts) {
		vty_out(vty, "%% Error: cannot remove BTS neighbor, no BTS on this node%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Is there a local BTS that matches the key? */
	llist_for_each_entry_safe(neigh, safe, &bts->local_neighbors, entry) {
		struct gsm_bts *neigh_bts = neigh->bts;
		if (!neighbor_ident_key_matches_bts(key, neigh->bts))
			continue;
		rc = gsm_bts_local_neighbor_del(bts, neigh->bts);
		if (rc > 0) {
			vty_out(vty, "%% Removed local neighbor bts %u to bts %u%s",
				bts->nr, neigh_bts->nr, VTY_NEWLINE);
			removed += rc;
		}
	}

	if (neighbor_ident_del(g_neighbor_cells, key)) {
		vty_out(vty, "%% Removed remote BSS neighbor %s%s",
			neighbor_ident_key_name(key), VTY_NEWLINE);
		removed ++;
	}

	if (!removed) {
		vty_out(vty, "%% Cannot remove, no such neighbor: %s%s",
			neighbor_ident_key_name(key), VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_neighbor_add_lac_arfcn_bsic, cfg_neighbor_add_lac_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD LAC_PARAMS " " NEIGHBOR_IDENT_VTY_KEY_PARAMS,
	NEIGHBOR_ADD_DOC LAC_DOC NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	struct neighbor_ident_key nik;
	struct gsm0808_cell_id *cell_id = neighbor_ident_vty_parse_lac(vty, argv);
	if (!cell_id)
		return CMD_WARNING;
	if (!neighbor_ident_vty_parse_key_params(vty, argv + 1, &nik))
		return CMD_WARNING;
	return add_remote_or_local_bts(vty, cell_id, &nik);
}

DEFUN(cfg_neighbor_add_lac_ci_arfcn_bsic, cfg_neighbor_add_lac_ci_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD LAC_CI_PARAMS " " NEIGHBOR_IDENT_VTY_KEY_PARAMS,
	NEIGHBOR_ADD_DOC LAC_CI_DOC NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	struct neighbor_ident_key nik;
	struct gsm0808_cell_id *cell_id = neighbor_ident_vty_parse_lac_ci(vty, argv);
	if (!cell_id)
		return CMD_WARNING;
	if (!neighbor_ident_vty_parse_key_params(vty, argv + 2, &nik))
		return CMD_WARNING;
	return add_remote_or_local_bts(vty, cell_id, &nik);
}

DEFUN(cfg_neighbor_add_cgi_arfcn_bsic, cfg_neighbor_add_cgi_arfcn_bsic_cmd,
	NEIGHBOR_ADD_CMD CGI_PARAMS " " NEIGHBOR_IDENT_VTY_KEY_PARAMS,
	NEIGHBOR_ADD_DOC CGI_DOC NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	struct neighbor_ident_key nik;
	struct gsm0808_cell_id *cell_id = neighbor_ident_vty_parse_cgi(vty, argv);
	if (!cell_id)
		return CMD_WARNING;
	if (!neighbor_ident_vty_parse_key_params(vty, argv + 4, &nik))
		return CMD_WARNING;
	return add_remote_or_local_bts(vty, cell_id, &nik);
}

DEFUN(cfg_neighbor_del_bts_nr, cfg_neighbor_del_bts_nr_cmd,
	NEIGHBOR_DEL_CMD LOCAL_BTS_PARAMS,
	NEIGHBOR_DEL_DOC LOCAL_BTS_DOC)
{
	return del_local_bts(vty, neighbor_ident_vty_parse_bts_nr(vty, argv));
}

DEFUN(cfg_neighbor_del_arfcn_bsic, cfg_neighbor_del_arfcn_bsic_cmd,
	NEIGHBOR_DEL_CMD NEIGHBOR_IDENT_VTY_KEY_PARAMS,
	NEIGHBOR_DEL_DOC NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	struct neighbor_ident_key key;

	if (!neighbor_ident_vty_parse_key_params(vty, argv, &key))
		return CMD_WARNING;

	return del_by_key(vty, &key);
}

struct write_neighbor_ident_entry_data {
	struct vty *vty;
	const char *indent;
	struct gsm_bts *bts;
};

static bool write_neighbor_ident_list(const struct neighbor_ident_key *key,
				      const struct gsm0808_cell_id_list2 *val,
				      void *cb_data)
{
	struct write_neighbor_ident_entry_data *d = cb_data;
	struct vty *vty = d->vty;
	int i;

	if (d->bts) {
		if (d->bts->nr != key->from_bts)
			return true;
	} else if (key->from_bts != NEIGHBOR_IDENT_KEY_ANY_BTS)
			return true;

#define NEIGH_BSS_WRITE(fmt, args...) do { \
		vty_out(vty, "%sneighbor " fmt " arfcn %u ", d->indent, ## args, key->arfcn); \
		if (key->bsic == BSIC_ANY) \
			vty_out(vty, "bsic any"); \
		else \
			vty_out(vty, "bsic %u", key->bsic & 0x3f); \
		vty_out(vty, "%s", VTY_NEWLINE); \
	} while(0)

	switch (val->id_discr) {
	case CELL_IDENT_LAC:
		for (i = 0; i < val->id_list_len; i++) {
			NEIGH_BSS_WRITE("lac %u", val->id_list[i].lac);
		}
		break;
	case CELL_IDENT_LAC_AND_CI:
		for (i = 0; i < val->id_list_len; i++) {
			NEIGH_BSS_WRITE("lac-ci %u %u",
					val->id_list[i].lac_and_ci.lac,
					val->id_list[i].lac_and_ci.ci);
		}
		break;
	case CELL_IDENT_WHOLE_GLOBAL:
		for (i = 0; i < val->id_list_len; i++) {
			const struct osmo_cell_global_id *cgi = &val->id_list[i].global;
			NEIGH_BSS_WRITE("cgi %s %s %u %u",
					osmo_mcc_name(cgi->lai.plmn.mcc),
					osmo_mnc_name(cgi->lai.plmn.mnc, cgi->lai.plmn.mnc_3_digits),
					cgi->lai.lac, cgi->cell_identity);
		}
		break;
	default:
		vty_out(vty, "%% Unsupported Cell Identity%s", VTY_NEWLINE);
	}
#undef NEIGH_BSS_WRITE

	return true;
}

void neighbor_ident_vty_write_remote_bss(struct vty *vty, const char *indent, struct gsm_bts *bts)
{
	struct write_neighbor_ident_entry_data d = {
		.vty = vty,
		.indent = indent,
		.bts = bts,
	};

	neighbor_ident_iter(g_neighbor_cells, write_neighbor_ident_list, &d);
}

void neighbor_ident_vty_write_local_neighbors(struct vty *vty, const char *indent, struct gsm_bts *bts)
{
	struct gsm_bts_ref *neigh;

	llist_for_each_entry(neigh, &bts->local_neighbors, entry) {
		vty_out(vty, "%sneighbor bts %u%s", indent, neigh->bts->nr, VTY_NEWLINE);
	}
}

void neighbor_ident_vty_write(struct vty *vty, const char *indent, struct gsm_bts *bts)
{
	neighbor_ident_vty_write_local_neighbors(vty, indent, bts);
	neighbor_ident_vty_write_remote_bss(vty, indent, bts);
}

DEFUN(show_bts_neighbor, show_bts_neighbor_cmd,
      "show bts <0-255> neighbor " NEIGHBOR_IDENT_VTY_KEY_PARAMS,
      SHOW_STR "Display information about a BTS\n" "BTS number\n"
      "Query which cell would be the target for this neighbor ARFCN+BSIC\n"
      NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	int found = 0;
	struct neighbor_ident_key key;
	struct gsm_bts_ref *neigh;
	const struct gsm0808_cell_id_list2 *res;
	struct gsm_bts *bts = gsm_bts_num(g_net, atoi(argv[0]));
	struct write_neighbor_ident_entry_data d = {
		.vty = vty,
		.indent = "% ",
		.bts = bts,
	};

	if (!bts) {
		vty_out(vty, "%% Error: cannot find BTS '%s'%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!neighbor_ident_bts_parse_key_params(vty, bts, &argv[1], &key))
		return CMD_WARNING;

	/* Is there a local BTS that matches the key? */
	llist_for_each_entry(neigh, &bts->local_neighbors, entry) {
		if (!neighbor_ident_key_matches_bts(&key, neigh->bts))
			continue;
		vty_out(vty, "%% %s resolves to local BTS %u lac-ci %u %u%s",
			neighbor_ident_key_name(&key), neigh->bts->nr, neigh->bts->location_area_code,
			neigh->bts->cell_identity, VTY_NEWLINE);
		found++;
	}

	res = neighbor_ident_get(g_neighbor_cells, &key);
	if (res) {
		write_neighbor_ident_list(&key, res, &d);
		found++;
	}

	if (!found)
		vty_out(vty, "%% No entry for %s%s", neighbor_ident_key_name(&key), VTY_NEWLINE);

	return CMD_SUCCESS;
}

void neighbor_ident_vty_init(struct gsm_network *net, struct neighbor_ident_list *nil)
{
	g_net = net;
	g_neighbor_cells = nil;
	install_element(BTS_NODE, &cfg_neighbor_add_bts_nr_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_ci_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_lac_ci_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_add_cgi_arfcn_bsic_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_bts_nr_cmd);
	install_element(BTS_NODE, &cfg_neighbor_del_arfcn_bsic_cmd);
	install_element_ve(&show_bts_neighbor_cmd);
}
