/* Manage identity of neighboring BSS cells for inter-MSC handover. */
/*
 * (C) 2018-2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Neels Hofmeyr
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
 */

#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/cell_id_list.h>

/* XXX greater than or equal to IPA_STRING_MAX (libosmocore) and MAX_PC_STR_LEN (libosmo-sccp). */
#define NEIGHBOR_IDENT_ADDR_STRING_MAX 64

static struct gsm_network *gsmnet;

void neighbor_ident_init(struct gsm_network *net)
{
	gsmnet = net;
	INIT_LLIST_HEAD(&gsmnet->neighbor_ident_list);
}

int msc_ipa_name_from_str(struct msc_ipa_name *min, const char *name)
{
	int rc = osmo_strlcpy(min->buf, name, sizeof(min->buf));
	if (rc >= sizeof(min->buf)) {
		min->len = 0;
		return -1;
	}
	min->len = rc;
	return 0;
}

int msc_ipa_name_cmp(const struct msc_ipa_name *a, const struct msc_ipa_name *b)
{
	size_t cmp_len;
	int rc;
	if (a == b)
		return 0;
	if (!a || !b)
		return a ? 1 : -1;
	cmp_len = OSMO_MIN(sizeof(a->buf), OSMO_MIN(a->len, b->len));
	if (!cmp_len)
		rc = 0;
	else
		rc = memcmp(a->buf, b->buf, cmp_len);
	if (rc)
		return rc;
	if (a->len < b->len)
		return -1;
	if (a->len > b->len)
		return 1;
	return 0;
}

const char *neighbor_ident_addr_name(const struct neighbor_ident_addr *nia)
{
	static char buf[128];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };

	OSMO_STRBUF_PRINTF(sb, "%s-", osmo_rat_type_name(nia->ran_type));

	switch (nia->type) {
	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		OSMO_STRBUF_PRINTF(sb, "localRAN-%s", nia->local_ran_peer_pc_str);
		break;
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		OSMO_STRBUF_PRINTF(sb, "remoteMSC-");
		OSMO_STRBUF_APPEND_NOLEN(sb, osmo_escape_str_buf2, nia->remote_msc_ipa_name.buf,
					 nia->remote_msc_ipa_name.len);
		break;
	default:
		return NULL;
	}

	return buf;
}

const struct neighbor_ident_entry *neighbor_ident_add(struct llist_head *ni_list,
						      const struct neighbor_ident_addr *nia,
						      const struct gsm0808_cell_id *cid)
{
	struct neighbor_ident_entry *nie;

	if (!ni_list)
		return NULL;

	nie = (struct neighbor_ident_entry*)neighbor_ident_find_by_addr(ni_list, nia);
	if (!nie) {
		nie = talloc_zero(gsmnet, struct neighbor_ident_entry);
		OSMO_ASSERT(nie);
		*nie = (struct neighbor_ident_entry){
			.addr = *nia,
		};
		INIT_LLIST_HEAD(&nie->cell_ids);
		llist_add_tail(&nie->entry, ni_list);
	}

	cell_id_list_add_cell(nie, &nie->cell_ids, cid);
	return nie;
}

const struct neighbor_ident_entry *neighbor_ident_find_by_cell(const struct llist_head *ni_list,
							       enum osmo_rat_type ran_type,
							       const struct gsm0808_cell_id *cell_id)
{
	struct neighbor_ident_entry *e;
	llist_for_each_entry(e, ni_list, entry) {
		if (ran_type != OSMO_RAT_UNKNOWN) {
			if (e->addr.ran_type != ran_type)
				continue;
		}

		if (!cell_id_list_find(&e->cell_ids, cell_id, 0, false))
			continue;
		return e;
	}
	return NULL;
}

const struct neighbor_ident_entry *neighbor_ident_find_by_addr(const struct llist_head *ni_list,
							       const struct neighbor_ident_addr *nia)
{
	struct neighbor_ident_entry *e;

	llist_for_each_entry(e, ni_list, entry) {
		if (nia->ran_type != OSMO_RAT_UNKNOWN
		    && e->addr.ran_type != nia->ran_type)
			continue;

		if (e->addr.type != nia->type)
			continue;

		switch (e->addr.type) {
		case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
			if (strcmp(e->addr.local_ran_peer_pc_str, nia->local_ran_peer_pc_str))
				continue;
			break;
		case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
			if (msc_ipa_name_cmp(&e->addr.remote_msc_ipa_name, &nia->remote_msc_ipa_name))
				continue;
			break;
		default:
			continue;
		}

		return e;
	}

	return NULL;
}

void neighbor_ident_del(const struct neighbor_ident_entry *nie)
{
	struct neighbor_ident_entry *e = (struct neighbor_ident_entry*)nie;
	llist_del(&e->entry);
	talloc_free(e);
}

void neighbor_ident_clear(struct llist_head *ni_list)
{
	struct neighbor_ident_entry *nie;
	while ((nie = llist_first_entry_or_null(ni_list, struct neighbor_ident_entry, entry)))
		neighbor_ident_del(nie);
}
