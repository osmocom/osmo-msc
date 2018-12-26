/* Manage identity of neighboring BSS cells for inter-MSC handover. */
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

#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include <osmocom/msc/neighbor_ident.h>
#include <osmocom/msc/gsm_data.h>

/* XXX greater than or equal to IPA_STIRNG_MAX (libosmocore) and MAX_PC_STR_LEN (libosmo-sccp). */
#define NEIGHBOR_IDENT_ADDR_STRING_MAX 64

const char *neighbor_ident_addr_name(struct gsm_network *net, const struct neighbor_ident_addr *na)
{
	static char buf[NEIGHBOR_IDENT_ADDR_STRING_MAX + 4];
	struct osmo_ss7_instance *ss7;

	switch (na->type) {
	case MSC_NEIGHBOR_TYPE_BSC:
		ss7 = osmo_ss7_instance_find(net->a.cs7_instance);
		OSMO_ASSERT(ss7);
		snprintf(buf, sizeof(buf), "BSC %s", osmo_ss7_pointcode_print(ss7, na->a.point_code));
		break;
	case MSC_NEIGHBOR_TYPE_MSC:
		snprintf(buf, sizeof(buf), "MSC %s", na->a.ipa_name);
		break;
	default:
		return NULL;
	}

	return buf;
}

struct neighbor_ident_list *neighbor_ident_init(void *talloc_ctx)
{
	struct neighbor_ident_list *nil = talloc_zero(talloc_ctx, struct neighbor_ident_list);
	OSMO_ASSERT(nil);
	INIT_LLIST_HEAD(&nil->list);
	return nil;
}

void neighbor_ident_free(struct neighbor_ident_list *nil)
{
	if (!nil)
		return;
	talloc_free(nil);
}

static struct neighbor_ident *_neighbor_ident_get(const struct neighbor_ident_list *nil,
						  const struct neighbor_ident_addr *na)
{
	struct neighbor_ident *ni;

	llist_for_each_entry(ni, &nil->list, entry) {
		if (na->type != ni->addr.type)
			continue;

		switch (na->type) {
		case MSC_NEIGHBOR_TYPE_BSC:
			if (ni->addr.a.point_code == na->a.point_code)
				return ni;
			break;
		case MSC_NEIGHBOR_TYPE_MSC:
			if (strcmp(ni->addr.a.ipa_name, na->a.ipa_name) == 0)
				return ni;
			break;
		}
	}

	return NULL;
}

static void _neighbor_ident_free(struct neighbor_ident *ni)
{
	llist_del(&ni->entry);
	talloc_free(ni);
}

/*! Add Cell Identifiers to a neighbor BSC/MSC entry.
 * Exactly one kind of identifier is allowed per entry, and any number of entries of that kind
 * may be added up to the capacity of gsm0808_cell_id_list2, by one or more calls to this function. To
 * replace an existing entry, first call neighbor_ident_del(nil, cell_id).
 * \returns number of entries in the resulting identifier list, or negative on error:
 *   see gsm0808_cell_id_list_add() for the meaning of returned error codes;
 *   return -ENOMEM when the list is not initialized, -ERANGE when the BSIC value is too large. */
int neighbor_ident_add(struct neighbor_ident_list *nil, const struct neighbor_ident_addr *addr,
		       const struct gsm0808_cell_id_list2 *cell_id)
{
	struct neighbor_ident *ni;
	int rc;

	if (!nil)
		return -ENOMEM;

	ni = _neighbor_ident_get(nil, addr);
	if (!ni) {
		ni = talloc_zero(nil, struct neighbor_ident);
		OSMO_ASSERT(ni);
		ni->addr = *addr;
		llist_add_tail(&ni->entry, &nil->list);
		return ni->cell_ids.id_list_len;
	}

	rc = gsm0808_cell_id_list_add(&ni->cell_ids, cell_id);

	if (rc < 0)
		return rc;

	return ni->cell_ids.id_list_len;
}

/*! Find cell identity for given BSC or MSC, as previously added by neighbor_ident_add().
 */
const struct gsm0808_cell_id_list2 *neighbor_ident_get(const struct neighbor_ident_list *nil,
						       const struct neighbor_ident_addr *addr)
{
	struct neighbor_ident *ni;
	if (!nil)
		return NULL;
	ni = _neighbor_ident_get(nil, addr);
	if (!ni)
		return NULL;
	return &ni->cell_ids;
}

/*! Find a BSC or MSC, as previously added by neighbor_ident_add(), for a given cell identity.
 */
const struct neighbor_ident_addr *neighbor_ident_lookup_cell(const struct neighbor_ident_list *nil,
							     struct gsm0808_cell_id *cell_id)
{
	struct neighbor_ident *ni;
	if (!nil)
		return NULL;
	llist_for_each_entry(ni, &nil->list, entry) {
		if (gsm0808_cell_id_matches_list(cell_id, &ni->cell_ids, 0))
			return &ni->addr;
	}

	return NULL;
}

bool neighbor_ident_del(struct neighbor_ident_list *nil, const struct neighbor_ident_addr *addr)
{
	struct neighbor_ident *ni;
	if (!nil)
		return false;
	ni = _neighbor_ident_get(nil, addr);
	if (!ni)
		return false;
	_neighbor_ident_free(ni);
	return true;
}

void neighbor_ident_clear(struct neighbor_ident_list *nil)
{
	struct neighbor_ident *ni;
	while ((ni = llist_first_entry_or_null(&nil->list, struct neighbor_ident, entry)))
		_neighbor_ident_free(ni);
}

/*! Iterate all neighbor_ident_list entries and call iter_cb for each.
 * If iter_cb returns false, the iteration is stopped. */
void neighbor_ident_iter(const struct neighbor_ident_list *nil,
			 bool (* iter_cb )(const struct neighbor_ident_addr *addr,
					   const struct gsm0808_cell_id_list2 *cell_ids,
					   void *cb_data),
			 void *cb_data)
{
	struct neighbor_ident *ni, *ni_next;
	if (!nil)
		return;
	llist_for_each_entry_safe(ni, ni_next, &nil->list, entry) {
		if (!iter_cb(&ni->addr, &ni->cell_ids, cb_data))
			return;
	}
}
