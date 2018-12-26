/* Manage identity of neighboring BSS cells for inter-BSC handover.
 *
 * Measurement reports tell us about neighbor ARFCN and BSIC. If that ARFCN and BSIC is not managed by
 * this local BSS, we need to tell the MSC a cell identity, like CGI, LAC+CI, etc. -- hence we need a
 * mapping from ARFCN+BSIC to Cell Identifier List, which needs to be configured by the user.
 */
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

#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/bsc/neighbor_ident.h>

struct neighbor_ident_list {
	struct llist_head list;
};

struct neighbor_ident {
	struct llist_head entry;

	struct neighbor_ident_key key;
	struct gsm0808_cell_id_list2 val;
};

#define APPEND_THING(func, args...) do { \
		int remain = buflen - (pos - buf); \
		int l = func(pos, remain, ##args); \
		if (l < 0 || l > remain) \
			pos = buf + buflen; \
		else \
			pos += l; \
	} while(0)
#define APPEND_STR(fmt, args...) APPEND_THING(snprintf, fmt, ##args)

const char *_neighbor_ident_key_name(char *buf, size_t buflen, const struct neighbor_ident_key *ni_key)
{
	char *pos = buf;

	APPEND_STR("BTS ");
	if (ni_key->from_bts == NEIGHBOR_IDENT_KEY_ANY_BTS)
		APPEND_STR("*");
	else if (ni_key->from_bts >= 0 && ni_key->from_bts <= 255)
		APPEND_STR("%d", ni_key->from_bts);
	else
		APPEND_STR("invalid(%d)", ni_key->from_bts);

	APPEND_STR(" to ");
	if (ni_key->bsic == BSIC_ANY)
		APPEND_STR("ARFCN %u (any BSIC)", ni_key->arfcn);
	else
		APPEND_STR("ARFCN %u BSIC %u", ni_key->arfcn, ni_key->bsic & 0x3f);
	return buf;
}

const char *neighbor_ident_key_name(const struct neighbor_ident_key *ni_key)
{
	static char buf[64];
	return _neighbor_ident_key_name(buf, sizeof(buf), ni_key);
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

/* Return true when the entry matches the search_for requirements.
 * If exact_match is false, a BSIC_ANY entry acts as wildcard to match any search_for on that ARFCN,
 * and a BSIC_ANY in search_for likewise returns any one entry that matches the ARFCN;
 * also a from_bts == NEIGHBOR_IDENT_KEY_ANY_BTS in either entry or search_for will match.
 * If exact_match is true, only identical bsic values and identical from_bts values return a match.
 * Note, typically wildcard BSICs are only in entry, e.g. the user configured list, and search_for
 * contains a specific BSIC, e.g. as received from a Measurement Report. */
bool neighbor_ident_key_match(const struct neighbor_ident_key *entry,
			      const struct neighbor_ident_key *search_for,
			      bool exact_match)
{
	if (exact_match
	    && entry->from_bts != search_for->from_bts)
		return false;

	if (search_for->from_bts != NEIGHBOR_IDENT_KEY_ANY_BTS
	    && entry->from_bts != NEIGHBOR_IDENT_KEY_ANY_BTS
	    && entry->from_bts != search_for->from_bts)
		return false;

	if (entry->arfcn != search_for->arfcn)
		return false;

	if (exact_match && entry->bsic != search_for->bsic)
		return false;

	if (entry->bsic == BSIC_ANY || search_for->bsic == BSIC_ANY)
		return true;

	return entry->bsic == search_for->bsic;
}

static struct neighbor_ident *_neighbor_ident_get(const struct neighbor_ident_list *nil,
						  const struct neighbor_ident_key *key,
						  bool exact_match)
{
	struct neighbor_ident *ni;
	struct neighbor_ident *wildcard_match = NULL;

	/* Do both exact-bsic and wildcard matching in the same iteration:
	 * Any exact match returns immediately, while for a wildcard match we still go through all
	 * remaining items in case an exact match exists. */
	llist_for_each_entry(ni, &nil->list, entry) {
		if (neighbor_ident_key_match(&ni->key, key, true))
			return ni;
		if (!exact_match) {
			if (neighbor_ident_key_match(&ni->key, key, false))
				wildcard_match = ni;
		}
	}
	return wildcard_match;
}

static void _neighbor_ident_free(struct neighbor_ident *ni)
{
	llist_del(&ni->entry);
	talloc_free(ni);
}

bool neighbor_ident_key_valid(const struct neighbor_ident_key *key)
{
	if (key->from_bts != NEIGHBOR_IDENT_KEY_ANY_BTS
	    && (key->from_bts < 0 || key->from_bts > 255))
		return false;

	if (key->bsic != BSIC_ANY && key->bsic > 0x3f)
		return false;
	return true;
}

/*! Add Cell Identifiers to an ARFCN+BSIC entry.
 * Exactly one kind of identifier is allowed per ARFCN+BSIC entry, and any number of entries of that kind
 * may be added up to the capacity of gsm0808_cell_id_list2, by one or more calls to this function. To
 * replace an existing entry, first call neighbor_ident_del(nil, key).
 * \returns number of entries in the resulting identifier list, or negative on error:
 *   see gsm0808_cell_id_list_add() for the meaning of returned error codes;
 *   return -ENOMEM when the list is not initialized, -ERANGE when the BSIC value is too large. */
int neighbor_ident_add(struct neighbor_ident_list *nil, const struct neighbor_ident_key *key,
		       const struct gsm0808_cell_id_list2 *val)
{
	struct neighbor_ident *ni;
	int rc;

	if (!nil)
		return -ENOMEM;

	if (!neighbor_ident_key_valid(key))
		return -ERANGE;

	ni = _neighbor_ident_get(nil, key, true);
	if (!ni) {
		ni = talloc_zero(nil, struct neighbor_ident);
		OSMO_ASSERT(ni);
		*ni = (struct neighbor_ident){
			.key = *key,
			.val = *val,
		};
		llist_add_tail(&ni->entry, &nil->list);
		return ni->val.id_list_len;
	}

	rc = gsm0808_cell_id_list_add(&ni->val, val);

	if (rc < 0)
		return rc;

	return ni->val.id_list_len;
}

/*! Find cell identity for given BTS, ARFCN and BSIC, as previously added by neighbor_ident_add().
 */
const struct gsm0808_cell_id_list2 *neighbor_ident_get(const struct neighbor_ident_list *nil,
						       const struct neighbor_ident_key *key)
{
	struct neighbor_ident *ni;
	if (!nil)
		return NULL;
	ni = _neighbor_ident_get(nil, key, false);
	if (!ni)
		return NULL;
	return &ni->val;
}

bool neighbor_ident_del(struct neighbor_ident_list *nil, const struct neighbor_ident_key *key)
{
	struct neighbor_ident *ni;
	if (!nil)
		return false;
	ni = _neighbor_ident_get(nil, key, true);
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
			 bool (* iter_cb )(const struct neighbor_ident_key *key,
					   const struct gsm0808_cell_id_list2 *val,
					   void *cb_data),
			 void *cb_data)
{
	struct neighbor_ident *ni, *ni_next;
	if (!nil)
		return;
	llist_for_each_entry_safe(ni, ni_next, &nil->list, entry) {
		if (!iter_cb(&ni->key, &ni->val, cb_data))
			return;
	}
}
