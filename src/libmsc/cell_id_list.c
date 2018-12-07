/* Manage a list of struct gsm0808_cell_id */
/*
 * (C) 2019 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <osmocom/msc/cell_id_list.h>

int cell_id_list_add_cell(void *talloc_ctx, struct llist_head *list, const struct gsm0808_cell_id *cid)
{
	struct cell_id_list_entry *e = cell_id_list_find(list, cid, 0, true);

	if (e)
		return 0;

	e = talloc_zero(talloc_ctx, struct cell_id_list_entry);
	e->cell_id = *cid;
	llist_add_tail(&e->entry, list);
	return 1;
}

int cell_id_list_add_list(void *talloc_ctx, struct llist_head *list, const struct gsm0808_cell_id_list2 *cil)
{
	struct gsm0808_cell_id one_id;
	int i;
	int added = 0;
	for (i = 0; i < cil->id_list_len; i++) {
		one_id = (struct gsm0808_cell_id){
			.id_discr = cil->id_discr,
			.id = cil->id_list[i],
		};
		added += cell_id_list_add_cell(talloc_ctx, list, &one_id);
	}
	return added;
}

void cell_id_list_del_entry(struct cell_id_list_entry *e)
{
	llist_del(&e->entry);
	talloc_free(e);
}

struct cell_id_list_entry *cell_id_list_find(struct llist_head *list,
					     const struct gsm0808_cell_id *id,
					     unsigned int match_nr,
					     bool exact_match)
{
	struct cell_id_list_entry *e;
	llist_for_each_entry(e, list, entry) {
		if (gsm0808_cell_ids_match(id, &e->cell_id, exact_match)) {
			if (match_nr)
				match_nr--;
			else
				return e;
		}
	}
	return NULL;
}
