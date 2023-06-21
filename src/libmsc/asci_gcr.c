/* Group Call Register (GCR) */
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

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/transaction.h>

#include <osmocom/msc/asci_gcr.h>

#define GCR_DEFAULT_TIMEOUT 60

static uint32_t pow10[9] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

/* Add cell to BSS list. */
struct gcr_cell *gcr_add_cell(struct gcr_bss *bss, uint16_t cell_id)
{
	struct gcr_cell *c;

	c = talloc_zero(bss, struct gcr_cell);
	if (!c)
		return NULL;
	c->cell_id = cell_id;
	llist_add_tail(&c->list, &bss->cell_list);

	return c;
}

/* Find cell entry in BSS list. */
struct gcr_cell *gcr_find_cell(struct gcr_bss *bss, uint16_t cell_id)
{
	struct gcr_cell *c;

	llist_for_each_entry(c, &bss->cell_list, list) {
		if (c->cell_id == cell_id)
			return c;
	}

	return NULL;
}

/* Remove cell entry from BSS list. */
void gcr_rm_cell(struct gcr_bss *bss, uint16_t cell_id)
{
	struct gcr_cell *c = gcr_find_cell(bss, cell_id);

	if (c) {
		llist_del(&c->list);
		talloc_free(c);
	}
}

/* Add BSS to GCR list. */
struct gcr_bss *gcr_add_bss(struct gcr *gcr, int pc)
{
	struct gcr_bss *b;

	b = talloc_zero(gcr, struct gcr_bss);
	if (!b)
		return NULL;
	INIT_LLIST_HEAD(&b->cell_list);
	b->pc = pc;
	llist_add_tail(&b->list, &gcr->bss_list);

	return b;
}

/* Find BSS entry in GCR list. */
struct gcr_bss *gcr_find_bss(struct gcr *gcr, int pc)
{
	struct gcr_bss *b;

	llist_for_each_entry(b, &gcr->bss_list, list) {
		if (b->pc == pc)
			return b;
	}

	return NULL;
}

/* Remove BSS entry from GCR list. */
void gcr_rm_bss(struct gcr *gcr, int pc)
{
	struct gcr_bss *b = gcr_find_bss(gcr, pc);

	if (b) {
		/* All cell definitons will be removed, as they are attached to BSS. */
		llist_del(&b->list);
		talloc_free(b);
	}
}

/* Create a new (empty) GCR list. */
struct gcr *gcr_create(struct gsm_network *gsmnet, enum trans_type trans_type, const char *group_id)
{
	struct gcr *gcr;

	gcr = talloc_zero(gsmnet, struct gcr);
	if (!gcr)
		return NULL;

	INIT_LLIST_HEAD(&gcr->bss_list);
	gcr->trans_type = trans_type;
	gcr->timeout = GCR_DEFAULT_TIMEOUT;
	gcr->mute_talker = true;
	osmo_strlcpy(gcr->group_id, group_id, sizeof(gcr->group_id));
	llist_add_tail(&gcr->list, &gsmnet->asci.gcr_lists);

	return gcr;
}

/* Destroy a GCR list. */
void gcr_destroy(struct gcr *gcr)
{
	/* All BSS definitons will be removed, as they are attached to GCR. */
	llist_del(&gcr->list);
	talloc_free(gcr);
}

/* Find GCR list by group ID. */
struct gcr *gcr_by_group_id(struct gsm_network *gsmnet, enum trans_type trans_type, const char *group_id)
{
	struct gcr *gcr;

	llist_for_each_entry(gcr, &gsmnet->asci.gcr_lists, list) {
		if (gcr->trans_type == trans_type && !strcmp(gcr->group_id, group_id))
			return gcr;
	}

	return NULL;
}

/* Find GCR list by callref. */
struct gcr *gcr_by_callref(struct gsm_network *gsmnet, enum trans_type trans_type, uint32_t callref)
{
	struct gcr *most_specific_gcr = NULL, *gcr;
	int a, b;
	size_t most_specific_len = 0, l;

	llist_for_each_entry(gcr, &gsmnet->asci.gcr_lists, list) {
		/* Compare only the digits in Group ID with the digits in callref.
		 * callref is an integer. Only the remainder, based on Group ID length, is checked. */
		l = strlen(gcr->group_id);
		a = atoi(gcr->group_id);
		OSMO_ASSERT(l < ARRAY_SIZE(pow10));
		b = callref % pow10[l];
		if (gcr->trans_type == trans_type && a == b) {
			/* Get most specific GROUP ID, no matter what order they are stored. */
			if (l > most_specific_len) {
				most_specific_gcr = gcr;
				most_specific_len = l;
			}
		}
	}

	return most_specific_gcr;
}
