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

#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808_utils.h>

struct cell_id_list_entry {
	struct llist_head entry;
	struct gsm0808_cell_id cell_id;
};

int cell_id_list_add_cell(void *talloc_ctx, struct llist_head *list, const struct gsm0808_cell_id *cid);
int cell_id_list_add_list(void *talloc_ctx, struct llist_head *list, const struct gsm0808_cell_id_list2 *cil);

struct cell_id_list_entry *cell_id_list_find(struct llist_head *list,
					     const struct gsm0808_cell_id *id,
					     unsigned int match_nr,
					     bool exact_match);

void cell_id_list_del_entry(struct cell_id_list_entry *e);
