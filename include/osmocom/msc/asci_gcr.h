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
#pragma once

/* Group Call Register */
struct gcr {
	struct llist_head list;
	enum trans_type trans_type;
	char group_id[9];
	uint16_t timeout;
	bool mute_talker;
	struct llist_head bss_list;
};

struct gcr_bss {
	struct llist_head list;
	int pc;
	struct llist_head cell_list;
};

struct gcr_cell {
	struct llist_head list;
	uint16_t cell_id;
};

struct gcr_cell *gcr_add_cell(struct gcr_bss *bss, uint16_t cell_id);
struct gcr_cell *gcr_find_cell(struct gcr_bss *bss, uint16_t cell_id);
void gcr_rm_cell(struct gcr_bss *bss, uint16_t cell_id);
struct gcr_bss *gcr_add_bss(struct gcr *gcr, int pc);
struct gcr_bss *gcr_find_bss(struct gcr *gcr, int pc);
void gcr_rm_bss(struct gcr *gcr, int pc);
struct gcr *gcr_create(struct gsm_network *gsmnet, enum trans_type trans_type, const char *group_id);
void gcr_destroy(struct gcr *gcr);
struct gcr *gcr_by_group_id(struct gsm_network *gsmnet, enum trans_type trans_type, const char *group_id);
struct gcr *gcr_by_callref(struct gsm_network *gsmnet, enum trans_type trans_type, uint32_t callref);
