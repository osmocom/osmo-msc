/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <osmocom/msc/msc_lac.h>
#include <stdint.h>

/* Update list with LAC information for a particular BSC */
void msc_lac_update_a(struct gsm_network *network, uint16_t lac, struct bsc_context *bsc_context)
{
	struct lac_context *lac_context;
	bool create_lac_context = true;

	/* Try to find the lac_context list entry based on the given LAC,
	 * if one exist, we do not need to create a new one */
	llist_for_each_entry(lac_context, &network->lac_contexts, list) {
		if (lac_context->lac == lac) {
			create_lac_context = false;
			break;
		}
	}

	/* We failed to find an existing LAC context, so we create a new one */
	if (create_lac_context) {
		lac_context = talloc_zero(network, struct lac_context);
		lac_context->lac = lac;
		llist_add_tail(&lac_context->list, &network->lac_contexts);
	}

	/* Update context info */
	lac_context->bsc_context = bsc_context;
	lac_context->ran_type = RAN_GERAN_A;

	/* TODO: Add some statistical information like timestamps, when created? when last seen? */
}
