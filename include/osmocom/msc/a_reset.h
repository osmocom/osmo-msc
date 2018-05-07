/* (C) 2017 by sysmocom s.f.m.c. GmbH
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

#pragma once

/* Create and start state machine which handles the reset/reset-ack procedure */
struct osmo_fsm_inst *a_reset_alloc(void *ctx, const char *name, void *cb,
				    void *priv, bool already_connected);

/* Confirm that we sucessfully received a reset acknowlege message */
void a_reset_ack_confirm(struct osmo_fsm_inst *reset_fsm);

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct osmo_fsm_inst *reset_fsm);
