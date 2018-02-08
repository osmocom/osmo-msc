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

#include <osmocom/msc/a_iface.h>

/* Note: The structs and functions presented in this header file are intended
 * to be used only by a_iface.c. */

/* A structure to hold tha most basic information about a sigtran connection
 * we use this struct internally here to pass connection data around */
struct a_conn_info {
	struct bsc_context *bsc;
	uint32_t conn_id;
	struct gsm_network *network;
};

/* Receive incoming connection less data messages via sccp */
void a_sccp_rx_udt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg);

/* Receive incoming connection oriented data messages via sccp */
int a_sccp_rx_dt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg);

