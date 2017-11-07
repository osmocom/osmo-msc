/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/gsm_data.h>

/* MGCP state handler context. This context information stores all information
 * to handle the direction of the RTP streams via MGCP. There is one instance
 * of this context struct per subscriber connection.
 * (see also struct gsm_subscriber_connection) */
struct mgcp_ctx {
	/* FSM instance, which handles the connection switching procedure */
	struct osmo_fsm_inst *fsm;

	/* RTP endpoint number. This number identifies the endpoint
	 * on the MGW on which the RAN and CN connection is created. This
	 * endpoint number is assigned and released automatically. */
	uint16_t rtp_endpoint;

	/* Set to true, when the context information is no longer needed */
	bool free_ctx;

	/* RTP connection identifiers */
	char conn_id_ran[MGCP_CONN_ID_LENGTH];
	char conn_id_cn[MGCP_CONN_ID_LENGTH];

	/* Copy of the pointer and the data with context information
	 * needed to process the AoIP and MGCP requests (system data) */
	struct mgcp_client *mgcp;
	struct gsm_trans *trans;
	mgcp_trans_id_t mgw_pending_trans;
};

int msc_mgcp_call_assignment(struct gsm_trans *trans);
int msc_mgcp_ass_complete(struct gsm_subscriber_connection *conn, uint16_t port, char *addr);
int msc_mgcp_call_complete(struct gsm_trans *trans, uint16_t port, char *addr);
int msc_mgcp_call_release(struct gsm_trans *trans);
