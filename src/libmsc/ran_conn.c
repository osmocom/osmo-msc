/* MSC RAN connection implementation */

/*
 * (C) 2016-2018 by sysmocom s.f.m.c. <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>

#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/msub.h>

struct ran_conn *ran_conn_create_incoming(struct ran_peer *ran_peer, uint32_t sccp_conn_id)
{
	struct ran_conn *conn;

	conn = talloc(ran_peer, struct ran_conn);
	OSMO_ASSERT(conn);

	*conn = (struct ran_conn){
		.ran_peer = ran_peer,
		.sccp_conn_id = sccp_conn_id,
	};

	llist_add(&conn->entry, &ran_peer->sri->ran_conns);
	return conn;
}

struct ran_conn *ran_conn_create_outgoing(struct ran_peer *ran_peer)
{
	/* FIXME use method being developed in gerrit id Ifd55c6b7ed2558ff072042079cf45f5068a971de */
	static uint32_t next_outgoing_conn_id = 2342;
	uint32_t conn_id = 0;
	int attempts = 1000;
	bool already_used = true;
	while (attempts--) {
		struct ran_conn *conn;

		conn_id = next_outgoing_conn_id;
		next_outgoing_conn_id++;

		already_used = false;
		llist_for_each_entry(conn, &ran_peer->sri->ran_conns, entry) {
			if (conn->sccp_conn_id == conn_id) {
				already_used = true;
				break;
			}
		}

		if (!already_used)
			break;
	}
	if (already_used)
		return NULL;
	LOG_RAN_PEER(ran_peer, LOGL_DEBUG, "Outgoing conn id: %u\n", conn_id);
	return ran_conn_create_incoming(ran_peer, conn_id);
}

/* Return statically allocated string of the ran_conn RAT type and id. */
const char *ran_conn_name(struct ran_conn *conn)
{
	static char id[42];
	int rc;
	const char *ran_peer_name;

	if (!conn)
		return "ran_conn==NULL";

	if (!conn->ran_peer || !conn->ran_peer->sri || !conn->ran_peer->sri->ran)
		ran_peer_name = "no-RAN-peer";
	else
		ran_peer_name = osmo_rat_type_name(conn->ran_peer->sri->ran->type);

	rc = snprintf(id, sizeof(id), "%s-%u", ran_peer_name, conn->sccp_conn_id);
	/* < 0 is error, == 0 is empty, >= size means truncation. Not really expecting this to catch on in any practical
	 * situation. */
	if (rc <= 0 || rc >= sizeof(id))
		return "conn-name-error";
	return id;
}

int ran_conn_down_l2_co(struct ran_conn *conn, struct msgb *l3, bool initial)
{
	struct ran_peer_ev_ctx co = {
		.conn_id = conn->sccp_conn_id,
		.conn = conn,
		.msg = l3,
	};
	if (!conn->ran_peer)
		return -EIO;
	return osmo_fsm_inst_dispatch(conn->ran_peer->fi,
				      initial ? RAN_PEER_EV_MSG_DOWN_CO_INITIAL : RAN_PEER_EV_MSG_DOWN_CO,
				      &co);
}

void ran_conn_msc_role_gone(struct ran_conn *conn, struct osmo_fsm_inst *msc_role)
{
	if (!conn)
		return;

	if (conn->msc_role != msc_role)
		return;

	conn->msc_role = NULL;
	ran_conn_close(conn);
}

/* Regularly close the conn */
void ran_conn_close(struct ran_conn *conn)
{
	if (!conn)
		return;
	if (conn->closing)
		return;
	conn->closing = true;
	LOG_RAN_PEER(conn->ran_peer, LOGL_DEBUG, "Closing %s\n", ran_conn_name(conn));

	if (conn->msc_role) {
		osmo_fsm_inst_dispatch(conn->msc_role, MSC_EV_FROM_RAN_CONN_RELEASED, NULL);
		conn->msc_role = NULL;
	}

	if (conn->ran_peer) {
		/* Todo: pass a useful SCCP cause? */
		sccp_ran_disconnect(conn->ran_peer->sri, conn->sccp_conn_id, 0);
		conn->ran_peer = NULL;
	}

	LOG_RAN_PEER(conn->ran_peer, LOGL_DEBUG, "Deallocating %s\n", ran_conn_name(conn));
	llist_del(&conn->entry);
	talloc_free(conn);
}

/* Same as ran_conn_close() but without sending any SCCP messages (e.g. after RESET) */
void ran_conn_discard(struct ran_conn *conn)
{
	if (!conn)
		return;
	/* Make sure to drop dead and don't dispatch things like DISCONNECT requests on SCCP. */
	conn->ran_peer = NULL;
	ran_conn_close(conn);
}
