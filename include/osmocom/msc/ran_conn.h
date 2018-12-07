#pragma once
/* MSC RAN connection implementation */

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

struct ran_peer;
struct osmo_fsm_inst;
struct msgb;

/* active radio connection of a mobile subscriber */
struct ran_conn {
	/* Entry in sccp_ran_inst->ran_conns */
	struct llist_head entry;

	struct ran_peer *ran_peer;
	uint32_t sccp_conn_id;

	/* MSC role that this RAN connection belongs to. This will be either an msc_i (currently active
	 * connection) or an msc_t (transitory new connection during Handover). */
	struct osmo_fsm_inst *msc_role;

	bool closing;
};

struct ran_conn *ran_conn_create_incoming(struct ran_peer *ran_peer, uint32_t sccp_conn_id);
struct ran_conn *ran_conn_create_outgoing(struct ran_peer *ran_peer);
const char *ran_conn_name(struct ran_conn *conn);
int ran_conn_down_l2_co(struct ran_conn *conn, struct msgb *l3, bool initial);
void ran_conn_msc_role_gone(struct ran_conn *conn, struct osmo_fsm_inst *msc_role);
void ran_conn_close(struct ran_conn *conn);
void ran_conn_discard(struct ran_conn *conn);
