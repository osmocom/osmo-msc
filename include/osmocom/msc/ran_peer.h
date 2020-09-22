#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/sccp_sap.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/paging.h>

struct vlr_subscr;
struct ran_conn;
struct neighbor_ident_entry;

#define LOG_RAN_PEER_CAT(RAN_PEER, subsys, loglevel, fmt, args ...) \
	LOGPFSMSL((RAN_PEER)? (RAN_PEER)->fi : NULL, subsys, loglevel, fmt, ## args)

#define LOG_RAN_PEER(RAN_PEER, loglevel, fmt, args ...) \
	LOG_RAN_PEER_CAT(RAN_PEER, \
			 (RAN_PEER) && (RAN_PEER)->sri? (RAN_PEER)->sri->ran->log_subsys : DMSC, \
			 loglevel, fmt, ## args)

/* A BSC or RNC with activity on a local SCCP connection.
 * Here we collect those BSC and RNC peers that are actually connected to the MSC and manage their connection Reset
 * status.
 *
 * Before we had explicit neighbor configuration for inter-BSC and inter-MSC handover, the only way to know which peer
 * address corresponds to which LAC (for paging a specific LAC) was to collect the LAC from L3 messages coming in on a
 * subscriber connection. We still continue that practice to support unconfigured operation.
 *
 * The neighbor list config extends this by possibly naming LAC and CI that have not seen explicit activity yet, and
 * allows us to page towards the correct peer's SCCP address from the start.
 *
 * So, for paging, the idea is to look for a LAC that is recorded here, and if not found, query the neighbor
 * configuration for a peer's SCCP address matching that LAC. If found, look for active connections on that SCCP address
 * here.
 *
 * Any valid RAN peer will contact us and initiate a RESET procedure. In turn, on osmo-msc start, we may choose to
 * initiate a RESET procedure towards every known RAN peer.
 *
 * Semantically, it would make sense to keep the list of ran_conn instances in each struct ran_peer, but since
 * non-Initial Connection-Oriented messages indicate only the conn by id (and identify the ran_peer from that), the conn
 * list is kept in sccp_ran_inst. For convenience, see ran_peer_for_each_ran_conn().
 */
struct ran_peer {
	/* Entry in sccp_ran_inst->ran_peers */
	struct llist_head entry;

	struct sccp_ran_inst *sri;
	struct osmo_sccp_addr peer_addr;
	struct osmo_fsm_inst *fi;

	/* See cell_id_list.h */
	struct llist_head cells_seen;

	/* Whether we detected the BSC supports Osmux (during BSSMAP_RESET) */
	bool remote_supports_osmux;
};

#define ran_peer_for_each_ran_conn(RAN_CONN, RAN_PEER) \
	llist_for_each_entry(RAN_CONN, &(RAN_PEER)->sri->ran_conns, entry) \
		if ((RAN_CONN)->ran_peer == (RAN_PEER))

#define ran_peer_for_each_ran_conn_safe(RAN_CONN, RAN_CONN_NEXT, RAN_PEER) \
	llist_for_each_entry_safe(RAN_CONN, RAN_CONN_NEXT, &(RAN_PEER)->sri->ran_conns, entry) \
		if ((RAN_CONN)->ran_peer == (RAN_PEER))

enum ran_peer_state {
	RAN_PEER_ST_WAIT_RX_RESET = 0,
	RAN_PEER_ST_WAIT_RX_RESET_ACK,
	RAN_PEER_ST_READY,
	RAN_PEER_ST_DISCARDING,
};

enum ran_peer_event {
	RAN_PEER_EV_MSG_UP_CL = 0,
	RAN_PEER_EV_MSG_UP_CO_INITIAL,
	RAN_PEER_EV_MSG_UP_CO,
	RAN_PEER_EV_MSG_DOWN_CL,
	RAN_PEER_EV_MSG_DOWN_CO_INITIAL,
	RAN_PEER_EV_MSG_DOWN_CO,
	RAN_PEER_EV_RX_RESET,
	RAN_PEER_EV_RX_RESET_ACK,
	RAN_PEER_EV_CONNECTION_SUCCESS,
	RAN_PEER_EV_CONNECTION_TIMEOUT,
};

struct ran_peer_ev_ctx {
	uint32_t conn_id;
	struct ran_conn *conn;
	struct msgb *msg;
};

struct ran_peer *ran_peer_find_or_create(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *peer_addr);
struct ran_peer *ran_peer_find_by_addr(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *peer_addr);

void ran_peer_cells_seen_add(struct ran_peer *ran_peer, const struct gsm0808_cell_id *id);

int ran_peer_up_l2(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *calling_addr, bool co, uint32_t conn_id,
		   struct msgb *l2);
void ran_peer_disconnect(struct sccp_ran_inst *sri, uint32_t conn_id);

int ran_peers_down_paging(struct sccp_ran_inst *sri, enum CELL_IDENT page_where, struct vlr_subscr *vsub,
			  enum paging_cause cause);
int ran_peer_down_paging(struct ran_peer *rp, const struct gsm0808_cell_id *page_id, struct vlr_subscr *vsub,
			 enum paging_cause cause);

struct ran_peer *ran_peer_find_by_cell_id(struct sccp_ran_inst *sri, const struct gsm0808_cell_id *cid,
					  bool expecting_single_match);
