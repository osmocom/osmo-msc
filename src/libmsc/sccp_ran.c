/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
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
 */

#include <osmocom/core/logging.h>

#include <osmocom/sccp/sccp_types.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/ran_peer.h>

struct osmo_tdef g_sccp_tdefs[] = {
	{}
};

static int sccp_ran_sap_up(struct osmo_prim_hdr *oph, void *_scu);

struct sccp_ran_inst *sccp_ran_init(void *talloc_ctx, struct osmo_sccp_instance *sccp, enum osmo_sccp_ssn ssn,
				    const char *sccp_user_name, struct ran_infra *ran, void *user_data)
{
	struct sccp_ran_inst *sri = talloc(talloc_ctx, struct sccp_ran_inst);
	*sri = (struct sccp_ran_inst){
		.ran = ran,
		.sccp = sccp,
		.user_data = user_data,
	};

	INIT_LLIST_HEAD(&sri->ran_peers);
	INIT_LLIST_HEAD(&sri->ran_conns);

	osmo_sccp_local_addr_by_instance(&sri->local_sccp_addr, sccp, ssn);
	sri->scu = osmo_sccp_user_bind(sccp, sccp_user_name, sccp_ran_sap_up, ssn);
	osmo_sccp_user_set_priv(sri->scu, sri);

	OSMO_ASSERT(!ran->sri);
	ran->sri = sri;

	return sri;
}

static void handle_pcstate_ind(struct sccp_ran_inst *sri, const struct osmo_scu_pcstate_param *pcst)
{
	struct osmo_ss7_instance *cs7 = osmo_sccp_get_ss7(sri->sccp);
	struct ran_peer *rp;
	bool connected;
	bool disconnected;

	LOGP(DMSC, LOGL_DEBUG, "N-PCSTATE ind: affected_pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
	     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
	     osmo_sccp_sp_status_name(pcst->sp_status),
	     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));

	/* If we don't care about that point-code, ignore PCSTATE. */
	rp = ran_peer_find_by_pc(sri, pcst->affected_pc);
	if (!rp) {
		LOGP(DMSC, LOGL_DEBUG, "No ran_peer found under pc=%u=s%s\n",
		     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc));
		return;
	}

	/* See if this marks the point code to have become available, or to have been lost.
	 *
	 * I want to detect two events:
	 * - connection event (both indicators say PC is reachable).
	 * - disconnection event (at least one indicator says the PC is not reachable).
	 *
	 * There are two separate incoming indicators with various possible values -- the incoming events can be:
	 *
	 * - neither connection nor disconnection indicated -- just indicating congestion
	 *   connected == false, disconnected == false --> do nothing.
	 * - both incoming values indicate that we are connected
	 *   --> trigger connected
	 * - both indicate we are disconnected
	 *   --> trigger disconnected
	 * - one value indicates 'connected', the other indicates 'disconnected'
	 *   --> trigger disconnected
	 *
	 * Congestion could imply that we're connected, but it does not indicate that a PC's reachability changed, so no need to
	 * trigger on that.
	 */
	connected = false;
	disconnected = false;

	switch (pcst->sp_status) {
	case OSMO_SCCP_SP_S_ACCESSIBLE:
		connected = true;
		break;
	case OSMO_SCCP_SP_S_INACCESSIBLE:
		disconnected = true;
		break;
	default:
	case OSMO_SCCP_SP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	switch (pcst->remote_sccp_status) {
	case OSMO_SCCP_REM_SCCP_S_AVAILABLE:
		if (!disconnected)
			connected = true;
		break;
	case OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN:
	case OSMO_SCCP_REM_SCCP_S_UNEQUIPPED:
	case OSMO_SCCP_REM_SCCP_S_INACCESSIBLE:
		disconnected = true;
		connected = false;
		break;
	default:
	case OSMO_SCCP_REM_SCCP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	if (disconnected) {
		LOG_RAN_PEER(rp, LOGL_NOTICE,
			     "now unreachable: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			     osmo_sccp_sp_status_name(pcst->sp_status),
			     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		osmo_fsm_inst_dispatch(rp->fi, RAN_PEER_EV_UNAVAILABLE, NULL);
	} else if (connected) {
		LOG_RAN_PEER(rp, LOGL_NOTICE,
			     "now available: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			     osmo_sccp_sp_status_name(pcst->sp_status),
			     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
		osmo_fsm_inst_dispatch(rp->fi, RAN_PEER_EV_AVAILABLE, NULL);
	}
}

static int sccp_ran_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct sccp_ran_inst *sri = osmo_sccp_user_get_priv(scu);
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_sccp_addr *my_addr;
	struct osmo_sccp_addr *peer_addr;
	uint32_t conn_id;
	int rc;

	if (!sri->ran || !sri->ran->sccp_ran_ops.up_l2) {
		LOG_SCCP_RAN_CL(sri, NULL, LOGL_ERROR, "This RAN type is not set up\n");
		msgb_free(oph->msg);
		return -1;
	}

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* indication of new inbound connection request */
		conn_id = prim->u.connect.conn_id;
		my_addr = &prim->u.connect.called_addr;
		peer_addr = &prim->u.connect.calling_addr;
		LOG_SCCP_RAN_CO(sri, peer_addr, conn_id, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (!msgb_l2(oph->msg) || msgb_l2len(oph->msg) == 0) {
			LOG_SCCP_RAN_CO(sri, peer_addr, conn_id, LOGL_NOTICE, "Received invalid N-CONNECT.ind\n");
			rc = -1;
			break;
		}

		if (osmo_sccp_addr_ri_cmp(&sri->local_sccp_addr, my_addr))
			LOG_SCCP_RAN_CO(sri, NULL, conn_id, LOGL_INFO,
					"Called address is %s which is not the locally configured address\n",
					osmo_sccp_inst_addr_name(sri->sccp, my_addr));

		/* ensure the local SCCP socket is ACTIVE */
		osmo_sccp_tx_conn_resp(scu, conn_id, my_addr, NULL, 0);

		rc = sri->ran->sccp_ran_ops.up_l2(sri, peer_addr, true, conn_id, oph->msg);
		if (rc)
			osmo_sccp_tx_disconn(scu, conn_id, my_addr, SCCP_RETURN_CAUSE_UNQUALIFIED);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* connection-oriented data received */
		conn_id = prim->u.data.conn_id;
		LOG_SCCP_RAN_CO(sri, NULL, conn_id, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		rc = sri->ran->sccp_ran_ops.up_l2(sri, NULL, true, conn_id, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		/* indication of disconnect */
		conn_id = prim->u.disconnect.conn_id;
		LOG_SCCP_RAN_CO(sri, NULL, conn_id, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		/* If there is no L2 payload in the N-DISCONNECT, no need to dispatch up_l2(). */
		if (msgb_l2len(oph->msg))
			rc = sri->ran->sccp_ran_ops.up_l2(sri, NULL, true, conn_id, oph->msg);
		else
			rc = 0;

		/* Make sure the ran_conn is dropped. It might seem more optimal to combine the disconnect() into
		 * up_l2(), but since an up_l2() dispatch might already cause the ran_conn to be discarded for other
		 * reasons, a separate disconnect() with a separate conn_id lookup is actually necessary. */
		sri->ran->sccp_ran_ops.disconnect(sri, conn_id);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* connection-less data received */
		my_addr = &prim->u.unitdata.called_addr;
		peer_addr = &prim->u.unitdata.calling_addr;
		LOG_SCCP_RAN_CL(sri, peer_addr, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (osmo_sccp_addr_ri_cmp(&sri->local_sccp_addr, my_addr))
			LOG_SCCP_RAN_CL(sri, NULL, LOGL_INFO,
					"Called address is %s which is not the locally configured address\n",
					osmo_sccp_inst_addr_name(sri->sccp, my_addr));

		rc = sri->ran->sccp_ran_ops.up_l2(sri, peer_addr, false, 0, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		handle_pcstate_ind(sri, &prim->u.pcstate);
		rc = 0;
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_STATE, PRIM_OP_INDICATION):
		LOG_SCCP_RAN_CL(sri, NULL, LOGL_INFO,
				"SCCP-User-SAP: Ignoring %s.%s\n",
				osmo_scu_prim_type_name(oph->primitive),
				get_value_string(osmo_prim_op_names, oph->operation));
		rc = 0;
		break;

	default:
		LOG_SCCP_RAN_CL(sri, NULL, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));
		rc = -1;
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

/* Push some padding if necessary to reach a multiple-of-eight offset to be msgb_push() an osmo_scu_prim that will then
 * be 8-byte aligned. */
static void msgb_pad_mod8(struct msgb *msg)
{
	uint8_t mod8 = (intptr_t)(msg->data) % 8;
	if (mod8)
		msgb_push(msg, mod8);
}

int sccp_ran_down_l2_co_initial(struct sccp_ran_inst *sri,
				const struct osmo_sccp_addr *called_addr,
				uint32_t conn_id, struct msgb *l2)
{
	struct osmo_scu_prim *prim;

	l2->l2h = l2->data;

	msgb_pad_mod8(l2);
	prim = (struct osmo_scu_prim *) msgb_push(l2, sizeof(*prim));
	prim->u.connect = (struct osmo_scu_connect_param){
		.called_addr = *called_addr,
		.calling_addr = sri->local_sccp_addr,
		.sccp_class = 2,
		//.importance = ?,
		.conn_id = conn_id,
	};
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST, l2);
	return osmo_sccp_user_sap_down_nofree(sri->scu, &prim->oph);
}

int sccp_ran_down_l2_co(struct sccp_ran_inst *sri, uint32_t conn_id, struct msgb *l2)
{
	struct osmo_scu_prim *prim;

	l2->l2h = l2->data;

	msgb_pad_mod8(l2);
	prim = (struct osmo_scu_prim *) msgb_push(l2, sizeof(*prim));
	prim->u.data.conn_id = conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST, l2);
	return osmo_sccp_user_sap_down_nofree(sri->scu, &prim->oph);
}

int sccp_ran_down_l2_cl(struct sccp_ran_inst *sri, const struct osmo_sccp_addr *called_addr, struct msgb *l2)
{
	struct osmo_scu_prim *prim;

	l2->l2h = l2->data;

	msgb_pad_mod8(l2);
	prim = (struct osmo_scu_prim *) msgb_push(l2, sizeof(*prim));
	prim->u.unitdata = (struct osmo_scu_unitdata_param){
		.called_addr = *called_addr,
		.calling_addr = sri->local_sccp_addr,
	};
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST, l2);
	return osmo_sccp_user_sap_down_nofree(sri->scu, &prim->oph);
}

int sccp_ran_disconnect(struct sccp_ran_inst *sri, uint32_t conn_id, uint32_t cause)
{
	return osmo_sccp_tx_disconn(sri->scu, conn_id, NULL, cause);
}
