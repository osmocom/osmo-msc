/* (C) 2017 by sysmocom s.f.m.c. GmbH
 * (C) 2018 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/a_iface_bssap.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/msc/a_reset.h>
#include <osmocom/msc/osmo_msc.h>
#include <osmocom/msc/vlr.h>

#include <errno.h>

/* A pointer to the GSM network we work with. By the current paradigm,
 * there can only be one gsm_network per MSC. The pointer is set once
 * when calling a_init() */
static struct gsm_network *gsm_network = NULL;

/* A struct to track currently active connections. We need that information
 * to handle failure sitautions. In case of a problem, we must know which
 * connections are currently open and which BSC is responsible. We also need
 * the data to perform our connection checks (a_reset). All other logic will
 * look at the connection ids and addresses that are supplied by the
 * primitives */
struct bsc_conn {
	struct llist_head list;
	uint32_t conn_id;			/* Connection identifier */
	struct bsc_context *bsc;
};

/* Internal list with connections we currently maintain. This
 * list is of type struct bsc_conn (see above) */
static LLIST_HEAD(active_connections);

/* Record info of a new active connection in the active connection list */
static void record_bsc_con(const void *ctx, struct bsc_context *bsc, uint32_t conn_id)
{
	struct bsc_conn *conn;

	conn = talloc_zero(ctx, struct bsc_conn);
	OSMO_ASSERT(conn);

	conn->conn_id = conn_id;
	conn->bsc = bsc;

	llist_add_tail(&conn->list, &active_connections);
}

/* Delete info of a closed connection from the active connection list */
void a_delete_bsc_con(uint32_t conn_id)
{
	struct bsc_conn *conn;
	struct bsc_conn *conn_temp;

	llist_for_each_entry_safe(conn, conn_temp, &active_connections, list) {
		if (conn->conn_id == conn_id) {
			LOGPBSCCONN(conn, LOGL_DEBUG, "Removing A-interface conn\n");
			llist_del(&conn->list);
			talloc_free(conn);
		}
	}
}

/* Find a specified connection id */
static struct bsc_conn *find_bsc_con(uint32_t conn_id)
{
	struct bsc_conn *conn;

	/* Find the address for the current connection id */
	llist_for_each_entry(conn, &active_connections, list) {
		if (conn->conn_id == conn_id) {
			return conn;
		}
	}

	return NULL;
}

/* Check if a specified connection id has an active SCCP connection */
static bool check_connection_active(uint32_t conn_id)
{
	if (find_bsc_con(conn_id))
		return true;
	else
		return false;
}

/* Get the context for a specific calling (BSC) address */
static struct bsc_context *get_bsc_context_by_sccp_addr(const struct osmo_sccp_addr *addr)
{
	struct bsc_context *bsc_ctx;
	struct osmo_ss7_instance *ss7;

	if (!addr)
		return NULL;

	llist_for_each_entry(bsc_ctx, &gsm_network->a.bscs, list) {
		if (memcmp(&bsc_ctx->bsc_addr, addr, sizeof(*addr)) == 0)
			return bsc_ctx;
	}

	ss7 = osmo_ss7_instance_find(gsm_network->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DBSSAP, LOGL_NOTICE, "The calling BSC (%s) is unknown to this MSC ...\n",
	     osmo_sccp_addr_name(ss7, addr));
	return NULL;
}

/* Send DTAP message via A-interface, take ownership of msg */
int a_iface_tx_dtap(struct msgb *msg)
{
	struct gsm_subscriber_connection *conn;
	struct msgb *msg_resp;

	/* FIXME: Set this to some meaninful value! */
	uint8_t link_id = 0x00;
	OSMO_ASSERT(msg);
	conn = (struct gsm_subscriber_connection *)msg->dst;
	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->a.scu);

	LOGPCONN(conn, LOGL_DEBUG, "Passing DTAP message from MSC to BSC\n");

	msg->l3h = msg->data;
	msg_resp = gsm0808_create_dtap(msg, link_id);

	/* gsm0808_create_dtap() has copied the data to msg_resp,
	 * so msg has served its purpose now */
	msgb_free(msg);

	if (!msg_resp) {
		LOGPCONN(conn, LOGL_ERROR, "Unable to generate BSSMAP DTAP message!\n");
		return -EINVAL;
	}

	LOGPCONN(conn, LOGL_DEBUG, "N-DATA.req(%s)\n", msgb_hexdump_l2(msg_resp));
	/* osmo_sccp_tx_data_msg() takes ownership of msg_resp */
	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_resp);
}

/* Send Cipher mode command via A-interface */
int a_iface_tx_cipher_mode(const struct gsm_subscriber_connection *conn,
			   struct gsm0808_encrypt_info *ei, int include_imeisv)
{
	/* TODO generalize for A- and Iu interfaces, don't name after 08.08 */
	struct msgb *msg_resp;
	uint8_t crm = 0x01;

	OSMO_ASSERT(conn);
	LOGPCONN(conn, LOGL_DEBUG, "Tx BSSMAP CIPHER MODE COMMAND to BSC, %u ciphers (%s)",
		 ei->perm_algo_len, osmo_hexdump_nospc(ei->perm_algo, ei->perm_algo_len));
	LOGPC(DBSSAP, LOGL_DEBUG, " key %s\n", osmo_hexdump_nospc(ei->key, ei->key_len));

	msg_resp = gsm0808_create_cipher(ei, include_imeisv ? &crm : NULL);
	LOGPCONN(conn, LOGL_DEBUG, "N-DATA.req(%s)\n", msgb_hexdump_l2(msg_resp));

	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_resp);
}

/* Page a subscriber via A-interface */
int a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac)
{
	struct bsc_context *bsc_ctx;
	struct gsm0808_cell_id_list2 cil;
	struct msgb *msg;
	int page_count = 0;
	struct osmo_ss7_instance *ss7;

	OSMO_ASSERT(imsi);

	cil.id_discr = CELL_IDENT_LAC;
	cil.id_list[0].lac = lac;
	cil.id_list_len = 1;

	ss7 = osmo_ss7_instance_find(gsm_network->a.cs7_instance);
	OSMO_ASSERT(ss7);

	/* Deliver paging request to all known BSCs */
	llist_for_each_entry(bsc_ctx, &gsm_network->a.bscs, list) {
		if (a_reset_conn_ready(bsc_ctx->reset)) {
			LOGP(DBSSAP, LOGL_DEBUG,
			     "Tx BSSMAP paging message from MSC %s to BSC %s (imsi=%s, tmsi=0x%08x, lac=%u)\n",
			     osmo_sccp_addr_name(ss7, &bsc_ctx->msc_addr),
			     osmo_sccp_addr_name(ss7, &bsc_ctx->bsc_addr), imsi, tmsi, lac);
			msg = gsm0808_create_paging2(imsi, &tmsi, &cil, NULL);
			osmo_sccp_tx_unitdata_msg(bsc_ctx->sccp_user,
						  &bsc_ctx->msc_addr, &bsc_ctx->bsc_addr, msg);
			page_count++;
		} else {
			LOGP(DBSSAP, LOGL_DEBUG,
			     "Connection down, dropping paging from MSC %s to BSC %s (imsi=%s, tmsi=0x%08x, lac=%u)\n",
			     osmo_sccp_addr_name(ss7, &bsc_ctx->msc_addr),
			     osmo_sccp_addr_name(ss7, &bsc_ctx->bsc_addr), imsi, tmsi, lac);
		}
	}

	if (page_count <= 0)
		LOGP(DBSSAP, LOGL_ERROR, "Could not deliver paging because none of the associated BSCs is available!\n");

	return page_count;
}

/* Convert speech version field */
static uint8_t convert_speech_version_l3_to_A(int speech_ver)
{
	/* The speech versions that are transmitted in the Bearer capability
	 * information element, that is transmitted on the Layer 3 (CC)
	 * use a different encoding than the permitted speech version
	 * identifier, that is signalled in the channel type element on the A
	 * interface. (See also 3GPP TS 48.008, 3.2.2.1 and 3GPP TS 24.008,
	 * 10.5.103 */

	switch (speech_ver) {
	case GSM48_BCAP_SV_FR:
		return GSM0808_PERM_FR1;
	case GSM48_BCAP_SV_HR:
		return GSM0808_PERM_HR1;
	case GSM48_BCAP_SV_EFR:
		return GSM0808_PERM_FR2;
	case GSM48_BCAP_SV_AMR_F:
		return GSM0808_PERM_FR3;
	case GSM48_BCAP_SV_AMR_H:
		return GSM0808_PERM_HR3;
	case GSM48_BCAP_SV_AMR_OFW:
		return GSM0808_PERM_FR4;
	case GSM48_BCAP_SV_AMR_OHW:
		return GSM0808_PERM_HR4;
	case GSM48_BCAP_SV_AMR_FW:
		return GSM0808_PERM_FR5;
	case GSM48_BCAP_SV_AMR_OH:
		return GSM0808_PERM_HR6;
	}

	/* If nothing matches, tag the result as invalid */
	LOGP(DBSSAP, LOGL_ERROR, "Invalid permitted speech version: %d\n", speech_ver);
	return 0xFF;
}

/* Convert speech preference field */
static uint8_t convert_speech_pref_l3_to_A(int radio)
{
	/* The Radio channel requirement field that is transmitted in the
	 * Bearer capability information element, that is transmitted on the
	 * Layer 3 (CC) uses a different encoding than the Channel rate and
	 * type field that is signalled in the channel type element on the A
	 * interface. (See also 3GPP TS 48.008, 3.2.2.1 and 3GPP TS 24.008,
	 * 10.5.102 */

	switch (radio) {
	case GSM48_BCAP_RRQ_FR_ONLY:
		return GSM0808_SPEECH_FULL_BM;
	case GSM48_BCAP_RRQ_DUAL_FR:
		return GSM0808_SPEECH_FULL_PREF;
	case GSM48_BCAP_RRQ_DUAL_HR:
		return GSM0808_SPEECH_HALF_PREF;
	}

	LOGP(DBSSAP, LOGL_ERROR, "Invalid radio channel preference: %d; defaulting to full rate.\n",
	     radio);
	return GSM0808_SPEECH_FULL_BM;
}

/* Assemble the channel type field */
static int enc_channel_type(struct gsm0808_channel_type *ct, const struct gsm_mncc_bearer_cap *bc)
{
	unsigned int i;
	uint8_t sv;
	unsigned int count = 0;
	bool only_gsm_hr = true;

	OSMO_ASSERT(ct);
	OSMO_ASSERT(bc);

	ct->ch_indctr = GSM0808_CHAN_SPEECH;

	for (i = 0; i < ARRAY_SIZE(bc->speech_ver); i++) {
		if (bc->speech_ver[i] == -1)
			break;
		sv = convert_speech_version_l3_to_A(bc->speech_ver[i]);
		if (sv != 0xFF) {
			/* Detect if something else than
			 * GSM HR V1 is supported */
			if (sv == GSM0808_PERM_HR2 ||
			    sv == GSM0808_PERM_HR3 || sv == GSM0808_PERM_HR4 || sv == GSM0808_PERM_HR6)
				only_gsm_hr = false;

			ct->perm_spch[count] = sv;
			count++;
		}
	}
	ct->perm_spch_len = count;

	if (only_gsm_hr)
		/* Note: We must avoid the usage of GSM HR1 as this
		 * codec only offers very poor audio quality. If the
		 * MS only supports GSM HR1 (and full rate), and has
		 * a preference for half rate. Then we will ignore the
		 * preference and assume a preference for full rate. */
		ct->ch_rate_type = GSM0808_SPEECH_FULL_BM;
	else
		ct->ch_rate_type = convert_speech_pref_l3_to_A(bc->radio);

	if (count)
		return 0;
	else
		return -EINVAL;
}

/* Assemble the speech codec field */
static int enc_speech_codec_list(struct gsm0808_speech_codec_list *scl, const struct gsm0808_channel_type *ct)
{
	unsigned int i;
	int rc;

	memset(scl, 0, sizeof(*scl));
	for (i = 0; i < ct->perm_spch_len; i++) {
		rc = gsm0808_speech_codec_from_chan_type(&scl->codec[i], ct->perm_spch[i]);
		if (rc != 0)
			return -EINVAL;
	}
	scl->len = i;

	return 0;
}

/* Send assignment request via A-interface */
int a_iface_tx_assignment(const struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn;
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list scl;
	uint32_t *ci_ptr = NULL;
	struct msgb *msg;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in rtp_addr_in;
	int rc;

	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	LOGPCONN(conn, LOGL_DEBUG, "Tx BSSMAP ASSIGNMENT COMMAND to BSC\n");

	/* Channel type */
	rc = enc_channel_type(&ct, &trans->bearer_cap);
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "Not sending Assignment to BSC: failed to generate channel type\n");
		return -EINVAL;
	}

	/* Speech codec list */
	rc = enc_speech_codec_list(&scl, &ct);
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "Not sending Assignment to BSC: failed to generate speech codec list\n");
		return -EINVAL;
	}

	/* Package RTP-Address data */
	memset(&rtp_addr_in, 0, sizeof(rtp_addr_in));
	rtp_addr_in.sin_family = AF_INET;
	rtp_addr_in.sin_port = osmo_htons(conn->rtp.local_port_ran);
	rtp_addr_in.sin_addr.s_addr = inet_addr(conn->rtp.local_addr_ran);

	if (rtp_addr_in.sin_addr.s_addr == INADDR_NONE) {
		LOGPCONN(conn, LOGL_ERROR, "Invalid RTP-Address -- assignment not sent!\n");
		return -EINVAL;
	}
	if (rtp_addr_in.sin_port == 0) {
		LOGPCONN(conn, LOGL_ERROR, "Invalid RTP-Port -- assignment not sent!\n");
		return -EINVAL;
	}

	memset(&rtp_addr, 0, sizeof(rtp_addr));
	memcpy(&rtp_addr, &rtp_addr_in, sizeof(rtp_addr_in));

	msg = gsm0808_create_ass(&ct, NULL, &rtp_addr, &scl, ci_ptr);

	LOGPCONN(conn, LOGL_DEBUG, "N-DATA.req(%s)\n", msgb_hexdump_l2(msg));
	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg);
}

/* Send clear command via A-interface */
int a_iface_tx_clear_cmd(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg;

	LOGPCONN(conn, LOGL_INFO, "Tx BSSMAP CLEAR COMMAND to BSC\n");

	msg = gsm0808_create_clear_command(GSM0808_CAUSE_CALL_CONTROL);
	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg);
}

/* Callback function: Close all open connections */
static void a_reset_cb(const void *priv)
{
	struct msgb *msg;
	struct bsc_context *bsc_ctx = (struct bsc_context*) priv;
	struct osmo_ss7_instance *ss7;

	/* Skip if the A interface is not properly initalized yet */
	if (!gsm_network)
		return;

	/* Clear all now orphaned subscriber connections */
	a_clear_all(bsc_ctx->sccp_user, &bsc_ctx->bsc_addr);

	/* Send reset to the remote BSC */
	ss7 = osmo_ss7_instance_find(gsm_network->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DBSSAP, LOGL_NOTICE, "Tx BSSMAP RESET to BSC %s\n", osmo_sccp_addr_name(ss7, &bsc_ctx->bsc_addr));
	msg = gsm0808_create_reset();
	osmo_sccp_tx_unitdata_msg(bsc_ctx->sccp_user, &bsc_ctx->msc_addr,
				  &bsc_ctx->bsc_addr, msg);
}

/* Add a new BSC connection to our internal list with known BSCs */
static struct bsc_context *add_bsc(const struct osmo_sccp_addr *msc_addr,
				   const struct osmo_sccp_addr *bsc_addr, struct osmo_sccp_user *scu)
{
	struct bsc_context *bsc_ctx;
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_ss7_instance_find(gsm_network->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DBSSAP, LOGL_NOTICE, "Adding new BSC connection for BSC %s...\n", osmo_sccp_addr_name(ss7, bsc_addr));

	/* Generate and fill up a new bsc context */
	bsc_ctx = talloc_zero(gsm_network, struct bsc_context);
	OSMO_ASSERT(bsc_ctx);
	memcpy(&bsc_ctx->bsc_addr, bsc_addr, sizeof(*bsc_addr));
	memcpy(&bsc_ctx->msc_addr, msc_addr, sizeof(*msc_addr));
	bsc_ctx->sccp_user = scu;
	llist_add_tail(&bsc_ctx->list, &gsm_network->a.bscs);

	return bsc_ctx;
}

/* start the BSSMAP RESET fsm */
void a_start_reset(struct bsc_context *bsc_ctx, bool already_connected)
{
	char bsc_name[32];
	OSMO_ASSERT(bsc_ctx->reset == NULL);
	/* Start reset procedure to make the new connection active */
	snprintf(bsc_name, sizeof(bsc_name), "bsc-%i", bsc_ctx->bsc_addr.pc);
	bsc_ctx->reset = a_reset_alloc(bsc_ctx, bsc_name, a_reset_cb, bsc_ctx, already_connected);
}

/* determine if given msg is BSSMAP RESET related (true) or not (false) */
static bool bssmap_is_reset(struct msgb *msg)
{
	struct bssmap_header *bs = (struct bssmap_header *)msgb_l2(msg);

	if (msgb_l2len(msg) < sizeof(*bs))
		return false;

	if (bs->type != BSSAP_MSG_BSS_MANAGEMENT)
		return false;

	if (msg->l2h[sizeof(*bs)] == BSS_MAP_MSG_RESET)
		return true;

	if (msg->l2h[sizeof(*bs)] == BSS_MAP_MSG_RESET_ACKNOWLEDGE)
		return true;

	return false;
}

/* Callback function, called by the SSCP stack when data arrives */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	int rc = 0;
	struct a_conn_info a_conn_info;
	struct bsc_conn *bsc_con;

	memset(&a_conn_info, 0, sizeof(a_conn_info));
	a_conn_info.network = gsm_network;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle inbound connection indication */
		a_conn_info.conn_id = scu_prim->u.connect.conn_id;
		a_conn_info.bsc = get_bsc_context_by_sccp_addr(&scu_prim->u.unitdata.calling_addr);
		if (!a_conn_info.bsc) {
			/* We haven't heard from this BSC before, allocate it */
			a_conn_info.bsc = add_bsc(&scu_prim->u.connect.called_addr,
						  &scu_prim->u.connect.calling_addr, scu);
			a_start_reset(a_conn_info.bsc, false);
		} else {
			/* This BSC is already known to us, check if we have been through reset yet */
			if (a_reset_conn_ready(a_conn_info.bsc->reset) == false) {
				LOGP(DBSSAP, LOGL_NOTICE, "Refusing N-CONNECT.ind(%u, %s), BSC not reset yet\n",
				     scu_prim->u.connect.conn_id, msgb_hexdump_l2(oph->msg));
				rc = osmo_sccp_tx_disconn(scu, a_conn_info.conn_id, &a_conn_info.bsc->msc_addr,
							  SCCP_RETURN_CAUSE_UNQUALIFIED);
				break;
			}

			osmo_sccp_tx_conn_resp(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, NULL, 0);
			if (msgb_l2len(oph->msg) > 0) {
				LOGP(DBSSAP, LOGL_DEBUG, "N-CONNECT.ind(%u, %s)\n",
				     scu_prim->u.connect.conn_id, msgb_hexdump_l2(oph->msg));
				rc = a_sccp_rx_dt(scu, &a_conn_info, oph->msg);
			} else
				LOGP(DBSSAP, LOGL_DEBUG, "N-CONNECT.ind(%u)\n", scu_prim->u.connect.conn_id);
			record_bsc_con(scu, a_conn_info.bsc, scu_prim->u.connect.conn_id);
		}
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		bsc_con = find_bsc_con(scu_prim->u.data.conn_id);
		if (!bsc_con) {
			LOGP(DBSSAP, LOGL_ERROR, "N-DATA.ind(%u, %s) for unknown conn_id\n",
				scu_prim->u.data.conn_id, msgb_hexdump_l2(oph->msg));
			break;
		}
		a_conn_info.conn_id = scu_prim->u.data.conn_id;
		a_conn_info.bsc = bsc_con->bsc;
		LOGP(DBSSAP, LOGL_DEBUG, "N-DATA.ind(%u, %s)\n",
		     scu_prim->u.data.conn_id, msgb_hexdump_l2(oph->msg));
		a_sccp_rx_dt(scu, &a_conn_info, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UNITDATA */

		/* Get BSC context, create a new one if necessary */
		a_conn_info.bsc = get_bsc_context_by_sccp_addr(&scu_prim->u.unitdata.calling_addr);
		if (!a_conn_info.bsc) {
			/* We haven't heard from this BSC before, allocate it */
			a_conn_info.bsc = add_bsc(&scu_prim->u.unitdata.called_addr,
						&scu_prim->u.unitdata.calling_addr, scu);
			/* Make sure that reset procedure is started */
			a_start_reset(a_conn_info.bsc, false);
		}

		/* As long as we are in the reset phase, only reset related BSSMAP messages may pass
		 * beond here. */
		if (!bssmap_is_reset(oph->msg) && a_reset_conn_ready(a_conn_info.bsc->reset) == false) {
			LOGP(DBSSAP, LOGL_NOTICE, "Ignoring N-UNITDATA.ind(%s), BSC not reset yet\n",
			     msgb_hexdump_l2(oph->msg));
			break;
		}

		DEBUGP(DBSSAP, "N-UNITDATA.ind(%s)\n", msgb_hexdump_l2(oph->msg));
		a_sccp_rx_udt(scu, &a_conn_info, oph->msg);
		break;

	default:
		LOGP(DBSSAP, LOGL_ERROR, "Unhandled SIGTRAN operation %s on primitive %u\n",
		     get_value_string(osmo_prim_op_names, oph->operation), oph->primitive);
		break;
	}

	/* We didn't transfer msgb ownership to any downstream functions so we rely on
	 * this single/central location to free() the msgb wrapping the primitive */
	msgb_free(oph->msg);
	return rc;
}

/* Clear all subscriber connections on a specified BSC */
void a_clear_all(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *bsc_addr)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_subscriber_connection *conn_temp;
	struct gsm_network *network = gsm_network;

	OSMO_ASSERT(scu);
	OSMO_ASSERT(bsc_addr);

	llist_for_each_entry_safe(conn, conn_temp, &network->subscr_conns, entry) {
		/* Clear only A connections and connections that actually
		 * belong to the specified BSC */
		if (conn->via_ran == RAN_GERAN_A && memcmp(bsc_addr, &conn->a.bsc_addr, sizeof(conn->a.bsc_addr)) == 0) {
			uint32_t conn_id = conn->a.conn_id;
			LOGPCONN(conn, LOGL_NOTICE, "Dropping orphaned subscriber connection\n");
			/* This call will/may talloc_free(conn), so we must save conn_id above */
			msc_clear_request(conn, GSM48_CC_CAUSE_SWITCH_CONG);

			/* If there is still an SCCP connection active, remove it now */
			if (check_connection_active(conn_id)) {
				osmo_sccp_tx_disconn(scu, conn_id, bsc_addr,
						     SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);
				a_delete_bsc_con(conn_id);
			}
		}
	}
}

/* Initalize A interface connection between to MSC and BSC */
int a_init(struct osmo_sccp_instance *sccp, struct gsm_network *network)
{
	OSMO_ASSERT(sccp);
	OSMO_ASSERT(network);

	/* FIXME: Remove hardcoded parameters, use parameters in parameter list */
	LOGP(DBSSAP, LOGL_NOTICE, "Initalizing SCCP connection to stp...\n");

	/* Set GSM network variable, there can only be
	 * one network by design */
	if (gsm_network != NULL) {
		OSMO_ASSERT(gsm_network == network);
	} else
		gsm_network = network;

	/* SCCP Protocol stack */
	osmo_sccp_user_bind(sccp, "OsmoMSC-A", sccp_sap_up, SCCP_SSN_BSSAP);

	return 0;
}
