/* (C) 2017 by Sysmocom s.f.m.c. GmbH
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
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/a_iface_bssap.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/osmo_msc.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/msc/a_reset.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/msc_mgcp.h>

#include <errno.h>

#define IP_V4_ADDR_LEN 4

/*
 * Helper functions to lookup and allocate subscribers
 */

/* Allocate a new subscriber connection */
static struct gsm_subscriber_connection *subscr_conn_allocate_a(const struct a_conn_info *a_conn_info,
								struct gsm_network *network,
								uint16_t lac, struct osmo_sccp_user *scu, int conn_id)
{
	struct gsm_subscriber_connection *conn;

	LOGP(DMSC, LOGL_DEBUG, "Allocating A-Interface subscriber conn: lac %i, conn_id %i\n", lac, conn_id);

	conn = talloc_zero(network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = network;
	conn->via_ran = RAN_GERAN_A;
	conn->lac = lac;

	conn->a.conn_id = conn_id;
	conn->a.scu = scu;

	/* Also backup the calling address of the BSC, this allows us to
	 * identify later which BSC is responsible for this subscriber connection */
	memcpy(&conn->a.bsc_addr, &a_conn_info->bsc->bsc_addr, sizeof(conn->a.bsc_addr));

	llist_add_tail(&conn->entry, &network->subscr_conns);
	LOGPCONN(conn, LOGL_DEBUG, "A-Interface subscriber connection successfully allocated!\n");
	return conn;
}

/* Return an existing A subscriber connection record for the given
 * connection IDs, or return NULL if not found. */
static struct gsm_subscriber_connection *subscr_conn_lookup_a(const struct gsm_network *network, int conn_id)
{
	struct gsm_subscriber_connection *conn;

	OSMO_ASSERT(network);

	DEBUGP(DMSC, "Looking for A subscriber: conn_id %i\n", conn_id);

	/* FIXME: log_subscribers() is defined in iucs.c as static inline, if
	 * maybe this function should be public to reach it from here? */
	/* log_subscribers(network); */

	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		if (conn->via_ran == RAN_GERAN_A && conn->a.conn_id == conn_id) {
			LOGPCONN(conn, LOGL_DEBUG, "Found A subscriber for conn_id %i\n", conn_id);
			return conn;
		}
	}
	DEBUGP(DMSC, "No A subscriber found for conn_id %i\n", conn_id);
	return NULL;
}

/*
 * BSSMAP handling for UNITDATA
 */

/* Endpoint to handle BSSMAP reset */
static void bssmap_rx_reset(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_ss7_instance_find(network->a.cs7_instance);
	OSMO_ASSERT(ss7);

	LOGP(DMSC, LOGL_NOTICE, "Rx BSSMAP RESET from BSC %s, sending RESET ACK\n",
	     osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));
	osmo_sccp_tx_unitdata_msg(scu, &a_conn_info->bsc->msc_addr, &a_conn_info->bsc->bsc_addr,
				  gsm0808_create_reset_ack());

	/* Make sure all orphand subscriber connections will be cleard */
	a_clear_all(scu, &a_conn_info->bsc->bsc_addr);

	if (!a_conn_info->bsc->reset)
		a_start_reset(a_conn_info->bsc, true);

	msgb_free(msg);
}

/* Endpoint to handle BSSMAP reset acknowlegement */
static void bssmap_rx_reset_ack(const struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info,
				struct msgb *msg)
{

	struct gsm_network *network = a_conn_info->network;
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_ss7_instance_find(network->a.cs7_instance);
	OSMO_ASSERT(ss7);

	if (a_conn_info->bsc->reset == NULL) {
		LOGP(DMSC, LOGL_ERROR, "Received RESET ACK from an unknown BSC %s, ignoring...\n",
		     osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));
		goto fail;
	}

	LOGP(DMSC, LOGL_NOTICE, "Received RESET ACK from BSC %s\n",
		osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));

	/* Confirm that we managed to get the reset ack message
	 * towards the connection reset logic */
	a_reset_ack_confirm(a_conn_info->bsc->reset);

fail:
	msgb_free(msg);
}

/* Handle UNITDATA BSSMAP messages */
static void bssmap_rcvmsg_udt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* Note: When in the MSC role, RESET ACK is the only valid message that
	 * can be received via UNITDATA */

	if (msgb_l3len(msg) < 1) {
		LOGP(DMSC, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		msgb_free(msg);
		return;
	}

	LOGP(DMSC, LOGL_DEBUG, "Rx BSSMAP UDT %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_RESET:
		bssmap_rx_reset(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		bssmap_rx_reset_ack(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented message format: %s -- message discarded!\n",
		     gsm0808_bssmap_name(msg->l3h[0]));
		msgb_free(msg);
	}
}

/* Receive incoming connection less data messages via sccp */
void a_sccp_rx_udt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* Note: The only valid message type that can be received
	 * via UNITDATA are BSS Management messages */
	struct bssmap_header *bs;

	OSMO_ASSERT(scu);
	OSMO_ASSERT(a_conn_info);
	OSMO_ASSERT(msg);

	LOGP(DMSC, LOGL_DEBUG, "Rx BSSMAP UDT: %s\n", msgb_hexdump_l2(msg));

	if (msgb_l2len(msg) < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "Error: Header is too short -- discarding message!\n");
		msgb_free(msg);
		return;
	}

	bs = (struct bssmap_header *)msgb_l2(msg);
	if (bs->length < msgb_l2len(msg) - sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "Error: Message is too short -- discarding message!\n");
		msgb_free(msg);
		return;
	}

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_udt(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DMSC, LOGL_ERROR,
		     "Error: Unimplemented message type: %s -- message discarded!\n", gsm0808_bssmap_name(bs->type));
		msgb_free(msg);
	}
}

/*
 * BSSMAP handling for connection oriented data
 */

/* Endpoint to handle BSSMAP clear request */
static int bssmap_rx_clear_rqst(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct tlv_parsed tp;
	int rc;
	struct msgb *msg_resp;
	uint8_t cause;

	LOGPCONN(conn, LOGL_INFO, "Rx BSSMAP CLEAR REQUEST\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGP(DMSC, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}
	cause = TLVP_VAL(&tp, GSM0808_IE_CAUSE)[0];

	/* Respond with clear command */
	msg_resp = gsm0808_create_clear_command(GSM0808_CAUSE_CALL_CONTROL);
	rc = osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_resp);

	msc_clear_request(conn, cause);

	msgb_free(msg);
	return rc;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP clear complete */
static int bssmap_rx_clear_complete(struct osmo_sccp_user *scu,
				    const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	int rc;

	LOGP(DMSC, LOGL_INFO, "Rx BSSMAP CLEAR COMPPLETE, releasing SCCP connection\n");
	rc = osmo_sccp_tx_disconn(scu, a_conn_info->conn_id,
				  NULL, SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);

	/* Remove the record from the list with active connections. */
	a_delete_bsc_con(a_conn_info->conn_id);

	msgb_free(msg);
	return rc;
}

/* Endpoint to handle layer 3 complete messages */
static int bssmap_rx_l3_compl(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct tlv_parsed tp;
	struct {
		uint8_t ident;
		struct gsm48_loc_area_id lai;
		uint16_t ci;
	} __attribute__ ((packed)) lai_ci;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	uint8_t data_length;
	const uint8_t *data;
	int rc;

	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;

	LOGP(DMSC, LOGL_INFO, "Rx BSSMAP COMPLETE L3 INFO (conn_id=%i)\n", a_conn_info->conn_id);

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory CELL IDENTIFIER not present -- discarding message!\n");
		goto fail;
	}
	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory LAYER 3 INFORMATION not present -- discarding message!\n");
		goto fail;
	}

	/* Parse Cell ID element */
	/* FIXME: Encapsulate this in a parser/generator function inside
	 * libosmocore, add support for all specified cell identification
	 * discriminators (see 3GPP ts 3.2.2.17 Cell Identifier) */
	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER);
	if (sizeof(lai_ci) != data_length) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (wrong field length) -- discarding message!\n");
		goto fail;
	}
	memcpy(&lai_ci, data, sizeof(lai_ci));
	if (lai_ci.ident != CELL_IDENT_WHOLE_GLOBAL) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (wrong cell identification discriminator) -- discarding message!\n");
		goto fail;
	}
	if (gsm48_decode_lai(&lai_ci.lai, &mcc, &mnc, &lac) != 0) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (lai decoding failed) -- discarding message!\n");
		goto fail;
	}

	/* Parse Layer 3 Information element */
	/* FIXME: This is probably to hackish, compiler also complains "assignment discards ‘const’ qualifier..." */
	msg->l3h = (uint8_t*)TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION);
	msg->tail = msg->l3h + TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	/* Create new subscriber context */
	conn = subscr_conn_allocate_a(a_conn_info, network, lac, scu, a_conn_info->conn_id);

	/* Handover location update to the MSC code */
	rc = msc_compl_l3(conn, msg, 0);
	msgb_free(msg);

	if (rc == MSC_CONN_ACCEPT) {
		LOGP(DMSC, LOGL_INFO, "User has been accepted by MSC.\n");
		return 0;
	} else if (rc == MSC_CONN_REJECT)
		LOGP(DMSC, LOGL_INFO, "User has been rejected by MSC.\n");
	else
		LOGP(DMSC, LOGL_INFO, "User has been rejected by MSC (unknown error)\n");

	return -EINVAL;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP classmark update */
static int bssmap_rx_classmark_upd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct tlv_parsed tp;
	const uint8_t *cm2 = NULL;
	const uint8_t *cm3 = NULL;
	uint8_t cm2_len = 0;
	uint8_t cm3_len = 0;

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP CLASSMARK UPDATE\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2)) {
		LOGPCONN(conn, LOGL_ERROR, "Mandatory Classmark Information Type 2 not present -- discarding message!\n");
		goto fail;
	}

	cm2 = TLVP_VAL(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);
	cm2_len = TLVP_LEN(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);

	if (TLVP_PRESENT(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3)) {
		cm3 = TLVP_VAL(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
		cm3_len = TLVP_LEN(&tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
	}

	/* Inform MSC about the classmark change */
	msc_classmark_chg(conn, cm2, cm2_len, cm3, cm3_len);

	msgb_free(msg);
	return 0;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP cipher mode complete */
static int bssmap_rx_ciph_compl(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	/* FIXME: The field GSM0808_IE_LAYER_3_MESSAGE_CONTENTS is optional by
	 * means of the specification. So there can be messages without L3 info.
	 * In this case, the code will crash becrause msc_cipher_mode_compl()
	 * is not able to deal with msg = NULL and apperently
	 * msc_cipher_mode_compl() was never meant to be used without L3 data.
	 * This needs to be discussed further! */

	struct tlv_parsed tp;
	uint8_t alg_id = 1;

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP CIPHER MODE COMPLETE\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHOSEN_ENCR_ALG)) {
		alg_id = TLVP_VAL(&tp, GSM0808_IE_CHOSEN_ENCR_ALG)[0] - 1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS)) {
		msg->l3h = (uint8_t*)TLVP_VAL(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
		msg->tail = msg->l3h + TLVP_LEN(&tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
	} else {
		msgb_free(msg);
		msg = NULL;
	}

	/* Hand over cipher mode complete message to the MSC */
	msc_cipher_mode_compl(conn, msg, alg_id);
	msgb_free(msg);

	return 0;
}

/* Endpoint to handle BSSMAP cipher mode reject */
static int bssmap_rx_ciph_rej(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct tlv_parsed tp;
	uint8_t cause;

	LOGPCONN(conn, LOGL_NOTICE, "RX BSSMAP CIPHER MODE REJECT\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, BSS_MAP_MSG_CIPHER_MODE_REJECT)) {
		LOGPCONN(conn, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}

	cause = TLVP_VAL(&tp, BSS_MAP_MSG_CIPHER_MODE_REJECT)[0];
	LOGPCONN(conn, LOGL_NOTICE, "Cipher mode rejection cause: %i\n", cause);

	/* FIXME: Can we do something meaningful here? e.g. report to the
	 * msc code somehow that the cipher mode command has failed. */

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle BSSMAP assignment failure */
static int bssmap_rx_ass_fail(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct tlv_parsed tp;
	uint8_t cause;
	uint8_t *rr_cause_ptr = NULL;
	uint8_t rr_cause;

	LOGPCONN(conn, LOGL_NOTICE, "Rx BSSMAP ASSIGNMENT FAILURE message\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGPCONN(conn, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}
	cause = TLVP_VAL(&tp, GSM0808_IE_CAUSE)[0];

	if (TLVP_PRESENT(&tp, GSM0808_IE_RR_CAUSE)) {
		rr_cause = TLVP_VAL(&tp, GSM0808_IE_RR_CAUSE)[0];
		rr_cause_ptr = &rr_cause;
	}

	/* FIXME: In AoIP, the Assignment failure will carry also an optional
	 * Codec List (BSS Supported) element. It has to be discussed if we
	 * can ignore this element. If not, The msc_assign_fail() function
	 * call has to change. However msc_assign_fail() does nothing in the
	 * end. So probably we can just leave it as it is. Even for AoIP */

	/* Inform the MSC about the assignment failure event */
	msc_assign_fail(conn, cause, rr_cause_ptr);

	msgb_free(msg);
	return 0;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle sapi "n" reject */
static int bssmap_rx_sapi_n_rej(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct tlv_parsed tp;
	uint8_t dlci;

	LOGPCONN(conn, LOGL_NOTICE, "Rx BSSMAP SAPI-N-REJECT message\n");

	/* Note: The MSC code seems not to care about the cause code, but by
	 * the specification it is mandatory, so we check its presence. See
	 * also 3GPP TS 48.008 3.2.1.34 SAPI "n" REJECT */
	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CAUSE)) {
		LOGPCONN(conn, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		goto fail;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_DLCI)) {
		LOGPCONN(conn, LOGL_ERROR, "DLCI is missing -- discarding message!\n");
		goto fail;
	}
	dlci = TLVP_VAL(&tp, GSM0808_IE_DLCI)[0];

	/* Inform the MSC about the sapi "n" reject event */
	msc_sapi_n_reject(conn, dlci);

	msgb_free(msg);
	return 0;

fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Endpoint to handle assignment complete */
static int bssmap_rx_ass_compl(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct mgcp_client *mgcp;
	struct tlv_parsed tp;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in *rtp_addr_in;
	int rc;

	mgcp = conn->network->mgw.client;
	OSMO_ASSERT(mgcp);

	LOGPCONN(conn, LOGL_INFO, "Rx BSSMAP ASSIGNMENT COMPLETE message\n");

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, msgb_l3len(msg) - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
		LOGPCONN(conn, LOGL_ERROR, "AoIP transport identifier missing -- discarding message!\n");
		goto fail;
	}

	/* Decode AoIP transport address element */
	rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr, TLVP_VAL(&tp, GSM0808_IE_AOIP_TRASP_ADDR),
					 TLVP_LEN(&tp, GSM0808_IE_AOIP_TRASP_ADDR));
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "Unable to decode aoip transport address.\n");
		goto fail;
	}

	/* use address / port supplied with the AoIP
	 * transport address element */
	if (rtp_addr.ss_family == AF_INET) {
		rtp_addr_in = (struct sockaddr_in *)&rtp_addr;
		msc_mgcp_ass_complete(conn, osmo_ntohs(rtp_addr_in->sin_port), inet_ntoa(rtp_addr_in->sin_addr));
	} else {
		LOGPCONN(conn, LOGL_ERROR, "Unsopported addressing scheme. (supports only IPV4)\n");
		goto fail;
	}

	/* FIXME: Seems to be related to authentication or,
	   encryption. Is this really in the right place? */
	msc_rx_sec_mode_compl(conn);

	msgb_free(msg);
	return 0;
fail:
	msgb_free(msg);
	return -EINVAL;
}

/* Handle incoming connection oriented BSSMAP messages */
static int rx_bssmap(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_subscriber_connection *conn;

	if (msgb_l3len(msg) < 1) {
		LOGP(DMSC, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		msgb_free(msg);
		return -1;
	}

	/* Only message types allowed without a 'conn' */
	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_COMPLETE_LAYER_3:
		return bssmap_rx_l3_compl(scu, a_conn_info, msg);
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return bssmap_rx_clear_complete(scu, a_conn_info, msg);
	default:
		break;
	}

	conn = subscr_conn_lookup_a(a_conn_info->network, a_conn_info->conn_id);
	if (!conn) {
		LOGP(DMSC, LOGL_ERROR, "Couldn't find subscr_conn for conn_id=%d\n", a_conn_info->conn_id);
		msgb_free(msg);
		return -EINVAL;
	}

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP DT1 %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_CLEAR_RQST:
		return bssmap_rx_clear_rqst(conn, msg);
	case BSS_MAP_MSG_CLASSMARK_UPDATE:
		return bssmap_rx_classmark_upd(conn, msg);
	case BSS_MAP_MSG_CIPHER_MODE_COMPLETE:
		return bssmap_rx_ciph_compl(conn, msg);
	case BSS_MAP_MSG_CIPHER_MODE_REJECT:
		return bssmap_rx_ciph_rej(conn, msg);
	case BSS_MAP_MSG_ASSIGMENT_FAILURE:
		return bssmap_rx_ass_fail(conn, msg);
	case BSS_MAP_MSG_SAPI_N_REJECT:
		return bssmap_rx_sapi_n_rej(conn, msg);
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		return bssmap_rx_ass_compl(conn, msg);
	default:
		LOGPCONN(conn, LOGL_ERROR, "Unimplemented msg type: %s\n", gsm0808_bssmap_name(msg->l3h[0]));
		msgb_free(msg);
		return -EINVAL;
	}

	return -EINVAL;
}

/* Endpoint to handle regular BSSAP DTAP messages */
static int rx_dtap(const struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct gsm_subscriber_connection *conn;

	conn = subscr_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn) {
		msgb_free(msg);
		return -EINVAL;
	}

	LOGPCONN(conn, LOGL_DEBUG, "Rx DTAP %s\n", msgb_hexdump_l2(msg));

	/* msc_dtap expects the dtap payload in l3h */
	msg->l3h = msg->l2h + 3;

	/* Forward dtap payload into the msc */
	msc_dtap(conn, conn->a.conn_id, msg);
	msgb_free(msg);

	return 0;
}

/* Handle incoming connection oriented messages */
int a_sccp_rx_dt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	OSMO_ASSERT(scu);
	OSMO_ASSERT(a_conn_info);
	OSMO_ASSERT(msg);

	if (msgb_l2len(msg) < sizeof(struct bssmap_header)) {
		LOGP(DMSC, LOGL_NOTICE, "The header is too short -- discarding message!\n");
		msgb_free(msg);
		return -EINVAL;
	}

	switch (msg->l2h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		return rx_bssmap(scu, a_conn_info, msg);
	case BSSAP_MSG_DTAP:
		return rx_dtap(scu, a_conn_info, msg);
	default:
		LOGP(DMSC, LOGL_ERROR, "Unimplemented BSSAP msg type: %s\n", gsm0808_bssap_name(msg->l2h[0]));
		msgb_free(msg);
		return -EINVAL;
	}

	return -EINVAL;
}
