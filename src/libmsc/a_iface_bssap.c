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
#include <osmocom/core/byteswap.h>
#include <osmocom/msc/a_reset.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/msc_mgcp.h>

#include <errno.h>

#define IP_V4_ADDR_LEN 4

/*
 * Helper functions to lookup and allocate subscribers
 */

/* Allocate a new RAN connection */
static struct ran_conn *ran_conn_allocate_a(const struct a_conn_info *a_conn_info,
								struct gsm_network *network,
								uint16_t lac, struct osmo_sccp_user *scu, int conn_id)
{
	struct ran_conn *conn;

	LOGP(DMSC, LOGL_DEBUG, "Allocating A-Interface RAN conn: lac %i, conn_id %i\n", lac, conn_id);

	conn = ran_conn_alloc(network, OSMO_RAT_GERAN_A, lac);
	if (!conn)
		return NULL;

	conn->a.conn_id = conn_id;
	conn->a.scu = scu;

	/* Also backup the calling address of the BSC, this allows us to
	 * identify later which BSC is responsible for this RAN connection */
	memcpy(&conn->a.bsc_addr, &a_conn_info->bsc->bsc_addr, sizeof(conn->a.bsc_addr));

	LOGPCONN(conn, LOGL_DEBUG, "A-Interface RAN connection successfully allocated!\n");
	return conn;
}

/* Return an existing A RAN connection record for the given
 * connection IDs, or return NULL if not found. */
static struct ran_conn *ran_conn_lookup_a(const struct gsm_network *network, int conn_id)
{
	struct ran_conn *conn;

	OSMO_ASSERT(network);

	DEBUGP(DMSC, "Looking for A subscriber: conn_id %i\n", conn_id);

	/* FIXME: log_subscribers() is defined in iucs.c as static inline, if
	 * maybe this function should be public to reach it from here? */
	/* log_subscribers(network); */

	llist_for_each_entry(conn, &network->ran_conns, entry) {
		if (conn->via_ran == OSMO_RAT_GERAN_A && conn->a.conn_id == conn_id) {
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

	LOGP(DBSSAP, LOGL_NOTICE, "Rx BSSMAP RESET from BSC %s, sending RESET ACK\n",
	     osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));
	osmo_sccp_tx_unitdata_msg(scu, &a_conn_info->bsc->msc_addr, &a_conn_info->bsc->bsc_addr,
				  gsm0808_create_reset_ack());

	/* Make sure all orphand RAN connections will be cleard */
	a_clear_all(scu, &a_conn_info->bsc->bsc_addr);

	if (!a_conn_info->bsc->reset_fsm)
		a_start_reset(a_conn_info->bsc, true);

	/* Treat an incoming RESET like an ACK to any RESET request we may have just sent.
	 * After all, what we wanted is the A interface to be reset, which we now know has happened. */
	a_reset_ack_confirm(a_conn_info->bsc->reset_fsm);
}

/* Endpoint to handle BSSMAP reset acknowlegement */
static void bssmap_rx_reset_ack(const struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info,
				struct msgb *msg)
{

	struct gsm_network *network = a_conn_info->network;
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_ss7_instance_find(network->a.cs7_instance);
	OSMO_ASSERT(ss7);

	if (a_conn_info->bsc->reset_fsm == NULL) {
		LOGP(DBSSAP, LOGL_ERROR, "Received RESET ACK from an unknown BSC %s, ignoring...\n",
		     osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));
		return;
	}

	LOGP(DBSSAP, LOGL_NOTICE, "Received RESET ACK from BSC %s\n",
		osmo_sccp_addr_name(ss7, &a_conn_info->bsc->bsc_addr));

	/* Confirm that we managed to get the reset ack message
	 * towards the connection reset logic */
	a_reset_ack_confirm(a_conn_info->bsc->reset_fsm);
}

/* Handle UNITDATA BSSMAP messages */
static void bssmap_rcvmsg_udt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	/* Note: When in the MSC role, RESET ACK is the only valid message that
	 * can be received via UNITDATA */

	if (msgb_l3len(msg) < 1) {
		LOGP(DBSSAP, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		return;
	}

	LOGP(DBSSAP, LOGL_DEBUG, "Rx BSSMAP UDT %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_RESET:
		bssmap_rx_reset(scu, a_conn_info, msg);
		break;
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		bssmap_rx_reset_ack(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DBSSAP, LOGL_NOTICE, "Unimplemented message format: %s -- message discarded!\n",
		     gsm0808_bssmap_name(msg->l3h[0]));
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

	LOGP(DBSSAP, LOGL_DEBUG, "Rx BSSMAP UDT: %s\n", msgb_hexdump_l2(msg));

	if (msgb_l2len(msg) < sizeof(*bs)) {
		LOGP(DBSSAP, LOGL_ERROR, "Error: Header is too short -- discarding message!\n");
		return;
	}

	bs = (struct bssmap_header *)msgb_l2(msg);
	if (bs->length < msgb_l2len(msg) - sizeof(*bs)) {
		LOGP(DBSSAP, LOGL_ERROR, "Error: Message is too short -- discarding message!\n");
		return;
	}

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_udt(scu, a_conn_info, msg);
		break;
	default:
		LOGP(DBSSAP, LOGL_ERROR,
		     "Error: Unimplemented message type: %s -- message discarded!\n", gsm0808_bssmap_name(bs->type));
	}
}

/*
 * BSSMAP handling for connection oriented data
 */

/* Endpoint to handle BSSMAP clear request */
static int bssmap_rx_clear_rqst(struct ran_conn *conn,
				struct msgb *msg, struct tlv_parsed *tp)
{
	uint8_t cause;

	LOGPCONN(conn, LOGL_INFO, "Rx BSSMAP CLEAR REQUEST\n");

	if (!TLVP_PRESENT(tp, GSM0808_IE_CAUSE)) {
		LOGP(DBSSAP, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		return -EINVAL;
	}
	cause = TLVP_VAL(tp, GSM0808_IE_CAUSE)[0];

	ran_conn_mo_close(conn, cause);

	return 0;
}

/* Endpoint to handle BSSMAP clear complete */
static int bssmap_rx_clear_complete(struct osmo_sccp_user *scu,
				    const struct a_conn_info *a_conn_info,
				    struct ran_conn *conn)
{
	int rc;

	LOGPCONN(conn, LOGL_INFO, "Rx BSSMAP CLEAR COMPLETE, releasing SCCP connection\n");

	if (conn)
		ran_conn_rx_bssmap_clear_complete(conn);

	rc = osmo_sccp_tx_disconn(scu, a_conn_info->conn_id,
				  NULL, SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);

	/* Remove the record from the list with active connections. */
	a_delete_bsc_con(a_conn_info->conn_id);

	return rc;
}

/* Endpoint to handle layer 3 complete messages */
static int bssmap_rx_l3_compl(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info,
			      struct msgb *msg, struct tlv_parsed *tp)
{
	struct gsm0808_cell_id_list2 cil;
	uint16_t lac = 0;
	uint8_t data_length;
	const uint8_t *data;
	struct gsm_network *network = a_conn_info->network;
	struct ran_conn *conn;

	LOGP(DBSSAP, LOGL_INFO, "Rx BSSMAP COMPLETE L3 INFO (conn_id=%i)\n", a_conn_info->conn_id);

	if (!TLVP_PRESENT(tp, GSM0808_IE_CELL_IDENTIFIER)) {
		LOGP(DBSSAP, LOGL_ERROR, "Mandatory CELL IDENTIFIER not present -- discarding message!\n");
		return -EINVAL;
	}
	if (!TLVP_PRESENT(tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DBSSAP, LOGL_ERROR, "Mandatory LAYER 3 INFORMATION not present -- discarding message!\n");
		return -EINVAL;
	}

	/* Parse Cell ID element -- this should yield a cell identifier "list" with 1 element. */

	data_length = TLVP_LEN(tp, GSM0808_IE_CELL_IDENTIFIER);
	data = TLVP_VAL(tp, GSM0808_IE_CELL_IDENTIFIER);
	if (gsm0808_dec_cell_id_list2(&cil, data, data_length) < 0 || cil.id_list_len != 1) {
		LOGP(DBSSAP, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER -- discarding message!\n");
		return -EINVAL;
	}

	/* Determine the LAC which we will use for this subscriber. */
	switch (cil.id_discr) {
	case CELL_IDENT_WHOLE_GLOBAL: {
		const struct osmo_cell_global_id *id = &cil.id_list[0].global;
		if (osmo_plmn_cmp(&id->lai.plmn, &network->plmn) != 0) {
			LOGP(DBSSAP, LOGL_ERROR,
			     "WHOLE GLOBAL CELL IDENTIFIER does not match network MCC/MNC -- discarding message!\n");
			return -EINVAL;
		}
		lac = id->lai.lac;
		break;
	}
	case CELL_IDENT_LAC_AND_CI: {
		const struct osmo_lac_and_ci_id *id = &cil.id_list[0].lac_and_ci;
		lac = id->lac;
		break;
	}
	case CELL_IDENT_LAI_AND_LAC: {
		const struct osmo_location_area_id *id = &cil.id_list[0].lai_and_lac;
		if (osmo_plmn_cmp(&id->plmn, &network->plmn) != 0) {
			LOGP(DBSSAP, LOGL_ERROR,
			     "LAI AND LAC CELL IDENTIFIER does not match network MCC/MNC -- discarding message!\n");
			return -EINVAL;
		}
		lac = id->lac;
		break;
	}
	case CELL_IDENT_LAC:
		lac = cil.id_list[0].lac;
		break;

	case CELL_IDENT_CI:
	case CELL_IDENT_NO_CELL:
	case CELL_IDENT_BSS:
		LOGP(DBSSAP, LOGL_ERROR,
		     "CELL IDENTIFIER does not specify a LAC -- discarding message!\n");
		return -EINVAL;

	default:
		LOGP(DBSSAP, LOGL_ERROR,
		     "Unable to parse element CELL IDENTIFIER (unknown cell identification discriminator 0x%x) "
		     "-- discarding message!\n", cil.id_discr);
		return -EINVAL;
	}

	/* Parse Layer 3 Information element */
	msg->l3h = (uint8_t*)TLVP_VAL(tp, GSM0808_IE_LAYER_3_INFORMATION);
	msgb_l3trim(msg, TLVP_LEN(tp, GSM0808_IE_LAYER_3_INFORMATION));

	if (msgb_l3len(msg) < sizeof(struct gsm48_hdr)) {
		LOGP(DBSSAP, LOGL_ERROR, "COMPL_L3 with too short L3 (%d) -- discarding\n",
		     msgb_l3len(msg));
		return -ENODATA;
	}

	/* Create new subscriber context */
	conn = ran_conn_allocate_a(a_conn_info, network, lac, scu, a_conn_info->conn_id);

	/* Handover location update to the MSC code */
	ran_conn_compl_l3(conn, msg, 0);
	return 0;
}

/* Endpoint to handle BSSMAP classmark update */
static int bssmap_rx_classmark_upd(struct ran_conn *conn, struct msgb *msg,
				   struct tlv_parsed *tp)
{
	const uint8_t *cm2 = NULL;
	const uint8_t *cm3 = NULL;
	uint8_t cm2_len = 0;
	uint8_t cm3_len = 0;

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP CLASSMARK UPDATE\n");

	if (!TLVP_PRESENT(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2)) {
		LOGPCONN(conn, LOGL_ERROR, "Mandatory Classmark Information Type 2 not present -- discarding message!\n");
		return -EINVAL;
	}

	cm2 = TLVP_VAL(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);
	cm2_len = TLVP_LEN(tp, GSM0808_IE_CLASSMARK_INFORMATION_T2);

	if (TLVP_PRESENT(tp, GSM0808_IE_CLASSMARK_INFORMATION_T3)) {
		cm3 = TLVP_VAL(tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
		cm3_len = TLVP_LEN(tp, GSM0808_IE_CLASSMARK_INFORMATION_T3);
	}

	/* Inform MSC about the classmark change */
	ran_conn_classmark_chg(conn, cm2, cm2_len, cm3, cm3_len);

	return 0;
}

/* Endpoint to handle BSSMAP cipher mode complete */
static int bssmap_rx_ciph_compl(struct ran_conn *conn, struct msgb *msg,
				struct tlv_parsed *tp)
{
	/* FIXME: The field GSM0808_IE_LAYER_3_MESSAGE_CONTENTS is optional by
	 * means of the specification. So there can be messages without L3 info.
	 * In this case, the code will crash becrause ran_conn_cipher_mode_compl()
	 * is not able to deal with msg = NULL and apperently
	 * ran_conn_cipher_mode_compl() was never meant to be used without L3 data.
	 * This needs to be discussed further! */

	uint8_t alg_id = 1;
	struct rate_ctr_group *msc = conn->network->msc_ctrs;

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP CIPHER MODE COMPLETE\n");

	if (TLVP_PRESENT(tp, GSM0808_IE_CHOSEN_ENCR_ALG)) {
		alg_id = TLVP_VAL(tp, GSM0808_IE_CHOSEN_ENCR_ALG)[0] - 1;
	}

	if (TLVP_PRESENT(tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS)) {
		msg->l3h = (uint8_t*)TLVP_VAL(tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS);
		msgb_l3trim(msg, TLVP_LEN(tp, GSM0808_IE_LAYER_3_MESSAGE_CONTENTS));
	} else {
		msg = NULL;
	}

	rate_ctr_inc(&msc->ctr[MSC_CTR_BSSMAP_CIPHER_MODE_COMPLETE]);

	/* Hand over cipher mode complete message to the MSC */
	ran_conn_cipher_mode_compl(conn, msg, alg_id);

	return 0;
}

/* Endpoint to handle BSSMAP cipher mode reject, 3GPP TS 08.08 §3.2.1.48 */
static int bssmap_rx_ciph_rej(struct ran_conn *conn,
			      struct msgb *msg, struct tlv_parsed *tp)
{
	int rc;
	enum gsm0808_cause cause;
	struct rate_ctr_group *msc = conn->network->msc_ctrs;

	LOGPCONN(conn, LOGL_NOTICE, "RX BSSMAP CIPHER MODE REJECT\n");

	rc = gsm0808_get_cipher_reject_cause(tp);
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "failed (%s) to extract Cause from Cipher mode reject: %s\n",
			 strerror(-rc), msgb_hexdump(msg));
		return rc;
	}

	rate_ctr_inc(&msc->ctr[MSC_CTR_BSSMAP_CIPHER_MODE_REJECT]);
	cause = (enum gsm0808_cause)rc;
	LOGPCONN(conn, LOGL_NOTICE, "Cipher mode rejection cause: %s\n", gsm0808_cause_name(cause));

	/* FIXME: Can we do something meaningful here? e.g. report to the
	 * msc code somehow that the cipher mode command has failed. */

	return 0;
}

/* Endpoint to handle BSSMAP assignment failure */
static int bssmap_rx_ass_fail(struct ran_conn *conn, struct msgb *msg,
			      struct tlv_parsed *tp)
{
	uint8_t cause;
	uint8_t *rr_cause_ptr = NULL;
	uint8_t rr_cause;

	LOGPCONN(conn, LOGL_NOTICE, "Rx BSSMAP ASSIGNMENT FAILURE message\n");

	if (!TLVP_PRESENT(tp, GSM0808_IE_CAUSE)) {
		LOGPCONN(conn, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		return -EINVAL;
	}
	cause = TLVP_VAL(tp, GSM0808_IE_CAUSE)[0];

	if (TLVP_PRESENT(tp, GSM0808_IE_RR_CAUSE)) {
		rr_cause = TLVP_VAL(tp, GSM0808_IE_RR_CAUSE)[0];
		rr_cause_ptr = &rr_cause;
	}

	/* FIXME: In AoIP, the Assignment failure will carry also an optional
	 * Codec List (BSS Supported) element. It has to be discussed if we
	 * can ignore this element. If not, The ran_conn_assign_fail() function
	 * call has to change. However ran_conn_assign_fail() does nothing in the
	 * end. So probably we can just leave it as it is. Even for AoIP */

	/* Inform the MSC about the assignment failure event */
	ran_conn_assign_fail(conn, cause, rr_cause_ptr);

	return 0;
}

/* Endpoint to handle sapi "n" reject */
static int bssmap_rx_sapi_n_rej(struct ran_conn *conn, struct msgb *msg,
				struct tlv_parsed *tp)
{
	uint8_t dlci;

	LOGPCONN(conn, LOGL_NOTICE, "Rx BSSMAP SAPI-N-REJECT message\n");

	/* Note: The MSC code seems not to care about the cause code, but by
	 * the specification it is mandatory, so we check its presence. See
	 * also 3GPP TS 48.008 3.2.1.34 SAPI "n" REJECT */
	if (!TLVP_PRESENT(tp, GSM0808_IE_CAUSE)) {
		LOGPCONN(conn, LOGL_ERROR, "Cause code is missing -- discarding message!\n");
		return -EINVAL;
	}
	if (!TLVP_PRESENT(tp, GSM0808_IE_DLCI)) {
		LOGPCONN(conn, LOGL_ERROR, "DLCI is missing -- discarding message!\n");
		return -EINVAL;
	}
	dlci = TLVP_VAL(tp, GSM0808_IE_DLCI)[0];

	/* Inform the MSC about the sapi "n" reject event */
	ran_conn_sapi_n_reject(conn, dlci);

	return 0;
}

/* Use the speech codec info we go with the assignment complete to dtermine
 * which codec we will signal to the MGW */
static enum mgcp_codecs mgcp_codec_from_sc(struct gsm0808_speech_codec *sc)
{
	switch (sc->type) {
	case GSM0808_SCT_FR1:
		return CODEC_GSM_8000_1;
		break;
	case GSM0808_SCT_FR2:
		return CODEC_GSMEFR_8000_1;
		break;
	case GSM0808_SCT_FR3:
		return CODEC_AMR_8000_1;
		break;
	case GSM0808_SCT_FR4:
		return CODEC_AMRWB_16000_1;
		break;
	case GSM0808_SCT_FR5:
		return CODEC_AMRWB_16000_1;
		break;
	case GSM0808_SCT_HR1:
		return CODEC_GSMHR_8000_1;
		break;
	case GSM0808_SCT_HR3:
		return CODEC_AMR_8000_1;
		break;
	case GSM0808_SCT_HR4:
		return CODEC_AMRWB_16000_1;
		break;
	case GSM0808_SCT_HR6:
		return CODEC_AMRWB_16000_1;
		break;
	default:
		return CODEC_PCMU_8000_1;
		break;
	}
}

/* Endpoint to handle assignment complete */
static int bssmap_rx_ass_compl(struct ran_conn *conn, struct msgb *msg,
			       struct tlv_parsed *tp)
{
	struct sockaddr_storage rtp_addr;
	struct gsm0808_speech_codec sc;
	struct sockaddr_in *rtp_addr_in;
	int rc;

	LOGPCONN(conn, LOGL_INFO, "Rx BSSMAP ASSIGNMENT COMPLETE message\n");

	if (!TLVP_PRESENT(tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
		LOGPCONN(conn, LOGL_ERROR, "AoIP transport identifier missing -- discarding message!\n");
		return -EINVAL;
	}

	/* Decode AoIP transport address element */
	rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr, TLVP_VAL(tp, GSM0808_IE_AOIP_TRASP_ADDR),
					 TLVP_LEN(tp, GSM0808_IE_AOIP_TRASP_ADDR));
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "Unable to decode aoip transport address.\n");
		return -EINVAL;
	}

	/* Decode speech codec (choosen) element */
	rc = gsm0808_dec_speech_codec(&sc, TLVP_VAL(tp, GSM0808_IE_SPEECH_CODEC),
					 TLVP_LEN(tp, GSM0808_IE_SPEECH_CODEC));
	if (rc < 0) {
		LOGPCONN(conn, LOGL_ERROR, "Unable to decode speech codec (choosen).\n");
		return -EINVAL;
	}
	conn->rtp.codec_ran = mgcp_codec_from_sc(&sc);

	/* use address / port supplied with the AoIP
	 * transport address element */
	if (rtp_addr.ss_family == AF_INET) {
		rtp_addr_in = (struct sockaddr_in *)&rtp_addr;
		msc_mgcp_ass_complete(conn, osmo_ntohs(rtp_addr_in->sin_port), inet_ntoa(rtp_addr_in->sin_addr));
	} else {
		LOGPCONN(conn, LOGL_ERROR, "Unsopported addressing scheme. (supports only IPV4)\n");
		return -EINVAL;
	}

	return 0;
}

/* Handle incoming connection oriented BSSMAP messages */
static int rx_bssmap(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct ran_conn *conn;
	struct tlv_parsed tp;
	int rc;
	uint8_t msg_type;

	if (msgb_l3len(msg) < 1) {
		LOGP(DBSSAP, LOGL_NOTICE, "Error: No data received -- discarding message!\n");
		return -1;
	}
	msg_type = msg->l3h[0];

	rc = osmo_bssap_tlv_parse(&tp, msg->l3h + 1, msgb_l3len(msg) - 1);
	if (rc < 0) {
		LOGP(DBSSAP, LOGL_ERROR, "Failed parsing TLV -- discarding message! %s\n",
			osmo_hexdump(msg->l3h, msgb_l3len(msg)));
		return -EINVAL;
	}

	/* Only message types allowed without a 'conn' */
	switch (msg_type) {
	case BSS_MAP_MSG_COMPLETE_LAYER_3:
		return bssmap_rx_l3_compl(scu, a_conn_info, msg, &tp);
	default:
		break;
	}

	conn = ran_conn_lookup_a(a_conn_info->network, a_conn_info->conn_id);
	if (!conn) {
		LOGP(DBSSAP, LOGL_ERROR, "Couldn't find ran_conn for conn_id=%d\n", a_conn_info->conn_id);
		/* We expect a Clear Complete to come in on a valid conn. But if for some reason we still
		 * have the SCCP connection while the RAN connection data is already gone, at
		 * least close the SCCP conn. */

		if (msg_type == BSS_MAP_MSG_CLEAR_COMPLETE)
			return bssmap_rx_clear_complete(scu, a_conn_info, NULL);

		return -EINVAL;
	}

	LOGPCONN(conn, LOGL_DEBUG, "Rx BSSMAP DT1 %s\n", gsm0808_bssmap_name(msg_type));

	switch (msg_type) {
	case BSS_MAP_MSG_CLEAR_RQST:
		return bssmap_rx_clear_rqst(conn, msg, &tp);
	case BSS_MAP_MSG_CLEAR_COMPLETE:
		return bssmap_rx_clear_complete(scu, a_conn_info, conn);
	case BSS_MAP_MSG_CLASSMARK_UPDATE:
		return bssmap_rx_classmark_upd(conn, msg, &tp);
	case BSS_MAP_MSG_CIPHER_MODE_COMPLETE:
		return bssmap_rx_ciph_compl(conn, msg, &tp);
	case BSS_MAP_MSG_CIPHER_MODE_REJECT:
		return bssmap_rx_ciph_rej(conn, msg, &tp);
	case BSS_MAP_MSG_ASSIGMENT_FAILURE:
		return bssmap_rx_ass_fail(conn, msg, &tp);
	case BSS_MAP_MSG_SAPI_N_REJECT:
		return bssmap_rx_sapi_n_rej(conn, msg, &tp);
	case BSS_MAP_MSG_ASSIGMENT_COMPLETE:
		return bssmap_rx_ass_compl(conn, msg, &tp);
	default:
		LOGPCONN(conn, LOGL_ERROR, "Unimplemented msg type: %s\n", gsm0808_bssmap_name(msg_type));
		return -EINVAL;
	}

	return -EINVAL;
}

/* Endpoint to handle regular BSSAP DTAP messages. No ownership of 'msg' is passed on! */
static int rx_dtap(const struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	struct gsm_network *network = a_conn_info->network;
	struct ran_conn *conn;
	struct dtap_header *dtap = (struct dtap_header *) msg->l2h;

	conn = ran_conn_lookup_a(network, a_conn_info->conn_id);
	if (!conn) {
		return -EINVAL;
	}

	LOGPCONN(conn, LOGL_DEBUG, "Rx DTAP %s\n", msgb_hexdump_l2(msg));

	/* ran_conn_dtap expects the dtap payload in l3h */
	msg->l3h = msg->l2h + 3;
	OMSC_LINKID_CB(msg) = dtap->link_id;

	/* Forward dtap payload into the msc */
	ran_conn_dtap(conn, msg);

	return 0;
}

/* Handle incoming connection oriented messages. No ownership of 'msg' is passed on! */
int a_sccp_rx_dt(struct osmo_sccp_user *scu, const struct a_conn_info *a_conn_info, struct msgb *msg)
{
	OSMO_ASSERT(scu);
	OSMO_ASSERT(a_conn_info);
	OSMO_ASSERT(msg);

	if (msgb_l2len(msg) < sizeof(struct bssmap_header)) {
		LOGP(DBSSAP, LOGL_NOTICE, "The header is too short -- discarding message!\n");
		return -EINVAL;
	}

	switch (msg->l2h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l3h = &msg->l2h[sizeof(struct bssmap_header)];
		return rx_bssmap(scu, a_conn_info, msg);
	case BSSAP_MSG_DTAP:
		return rx_dtap(scu, a_conn_info, msg);
	default:
		LOGP(DBSSAP, LOGL_ERROR, "Unimplemented BSSAP msg type: %s\n", gsm0808_bssap_name(msg->l2h[0]));
		return -EINVAL;
	}

	return -EINVAL;
}
