/* Handle VGCS/VBCS calls. (Voice Group/Broadcast Call Service). */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Andreas Eversberg
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

/* The process consists of four state machines:
 *
 * The call control state machine "GCC" handles the voice group/broadcast call.
 * There is one instance for every call. It is mainly controlled by the calling
 * subscriber. The state machine is described in 3GPP TS 44.068 / 44.069.
 * One SCCP connection to the calling subscriber is associated with the state
 * machine. Once the calling subscriber leaves or is assigned to the VGCS/VBS
 * channel, the association to the MSC-A role is removed and the SCCP connection
 * is closed. The state machine with the transaction still exists until the end
 * of the call.
 *
 * The BSS control state machine "vgcs_bss_fsm" handles the call in each BSC.
 * There are as many instances as there are BSCs where the call is placed to.
 * The instances are linked to the call control in a 1:n relation.
 * One SCCP connection for every BSC is associated with the state machine.
 * It sets up the call in the BSC and handles the uplink control and signaling
 * with the talking phone.
 *
 * The resource controling state machine "vgcs_cell_fsm" handles the channel for
 * each BTS that has a VGCS for the call. The instances are linked to the BSS
 * control in a 1:n relation.
 * One SCCP connection for every cell is associated with each list entry.
 * It assigns the VGCS/VBS channel and the conference bridge in the MGW.
 *
 * The MGW endpoint state machine "vgcs_mgw_ep_fsm" handles the endpoint
 * connection for each call. It controls the clearing of the MGW connections
 * in case of endpoint failure. All instances of the resource controlling state
 * machine are linked to this state machine in a 1:n relation.
 *
 * Setup of a call:
 *
 * When the calling subscriber dials a group/broadcast call, the GCR is checked
 * for an existing Group ID. If it exists, the call is setup towards the a given
 * list of MSCs for this Group ID. Also the channels are assigned for a given
 * list of cells for this Group ID.
 * The call can also be initiated via VTY.
 *
 * Then the calling subscriber is assigned to the VGCS channel of the same cell
 * where the call was initialized. Afterwards the call is connected. The calling
 * subscriber may then stay on the uplink or release it.
 *
 * Uplink control:
 *
 * Any BSC may indicate a talking subscriber. If there is no talking subscriber
 * yet, the uplink is granted, otherwise it is rejected. If the uplink is in
 * use on one BSC, all other BSCs will be blocked. If the uplink becomes free,
 * all other BSCs will be unblocked.
 *
 * Termination of the call:
 *
 * The calling subscriber accesses the uplink. The it sends a termination
 * request. This request is acknowledged by a termination command towards
 * the calling subscriber. The call is cleared.
 * The call can also be terminated via VTY and/or a timeout.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/protocol/gsm_44_068.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/ran_msg_a.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/codec_mapping.h>
#include <osmocom/msc/msc_vgcs.h>
#include <osmocom/msc/asci_gcr.h>

#define S(x)	(1 << (x))

#define LOG_GCC(trans, level, fmt, args...) \
	LOGP((trans) ? ((trans->type == TRANS_GCC) ? DGCC : DBCC) : DASCI, level, \
	     (trans) ? ((trans->type == TRANS_GCC) ? ("GCC callref %s: " fmt) : ("BCC callref %s: " fmt)) : "%s" fmt, \
	     (trans) ? gsm44068_group_id_string(trans->callref) : "", ##args)
#define LOG_BSS(bss, level, fmt, args...) \
	LOGP(DASCI, level, \
	     (bss->trans_type == TRANS_GCC) ? ("GCC callref %s, BSS #%s: " fmt) : ("BCC callref %s, BSS #%s: " fmt), \
	     gsm44068_group_id_string(bss->callref), osmo_ss7_pointcode_print(NULL, bss->pc), ##args)
#define LOG_CELL(cell, level, fmt, args...) \
	LOGP(DASCI, level, \
	     (cell->trans_type == TRANS_GCC) ? ("GCC callref %s, BSS #%s, CID %d: " fmt) \
					     : ("BCC callref %s, BSS #%s, CID %d: " fmt), \
	     gsm44068_group_id_string(cell->callref), osmo_ss7_pointcode_print(NULL, cell->pc), cell->cell_id, ##args)

static struct osmo_fsm vgcs_bcc_fsm;
static struct osmo_fsm vgcs_gcc_fsm;
static struct osmo_fsm vgcs_bss_fsm;
static struct osmo_fsm vgcs_cell_fsm;
static struct osmo_fsm vgcs_mgw_ep_fsm;

static __attribute__((constructor)) void vgcs_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&vgcs_bcc_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&vgcs_gcc_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&vgcs_bss_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&vgcs_cell_fsm) == 0);
	OSMO_ASSERT(osmo_fsm_register(&vgcs_mgw_ep_fsm) == 0);
}

const char *gsm44068_group_id_string(uint32_t callref)
{
	static char string[9];

	snprintf(string, sizeof(string), "%08u", callref);
	string[sizeof(string) - 1] = '\0';

	return string;
}

/* Resolve ran peer from point-code */
static struct ran_peer *ran_peer_for_pc(struct gsm_network *msc_network, int pc)
{
	struct sccp_ran_inst *sri;
	struct osmo_sccp_addr addr = {};
	struct ran_peer *rp;

	sri = msc_network->a.sri;
	if (!osmo_sccp_get_ss7(sri->sccp)) {
		LOGP(DASCI, LOGL_ERROR, "No SS7???\n");
		return NULL;
	}
	osmo_sccp_make_addr_pc_ssn(&addr, pc, sri->ran->ssn);
	rp = ran_peer_find_by_addr(sri, &addr);

	return rp;
}

/* Encode message and send towards BSC. */
int ran_encode_and_send(struct osmo_fsm_inst *fi, struct ran_msg *ran_msg, struct ran_conn *conn, bool initial)
{
	struct msgb *l3_msg;
	int rc;

	l3_msg = ran_a_encode(fi, ran_msg);
	if (!l3_msg) {
		LOGP(DASCI, LOGL_ERROR, "ran_a_encode() failed.\n");
		return -EINVAL;
	}
	rc = ran_conn_down_l2_co(conn, l3_msg, initial);
	msgb_free(l3_msg);

	return rc;
}

/* Transmit DTAP message to talker
 * This is used for sending group/broadcast call control messages. */
int tx_dtap_to_talker(struct vgcs_bss *bss, struct msgb *l3_msg)
{
	struct ran_msg ran_msg;
	struct gsm48_hdr *gh = msgb_l3(l3_msg) ? : l3_msg->data;
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	int rc;


	LOG_BSS(bss, LOGL_DEBUG, "Sending DTAP: %s %s\n",
		gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));

	ran_msg = (struct ran_msg){
		.msg_type = RAN_MSG_DTAP,
		.dtap = l3_msg,
	};

	rc = ran_encode_and_send(bss->fi, &ran_msg, bss->conn, false);

	return rc;
}

/*
 * GCC/BCC Message transcoding
 */

static void _add_cause_ie(struct msgb *msg, uint8_t cause, uint8_t *diag, uint8_t diag_len)
{
	uint8_t *ie = msgb_put(msg, 2 + diag_len);

	ie[0] = 1 + diag_len;
	ie[1] = cause;
	if (diag && diag_len) {
		ie[1] |= 0x80;
		memcpy(ie + 2, diag, diag_len);
	}
}

static void _add_callref_ie(struct msgb *msg, uint32_t callref, bool with_prio, uint8_t prio)
{
	uint32_t ie;

	ie = callref << 5;
	if (with_prio)
		ie |= 0x10 | (prio << 1);
	msgb_put_u32(msg, ie);
}

static int _msg_too_short(void)
{
	LOGP(DASCI, LOGL_ERROR, "MSG too short.\n");
	return -EINVAL;
}

static int _ie_invalid(void)
{
	LOGP(DASCI, LOGL_ERROR, "IE invalid.\n");
	return -EINVAL;
}

static int _rx_callref(uint8_t *ie, unsigned int remaining_len, uint32_t *callref, bool *with_prio, uint8_t *prio)
{
	uint8_t ie_len;

	ie_len = sizeof(uint32_t);
	if (remaining_len < ie_len)
		return _msg_too_short();
	*callref = osmo_load32be(ie) >> 5;
	if (ie[3] & 0x10) {
		*with_prio = true;
		*prio = (ie[3] >> 1) & 0x7;
	} else
		*with_prio = false;

	return ie_len;
}

/* 3GPP TS 44.068 Clause 8.1 */
static int gsm44068_tx_connect(struct gsm_trans *trans, uint8_t pdisc, uint32_t callref, bool with_prio, uint8_t prio,
			       uint8_t oi, uint8_t talker_prio, bool with_sms, uint8_t sms_dc, uint8_t sms_gp)
{
	struct msgb *msg = gsm44068_msgb_alloc_name("GSM 44.068 TX CONNECT");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t ie;

	gh->proto_discr = pdisc;
	gh->msg_type = OSMO_GSM44068_MSGT_CONNECT;
	_add_callref_ie(msg, callref, with_prio, prio);
	ie = (talker_prio << 4) | oi;
	msgb_put_u8(msg, ie);
	if (with_sms) {
		ie = OSMO_GSM44068_IEI_SMS_INDICATIONS | (sms_dc << 1) | sms_gp;
		msgb_put_u8(msg, ie);
	}

	/* Send to calling subscriber, depending on the link he is. */
	if (trans->msc_a)
		return msc_a_tx_dtap_to_i(trans->msc_a, msg);
	if (trans->gcc.uplink_bss)
		return tx_dtap_to_talker(trans->gcc.uplink_bss, msg);
	msgb_free(msg);
	return -EIO;
}

/* The Get Status procedure is not used by the current implementation.
 * It is commented out, so it can be used in the future.
 * The idea is to have a complete set of GCC/BCC message transcoding.
 */
#if 0
/* 3GPP TS 44.068 Clause 8.2 */
static int gsm44068_tx_get_status(struct gsm_trans *trans, uint8_t pdisc, struct osmo_mobile_identity *mi)
{
	struct msgb *msg = gsm44068_msgb_alloc_name("GSM 44.068 TX GET STATUS");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = OSMO_GSM44068_MSGT_GET_STATUS;
	if (mi) {
		uint8_t *l;
		int rc;

		l = msgb_tl_put(msg, OSMO_GSM44068_IEI_MOBILE_IDENTITY);
		rc = osmo_mobile_identity_encode_msgb(msg, mi, false);
		if (rc < 0) {
			msgb_free(msg);
			return -EINVAL;
		}
		*l = rc;
	}

	/* Send to calling subscriber, depending on the link he is. */
	if (trans->msc_a)
		return msc_a_tx_dtap_to_i(trans->msc_a, msg);
	if (trans->gcc.uplink_bss)
		return tx_dtap_to_talker(trans->gcc.uplink_bss, msg);
	msgb_free(msg);
	return -EIO;
}
#endif

/* 3GPP TS 44.068 Clause 8.3 and 8.3a */
static int gsm44068_rx_immediate_setup(struct msgb *msg, uint8_t *talker_prio, uint8_t *key_seq,
				       struct gsm48_classmark2 *cm2, struct osmo_mobile_identity *mi,
				       uint32_t *callref, bool *with_prio, uint8_t *prio, char *user_user)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int remaining_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t *ie = gh->data;
	uint8_t ie_len;
	uint64_t otdi;
	int i;
	int rc;

	/* Talker priority / Cyphering key sequence */
	if (remaining_len < 1)
		return _msg_too_short();
	*talker_prio = ie[0] & 0x07;
	*key_seq = (ie[0] >> 4) & 0x07;
	remaining_len -= 1;
	ie += 1;

	/* Mobile station classmark 2 */
	if (remaining_len < 4)
		return _msg_too_short();
	ie_len = ie[0];
	if (remaining_len < ie_len + 1)
		return _msg_too_short();
	if (ie_len != 3)
		return _ie_invalid();
	memcpy(cm2, ie + 1, ie_len);
	remaining_len -= ie_len + 1;
	ie += ie_len + 1;

	/* Mobile indentity */
	if (gh->msg_type == OSMO_GSM44068_MSGT_IMMEDIATE_SETUP) {
		/* IMMEDIATE SETUP uses IMSI/TMSI */
		if (remaining_len < 2)
			return _msg_too_short();
		ie_len = ie[0];
		if (remaining_len < ie_len + 1)
			return _msg_too_short();
		rc = osmo_mobile_identity_decode(mi, ie + 1, ie_len, false);
		if (rc) {
			LOGP(DMM, LOGL_ERROR, "Failure to decode Mobile Identity in GCC/BCC IMMEDDIATE SETUP"
					      " (rc=%d)\n", rc);
			return -EINVAL;
		}
		remaining_len -= ie_len + 1;
		ie += ie_len + 1;
	} else {
		/* IMMEDIATE SETUP 2 uses TMSI only */
		if (remaining_len < 4)
			return _msg_too_short();
		mi->type = GSM_MI_TYPE_TMSI;
		mi->tmsi = osmo_load32be(ie);
		remaining_len -= 4;
		ie += 4;
	}

	/* Call reference */
	rc = _rx_callref(ie, remaining_len, callref, with_prio, prio);
	if (rc < 0)
		return rc;
	remaining_len -= rc;
	ie += rc;

	/* OTID */
	if (gh->msg_type == OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2 && user_user) {
		ie_len = 5;
		if (remaining_len < ie_len)
			return _msg_too_short();
		otdi = osmo_load32be(ie + 1) | ((uint64_t)ie[0] << 32);

		for (i = 0; i < 12; i++) {
			user_user[i] = (otdi % 10) + '0';
			otdi /= 10;
		}
		user_user[i] = '\0';
		remaining_len -= ie_len;
		ie += ie_len;
	} else if (user_user)
		user_user[0] = '\0';

	return 0;
}

/* 3GPP TS 44.068 Clause 8.4 */
static int gsm44068_tx_set_parameter(struct gsm_trans *trans, uint8_t pdisc, uint8_t da, uint8_t ua, uint8_t comm,
				     uint8_t oi)
{
	struct msgb *msg = gsm44068_msgb_alloc_name("GSM 44.068 TX SET PARAMETER");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t ie;

	gh->proto_discr = pdisc;
	gh->msg_type = OSMO_GSM44068_MSGT_SET_PARAMETER;
	ie = (da << 3) | (ua << 2) | (comm << 1) | oi;
	msgb_put_u8(msg, ie);

	/* Send to calling subscriber, depending on the link he is. */
	if (trans->msc_a)
		return msc_a_tx_dtap_to_i(trans->msc_a, msg);
	if (trans->gcc.uplink_bss)
		return tx_dtap_to_talker(trans->gcc.uplink_bss, msg);
	msgb_free(msg);
	return -EIO;
}

/* 3GPP TS 44.068 Clause 8.5 */
static int gsm44068_rx_setup(struct msgb *msg, bool *with_talker_prio, uint8_t *talker_prio,
			     uint32_t *callref, bool *with_prio, uint8_t *prio, char *user_user)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int remaining_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t *ie = gh->data;
	struct tlv_parsed tp;
	struct tlv_p_entry *tlv;
	int rc;

	/* Call reference */
	rc = _rx_callref(ie, remaining_len, callref, with_prio, prio);
	if (rc < 0)
		return rc;
	remaining_len -= rc;
	ie += rc;

	rc = tlv_parse(&tp, &osmo_gsm44068_att_tlvdef, ie, remaining_len, 0, 0);
	if (rc < 0)
		return _ie_invalid();

	/* User-user */
	tlv = TLVP_GET(&tp, OSMO_GSM44068_IEI_USER_USER);
	if (tlv && tlv->len && tlv->len <= 1 + 12 && user_user) {
		memcpy(user_user, tlv->val, tlv->len - 1);
		user_user[tlv->len - 1] = '\0';
	}

	/* Talker priority */
	tlv = TLVP_GET(&tp, OSMO_GSM44068_IEI_TALKER_PRIORITY);
	if (tlv && tlv->len) {
		*with_talker_prio = true;
		*talker_prio = tlv->val[0] & 0x07;
	} else
		*with_talker_prio = false;

	return 0;
}

/* 3GPP TS 44.068 Clause 8.6 */
static int gsm44068_rx_status(struct msgb *msg, uint8_t *cause, uint8_t *diag, uint8_t *diag_len,
			      bool *with_call_state, enum osmo_gsm44068_call_state *call_state,
			      bool *with_state_attrs, uint8_t *da, uint8_t *ua, uint8_t *comm, uint8_t *oi)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int remaining_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t *ie = gh->data;
	uint8_t ie_len;
	struct tlv_parsed tp;
	struct tlv_p_entry *tlv;
	int rc;

	/* Cause */
	if (remaining_len < 2 || ie[0] < remaining_len - 2)
		return _msg_too_short();
	ie_len = ie[0];
	if (remaining_len < ie_len + 1)
		return _msg_too_short();
	if (ie_len < 1)
		return _ie_invalid();
	*cause = ie[1] & 0x7f;
	*diag_len = ie_len - 1;
	if (*diag_len)
		memcpy(diag, ie + 2, ie_len - 1);
	remaining_len -= ie_len + 1;
	ie += ie_len + 1;

	rc = tlv_parse(&tp, &osmo_gsm44068_att_tlvdef, ie, remaining_len, 0, 0);
	if (rc < 0)
		return _ie_invalid();

	/* Call state */
	tlv = TLVP_GET(&tp, OSMO_GSM44068_IEI_CALL_STATE);
	if (tlv) {
		*with_call_state = true;
		*call_state = tlv->val[0] & 0x7;
	} else
		*with_call_state = false;

	/* State attributes */
	tlv = TLVP_GET(&tp, OSMO_GSM44068_IEI_STATE_ATTRIBUTES);
	if (tlv) {
		*with_state_attrs = true;
		*da = (tlv->val[0] >> 3) & 0x1;
		*ua = (tlv->val[0] >> 2) & 0x1;
		*comm = (tlv->val[0] >> 1) & 0x1;
		*oi = tlv->val[0] & 0x1;
	} else
		*with_state_attrs = false;

	return 0;
}

/* 3GPP TS 44.068 Clause 8.7 and 8.8 */
static int gsm44068_tx_termination(struct msc_a *msc_a, struct vgcs_bss *bss, uint8_t pdisc, uint8_t msg_type,
				   uint8_t cause, uint8_t *diag, uint8_t diag_len)
{
	struct msgb *msg = gsm44068_msgb_alloc_name("GSM 44.068 TX TERMINATION");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;
	_add_cause_ie(msg, cause, diag, diag_len);

	/* Send to calling subscriber, depending on the link he is. */
	if (msc_a)
		return msc_a_tx_dtap_to_i(msc_a, msg);
	if (bss)
		return tx_dtap_to_talker(bss, msg);
	msgb_free(msg);
	return -EIO;
}

/* 3GPP TS 44.068 Clause 8.9 */
static int gsm44068_rx_termination_req(struct msgb *msg, uint32_t *callref, bool *with_prio, uint8_t *prio,
				       bool *with_talker_prio, uint8_t *talker_prio)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int remaining_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t *ie = gh->data;
	struct tlv_parsed tp;
	struct tlv_p_entry *tlv;
	int rc;

	/* Call reference */
	rc = _rx_callref(ie, remaining_len, callref, with_prio, prio);
	if (rc < 0)
		return rc;
	remaining_len -= rc;
	ie += rc;

	rc = tlv_parse(&tp, &osmo_gsm44068_att_tlvdef, ie, remaining_len, 0, 0);
	if (rc < 0)
		return _ie_invalid();

	/* Talker priority */
	tlv = TLVP_GET(&tp, OSMO_GSM44068_IEI_TALKER_PRIORITY);
	if (tlv && tlv->len) {
		*with_talker_prio = true;
		*talker_prio = tlv->val[0] & 0x07;
	} else
		*with_talker_prio = false;

	return 0;
}

/*
 * GCC/BCC state machine - handles calling subscriber process
 */

static const struct value_string vgcs_gcc_fsm_event_names[] = {
	OSMO_VALUE_STRING(VGCS_GCC_EV_NET_SETUP),
	OSMO_VALUE_STRING(VGCS_GCC_EV_NET_TERM),
	OSMO_VALUE_STRING(VGCS_GCC_EV_USER_SETUP),
	OSMO_VALUE_STRING(VGCS_GCC_EV_USER_TERM),
	OSMO_VALUE_STRING(VGCS_GCC_EV_BSS_ESTABLISHED),
	OSMO_VALUE_STRING(VGCS_GCC_EV_BSS_ASSIGN_CPL),
	OSMO_VALUE_STRING(VGCS_GCC_EV_BSS_ASSIGN_FAIL),
	OSMO_VALUE_STRING(VGCS_GCC_EV_BSS_RELEASED),
	OSMO_VALUE_STRING(VGCS_GCC_EV_TIMEOUT),
	{ }
};

static int gcc_establish_bss(struct gsm_trans *trans)
{
	struct gsm_network *net = trans->net;
	struct vgcs_mgw_ep *mgw = NULL;
	struct mgcp_client *mgcp_client;
	struct gcr *gcr;
	struct gcr_bss *b;
	struct gcr_cell *c;
	struct vgcs_bss *bss;
	struct vgcs_bss_cell *cell;
	struct osmo_fsm_inst *fi;
	struct ran_peer *rp;

	/* Failure should not happen, because it has been checked before. */
	gcr = gcr_by_callref(trans->net, trans->type, trans->callref);
	if (!gcr)
		return -EINVAL;

	/* Allocate MGW endpoint. */
	mgcp_client = mgcp_client_pool_get(trans->net->mgw.mgw_pool);
	if (!mgcp_client) {
		LOG_GCC(trans, LOGL_ERROR, "No MGW client, please check config.\n");
		goto err_mgw;
	}
	fi = osmo_fsm_inst_alloc(&vgcs_mgw_ep_fsm, net, NULL, LOGL_DEBUG, NULL);
	if (!fi) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for VGCS MSG state machine.\n");
		goto err_mgw;
	}
	osmo_fsm_inst_update_id(fi, "vgcs-mgw-ep");
	osmo_fsm_inst_state_chg(fi, VGCS_MGW_EP_ST_ACTIVE, 0, 0);
	mgw = talloc_zero(fi, struct vgcs_mgw_ep);
	if (!mgw) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for MGW ep structure.\n");
		osmo_fsm_inst_free(fi);
		goto err_mgw;
	}
	mgw->fi = fi;
	fi->priv = mgw;
	INIT_LLIST_HEAD(&mgw->cell_list);
	mgw->mgw_ep = osmo_mgcpc_ep_alloc(mgw->fi, VGCS_MGW_EP_EV_FREE,
					  mgcp_client, trans->net->mgw.tdefs, mgw->fi->id,
					  "%s", mgcp_client_rtpbridge_wildcard(mgcp_client));
	if (!mgw->mgw_ep) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for MGW endpoint state machine.\n");
		goto err_mgw;
	}

	/* Create BSS list structures. */
	LOG_GCC(trans, LOGL_DEBUG, "Creating BSS list structure with cell list structures.\n");
	llist_for_each_entry(b, &gcr->bss_list, list) {
		LOG_GCC(trans, LOGL_DEBUG, " -> BSS with PC %s.\n", osmo_ss7_pointcode_print(NULL, b->pc));
		/* Resolve ran_peer. */
		rp = ran_peer_for_pc(trans->net, b->pc);
		if (!rp) {
			LOG_GCC(trans, LOGL_ERROR, "Failed to resolve point code %s, skipping BSS!\n",
				      osmo_ss7_pointcode_print(NULL, b->pc));
			continue;
		}
		/* Create state machine. */
		fi = osmo_fsm_inst_alloc(&vgcs_bss_fsm, net, NULL, LOGL_DEBUG, NULL);
		if (!fi) {
			LOG_GCC(trans, LOGL_ERROR, "No memory for state machine.\n");
			break;
		}
		/* Create call structure. */
		bss = talloc_zero(fi, struct vgcs_bss);
		if (!bss) {
			LOG_GCC(trans, LOGL_ERROR, "No memory for BSS call structure.\n");
			osmo_fsm_inst_free(fi);
			break;
		}
		bss->fi = fi;
		fi->priv = bss;
		INIT_LLIST_HEAD(&bss->cell_list);
		bss->trans = trans;
		bss->trans_type = trans->type;
		bss->callref = trans->callref;
		bss->pc = b->pc;
		/* Create ran connection. */
		bss->conn = ran_conn_create_outgoing(rp);
		if (!bss->conn) {
			LOG_GCC(trans, LOGL_ERROR, "Failed to create RAN connection.\n");
			osmo_fsm_inst_free(bss->fi);
			continue;
		}
		bss->conn->vgcs.bss = bss;
		/* Create cell list structures. */
		llist_for_each_entry(c, &b->cell_list, list) {
			LOG_GCC(trans, LOGL_DEBUG, " -> Cell ID %d.\n", c->cell_id);
			/* Create state machine. */
			fi = osmo_fsm_inst_alloc(&vgcs_cell_fsm, net, NULL, LOGL_DEBUG, NULL);
			if (!fi) {
				LOG_GCC(trans, LOGL_ERROR, "No memory for state machine.\n");
				break;
			}
			/* Create cell structure. */
			cell = talloc_zero(fi, struct vgcs_bss_cell);
			if (!cell) {
				LOG_GCC(trans, LOGL_ERROR, "No memory for BSS cell structure.\n");
				osmo_fsm_inst_free(fi);
				break;
			}
			cell->fi = fi;
			fi->priv = cell;
			osmo_fsm_inst_update_id_f(cell->fi, "vgcs-cell-%d", c->cell_id);
			cell->trans_type = trans->type;
			cell->callref = trans->callref;
			cell->pc = b->pc;
			cell->cell_id = c->cell_id;
			cell->call_id = trans->call_id;
			/* Create ran connection. */
			cell->conn = ran_conn_create_outgoing(rp);
			if (!cell->conn) {
				LOG_GCC(trans, LOGL_ERROR, "Failed to create RAN connection.\n");
				osmo_fsm_inst_free(cell->fi);
				continue;
			}
			cell->conn->vgcs.cell = cell;
			/* Attach to cell list of BSS and MGW endpoint */
			llist_add_tail(&cell->list_bss, &bss->cell_list);
			cell->bss = bss;
			llist_add_tail(&cell->list_mgw, &mgw->cell_list);
			cell->mgw = mgw;
		}
		/* No cell? */
		if (llist_empty(&bss->cell_list)) {
			LOG_GCC(trans, LOGL_DEBUG, " -> No Cell in this BSS.\n");
			osmo_fsm_inst_free(bss->fi);
			break;
		}
		/* Attach to transaction list */
		llist_add_tail(&bss->list, &trans->gcc.bss_list);
		/* Trigger VGCS/VBS SETUP */
		osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_SETUP, NULL);
	}
	/* No BSS? */
	if (llist_empty(&trans->gcc.bss_list)) {
		/* Also destroy MGW, because this list is empty too! */
		LOG_GCC(trans, LOGL_NOTICE, "No BSS found, please check your VTY configuration and add cells.\n");
		goto err_mgw;
	}
	return 0;

err_mgw:
	if (mgw) {
		if (mgw->mgw_ep) {
			/* This will also free FSM instance and vgcs_mgw_ep structure. */
			osmo_fsm_inst_dispatch(mgw->fi, VGCS_MGW_EP_EV_CLEAR, NULL);
			return -EINVAL;
		}
		osmo_fsm_inst_free(mgw->fi);
	}
	return -EINVAL;
}

/* Send Assignment Request to the calling subscriber.
 * This is used to assign the subscriber from early assigned channel to the VGCS/VBS channel. */
static int gcc_assign(struct gsm_trans *trans)
{
	struct ran_msg tx_ran_msg;
	struct gsm0808_channel_type channel_type;
	struct vgcs_bss *bss = NULL, *b;

	/* No assignment, because the calling subscriber is already assigned or there is no calling subscriber. */
	if (!trans->msc_a)
		return 0;

	/* Check calling subscriber's MSC */
	struct ran_conn *conn = msub_ran_conn(trans->msc_a->c.msub);
	if (!conn) {
		LOG_GCC(trans, LOGL_ERROR, "Calling subscriber has no ran_conn????\n");
		return -EINVAL;
	}
	llist_for_each_entry(b, &trans->gcc.bss_list, list) {
		if (osmo_sccp_addr_ri_cmp(&conn->ran_peer->peer_addr, &b->conn->ran_peer->peer_addr))
			continue;
		bss = b;
		break;
	}
	if (!bss) {
		LOG_GCC(trans, LOGL_ERROR, "Calling subscriber comes from BSC that has no VGCS call.\n");
		return -EINVAL;
	}

	/* For now we support GSM/FR V1 only. This shall be supported by all MS. */
	channel_type = (struct gsm0808_channel_type) {
		.ch_indctr = GSM0808_CHAN_SPEECH,
		.ch_rate_type = GSM0808_SPEECH_FULL_BM,
		.perm_spch_len = 1,
		.perm_spch[0] = GSM0808_PERM_FR1,
	};

	/* Send assignment to VGCS channel */
	tx_ran_msg = (struct ran_msg) {
		.msg_type = RAN_MSG_ASSIGNMENT_COMMAND,
		.assignment_command = {
			.channel_type = &channel_type,
			.callref_present = true,
			.callref = {
				.sf = (trans->type == TRANS_GCC),
			},
		},
	};
	osmo_store32be_ext(trans->callref >> 3, &tx_ran_msg.assignment_command.callref.call_ref_hi, 3);
	tx_ran_msg.assignment_command.callref.call_ref_lo = trans->callref & 0x7;
	if (msc_a_ran_down(trans->msc_a, MSC_ROLE_I, &tx_ran_msg)) {
		LOG_GCC(trans, LOGL_ERROR, "Cannot send Assignment\n");
		return -EIO;
	}

	/* Assign Talker to BSS of the calling subscriber. */
	trans->gcc.uplink_bss = bss;

	return 0;
}

/* Send CONNECT to the calling subscriber. */
static void gcc_connect(struct gsm_trans *trans)
{
	uint8_t pdisc = (trans->type == TRANS_GCC) ? GSM48_PDISC_GROUP_CC : GSM48_PDISC_BCAST_CC;
	int rc;

	/* Send CONNECT towards MS. */
	rc = gsm44068_tx_connect(trans,
				 pdisc | (trans->transaction_id << 4),
				 trans->callref, 0, 0, 1, 0, 0, 0, 0);
	if (rc < 0)
		LOG_GCC(trans, LOGL_ERROR, "Failed to send CONNECT towards MS. Continue anyway.\n");
}

/* Release dedicated (SDCCH) channel of calling subscriber after assigning to VGCS */
static void release_msc_a(struct gsm_trans *trans)
{
	struct msc_a *msc_a = trans->msc_a;

	if (!msc_a)
		return;

	trans->msc_a = NULL;
	switch (trans->type) {
	case TRANS_GCC:
		msc_a_put(msc_a, MSC_A_USE_GCC);
		break;
	case TRANS_BCC:
		msc_a_put(msc_a, MSC_A_USE_BCC);
		break;
	default:
		break;
	}
}

/* Send TERMINATE to the calling/talking subscriber, then destroy transaction. */
static void gcc_terminate_and_destroy(struct gsm_trans *trans, enum osmo_gsm44068_cause cause)
{
	uint8_t pdisc = (trans->type == TRANS_GCC) ? GSM48_PDISC_GROUP_CC : GSM48_PDISC_BCAST_CC;
	int rc;

	/* Send TERMINATION towards MS. */
	rc = gsm44068_tx_termination(trans->msc_a, trans->gcc.uplink_bss,
				     pdisc | (trans->transaction_id << 4),
				     OSMO_GSM44068_MSGT_TERMINATION,
				     cause,  NULL, 0);
	if (rc < 0)
		LOG_GCC(trans, LOGL_ERROR, "Failed to send TERMINATION towards MS. Continue anyway.\n");

	/* Destroy transaction, note that also _gsm44068_gcc_trans_free() will be called by trans_free().
	 * There the complete state machine is destroyed. */
	trans->callref = 0;
	trans_free(trans);
}

/* Start inactivity timer.
 * This timer is used to terminate the call, if the radio connection to the caller gets lost. */
static void start_inactivity_timer(struct gsm_trans *trans)
{
	if (trans->gcc.inactivity_to) {
		LOG_GCC(trans, LOGL_DEBUG, "Set inactivity timer to %d seconds.\n", trans->gcc.inactivity_to);
		osmo_timer_schedule(&trans->gcc.timer_inactivity, trans->gcc.inactivity_to, 0);
	}
}

static void stop_inactivity_timer(struct gsm_trans *trans)
{
	if (osmo_timer_pending(&trans->gcc.timer_inactivity)) {
		LOG_GCC(trans, LOGL_DEBUG, "Stop pending inactivity timer.\n");
		osmo_timer_del(&trans->gcc.timer_inactivity);
	}
}

static void inactivity_timer_cb(void *data)
{
	struct gsm_trans *trans = data;

	osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_TIMEOUT, NULL);
}

/* Set the parameters of the talker. (downlink mute/unmute, uplink unmute, COMM=T, originator) */
static int set_parameter(struct gsm_trans *trans)
{
	uint8_t pdisc = (trans->type == TRANS_GCC) ? GSM48_PDISC_GROUP_CC : GSM48_PDISC_BCAST_CC;
	int rc;

	rc = gsm44068_tx_set_parameter(trans, pdisc | (trans->transaction_id << 4),
				       !trans->gcc.mute_talker, 1, 1, trans->gcc.uplink_originator);
	if (rc < 0)
		LOG_GCC(trans, LOGL_ERROR, "Failed to send SET PARAMETER towards MS.\n");
	return rc;
}

/* Check in which cell the uplink is used and set "uplink_cell". */
static int set_uplink_cell(struct vgcs_bss *bss, struct gsm0808_cell_id *cell_id_ie, uint16_t cell_id)
{
	struct vgcs_bss_cell *cell;

	if (cell_id_ie) {
		/* Get cell ID to determine talker channel. */
		switch (cell_id_ie->id_discr) {
		case CELL_IDENT_CI:
			cell_id = cell_id_ie->id.ci;
			break;
		case CELL_IDENT_LAC_AND_CI:
			cell_id = cell_id_ie->id.lac_and_ci.ci;
			break;
		default:
			LOG_BSS(bss, LOGL_DEBUG, "Cannot idenitfy cell, please fix!\n");
			return -EINVAL;
		}
	}

	/* Search for cell ID. */
	bss->trans->gcc.uplink_cell = NULL;
	llist_for_each_entry(cell, &bss->cell_list, list_bss) {
		if (cell->cell_id == cell_id) {
			LOG_BSS(bss, LOGL_DEBUG, "Talker is talking on cell %d.\n", cell->cell_id);
			bss->trans->gcc.uplink_cell = cell;
			return 0;
		}
	}

	LOG_BSS(bss, LOGL_DEBUG, "Cell ID %d is not in list of current BSS, please fix!\n", cell_id);
	return -EINVAL;
}

/* Set the MGW conference mode.
 * All cells are listening to the conference. If there is a talker, this cell is also transmitting to the conference. */
static int set_mgw_conference(struct gsm_trans *trans)
{
	struct vgcs_bss *bss;
	struct vgcs_bss_cell *cell;
	struct rtp_stream *rtps;
	int rc;

	/* All cells without talker are listening */
	llist_for_each_entry(bss, &trans->gcc.bss_list, list) {
		llist_for_each_entry(cell, &bss->cell_list, list_bss) {
			if (!(rtps = cell->rtps))
				continue;
			if (rtps->crcx_conn_mode != MGCP_CONN_SEND_ONLY) {
				LOG_CELL(cell, LOGL_DEBUG, "Setting cell %d into listening mode.\n", cell->cell_id);
				rtp_stream_set_mode(rtps, MGCP_CONN_SEND_ONLY);
				rc = rtp_stream_commit(rtps);
				if (rc < 0)
					LOG_CELL(cell, LOGL_ERROR, "Failed to commit parameters to RTP stream "
						 "for cell %d.\n", cell->cell_id);
			}
		}
	}

	if (trans->gcc.uplink_cell && trans->gcc.uplink_cell->rtps) {
		cell = trans->gcc.uplink_cell;
		rtps = cell->rtps;
		LOG_CELL(cell, LOGL_DEBUG, "Setting cell %d into listening mode.\n", cell->cell_id);
		rtp_stream_set_mode(rtps, MGCP_CONN_CONFECHO);
		rc = rtp_stream_commit(rtps);
		if (rc < 0)
			LOG_CELL(cell, LOGL_ERROR, "Failed to commit parameters to RTP stream "
				 "for cell %d.\n", cell->cell_id);
	}

	return 0;
}

static void _assign_complete(struct gsm_trans *trans, bool send_connect)
{
	uint16_t cell_id;

	OSMO_ASSERT(trans->msc_a);

	/* Change state. */
	osmo_fsm_inst_state_chg(trans->gcc.fi, VGCS_GCC_ST_N2_CALL_ACTIVE, 0, 0);
	/* Get cell ID. */
	cell_id = trans->msc_a->via_cell.cell_identity;
	/* Releasing dedicated channel. */
	release_msc_a(trans);
	/* Send CONNECT to the calling subscriber. */
	if (send_connect)
		gcc_connect(trans);
	/* Set parameter. */
	set_parameter(trans);
	/* Start inactivity timer, if uplink is free. */
	if (!trans->gcc.uplink_busy)
		start_inactivity_timer(trans);
	/* Set cell of current talker. */
	set_uplink_cell(trans->gcc.uplink_bss, NULL, cell_id);
	/* Set MGW conference. */
	set_mgw_conference(trans);
}

#define CONNECT_OPTION false

static void vgcs_gcc_fsm_n0_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_trans *trans = fi->priv;
	int rc;

	switch (event) {
	case VGCS_GCC_EV_NET_SETUP:
		/* Establish call towards all BSSs. */
		LOG_GCC(trans, LOGL_DEBUG, "Setup by network, trying to establish cells.\n");
		rc = gcc_establish_bss(trans);
		if (rc < 0) {
			LOG_GCC(trans, LOGL_NOTICE, "Failed to setup call to any cell.\n");
			gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
			break;
		}
		/* Keep state until established or released. */
		break;
	case VGCS_GCC_EV_NET_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by network, destroying call.\n");
		/* Destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_USER_SETUP:
		LOG_GCC(trans, LOGL_DEBUG, "Setup by MS, trying to establish cells.\n");
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_GCC_ST_N1_CALL_INITIATED, 0, 0);
		/* Establish call towards all BSSs. */
		rc = gcc_establish_bss(trans);
		if (rc < 0) {
			LOG_GCC(trans, LOGL_NOTICE, "Failed to setup call to any cell.\n");
			gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
			break;
		}
		if (CONNECT_OPTION) {
			/* Send CONNECT to the calling subscriber. */
			gcc_connect(trans);
			/* Change state. */
			osmo_fsm_inst_state_chg(fi, VGCS_GCC_ST_N3_CALL_EST_PROC, 0, 0);
		}
		break;
	case VGCS_GCC_EV_BSS_ESTABLISHED:
		LOG_GCC(trans, LOGL_DEBUG, "All cells establised, for a group call, sending CONNECT to caller.\n");
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_GCC_ST_N2_CALL_ACTIVE, 0, 0);
		/* Start inactivity timer, if uplink is free. */
		if (!trans->gcc.uplink_busy)
			start_inactivity_timer(trans);
		break;
	case VGCS_GCC_EV_BSS_RELEASED:
		LOG_GCC(trans, LOGL_DEBUG, "All group call in all cells failed, destroying call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_gcc_fsm_n1_call_initiated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_trans *trans = fi->priv;
	int rc;

	switch (event) {
	case VGCS_GCC_EV_NET_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by network, destroying call.\n");
		/* Destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_USER_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by user, destroying call.\n");
		/* Send TERMINATE to the calling subscriber and destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_BSS_ESTABLISHED:
		LOG_GCC(trans, LOGL_DEBUG, "All cells establised, for a group call, assign caller to VGCS.\n");
		/* Send assignment to the calling subscriber. */
		rc = gcc_assign(trans);
		if (rc < 0) {
			gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
			break;
		}
		break;
	case VGCS_GCC_EV_BSS_ASSIGN_CPL:
		LOG_GCC(trans, LOGL_DEBUG, "Assignment complete, sending CONNECT to caller, releasing channel.\n");
		/* Handle assignment complete */
		_assign_complete(trans, true);
		break;
	case VGCS_GCC_EV_BSS_ASSIGN_FAIL:
		LOG_GCC(trans, LOGL_DEBUG, "Assignment failed, releasing call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	case VGCS_GCC_EV_BSS_RELEASED:
		LOG_GCC(trans, LOGL_DEBUG, "All group call in all cells failed, destroying call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_gcc_fsm_n2_call_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_trans *trans = fi->priv;

	switch (event) {
	case VGCS_GCC_EV_NET_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by network, destroying call.\n");
		/* Destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_USER_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by user, destroying call.\n");
		/* Send TERMINATE to the calling subscriber and destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_BSS_RELEASED:
		LOG_GCC(trans, LOGL_DEBUG, "All group call in all cells failed, destroying call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	case VGCS_GCC_EV_TIMEOUT:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by inactivity timer, destroying call.\n");
		/* Destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_gcc_fsm_n3_call_est_proc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_trans *trans = fi->priv;
	int rc;

	switch (event) {
	case VGCS_GCC_EV_NET_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by network, destroying call.\n");
		/* Destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_USER_TERM:
		LOG_GCC(trans, LOGL_DEBUG, "Termination by user, destroying call.\n");
		/* Send TERMINATE to the calling subscriber and destroy group call in all cells. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
		break;
	case VGCS_GCC_EV_BSS_ESTABLISHED:
		LOG_GCC(trans, LOGL_DEBUG, "All cells establised, for a group call, assign caller to VGCS.\n");
		/* Send assignment to the calling subscriber. */
		rc = gcc_assign(trans);
		if (rc < 0) {
			gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
			break;
		}
		break;
	case VGCS_GCC_EV_BSS_ASSIGN_CPL:
		LOG_GCC(trans, LOGL_DEBUG, "Assignment complete, sending CONNECT to caller, releasing channel.\n");
		/* Handle assignment complete */
		_assign_complete(trans, false);
		break;
	case VGCS_GCC_EV_BSS_ASSIGN_FAIL:
		LOG_GCC(trans, LOGL_DEBUG, "Assignment failed, releasing call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	case VGCS_GCC_EV_BSS_RELEASED:
		LOG_GCC(trans, LOGL_DEBUG, "All group call in all cells failed, destroying call.\n");
		/* Send TERMINATE to the calling subscriber. */
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_gcc_fsm_states[] = {
	[VGCS_GCC_ST_N0_NULL] = {
		.name = "NULL (N0)",
		.in_event_mask = S(VGCS_GCC_EV_NET_SETUP) |
				 S(VGCS_GCC_EV_NET_TERM) |
				 S(VGCS_GCC_EV_USER_SETUP) |
				 S(VGCS_GCC_EV_BSS_ESTABLISHED) |
				 S(VGCS_GCC_EV_BSS_RELEASED),
		.out_state_mask = S(VGCS_GCC_ST_N1_CALL_INITIATED) |
				  S(VGCS_GCC_ST_N2_CALL_ACTIVE),
		.action = vgcs_gcc_fsm_n0_null,
	},
	[VGCS_GCC_ST_N1_CALL_INITIATED] = {
		.name = "CALL INITATED (N1)",
		.in_event_mask = S(VGCS_GCC_EV_NET_TERM) |
				 S(VGCS_GCC_EV_USER_TERM) |
				 S(VGCS_GCC_EV_BSS_ESTABLISHED) |
				 S(VGCS_GCC_EV_BSS_ASSIGN_CPL) |
				 S(VGCS_GCC_EV_BSS_ASSIGN_FAIL) |
				 S(VGCS_GCC_EV_BSS_RELEASED),
		.out_state_mask = S(VGCS_GCC_ST_N0_NULL) |
				  S(VGCS_GCC_ST_N2_CALL_ACTIVE) |
				  S(VGCS_GCC_ST_N3_CALL_EST_PROC),
		.action = vgcs_gcc_fsm_n1_call_initiated,
	},
	[VGCS_GCC_ST_N2_CALL_ACTIVE] = {
		.name = "CALL ACTIVE (N2)",
		.in_event_mask = S(VGCS_GCC_EV_NET_TERM) |
				 S(VGCS_GCC_EV_USER_TERM) |
				 S(VGCS_GCC_EV_BSS_RELEASED) |
				 S(VGCS_GCC_EV_TIMEOUT),
		.out_state_mask = S(VGCS_GCC_ST_N0_NULL),
		.action = vgcs_gcc_fsm_n2_call_active,
	},
	[VGCS_GCC_ST_N3_CALL_EST_PROC] = {
		.name = "CALL EST PROCEEDING (N3)",
		.in_event_mask = S(VGCS_GCC_EV_NET_TERM) |
				 S(VGCS_GCC_EV_USER_TERM) |
				 S(VGCS_GCC_EV_BSS_ESTABLISHED) |
				 S(VGCS_GCC_EV_BSS_ASSIGN_CPL) |
				 S(VGCS_GCC_EV_BSS_ASSIGN_FAIL) |
				 S(VGCS_GCC_EV_BSS_RELEASED),
		.out_state_mask = S(VGCS_GCC_ST_N2_CALL_ACTIVE) |
				  S(VGCS_GCC_ST_N0_NULL),
		.action = vgcs_gcc_fsm_n3_call_est_proc,
	},
	// We don't need a state to wait for the group call to be terminated in all cells
};

static struct osmo_fsm vgcs_bcc_fsm = {
	.name = "bcc",
	.states = vgcs_gcc_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_gcc_fsm_states),
	.log_subsys = DBCC,
	.event_names = vgcs_gcc_fsm_event_names,
};

static struct osmo_fsm vgcs_gcc_fsm = {
	.name = "gcc",
	.states = vgcs_gcc_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_gcc_fsm_states),
	.log_subsys = DGCC,
	.event_names = vgcs_gcc_fsm_event_names,
};

const char *vgcs_bcc_gcc_state_name(struct osmo_fsm_inst *fi)
{
	return vgcs_gcc_fsm_states[fi->state].name;
}

static int update_uplink_state(struct vgcs_bss *bss, bool uplink_busy);

/* Receive RR messages from calling subscriber, prior assignment to VGCS/VBS. */
int gsm44068_rcv_rr(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm_trans *trans = NULL;
	struct gsm48_hdr *gh;
	uint8_t msg_type;

	gh = msgb_l3(msg);
	msg_type = gsm48_hdr_msg_type(gh);

	/* Find transaction. */
	trans = trans_find_by_type(msc_a, TRANS_GCC);
	if (!trans)
		trans = trans_find_by_type(msc_a, TRANS_BCC);

	if (!trans) {
		LOG_GCC(trans, LOGL_ERROR, "No VGCS/VBS transaction.\n");
		return -EINVAL;
	}

	/* In case the phone releases uplink prior being assigned to a VGCS */
	if (msg_type == GSM48_MT_RR_UPLINK_RELEASE) {
		struct vgcs_bss *bss;

		LOG_GCC(trans, LOGL_INFO, "Received UPLINK RELEASE on initial channel.\n");
		/* Clear the busy flag and unblock all cells. */
		trans->gcc.uplink_bss = NULL;
		trans->gcc.uplink_cell = NULL;
		trans->gcc.uplink_busy = false;
		llist_for_each_entry(bss, &trans->gcc.bss_list, list) {
			/* Update uplink state. */
			update_uplink_state(bss, trans->gcc.uplink_busy);
		}
		/* Start inactivity timer. */
		start_inactivity_timer(bss->trans);
		/* Next, the MS will switch to the VGCS as listener. Nothing else to do here. */
	}

	return 0;
}

/* Allocation of transaction for group call */
static struct gsm_trans *trans_alloc_vgcs(struct gsm_network *net,
					  struct vlr_subscr *vsub,
					  enum trans_type trans_type, uint8_t transaction_id,
					  uint32_t callref,
					  struct gcr *gcr,
					  bool uplink_busy)
{
	struct gsm_trans *trans;

	trans = trans_alloc(net, vsub, trans_type, transaction_id, callref);
	if (!trans) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for trans.\n");
		return NULL;
	}
	/* The uplink is busy when the call is started until the calling subscriber releases. */
	trans->gcc.uplink_busy = uplink_busy;
	trans->gcc.uplink_originator = true;
	INIT_LLIST_HEAD(&trans->gcc.bss_list);
	trans->gcc.inactivity_to = gcr->timeout;
	trans->gcc.mute_talker = gcr->mute_talker;
	trans->gcc.timer_inactivity.data = trans;
	trans->gcc.timer_inactivity.cb = inactivity_timer_cb;
	trans->gcc.fi = osmo_fsm_inst_alloc((trans_type == TRANS_GCC) ? &vgcs_gcc_fsm : &vgcs_bcc_fsm,
					    trans, trans, LOGL_DEBUG, NULL);
	if (!trans->gcc.fi) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for state machine.\n");
		trans_free(trans);
		return NULL;
	}

	return trans;
}

/* Create transaction from incoming voice group/broadcast call. */
static struct gsm_trans *trans_create_bcc_gcc(struct msc_a *msc_a, enum trans_type trans_type, uint8_t transaction_id,
					      uint8_t pdisc, uint8_t msg_type, uint32_t callref)
{
	struct gsm_network *net;
	struct vlr_subscr *vsub;
	struct gsm_trans *trans = NULL;
	struct gcr *gcr;
	int rc;

	if (!msc_a) {
		LOG_GCC(trans, LOGL_ERROR, "Invalid conn: no msc_a\n");
		return NULL;
	}
	net = msc_a_net(msc_a);
	vsub = msc_a_vsub(msc_a);

	if (!vsub) {
		LOG_GCC(trans, LOGL_ERROR, "Invalid conn: no subscriber\n");
		return NULL;
	}

	/* An earlier CM Service Request for this CC message now has concluded */
	if (!osmo_use_count_by(&msc_a->use_count,
			       (trans_type == TRANS_GCC) ? MSC_A_USE_CM_SERVICE_GCC : MSC_A_USE_CM_SERVICE_BCC))
		LOG_MSC_A(msc_a, LOGL_ERROR,
			  "Creating new %s transaction without prior CM Service Request.\n",
			  get_value_string(trans_type_names, trans_type));
	else
		msc_a_put(msc_a,
			  (trans_type == TRANS_GCC) ? MSC_A_USE_CM_SERVICE_GCC : MSC_A_USE_CM_SERVICE_BCC);

	/* A transaction must be created with a SETUP message. */
	if (msg_type != OSMO_GSM44068_MSGT_IMMEDIATE_SETUP
	 && msg_type != OSMO_GSM44068_MSGT_SETUP
	 && msg_type != OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2) {
		LOG_GCC(trans, LOGL_ERROR, "No transaction and message is not a SETUP.\n");
		return NULL;
	}

	/* Check if callref already exists. */
	trans = trans_find_by_callref(net, trans_type, callref);
	if (trans) {
		LOG_GCC(trans, LOGL_INFO, "Call to existing %s with callref %s, rejecting!\n",
			  trans_type_name(trans_type), gsm44068_group_id_string(callref));
		rc = gsm44068_tx_termination(msc_a, NULL,
					     pdisc | (transaction_id << 4),
					     OSMO_GSM44068_MSGT_TERMINATION,
					     OSMO_GSM44068_CAUSE_BUSY,  NULL, 0);
		if (rc < 0)
			LOG_GCC(trans, LOGL_ERROR, "Failed to send TERMINATION towards MS.\n");
		return 0;
	}

	/* Check GCR for Group ID. */
	gcr = gcr_by_callref(net, trans_type, callref);
	if (!gcr) {
		LOG_GCC(trans, LOGL_INFO, "No Group configured for %s callref %s, rejecting!\n",
			  trans_type_name(trans_type), gsm44068_group_id_string(callref));
		// FIXME: Better cause value for a group that does not exist ?
		rc = gsm44068_tx_termination(msc_a, NULL,
					     pdisc | (transaction_id << 4),
					     OSMO_GSM44068_MSGT_TERMINATION,
					     OSMO_GSM44068_CAUSE_REQUESTED_SERVICE_NOT_SUB,  NULL, 0);
		if (rc < 0)
			LOG_GCC(trans, LOGL_ERROR, "Failed to send TERMINATION towards MS.\n");
		return 0;
	}

	/* Create transaction, uplink is busy. */
	trans = trans_alloc_vgcs(net, vsub, trans_type, transaction_id, callref, gcr, true);
	if (!trans) {
		rc = gsm44068_tx_termination(msc_a, NULL,
					     pdisc | (transaction_id << 4),
					     OSMO_GSM44068_MSGT_TERMINATION,
					     OSMO_GSM44068_CAUSE_NETWORK_FAILURE, NULL, 0);
		if (rc < 0)
			LOG_GCC(trans, LOGL_ERROR, "Failed to send TERMINATION towards MS.\n");
		return NULL;
	}

	if (osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_TRANSACTION_ACCEPTED, trans)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Not allowed to accept %s transaction.\n",
			  get_value_string(trans_type_names, trans_type));
		gcc_terminate_and_destroy(trans, OSMO_GSM44068_CAUSE_NETWORK_FAILURE);
		return NULL;
	}

	/* Assign transaction */
	msc_a_get(msc_a, (trans_type == TRANS_GCC) ? MSC_A_USE_GCC : MSC_A_USE_BCC);
	trans->msc_a = msc_a;
	trans->dlci = 0; /* main DCCH */

	return trans;
}

/* Receive GCC/BCC messages from calling subscriber, depending on the PDISC used. */
int gsm44068_rcv_bcc_gcc(struct msc_a *msc_a, struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t transaction_id = gsm48_hdr_trans_id_flip_ti(gh);
	enum trans_type trans_type = (pdisc == GSM48_PDISC_GROUP_CC) ? TRANS_GCC : TRANS_BCC;

	uint8_t key_seq;
	bool talker_prio_requested;
	bool with_talker_prio;
	uint8_t talker_prio;
	struct gsm48_classmark2 cm2;
	struct osmo_mobile_identity mi;
	uint32_t callref;
	bool with_prio;
	uint8_t prio;
	char user_user[64] = "";
	uint8_t cause;
	uint8_t diag[256];
	uint8_t diag_len;
	bool with_call_state;
	enum osmo_gsm44068_call_state call_state;
	bool with_state_attrs;
	uint8_t da, ua, comm, oi;
	int rc = 0;

	/* Remove sequence number (bit 7) from message type. */
	msg_type &= 0xbf;

	/* Parse messages. */
	switch (msg_type) {
	case OSMO_GSM44068_MSGT_SETUP:
		rc = gsm44068_rx_setup(msg, &talker_prio_requested, &talker_prio, &callref, &with_prio, &prio,
				       user_user);
		break;
	case OSMO_GSM44068_MSGT_IMMEDIATE_SETUP:
	case OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2:
		rc = gsm44068_rx_immediate_setup(msg, &talker_prio, &key_seq, &cm2, &mi, &callref, &with_prio, &prio,
						 user_user);
		break;
	case OSMO_GSM44068_MSGT_STATUS:
		rc = gsm44068_rx_status(msg, &cause, diag, &diag_len, &with_call_state, &call_state,
					&with_state_attrs, &da, &ua, &comm, &oi);
		break;
	case OSMO_GSM44068_MSGT_TERMINATION_REQUEST:
		rc = gsm44068_rx_termination_req(msg, &callref, &with_prio, &prio, &with_talker_prio, &talker_prio);
		break;
	default:
		LOG_GCC(trans, LOGL_ERROR, "Invalid message type: 0x%02x\n", msg_type);
		return -EINVAL;
	}
	if (rc < 0)
		return rc;

	/* Find transaction, if called from msc_a. */
	if (!trans)
		trans = trans_find_by_id(msc_a, trans_type, transaction_id);

	/* Create transaction for SETUP message. */
	if (!trans) {
		trans = trans_create_bcc_gcc(msc_a, trans_type, transaction_id, pdisc, msg_type, callref);
		if (!trans)
			return -EINVAL;
	} else {
		/* A phone may not call while a VGCS is already active */
		if (msg_type == OSMO_GSM44068_MSGT_IMMEDIATE_SETUP
		 || msg_type == OSMO_GSM44068_MSGT_SETUP
		 || msg_type == OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2) {
			LOG_GCC(trans, LOGL_ERROR, "Received SETUP while call is already set up, rejecting.\n");
			rc = gsm44068_tx_termination(msc_a, NULL,
						     pdisc | (transaction_id << 4),
						     OSMO_GSM44068_MSGT_TERMINATION,
						     OSMO_GSM44068_CAUSE_NETWORK_FAILURE, NULL, 0);
			if (rc < 0)
				LOG_GCC(trans, LOGL_ERROR, "Failed to send TERMINATION towards MS.\n");
			return -EINVAL;
		}
	}

	/* Handle received GCC messages (trigger state machine). */
	switch (msg_type) {
	case OSMO_GSM44068_MSGT_IMMEDIATE_SETUP:
	case OSMO_GSM44068_MSGT_SETUP:
	case OSMO_GSM44068_MSGT_IMMEDIATE_SETUP_2:
		LOG_GCC(trans, LOGL_INFO, "Received SETUP.\n");
		osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_USER_SETUP, NULL);
		break;
	case OSMO_GSM44068_MSGT_STATUS:
		LOG_GCC(trans, LOGL_NOTICE, "Received STATUS with cause %d (%s).\n", cause,
			  get_value_string(osmo_gsm44068_cause_names, cause));
		if (diag_len)
			LOG_GCC(trans, LOGL_NOTICE, " -> diagnostics: %s\n", osmo_hexdump(diag, diag_len));
		if (with_call_state)
			LOG_GCC(trans, LOGL_NOTICE, " -> call state %s\n",
				  get_value_string(osmo_gsm44068_call_state_names, call_state));
		break;
	case OSMO_GSM44068_MSGT_TERMINATION_REQUEST:
		LOG_GCC(trans, LOGL_INFO, "Received TERMINATRION REQUEST.\n");
		if (callref != trans->callref) {
			LOG_GCC(trans, LOGL_NOTICE, "Received callref 0x%x does not match!\n", callref);
			break;
		}
		osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_USER_TERM, NULL);
		break;
	}

	return 0;
}

static void bss_clear(struct vgcs_bss *bss, uint8_t cause, bool notify_trans);

/* Call Control Specific transaction release.
 * gets called by trans_free, DO NOT CALL YOURSELF! */
void gsm44068_bcc_gcc_trans_free(struct gsm_trans *trans)
{
	struct vgcs_bss *bss, *bss2;

	/* Free FSM. */
	if (trans->gcc.fi) {
		osmo_fsm_inst_state_chg(trans->gcc.fi, VGCS_GCC_ST_N0_NULL, 0, 0);
		osmo_fsm_inst_term(trans->gcc.fi, OSMO_FSM_TERM_REGULAR, NULL);
	}

	/* Remove relations to cells.
	 * We must loop safe, because bss_clear() will detach every call control instance from list. */
	llist_for_each_entry_safe(bss, bss2, &trans->gcc.bss_list, list)
		osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_CLEAR, NULL);

	/* Stop inactivity timer. */
	stop_inactivity_timer(trans);
}

/* Create a new call from VTY command. */
const char *vgcs_vty_initiate(struct gsm_network *gsmnet, struct gcr *gcr)
{
	enum trans_type trans_type;
	uint32_t callref;
	struct gsm_trans *trans;

	/* Get callref from stored suffix. Caller cannot choose a prefix. */
	trans_type = gcr->trans_type;
	callref = atoi(gcr->group_id);

	/* Check if callref already exists. */
	trans = trans_find_by_callref(gsmnet, trans_type, callref);
	if (trans) {
		LOG_GCC(trans, LOGL_INFO, "Call to existing %s with callref %s, rejecting!\n",
			trans_type_name(trans_type), gsm44068_group_id_string(callref));
		return "Call already exists.";
	}

	/* Create transaction, uplink is free. */
	trans = trans_alloc_vgcs(gsmnet, NULL, trans_type, 0, callref, gcr, false);
	if (!trans) {
		LOG_GCC(trans, LOGL_ERROR, "No memory for trans.\n");
		return "Failed to create call.";
	}

	LOG_GCC(trans, LOGL_INFO, "VTY initiates call.\n");
	osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_NET_SETUP, NULL);

	return NULL;
}

/* Destroy a call from VTY command. */
const char *vgcs_vty_terminate(struct gsm_network *gsmnet, struct gcr *gcr)
{
	enum trans_type trans_type;
	uint32_t callref;
	struct gsm_trans *trans;

	/* Get callref from stored suffix. Caller cannot choose a prefix. */
	trans_type = gcr->trans_type;
	callref = atoi(gcr->group_id);

	/* Check if callref exists. */
	trans = trans_find_by_callref(gsmnet, trans_type, callref);
	if (!trans)
		return "Call does not exist.";

	LOG_GCC(trans, LOGL_INFO, "VTY terminates call.\n");
	osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_NET_TERM, NULL);

	return NULL;
}

/*
 * BSS state machine - handles all BSS "call control" instances
 */

static const struct value_string vgcs_bss_fsm_event_names[] = {
	OSMO_VALUE_STRING(VGCS_BSS_EV_SETUP),
	OSMO_VALUE_STRING(VGCS_BSS_EV_SETUP_ACK),
	OSMO_VALUE_STRING(VGCS_BSS_EV_SETUP_REFUSE),
	OSMO_VALUE_STRING(VGCS_BSS_EV_ACTIVE_OR_FAIL),
	OSMO_VALUE_STRING(VGCS_BSS_EV_UL_REQUEST),
	OSMO_VALUE_STRING(VGCS_BSS_EV_UL_REQUEST_CNF),
	OSMO_VALUE_STRING(VGCS_BSS_EV_UL_APP_DATA),
	OSMO_VALUE_STRING(VGCS_BSS_EV_BSS_DTAP),
	OSMO_VALUE_STRING(VGCS_BSS_EV_UL_RELEASE),
	OSMO_VALUE_STRING(VGCS_BSS_EV_CLEAR),
	OSMO_VALUE_STRING(VGCS_BSS_EV_CLOSE),
	OSMO_VALUE_STRING(VGCS_BSS_EV_RELEASED),
	{ }
};

/* Blocks or unblocks uplinks of a BSS. */
static int update_uplink_state(struct vgcs_bss *bss, bool uplink_busy)
{
	struct ran_msg ran_msg;
	int rc;

	if (uplink_busy) {
		/* Send UPLINK SEIZED COMMAND to BSS. */
		LOG_BSS(bss, LOGL_DEBUG, "Sending (VGCS) UPLINK SEIZED COMMAND towards BSS.\n");
		ran_msg = (struct ran_msg){
			.msg_type = RAN_MSG_UPLINK_SEIZED_CMD,
			.uplink_seized_cmd = {
				.cause = GSM0808_CAUSE_CALL_CONTROL,
			},
		};
	} else {
		/* Send UPLINK RELEASE COMMAND to BSS. */
		LOG_BSS(bss, LOGL_DEBUG, "Sending (VGCS) UPLINK RELEASE COMMAND towards BSS.\n");
		ran_msg = (struct ran_msg){
			.msg_type = RAN_MSG_UPLINK_RELEASE_CMD,
			.uplink_release_cmd = {
				.cause = GSM0808_CAUSE_CALL_CONTROL,
			},
		};
	}

	rc = ran_encode_and_send(bss->fi, &ran_msg, bss->conn, false);

	return rc;
}

/* Clear the connection towards BSS.
 * The instance is removed soon, so it is detached from transaction and cells. */
static void bss_clear(struct vgcs_bss *bss, uint8_t cause, bool notify_trans)
{
	struct ran_msg ran_msg;
	struct gsm_trans *trans = bss->trans;
	struct vgcs_bss_cell *cell, *cell2;

	/* Must detach us from transaction. */
	if (bss->trans) {
		/* Remove pointer to talking BSS and cell. */
		if (bss == bss->trans->gcc.uplink_bss) {
			bss->trans->gcc.uplink_bss = NULL;
			bss->trans->gcc.uplink_cell = NULL;
		}
		llist_del(&bss->list);
		bss->trans = NULL;
	}

	/* Change state. */
	osmo_fsm_inst_state_chg(bss->fi, VGCS_BSS_ST_RELEASE, 0, 0);

	/* Send Clear Command to BSS. */
	ran_msg = (struct ran_msg){
		.msg_type = RAN_MSG_CLEAR_COMMAND,
		.clear_command = {
			.gsm0808_cause = cause,
		},
	};
	if (bss->conn) {
		LOG_BSS(bss, LOGL_DEBUG, "Sending CLEAR COMMAND for call controling channel.\n");
		ran_encode_and_send(bss->fi, &ran_msg, bss->conn, false);
	}

	/* Trigger clear of all cells. Be safe, because the process will remove cells from list. */
	llist_for_each_entry_safe(cell, cell2, &bss->cell_list, list_bss)
		osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_CLEAR, NULL);

	/* Detach us from all BSS, if still linked */
	llist_for_each_entry_safe(cell, cell2, &bss->cell_list, list_bss) {
		llist_del(&cell->list_bss);
		cell->bss = NULL;
	}

	/* If all BS are gone, notify calling subscriber process. */
	if (notify_trans && trans && llist_empty(&trans->gcc.bss_list)) {
		LOG_BSS(bss, LOGL_DEBUG, "Notify calling user process, that all BSSs are cleared.\n");
		osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_BSS_RELEASED, NULL);
	}
}

/* When finally the BSS connection is released. (CLEAR COMPLETE response)
 * The instance is removed, so it is detached from transaction and cells, if not already. */
static void bss_destroy(struct vgcs_bss *bss)
{
	struct vgcs_bss_cell *cell, *cell2;

	LOG_BSS(bss, LOGL_DEBUG, "Removing BSS call controling instance.\n");

	/* Must detach us from transaction, if not already. */
	if (bss->trans) {
		/* Remove pointer to talking BSS and cell. */
		if (bss == bss->trans->gcc.uplink_bss) {
			bss->trans->gcc.uplink_bss = NULL;
			bss->trans->gcc.uplink_cell = NULL;
		}
		llist_del(&bss->list);
		bss->trans = NULL;
	}

	/* Detach us from RAN connection. */
	if (bss->conn) {
		if (bss->conn->vgcs.bss == bss)
			bss->conn->vgcs.bss = NULL;
		if (bss->conn->vgcs.cell == bss)
			bss->conn->vgcs.cell = NULL;
		ran_conn_close(bss->conn);
		bss->conn = NULL;
	}

	/* Detach us from all BSS, if still linked */
	llist_for_each_entry_safe(cell, cell2, &bss->cell_list, list_bss) {
		llist_del(&cell->list_bss);
		cell->bss = NULL;
	}

	/* Free FSM. (should be allocated) */
	osmo_fsm_inst_state_chg(bss->fi, VGCS_BSS_ST_NULL, 0, 0);
	osmo_fsm_inst_term(bss->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

/* Get identity of talker.
 * This is required to detect if the talker is the calling subscriber. */
static int talker_identity(struct vgcs_bss *bss, uint8_t *l3, int l3_len)
{
	struct osmo_mobile_identity mi;
	int rc;

	puts(osmo_hexdump(l3, l3_len));
	rc = osmo_mobile_identity_decode_from_l3_buf(&mi, l3, l3_len, false);
	if (rc < 0) {
		LOG_BSS(bss, LOGL_DEBUG, "Talker's Identity cannot be decoded.\n");
		return rc;
	}

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
		if (!bss->trans->vsub)
			break;
		LOG_BSS(bss, LOGL_DEBUG, "Talker's sends IMSI %s, originator has IMSI %s.\n",
			mi.imsi, bss->trans->vsub->imsi);
		if (!strcmp(mi.imsi, bss->trans->vsub->imsi))
			return 1;
		break;
	case GSM_MI_TYPE_TMSI:
		if (!bss->trans->vsub)
			break;
		LOG_BSS(bss, LOGL_DEBUG, "Talker's sends TMSI 0x%08x, originator has TMSI 0x%08x.\n",
			mi.tmsi, bss->trans->vsub->tmsi);
		if (mi.tmsi == bss->trans->vsub->tmsi)
			return 1;
		break;
	default:
		LOG_BSS(bss, LOGL_DEBUG, "Talker's Identity is not IMSI nor TMSI.\n");
		return -EINVAL;
	}

	return 0;
}

static void vgcs_bss_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss *bss = fi->priv;
	struct ran_msg ran_msg;

	switch (event) {
	case VGCS_BSS_EV_SETUP:
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_BSS_ST_SETUP, 0, 0);
		/* Send VGCS/VBS SETUP to BSS. */
		LOG_BSS(bss, LOGL_DEBUG, "Sending VGCS/VBS SETUP towards BSS.\n");
		ran_msg = (struct ran_msg){
			.msg_type = RAN_MSG_VGCS_VBS_SETUP,
			.vgcs_vbs_setup = {
				.callref = {
					.sf = (bss->trans->type == TRANS_GCC),
				},
				.vgcs_feature_flags_present = true,
			},
		};
		osmo_store32be_ext(bss->callref >> 3, &ran_msg.vgcs_vbs_setup.callref.call_ref_hi, 3);
		ran_msg.vgcs_vbs_setup.callref.call_ref_lo = bss->callref & 0x7;
		/* First message, so we must set "initial" to "true". */
		ran_encode_and_send(fi, &ran_msg, bss->conn, true);
		break;
	case VGCS_BSS_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_BSS(bss, LOGL_DEBUG, "Received clearing from calling user process.\n");
		bss_clear(bss, GSM0808_CAUSE_CALL_CONTROL, false);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_bss_fsm_setup(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss *bss = fi->priv;
	struct vgcs_bss_cell *cell, *cell2;

	switch (event) {
	case VGCS_BSS_EV_SETUP_ACK:
		/* Receive VGCS/VBS SETUP ACK from BSS. */
		LOG_BSS(bss, LOGL_DEBUG, "Received VGCS/VBS SETUP ACK from BSS.\n");
		/* Send current uplink state to this BSS. */
		if (bss->trans)
			update_uplink_state(bss, bss->trans->gcc.uplink_busy);
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_BSS_ST_ASSIGNMENT, 0, 0);
		/* Trigger VGCS/VBS ASSIGNMENT */
		llist_for_each_entry_safe(cell, cell2, &bss->cell_list, list_bss)
			osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_ASSIGN, NULL);
		/* If all failed, clear call. */
		if (llist_empty(&bss->cell_list)) {
			LOG_BSS(bss, LOGL_NOTICE, "All VGCS/VBS assignments failed.\n");
			bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
			break;
		}
		break;
	case VGCS_BSS_EV_SETUP_REFUSE:
		/* Received VGCS/VBS SETUP REFUSE from BSS. */
		LOG_BSS(bss, LOGL_NOTICE, "Received VGCS/VBS SETUP REFUSE from BSS.\n");
		bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
		break;
	case VGCS_BSS_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_BSS(bss, LOGL_DEBUG, "Received clearing from calling user process.\n");
		bss_clear(bss, GSM0808_CAUSE_CALL_CONTROL, false);
		break;
	case VGCS_BSS_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed. */
		LOG_BSS(bss, LOGL_NOTICE, "Received SCCP connecting closing from MSC.\n");
		if (bss->conn) {
			bss->conn->vgcs.bss = NULL;
			bss->conn = NULL;
		}
		bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_bss_fsm_assignment(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss *bss = fi->priv;
	struct vgcs_bss_cell *c;
	bool assigned;

	switch (event) {
	case VGCS_BSS_EV_ACTIVE_OR_FAIL:
		/* If all gone, clear call. */
		if (llist_empty(&bss->cell_list)) {
			LOG_BSS(bss, LOGL_NOTICE, "All VGCS/VBS assignments failed.\n");
			bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
			break;
		}
		/* Is there a response for all cells?
		 * This means that all the channels have a positive response
		 * There is no channel with negative response, because a
		 * negative response will remove the channel. */
		assigned = true;
		llist_for_each_entry(c, &bss->cell_list, list_bss) {
			if (!c->assigned)
				assigned = false;
		}
		if (!assigned)
			break;
		LOG_BSS(bss, LOGL_DEBUG, "All VGCS/VBS assignments have responded.\n");
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_BSS_ST_ACTIVE, 0, 0);
		/* Notify calling subscriber process. */
		LOG_BSS(bss, LOGL_DEBUG, "Notify calling user process, that all BSSs are connected.\n");
		if (bss->trans)
			osmo_fsm_inst_dispatch(bss->trans->gcc.fi, VGCS_GCC_EV_BSS_ESTABLISHED, NULL);
		break;
	case VGCS_BSS_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_BSS(bss, LOGL_DEBUG, "Received clearing from calling user process.\n");
		bss_clear(bss, GSM0808_CAUSE_CALL_CONTROL, false);
		break;
	case VGCS_BSS_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed. */
		LOG_BSS(bss, LOGL_NOTICE, "Received SCCP connecting closing from MSC.\n");
		if (bss->conn) {
			bss->conn->vgcs.bss = NULL;
			bss->conn = NULL;
		}
		bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_bss_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss *bss = fi->priv, *other;
	struct ran_msg *rx_ran_msg = data;
	struct ran_msg tx_ran_msg;
	int rc;

	switch (event) {
	case VGCS_BSS_EV_UL_REQUEST:
		LOG_BSS(bss, LOGL_DEBUG, "Listener changed to talker.\n");
		if (!bss->trans)
			break;
		/* Someone is talking. Check if there is no other uplink already busy.
		 * This should not happen, since all other cells are blocked (SEIZED) as soon as the uplink was
		 * requested. This may happen due to a race condition, where the uplink was requested before the
		 * UPLINK SEIZED COMMAND has been received by BSS. */
		if (bss->trans->gcc.uplink_busy) {
			/* Send UPLINK REJECT COMMAND to BSS. */
			LOG_BSS(bss, LOGL_DEBUG, "Sending (VGCS) UPLINK REJECT COMMAND towards BSS.\n");
			tx_ran_msg = (struct ran_msg){
				.msg_type = RAN_MSG_UPLINK_REJECT_CMD,
				.uplink_reject_cmd = {
					.cause = GSM0808_CAUSE_CALL_CONTROL,
				},
			};
			ran_encode_and_send(fi, &tx_ran_msg, bss->conn, false);
			break;
		}
		/* Send UPLINK REQUEST ACKNOWLEDGE to BSS. */
		LOG_BSS(bss, LOGL_DEBUG, "Sending (VGCS) UPLINK REQUEST ACKNOWLEDGE towards BSS.\n");
		tx_ran_msg = (struct ran_msg){
			.msg_type = RAN_MSG_UPLINK_REQUEST_ACK,
		};
		ran_encode_and_send(fi, &tx_ran_msg, bss->conn, false);
		/* Set the busy flag and block all other cells. */
		bss->trans->gcc.uplink_bss = bss;
		bss->trans->gcc.uplink_busy = true;
		bss->trans->gcc.uplink_originator = false;
		llist_for_each_entry(other, &bss->trans->gcc.bss_list, list) {
			if (other == bss)
				continue;
			/* Update uplink state. */
			update_uplink_state(bss, bss->trans->gcc.uplink_busy);
		}
		/* Stop inactivity timer. */
		stop_inactivity_timer(bss->trans);
		break;
	case VGCS_BSS_EV_UL_REQUEST_CNF:
		LOG_BSS(bss, LOGL_DEBUG, "Talker established uplink.\n");
		if (!bss->trans)
			break;
		if (!bss->trans->gcc.uplink_busy || bss->trans->gcc.uplink_bss != bss) {
			LOG_BSS(bss, LOGL_ERROR, "Got UL REQUEST CNF, but we did not granted uplink.\n");
			break;
		}
		/* Determine if talker is the originator of the call. */
		rc = talker_identity(bss, rx_ran_msg->uplink_request_cnf.l3.l3,
				     rx_ran_msg->uplink_request_cnf.l3.l3_len);
		if (rc > 0) {
			bss->trans->gcc.uplink_originator = true;
			LOG_BSS(bss, LOGL_DEBUG, "Talker is the originator of the call.\n");
		}
		/* Set parameter. */
		set_parameter(bss->trans);
		/* Set cell of current talker. */
		set_uplink_cell(bss, &rx_ran_msg->uplink_request_cnf.cell_identifier, 0);
		/* Set MGW conference. */
		set_mgw_conference(bss->trans);
		break;
	case VGCS_BSS_EV_UL_APP_DATA:
		LOG_BSS(bss, LOGL_DEBUG, "Talker sends application data on uplink.\n");
		if (!bss->trans)
			break;
		if (!bss->trans->gcc.uplink_busy || bss->trans->gcc.uplink_bss != bss) {
			LOG_BSS(bss, LOGL_ERROR, "Got UP APP DATA, but we did not granted uplink.\n");
			break;
		}
		// FIXME: Use L3 info and feed to app.
		break;
	case VGCS_BSS_EV_BSS_DTAP:
		LOG_BSS(bss, LOGL_DEBUG, "Talker sends DTAP message.\n");
		if (!bss->trans)
			break;
		if (!bss->trans->gcc.uplink_busy || bss->trans->gcc.uplink_bss != bss) {
			LOG_BSS(bss, LOGL_ERROR, "Got DTAP from BSS, but we did not granted uplink.\n");
			break;
		}
		gsm44068_rcv_bcc_gcc(NULL, bss->trans, rx_ran_msg->dtap);
		break;
	case VGCS_BSS_EV_UL_RELEASE:
		LOG_BSS(bss, LOGL_DEBUG, "Talker released uplink.\n");
		if (!bss->trans)
			break;
		if (bss->trans->type == TRANS_BCC) {
			LOG_BSS(bss, LOGL_DEBUG, "This is a broadcast call, terminating call.\n");
			gcc_terminate_and_destroy(bss->trans, OSMO_GSM44068_CAUSE_NORMAL_CALL_CLEARING);
			break;
		}
		if (!bss->trans->gcc.uplink_busy) {
			LOG_BSS(bss, LOGL_NOTICE, "Got uplink release, but no uplink busy.\n");
			break;
		}
		/* Talker release the uplink. Ignore, if not from the current talking cell. */
		if (bss->trans->gcc.uplink_bss != bss) {
			LOG_BSS(bss, LOGL_NOTICE, "Got uplink release, but uplink busy in other cell.\n");
			break;
		}
		/* Clear the busy flag and unblock all other cells. */
		bss->trans->gcc.uplink_bss = NULL;
		bss->trans->gcc.uplink_cell = NULL;
		bss->trans->gcc.uplink_busy = false;
		llist_for_each_entry(other, &bss->trans->gcc.bss_list, list) {
			if (other == bss)
				continue;
			/* Update uplink state. */
			if (bss->trans)
				update_uplink_state(bss, bss->trans->gcc.uplink_busy);
		}
		/* Set MGW conference. */
		set_mgw_conference(bss->trans);
		/* Start inactivity timer. */
		start_inactivity_timer(bss->trans);
		break;
	case VGCS_BSS_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_BSS(bss, LOGL_DEBUG, "Received clearing from calling user process.\n");
		bss_clear(bss, GSM0808_CAUSE_CALL_CONTROL, false);
		break;
	case VGCS_BSS_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed. */
		LOG_BSS(bss, LOGL_NOTICE, "Received SCCP connecting closing from MSC.\n");
		if (bss->conn) {
			bss->conn->vgcs.bss = NULL;
			bss->conn = NULL;
		}
		bss_clear(bss, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC, true);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_bss_fsm_release(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss *bss = fi->priv;

	switch (event) {
	case VGCS_BSS_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed while waitring fro CLEAR COMPLETE. */
		LOG_BSS(bss, LOGL_NOTICE, "Received SCCP closing collision.\n");
		bss_destroy(bss);
		break;
	case VGCS_BSS_EV_RELEASED:
		LOG_BSS(bss, LOGL_DEBUG, "Received CLEAR COMPLETE from BSS, we are done!\n");
		bss_destroy(bss);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_bss_fsm_states[] = {
	[VGCS_BSS_ST_NULL] = {
		.name = "NULL",
		.in_event_mask = S(VGCS_BSS_EV_SETUP) |
				 S(VGCS_BSS_EV_CLEAR),
		.out_state_mask = S(VGCS_BSS_ST_SETUP),
		.action = vgcs_bss_fsm_null,
	},
	[VGCS_BSS_ST_SETUP] = {
		.name = "SETUP sent",
		.in_event_mask = S(VGCS_BSS_EV_SETUP_ACK) |
				 S(VGCS_BSS_EV_SETUP_REFUSE) |
				 S(VGCS_BSS_EV_CLEAR) |
				 S(VGCS_BSS_EV_CLOSE),
		.out_state_mask = S(VGCS_BSS_ST_ASSIGNMENT) |
				  S(VGCS_BSS_ST_RELEASE),
		.action = vgcs_bss_fsm_setup,
	},
	[VGCS_BSS_ST_ASSIGNMENT] = {
		.name = "ASSIGNMENT Sent",
		.in_event_mask = S(VGCS_BSS_EV_ACTIVE_OR_FAIL) |
				 S(VGCS_BSS_EV_CLEAR) |
				 S(VGCS_BSS_EV_CLOSE),
		.out_state_mask = S(VGCS_BSS_ST_ACTIVE) |
				  S(VGCS_BSS_ST_RELEASE),
		.action = vgcs_bss_fsm_assignment,
	},
	[VGCS_BSS_ST_ACTIVE] = {
		.name = "VGCS/VBS Active",
		.in_event_mask = S(VGCS_BSS_EV_UL_REQUEST) |
				 S(VGCS_BSS_EV_UL_REQUEST_CNF) |
				 S(VGCS_BSS_EV_UL_APP_DATA) |
				 S(VGCS_BSS_EV_BSS_DTAP) |
				 S(VGCS_BSS_EV_UL_RELEASE) |
				 S(VGCS_BSS_EV_CLEAR) |
				 S(VGCS_BSS_EV_CLOSE),
		.out_state_mask = S(VGCS_BSS_ST_RELEASE),
		.action = vgcs_bss_fsm_active,
	},
	[VGCS_BSS_ST_RELEASE] = {
		.name = "Releasing VGCS/VBS control",
		.in_event_mask = S(VGCS_BSS_EV_CLEAR) |
				 S(VGCS_BSS_EV_RELEASED),
		.out_state_mask = S(VGCS_BSS_ST_NULL),
		.action = vgcs_bss_fsm_release,
	},
};

static struct osmo_fsm vgcs_bss_fsm = {
	.name = "vgcs_bss",
	.states = vgcs_bss_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_bss_fsm_states),
	.log_subsys = DASCI,
	.event_names = vgcs_bss_fsm_event_names,
};

/* The BSS accepts VGCS/VBS and sends us supported features. */
void vgcs_vbs_setup_ack(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_SETUP_ACK, (void *)ran_msg);
}

/* The BSS refuses VGCS/VBS. */
void vgcs_vbs_setup_refuse(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_SETUP_REFUSE, (void *)ran_msg);
}

/* The BSS needs more time for VGCS/VBS channel assignment. */
void vgcs_vbs_queuing_ind(struct vgcs_bss_cell *cell)
{
	if (!cell->bss)
		return;
}

/* A mobile station requests the uplink on a VGCS channel. */
void vgcs_uplink_request(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_UL_REQUEST, (void *)ran_msg);
}

/* The uplink on a VGCS channel has been established. */
void vgcs_uplink_request_cnf(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_UL_REQUEST_CNF, (void *)ran_msg);
}

/* Application data received on the uplink of a VGCS channel. */
void vgcs_app_data(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_UL_APP_DATA, (void *)ran_msg);
}

/* Application data received on the uplink of a VGCS channel. */
void vgcs_bss_dtap(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_BSS_DTAP, (void *)ran_msg);
}

/* A mobile station releases the uplink on a VGCS channel. */
void vgcs_uplink_release_ind(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	if (!bss->trans)
		return;
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_UL_RELEASE, (void *)ran_msg);
}

/* The BSS gives cell status about VGCS/VBS channel. */
void vgcs_vbs_assign_status(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg)
{
	if (!cell->bss)
		return;
}

void vgcs_vbs_caller_assign_cpl(struct gsm_trans *trans)
{
	osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_BSS_ASSIGN_CPL, NULL);
}

void vgcs_vbs_caller_assign_fail(struct gsm_trans *trans)
{
	osmo_fsm_inst_dispatch(trans->gcc.fi, VGCS_GCC_EV_BSS_ASSIGN_FAIL, NULL);
}

/* BSS indicated that the channel has been released. */
void vgcs_vbs_clear_req(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_CLOSE, (void *)ran_msg);
}

/* BSS indicated that the channel has been released. */
void vgcs_vbs_clear_cpl(struct vgcs_bss *bss, const struct ran_msg *ran_msg)
{
	osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_RELEASED, (void *)ran_msg);
}

/*
 * Cell resource state machine - handles all "resource control" instances
 */

static const struct value_string vgcs_cell_fsm_event_names[] = {
	OSMO_VALUE_STRING(VGCS_CELL_EV_RTP_STREAM_GONE),
	OSMO_VALUE_STRING(VGCS_CELL_EV_RTP_STREAM_ADDR_AVAILABLE),
	OSMO_VALUE_STRING(VGCS_CELL_EV_RTP_STREAM_ESTABLISHED),
	OSMO_VALUE_STRING(VGCS_CELL_EV_ASSIGN),
	OSMO_VALUE_STRING(VGCS_CELL_EV_ASSIGN_RES),
	OSMO_VALUE_STRING(VGCS_CELL_EV_ASSIGN_FAIL),
	OSMO_VALUE_STRING(VGCS_CELL_EV_CLEAR),
	OSMO_VALUE_STRING(VGCS_CELL_EV_CLOSE),
	OSMO_VALUE_STRING(VGCS_CELL_EV_RELEASED),
	{ }
};

static void cell_destroy(struct vgcs_bss_cell *cell);

/* Clear the connection towards BSS.
 * Relations to the BSS and transaction is removed. */
static void cell_clear(struct vgcs_bss_cell *cell, uint8_t cause)
{
	struct ran_msg ran_msg;

	/* Must detach us from BSS. */
	if (cell->bss) {
		/* Remove pointer to talking channel. */
		if (cell->bss->trans && cell->bss->trans->gcc.uplink_cell == cell)
			cell->bss->trans->gcc.uplink_cell = NULL;
		llist_del(&cell->list_bss);
		cell->bss = NULL;
	}

	/* Change state. */
	if (cell->fi->state != VGCS_CELL_ST_RELEASE)
		osmo_fsm_inst_state_chg(cell->fi, VGCS_CELL_ST_RELEASE, 0, 0);

	/* If there is no event to wait for, we can just destroy. */
	if (!cell->conn && !cell->rtps) {
		cell_destroy(cell);
		return;
	}

	/* Send Clear Command to BSS. */
	if (cell->conn) {
		ran_msg = (struct ran_msg){
			.msg_type = RAN_MSG_CLEAR_COMMAND,
			.clear_command = {
				.gsm0808_cause = cause,
			},
		};
		LOG_CELL(cell, LOGL_DEBUG, "Sending CLEAR COMMAND for call controling channel.\n");
		ran_encode_and_send(cell->fi, &ran_msg, cell->conn, false);
	}

	/* Clear RTP stream. This may trigger VGCS_CELL_EV_RTP_STREAM_GONE within this release function. */
	if (cell->rtps)
		rtp_stream_release(cell->rtps);
}

/* When finally the BSS connection is released. (CLEAR COMPLETE response)
 * Relations to the BSS and transaction is removed, if not already. */
static void cell_destroy(struct vgcs_bss_cell *cell)
{
	struct vgcs_mgw_ep *mgw;

	/* close RAN conn */
	if (cell->conn) {
		cell->conn->vgcs.cell = NULL;
		ran_conn_close(cell->conn);
		cell->conn = NULL;
	}

	/* Detach from BSS now. Check, to prevent race condition. */
	if (cell->bss) {
		/* Remove pointer to talking channel. */
		if (cell->bss->trans && cell->bss->trans->gcc.uplink_cell == cell)
			cell->bss->trans->gcc.uplink_cell = NULL;
		llist_del(&cell->list_bss);
		cell->bss = NULL;
	}

	/* Detach from MGW now. Check, to prevent race condition. */
	if (cell->mgw) {
		mgw = cell->mgw;
		llist_del(&cell->list_mgw);
		cell->mgw = NULL;
		/* Destroy MGW endpoint, if list is empty. */
		if (llist_empty(&mgw->cell_list))
			osmo_fsm_inst_dispatch(mgw->fi, VGCS_MGW_EP_EV_CLEAR, NULL);
	}

	LOG_CELL(cell, LOGL_DEBUG, "Detroy connection to cell.\n");

	/* Free FSM. (should be allocated) */
	osmo_fsm_inst_state_chg(cell->fi, VGCS_CELL_ST_NULL, 0, 0);
	osmo_fsm_inst_term(cell->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void vgcs_cell_fsm_null(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss_cell *cell = fi->priv;
	const struct codec_mapping *cm;
	int rc;

	switch (event) {
	case VGCS_CELL_EV_ASSIGN:
		LOG_CELL(cell, LOGL_DEBUG, "Received assignment from BSS controling process.\n");
		/* Allocate rtps stream. */
		cell->rtps = rtp_stream_alloc(cell->fi, VGCS_CELL_EV_RTP_STREAM_GONE,
					      VGCS_CELL_EV_RTP_STREAM_ADDR_AVAILABLE,
					      VGCS_CELL_EV_RTP_STREAM_ESTABLISHED, RTP_TO_RAN, cell->call_id,
					      NULL);
		if (!cell->rtps) {
			LOG_CELL(cell, LOGL_DEBUG, "Failed to allocate RTP stream, cannot continue.\n");
			cell_destroy(cell);
			break;
		}
		/* Hard coded codec: GSM V1 */
		cm = codec_mapping_by_gsm0808_speech_codec_type(GSM0808_SCT_FR1);
		if (!cm) {
			LOG_CELL(cell, LOGL_DEBUG, "Selected codec not supported, cannot continue.\n");
			cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			break;
		}
		rtp_stream_set_one_codec(cell->rtps, &cm->sdp);
		/* Set initial mode. */
		rtp_stream_set_mode(cell->rtps, MGCP_CONN_RECV_ONLY);
		/* Commit RTP stream. */
		if (!cell->bss || !cell->bss->trans) {
			LOG_CELL(cell, LOGL_DEBUG, "No BSS/transaction, cannot continue.\n");
			cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			break;
		}
		if (!cell->mgw || !cell->mgw->mgw_ep) {
			LOG_CELL(cell, LOGL_DEBUG, "No MGW endpoint, cannot continue.\n");
			cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			break;
		}
		rc = rtp_stream_ensure_ci(cell->rtps, cell->mgw->mgw_ep);
		if (rc < 0) {
			LOG_CELL(cell, LOGL_DEBUG, "Failed to trigger RTP stream CI.\n");
			cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			break;
		}
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_CELL_ST_ASSIGNMENT, 0, 0);
		break;
	case VGCS_CELL_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_CELL(cell, LOGL_DEBUG, "Received clearing from BSS controling process.\n");
		cell_clear(cell, GSM0808_CAUSE_CALL_CONTROL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_cell_fsm_assignment(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss_cell *cell = fi->priv;
	struct ran_msg *rx_ran_msg = data;
	struct ran_msg tx_ran_msg;
	struct osmo_sockaddr_str ss;
	const struct codec_mapping *cm;
	struct vgcs_bss *bss;
	int rc;

	switch (event) {
	case VGCS_CELL_EV_RTP_STREAM_GONE:
		/* The RTP stream failed. */
		LOG_CELL(cell, LOGL_ERROR, "RTP stream of MGW failed.\n");
		cell->rtps = NULL;
		goto channel_fail;
		break;
	case VGCS_CELL_EV_RTP_STREAM_ADDR_AVAILABLE:
		/* The RTP stream sends its peer. */
		if (!osmo_sockaddr_str_is_nonzero(&cell->rtps->local)) {
			LOG_CELL(cell, LOGL_ERROR, "Invalid RTP address received from MGW: " OSMO_SOCKADDR_STR_FMT "\n",
				OSMO_SOCKADDR_STR_FMT_ARGS(&cell->rtps->local));
			goto channel_fail;
		}
		LOG_CELL(cell, LOGL_DEBUG,
			"MGW endpoint's RTP address available for the CI %s: " OSMO_SOCKADDR_STR_FMT " (osmux=%s:%d)\n",
			rtp_direction_name(cell->rtps->dir), OSMO_SOCKADDR_STR_FMT_ARGS(&cell->rtps->local),
			cell->rtps->use_osmux ? "yes" : "no", cell->rtps->local_osmux_cid);
		/* Send VGCS/VBS ASSIGNMENT REQUEST to BSS */
		LOG_CELL(cell, LOGL_DEBUG, "Sending VGCS/VBS ASSIGNMENT REQUEST towards BSS.\n");
		tx_ran_msg = (struct ran_msg) {
			.msg_type = RAN_MSG_VGCS_VBS_ASSIGN_REQ,
			.vgcs_vbs_assign_req = {
				/* For now we support GSM/FR V1 only. This shall be supported by all MS. */
				.channel_type = {
					.ch_indctr = GSM0808_CHAN_SPEECH,
					.ch_rate_type = GSM0808_SPEECH_FULL_BM,
					.perm_spch_len = 1,
					.perm_spch[0] = GSM0808_PERM_FR1,
				},
				/* For now we want a channel without any delay. */
				.ass_req = GSM0808_ASRQ_IMMEDIATE,
				.callref = {
					.sf = (cell->trans_type == TRANS_GCC),
				},
				/* We need to identify the cell only. */
				.cell_identifier = {
					.id_discr = CELL_IDENT_CI,
					.id.ci = cell->cell_id,
				},
				.aoip_transport_layer_present = true,
				.call_id_present = true,
				.call_id = cell->call_id,
				.codec_list_present = true,
				.codec_list_msc_preferred = {
					.len = 1,
					.codec[0] = {
						.fi = 1,
						.type = GSM0808_SCT_FR1,
						.cfg = 0,
					},
				},
			},
		};
		osmo_store32be_ext(cell->callref >> 3, &tx_ran_msg.vgcs_vbs_assign_req.callref.call_ref_hi, 3);
		tx_ran_msg.vgcs_vbs_assign_req.callref.call_ref_lo = cell->callref & 0x7;
		osmo_sockaddr_str_to_sockaddr(&cell->rtps->local, &tx_ran_msg.vgcs_vbs_assign_req.aoip_transport_layer);
		/* First message, so we must set "initial" to "true". */
		ran_encode_and_send(fi, &tx_ran_msg, cell->conn, true);
		break;
	case VGCS_CELL_EV_RTP_STREAM_ESTABLISHED:
		/* The RTP stream established. */
		LOG_CELL(cell, LOGL_DEBUG, "RTP stream is established.\n");
		break;
	case VGCS_CELL_EV_ASSIGN_RES:
		/* Receive VGCS/VBS ASSIGNMENT RESULT from BSS. */
		LOG_CELL(cell, LOGL_DEBUG, "Received VGCS/VBS ASSIGNMENT RESULT from BSS.\n");
		cell->assigned = true;
		if (!rx_ran_msg->vgcs_vbs_assign_res.aoip_transport_layer_present
		 && !rx_ran_msg->vgcs_vbs_assign_res.codec_present
		 && !rx_ran_msg->vgcs_vbs_assign_res.call_id_present) {
			LOG_CELL(cell, LOGL_ERROR, "Mandatory IEs missing.\n");
			goto channel_fail;
		}
		/* Send remote peer to RTP stream. */
		if (osmo_sockaddr_str_from_sockaddr(&ss, &rx_ran_msg->vgcs_vbs_assign_res.aoip_transport_layer)) {
			LOG_CELL(cell, LOGL_ERROR, "Cannot RTP-CONNECT, invalid RTP IP:port in incoming MNCC "
				 "message\n");
			goto channel_fail;
		}
		rtp_stream_set_remote_addr(cell->rtps, &ss);
		/* Send remote codec to RTP stream. */
		cm = codec_mapping_by_gsm0808_speech_codec_type(rx_ran_msg->vgcs_vbs_assign_res.codec_msc_chosen.type);
		if (!cm) {
			LOG_CELL(cell, LOGL_ERROR, "Chosen codec by BSC is not supported by MSC.\n");
			goto channel_fail;
		}
		rtp_stream_set_one_codec(cell->rtps, &cm->sdp);
		/* Set listening mode. */
		rtp_stream_set_mode(cell->rtps, MGCP_CONN_SEND_ONLY);
		/* Commit RTP stream. */
		rc = rtp_stream_commit(cell->rtps);
		if (rc < 0) {
			LOG_CELL(cell, LOGL_ERROR, "Failed to commit parameters to RTP stream.\n");
			goto channel_fail;
		}
		/* Change state. */
		osmo_fsm_inst_state_chg(fi, VGCS_CELL_ST_ACTIVE, 0, 0);
		/* Notify BSS FSM about channel activation. */
		if (cell->bss)
			osmo_fsm_inst_dispatch(cell->bss->fi, VGCS_BSS_EV_ACTIVE_OR_FAIL, NULL);
		break;
	case VGCS_CELL_EV_ASSIGN_FAIL:
		/* Received VGCS/VBS ASSIGNMENT FAILURE from BSS. */
		LOG_CELL(cell, LOGL_NOTICE, "Received VGCS/VBS ASSIGNMENT FAILURE from BSS.\n");
channel_fail:
		bss = cell->bss;
		cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		/* Notify BSS FSM about channel failure. */
		if (bss)
			osmo_fsm_inst_dispatch(bss->fi, VGCS_BSS_EV_ACTIVE_OR_FAIL, NULL);
		break;
	case VGCS_CELL_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_CELL(cell, LOGL_DEBUG, "Received clearing from BSS controling process.\n");
		cell_clear(cell, GSM0808_CAUSE_CALL_CONTROL);
		break;
	case VGCS_CELL_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed. */
		LOG_CELL(cell, LOGL_NOTICE, "Received SCCP connecting closing from MSC.\n");
		if (cell->conn) {
			cell->conn->vgcs.bss = NULL;
			cell->conn = NULL;
		}
		cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_cell_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss_cell *cell = fi->priv;

	switch (event) {
	case VGCS_CELL_EV_RTP_STREAM_GONE:
		/* The RTP stream failed. */
		LOG_CELL(cell, LOGL_ERROR, "RTP stream of MGW failed.\n");
		cell->rtps = NULL;
		cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		break;
	case VGCS_CELL_EV_RTP_STREAM_ESTABLISHED:
		/* The RTP stream established. */
		LOG_CELL(cell, LOGL_DEBUG, "RTP stream is established.\n");
		break;
	case VGCS_CELL_EV_CLEAR:
		/* The calling user process requested clearing of VGCS/VBS call. */
		LOG_CELL(cell, LOGL_DEBUG, "Received clearing from BSS controling process.\n");
		cell_clear(cell, GSM0808_CAUSE_CALL_CONTROL);
		break;
	case VGCS_CELL_EV_CLOSE:
		/* The SCCP connection from the MSC has been closed. */
		LOG_CELL(cell, LOGL_NOTICE, "Received SCCP connecting closing from MSC.\n");
		if (cell->conn) {
			cell->conn->vgcs.bss = NULL;
			cell->conn = NULL;
		}
		cell_clear(cell, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void vgcs_cell_fsm_release(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_bss_cell *cell = fi->priv;

	switch (event) {
	case VGCS_CELL_EV_RTP_STREAM_GONE:
		/* The RTP stream gone. */
		LOG_CELL(cell, LOGL_ERROR, "RTP stream gone.\n");
		cell->rtps = NULL;
		/* Wait for RAN conn. */
		if (cell->conn)
			break;
		cell_destroy(cell);
		break;
	case VGCS_CELL_EV_CLEAR:
	case VGCS_CELL_EV_RELEASED:
		if (event == VGCS_CELL_EV_CLEAR) {
			/* The SCCP connection from the MSC has been closed while waiting for CLEAR COMPLETE. */
			LOG_CELL(cell, LOGL_NOTICE, "Received SCCP closing collision.\n");
		} else
			LOG_CELL(cell, LOGL_DEBUG, "Received CLEAR COMPLETE from BSS, we are done!\n");
		/* Wait for RTP stream. */
		if (cell->rtps) {
			/* close RAN conn */
			if (cell->conn) {
				cell->conn->vgcs.cell = NULL;
				ran_conn_close(cell->conn);
				cell->conn = NULL;
			}
			break;
		}
		cell_destroy(cell);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_cell_fsm_states[] = {
	[VGCS_CELL_ST_NULL] = {
		.name = "NULL",
		.in_event_mask = S(VGCS_CELL_EV_ASSIGN) |
				 S(VGCS_CELL_EV_CLEAR),
		.out_state_mask = S(VGCS_CELL_ST_ASSIGNMENT),
		.action = vgcs_cell_fsm_null,
	},
	[VGCS_CELL_ST_ASSIGNMENT] = {
		.name = "ASSIGNMENT Sent",
		.in_event_mask = S(VGCS_CELL_EV_RTP_STREAM_GONE) |
				 S(VGCS_CELL_EV_RTP_STREAM_ADDR_AVAILABLE) |
				 S(VGCS_CELL_EV_RTP_STREAM_ESTABLISHED) |
				 S(VGCS_CELL_EV_ASSIGN_RES) |
				 S(VGCS_CELL_EV_ASSIGN_FAIL) |
				 S(VGCS_CELL_EV_CLEAR) |
				 S(VGCS_CELL_EV_CLOSE),
		.out_state_mask = S(VGCS_CELL_ST_ACTIVE) |
				  S(VGCS_CELL_ST_RELEASE),
		.action = vgcs_cell_fsm_assignment,
	},
	[VGCS_CELL_ST_ACTIVE] = {
		.name = "VGCS/VBS channel active",
		.in_event_mask = S(VGCS_CELL_EV_RTP_STREAM_GONE) |
				 S(VGCS_CELL_EV_RTP_STREAM_ESTABLISHED) |
				 S(VGCS_CELL_EV_CLEAR) |
				 S(VGCS_CELL_EV_CLOSE),
		.out_state_mask = S(VGCS_CELL_ST_RELEASE),
		.action = vgcs_cell_fsm_active,
	},
	[VGCS_CELL_ST_RELEASE] = {
		.name = "Releasing VGCS/VBS channel",
		.in_event_mask = S(VGCS_CELL_EV_RTP_STREAM_GONE) |
				 S(VGCS_CELL_EV_CLEAR) |
				 S(VGCS_CELL_EV_RELEASED),
		.out_state_mask = S(VGCS_CELL_ST_NULL),
		.action = vgcs_cell_fsm_release,
	},
};

static struct osmo_fsm vgcs_cell_fsm = {
	.name = "vgcs_cell",
	.states = vgcs_cell_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_cell_fsm_states),
	.log_subsys = DASCI,
	.event_names = vgcs_cell_fsm_event_names,
};

/* The BSS accepts VGCS/VBS channel assignment. */
void vgcs_vbs_assign_result(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg)
{
	osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_ASSIGN_RES, (void *)ran_msg);
}

/* The BSS refuses VGCS/VBS channel assignment. */
void vgcs_vbs_assign_fail(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg)
{
	osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_ASSIGN_FAIL, (void *)ran_msg);
}

/* BSS indicated that the channel has been released. */
void vgcs_vbs_clear_req_channel(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg)
{
	LOG_CELL(cell, LOGL_DEBUG, "Received CLEAR REQUEST for resource controling channel from BSS.\n");
	osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_CLOSE, (void *)ran_msg);
}

/* BSS confirms the release of channel. */
void vgcs_vbs_clear_cpl_channel(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg)
{
	LOG_CELL(cell, LOGL_DEBUG, "Received CLEAR COMPLETE for resource controling channel from BSS.\n");
	osmo_fsm_inst_dispatch(cell->fi, VGCS_CELL_EV_RELEASED, (void *)ran_msg);
}

/*
 * MGW endpoint FSM
 */

static const struct value_string vgcs_mgw_ep_fsm_event_names[] = {
	OSMO_VALUE_STRING(VGCS_MGW_EP_EV_FREE),
	OSMO_VALUE_STRING(VGCS_MGW_EP_EV_CLEAR),
	{ }
};

static void vgcs_mgw_ep_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct vgcs_mgw_ep *mgw = fi->priv;
	struct vgcs_bss_cell *cell, *cell2;
	struct mgcp_client *mgcp_client;

	switch (event) {
	case VGCS_MGW_EP_EV_FREE:
		LOGP(DASCI, LOGL_DEBUG, "MGW connection closed, removing all cell instances.\n");
		llist_for_each_entry_safe(cell, cell2, &mgw->cell_list, list_mgw) {
			if (cell->rtps)
				cell->rtps->ci = NULL;
			llist_del(&cell->list_mgw);
			cell->mgw = NULL;
		}
		/* Put MGCP client back into MGW pool. */
		mgcp_client = osmo_mgcpc_ep_client(mgw->mgw_ep);
		mgcp_client_pool_put(mgcp_client);
		/* Destroy this instance. */
		osmo_fsm_inst_term_children(fi, OSMO_FSM_TERM_PARENT, NULL);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case VGCS_MGW_EP_EV_CLEAR:
		if (!llist_empty(&mgw->cell_list))
			break;
		LOGP(DASCI, LOGL_DEBUG, "Cell list of MGW instance is now empty, dropping.\n");
		/* Destroy this instance. */
		osmo_fsm_inst_term_children(fi, OSMO_FSM_TERM_PARENT, NULL);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static const struct osmo_fsm_state vgcs_mgw_ep_fsm_states[] = {
	[VGCS_MGW_EP_ST_NULL] = {
		.name = "NULL",
		.out_state_mask = S(VGCS_MGW_EP_ST_ACTIVE),
	},
	[VGCS_MGW_EP_ST_ACTIVE] = {
		.name = "MGW endpoint allocated",
		.in_event_mask = S(VGCS_MGW_EP_EV_FREE) |
				 S(VGCS_MGW_EP_EV_CLEAR),
		.out_state_mask = S(VGCS_MGW_EP_ST_NULL),
		.action = vgcs_mgw_ep_fsm_active,
	},
};

static struct osmo_fsm vgcs_mgw_ep_fsm = {
	.name = "vgcs_mgw_ep",
	.states = vgcs_mgw_ep_fsm_states,
	.num_states = ARRAY_SIZE(vgcs_mgw_ep_fsm_states),
	.log_subsys = DASCI,
	.event_names = vgcs_mgw_ep_fsm_event_names,
};
