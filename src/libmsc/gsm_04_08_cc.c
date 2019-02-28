/* GSM Mobile Radio Interface Layer 3 Call Control */

/* (C) 2008-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
 * All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <regex.h>
#include <sys/types.h>

#include "bscconfig.h"

#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_04_14.h>
#include <osmocom/msc/gsm_09_11.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/silent_call.h>
#include <osmocom/msc/mncc_int.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msc_ifaces.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/crypt/auth.h>
#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/msc_mgcp.h>

#include <assert.h>

static uint32_t new_callref = 0x80000001;

static void gsm48_cc_guard_timeout(void *arg)
{
	struct gsm_trans *trans = arg;
	LOG_TRANS(trans, LOGL_DEBUG, "guard timeout expired\n");
	trans_free(trans);
	return;
}

static void gsm48_stop_guard_timer(struct gsm_trans *trans)
{
	if (osmo_timer_pending(&trans->cc.timer_guard)) {
		LOG_TRANS(trans, LOGL_DEBUG, "stopping pending guard timer\n");
		osmo_timer_del(&trans->cc.timer_guard);
	}
}

static void gsm48_start_guard_timer(struct gsm_trans *trans)
{
	/* NOTE: The purpose of this timer is to prevent the cc state machine
	 * from hanging in cases where mncc, gsm48 or both become unresponsive
	 * for some reason. The timer is started initially with the setup from
	 * the gsm48 side and then re-started with every incoming mncc message.
	 * Once the mncc state reaches its active state the timer is stopped.
	 * So if the cc state machine does not show any activity for an
	 * extended amount of time during call setup or teardown the guard
	 * timer will time out and hard-clear the connection. */
	if (osmo_timer_pending(&trans->cc.timer_guard))
		gsm48_stop_guard_timer(trans);
	LOG_TRANS(trans, LOGL_DEBUG, "starting guard timer with %d seconds\n", trans->net->mncc_guard_timeout);
	osmo_timer_setup(&trans->cc.timer_guard, gsm48_cc_guard_timeout, trans);
	osmo_timer_schedule(&trans->cc.timer_guard,
			    trans->net->mncc_guard_timeout, 0);
}

/* Call Control */

void cc_tx_to_mncc(struct gsm_network *net, struct msgb *msg)
{
	net->mncc_recv(net, msg);
}

int gsm48_cc_tx_notify_ss(struct gsm_trans *trans, const char *message)
{
	struct gsm48_hdr *gh;
	struct msgb *ss_notify;

	ss_notify = gsm0480_create_notifySS(message);
	if (!ss_notify)
		return -1;

	gsm0480_wrap_invoke(ss_notify, GSM0480_OP_CODE_NOTIFY_SS, 0);
	uint8_t *data = msgb_push(ss_notify, 1);
	data[0] = ss_notify->len - 1;
	gh = (struct gsm48_hdr *) msgb_push(ss_notify, sizeof(*gh));
	gh->msg_type = GSM48_MT_CC_FACILITY;
	return gsm48_conn_sendmsg(ss_notify, trans->conn, trans);
}

/* FIXME: this count_statistics is a state machine behaviour. we should convert
 * the complete call control into a state machine. Afterwards we can move this
 * code into state transitions.
 */
static void count_statistics(struct gsm_trans *trans, int new_state)
{
	int old_state = trans->cc.state;
	struct rate_ctr_group *msc = trans->net->msc_ctrs;

	if (old_state == new_state)
		return;

	/* state incoming */
	switch (new_state) {
	case GSM_CSTATE_ACTIVE:
		osmo_counter_inc(trans->net->active_calls);
		rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_ACTIVE]);
		break;
	}

	/* state outgoing */
	switch (old_state) {
	case GSM_CSTATE_ACTIVE:
		osmo_counter_dec(trans->net->active_calls);
		if (new_state == GSM_CSTATE_DISCONNECT_REQ ||
				new_state == GSM_CSTATE_DISCONNECT_IND)
			rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_COMPLETE]);
		else
			rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_INCOMPLETE]);
		break;
	}
}

/* The entire call control code is written in accordance with Figure 7.10c
 * for 'very early assignment', i.e. we allocate a TCH/F during IMMEDIATE
 * ASSIGN, then first use that TCH/F for signalling and later MODE MODIFY
 * it for voice */

static void new_cc_state(struct gsm_trans *trans, int state)
{
	if (state > 31 || state < 0)
		return;

	LOG_TRANS(trans, LOGL_DEBUG, "new state %s -> %s\n",
		  gsm48_cc_state_name(trans->cc.state),
		  gsm48_cc_state_name(state));

	count_statistics(trans, state);
	trans->cc.state = state;

	/* Stop the guard timer when a call reaches the active state */
	if (state == GSM_CSTATE_ACTIVE)
		gsm48_stop_guard_timer(trans);
}

static int gsm48_cc_tx_status(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC STATUS");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t *cause, *call_state;

	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static void gsm48_stop_cc_timer(struct gsm_trans *trans)
{
	if (osmo_timer_pending(&trans->cc.timer)) {
		LOG_TRANS(trans, LOGL_DEBUG, "stopping pending timer T%x\n", trans->cc.Tcurrent);
		osmo_timer_del(&trans->cc.timer);
		trans->cc.Tcurrent = 0;
	}
}

static int mncc_recvmsg(struct gsm_network *net, struct gsm_trans *trans,
			int msg_type, struct gsm_mncc *mncc)
{
	struct msgb *msg;
	unsigned char *data;

	LOG_TRANS_CAT(trans, DMNCC, LOGL_DEBUG, "tx %s\n", get_mncc_name(msg_type));

	mncc->msg_type = msg_type;

	msg = msgb_alloc(sizeof(struct gsm_mncc), "MNCC");
	if (!msg)
		return -ENOMEM;

	data = msgb_put(msg, sizeof(struct gsm_mncc));
	memcpy(data, mncc, sizeof(struct gsm_mncc));

	cc_tx_to_mncc(net, msg);

	return 0;
}

int mncc_release_ind(struct gsm_network *net, struct gsm_trans *trans,
		     uint32_t callref, int location, int value)
{
	struct gsm_mncc rel;

	memset(&rel, 0, sizeof(rel));
	rel.callref = callref;
	mncc_set_cause(&rel, location, value);
	if (trans && trans->cc.state == GSM_CSTATE_RELEASE_REQ)
		return mncc_recvmsg(net, trans, MNCC_REL_CNF, &rel);
	return mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
}

/* Call Control Specific transaction release.
 * gets called by trans_free, DO NOT CALL YOURSELF! */
void _gsm48_cc_trans_free(struct gsm_trans *trans)
{
	gsm48_stop_cc_timer(trans);

	/* Initiate the teardown of the related connections on the MGW */
	msc_mgcp_call_release(trans);

	/* send release to L4, if callref still exists */
	if (trans->callref) {
		/* Ressource unavailable */
		mncc_release_ind(trans->net, trans, trans->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		/* This is a final freeing of the transaction. The MNCC release may have triggered the
		 * T308 release timer, but we don't have the luxury of graceful CC Release here. */
		gsm48_stop_cc_timer(trans);
	}
	if (trans->cc.state != GSM_CSTATE_NULL)
		new_cc_state(trans, GSM_CSTATE_NULL);

	gsm48_stop_guard_timer(trans);
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg);

/* call-back from paging the B-end of the connection */
static int setup_trig_pag_evt(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_conn, void *_transt)
{
	struct ran_conn *conn = _conn;
	struct gsm_trans *transt = _transt;
	enum gsm_paging_event paging_event = event;

	OSMO_ASSERT(!transt->conn);

	switch (paging_event) {
	case GSM_PAGING_SUCCEEDED:
		LOG_TRANS(transt, LOGL_DEBUG, "Paging succeeded\n");
		OSMO_ASSERT(conn);
		/* Assign conn */
		transt->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_CC);
		transt->paging_request = NULL;
		/* send SETUP request to called party */
		gsm48_cc_tx_setup(transt, &transt->cc.msg);
		break;
	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_BUSY:
		LOG_TRANS(transt, LOGL_DEBUG, "Paging expired\n");
		/* Temporarily out of order */
		mncc_release_ind(transt->net, transt,
				 transt->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_DEST_OOO);
		transt->callref = 0;
		transt->paging_request = NULL;
		trans_free(transt);
		break;
	}

	return 0;
}

/* bridge channels of two transactions */
static int tch_bridge(struct gsm_network *net, struct gsm_mncc_bridge *bridge)
{
	struct gsm_trans *trans1 = trans_find_by_callref(net, bridge->callref[0]);
	struct gsm_trans *trans2 = trans_find_by_callref(net, bridge->callref[1]);
	int rc;

	if (!trans1 || !trans2) {
		LOG_TRANS(trans1 ? : trans2, LOGL_ERROR, "Cannot MNCC_BRIDGE, one or both call legs are unset\n");
		return -EIO;
	}

	if (!trans1->conn || !trans2->conn) {
		LOG_TRANS(trans1, LOGL_ERROR, "Cannot MNCC_BRIDGE, one or both call legs lack an active connection\n");
		LOG_TRANS(trans2, LOGL_ERROR, "Cannot MNCC_BRIDGE, one or both call legs lack an active connection\n");
		return -EIO;
	}

	LOG_TRANS(trans1, LOGL_DEBUG, "MNCC_BRIDGE: Local bridge to callref 0x%x\n", trans2->callref);
	LOG_TRANS(trans2, LOGL_DEBUG, "MNCC_BRIDGE: Local bridge to callref 0x%x\n", trans1->callref);

	/* Which subscriber do we want to track trans1 or trans2? */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans1->vsub);

	/* This call briding mechanism is only used with the internal MNCC.
	 * functionality (with external MNCC briding would be done by the PBX)
	 * This means we may just copy the codec info we have for the RAN side
	 * of the first leg to the CN side of both legs. This also means that
	 * if both legs use different codecs the MGW must perform transcoding
	 * on the second leg. */
	trans1->conn->rtp.codec_cn = trans1->conn->rtp.codec_ran;
	trans2->conn->rtp.codec_cn = trans1->conn->rtp.codec_ran;

	/* Bridge RTP streams */
	rc = msc_mgcp_call_complete(trans1, trans2->conn->rtp.local_port_cn,
				    trans2->conn->rtp.local_addr_cn);
	if (rc)
		return -EINVAL;

	rc = msc_mgcp_call_complete(trans2, trans1->conn->rtp.local_port_cn,
				    trans1->conn->rtp.local_addr_cn);
	if (rc)
		return -EINVAL;

	return 0;
}

static int gsm48_cc_rx_status_enq(struct gsm_trans *trans, struct msgb *msg)
{
	LOG_TRANS(trans, LOGL_DEBUG, "-> STATUS ENQ\n");
	return gsm48_cc_tx_status(trans, msg);
}

static int gsm48_cc_tx_release(struct gsm_trans *trans, void *arg);
static int gsm48_cc_tx_disconnect(struct gsm_trans *trans, void *arg);

static void gsm48_cc_timeout(void *arg)
{
	struct gsm_trans *trans = arg;
	int disconnect = 0, release = 0;
	int mo_cause = GSM48_CC_CAUSE_RECOVERY_TIMER;
	int mo_location = GSM48_CAUSE_LOC_USER;
	int l4_cause = GSM48_CC_CAUSE_NORMAL_UNSPEC;
	int l4_location = GSM48_CAUSE_LOC_PRN_S_LU;
	struct gsm_mncc mo_rel, l4_rel;

	memset(&mo_rel, 0, sizeof(struct gsm_mncc));
	mo_rel.callref = trans->callref;
	memset(&l4_rel, 0, sizeof(struct gsm_mncc));
	l4_rel.callref = trans->callref;

	switch(trans->cc.Tcurrent) {
	case 0x303:
		release = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x310:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x313:
		disconnect = 1;
		/* unknown, did not find it in the specs */
		break;
	case 0x301:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x308:
		if (!trans->cc.T308_second) {
			/* restart T308 a second time */
			gsm48_cc_tx_release(trans, &trans->cc.msg);
			trans->cc.T308_second = 1;
			break; /* stay in release state */
		}
		trans_free(trans);
		return;
	case 0x306:
		release = 1;
		mo_cause = trans->cc.msg.cause.value;
		mo_location = trans->cc.msg.cause.location;
		break;
	case 0x323:
		disconnect = 1;
		break;
	default:
		release = 1;
	}

	if (release && trans->callref) {
		/* process release towards layer 4 */
		mncc_release_ind(trans->net, trans, trans->callref,
				 l4_location, l4_cause);
		trans->callref = 0;
	}

	if (disconnect && trans->callref) {
		/* process disconnect towards layer 4 */
		mncc_set_cause(&l4_rel, l4_location, l4_cause);
		mncc_recvmsg(trans->net, trans, MNCC_DISC_IND, &l4_rel);
	}

	/* process disconnect towards mobile station */
	if (disconnect || release) {
		mncc_set_cause(&mo_rel, mo_location, mo_cause);
		mo_rel.cause.diag[0] = ((trans->cc.Tcurrent & 0xf00) >> 8) + '0';
		mo_rel.cause.diag[1] = ((trans->cc.Tcurrent & 0x0f0) >> 4) + '0';
		mo_rel.cause.diag[2] = (trans->cc.Tcurrent & 0x00f) + '0';
		mo_rel.cause.diag_len = 3;

		if (disconnect)
			gsm48_cc_tx_disconnect(trans, &mo_rel);
		if (release)
			gsm48_cc_tx_release(trans, &mo_rel);
	}

}

/* disconnect both calls from the bridge */
static inline void disconnect_bridge(struct gsm_network *net,
				     struct gsm_mncc_bridge *bridge, int err)
{
	struct gsm_trans *trans0 = trans_find_by_callref(net, bridge->callref[0]);
	struct gsm_trans *trans1 = trans_find_by_callref(net, bridge->callref[1]);
	struct gsm_mncc mx_rel;
	if (!trans0 || !trans1)
		return;

	LOG_TRANS(trans0, LOGL_ERROR, "Failed to bridge TCH for calls %x <-> %x :: %s \n",
	       trans0->callref, trans1->callref, strerror(err));
	LOG_TRANS(trans1, LOGL_ERROR, "Failed to bridge TCH for calls %x <-> %x :: %s \n",
	       trans0->callref, trans1->callref, strerror(err));

	memset(&mx_rel, 0, sizeof(struct gsm_mncc));
	mncc_set_cause(&mx_rel, GSM48_CAUSE_LOC_INN_NET,
		       GSM48_CC_CAUSE_CHAN_UNACCEPT);

	mx_rel.callref = trans0->callref;
	gsm48_cc_tx_disconnect(trans0, &mx_rel);

	mx_rel.callref = trans1->callref;
	gsm48_cc_tx_disconnect(trans1, &mx_rel);
}

static void gsm48_start_cc_timer(struct gsm_trans *trans, int current,
				 int sec, int micro)
{
	LOG_TRANS(trans, LOGL_DEBUG, "starting timer T%x with %d seconds\n", current, sec);
	osmo_timer_setup(&trans->cc.timer, gsm48_cc_timeout, trans);
	osmo_timer_schedule(&trans->cc.timer, sec, micro);
	trans->cc.Tcurrent = current;
}

static int gsm48_cc_rx_setup(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc setup;

	gsm48_start_guard_timer(trans);

	memset(&setup, 0, sizeof(struct gsm_mncc));
	setup.callref = trans->callref;

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* emergency setup is identified by msg_type */
	if (msg_type == GSM48_MT_CC_EMERG_SETUP) {
		setup.fields |= MNCC_F_EMERGENCY;
		setup.emergency = 1;
		/* use destination number as configured by user (if any) */
		if (trans->net->emergency.route_to_msisdn) {
			setup.fields |= MNCC_F_CALLED;
			setup.called.type = 0; /* unknown */
			setup.called.plan = 0; /* unknown */
			OSMO_STRLCPY_ARRAY(setup.called.number,
					   trans->net->emergency.route_to_msisdn);
		}
	}

	/* use subscriber as calling party number */
	setup.fields |= MNCC_F_CALLING;
	OSMO_STRLCPY_ARRAY(setup.calling.number, trans->vsub->msisdn);
	OSMO_STRLCPY_ARRAY(setup.imsi, trans->vsub->imsi);

	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		setup.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&setup.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&setup.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		setup.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&setup.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* called party bcd number */
	if (TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		setup.fields |= MNCC_F_CALLED;
		gsm48_decode_called(&setup.called,
			      TLVP_VAL(&tp, GSM48_IE_CALLED_BCD)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		setup.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&setup.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		setup.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&setup.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}
	/* CLIR suppression */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_SUPP))
		setup.clir.sup = 1;
	/* CLIR invocation */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_INVOC))
		setup.clir.inv = 1;
	/* cc cap */
	if (TLVP_PRESENT(&tp, GSM48_IE_CC_CAP)) {
		setup.fields |= MNCC_F_CCCAP;
		gsm48_decode_cccap(&setup.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_INITIATED);

	LOG_TRANS(trans, setup.emergency ? LOGL_NOTICE : LOGL_INFO, "%sSETUP to %s\n",
		  setup.emergency ? "EMERGENCY_" : "", setup.called.number);

	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP]);

	/* indicate setup to MNCC */
	mncc_recvmsg(trans->net, trans, MNCC_SETUP_IND, &setup);

	/* MNCC code will modify the channel asynchronously, we should
	 * ipaccess-bind only after the modification has been made to the
	 * lchan->tch_mode */
	return 0;
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC STUP");
	struct gsm48_hdr *gh;
	struct gsm_mncc *setup = arg;
	int rc, trans_id;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	/* transaction id must not be assigned */
	if (trans->transaction_id != TRANS_ID_UNASSIGNED) {
		LOG_TRANS(trans, LOGL_DEBUG, "TX Setup with assigned transaction. "
			"This is not allowed!\n");
		/* Temporarily out of order */
		rc = mncc_release_ind(trans->net, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}

	/* Get free transaction_id */
	trans_id = trans_assign_trans_id(trans->net, trans->vsub, GSM48_PDISC_CC);
	if (trans_id < 0) {
		/* no free transaction ID */
		rc = mncc_release_ind(trans->net, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}
	trans->transaction_id = trans_id;

	gh->msg_type = GSM48_MT_CC_SETUP;

	gsm48_start_cc_timer(trans, 0x303, GSM48_T303);

	/* bearer capability */
	if (setup->fields & MNCC_F_BEARER_CAP) {
		/* Create a copy of the bearer capability in the transaction struct, so we
		 * can use this information later */
		memcpy(&trans->bearer_cap, &setup->bearer_cap, sizeof(trans->bearer_cap));
		gsm48_encode_bearer_cap(msg, 0, &setup->bearer_cap);
	}
	/* facility */
	if (setup->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &setup->facility);
	/* progress */
	if (setup->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &setup->progress);
	/* calling party BCD number */
	if (setup->fields & MNCC_F_CALLING)
		gsm48_encode_calling(msg, &setup->calling);
	/* called party BCD number */
	if (setup->fields & MNCC_F_CALLED)
		gsm48_encode_called(msg, &setup->called);
	/* user-user */
	if (setup->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &setup->useruser);
	/* redirecting party BCD number */
	if (setup->fields & MNCC_F_REDIRECTING)
		gsm48_encode_redirecting(msg, &setup->redirecting);
	/* signal */
	if (setup->fields & MNCC_F_SIGNAL)
		gsm48_encode_signal(msg, setup->signal);

	new_cc_state(trans, GSM_CSTATE_CALL_PRESENT);

	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MT_SETUP]);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_call_conf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc call_conf;
	int rc;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x310, GSM48_T310);

	memset(&call_conf, 0, sizeof(struct gsm_mncc));
	call_conf.callref = trans->callref;

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
#if 0
	/* repeat */
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_CIR))
		call_conf.repeat = 1;
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_SEQ))
		call_conf.repeat = 2;
#endif
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		call_conf.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&call_conf.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&call_conf.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		call_conf.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&call_conf.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* cc cap */
	if (TLVP_PRESENT(&tp, GSM48_IE_CC_CAP)) {
		call_conf.fields |= MNCC_F_CCCAP;
		gsm48_decode_cccap(&call_conf.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	/* IMSI of called subscriber */
	OSMO_STRLCPY_ARRAY(call_conf.imsi, trans->vsub->imsi);

	new_cc_state(trans, GSM_CSTATE_MO_TERM_CALL_CONF);

	/* Assign call (if not done yet) */
	rc = msc_mgcp_try_call_assignment(trans);

	/* don't continue, if there were problems with
	 * the call assignment. */
	if (rc)
		return rc;

	return mncc_recvmsg(trans->net, trans, MNCC_CALL_CONF_IND,
			    &call_conf);
}

static int gsm48_cc_tx_call_proc_and_assign(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *proceeding = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC PROC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	int rc;

	gh->msg_type = GSM48_MT_CC_CALL_PROC;

	new_cc_state(trans, GSM_CSTATE_MO_CALL_PROC);

	/* bearer capability */
	if (proceeding->fields & MNCC_F_BEARER_CAP) {
		gsm48_encode_bearer_cap(msg, 0, &proceeding->bearer_cap);
		memcpy(&trans->bearer_cap, &proceeding->bearer_cap, sizeof(trans->bearer_cap));
	}
	/* facility */
	if (proceeding->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &proceeding->facility);
	/* progress */
	if (proceeding->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &proceeding->progress);

	rc = gsm48_conn_sendmsg(msg, trans->conn, trans);
	if (rc)
		return rc;

	/* Assign call (if not done yet) */
	return msc_mgcp_try_call_assignment(trans);
}

static int gsm48_cc_rx_alerting(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc alerting;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x301, GSM48_T301);

	memset(&alerting, 0, sizeof(struct gsm_mncc));
	alerting.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		alerting.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&alerting.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}

	/* progress */
	if (TLVP_PRESENT(&tp, GSM48_IE_PROGR_IND)) {
		alerting.fields |= MNCC_F_PROGRESS;
		gsm48_decode_progress(&alerting.progress,
				TLVP_VAL(&tp, GSM48_IE_PROGR_IND)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		alerting.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&alerting.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CALL_RECEIVED);

	return mncc_recvmsg(trans->net, trans, MNCC_ALERT_IND,
			    &alerting);
}

static int gsm48_cc_tx_alerting(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *alerting = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC ALERT");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_ALERTING;

	/* facility */
	if (alerting->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &alerting->facility);
	/* progress */
	if (alerting->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &alerting->progress);
	/* user-user */
	if (alerting->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &alerting->useruser);

	new_cc_state(trans, GSM_CSTATE_CALL_DELIVERED);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_progress(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *progress = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC PROGRESS");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_PROGRESS;

	/* progress */
	gsm48_encode_progress(msg, 1, &progress->progress);
	/* user-user */
	if (progress->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &progress->useruser);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_connect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *connect = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSN 04.08 CC CON");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x313, GSM48_T313);

	/* facility */
	if (connect->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &connect->facility);
	/* progress */
	if (connect->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &connect->progress);
	/* connected number */
	if (connect->fields & MNCC_F_CONNECTED)
		gsm48_encode_connected(msg, &connect->connected);
	/* user-user */
	if (connect->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &connect->useruser);

	new_cc_state(trans, GSM_CSTATE_CONNECT_IND);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_connect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc connect;

	gsm48_stop_cc_timer(trans);

	memset(&connect, 0, sizeof(struct gsm_mncc));
	connect.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* use subscriber as connected party number */
	connect.fields |= MNCC_F_CONNECTED;
	OSMO_STRLCPY_ARRAY(connect.connected.number, trans->vsub->msisdn);
	OSMO_STRLCPY_ARRAY(connect.imsi, trans->vsub->imsi);

	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		connect.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&connect.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		connect.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&connect.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		connect.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&connect.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CONNECT_REQUEST);
	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MT_CONNECT]);

	return mncc_recvmsg(trans->net, trans, MNCC_SETUP_CNF, &connect);
}


static int gsm48_cc_rx_connect_ack(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc connect_ack;

	gsm48_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);
	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MO_CONNECT_ACK]);

	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = trans->callref;

	return mncc_recvmsg(trans->net, trans, MNCC_SETUP_COMPL_IND,
			    &connect_ack);
}

static int gsm48_cc_tx_connect_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC CON ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT_ACK;

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_disconnect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc disc;

	gsm48_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_REQ);

	memset(&disc, 0, sizeof(struct gsm_mncc));
	disc.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_CAUSE, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		disc.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&disc.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		disc.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&disc.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		disc.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&disc.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		disc.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&disc.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_DISC_IND, &disc);

}

static struct gsm_mncc_cause default_cause = {
	.location	= GSM48_CAUSE_LOC_PRN_S_LU,
	.coding		= 0,
	.rec		= 0,
	.rec_val	= 0,
	.value		= GSM48_CC_CAUSE_NORMAL_UNSPEC,
	.diag_len	= 0,
	.diag		= { 0 },
};

static int gsm48_cc_tx_disconnect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *disc = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC DISC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_DISCONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x306, GSM48_T306);

	/* cause */
	if (disc->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &disc->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	/* facility */
	if (disc->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &disc->facility);
	/* progress */
	if (disc->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &disc->progress);
	/* user-user */
	if (disc->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &disc->useruser);

	/* store disconnect cause for T306 expiry */
	memcpy(&trans->cc.msg, disc, sizeof(struct gsm_mncc));

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_IND);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_release(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc;

	gsm48_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->cc.state == GSM_CSTATE_RELEASE_REQ) {
		/* release collision 5.4.5 */
		rc = mncc_recvmsg(trans->net, trans, MNCC_REL_CNF, &rel);
	} else {
		rc = gsm48_tx_simple(trans->conn,
				     GSM48_PDISC_CC | (trans->transaction_id << 4),
				     GSM48_MT_CC_RELEASE_COMPL);
		rc = mncc_recvmsg(trans->net, trans, MNCC_REL_IND, &rel);
	}

	new_cc_state(trans, GSM_CSTATE_NULL);

	trans->callref = 0;
	trans_free(trans);

	return rc;
}

static int gsm48_cc_tx_release(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC REL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RELEASE;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x308, GSM48_T308);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &rel->useruser);

	trans->cc.T308_second = 0;
	memcpy(&trans->cc.msg, rel, sizeof(struct gsm_mncc));

	if (trans->cc.state != GSM_CSTATE_RELEASE_REQ)
		new_cc_state(trans, GSM_CSTATE_RELEASE_REQ);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_release_compl(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc = 0;

	gsm48_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->callref) {
		switch (trans->cc.state) {
		case GSM_CSTATE_CALL_PRESENT:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REJ_IND, &rel);
			break;
		case GSM_CSTATE_RELEASE_REQ:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REL_CNF, &rel);
			break;
		default:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REL_IND, &rel);
		}
	}

	trans->callref = 0;
	trans_free(trans);

	return rc;
}

static int gsm48_cc_tx_release_compl(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC REL COMPL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	int ret;

	gh->msg_type = GSM48_MT_CC_RELEASE_COMPL;

	trans->callref = 0;

	gsm48_stop_cc_timer(trans);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &rel->useruser);

	ret =  gsm48_conn_sendmsg(msg, trans->conn, trans);

	trans_free(trans);

	return ret;
}

static int gsm48_cc_rx_facility(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc fac;

	memset(&fac, 0, sizeof(struct gsm_mncc));
	fac.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_FACILITY, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		fac.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&fac.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		fac.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&fac.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_FACILITY_IND, &fac);
}

static int gsm48_cc_tx_facility(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *fac = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC FAC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_FACILITY;

	/* facility */
	gsm48_encode_facility(msg, 1, &fac->facility);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_hold(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc hold;

	memset(&hold, 0, sizeof(struct gsm_mncc));
	hold.callref = trans->callref;
	return mncc_recvmsg(trans->net, trans, MNCC_HOLD_IND, &hold);
}

static int gsm48_cc_tx_hold_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC HLD ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_hold_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *hold_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC HLD REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_REJ;

	/* cause */
	if (hold_rej->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &hold_rej->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_retrieve(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc retrieve;

	memset(&retrieve, 0, sizeof(struct gsm_mncc));
	retrieve.callref = trans->callref;
	return mncc_recvmsg(trans->net, trans, MNCC_RETRIEVE_IND,
			    &retrieve);
}

static int gsm48_cc_tx_retrieve_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC RETR ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_retrieve_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *retrieve_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC RETR REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_REJ;

	/* cause */
	if (retrieve_rej->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &retrieve_rej->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_start_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* keypad facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_KPD_FACILITY)) {
		dtmf.fields |= MNCC_F_KEYPAD;
		gsm48_decode_keypad(&dtmf.keypad,
			      TLVP_VAL(&tp, GSM48_IE_KPD_FACILITY)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_START_DTMF_IND, &dtmf);
}

static int gsm48_cc_tx_start_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_ACK;

	/* keypad */
	if (dtmf->fields & MNCC_F_KEYPAD)
		gsm48_encode_keypad(msg, dtmf->keypad);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_start_dtmf_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_REJ;

	/* cause */
	if (dtmf->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &dtmf->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_stop_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF STP ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_STOP_DTMF_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_stop_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;

	return mncc_recvmsg(trans->net, trans, MNCC_STOP_DTMF_IND, &dtmf);
}

static int gsm48_cc_rx_modify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}

	new_cc_state(trans, GSM_CSTATE_MO_ORIG_MODIFY);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_IND, &modify);
}

static int gsm48_cc_tx_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY;

	gsm48_start_cc_timer(trans, 0x323, GSM48_T323);

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);
	memcpy(&trans->bearer_cap, &modify->bearer_cap, sizeof(trans->bearer_cap));

	new_cc_state(trans, GSM_CSTATE_MO_TERM_MODIFY);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_modify_complete(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	gsm48_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_CNF, &modify);
}

static int gsm48_cc_tx_modify_complete(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD COMPL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_COMPL;

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);
	memcpy(&trans->bearer_cap, &modify->bearer_cap, sizeof(trans->bearer_cap));

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_modify_reject(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	gsm48_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, GSM48_IE_CAUSE);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= GSM48_IE_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		modify.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&modify.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_REJ, &modify);
}

static int gsm48_cc_tx_modify_reject(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_REJECT;

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);
	memcpy(&trans->bearer_cap, &modify->bearer_cap, sizeof(trans->bearer_cap));
	/* cause */
	gsm48_encode_cause(msg, 1, &modify->cause);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_notify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *notify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC NOT");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_NOTIFY;

	/* notify */
	gsm48_encode_notify(msg, notify->notify);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_notify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
//	struct tlv_parsed tp;
	struct gsm_mncc notify;

	memset(&notify, 0, sizeof(struct gsm_mncc));
	notify.callref = trans->callref;
//	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len);
	if (payload_len >= 1)
		gsm48_decode_notify(&notify.notify, gh->data);

	return mncc_recvmsg(trans->net, trans, MNCC_NOTIFY_IND, &notify);
}

static int gsm48_cc_tx_userinfo(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *user = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USR INFO");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_USER_INFO;

	/* user-user */
	if (user->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 1, &user->useruser);
	/* more data */
	if (user->more)
		gsm48_encode_more(msg);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_userinfo(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc user;

	memset(&user, 0, sizeof(struct gsm_mncc));
	user.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_USER_USER, 0);
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		user.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&user.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* more data */
	if (TLVP_PRESENT(&tp, GSM48_IE_MORE_DATA))
		user.more = 1;

	return mncc_recvmsg(trans->net, trans, MNCC_USERINFO_IND, &user);
}

static void mncc_recv_rtp(struct gsm_network *net, uint32_t callref,
		int cmd, uint32_t addr, uint16_t port, uint32_t payload_type,
		uint32_t payload_msg_type)
{
	uint8_t data[sizeof(struct gsm_mncc)];
	struct gsm_mncc_rtp *rtp;

	memset(&data, 0, sizeof(data));
	rtp = (struct gsm_mncc_rtp *) &data[0];

	rtp->callref = callref;
	rtp->msg_type = cmd;
	rtp->ip = osmo_htonl(addr);
	rtp->port = port;
	rtp->payload_type = payload_type;
	rtp->payload_msg_type = payload_msg_type;
	mncc_recvmsg(net, NULL, cmd, (struct gsm_mncc *)data);
}

static void mncc_recv_rtp_sock(struct gsm_network *net, struct gsm_trans *trans, int cmd)
{
	int msg_type;

	/* FIXME This has to be set to some meaningful value.
	 * Possible options are:
	 * GSM_TCHF_FRAME, GSM_TCHF_FRAME_EFR,
	 * GSM_TCHH_FRAME, GSM_TCH_FRAME_AMR
	 * (0 if unknown) */
	msg_type = GSM_TCHF_FRAME;

	uint32_t addr = inet_addr(trans->conn->rtp.local_addr_cn);
	uint16_t port = trans->conn->rtp.local_port_cn;

	if (addr == INADDR_NONE) {
		LOGP(DMNCC, LOGL_ERROR,
		     "(subscriber:%s) external MNCC is signalling invalid IP-Address\n",
		     vlr_subscr_name(trans->vsub));
		return;
	}
	if (port == 0) {
		LOGP(DMNCC, LOGL_ERROR,
		     "(subscriber:%s) external MNCC is signalling invalid Port\n",
		     vlr_subscr_name(trans->vsub));
		return;
	}

	/* FIXME: This has to be set to some meaningful value,
	 * before the MSC-Split, this value was pulled from
	 * lchan->abis_ip.rtp_payload */
	uint32_t payload_type = 0;

	return mncc_recv_rtp(net, trans->callref, cmd,
			addr,
			port,
		        payload_type,
			msg_type);
}

static void mncc_recv_rtp_err(struct gsm_network *net, uint32_t callref, int cmd)
{
	return mncc_recv_rtp(net, callref, cmd, 0, 0, 0, 0);
}

static int tch_rtp_create(struct gsm_network *net, uint32_t callref)
{
	struct gsm_trans *trans;

	/* Find callref */
	trans = trans_find_by_callref(net, callref);
	if (!trans) {
		LOG_TRANS_CAT(trans, DMNCC, LOGL_ERROR, "RTP create for non-existing trans\n");
		mncc_recv_rtp_err(net, callref, MNCC_RTP_CREATE);
		return -EIO;
	}
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	if (!trans->conn) {
		LOG_TRANS_CAT(trans, DMNCC, LOGL_NOTICE, "RTP create for trans without conn\n");
		mncc_recv_rtp_err(net, callref, MNCC_RTP_CREATE);
		return 0;
	}

	/* When we call msc_mgcp_call_assignment() we will trigger, depending
	 * on the RAN type the call assignment on the A or Iu interface.
	 * msc_mgcp_call_assignment() also takes care about sending the CRCX
	 * command to the MGCP-GW. The CRCX will return the port number,
	 * where the PBX (e.g. Asterisk) will send its RTP stream to. We
	 * have to return this port number back to the MNCC by sending
	 * it back with the TCH_RTP_CREATE message. To make sure that
	 * this message is sent AFTER the response to CRCX from the
	 * MGCP-GW has arrived, we need will instruct msc_mgcp_call_assignment()
	 * to take care of this by setting trans->tch_rtp_create to true.
	 * This will make sure that gsm48_tch_rtp_create() (below) is
	 * called as soon as the local port number has become known. */
	trans->tch_rtp_create = true;

	/* Assign call (if not done yet) */
	return msc_mgcp_try_call_assignment(trans);
}

/* Trigger TCH_RTP_CREATE acknowledgement */
int gsm48_tch_rtp_create(struct gsm_trans *trans)
{
	/* This function is called as soon as the port, on which the
	 * mgcp-gw expects the incoming RTP stream from the remote
	 * end (e.g. Asterisk) is known. */

	struct ran_conn *conn = trans->conn;
	struct gsm_network *network = conn->network;

	mncc_recv_rtp_sock(network, trans, MNCC_RTP_CREATE);
	return 0;
}

static int tch_rtp_connect(struct gsm_network *net, struct gsm_mncc_rtp *rtp)
{
	struct gsm_trans *trans;
	struct in_addr addr;

	/* FIXME: in *rtp we should get the codec information of the remote
	 * leg. We will have to populate trans->conn->rtp.codec_cn with a
	 * meaningful value based on this information but unfortunately we
	 * can't do that yet because the mncc API can not signal dynamic
	 * payload types yet. This must be fixed first. Also there may be
	 * additional members necessary in trans->conn->rtp because we
	 * somehow need to deal with dynamic payload types that do not
	 * comply to 3gpp's assumptions of payload type numbers on the A
	 * interface. See also related tickets: OS#3399 and OS1683 */

	/* Find callref */
	trans = trans_find_by_callref(net, rtp->callref);
	if (!trans) {
		LOG_TRANS_CAT(trans, DMNCC, LOGL_ERROR, "RTP connect for non-existing trans\n");
		mncc_recv_rtp_err(net, rtp->callref, MNCC_RTP_CONNECT);
		return -EIO;
	}
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	if (!trans->conn) {
		LOG_TRANS_CAT(trans, DMNCC, LOGL_ERROR, "RTP connect for trans without conn\n");
		mncc_recv_rtp_err(net, rtp->callref, MNCC_RTP_CONNECT);
		return 0;
	}

	addr.s_addr = osmo_htonl(rtp->ip);
	return msc_mgcp_call_complete(trans, rtp->port, inet_ntoa(addr));
}

static struct downstate {
	uint32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, void *arg);
} downstatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_INITIATED), /* 5.2.1.2 */
	 MNCC_CALL_PROC_REQ, gsm48_cc_tx_call_proc_and_assign},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.2 | 5.2.1.5 */
	 MNCC_ALERT_REQ, gsm48_cc_tx_alerting},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC) | SBIT(GSM_CSTATE_CALL_DELIVERED), /* 5.2.1.2 | 5.2.1.6 | 5.2.1.6 */
	 MNCC_SETUP_RSP, gsm48_cc_tx_connect},
	{SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.4.2 */
	 MNCC_PROGRESS_REQ, gsm48_cc_tx_progress},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.2.1 */
	 MNCC_SETUP_REQ, gsm48_cc_tx_setup},
	{SBIT(GSM_CSTATE_CONNECT_REQUEST),
	 MNCC_SETUP_COMPL_REQ, gsm48_cc_tx_connect_ack},
	 /* signalling during call */
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_NOTIFY_REQ, gsm48_cc_tx_notify},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ),
	 MNCC_FACILITY_REQ, gsm48_cc_tx_facility},
	{ALL_STATES,
	 MNCC_START_DTMF_RSP, gsm48_cc_tx_start_dtmf_ack},
	{ALL_STATES,
	 MNCC_START_DTMF_REJ, gsm48_cc_tx_start_dtmf_rej},
	{ALL_STATES,
	 MNCC_STOP_DTMF_RSP, gsm48_cc_tx_stop_dtmf_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_CNF, gsm48_cc_tx_hold_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_REJ, gsm48_cc_tx_hold_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_CNF, gsm48_cc_tx_retrieve_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_REJ, gsm48_cc_tx_retrieve_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_MODIFY_REQ, gsm48_cc_tx_modify},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_RSP, gsm48_cc_tx_modify_complete},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_REJ, gsm48_cc_tx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_USERINFO_REQ, gsm48_cc_tx_userinfo},
	/* clearing */
	{SBIT(GSM_CSTATE_INITIATED),
	 MNCC_REJ_REQ, gsm48_cc_tx_release_compl},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_DISCONNECT_IND) - SBIT(GSM_CSTATE_RELEASE_REQ) - SBIT(GSM_CSTATE_DISCONNECT_REQ), /* 5.4.4 */
	 MNCC_DISC_REQ, gsm48_cc_tx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 MNCC_REL_REQ, gsm48_cc_tx_release},
};

#define DOWNSLLEN \
	(sizeof(downstatelist) / sizeof(struct downstate))


int mncc_tx_to_cc(struct gsm_network *net, int msg_type, void *arg)
{
	int i, rc = 0;
	struct gsm_trans *trans = NULL, *transt;
	struct ran_conn *conn = NULL;
	struct gsm_mncc *data = arg, rel;

	/* handle special messages */
	switch(msg_type) {
	case MNCC_BRIDGE:
		rc = tch_bridge(net, arg);
		if (rc < 0)
			disconnect_bridge(net, arg, -rc);
		return rc;
	case MNCC_RTP_CREATE:
		return tch_rtp_create(net, data->callref);
	case MNCC_RTP_CONNECT:
		return tch_rtp_connect(net, arg);
	case MNCC_RTP_FREE:
		/* unused right now */
		return -EIO;

	case MNCC_FRAME_DROP:
	case MNCC_FRAME_RECV:
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
	case GSM_TCHH_FRAME:
	case GSM_TCH_FRAME_AMR:
		LOG_TRANS_CAT(trans, DMNCC, LOGL_ERROR, "RTP streams must be handled externally; %s not supported.\n",
		     get_mncc_name(msg_type));
		return -ENOTSUP;
	}

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = data->callref;

	/* Find callref */
	trans = trans_find_by_callref(net, data->callref);

	/* Callref unknown */
	if (!trans) {
		struct vlr_subscr *vsub;

		if (msg_type != MNCC_SETUP_REQ) {
			LOG_TRANS_CAT(trans, DCC, LOGL_ERROR, "Unknown call reference for %s\n",
				      get_mncc_name(msg_type));
			/* Invalid call reference */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INVAL_TRANS_ID);
		}
		if (!data->called.number[0] && !data->imsi[0]) {
			LOG_TRANS_CAT(trans, DCC, LOGL_ERROR, "Neither number nor IMSI in %s\n",
				      get_mncc_name(msg_type));
			/* Invalid number */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INV_NR_FORMAT);
		}
		/* New transaction due to setup, find subscriber */
		if (data->called.number[0]) {
			vsub = vlr_subscr_find_by_msisdn(net->vlr, data->called.number, __func__);
			if (!vsub)
				LOG_TRANS_CAT(trans, DCC, LOGL_ERROR, "rx %s for unknown subscriber number '%s'\n",
					      get_mncc_name(msg_type), data->called.number);
		} else {
			vsub = vlr_subscr_find_by_imsi(net->vlr, data->imsi, __func__);
			if (!vsub)
				LOG_TRANS_CAT(trans, DCC, LOGL_ERROR, "rx %s for unknown subscriber IMSI '%s'\n",
					      get_mncc_name(msg_type), data->imsi);
		}
		if (!vsub)
			return mncc_release_ind(net, NULL, data->callref, GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_UNASSIGNED_NR);
		/* update the subscriber we deal with */
		log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

		/* If subscriber is not "attached" */
		if (!vsub->lu_complete) {
			LOG_TRANS_CAT(trans, DCC, LOGL_ERROR, "rx %s for subscriber that is not attached: %s\n",
				      get_mncc_name(msg_type), vlr_subscr_name(vsub));
			vlr_subscr_put(vsub, __func__);
			/* Temporarily out of order */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_DEST_OOO);
		}
		/* Create transaction */
		trans = trans_alloc(net, vsub, GSM48_PDISC_CC,
				    TRANS_ID_UNASSIGNED, data->callref);
		if (!trans) {
			LOG_TRANS(trans, LOGL_ERROR, "No memory for trans.\n");
			vlr_subscr_put(vsub, __func__);
			/* Ressource unavailable */
			mncc_release_ind(net, NULL, data->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			return -ENOMEM;
		}

		/* Find conn */
		conn = connection_for_subscr(vsub);

		/* If subscriber has no conn */
		if (!conn) {
			/* find transaction with this subscriber already paging */
			llist_for_each_entry(transt, &net->trans_list, entry) {
				/* Transaction of our conn? */
				if (transt == trans ||
				    transt->vsub != vsub)
					continue;
				LOG_TRANS(trans, LOGL_DEBUG,
					  "rx %s, subscriber not yet connected, paging already started\n",
					  get_mncc_name(msg_type));
				vlr_subscr_put(vsub, __func__);
				trans_free(trans);
				return 0;
			}

			/* store setup information until paging succeeds */
			memcpy(&trans->cc.msg, data, sizeof(struct gsm_mncc));

			/* Request a channel */
			trans->paging_request = subscr_request_conn(
							vsub,
							setup_trig_pag_evt,
							trans,
							"MNCC: establish call",
							SGSAP_SERV_IND_CS_CALL);
			if (!trans->paging_request) {
				LOG_TRANS(trans, LOGL_ERROR, "Failed to allocate paging token.\n");
				vlr_subscr_put(vsub, __func__);
				trans_free(trans);
				return 0;
			}
			vlr_subscr_put(vsub, __func__);
			return 0;
		}

		/* Assign conn */
		trans->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_CC);
		trans->dlci = 0x00; /* SAPI=0, not SACCH */
		vlr_subscr_put(vsub, __func__);
	} else {
		/* update the subscriber we deal with */
		log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	}

	LOG_TRANS_CAT(trans, DMNCC, LOGL_DEBUG, "rx %s\n", get_mncc_name(msg_type));

	gsm48_start_guard_timer(trans);

	if (trans->conn)
		conn = trans->conn;

	/* if paging did not respond yet */
	if (!conn) {
		LOG_TRANS(trans, LOGL_DEBUG, "rx %s in paging state\n", get_mncc_name(msg_type));
		mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_NORM_CALL_CLEAR);
		if (msg_type == MNCC_REL_REQ)
			rc = mncc_recvmsg(net, trans, MNCC_REL_CNF, &rel);
		else
			rc = mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	} else {
		LOG_TRANS(trans, LOGL_DEBUG, "rx %s in state %s\n",
			  get_mncc_name(msg_type), gsm48_cc_state_name(trans->cc.state));
	}

	/* Find function for current state and message */
	for (i = 0; i < DOWNSLLEN; i++)
		if ((msg_type == downstatelist[i].type)
		 && ((1 << trans->cc.state) & downstatelist[i].states))
			break;
	if (i == DOWNSLLEN) {
		LOG_TRANS(trans, LOGL_DEBUG, "Message '%s' unhandled at state '%s'\n",
			  get_mncc_name(msg_type), gsm48_cc_state_name(trans->cc.state));
		return 0;
	}

	rc = downstatelist[i].rout(trans, arg);

	return rc;
}


static struct datastate {
	uint32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, struct msgb *msg);
} datastatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_SETUP, gsm48_cc_rx_setup},
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_EMERG_SETUP, gsm48_cc_rx_setup},
	{SBIT(GSM_CSTATE_CONNECT_IND), /* 5.2.1.2 */
	 GSM48_MT_CC_CONNECT_ACK, gsm48_cc_rx_connect_ack},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_CALL_PRESENT), /* 5.2.2.3.2 */
	 GSM48_MT_CC_CALL_CONF, gsm48_cc_rx_call_conf},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF), /* ???? | 5.2.2.3.2 */
	 GSM48_MT_CC_ALERTING, gsm48_cc_rx_alerting},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF) | SBIT(GSM_CSTATE_CALL_RECEIVED), /* (5.2.2.6) | 5.2.2.6 | 5.2.2.6 */
	 GSM48_MT_CC_CONNECT, gsm48_cc_rx_connect},
	 /* signalling during call */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL),
	 GSM48_MT_CC_FACILITY, gsm48_cc_rx_facility},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_NOTIFY, gsm48_cc_rx_notify},
	{ALL_STATES,
	 GSM48_MT_CC_START_DTMF, gsm48_cc_rx_start_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STOP_DTMF, gsm48_cc_rx_stop_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STATUS_ENQ, gsm48_cc_rx_status_enq},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_HOLD, gsm48_cc_rx_hold},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_RETR, gsm48_cc_rx_retrieve},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_MODIFY, gsm48_cc_rx_modify},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_COMPL, gsm48_cc_rx_modify_complete},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_REJECT, gsm48_cc_rx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_USER_INFO, gsm48_cc_rx_userinfo},
	/* clearing */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 GSM48_MT_CC_DISCONNECT, gsm48_cc_rx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL), /* 5.4.4.1.2.2 */
	 GSM48_MT_CC_RELEASE, gsm48_cc_rx_release},
	{ALL_STATES, /* 5.4.3.4 */
	 GSM48_MT_CC_RELEASE_COMPL, gsm48_cc_rx_release_compl},
};

#define DATASLLEN \
	(sizeof(datastatelist) / sizeof(struct datastate))

int gsm0408_rcv_cc(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	uint8_t transaction_id = gsm48_hdr_trans_id_flip_ti(gh);
	struct gsm_trans *trans = NULL;
	int i, rc = 0;

	if (msg_type & 0x80) {
		LOG_TRANS(trans, LOGL_DEBUG, "MSG 0x%2x not defined for PD error\n", msg_type);
		return -EINVAL;
	}

	if (!conn->vsub) {
		LOG_TRANS(trans, LOGL_ERROR, "Invalid conn: no subscriber\n");
		return -EINVAL;
	}

	/* Find transaction */
	trans = trans_find_by_id(conn, GSM48_PDISC_CC, transaction_id);

	/* Create transaction */
	if (!trans) {
		DEBUGP(DCC, "Unknown transaction ID %x, "
			"creating new trans.\n", transaction_id);
		/* Create transaction */
		trans = trans_alloc(conn->network, conn->vsub,
				    GSM48_PDISC_CC,
				    transaction_id, new_callref++);
		if (!trans) {
			LOG_TRANS(trans, LOGL_ERROR, "No memory for trans.\n");
			rc = gsm48_tx_simple(conn,
					     GSM48_PDISC_CC | (transaction_id << 4),
					     GSM48_MT_CC_RELEASE_COMPL);
			return -ENOMEM;
		}
		/* Assign transaction */
		trans->conn = ran_conn_get(conn, RAN_CONN_USE_TRANS_CC);
		trans->dlci = OMSC_LINKID_CB(msg); /* DLCI as received from BSC */
		cm_service_request_concludes(conn, msg);
	}

	LOG_TRANS(trans, LOGL_DEBUG, "rx %s in state %s\n", gsm48_cc_msg_name(msg_type),
		  gsm48_cc_state_name(trans->cc.state));

	/* find function for current state and message */
	for (i = 0; i < DATASLLEN; i++)
		if ((msg_type == datastatelist[i].type)
		 && ((1 << trans->cc.state) & datastatelist[i].states))
			break;
	if (i == DATASLLEN) {
		LOG_TRANS(trans, LOGL_ERROR, "Message unhandled at this state.\n");
		return 0;
	}

	assert(trans->vsub);

	rc = datastatelist[i].rout(trans, msg);

	ran_conn_communicating(conn);
	return rc;
}
