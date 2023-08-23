/* Code to manage a subscriber's MSC-A role */
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

#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/signal.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/msc_roles.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/paging.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/transaction_cc.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/ran_msg_a.h>
#include <osmocom/msc/ran_msg_iu.h>
#include <osmocom/msc/sgs_iface.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/gsm_09_11.h>
#include <osmocom/msc/gsm_04_14.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/msc_ho.h>
#include <osmocom/msc/codec_mapping.h>
#include <osmocom/msc/msc_vgcs.h>

#define MSC_A_USE_WAIT_CLEAR_COMPLETE "wait-Clear-Complete"

static struct osmo_fsm msc_a_fsm;

static const struct osmo_tdef_state_timeout msc_a_fsm_timeouts[32] = {
	[MSC_A_ST_VALIDATE_L3] = { .T = -1 },
	[MSC_A_ST_AUTH_CIPH] = { .keep_timer = true },
	[MSC_A_ST_WAIT_CLASSMARK_UPDATE] = { .keep_timer = true },
	[MSC_A_ST_AUTHENTICATED] = { .keep_timer = true },
	[MSC_A_ST_RELEASING] = { .T = -2 },
	[MSC_A_ST_RELEASED] = { .T = -2 },
};

/* Transition to a state, using the T timer defined in msc_a_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define msc_a_state_chg_always(msc_a, state) \
	osmo_tdef_fsm_inst_state_chg((msc_a)->c.fi, state, msc_a_fsm_timeouts, (msc_a)->c.ran->tdefs, 5)

/* Same as msc_a_state_chg_always() but ignore if the msc_a already is in the target state. */
#define msc_a_state_chg(msc_a, STATE) do { \
		if ((msc_a)->c.fi->state != STATE) \
			msc_a_state_chg_always(msc_a, STATE); \
	} while(0)

struct gsm_network *msc_a_net(const struct msc_a *msc_a)
{
	return msub_net(msc_a->c.msub);
}

struct vlr_subscr *msc_a_vsub(const struct msc_a *msc_a)
{
	if (!msc_a)
		return NULL;
	return msub_vsub(msc_a->c.msub);
}

struct msc_i *msc_a_msc_i(const struct msc_a *msc_a)
{
	if (!msc_a)
		return NULL;
	return msub_msc_i(msc_a->c.msub);
}

struct msc_t *msc_a_msc_t(const struct msc_a *msc_a)
{
	if (!msc_a)
		return NULL;
	return msub_msc_t(msc_a->c.msub);
}

struct msc_a *msc_a_fi_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_a_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

bool msc_a_is_ciphering_to_be_attempted(const struct msc_a *msc_a)
{
	struct gsm_network *net = msc_a_net(msc_a);
	bool is_utran = (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU);
	if (is_utran)
		return net->uea_encryption_mask > (1 << OSMO_UTRAN_UEA0);
	else
		return net->a5_encryption_mask > 0x1;
}

bool msc_a_is_ciphering_required(const struct msc_a *msc_a)
{
	struct gsm_network *net = msc_a_net(msc_a);
	bool is_utran = (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU);
	if (is_utran)
		return net->uea_encryption_mask
			&& ((net->uea_encryption_mask & (1 << OSMO_UTRAN_UEA0)) == 0);
	else
		return net->a5_encryption_mask
			&& ((net->a5_encryption_mask & 0x1) == 0);
}

static void update_counters(struct osmo_fsm_inst *fi, bool conn_accepted)
{
	struct msc_a *msc_a = fi->priv;
	struct gsm_network *net = msc_a_net(msc_a);
	switch (msc_a->complete_layer3_type) {
	case COMPLETE_LAYER3_LU:
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, conn_accepted ? MSC_CTR_LOC_UPDATE_COMPLETED : MSC_CTR_LOC_UPDATE_FAILED));
		break;
	case COMPLETE_LAYER3_CM_SERVICE_REQ:
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, conn_accepted ? MSC_CTR_CM_SERVICE_REQUEST_ACCEPTED : MSC_CTR_CM_SERVICE_REQUEST_REJECTED));
		break;
	case COMPLETE_LAYER3_PAGING_RESP:
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs, conn_accepted ? MSC_CTR_PAGING_RESP_ACCEPTED : MSC_CTR_PAGING_RESP_REJECTED));
		break;
	case COMPLETE_LAYER3_CM_RE_ESTABLISH_REQ:
		rate_ctr_inc(rate_ctr_group_get_ctr(net->msc_ctrs,
						    conn_accepted ? MSC_CTR_CM_RE_ESTABLISH_REQ_ACCEPTED
								  : MSC_CTR_CM_RE_ESTABLISH_REQ_REJECTED));
		break;
	default:
		break;
	}
}

static void evaluate_acceptance_outcome(struct osmo_fsm_inst *fi, bool conn_accepted)
{
	struct msc_a *msc_a = fi->priv;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	update_counters(fi, conn_accepted);

	if (conn_accepted) {
		/* Record the Cell ID seen in Complete Layer 3 Information in the VLR, so that it also shows in vty
		 * 'show' output. */
		vsub->cgi = msc_a->via_cell;
	}

	/* Trigger transactions that we paged for */
	if (msc_a->complete_layer3_type == COMPLETE_LAYER3_PAGING_RESP) {
		if (conn_accepted)
			paging_response(msc_a);
		else
			paging_expired(vsub);
	}

	if (conn_accepted)
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_ATTACHED, msc_a_vsub(msc_a));

	if (msc_a->complete_layer3_type == COMPLETE_LAYER3_LU)
		msc_a_put(msc_a, MSC_A_USE_LOCATION_UPDATING);

	if (msc_a->complete_layer3_type == COMPLETE_LAYER3_CM_RE_ESTABLISH_REQ) {
		/* Trigger new Assignment to recommence the voice call. A little dance here because normally we verify
		 * that no CC trans is already active. */
		struct gsm_trans *cc_trans = msc_a->cc.active_trans;
		msc_a->cc.active_trans = NULL;
		osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_TRANSACTION_ACCEPTED, cc_trans);
		msc_a_try_call_assignment(cc_trans);
	}
}

bool msc_a_is_accepted(const struct msc_a *msc_a)
{
	if (!msc_a || !msc_a->c.fi)
		return false;
	return msc_a->c.fi->state == MSC_A_ST_AUTHENTICATED
		|| msc_a->c.fi->state == MSC_A_ST_COMMUNICATING;
}

bool msc_a_in_release(struct msc_a *msc_a)
{
	if (!msc_a)
		return true;
	if (msc_a->c.fi->state == MSC_A_ST_RELEASING)
		return true;
	if (msc_a->c.fi->state == MSC_A_ST_RELEASED)
		return true;
	return false;
}

static int msc_a_ran_dec(struct msc_a *msc_a, const struct an_apdu *an_apdu, enum msc_role from_role)
{
	int rc;
	struct msc_a_ran_dec_data d = {
		.from_role = from_role,
		.an_apdu = an_apdu,
	};
	msc_a_get(msc_a, __func__);
	rc = msc_role_ran_decode(msc_a->c.fi, an_apdu, msc_a_ran_decode_cb, &d);
	msc_a_put(msc_a, __func__);
	return rc;
};

static void msc_a_fsm_validate_l3(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;
	const struct an_apdu *an_apdu;

	switch (event) {
	case MSC_A_EV_FROM_I_COMPLETE_LAYER_3:
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		an_apdu = data;
		msc_a_ran_dec(msc_a, an_apdu, MSC_ROLE_I);
		return;

	case MSC_A_EV_COMPLETE_LAYER_3_OK:
		msc_a_state_chg(msc_a, MSC_A_ST_AUTH_CIPH);
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
		evaluate_acceptance_outcome(fi, false);
		/* fall through */
	case MSC_A_EV_UNUSED:
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

/* Figure out whether to first send a Classmark Request to the MS to figure out algorithm support. */
static bool msc_a_need_classmark_for_ciphering(struct msc_a *msc_a)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	int i = 0;
	bool request_classmark = false;

	/* Only on GERAN-A do we ever need Classmark Information for Ciphering. */
	if (msc_a->c.ran->type != OSMO_RAT_GERAN_A)
		return false;

	for (i = 0; i < 8; i++) {
		int supported;

		/* A5/n permitted by osmo-msc.cfg? */
		if (!(net->a5_encryption_mask & (1 << i)))
			continue;

		/* A5/n supported by MS? */
		supported = osmo_gsm48_classmark_supports_a5(&vsub->classmark, i);
		if (supported < 0) {
			LOG_MSC_A(msc_a, LOGL_DEBUG, "For A5/%d, we still need Classmark %d\n", i, -supported);
			request_classmark = true;
		}
	}

	return request_classmark;
}

static int msc_a_ran_enc_ciphering(struct msc_a *msc_a, bool umts_aka, bool retrieve_imeisv);

/* VLR callback for ops.set_ciph_mode() */
int msc_a_vlr_set_cipher_mode(void *_msc_a, bool umts_aka, bool retrieve_imeisv)
{
	struct msc_a *msc_a = _msc_a;
	struct vlr_subscr *vsub;

	if (!msc_a) {
		LOGP(DMSC, LOGL_ERROR, "Insufficient info to start ciphering: "
				       "MSC-A role is NULL?!?\n");
		return -EINVAL;
	}

	vsub = msc_a_vsub(msc_a);
	if (!vsub || !vsub->last_tuple) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Insufficient info to start ciphering: "
					     "vlr_subscr is NULL?!?\n");
		return -EINVAL;
	}

	if (msc_a_need_classmark_for_ciphering(msc_a)) {
		int rc;
		struct ran_msg msg = {
			.msg_type = RAN_MSG_CLASSMARK_REQUEST,
		};
		rc = msc_a_ran_down(msc_a, MSC_ROLE_I, &msg);
		if (rc) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "Cannot send Classmark Request\n");
			return -EIO;
		}

		msc_a->state_before_classmark_update = msc_a->c.fi->state;
		msc_a->action_on_classmark_update = (struct msc_a_action_on_classmark_update){
			.type = MSC_A_CLASSMARK_UPDATE_THEN_CIPHERING,
			.ciphering = {
				.umts_aka = umts_aka,
				.retrieve_imeisv = retrieve_imeisv,
			},
		};
		msc_a_state_chg(msc_a, MSC_A_ST_WAIT_CLASSMARK_UPDATE);
		return 0;
	}

	return msc_a_ran_enc_ciphering(msc_a, umts_aka, retrieve_imeisv);
}

static uint8_t filter_a5(uint8_t a5_mask, bool umts_aka)
{
	/* With GSM AKA: allow A5/0, 1, 3 = 0b00001011 = 0xb.
	 * UMTS aka: allow A5/0, 1, 3, 4 = 0b00011011 = 0x1b.
	 */
	return a5_mask & (umts_aka ? 0x1b : 0x0b);
}

static int msc_a_ran_enc_ciphering(struct msc_a *msc_a, bool umts_aka, bool retrieve_imeisv)
{
	struct gsm_network *net;
	struct vlr_subscr *vsub;
	struct ran_msg msg;

	if (!msc_a) {
		LOGP(DMSC, LOGL_ERROR, "Insufficient info to start ciphering: "
				       "MSC-A role is NULL?!?\n");
		return -EINVAL;
	}

	net = msc_a_net(msc_a);
	vsub = msc_a_vsub(msc_a);

	if (!net || !vsub || !vsub->last_tuple) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Insufficient info to start ciphering: "
					     "gsm_network and/or vlr_subscr is NULL?!?\n");
		return -EINVAL;
	}

	msg = (struct ran_msg){
		.msg_type = RAN_MSG_CIPHER_MODE_COMMAND,
		.cipher_mode_command = {
			.vec = vsub->last_tuple ? &vsub->last_tuple->vec : NULL,
			.classmark = &vsub->classmark,
			.geran = {
				.umts_aka = umts_aka,
				.retrieve_imeisv = retrieve_imeisv,
				.a5_encryption_mask = filter_a5(net->a5_encryption_mask, umts_aka),

				/* for ran_a.c to store the GERAN key that is actually used */
				.chosen_key = &msc_a->geran_encr,
			},
			.utran = {
				.uea_encryption_mask = net->uea_encryption_mask,
			},
		},
	};

	if (msc_a_ran_down(msc_a, MSC_ROLE_I, &msg)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Sending Cipher Mode Command failed\n");
		/* Returning error to the VLR ops.set_ciph_mode() will cancel the attach. Other callers need to take
		 * care of the return value. */
		return -EINVAL;
	}

	if (msc_a->geran_encr.key_len)
		LOG_MSC_A(msc_a, LOGL_DEBUG, "RAN encoding chose ciphering: A5/%d kc %s kc128 %s\n",
			  msc_a->geran_encr.alg_id - 1,
			  osmo_hexdump_nospc_c(OTC_SELECT, msc_a->geran_encr.key, msc_a->geran_encr.key_len),
			  msc_a->geran_encr.kc128_present ?
			    osmo_hexdump_nospc_c(OTC_SELECT, msc_a->geran_encr.kc128, sizeof(msc_a->geran_encr.kc128))
			    : "-");
	return 0;
}

static void msc_a_fsm_auth_ciph(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	/* If accepted, transition the state, all other cases mean failure. */
	switch (event) {
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		msc_a_ran_dec(msc_a, data, MSC_ROLE_I);
		return;

	case MSC_A_EV_AUTHENTICATED:
		msc_a_state_chg(msc_a, MSC_A_ST_AUTHENTICATED);
		return;

	case MSC_A_EV_UNUSED:
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
		evaluate_acceptance_outcome(fi, false);
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;


	default:
		OSMO_ASSERT(false);
	}
}

static void msc_a_fsm_wait_classmark_update(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	switch (event) {
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		msc_a_ran_dec(msc_a, data, MSC_ROLE_I);
		return;

	case MSC_A_EV_CLASSMARK_UPDATE:
		switch (msc_a->action_on_classmark_update.type) {
		case MSC_A_CLASSMARK_UPDATE_THEN_CIPHERING:
			msc_a_state_chg(msc_a, MSC_A_ST_AUTH_CIPH);
			if (msc_a_ran_enc_ciphering(msc_a,
						     msc_a->action_on_classmark_update.ciphering.umts_aka,
						     msc_a->action_on_classmark_update.ciphering.retrieve_imeisv)) {
				LOG_MSC_A(msc_a, LOGL_ERROR,
					  "After Classmark Update, still failed to send Cipher Mode Command\n");
				msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
			}
			return;

		default:
			LOG_MSC_A(msc_a, LOGL_ERROR, "Internal error: After Classmark Update, don't know what to do\n");
			msc_a_state_chg(msc_a, msc_a->state_before_classmark_update);
			return;
		}

	case MSC_A_EV_UNUSED:
		/* Seems something detached / aborted in the middle of auth+ciph. */
		evaluate_acceptance_outcome(fi, false);
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
		evaluate_acceptance_outcome(fi, false);
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static bool msc_a_fsm_has_active_transactions(struct osmo_fsm_inst *fi)
{
	struct msc_a *msc_a = fi->priv;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct gsm_trans *trans;

	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_SILENT_CALL)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: silent call still active\n", __func__);
		return true;
	}

	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_CC)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still awaiting MO CC request after a CM Service Request\n",
			 __func__);
		return true;
	}
	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_GCC)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still awaiting MO GCC request after a CM Service Request\n",
			 __func__);
		return true;
	}
	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_BCC)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still awaiting MO BCC request after a CM Service Request\n",
			 __func__);
		return true;
	}
	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_SMS)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still awaiting MO SMS after a CM Service Request\n",
			 __func__);
		return true;
	}
	if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_SS)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still awaiting MO SS after a CM Service Request\n",
			 __func__);
		return true;
	}

	if (vsub && !llist_empty(&vsub->cs.requests)) {
		struct paging_request *pr;
		llist_for_each_entry(pr, &vsub->cs.requests, entry) {
			LOG_MSC_A(msc_a, LOGL_DEBUG, "%s: still active: %s\n", __func__, pr->label);
		}
		return true;
	}

	if ((trans = trans_has_conn(msc_a))) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "connection still has active transaction: %s\n",
			  trans_type_name(trans->type));
		return true;
	}

	return false;
}

static void msc_a_fsm_authenticated_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_a *msc_a = fi->priv;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	/* Stop Location Update expiry for this subscriber. While the subscriber
	 * has an open connection the LU expiry timer must remain disabled.
	 * Otherwise we would kick the subscriber off the network when the timer
	 * expires e.g. during a long phone call.
	 * The LU expiry timer will restart once the connection is closed. */
	if (vsub)
		vsub->expire_lu = VLR_SUBSCRIBER_NO_EXPIRATION;

	evaluate_acceptance_outcome(fi, true);
}

static void msc_a_fsm_authenticated(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	switch (event) {
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		msc_a_ran_dec(msc_a, data, MSC_ROLE_I);
		return;

	case MSC_A_EV_COMPLETE_LAYER_3_OK:
		/* When Authentication is off, we may already be in the Accepted state when the code
		 * evaluates the Compl L3. Simply ignore. This just cosmetically mutes the error log
		 * about the useless event. */
		return;

	case MSC_A_EV_TRANSACTION_ACCEPTED:
		msc_a_state_chg(msc_a, MSC_A_ST_COMMUNICATING);
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
	case MSC_A_EV_UNUSED:
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static struct call_leg *msc_a_ensure_call_leg(struct msc_a *msc_a, struct gsm_trans *for_cc_trans)
{
	struct call_leg *cl = msc_a->cc.call_leg;
	struct gsm_network *net = msc_a_net(msc_a);

	/* Ensure that events about RTP endpoints coming from the msc_a->cc.call_leg know which gsm_trans to abort on
	 * error */
	if (!msc_a->cc.active_trans)
		msc_a->cc.active_trans = for_cc_trans;
	if (msc_a->cc.active_trans != for_cc_trans) {
		LOG_TRANS(for_cc_trans, LOGL_ERROR,
			  "Cannot create call leg, another trans is already active for this conn\n");
		return NULL;
	}

	if (!cl) {
		cl = msc_a->cc.call_leg = call_leg_alloc(msc_a->c.fi,
							 MSC_EV_CALL_LEG_TERM,
							 MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE,
							 MSC_EV_CALL_LEG_RTP_COMPLETE);
		OSMO_ASSERT(cl);

		if (net->use_osmux != OSMUX_USAGE_OFF) {
			struct msc_i *msc_i = msc_a_msc_i(msc_a);
			if (msc_i->c.remote_to) {
				/* TODO: investigate what to do in this case */
				LOG_MSC_A(msc_a, LOGL_ERROR, "Osmux not yet supported for inter-MSC");
			} else {
				cl->ran_peer_supports_osmux = msc_i->ran_conn->ran_peer->remote_supports_osmux;
			}
		}

	}
	return cl;
}

int msc_a_ensure_cn_local_rtp(struct msc_a *msc_a, struct gsm_trans *cc_trans)
{
	struct call_leg *cl;
	struct rtp_stream *rtp_to_ran;

	cl = msc_a_ensure_call_leg(msc_a, cc_trans);
	if (!cl)
		return -EINVAL;
	rtp_to_ran = cl->rtp[RTP_TO_RAN];

	if (call_leg_local_ip(cl, RTP_TO_CN)) {
		/* Already has an RTP address and port towards the CN, continue right away. */
		return osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE, cl->rtp[RTP_TO_CN]);
	}

	/* No CN RTP address available yet, ask the MGW to create one.
	 * Set a codec to be used: if Assignment on the RAN side is already done, take the same codec as the RTP_TO_RAN.
	 * If no RAN side RTP is established, try to guess a preliminary codec from SDP -- before Assignment, picking a
	 * codec from the SDP is more politeness/avoiding confusion than necessity. The actual codec to be used would be
	 * determined later. If no codec could be determined, pass none for the time being. */
	return call_leg_ensure_ci(cl, RTP_TO_CN, cc_trans->call_id, cc_trans,
				  rtp_to_ran->codecs_known ? &rtp_to_ran->codecs : NULL, NULL);
}

/* The MGW has given us a local IP address for the RAN side. Ready to start the Assignment of a voice channel. */
static void msc_a_call_leg_ran_local_addr_available(struct msc_a *msc_a)
{
	struct ran_msg msg;
	struct gsm_trans *cc_trans = msc_a->cc.active_trans;
	struct gsm0808_channel_type channel_type;

	if (!cc_trans) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "No CC transaction active\n");
		call_leg_release(msc_a->cc.call_leg);
		return;
	}

	trans_cc_filter_run(cc_trans);
	LOG_TRANS(cc_trans, LOGL_DEBUG, "Sending Assignment Command\n");

	switch (cc_trans->bearer_cap.transfer) {
	case GSM48_BCAP_ITCAP_SPEECH:
		if (!cc_trans->cc.local.audio_codecs.count) {
			LOG_TRANS(cc_trans, LOGL_ERROR, "Assignment not possible, no matching codec: %s\n",
				  codec_filter_to_str(&cc_trans->cc.codecs, &cc_trans->cc.local, &cc_trans->cc.remote));
			call_leg_release(msc_a->cc.call_leg);
			return;
		}

		/* Compose 48.008 Channel Type from the current set of codecs
		 * determined from both local and remote codec capabilities. */
		if (sdp_audio_codecs_to_gsm0808_channel_type(&channel_type, &cc_trans->cc.local.audio_codecs)) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "Cannot compose Channel Type (Permitted Speech) from codecs: %s\n",
				  codec_filter_to_str(&cc_trans->cc.codecs, &cc_trans->cc.local, &cc_trans->cc.remote));
			trans_free(cc_trans);
			return;
		}
		break;
	case GSM48_BCAP_ITCAP_UNR_DIG_INF:
		if (!cc_trans->cc.local.bearer_services.count) {
			LOG_TRANS(cc_trans, LOGL_ERROR, "Assignment not possible, no matching bearer service: %s\n",
				  csd_filter_to_str(&cc_trans->cc.csd, &cc_trans->cc.local, &cc_trans->cc.remote));
			call_leg_release(msc_a->cc.call_leg);
			return;
		}

		/* Compose 48.008 Channel Type from the current set of bearer
		 * services determined from local and remote capabilities. */
		if (csd_bs_list_to_gsm0808_channel_type(&channel_type, &cc_trans->cc.local.bearer_services)) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "Cannot compose channel type from: %s\n",
				  csd_filter_to_str(&cc_trans->cc.csd, &cc_trans->cc.local, &cc_trans->cc.remote));
			return;
		}
		break;
	default:
		LOG_TRANS(cc_trans, LOGL_ERROR, "Assignment not possible for information transfer capability %d\n",
			  cc_trans->bearer_cap.transfer);
		call_leg_release(msc_a->cc.call_leg);
		return;
	}

	/* The RAN side RTP address is known, so the voice/CSD Assignment can commence. */
	msg = (struct ran_msg){
		.msg_type = RAN_MSG_ASSIGNMENT_COMMAND,
		.assignment_command = {
			.cn_rtp = &msc_a->cc.call_leg->rtp[RTP_TO_RAN]->local,
			.channel_type = &channel_type,
			.osmux_present = msc_a->cc.call_leg->rtp[RTP_TO_RAN]->use_osmux,
			.osmux_cid = msc_a->cc.call_leg->rtp[RTP_TO_RAN]->local_osmux_cid,
			.call_id_present = true,
			.call_id = cc_trans->call_id,
			.lcls = cc_trans->cc.lcls,
		},
	};
	if (msc_a_ran_down(msc_a, MSC_ROLE_I, &msg)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Cannot send Assignment\n");
		trans_free(cc_trans);
		return;
	}
}

static struct gsm_trans *find_waiting_call(struct msc_a *msc_a)
{
	struct gsm_trans *trans;
	struct gsm_network *net = msc_a_net(msc_a);

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->msc_a != msc_a)
			continue;
		if (trans->type != TRANS_CC)
			continue;
		if (trans->msc_a->cc.active_trans == trans)
			continue;
		return trans;
	}
	return NULL;
}

static void msc_a_cleanup_rtp_streams(struct msc_a *msc_a, uint32_t event, void *data)
{
	switch (event) {

	case MSC_EV_CALL_LEG_TERM:
		msc_a->cc.call_leg = NULL;
		if (msc_a->cc.mncc_forwarding_to_remote_ran)
			msc_a->cc.mncc_forwarding_to_remote_ran->rtps = NULL;

		if (msc_a->ho.new_cell.mncc_forwarding_to_remote_ran)
			msc_a->ho.new_cell.mncc_forwarding_to_remote_ran->rtps = NULL;
		return;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_a->cc.mncc_forwarding_to_remote_ran = NULL;
		return;

	default:
		return;
	}
}

static void msc_a_fsm_communicating(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;
	struct rtp_stream *rtps;
	struct gsm_trans *waiting_trans;
	struct an_apdu *an_apdu;

	msc_a_cleanup_rtp_streams(msc_a, event, data);

	switch (event) {
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		an_apdu = data;
		msc_a_ran_dec(msc_a, an_apdu, MSC_ROLE_I);
		return;

	case MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE:
	case MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE:
	case MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST:
		an_apdu = data;
		msc_a_ran_dec(msc_a, an_apdu, MSC_ROLE_T);
		return;

	case MSC_A_EV_TRANSACTION_ACCEPTED:
		/* no-op */
		return;

	case MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE:
		rtps = data;
		if (!rtps) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "Invalid data for %s\n", osmo_fsm_event_name(fi->fsm, event));
			return;
		}
		if (!msc_a->cc.call_leg) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "No call leg active\n");
			return;
		}
		if (!osmo_sockaddr_str_is_nonzero(&rtps->local)) {
			LOG_MSC_A(msc_a, LOGL_ERROR, "Invalid RTP address received from MGW: " OSMO_SOCKADDR_STR_FMT "\n",
				 OSMO_SOCKADDR_STR_FMT_ARGS(&rtps->local));
			call_leg_release(msc_a->cc.call_leg);
			return;
		}
		LOG_MSC_A(msc_a, LOGL_DEBUG,
			  "MGW endpoint's RTP address available for the CI %s: " OSMO_SOCKADDR_STR_FMT " (osmux=%s:%d)\n",
			  rtp_direction_name(rtps->dir), OSMO_SOCKADDR_STR_FMT_ARGS(&rtps->local),
			  rtps->use_osmux ? "yes" : "no", rtps->local_osmux_cid);
		switch (rtps->dir) {
		case RTP_TO_RAN:
			msc_a_call_leg_ran_local_addr_available(msc_a);
			return;
		case RTP_TO_CN:
			cc_on_cn_local_rtp_port_known(rtps->for_trans);
			return;
		default:
			LOG_MSC_A(msc_a, LOGL_ERROR, "Invalid data for %s\n", osmo_fsm_event_name(fi->fsm, event));
			return;
		}

	case MSC_EV_CALL_LEG_RTP_COMPLETE:
		/* Nothing to do. */
		return;

	case MSC_MNCC_EV_CALL_ENDED:
		/* Cleaned up above */
		return;

	case MSC_EV_CALL_LEG_TERM:
		/* RTP streams cleaned up above */

		msc_a_get(msc_a, __func__);
		if (msc_a->cc.active_trans)
			trans_free(msc_a->cc.active_trans);

		/* If there is another call still waiting to be activated, this is the time when the mgcp_ctx is
		 * available again and the other call can start assigning. */
		waiting_trans = find_waiting_call(msc_a);
		if (waiting_trans) {
			LOG_MSC_A(msc_a, LOGL_DEBUG, "(ti %02x) Call waiting: starting Assignment\n",
				  waiting_trans->transaction_id);
			msc_a_try_call_assignment(waiting_trans);
		}
		msc_a_put(msc_a, __func__);
		return;

	case MSC_A_EV_HANDOVER_REQUIRED:
		msc_ho_start(msc_a, (struct ran_handover_required*)data);
		return;

	case MSC_A_EV_HANDOVER_END:
		/* Termination event of the msc_ho_fsm. No action needed, it's all done in the msc_ho_fsm cleanup. This
		 * event only exists because osmo_fsm_inst_alloc_child() requires a parent term event; and maybe
		 * interesting for logging. */
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
	case MSC_A_EV_UNUSED:
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static int msc_a_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct msc_a *msc_a = fi->priv;
	if (msc_a_in_release(msc_a)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Timeout while releasing, discarding right now\n");
		msc_a_put_all(msc_a, MSC_A_USE_WAIT_CLEAR_COMPLETE);
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASED);
	} else {
		enum gsm48_reject_value cause = GSM48_REJECT_CONGESTION;
		osmo_fsm_inst_dispatch(fi, MSC_A_EV_CN_CLOSE, &cause);
	}
	return 0;
}

static void msc_a_fsm_releasing_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_a *msc_a = fi->priv;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	int i;
	char buf[128];
	const char * const use_counts_to_cancel[] = {
		MSC_A_USE_LOCATION_UPDATING,
		MSC_A_USE_CM_SERVICE_CC,
		MSC_A_USE_CM_SERVICE_SMS,
		MSC_A_USE_CM_SERVICE_SS,
		MSC_A_USE_CM_SERVICE_GCC,
		MSC_A_USE_CM_SERVICE_BCC,
		MSC_A_USE_PAGING_RESPONSE,
	};

	LOG_MSC_A(msc_a, LOGL_DEBUG, "Releasing: msc_a use is %s\n",
		  osmo_use_count_name_buf(buf, sizeof(buf), &msc_a->use_count));

	if (vsub) {
		vlr_subscr_get(vsub, __func__);

		/* Cancel all VLR FSMs, if any */
		vlr_subscr_cancel_attach_fsm(vsub, OSMO_FSM_TERM_ERROR, GSM48_REJECT_CONGESTION);

		/* The subscriber has no active connection anymore.
		 * Restart the periodic Location Update expiry timer for this subscriber. */
		vlr_subscr_enable_expire_lu(vsub);
	}

	/* If we're closing in a middle of a trans, we need to clean up */
	trans_conn_closed(msc_a);

	call_leg_release(msc_a->cc.call_leg);

	/* Cancel use counts for pending CM Service / Paging */
	for (i = 0; i < ARRAY_SIZE(use_counts_to_cancel); i++) {
		const char *use = use_counts_to_cancel[i];
		int32_t count = osmo_use_count_by(&msc_a->use_count, use);
		if (!count)
			continue;
		LOG_MSC_A(msc_a, LOGL_DEBUG, "Releasing: canceling still pending use: %s (%d)\n", use, count);
		osmo_use_count_get_put(&msc_a->use_count, use, -count);
	}

	if (msc_a->c.ran->type == OSMO_RAT_EUTRAN_SGS) {
		sgs_iface_tx_release(vsub);
		/* In SGsAP there is no confirmation of a release. */
		msc_a_state_chg(msc_a, MSC_A_ST_RELEASED);
	} else {
		struct ran_msg msg = {
			.msg_type = RAN_MSG_CLEAR_COMMAND,
			.clear_command = {
				/* "Call Control" is the only cause code listed in 3GPP TS 48.008 3.2.1.21 CLEAR COMMAND
				 * that qualifies for a normal release situation. (OS#4664) */
				.gsm0808_cause = GSM0808_CAUSE_CALL_CONTROL,
				.csfb_ind = (vsub && vsub->sgs_fsm->state == SGS_UE_ST_ASSOCIATED),
			},
		};
		msc_a_get(msc_a, MSC_A_USE_WAIT_CLEAR_COMPLETE);
		msc_a_ran_down(msc_a, MSC_ROLE_I, &msg);

		/* The connection is cleared. The MS will now go back to 4G,
		   Switch the RAN type back to SGS. */
		if (vsub && vsub->sgs_fsm->state == SGS_UE_ST_ASSOCIATED)
			vsub->cs.attached_via_ran = OSMO_RAT_EUTRAN_SGS;
	}

	if (vsub)
		vlr_subscr_put(vsub, __func__);
}

static void msc_a_fsm_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_a *msc_a = fi->priv;

	msc_a_cleanup_rtp_streams(msc_a, event, data);

	switch (event) {
	case MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST:
	case MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST:
		msc_a_ran_dec(msc_a, data, MSC_ROLE_I);
		return;

	case MSC_A_EV_MO_CLOSE:
	case MSC_A_EV_CN_CLOSE:
	case MSC_A_EV_UNUSED:
		/* Already releasing */
		return;

	case MSC_EV_CALL_LEG_TERM:
	case MSC_MNCC_EV_CALL_ENDED:
		/* RTP streams cleaned up above */
		return;

	case MSC_A_EV_HANDOVER_END:
		/* msc_ho_fsm does cleanup. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}


static void msc_a_fsm_released_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_a *msc_a = msc_a_fi_priv(fi);
	char buf[128];
	LOG_MSC_A(msc_a, LOGL_DEBUG, "Released: msc_a use is %s\n",
		  osmo_use_count_name_buf(buf, sizeof(buf), &msc_a->use_count));
	if (osmo_use_count_total(&msc_a->use_count) == 0)
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, fi);
}

static void msc_a_fsm_released(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	if (event == MSC_A_EV_UNUSED)
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, fi);
}

void msc_a_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_a *msc_a = msc_a_fi_priv(fi);

	trans_conn_closed(msc_a);

	if (msc_a_fsm_has_active_transactions(fi))
		LOG_MSC_A(msc_a, LOGL_ERROR, "Deallocating active transactions failed\n");

	LOG_MSC_A_CAT(msc_a, DREF, LOGL_DEBUG, "max total use count was %d\n", msc_a->max_total_use_count);
}

const struct value_string msc_a_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSC_REMOTE_EV_RX_GSUP),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_COMPLETE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_TERM),
	OSMO_VALUE_STRING(MSC_MNCC_EV_NEED_LOCAL_RTP),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_PROCEEDING),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_COMPLETE),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_ENDED),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_I_COMPLETE_LAYER_3),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE),
	OSMO_VALUE_STRING(MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST),
	OSMO_VALUE_STRING(MSC_A_EV_COMPLETE_LAYER_3_OK),
	OSMO_VALUE_STRING(MSC_A_EV_CLASSMARK_UPDATE),
	OSMO_VALUE_STRING(MSC_A_EV_AUTHENTICATED),
	OSMO_VALUE_STRING(MSC_A_EV_TRANSACTION_ACCEPTED),
	OSMO_VALUE_STRING(MSC_A_EV_CN_CLOSE),
	OSMO_VALUE_STRING(MSC_A_EV_MO_CLOSE),
	OSMO_VALUE_STRING(MSC_A_EV_UNUSED),
	OSMO_VALUE_STRING(MSC_A_EV_HANDOVER_REQUIRED),
	OSMO_VALUE_STRING(MSC_A_EV_HANDOVER_END),
	{}
};

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_a_fsm_states[] = {
	[MSC_A_ST_VALIDATE_L3] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_VALIDATE_L3),
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_COMPLETE_LAYER_3)
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_COMPLETE_LAYER_3_OK)
			| S(MSC_A_EV_MO_CLOSE)
			| S(MSC_A_EV_CN_CLOSE)
			| S(MSC_A_EV_UNUSED)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_VALIDATE_L3)
			| S(MSC_A_ST_AUTH_CIPH)
			| S(MSC_A_ST_RELEASING)
			,
		.action = msc_a_fsm_validate_l3,
	},
	[MSC_A_ST_AUTH_CIPH] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_AUTH_CIPH),
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_AUTHENTICATED)
			| S(MSC_A_EV_MO_CLOSE)
			| S(MSC_A_EV_CN_CLOSE)
			| S(MSC_A_EV_UNUSED)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_WAIT_CLASSMARK_UPDATE)
			| S(MSC_A_ST_AUTHENTICATED)
			| S(MSC_A_ST_RELEASING)
			,
		.action = msc_a_fsm_auth_ciph,
	},
	[MSC_A_ST_WAIT_CLASSMARK_UPDATE] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_WAIT_CLASSMARK_UPDATE),
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_CLASSMARK_UPDATE)
			| S(MSC_A_EV_MO_CLOSE)
			| S(MSC_A_EV_CN_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_AUTH_CIPH)
			| S(MSC_A_ST_RELEASING)
			,
		.action = msc_a_fsm_wait_classmark_update,
	},
	[MSC_A_ST_AUTHENTICATED] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_AUTHENTICATED),
		/* allow everything to release for any odd behavior */
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_TRANSACTION_ACCEPTED)
			| S(MSC_A_EV_MO_CLOSE)
			| S(MSC_A_EV_CN_CLOSE)
			| S(MSC_A_EV_UNUSED)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_RELEASING)
			| S(MSC_A_ST_COMMUNICATING)
			,
		.onenter = msc_a_fsm_authenticated_enter,
		.action = msc_a_fsm_authenticated,
	},
	[MSC_A_ST_COMMUNICATING] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_COMMUNICATING),
		/* allow everything to release for any odd behavior */
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_PREPARE_SUBSEQUENT_HANDOVER_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE)
			| S(MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE)
			| S(MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_TRANSACTION_ACCEPTED)
			| S(MSC_A_EV_MO_CLOSE)
			| S(MSC_A_EV_CN_CLOSE)
			| S(MSC_A_EV_UNUSED)
			| S(MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE)
			| S(MSC_EV_CALL_LEG_RTP_COMPLETE)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_A_EV_HANDOVER_REQUIRED)
			| S(MSC_A_EV_HANDOVER_END)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_RELEASING)
			,
		.action = msc_a_fsm_communicating,
	},
	[MSC_A_ST_RELEASING] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_RELEASING),
		.in_event_mask = 0
			| S(MSC_A_EV_FROM_I_PROCESS_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_A_EV_FROM_I_SEND_END_SIGNAL_REQUEST)
			| S(MSC_A_EV_UNUSED)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_A_EV_HANDOVER_END)
			| S(MSC_A_EV_CN_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_A_ST_RELEASED)
			,
		.onenter = msc_a_fsm_releasing_onenter,
		.action = msc_a_fsm_releasing,
	},
	[MSC_A_ST_RELEASED] = {
		.name = OSMO_STRINGIFY(MSC_A_ST_RELEASED),
		.in_event_mask = 0
			| S(MSC_A_EV_UNUSED)
			,
		.onenter = msc_a_fsm_released_onenter,
		.action = msc_a_fsm_released,
	},
};

static struct osmo_fsm msc_a_fsm = {
	.name = "msc_a",
	.states = msc_a_fsm_states,
	.num_states = ARRAY_SIZE(msc_a_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_a_fsm_event_names,
	.timer_cb = msc_a_fsm_timer_cb,
	.cleanup = msc_a_fsm_cleanup,
};

static __attribute__((constructor)) void msc_a_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&msc_a_fsm) == 0);
}

static int msc_a_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct msc_a *msc_a = e->use_count->talloc_object;
	char buf[128];
	int32_t total;
	int level;

	if (!e->use)
		return -EINVAL;

	total = osmo_use_count_total(&msc_a->use_count);

	if (total == 0
	    || (total == 1 && old_use_count == 0 && e->count == 1))
		level = LOGL_INFO;
	else
		level = LOGL_DEBUG;

	LOG_MSC_A_CAT_SRC(msc_a, DREF, level, file, line, "%s %s: now used by %s\n",
			  (e->count - old_use_count) > 0? "+" : "-", e->use,
			  osmo_use_count_name_buf(buf, sizeof(buf), &msc_a->use_count));

	if (e->count < 0)
		return -ERANGE;

	msc_a->max_total_use_count = OSMO_MAX(msc_a->max_total_use_count, total);

	if (total == 0)
		osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_UNUSED, NULL);
	return 0;
}

struct msc_a *msc_a_alloc(struct msub *msub, struct ran_infra *ran)
{
	struct msc_a *msc_a = msub_role_alloc(msub, MSC_ROLE_A, &msc_a_fsm, struct msc_a, ran);
	msc_a->use_count = (struct osmo_use_count){
		.talloc_object = msc_a,
		.use_cb = msc_a_use_cb,
	};
	osmo_use_count_make_static_entries(&msc_a->use_count, msc_a->use_count_buf, ARRAY_SIZE(msc_a->use_count_buf));
	/* Start timeout for first state */
	msc_a_state_chg_always(msc_a, MSC_A_ST_VALIDATE_L3);
	return msc_a;
}

bool msc_a_is_establishing_auth_ciph(const struct msc_a *msc_a)
{
	if (!msc_a || !msc_a->c.fi)
		return false;
	return msc_a->c.fi->state == MSC_A_ST_AUTH_CIPH;
}

const struct value_string complete_layer3_type_names[] = {
	{ COMPLETE_LAYER3_NONE, "NONE" },
	{ COMPLETE_LAYER3_LU, "LU" },
	{ COMPLETE_LAYER3_CM_SERVICE_REQ, "CM_SERVICE_REQ" },
	{ COMPLETE_LAYER3_PAGING_RESP, "PAGING_RESP" },
	{ COMPLETE_LAYER3_CM_RE_ESTABLISH_REQ, "CM_RE_ESTABLISH_REQ" },
	{ 0, NULL }
};

#define _msc_a_update_id(MSC_A, FMT, ARGS ...) \
	do { \
		if (osmo_fsm_inst_update_id_f(msc_a->c.fi, FMT ":%s:%s", \
					      ## ARGS, \
					      msub_ran_conn_name(msc_a->c.msub), \
					      complete_layer3_type_name(msc_a->complete_layer3_type)) \
		    == 0) { \
			struct vlr_subscr *_vsub = msc_a_vsub(MSC_A); \
			if (_vsub) { \
				if (_vsub->lu_fsm) \
					osmo_fsm_inst_update_id(_vsub->lu_fsm, (MSC_A)->c.fi->id); \
				if (_vsub->auth_fsm) \
					osmo_fsm_inst_update_id(_vsub->auth_fsm, (MSC_A)->c.fi->id); \
				if (_vsub->proc_arq_fsm) \
					osmo_fsm_inst_update_id(_vsub->proc_arq_fsm, (MSC_A)->c.fi->id); \
			} \
			LOG_MSC_A(MSC_A, LOGL_DEBUG, "Updated ID\n"); \
		} \
		/* otherwise osmo_fsm_inst_update_id_f() will log an error. */ \
	} while (0)


/* Compose an ID almost like gsm48_mi_to_string(), but print the MI type along, and print a TMSI as hex. */
void msc_a_update_id_from_mi(struct msc_a *msc_a, const struct osmo_mobile_identity *mi)
{
	_msc_a_update_id(msc_a, "%s", osmo_mobile_identity_to_str_c(OTC_SELECT, mi));
}

/* Update msc_a->fi id string from current msc_a->vsub and msc_a->complete_layer3_type. */
void msc_a_update_id(struct msc_a *msc_a)
{
	_msc_a_update_id(msc_a, "%s", vlr_subscr_name(msc_a_vsub(msc_a)));
}

/* Iterate all msc_a instances that are relevant for this subscriber, and update FSM ID strings for all of the FSM
 * instances. */
void msc_a_update_id_for_vsub(struct vlr_subscr *for_vsub)
{
	struct msub *msub;
	llist_for_each_entry(msub, &msub_list, entry) {
		struct vlr_subscr *vsub = msub_vsub(msub);
		if (vsub != for_vsub)
			continue;
		msc_a_update_id(msub_msc_a(msub));
	}
}

static bool msg_is_initially_permitted(const struct gsm48_hdr *hdr)
{
	uint8_t pdisc = gsm48_hdr_pdisc(hdr);
	uint8_t msg_type = gsm48_hdr_msg_type(hdr);

	switch (pdisc) {
	case GSM48_PDISC_MM:
		switch (msg_type) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
		case GSM48_MT_MM_CM_SERV_REQ:
		case GSM48_MT_MM_CM_REEST_REQ:
		case GSM48_MT_MM_AUTH_RESP:
		case GSM48_MT_MM_AUTH_FAIL:
		case GSM48_MT_MM_ID_RESP:
		case GSM48_MT_MM_TMSI_REALL_COMPL:
		case GSM48_MT_MM_IMSI_DETACH_IND:
			return true;
		default:
			break;
		}
		break;
	case GSM48_PDISC_RR:
		switch (msg_type) {
		/* GSM48_MT_RR_CIPH_M_COMPL is actually handled in bssmap_rx_ciph_compl() and gets redirected in the
		 * BSSAP layer to ran_conn_cipher_mode_compl() (before this here is reached) */
		case GSM48_MT_RR_PAG_RESP:
		case GSM48_MT_RR_CIPH_M_COMPL:
			return true;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return false;
}

/* Main entry point for GSM 04.08/44.008 Layer 3 data (e.g. from the BSC). */
int msc_a_up_l3(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	int rc;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	int is_r99;

	OSMO_ASSERT(msg->l3h);
	OSMO_ASSERT(msg);

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);

	LOG_MSC_A_CAT(msc_a, DRLL, LOGL_DEBUG, "Dispatching 04.08 message: %s %s\n",
		      gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));

	/* To evaluate the 3GPP TS 24.007 Duplicate Detection, we need Classmark information on whether the MS is R99
	 * capable. If the subscriber is already actively connected, the Classmark information is stored with the
	 * vlr_subscr. Otherwise, this *must* be a Complete Layer 3 with Classmark info. */
	if (vsub)
		is_r99 = osmo_gsm48_classmark_is_r99(&vsub->classmark) ? 1 : 0;
	else
		is_r99 = compl_l3_msg_is_r99(msg);

	if (is_r99 < 0) {
		LOG_MSC_A(msc_a, LOGL_ERROR,
			  "No Classmark Information, dropping non-Complete-Layer3 message: %s\n",
			  gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));
		return -EACCES;
	}

	if (is_r99 >= 0
	    && ran_dec_dtap_undup_is_duplicate(msc_a->c.fi, msc_a->n_sd_next, is_r99 ? true : false, msg)) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "Dropping duplicate message"
			  " (3GPP TS 24.007 11.2.3.2 Message Type Octet / Duplicate Detection)\n");
		return 0;
	}

	if (!msc_a_is_accepted(msc_a)
	    && !msg_is_initially_permitted(gh)) {
		LOG_MSC_A(msc_a, LOGL_ERROR,
			  "Message not permitted for initial conn: %s\n",
			  gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));
		return -EACCES;
	}

	if (vsub && vsub->cs.attached_via_ran != msc_a->c.ran->type) {
		LOG_MSC_A(msc_a, LOGL_ERROR,
			  "Illegal situation: RAN type mismatch:"
			  " attached via %s, received message via %s\n",
			  osmo_rat_type_name(vsub->cs.attached_via_ran),
			  osmo_rat_type_name(msc_a->c.ran->type));
		return -EACCES;
	}

#if 0
	if (silent_call_reroute(conn, msg))
		return silent_call_rx(conn, msg);
#endif

	switch (pdisc) {
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
		rc = gsm44068_rcv_bcc_gcc(msc_a, NULL, msg);
		break;
	case GSM48_PDISC_CC:
		rc = gsm0408_rcv_cc(msc_a, msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(msc_a, msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(msc_a, msg);
		break;
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(msc_a, msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		LOG_MSC_A_CAT(msc_a, DRLL, LOGL_NOTICE, "Unimplemented "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -ENOTSUP;
		break;
	case GSM48_PDISC_NC_SS:
		rc = gsm0911_rcv_nc_ss(msc_a, msg);
		break;
	case GSM48_PDISC_TEST:
		rc = gsm0414_rcv_test(msc_a, msg);
		break;
	default:
		LOG_MSC_A_CAT(msc_a, DRLL, LOGL_NOTICE, "Unknown "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static void msc_a_up_call_assignment_complete(struct msc_a *msc_a, const struct ran_msg *ac)
{
	struct gsm_trans *cc_trans = msc_a->cc.active_trans, *gcc_trans;
	struct rtp_stream *rtps_to_ran = msc_a->cc.call_leg ? msc_a->cc.call_leg->rtp[RTP_TO_RAN] : NULL;
	const struct gsm0808_speech_codec *codec_if_known = ac->assignment_complete.codec_present ?
							    &ac->assignment_complete.codec : NULL;

	/* For a voice group call, handling is performed by VGCS FSM */
	gcc_trans = trans_find_by_type(msc_a, TRANS_GCC);
	if (gcc_trans) {
		vgcs_vbs_caller_assign_cpl(gcc_trans);
		return;
	}
	gcc_trans = trans_find_by_type(msc_a, TRANS_BCC);
	if (gcc_trans) {
		vgcs_vbs_caller_assign_cpl(gcc_trans);
		return;
	}

	if (!rtps_to_ran) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx Assignment Complete, but no RTP stream is set up\n");
		return;
	}
	if (!cc_trans) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx Assignment Complete, but no CC transaction is active\n");
		return;
	}

	if (rtps_to_ran->use_osmux != ac->assignment_complete.osmux_present) {
		LOG_MSC_A_CAT(msc_a, DCC, LOGL_ERROR, "Osmux usage ass request and complete don't match: %d vs %d\n",
			 rtps_to_ran->use_osmux, ac->assignment_complete.osmux_present);
		call_leg_release(msc_a->cc.call_leg);
		return;
	}

	if (codec_if_known) {
		const struct codec_mapping *codec_cn;
		/* For 2G:
		 * - The Assignment Complete has returned a specific codec (e.g. FR3 for AMR FR).
		 * - Set this codec at the MGW endpoint facing the RAN.
		 * - Also set this codec at the MGW endpoint facing the CN -- we require an exact match on both call
		 *   legs.
		 *   - TODO: be aware of transcoding that the MGW is capable of, e.g. AMR octet-aligned to AMR
		 *     bandwidth-efficient...
		 *
		 * For 3G:
		 * - ran_infra->force_mgw_codecs_to_ran sets VND.3GPP.IUFP as single codec at the MGW towards RAN.
		 * - ran_msg_iu.c always returns FR3 (AMR FR) for the assigned codec. Set that at the MGW towards CN.
		 * - So the MGW decapsulates IuUP <-> AMR
		 */
		codec_cn = codec_mapping_by_gsm0808_speech_codec_type(codec_if_known->type);
		/* TODO: use codec_mapping_by_gsm0808_speech_codec() to also match on codec_if_known->cfg */
		if (!codec_cn) {
			LOG_TRANS(cc_trans, LOGL_ERROR, "Unknown codec in Assignment Complete: %s\n",
				  gsm0808_speech_codec_type_name(codec_if_known->type));
			call_leg_release(msc_a->cc.call_leg);
			return;
		}

		/* Check for unexpected codec with CSD */
		if (cc_trans->bearer_cap.transfer == GSM48_BCAP_ITCAP_UNR_DIG_INF &&
		    codec_if_known->type != GSM0808_SCT_CSD) {
			LOG_TRANS(cc_trans, LOGL_ERROR, "Unexpected codec in Assignment Complete for CSD: %s\n",
				  gsm0808_speech_codec_type_name(codec_if_known->type));
			call_leg_release(msc_a->cc.call_leg);
			return;
		}

		/* Update RAN-side endpoint CI from Assignment result -- unless it is forced by the ran_infra, in which
		 * case it remains unchanged as passed to the earlier call of call_leg_ensure_ci(). */
		if (msc_a->c.ran->force_mgw_codecs_to_ran.count == 0)
			rtp_stream_set_one_codec(rtps_to_ran, &codec_cn->sdp);

		/* Update codec filter with Assignment result, for the CN side */
		cc_trans->cc.codecs.assignment = codec_cn->sdp;
	} else {
		/* No codec passed in Assignment Complete, set 'codecs.assignment' to none. */
		cc_trans->cc.codecs.assignment = (struct sdp_audio_codec){};
		LOG_TRANS(cc_trans, LOGL_INFO, "Assignment Complete without voice codec\n");
	}

	rtp_stream_set_remote_addr(rtps_to_ran, &ac->assignment_complete.remote_rtp);
	if (rtps_to_ran->use_osmux)
		rtp_stream_set_remote_osmux_cid(rtps_to_ran,
						ac->assignment_complete.osmux_cid);
	rtp_stream_commit(rtps_to_ran);

	/* Remember the Codec List (BSS Supported) */
	if (ac->assignment_complete.codec_list_bss_supported)
		codec_filter_set_bss(&cc_trans->cc.codecs, ac->assignment_complete.codec_list_bss_supported);

	trans_cc_filter_run(cc_trans);
	LOG_TRANS(cc_trans, LOGL_INFO, "Assignment Complete: RAN: %s, CN: %s\n",
		  sdp_audio_codecs_to_str(&rtps_to_ran->codecs),
		  sdp_audio_codecs_to_str(&cc_trans->cc.local.audio_codecs));

	if (cc_on_assignment_done(cc_trans)) {
		/* If an error occurred, it was logged in cc_assignment_done() */
		call_leg_release(msc_a->cc.call_leg);
		return;
	}
}

static void msc_a_up_call_assignment_failure(struct msc_a *msc_a, const struct ran_msg *af)
{
	struct gsm_trans *trans;

	/* For a normal voice call, there will be an rtp_stream FSM. */
	if (msc_a->cc.call_leg && msc_a->cc.call_leg->rtp[RTP_TO_RAN]) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Assignment Failure, releasing call\n");
		rtp_stream_release(msc_a->cc.call_leg->rtp[RTP_TO_RAN]);
		return;
	}

	/* For a voice group call, release is performed by VGCS FSM */
	trans = trans_find_by_type(msc_a, TRANS_GCC);
	if (trans) {
		vgcs_vbs_caller_assign_fail(trans);
		return;
	}
	trans = trans_find_by_type(msc_a, TRANS_BCC);
	if (trans) {
		vgcs_vbs_caller_assign_fail(trans);
		return;
	}

	/* Otherwise, a silent call might be active */
	trans = trans_find_by_type(msc_a, TRANS_SILENT_CALL);
	if (trans) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Assignment Failure, releasing silent call\n");
		trans_free(trans);
		return;
	}

	/* Neither a voice call nor silent call assignment. Assume the worst and detach. */
	msc_a_release_cn(msc_a);
}

static void msc_a_up_classmark_update(struct msc_a *msc_a, const struct osmo_gsm48_classmark *classmark,
				      struct osmo_gsm48_classmark *dst)
{
	if (!dst) {
		struct vlr_subscr *vsub = msc_a_vsub(msc_a);

		if (!vsub)
			dst = &msc_a->temporary_classmark;
		else
			dst = &vsub->classmark;
	}

	LOG_MSC_A(msc_a, LOGL_DEBUG, "A5 capabilities received from Classmark Update: %s\n",
		  osmo_gsm48_classmark_a5_name(classmark));
	osmo_gsm48_classmark_update(dst, classmark);

	/* bump subscr conn FSM in case it is waiting for a Classmark Update */
	if (msc_a->c.fi->state == MSC_A_ST_WAIT_CLASSMARK_UPDATE)
		osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_CLASSMARK_UPDATE, NULL);
}

static void msc_a_up_sapi_n_reject(struct msc_a *msc_a, const struct ran_msg *msg)
{
	int sapi = msg->sapi_n_reject.dlci & 0x7;
	if (sapi == UM_SAPI_SMS)
		gsm411_sapi_n_reject(msc_a);
}

static int msc_a_up_ho(struct msc_a *msc_a, const struct msc_a_ran_dec_data *d, uint32_t ho_fi_event)
{
	if (!msc_a->ho.fi) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx Handover message, but no Handover ongoing: %s\n", d->ran_dec->msg_name);
		return -EINVAL;
	}
	return osmo_fsm_inst_dispatch(msc_a->ho.fi, ho_fi_event, (void*)d);
}

int msc_a_ran_dec_from_msc_i(struct msc_a *msc_a, struct msc_a_ran_dec_data *d)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct gsm_network *net = msc_a_net(msc_a);
	const struct ran_msg *msg = d->ran_dec;
	int rc = -99;

	switch (msg->msg_type) {

	case RAN_MSG_COMPL_L3:
		/* In case the cell_id from Complete Layer 3 Information lacks a PLMN, write the configured PLMN code
		 * into msc_a->via_cell. Then overwrite with those bits obtained from Complete Layer 3 Information. */
		msc_a->via_cell = (struct osmo_cell_global_id){
			.lai.plmn = msc_a_net(msc_a)->plmn,
		};
		gsm0808_cell_id_to_cgi(&msc_a->via_cell, msg->compl_l3.cell_id);

		/* If a codec list was sent along in the RAN_MSG_COMPL_L3, remember it for any upcoming codec
		 * resolution. */
		if (msg->compl_l3.codec_list_bss_supported) {
			msc_a->cc.compl_l3_codec_list_bss_supported = *msg->compl_l3.codec_list_bss_supported;
			if (log_check_level(msc_a->c.ran->log_subsys, LOGL_DEBUG)) {
				struct sdp_audio_codecs ac = {};
				sdp_audio_codecs_from_speech_codec_list(&ac, &msc_a->cc.compl_l3_codec_list_bss_supported);
				LOG_MSC_A(msc_a, LOGL_DEBUG, "Complete Layer 3: Codec List (BSS Supported): %s\n",
					  sdp_audio_codecs_to_str(&ac));
			}
		}

		/* Submit the Complete Layer 3 Information DTAP */
		rc = msc_a_up_l3(msc_a, msg->compl_l3.msg);
		if (!rc) {
			struct ran_conn *conn = msub_ran_conn(msc_a->c.msub);
			if (conn)
				ran_peer_cells_seen_add(conn->ran_peer, msg->compl_l3.cell_id);
		}
		break;

	case RAN_MSG_DTAP:
		rc = msc_a_up_l3(msc_a, msg->dtap);
		break;

	case RAN_MSG_CLEAR_REQUEST:
		rc = osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_MO_CLOSE, NULL);
		break;

	case RAN_MSG_CLEAR_COMPLETE:
		switch (msc_a->c.fi->state) {
		case MSC_A_ST_RELEASING:
			msc_a_put_all(msc_a, MSC_A_USE_WAIT_CLEAR_COMPLETE);
			msc_a_state_chg(msc_a, MSC_A_ST_RELEASED);
			break;
		case MSC_A_ST_RELEASED:
			break;
		default:
			LOG_MSC_A(msc_a, LOGL_ERROR, "Received Clear Complete event, but did not send Clear Command\n");
			msc_a_state_chg(msc_a, MSC_A_ST_RELEASING);
			break;
		}
		rc = 0;
		break;

	case RAN_MSG_CLASSMARK_UPDATE:
		msc_a_up_classmark_update(msc_a, msg->classmark_update.classmark, NULL);
		rc = 0;
		break;

	case RAN_MSG_CIPHER_MODE_COMPLETE:
		/* Remember what Ciphering was negotiated (e.g. for Handover) */
		if (msg->cipher_mode_complete.alg_id) {
			msc_a->geran_encr.alg_id = msg->cipher_mode_complete.alg_id;
			LOG_MSC_A(msc_a, LOGL_DEBUG, "Cipher Mode Complete: chosen encryption algorithm: A5/%u\n",
				  msc_a->geran_encr.alg_id - 1);
		}

		if (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU) {
			int16_t utran_encryption;

			/* utran: ensure chosen ciphering mode is allowed
			 * If the IE is missing (utran_encryption == -1), parse it as no encryption */
			utran_encryption = msg->cipher_mode_complete.utran_encryption;
			if (utran_encryption == -1)
				utran_encryption = 0;
			if ((net->uea_encryption_mask & (1 << utran_encryption)) == 0) {
				/* cipher disallowed */
				LOG_MSC_A(msc_a, LOGL_ERROR, "Cipher Mode Complete: RNC chosen forbidden ciphering UEA%d\n",
					  msg->cipher_mode_complete.utran_encryption);
				vlr_subscr_rx_ciph_res(vsub, VLR_CIPH_REJECT);
				rc = 0;
				break;
			}
		}
		vlr_subscr_rx_ciph_res(vsub, VLR_CIPH_COMPL);
		rc = 0;

		/* Evaluate enclosed L3 message, typically Identity Response (IMEISV) */
		if (msg->cipher_mode_complete.l3_msg) {
			unsigned char *data = (unsigned char*)(msg->cipher_mode_complete.l3_msg->val);
			uint16_t len = msg->cipher_mode_complete.l3_msg->len;
			struct msgb *dtap = msgb_alloc(len, "DTAP from Cipher Mode Complete");
			unsigned char *pos = msgb_put(dtap, len);
			memcpy(pos, data, len);
			dtap->l3h = pos;
			rc = msc_a_up_l3(msc_a, dtap);
			msgb_free(dtap);
		}
		break;

	case RAN_MSG_CIPHER_MODE_REJECT:
		vlr_subscr_rx_ciph_res(vsub, VLR_CIPH_REJECT);
		rc = 0;
		break;

	case RAN_MSG_ASSIGNMENT_COMPLETE:
		msc_a_up_call_assignment_complete(msc_a, msg);
		rc = 0;
		break;

	case RAN_MSG_ASSIGNMENT_FAILURE:
		msc_a_up_call_assignment_failure(msc_a, msg);
		rc = 0;
		break;

	case RAN_MSG_SAPI_N_REJECT:
		msc_a_up_sapi_n_reject(msc_a, msg);
		rc = 0;
		break;

	case RAN_MSG_HANDOVER_PERFORMED:
		/* The BSS lets us know that a handover happened within the BSS, which doesn't concern us. */
		LOG_MSC_A(msc_a, LOGL_ERROR, "'Handover Performed' handling not implemented\n");
		break;

	case RAN_MSG_HANDOVER_REQUIRED:
		/* The BSS lets us know that it wants to handover to a different cell */
		rc = osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_HANDOVER_REQUIRED, (void*)&msg->handover_required);
		break;

	case RAN_MSG_HANDOVER_FAILURE:
		rc = msc_a_up_ho(msc_a, d, MSC_HO_EV_RX_FAILURE);
		break;

	case RAN_MSG_LCLS_STATUS:
		/* The BSS sends us LCLS_STATUS. We do nothing for now, but it is not an error. */
		LOG_MSC_A(msc_a, LOGL_DEBUG, "LCLS_STATUS (%s) received from MSC-I\n",
			  gsm0808_lcls_status_name(msg->lcls_status.status));
		rc = 0;
		break;

	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "Message from MSC-I not implemented: %s\n", ran_msg_type_name(msg->msg_type));
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

static int msc_a_rx_vgcs_bss_decoded(struct osmo_fsm_inst *caller_fi, void *caller_data, const struct ran_msg *msg)
{
	struct vgcs_bss *bss = caller_data;
	struct msc_a *msc_a = (bss->trans) ? bss->trans->msc_a : NULL;
	int rc = 0;

	switch (msg->msg_type) {
	case RAN_MSG_VGCS_VBS_SETUP_ACK:
		/* The BSS accepts VGCS/VBS and sends us supported features. */
		vgcs_vbs_setup_ack(bss, msg);
		break;
	case RAN_MSG_VGCS_VBS_SETUP_REFUSE:
		/* The BSS refuses VGCS/VBS. */
		vgcs_vbs_setup_refuse(bss, msg);
		break;
	case RAN_MSG_UPLINK_REQUEST:
		/* A mobile station requests the uplink on a VGCS channel. */
		vgcs_uplink_request(bss, msg);
		break;
	case RAN_MSG_UPLINK_REQUEST_CNF:
		/* The uplink on a VGCS channel has been established. */
		vgcs_uplink_request_cnf(bss, msg);
		break;
	case RAN_MSG_UPLINK_APPLICATION_DATA:
		/* Application data received on the uplink of a VGCS channel. */
		vgcs_app_data(bss, msg);
		break;
	case RAN_MSG_DTAP:
		/* BSS confirms the release of the channel. */
		vgcs_bss_dtap(bss, msg);
		break;
	case RAN_MSG_UPLINK_RELEASE_IND:
		/* A mobile station releases the uplink on a VGCS channel. */
		vgcs_uplink_release_ind(bss, msg);
		break;
	case RAN_MSG_CLEAR_REQUEST:
		/* BSS indicated that the channel has been released. */
		vgcs_vbs_clear_req(bss, msg);
		break;
	case RAN_MSG_CLEAR_COMPLETE:
		/* BSS confirms the release of the channel. */
		vgcs_vbs_clear_cpl(bss, msg);
		break;
	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "VGCS message from BSS not implemented: %s\n",
			  ran_msg_type_name(msg->msg_type));
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

int msc_a_rx_vgcs_bss(struct vgcs_bss *bss, struct ran_conn *from_conn, struct msgb *msg)
{
	struct ran_dec ran_dec;

	/* Feed through the decoding mechanism ran_msg. The decoded message arrives in msc_a_rx_vgcs_decoded() */
	ran_dec = (struct ran_dec) {
		.caller_data = bss,
		.decode_cb = msc_a_rx_vgcs_bss_decoded,
	};
	struct ran_peer *ran_peer = from_conn->ran_peer;
	struct ran_infra *ran = ran_peer->sri->ran;
	if (!ran->ran_dec_l2) {
		LOGP(DMSC, LOGL_ERROR, "No ran_dec_l2() defined for RAN type %s\n",
		     osmo_rat_type_name(ran->type));
		return -ENOTSUP;
	}
	return ran->ran_dec_l2(&ran_dec, msg);
}

static int msc_a_rx_vgcs_cell_decoded(struct osmo_fsm_inst *caller_fi, void *caller_data, const struct ran_msg *msg)
{
	struct vgcs_bss_cell *cell = caller_data;
	struct msc_a *msc_a = (cell->bss && cell->bss->trans) ? cell->bss->trans->msc_a : NULL;
	int rc = 0;

	switch (msg->msg_type) {
	case RAN_MSG_VGCS_VBS_ASSIGN_RES:
		/* The BSS accepts VGCS/VBS channel assignment. */
		vgcs_vbs_assign_result(cell, msg);
		break;
	case RAN_MSG_VGCS_VBS_ASSIGN_FAIL:
		/* The BSS refuses VGCS/VBS channel assignment. */
		vgcs_vbs_assign_fail(cell, msg);
		break;
	case RAN_MSG_VGCS_VBS_QUEUING_IND:
		/* The BSS needs more time for VGCS/VBS channel assignment. */
		vgcs_vbs_queuing_ind(cell);
		break;
	case RAN_MSG_VGCS_VBS_ASSIGN_STATUS:
		/* The BSS gives cell status about VGCS/VBS channel. */
		vgcs_vbs_assign_status(cell, msg);
		break;
	case RAN_MSG_CLEAR_REQUEST:
		/* BSS indicated that the channel has been released. */
		vgcs_vbs_clear_req_channel(cell, msg);
		break;
	case RAN_MSG_CLEAR_COMPLETE:
		/* BSS confirms the release of the channel. */
		vgcs_vbs_clear_cpl_channel(cell, msg);
		break;
	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "Message from BSS leg not implemented: %s\n",
			  ran_msg_type_name(msg->msg_type));
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

int msc_a_rx_vgcs_cell(struct vgcs_bss_cell *cell, struct ran_conn *from_conn, struct msgb *msg)
{
	struct ran_dec ran_dec;

	/* Feed through the decoding mechanism ran_msg. The decoded message arrives in msc_a_rx_vgcs_decoded() */
	ran_dec = (struct ran_dec) {
		.caller_data = cell,
		.decode_cb = msc_a_rx_vgcs_cell_decoded,
	};
	struct ran_peer *ran_peer = from_conn->ran_peer;
	struct ran_infra *ran = ran_peer->sri->ran;
	if (!ran->ran_dec_l2) {
		LOGP(DMSC, LOGL_ERROR, "No ran_dec_l2() defined for RAN type %s\n",
		     osmo_rat_type_name(ran->type));
		return -ENOTSUP;
	}
	return ran->ran_dec_l2(&ran_dec, msg);
}

static int msc_a_ran_dec_from_msc_t(struct msc_a *msc_a, struct msc_a_ran_dec_data *d)
{
	struct msc_t *msc_t = msc_a_msc_t(msc_a);
	int rc = -99;

	if (!msc_t) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx message from MSC-T role, but I have no active MSC-T role.\n");
		return -EINVAL;
	}

	OSMO_ASSERT(d->ran_dec);

	switch (d->ran_dec->msg_type) {

	case RAN_MSG_CLEAR_REQUEST:
		rc = osmo_fsm_inst_dispatch(msc_t->c.fi, MSC_T_EV_MO_CLOSE, NULL);
		break;

	case RAN_MSG_CLEAR_COMPLETE:
		rc = osmo_fsm_inst_dispatch(msc_t->c.fi, MSC_T_EV_CLEAR_COMPLETE, NULL);
		break;

	case RAN_MSG_CLASSMARK_UPDATE:
		msc_a_up_classmark_update(msc_a, d->ran_dec->classmark_update.classmark, &msc_t->classmark);
		rc = 0;
		break;

	case RAN_MSG_HANDOVER_REQUEST_ACK:
		/* new BSS accepts Handover */
		rc = msc_a_up_ho(msc_a, d, MSC_HO_EV_RX_REQUEST_ACK);
		break;

	case RAN_MSG_HANDOVER_DETECT:
		/* new BSS signals the MS is DETECTed on the new lchan */
		rc = msc_a_up_ho(msc_a, d, MSC_HO_EV_RX_DETECT);
		break;

	case RAN_MSG_HANDOVER_COMPLETE:
		/* new BSS signals the MS has fully moved to the new lchan */
		rc = msc_a_up_ho(msc_a, d, MSC_HO_EV_RX_COMPLETE);
		break;

	case RAN_MSG_HANDOVER_FAILURE:
		rc = msc_a_up_ho(msc_a, d, MSC_HO_EV_RX_FAILURE);
		break;

	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "Message from MSC-T not implemented: %s\n",
			  ran_msg_type_name(d->ran_dec->msg_type));
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

int msc_a_ran_decode_cb(struct osmo_fsm_inst *msc_a_fi, void *data, const struct ran_msg *msg)
{
	struct msc_a *msc_a = msc_a_fi_priv(msc_a_fi);
	struct msc_a_ran_dec_data *d = data;
	int rc = -99;

	d->ran_dec = msg;

	switch (d->from_role) {
	case MSC_ROLE_I:
		LOG_MSC_A(msc_a, LOGL_DEBUG, "RAN decode: %s\n", msg->msg_name ? : ran_msg_type_name(msg->msg_type));
		rc = msc_a_ran_dec_from_msc_i(msc_a, d);
		break;

	case MSC_ROLE_T:
		LOG_MSC_A(msc_a, LOGL_DEBUG, "RAN decode from MSC-T: %s\n",
			  msg->msg_name ? : ran_msg_type_name(msg->msg_type));
		rc = msc_a_ran_dec_from_msc_t(msc_a, d);
		break;

	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "Message from invalid role %s: %s\n", msc_role_name(d->from_role),
			  ran_msg_type_name(msg->msg_type));
		return -ENOTSUP;
	}

	if (rc)
		LOG_MSC_A(msc_a, LOGL_ERROR, "RAN decode error (rc=%d) for %s from %s\n", rc, ran_msg_type_name(msg->msg_type),
			  msc_role_name(d->from_role));
	return rc;
}

/* Your typical DTAP via FORWARD_ACCESS_SIGNALLING_REQUEST */
int _msc_a_ran_down(struct msc_a *msc_a, enum msc_role to_role, const struct ran_msg *ran_msg,
		   const char *file, int line)
{
	return _msc_a_msg_down(msc_a, to_role, msub_role_to_role_event(msc_a->c.msub, MSC_ROLE_A, to_role),
			       ran_msg, file, line);
}

/* To transmit more complex events than just FORWARD_ACCESS_SIGNALLING_REQUEST, e.g. an
 * MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST */
int _msc_a_msg_down(struct msc_a *msc_a, enum msc_role to_role, uint32_t to_role_event,
		    const struct ran_msg *ran_msg,
		    const char *file, int line)
{
	struct an_apdu an_apdu = {
		.an_proto = msc_a->c.ran->an_proto,
		.msg = msc_role_ran_encode(msc_a->c.fi, ran_msg),
	};
	if (!an_apdu.msg)
		return -EIO;
	return _msub_role_dispatch(msc_a->c.msub, to_role, to_role_event, &an_apdu, file, line);
}

int msc_a_tx_dtap_to_i(struct msc_a *msc_a, struct msgb *dtap)
{
	struct ran_msg ran_msg;
	struct gsm48_hdr *gh = msgb_l3(dtap) ? : dtap->data;
	uint8_t pdisc = gsm48_hdr_pdisc(gh);

	if (!msc_a) {
		LOGP(DMSC, LOGL_ERROR, "Attempt to send DTAP to NULL MSC-A, dropping message: %s %s\n",
		     gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));
		msgb_free(dtap);
		return -EIO;
	}

	if (msc_a->c.ran->type == OSMO_RAT_EUTRAN_SGS) {
		/* The SGs connection to the MME always is at the MSC-A. */
		return sgs_iface_tx_dtap_ud(msc_a, dtap);
	}

	LOG_MSC_A(msc_a, LOGL_DEBUG, "Sending DTAP: %s %s\n",
		  gsm48_pdisc_name(pdisc), gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));

	ran_msg = (struct ran_msg){
		.msg_type = RAN_MSG_DTAP,
		.dtap = dtap,
	};
	return msc_a_ran_down(msc_a, MSC_ROLE_I, &ran_msg);
}

struct msc_a *msc_a_for_vsub(const struct vlr_subscr *vsub, bool valid_conn_only)
{
	struct msc_a *msc_a = msub_msc_a(msub_for_vsub(vsub));
	if (valid_conn_only && !msc_a_is_accepted(msc_a))
		return NULL;
	return msc_a;
}

int msc_tx_common_id(struct msc_a *msc_a, enum msc_role to_role)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	if (vsub == NULL)
		return -ENODEV;
	struct ran_msg msg = {
		.msg_type = RAN_MSG_COMMON_ID,
		.common_id = {
			.imsi = vsub->imsi,
			.last_eutran_plmn_present = vsub->sgs.last_eutran_plmn_present,
		},
	};
	if (vsub->sgs.last_eutran_plmn_present) {
		memcpy(&msg.common_id.last_eutran_plmn, &vsub->sgs.last_eutran_plmn,
			sizeof(vsub->sgs.last_eutran_plmn));
	}

	return msc_a_ran_down(msc_a, to_role, &msg);
}

static int msc_a_start_assignment(struct msc_a *msc_a, struct gsm_trans *cc_trans)
{
	struct call_leg *cl;
	bool cn_rtp_available;
	bool ran_rtp_available;

	OSMO_ASSERT(!msc_a->cc.active_trans);
	msc_a->cc.active_trans = cc_trans;

	cc_trans->cc.codecs.assignment = (struct sdp_audio_codec){};

	OSMO_ASSERT(cc_trans && cc_trans->type == TRANS_CC);
	cl = msc_a_ensure_call_leg(msc_a, cc_trans);
	if (!cl)
		return -EINVAL;

	/* See if we can set a preliminary codec. If not, pass none for the time being. */
	trans_cc_filter_run(cc_trans);

	cn_rtp_available = call_leg_local_ip(cl, RTP_TO_CN);
	ran_rtp_available = call_leg_local_ip(cl, RTP_TO_RAN);

	/* Set up RTP ports for both RAN and CN side. Even though we ask for both at the same time, the
	 * osmo_mgcpc_ep_fsm automagically waits for the first CRCX to complete before firing the second CRCX. The one
	 * issued first here will also be the first CRCX sent to the MGW. Usually both still need to be set up. */
	if (!cn_rtp_available)
		call_leg_ensure_ci(cl, RTP_TO_CN, cc_trans->call_id, cc_trans,
				   &cc_trans->cc.local.audio_codecs, NULL);
	if (!ran_rtp_available) {
		struct sdp_audio_codecs *codecs;
		if (msc_a->c.ran->force_mgw_codecs_to_ran.count)
			codecs = &msc_a->c.ran->force_mgw_codecs_to_ran;
		else
			codecs = &cc_trans->cc.local.audio_codecs;
		return call_leg_ensure_ci(cl, RTP_TO_RAN, cc_trans->call_id, cc_trans, codecs, NULL);
	}

	/* Should these already be set up, immediately continue by retriggering the events signalling that the RTP
	 * ports are available. The ordering is: first CN, then RAN. */
	if (cn_rtp_available && ran_rtp_available)
		return osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE, cl->rtp[RTP_TO_RAN]);
	else if (cn_rtp_available)
		return osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE, cl->rtp[RTP_TO_CN]);
	/* Otherwise wait for MGCP response and continue from there.  */
	return 0;
}

int msc_a_try_call_assignment(struct gsm_trans *cc_trans)
{
	struct msc_a *msc_a = cc_trans->msc_a;
	OSMO_ASSERT(cc_trans->type == TRANS_CC);

	if (msc_a->cc.active_trans == cc_trans) {
		LOG_MSC_A(msc_a, LOGL_DEBUG, "Assignment for this trans already started earlier\n");
		return 0;
	}

	if (msc_a->cc.active_trans) {
		LOG_MSC_A(msc_a, LOGL_INFO, "Another call is already ongoing, not assigning yet\n");
		return 0;
	}

	LOG_MSC_A(msc_a, LOGL_DEBUG, "Starting call assignment\n");
	return msc_a_start_assignment(msc_a, cc_trans);
}

/* Map CM Service type to use token.
 * Given a CM Service type, return a matching token intended for osmo_use_count.
 * For unknown service type, return NULL.
 */
const char *msc_a_cm_service_type_to_use(struct msc_a *msc_a, enum osmo_cm_service_type cm_service_type)
{
	struct gsm_network *net = msc_a_net(msc_a);

	switch (cm_service_type) {
	case GSM48_CMSERV_MO_CALL_PACKET:
	case GSM48_CMSERV_EMERGENCY:
		return MSC_A_USE_CM_SERVICE_CC;

	case GSM48_CMSERV_SMS:
		return MSC_A_USE_CM_SERVICE_SMS;

	case GSM48_CMSERV_SUP_SERV:
		return MSC_A_USE_CM_SERVICE_SS;

	case GSM48_CMSERV_VGCS:
		if (net->asci.enable)
			return MSC_A_USE_CM_SERVICE_GCC;
		else
			return NULL;

	case GSM48_CMSERV_VBS:
		if (net->asci.enable)
			return MSC_A_USE_CM_SERVICE_BCC;
		else
			return NULL;

	default:
		return NULL;
	}
}

void msc_a_release_cn(struct msc_a *msc_a)
{
	osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_CN_CLOSE, NULL);
}

void msc_a_release_mo(struct msc_a *msc_a, enum gsm48_gsm_cause gsm_cause)
{
	osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_MO_CLOSE, NULL);
}
