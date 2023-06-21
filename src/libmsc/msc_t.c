/* The MSC-T role, a transitional RAN connection during Handover. */
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

#include <inttypes.h>

#include <osmocom/gsm/gsm48_ie.h>

#include <osmocom/msc/msc_t.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/msc_a_remote.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/ran_peer.h>
#include <osmocom/msc/ran_conn.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/call_leg.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/ran_infra.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msc_i.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/codec_mapping.h>

static struct osmo_fsm msc_t_fsm;

static struct msc_t *msc_t_find_by_handover_number(const char *handover_number)
{
	struct msub *msub;

	llist_for_each_entry(msub, &msub_list, entry) {
		struct msc_t *msc_t = msub_msc_t(msub);
		if (!msc_t)
			continue;
		if (!*msc_t->inter_msc.handover_number)
			continue;
		if (strcmp(msc_t->inter_msc.handover_number, handover_number))
			continue;
		/* Found the assigned Handover Number */
		return msc_t;
	}
	return NULL;
}

static uint64_t net_handover_number_next(struct gsm_network *net)
{
	uint64_t nr;
	if (net->handover_number.next < net->handover_number.range_start
	    || net->handover_number.next > net->handover_number.range_end)
		net->handover_number.next = net->handover_number.range_start;
	nr = net->handover_number.next;
	net->handover_number.next++;
	return nr;
}

static int msc_t_assign_handover_number(struct msc_t *msc_t)
{
	int rc;
	uint64_t started_at;
	uint64_t ho_nr;
	char ho_nr_str[GSM23003_MSISDN_MAX_DIGITS+1];
	struct gsm_network *net = msc_t_net(msc_t);
	bool usable = false;

	started_at = ho_nr = net_handover_number_next(net);

	if (!ho_nr) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "No Handover Number range defined in MSC config\n");
		return -ENOENT;
	}

	do {
		rc = snprintf(ho_nr_str, sizeof(ho_nr_str), "%"PRIu64, ho_nr);
		if (rc <= 0 || rc >= sizeof(ho_nr_str)) {
			LOG_MSC_T(msc_t, LOGL_ERROR, "Cannot compose Handover Number string (rc=%d)\n", rc);
			return -EINVAL;
		}

		if (!msc_t_find_by_handover_number(ho_nr_str)) {
			usable = true;
			break;
		}

		ho_nr = net_handover_number_next(net);
	} while(ho_nr != started_at);

	if (!usable) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "No Handover Number available\n");
		return -EINVAL;
	}

	LOG_MSC_T(msc_t, LOGL_INFO, "Assigning Handover Number %s\n", ho_nr_str);
	OSMO_STRLCPY_ARRAY(msc_t->inter_msc.handover_number, ho_nr_str);
	return 0;
}


static struct msc_t *msc_t_priv(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &msc_t_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

/* As a macro to log the caller's source file and line.
 * Assumes presence of local msc_t variable. */
#define msc_t_error(fmt, args...) do { \
		msc_t->ho_success = false; \
		LOG_MSC_T(msc_t, LOGL_ERROR, fmt, ##args); \
		msc_t_clear(msc_t); \
	} while(0)

static void msc_t_send_handover_failure(struct msc_t *msc_t, enum gsm0808_cause cause)
{
	struct ran_msg ran_enc_msg = {
		.msg_type = RAN_MSG_HANDOVER_FAILURE,
		.handover_failure = {
			.cause = cause,
		},
	};
	struct an_apdu an_apdu = {
		.an_proto = msc_t->c.ran->an_proto,
		.msg = msc_role_ran_encode(msc_t->c.fi, &ran_enc_msg),
	};
	msc_t->ho_fail_sent = true;
	if (!an_apdu.msg)
		return;

	msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE, &an_apdu);
}

static int msc_t_ho_request_decode_and_store_cb(struct osmo_fsm_inst *msc_t_fi, void *data,
						const struct ran_msg *ran_dec)
{
	struct msc_t *msc_t = msc_t_priv(msc_t_fi);

	if (ran_dec->msg_type != RAN_MSG_HANDOVER_REQUEST) {
		LOG_MSC_T(msc_t, LOGL_DEBUG, "Expected %s in incoming inter-MSC Handover message, got %s\n",
			  ran_msg_type_name(RAN_MSG_HANDOVER_REQUEST), ran_msg_type_name(ran_dec->msg_type));
		return -EINVAL;
	}

	msc_t->inter_msc.cell_id_target = ran_dec->handover_request.cell_id_target;
	msc_t->inter_msc.call_id = ran_dec->handover_request.call_id;

	/* TODO other parameters...?
	 * Global Call Reference
	 */
	return 0;
}

/* On an icoming Handover Request from a remote MSC, we first need to set up an MGW endpoint, because the BSC needs to
 * know our AoIP Transport Layer Address in the Handover Request message (which obviously the remote MSC doesn't send,
 * it needs to be our local RTP address). Creating the MGW endpoint this is asynchronous, so we need to store the
 * Handover Request data to forward to the BSC once the MGW endpoint is known.
 */
static int msc_t_decode_and_store_ho_request(struct msc_t *msc_t, const struct an_apdu *an_apdu)
{
	if (msc_role_ran_decode(msc_t->c.fi, an_apdu, msc_t_ho_request_decode_and_store_cb, NULL)) {
		msc_t_error("Failed to decode Handover Request\n");
		return -ENOTSUP;
	}
	/* Ok, decoding done, and above msc_t_ho_request_decode_and_store_cb() has retrieved what info we need at this
	 * point and stored it in msc_t->inter_msc.* */

	/* We're storing this for use after async events, so need to make sure that each and every bit of data is copied
	 * and no longer references some msgb that might be deallocated when this returns, nor remains in a local stack
	 * variable of some ran_decode implementation. The simplest is to store the entire msgb. */
	msc_t->inter_msc.ho_request = (struct an_apdu) {
		.an_proto = an_apdu->an_proto,
		.msg = msgb_copy(an_apdu->msg, "saved inter-MSC Handover Request"),
		/* A decoded osmo_gsup_message often still references memory of within the msgb the GSUP was received
		 * in. So, any info from an_apdu->e_info that would be needed would have to be copied separately.
		 * Omit e_info completely. */
	};
	return 0;
}

/* On an incoming Handover Request from a remote MSC, the target cell was transmitted in the Handover Request message.
 * Find the RAN peer and assign from the cell id decoded above in msc_t_decode_and_store_ho_request(). */
static int msc_t_find_ran_peer_from_ho_request(struct msc_t *msc_t)
{
	struct msc_a *msc_a = msub_msc_a(msc_t->c.msub);
	const struct neighbor_ident_entry *nie;
	struct ran_peer *rp_from_neighbor_ident;
	struct ran_peer *rp;

	switch (msc_ho_find_target_cell(msc_a, &msc_t->inter_msc.cell_id_target,
					&nie, &rp_from_neighbor_ident, &rp)) {
	case MSC_NEIGHBOR_TYPE_REMOTE_MSC:
		msc_t_error("Incoming Handover Request indicated target cell that belongs to a remote MSC:"
			    " Cell ID: %s; remote MSC: %s\n",
			    gsm0808_cell_id_name(&msc_t->inter_msc.cell_id_target),
			    neighbor_ident_addr_name(&nie->addr));
		return -EINVAL;

	case MSC_NEIGHBOR_TYPE_NONE:
		msc_t_error("Incoming Handover Request for unknown cell %s\n",
			    gsm0808_cell_id_name(&msc_t->inter_msc.cell_id_target));
		return -EINVAL;

	case MSC_NEIGHBOR_TYPE_LOCAL_RAN_PEER:
		/* That's what is expected: a local RAN peer, e.g. BSC, or a remote BSC from neighbor cfg. */
		if (!rp)
			rp = rp_from_neighbor_ident;
		break;
	}

	OSMO_ASSERT(rp);
	LOG_MSC_T(msc_t, LOGL_DEBUG, "Incoming Handover Request indicates target cell %s,"
		  " which belongs to RAN peer %s\n",
		  gsm0808_cell_id_name(&msc_t->inter_msc.cell_id_target), rp->fi->id);

	/* Finally we know where to direct the Handover */
	msc_t_set_ran_peer(msc_t, rp);
	return 0;
}

static int msc_t_send_stored_ho_request__decode_cb(struct osmo_fsm_inst *msc_t_fi, void *data,
						  const struct ran_msg *ran_dec)
{
	struct an_apdu an_apdu;
	struct msc_t *msc_t = msc_t_priv(msc_t_fi);
	struct osmo_sockaddr_str *rtp_ran_local = data;

	/* Copy ran_dec message to un-const so we can add the AoIP Transport Layer Address. All pointer references still
	 * remain on the same memory as ran_dec, which is fine. We're just going to encode it again right away. */
	struct ran_msg ran_enc = *ran_dec;

	if (ran_dec->msg_type != RAN_MSG_HANDOVER_REQUEST) {
		LOG_MSC_T(msc_t, LOGL_DEBUG, "Expected %s in incoming inter-MSC Handover message, got %s\n",
			  ran_msg_type_name(RAN_MSG_HANDOVER_REQUEST), ran_msg_type_name(ran_dec->msg_type));
		return -EINVAL;
	}

	/* Insert AoIP Transport Layer Address */
	ran_enc.handover_request.rtp_ran_local = rtp_ran_local;

	/* Finally ready to forward to BSC: encode and send out. */
	an_apdu = (struct an_apdu){
		.an_proto = msc_t->inter_msc.ho_request.an_proto,
		.msg = msc_role_ran_encode(msc_t->c.fi, &ran_enc),
	};
	if (!an_apdu.msg)
		return -EIO;
	return msc_t_down_l2_co(msc_t, &an_apdu, true);
}

/* The MGW endpoint is created, we know our AoIP Transport Layer Address and can send the Handover Request to the RAN
 * peer. */
static int msc_t_send_stored_ho_request(struct msc_t *msc_t)
{
	struct osmo_sockaddr_str *rtp_ran_local = call_leg_local_ip(msc_t->inter_msc.call_leg, RTP_TO_RAN);
	if (!rtp_ran_local) {
		msc_t_error("Local RTP address towards RAN is not set up properly, cannot send Handover Request\n");
		return -EINVAL;
	}

	/* The Handover Request received from the remote MSC is fed through, except we need to insert our local AoIP
	 * Transport Layer Address, i.e. the RTP IP:port of the MGW towards the RAN side. So we actually need to decode,
	 * add the AoIP and re-encode. By nature of decoding, it goes through the decode callback. */
	return msc_role_ran_decode(msc_t->c.fi, &msc_t->inter_msc.ho_request,
				   msc_t_send_stored_ho_request__decode_cb, rtp_ran_local);
}

static void msc_t_fsm_pending_first_co_initial_msg(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_t *msc_t = msc_t_priv(fi);
	struct msc_a *msc_a = msub_msc_a(msc_t->c.msub);
	struct an_apdu *an_apdu;

	OSMO_ASSERT(msc_a);

	switch (event) {

	case MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST:
		/* For an inter-MSC Handover coming in from a remote MSC, we do not yet know the RAN peer and AoIP
		 * Transport Layer Address.
		 * - RAN peer is found by decoding the actual Handover Request message and looking for the Cell
		 *   Identifier (Target).
		 * - To be able to tell the BSC about an AoIP Transport Layer Address, we first need to create an MGW
		 *   endpoint.
		 * For mere inter-BSC Handover, we know all of the above already. Find out which one this is.
		 */
		an_apdu = data;
		if (!msc_a->c.remote_to) {
			/* Inter-BSC */

			osmo_fsm_inst_state_chg(msc_t->c.fi, MSC_T_ST_WAIT_HO_REQUEST_ACK, 0, 0);
			/* Inter-BSC. All should be set up, just forward the message. */
			if (msc_t_down_l2_co(msc_t, an_apdu, true))
				msc_t_error("Failed to send AN-APDU to RAN peer\n");
		} else {
			/* Inter-MSC */

			if (msc_t->ran_conn) {
				msc_t_error("Unexpected state for inter-MSC Handover: RAN peer is already set up\n");
				return;
			}

			if (msc_t_decode_and_store_ho_request(msc_t, an_apdu))
				return;

			if (msc_t_find_ran_peer_from_ho_request(msc_t))
				return;

			/* Relying on timeout of the MGW operations, see onenter() for this state. */
			osmo_fsm_inst_state_chg(msc_t->c.fi, MSC_T_ST_WAIT_LOCAL_RTP, 0, 0);
		}
		return;

	case MSC_T_EV_CN_CLOSE:
		msc_t_clear(msc_t);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

void msc_t_fsm_wait_local_rtp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct msc_t *msc_t = msc_t_priv(fi);
	struct msc_a *msc_a = msub_msc_a(msc_t->c.msub);

	/* This only happens on inter-MSC HO incoming from a remote MSC */
	if (!msc_a->c.remote_to) {
		msc_t_error("Unexpected state: this is not an inter-MSC Handover\n");
		return;
	}

	if (msc_t->inter_msc.call_leg) {
		msc_t_error("Unexpected state: call leg already set up\n");
		return;
	}

	msc_t->inter_msc.call_leg = call_leg_alloc(msc_t->c.fi,
						   MSC_EV_CALL_LEG_TERM,
						   MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE,
						   MSC_EV_CALL_LEG_RTP_COMPLETE);
	if (!msc_t->inter_msc.call_leg
	    || call_leg_ensure_ci(msc_t->inter_msc.call_leg, RTP_TO_RAN, msc_t->inter_msc.call_id, NULL, NULL, NULL)
	    || call_leg_ensure_ci(msc_t->inter_msc.call_leg, RTP_TO_CN, msc_t->inter_msc.call_id, NULL, NULL, NULL)) {
		msc_t_error("Failed to set up call leg\n");
		return;
	}
	/* Now wait for two MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE, one per RTP connection */
}

void msc_t_fsm_wait_local_rtp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_t *msc_t = msc_t_priv(fi);
	struct rtp_stream *rtps;

	switch (event) {
	case MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE:
		rtps = data;
		if (!rtps) {
			msc_t_error("Invalid data for MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE\n");
			return;
		}
		/* If both to-RAN and to-CN sides have a CI set up, we can continue. */
		if (!call_leg_local_ip(msc_t->inter_msc.call_leg, RTP_TO_RAN)
		    || !call_leg_local_ip(msc_t->inter_msc.call_leg, RTP_TO_CN))
			return;

		osmo_fsm_inst_state_chg(msc_t->c.fi, MSC_T_ST_WAIT_HO_REQUEST_ACK, 0, 0);
		msc_t_send_stored_ho_request(msc_t);
		return;

	case MSC_EV_CALL_LEG_TERM:
		msc_t->inter_msc.call_leg = NULL;
		msc_t_error("Failed to set up MGW endpoint\n");
		return;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_t->inter_msc.mncc_forwarding_to_remote_cn = NULL;
		return;

	case MSC_T_EV_CN_CLOSE:
	case MSC_T_EV_MO_CLOSE:
		msc_t_clear(msc_t);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static int msc_t_patch_and_send_ho_request_ack(struct msc_t *msc_t, const struct an_apdu *incoming_an_apdu,
					       const struct ran_msg *ran_dec)
{
	int rc;
	struct rtp_stream *rtp_ran = msc_t->inter_msc.call_leg? msc_t->inter_msc.call_leg->rtp[RTP_TO_RAN] : NULL;
	struct rtp_stream *rtp_cn = msc_t->inter_msc.call_leg? msc_t->inter_msc.call_leg->rtp[RTP_TO_CN] : NULL;
	/* Since it's BCD, it needs rounded-up half the char* length of an MSISDN plus a type byte.
	 * But no need to introduce obscure math to save a few stack bytes, just have more. */
	uint8_t msisdn_enc_buf[GSM23003_MSISDN_MAX_DIGITS+1];
	/* Copy an_apdu and an_apdu->e_info in "copy-on-write" method, because they are const and we
	 * need to add the Handover Number to e_info. */
	const struct ran_handover_request_ack *r = &ran_dec->handover_request_ack;
	struct ran_msg ran_enc = *ran_dec;
	struct osmo_gsup_message e_info = {};
	struct an_apdu an_apdu = {
		.an_proto = incoming_an_apdu->an_proto,
		.e_info = &e_info,
	};
	if (incoming_an_apdu->e_info)
		e_info = *incoming_an_apdu->e_info;

	rc = msc_t_assign_handover_number(msc_t);
	if (rc)
		return rc;

	rc = gsm48_encode_bcd_number(msisdn_enc_buf, sizeof(msisdn_enc_buf), 0,
				     msc_t->inter_msc.handover_number);
	if (rc <= 0)
		return -EINVAL;

	e_info.msisdn_enc = msisdn_enc_buf;
	e_info.msisdn_enc_len = rc;

	/* Also need to fetch the RTP IP:port from AoIP Transport Address IE to tell the MGW about it */
	if (rtp_ran) {
		if (osmo_sockaddr_str_is_nonzero(&r->remote_rtp)) {
			LOG_MSC_T(msc_t, LOGL_DEBUG, "From Handover Request Ack, got " OSMO_SOCKADDR_STR_FMT "\n",
				  OSMO_SOCKADDR_STR_FMT_ARGS(&r->remote_rtp));
			rtp_stream_set_remote_addr(rtp_ran, &r->remote_rtp);
		} else {
			LOG_MSC_T(msc_t, LOGL_DEBUG, "No RTP IP:port in Handover Request Ack\n");
		}
		if (r->codec_present) {
			const struct codec_mapping *m = codec_mapping_by_gsm0808_speech_codec_type(r->codec.type);
			/* TODO: use codec_mapping_by_gsm0808_speech_codec() to also match on codec.cfg */
			if (!m) {
				LOG_MSC_T(msc_t, LOGL_ERROR, "Cannot resolve codec in Handover Request Ack: %s / %s\n",
					  gsm0808_speech_codec_type_name(r->codec.type),
					  m ? sdp_audio_codec_to_str(&m->sdp) : "(unknown)");
			} else {
				LOG_MSC_T(msc_t, LOGL_DEBUG, "From Handover Request Ack, got codec %s / %s\n",
					  gsm0808_speech_codec_type_name(r->codec.type),
					  sdp_audio_codec_to_str(&m->sdp));
				rtp_stream_set_one_codec(rtp_ran, &m->sdp);
				if (rtp_cn)
					rtp_stream_set_one_codec(rtp_cn, &m->sdp);
			}
		} else {
			LOG_MSC_T(msc_t, LOGL_DEBUG, "No codec in Handover Request Ack\n");
		}
		rtp_stream_commit(rtp_ran);
	} else {
		LOG_MSC_T(msc_t, LOGL_DEBUG, "No RTP to RAN set up yet\n");
	}

	/* Remove that AoIP Transport Layer IE so it doesn't get sent to the remote MSC */
	ran_enc.handover_request_ack.remote_rtp = (struct osmo_sockaddr_str){};

	an_apdu.msg = msc_role_ran_encode(msc_t->c.fi, &ran_enc);
	if (!an_apdu.msg)
		return -EIO;
	/* Send to remote MSC via msc_a_remote role */
	return msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE, &an_apdu);
}

static int msc_t_wait_ho_request_ack_decode_cb(struct osmo_fsm_inst *msc_t_fi, void *data,
					       const struct ran_msg *ran_dec)
{
	int rc;
	struct msc_t *msc_t = msc_t_priv(msc_t_fi);
	struct msc_a *msc_a = msub_msc_a(msc_t->c.msub);
	const struct an_apdu *an_apdu = data;

	switch (ran_dec->msg_type) {
	case RAN_MSG_HANDOVER_REQUEST_ACK:
		if (msc_a->c.remote_to) {
			/* inter-MSC. Add Handover Number, remove AoIP Transport Layer Address. */
			rc = msc_t_patch_and_send_ho_request_ack(msc_t, an_apdu, ran_dec);
		} else {
			/* inter-BSC. Just send as-is, with correct event. */
			rc = msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE,
						an_apdu);
		}
		if (rc)
			msc_t_error("Failed to send HO Request Ack\n");
		else
			osmo_fsm_inst_state_chg(msc_t->c.fi, MSC_T_ST_WAIT_HO_COMPLETE, 0, 0);
		return 0;

	case RAN_MSG_HANDOVER_FAILURE:
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE, an_apdu);
		return 0;

	case RAN_MSG_CLEAR_REQUEST:
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST,
				   an_apdu);
		return 0;

	default:
		LOG_MSC_T(msc_t, LOGL_ERROR, "Unexpected message during Prepare Handover procedure: %s\n",
			  ran_msg_type_name(ran_dec->msg_type));
		/* Let's just forward anyway. */
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST,
				   an_apdu);
		return 0;
	}
}

static void msc_t_fsm_wait_ho_request_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_t *msc_t = msc_t_priv(fi);
	struct an_apdu *an_apdu;

	switch (event) {

	case MSC_EV_FROM_RAN_UP_L2:
		an_apdu = data;
		/* For inter-MSC Handover, we need to examine the message type. Depending on the response, we must
		 * dispatch MSC_A_EV_FROM_T_PREPARE_HANDOVER_RESPONSE or MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE, which
		 * ensures the correct E-interface message type. And we need to include the Handover Number.
		 * For mere inter-BSC Handover, we know that our osmo-msc internals don't care much about which event
		 * dispatches a Handover Failure or Handover Request Ack, so we could skip the decoding. But it is a
		 * premature optimization that complicates comparing an inter-BSC with an inter-MSC HO. */
		msc_role_ran_decode(msc_t->c.fi, an_apdu, msc_t_wait_ho_request_ack_decode_cb, an_apdu);
		/* Action continues in msc_t_wait_ho_request_ack_decode_cb() */
		return;

	case MSC_EV_FROM_RAN_CONN_RELEASED:
		msc_t_clear(msc_t);
		return;

	case MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST:
		an_apdu = data;
		msc_t_down_l2_co(msc_t, an_apdu, false);
		return;

	case MSC_EV_CALL_LEG_TERM:
		msc_t->inter_msc.call_leg = NULL;
		msc_t_error("Failed to set up MGW endpoint\n");
		return;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_t->inter_msc.mncc_forwarding_to_remote_cn = NULL;
		return;

	case MSC_T_EV_CN_CLOSE:
	case MSC_T_EV_MO_CLOSE:
		msc_t_clear(msc_t);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static int msc_t_wait_ho_complete_decode_cb(struct osmo_fsm_inst *msc_t_fi, void *data,
					       const struct ran_msg *ran_dec)
{
	struct msc_t *msc_t = msc_t_priv(msc_t_fi);
	struct msc_a *msc_a = msub_msc_a(msc_t->c.msub);
	struct msc_i *msc_i;
	const struct an_apdu *an_apdu = data;

	switch (ran_dec->msg_type) {
	case RAN_MSG_HANDOVER_COMPLETE:
		msc_t->ho_success = true;

		/* For both inter-BSC local to this MSC and inter-MSC Handover for a remote MSC-A, forward the Handover
		 * Complete message so that the MSC-A can change the MSC-T (transitional) to a proper MSC-I role. */
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_SEND_END_SIGNAL_REQUEST, an_apdu);

		/* For inter-BSC Handover, the Handover Complete event has already cleaned up this msc_t, and it is
		 * already gone and deallocated. */
		if (!msc_a->c.remote_to)
			return 0;

		/* For inter-MSC Handover, the remote MSC-A only turns its msc_t_remote into an msc_i_remote on
		 * the same GSUP link. We are here on the MSC-B side of the GSUP link and have to take care of
		 * creating an MSC-I over here to match the msc_i_remote at MSC-A. */
		msc_i = msc_i_alloc(msc_t->c.msub, msc_t->c.ran);
		if (!msc_i) {
			msc_t_error("Failed to create MSC-I role\n");
			return -1;
		}

		msc_i->inter_msc.mncc_forwarding_to_remote_cn = msc_t->inter_msc.mncc_forwarding_to_remote_cn;
		mncc_call_reparent(msc_i->inter_msc.mncc_forwarding_to_remote_cn,
				   msc_i->c.fi, -1, MSC_MNCC_EV_CALL_ENDED, NULL, NULL);

		msc_i->inter_msc.call_leg = msc_t->inter_msc.call_leg;
		call_leg_reparent(msc_i->inter_msc.call_leg,
				  msc_i->c.fi,
				  MSC_EV_CALL_LEG_TERM,
				  MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE,
				  MSC_EV_CALL_LEG_RTP_COMPLETE);

		/* msc_i_set_ran_conn() properly "steals" the ran_conn from msc_t */
		msc_i_set_ran_conn(msc_i, msc_t->ran_conn);

		/* Nicked everything worth keeping from MSC-T, discard now. */
		msc_t_clear(msc_t);
		return 0;

	case RAN_MSG_HANDOVER_FAILURE:
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PREPARE_HANDOVER_FAILURE, an_apdu);
		return 0;

	default:
		LOG_MSC_T(msc_t, LOGL_ERROR, "Unexpected message during Prepare Handover procedure: %s\n",
			  ran_msg_type_name(ran_dec->msg_type));
		/* Let's just forward anyway. Fall thru */
	case RAN_MSG_HANDOVER_DETECT:
	case RAN_MSG_CLEAR_REQUEST:
		msub_role_dispatch(msc_t->c.msub, MSC_ROLE_A, MSC_A_EV_FROM_T_PROCESS_ACCESS_SIGNALLING_REQUEST,
				   an_apdu);
		return 0;
	}
}

static void msc_t_fsm_wait_ho_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc_t *msc_t = msc_t_priv(fi);
	struct an_apdu *an_apdu;

	switch (event) {

	case MSC_EV_FROM_RAN_UP_L2:
		an_apdu = data;
		/* We need to catch the Handover Complete message in order to send it as a SendEndSignal Request */
		msc_role_ran_decode(msc_t->c.fi, an_apdu, msc_t_wait_ho_complete_decode_cb, an_apdu);
		return;

	case MSC_EV_FROM_RAN_CONN_RELEASED:
		msc_t_clear(msc_t);
		return;

	case MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST:
		an_apdu = data;
		msc_t_down_l2_co(msc_t, an_apdu, false);
		return;

	case MSC_EV_CALL_LEG_TERM:
		msc_t->inter_msc.call_leg = NULL;
		msc_t_error("Failed to set up MGW endpoint\n");
		return;

	case MSC_MNCC_EV_CALL_ENDED:
		msc_t->inter_msc.mncc_forwarding_to_remote_cn = NULL;
		return;

	case MSC_T_EV_CN_CLOSE:
	case MSC_T_EV_MO_CLOSE:
		msc_t_clear(msc_t);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

void msc_t_mncc_cb(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg, void *data)
{
	struct msc_t *msc_t = data;
	struct gsm_mncc_number nr = {
		.plan = 1,
	};
	OSMO_STRLCPY_ARRAY(nr.number, msc_t->inter_msc.handover_number);

	switch (mncc_msg->msg_type) {
	case MNCC_RTP_CREATE:
		mncc_call_incoming_tx_setup_cnf(mncc_call, &nr);
		return;
	default:
		return;
	}
}

struct mncc_call *msc_t_check_call_to_handover_number(const struct gsm_mncc *msg)
{
	struct msc_t *msc_t;
	const char *handover_number;
	struct mncc_call_incoming_req req;
	struct mncc_call *mncc_call;

	if (!(msg->fields & MNCC_F_CALLED))
		return NULL;

	handover_number = msg->called.number;
	msc_t = msc_t_find_by_handover_number(handover_number);

	if (!msc_t)
		return NULL;

	if (msc_t->inter_msc.mncc_forwarding_to_remote_cn) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Incoming call for inter-MSC call forwarding,"
			  " but this MSC-T role already has an MNCC FSM set up\n");
		return NULL;
	}

	if (!msc_t->inter_msc.call_leg
	    || !msc_t->inter_msc.call_leg->rtp[RTP_TO_CN]) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Incoming call for inter-MSC call forwarding,"
			  " but this MSC-T has no RTP stream ready for MNCC\n");
		return NULL;
	}

	mncc_call = mncc_call_alloc(msc_t_vsub(msc_t),
				    msc_t->c.fi,
				    MSC_MNCC_EV_CALL_COMPLETE,
				    MSC_MNCC_EV_CALL_ENDED,
				    msc_t_mncc_cb, msc_t);
	if (!mncc_call) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Failed to set up call forwarding from remote MSC\n");
		return NULL;
	}
	msc_t->inter_msc.mncc_forwarding_to_remote_cn = mncc_call;

	if (mncc_call_set_rtp_stream(mncc_call, msc_t->inter_msc.call_leg->rtp[RTP_TO_CN])) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Failed to set up call forwarding from remote MSC\n");
		osmo_fsm_inst_term(mncc_call->fi, OSMO_FSM_TERM_REGULAR, NULL);
		return NULL;
	}

	req = (struct mncc_call_incoming_req){
		.setup_req_msg = *msg,
		.bearer_cap_present = true,
		.bearer_cap = {
			/* TODO derive values from actual config */
			/* FIXME are there no defines or enums for these numbers!? */
			/* Table 10.5.102/3GPP TS 24.008: Bearer capability information element:
			 * octet 3 of bearer cap for speech says 3 = "1 1 dual rate support MS/full rate speech version
			 * 1 preferred, half rate speech version 1 also supported" */
			.radio = 3,
			/* Table 10.5.103/3GPP TS 24.008 Bearer capability information element:
			 * 0: FR1, 2: FR2, 4: FR3, 1: HR1, 5: HR3, actually in this order. -1 marks the end of the list. */
			.speech_ver = { 0, 2, 4, 1, 5, -1 },
		},
	};
	if (mncc_call_incoming_start(mncc_call, &req)) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Failed to set up call forwarding from remote MSC\n");
		osmo_fsm_inst_term(mncc_call->fi, OSMO_FSM_TERM_REGULAR, NULL);
		return NULL;
	}
	return mncc_call;
}

static void msc_t_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct msc_t *msc_t = msc_t_priv(fi);

	if (!msc_t->ho_success && !msc_t->ho_fail_sent)
		msc_t_send_handover_failure(msc_t, GSM0808_CAUSE_EQUIPMENT_FAILURE);

	if (msc_t->ran_conn)
		ran_conn_msc_role_gone(msc_t->ran_conn, msc_t->c.fi);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state msc_t_fsm_states[] = {
	[MSC_T_ST_PENDING_FIRST_CO_INITIAL_MSG] = {
		.name = "PENDING_FIRST_CO_INITIAL_MSG",
		.action = msc_t_fsm_pending_first_co_initial_msg,
		.in_event_mask = 0
			| S(MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST)
			| S(MSC_T_EV_CN_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_T_ST_WAIT_LOCAL_RTP)
			| S(MSC_T_ST_WAIT_HO_REQUEST_ACK)
			,
	},
	[MSC_T_ST_WAIT_LOCAL_RTP] = {
		.name = "WAIT_LOCAL_RTP",
		.onenter = msc_t_fsm_wait_local_rtp_onenter,
		.action = msc_t_fsm_wait_local_rtp,
		.in_event_mask = 0
			| S(MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_T_EV_CN_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_T_ST_WAIT_HO_REQUEST_ACK)
			,
	},
	[MSC_T_ST_WAIT_HO_REQUEST_ACK] = {
		.name = "WAIT_HO_REQUEST_ACK",
		.action = msc_t_fsm_wait_ho_request_ack,
		.in_event_mask = 0
			| S(MSC_EV_FROM_RAN_UP_L2)
			| S(MSC_EV_FROM_RAN_CONN_RELEASED)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_T_EV_CN_CLOSE)
			| S(MSC_T_EV_MO_CLOSE)
			,
		.out_state_mask = 0
			| S(MSC_T_ST_WAIT_HO_COMPLETE)
			,
	},
	[MSC_T_ST_WAIT_HO_COMPLETE] = {
		.name = "WAIT_HO_COMPLETE",
		.action = msc_t_fsm_wait_ho_complete,
		.in_event_mask = 0
			| S(MSC_EV_FROM_RAN_UP_L2)
			| S(MSC_EV_FROM_RAN_CONN_RELEASED)
			| S(MSC_EV_CALL_LEG_TERM)
			| S(MSC_MNCC_EV_CALL_ENDED)
			| S(MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST)
			| S(MSC_T_EV_CN_CLOSE)
			| S(MSC_T_EV_MO_CLOSE)
			,
	},
};

const struct value_string msc_t_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSC_REMOTE_EV_RX_GSUP),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_LOCAL_ADDR_AVAILABLE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_RTP_COMPLETE),
	OSMO_VALUE_STRING(MSC_EV_CALL_LEG_TERM),
	OSMO_VALUE_STRING(MSC_MNCC_EV_NEED_LOCAL_RTP),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_PROCEEDING),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_COMPLETE),
	OSMO_VALUE_STRING(MSC_MNCC_EV_CALL_ENDED),

	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_COMPLETE_LAYER_3),
	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_UP_L2),
	OSMO_VALUE_STRING(MSC_EV_FROM_RAN_CONN_RELEASED),

	OSMO_VALUE_STRING(MSC_T_EV_FROM_A_PREPARE_HANDOVER_REQUEST),
	OSMO_VALUE_STRING(MSC_T_EV_FROM_A_FORWARD_ACCESS_SIGNALLING_REQUEST),
	OSMO_VALUE_STRING(MSC_T_EV_CN_CLOSE),
	OSMO_VALUE_STRING(MSC_T_EV_MO_CLOSE),
	OSMO_VALUE_STRING(MSC_T_EV_CLEAR_COMPLETE),
	{}
};

static struct osmo_fsm msc_t_fsm = {
	.name = "msc_t",
	.states = msc_t_fsm_states,
	.num_states = ARRAY_SIZE(msc_t_fsm_states),
	.log_subsys = DMSC,
	.event_names = msc_t_fsm_event_names,
	.cleanup = msc_t_fsm_cleanup,
};

static __attribute__((constructor)) void msc_t_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_t_fsm) == 0);
}

/* Send connection-oriented L3 message to RAN peer (MSC->[BSC|RNC]) */
int msc_t_down_l2_co(struct msc_t *msc_t, const struct an_apdu *an_apdu, bool initial)
{
	int rc;
	if (!msc_t->ran_conn) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Cannot Tx L2 message: no RAN conn\n");
		return -EIO;
	}

	if (an_apdu->an_proto != msc_t->c.ran->an_proto) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Mismatching AN-APDU proto: %s -- Dropping message\n",
			  an_proto_name(an_apdu->an_proto));
		return -EIO;
	}

	rc = ran_conn_down_l2_co(msc_t->ran_conn, an_apdu->msg, initial);
	if (rc)
		LOG_MSC_T(msc_t, LOGL_ERROR, "Failed to transfer message down to new RAN peer (rc=%d)\n", rc);
	return rc;
}

struct gsm_network *msc_t_net(const struct msc_t *msc_t)
{
	return msub_net(msc_t->c.msub);
}

struct vlr_subscr *msc_t_vsub(const struct msc_t *msc_t)
{
	if (!msc_t)
		return NULL;
	return msub_vsub(msc_t->c.msub);
}

struct msc_t *msc_t_alloc_without_ran_peer(struct msub *msub, struct ran_infra *ran)
{
	struct msc_t *msc_t;

	msub_role_alloc(msub, MSC_ROLE_T, &msc_t_fsm, struct msc_t, ran);
	msc_t = msub_msc_t(msub);
	if (!msc_t)
		return NULL;

	return msc_t;
}

int msc_t_set_ran_peer(struct msc_t *msc_t, struct ran_peer *ran_peer)
{
	if (!ran_peer || !ran_peer->sri || !ran_peer->sri->ran) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Invalid RAN peer: %s\n", ran_peer ? ran_peer->fi->id : "NULL");
		return -EINVAL;
	}

	if (ran_peer->sri->ran != msc_t->c.ran) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "This MSC-T was set up for %s, cannot assign RAN peer for %s\n",
			  osmo_rat_type_name(msc_t->c.ran->type), osmo_rat_type_name(ran_peer->sri->ran->type));
		return -EINVAL;
	}

	/* Create a new ran_conn with a fresh conn_id for the outgoing initial message. The msc_t FSM definition ensures
	 * that the first message sent or received is a Connection-Oriented Initial message. */
	msc_t->ran_conn = ran_conn_create_outgoing(ran_peer);
	if (!msc_t->ran_conn) {
		LOG_MSC_T(msc_t, LOGL_ERROR, "Failed to create outgoing RAN conn\n");
		return -EINVAL;
	}
	msc_t->ran_conn->msc_role = msc_t->c.fi;
	msub_update_id(msc_t->c.msub);
	return 0;
}

struct msc_t *msc_t_alloc(struct msub *msub, struct ran_peer *ran_peer)
{
	struct msc_t *msc_t = msc_t_alloc_without_ran_peer(msub, ran_peer->sri->ran);
	if (!msc_t)
		return NULL;
	if (msc_t_set_ran_peer(msc_t, ran_peer)) {
		msc_t_clear(msc_t);
		return NULL;
	}
	return msc_t;
}

void msc_t_clear(struct msc_t *msc_t)
{
	if (!msc_t)
		return;
	osmo_fsm_inst_term(msc_t->c.fi, OSMO_FSM_TERM_REGULAR, msc_t->c.fi);
}
