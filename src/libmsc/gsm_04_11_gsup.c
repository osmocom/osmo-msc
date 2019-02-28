/*
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
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
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/msc_common.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>

/* Common helper for preparing to be encoded GSUP message */
static void gsup_sm_msg_init(struct osmo_gsup_message *gsup_msg,
	enum osmo_gsup_message_type msg_type, const char *imsi,
	uint8_t *sm_rp_mr)
{
	/* Init a mew GSUP message */
	memset(gsup_msg, 0x00, sizeof(*gsup_msg));
	gsup_msg->message_type = msg_type;

	/* SM-RP-MR (Message Reference) */
	gsup_msg->sm_rp_mr = sm_rp_mr;

	/* Fill in subscriber's IMSI */
	OSMO_STRLCPY_ARRAY(gsup_msg->imsi, imsi);
}

int gsm411_gsup_mo_fwd_sm_req(struct gsm_trans *trans, struct msgb *msg,
	uint8_t sm_rp_mr, uint8_t *sm_rp_da, uint8_t sm_rp_da_len)
{
	uint8_t bcd_buf[GSM48_MI_SIZE] = { 0 };
	struct osmo_gsup_message gsup_msg;
	size_t bcd_len;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);

	LOG_TRANS(trans, LOGL_DEBUG, "TX GSUP MO-forwardSM-Req\n");

	/* Assign SM-RP-MR to transaction state */
	trans->sms.sm_rp_mr = sm_rp_mr;

	/* Encode subscriber's MSISDN */
	bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf),
		0, trans->vsub->msisdn);
	if (bcd_len <= 0 || bcd_len > sizeof(bcd_buf)) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to encode subscriber's MSISDN\n");
		return -EINVAL;
	}

	/* Initialize a new GSUP message */
	gsup_sm_msg_init(&gsup_msg, OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST,
		trans->vsub->imsi, &sm_rp_mr);

	/* According to 12.2.3, the MSISDN from VLR is inserted here */
	gsup_msg.sm_rp_oa_type = OSMO_GSUP_SMS_SM_RP_ODA_MSISDN;
	gsup_msg.sm_rp_oa_len = bcd_len;
	gsup_msg.sm_rp_oa = bcd_buf;

	/* SM-RP-DA should (already) contain SMSC address */
	gsup_msg.sm_rp_da_type = OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR;
	gsup_msg.sm_rp_da_len = sm_rp_da_len;
	gsup_msg.sm_rp_da = sm_rp_da;

	/* SM-RP-UI (TPDU) is pointed by msgb->l4h */
	gsup_msg.sm_rp_ui_len = msgb_l4len(msg);
	gsup_msg.sm_rp_ui = (uint8_t *) msgb_sms(msg);

	return osmo_gsup_client_enc_send(trans->net->vlr->gsup_client, &gsup_msg);
}

int gsm411_gsup_mo_ready_for_sm_req(struct gsm_trans *trans, uint8_t sm_rp_mr)
{
	struct osmo_gsup_message gsup_msg;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);

	LOG_TRANS(trans, LOGL_DEBUG, "TX GSUP READY-FOR-SM Req\n");

	/* Assign SM-RP-MR to transaction state */
	trans->sms.sm_rp_mr = sm_rp_mr;

	/* Initialize a new GSUP message */
	gsup_sm_msg_init(&gsup_msg, OSMO_GSUP_MSGT_READY_FOR_SM_REQUEST,
		trans->vsub->imsi, &sm_rp_mr);

	/* Indicate SMMA as the Alert Reason */
	gsup_msg.sm_alert_rsn = OSMO_GSUP_SMS_SM_ALERT_RSN_MEM_AVAIL;

	return osmo_gsup_client_enc_send(trans->net->vlr->gsup_client, &gsup_msg);
}

/* Triggers either RP-ACK or RP-ERROR on response from SMSC */
int gsm411_gsup_mo_handler(struct vlr_subscr *vsub,
	struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr;
	struct gsm_network *net;
	struct gsm_trans *trans;
	const char *msg_name;
	bool msg_is_err;

	/* Obtain required pointers */
	vlr = vsub->vlr;
	net = (struct gsm_network *) vlr->user_ctx;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

	/* Determine the message type and name */
	msg_is_err = OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type);
	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR:
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_RESULT:
		msg_name = "MO-forwardSM";
		break;
	case OSMO_GSUP_MSGT_READY_FOR_SM_ERROR:
	case OSMO_GSUP_MSGT_READY_FOR_SM_RESULT:
		msg_name = "MO-ReadyForSM";
		break;
	default:
		/* Shall not happen */
		OSMO_ASSERT(0);
	}

	/* Make sure that 'SMS over GSUP' is expected */
	if (!net->sms_over_gsup) {
		/* TODO: notify sender about that? */
		LOGP(DLSMS, LOGL_NOTICE, "Unexpected MO SMS over GSUP, "
			"ignoring message...\n");
		return -EIO;
	}

	/* Verify GSUP message */
	if (!gsup_msg->sm_rp_mr)
		goto msg_error;
	if (msg_is_err && !gsup_msg->sm_rp_cause)
		goto msg_error;

	/* Attempt to find DTAP-transaction */
	trans = trans_find_by_sm_rp_mr(net, vsub, *(gsup_msg->sm_rp_mr));
	if (!trans) {
		LOGP(DLSMS, LOGL_NOTICE, "No transaction found for %s, "
			"ignoring %s-%s message...\n", vlr_subscr_name(vsub),
			msg_name, msg_is_err ? "Err" : "Res");
		return -EIO; /* TODO: notify sender about that? */
	}

	LOG_TRANS(trans, LOGL_DEBUG, "RX %s-%s\n", msg_name, msg_is_err ? "Err" : "Res");

	/* Send either RP-ERROR, or RP-ACK */
	if (msg_is_err) {
		/* TODO: handle optional SM-RP-UI payload (requires API change) */
		gsm411_send_rp_error(trans, *(gsup_msg->sm_rp_mr),
			*(gsup_msg->sm_rp_cause));
	} else {
		gsm411_send_rp_ack(trans, *(gsup_msg->sm_rp_mr));
	}

	return 0;

msg_error:
	/* TODO: notify sender about that? */
	LOGP(DLSMS, LOGL_NOTICE, "RX malformed %s-%s\n",
		msg_name, msg_is_err ? "Err" : "Res");
	return -EINVAL;
}

int gsm411_gsup_mt_fwd_sm_res(struct gsm_trans *trans, uint8_t sm_rp_mr)
{
	struct osmo_gsup_message gsup_msg;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);

	LOG_TRANS(trans, LOGL_DEBUG, "TX MT-forwardSM-Res\n");

	/* Initialize a new GSUP message */
	gsup_sm_msg_init(&gsup_msg, OSMO_GSUP_MSGT_MT_FORWARD_SM_RESULT,
		trans->vsub->imsi, &sm_rp_mr);

	return osmo_gsup_client_enc_send(trans->net->vlr->gsup_client, &gsup_msg);
}

int gsm411_gsup_mt_fwd_sm_err(struct gsm_trans *trans,
	uint8_t sm_rp_mr, uint8_t cause)
{
	struct osmo_gsup_message gsup_msg;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);

	LOG_TRANS(trans, LOGL_DEBUG, "TX MT-forwardSM-Err\n");

	/* Initialize a new GSUP message */
	gsup_sm_msg_init(&gsup_msg, OSMO_GSUP_MSGT_MT_FORWARD_SM_ERROR,
		trans->vsub->imsi, &sm_rp_mr);

	/* SM-RP-Cause value */
	gsup_msg.sm_rp_cause = &cause;

	/* TODO: include optional SM-RP-UI field if present */
	return osmo_gsup_client_enc_send(trans->net->vlr->gsup_client, &gsup_msg);
}

/* Handles MT SMS (and triggers Paging Request if required) */
int gsm411_gsup_mt_handler(struct vlr_subscr *vsub,
	struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr;
	struct gsm_network *net;
	int rc;

	/* Obtain required pointers */
	vlr = vsub->vlr;
	net = (struct gsm_network *) vlr->user_ctx;

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

	LOGP(DLSMS, LOGL_DEBUG, "RX MT-forwardSM-Req\n");

	/* Make sure that 'SMS over GSUP' is expected */
	if (!net->sms_over_gsup) {
		LOGP(DLSMS, LOGL_NOTICE, "Unexpected MT SMS over GSUP, "
			"ignoring message...\n");
		/* TODO: notify sender about that? */
		return -EIO;
	}

	/**
	 * Verify GSUP message
	 *
	 * FIXME: SM-RP-MR is not known yet (to be assigned by MSC)
	 * NOTE: SM-RP-DA is out of our interest
	 */
	if (!gsup_msg->sm_rp_mr)
		goto msg_error;
	if (!gsup_msg->sm_rp_ui)
		goto msg_error;

	/* SM-RP-OA shall contain SMSC address */
	if (gsup_msg->sm_rp_oa_type != OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR)
		goto msg_error;

	/* Send RP-DATA */
	rc = gsm411_send_rp_data(net, vsub,
		gsup_msg->sm_rp_oa_len, gsup_msg->sm_rp_oa,
		gsup_msg->sm_rp_ui_len, gsup_msg->sm_rp_ui);
	if (rc) {
		LOGP(DLSMS, LOGL_NOTICE, "Failed to send MT SMS, "
			"ignoring MT-forwardSM-Req message...\n");
		/* TODO: notify sender about that? */
		return rc;
	}

	return 0;

msg_error:
	/* TODO: notify sender about that? */
	LOGP(DLSMS, LOGL_NOTICE, "RX malformed MT-forwardSM-Req\n");
	return -EINVAL;
}
