/* Directing individual GSUP messages to their respective handlers. */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <errno.h>

#include <osmocom/gsupclient/gsup_client.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsup_client_mux.h>

static enum osmo_gsup_message_class gsup_client_mux_classify(struct gsup_client_mux *gcm,
						    const struct osmo_gsup_message *gsup_msg)
{
	if (gsup_msg->message_class)
		return gsup_msg->message_class;

	LOGP(DLGSUP, LOGL_DEBUG, "No explicit GSUP Message Class, trying to guess from message type %s\n",
	     osmo_gsup_message_type_name(gsup_msg->message_type));

	switch (gsup_msg->message_type) {
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		return OSMO_GSUP_MESSAGE_CLASS_USSD;

	/* GSM 04.11 code implementing MO SMS */
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_ERROR:
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_RESULT:
	case OSMO_GSUP_MSGT_READY_FOR_SM_ERROR:
	case OSMO_GSUP_MSGT_READY_FOR_SM_RESULT:
	case OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST:
		return OSMO_GSUP_MESSAGE_CLASS_SMS;

	default:
		return OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT;
	}
}

/* Non-static for unit tests */
int gsup_client_mux_rx(struct osmo_gsup_client *gsup_client, struct msgb *msg)
{
	struct gsup_client_mux *gcm = gsup_client->data;
	struct osmo_gsup_message gsup;
	enum osmo_gsup_message_class message_class;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DLGSUP, LOGL_ERROR, "Failed to decode GSUP message: '%s' (%d) [ %s]\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc, osmo_hexdump(msg->data, msg->len));
		goto msgb_free_and_return;
	}

	if (!gsup.imsi[0]) {
		LOGP(DLGSUP, LOGL_ERROR, "Failed to decode GSUP message: missing IMSI\n");
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup.message_type))
			gsup_client_mux_tx_error_reply(gcm, &gsup, GMM_CAUSE_INV_MAND_INFO);
		rc = -GMM_CAUSE_INV_MAND_INFO;
		goto msgb_free_and_return;
	}

	message_class = gsup_client_mux_classify(gcm, &gsup);

	if (message_class <= OSMO_GSUP_MESSAGE_CLASS_UNSET || message_class >= ARRAY_SIZE(gcm->rx_cb)) {
		LOGP(DLGSUP, LOGL_ERROR, "Failed to classify GSUP message target\n");
		rc = -EINVAL;
		goto msgb_free_and_return;
	}

	if (!gcm->rx_cb[message_class].func) {
		LOGP(DLGSUP, LOGL_ERROR, "No receiver set up for GSUP Message Class %s\n", osmo_gsup_message_class_name(message_class));
		rc = -ENOTSUP;
		goto msgb_free_and_return;
	}

	rc = gcm->rx_cb[message_class].func(gcm, gcm->rx_cb[message_class].data, &gsup);

msgb_free_and_return:
	msgb_free(msg);
	return rc;
}

/* Make it clear that struct gsup_client_mux should be talloc allocated, so that it can be used as talloc parent. */
struct gsup_client_mux *gsup_client_mux_alloc(void *talloc_ctx)
{
	return talloc_zero(talloc_ctx, struct gsup_client_mux);
}

/* Start a GSUP client to serve this gsup_client_mux. */
int gsup_client_mux_start(struct gsup_client_mux *gcm, const char *gsup_server_addr_str, uint16_t gsup_server_port,
			  struct ipaccess_unit *ipa_dev)
{
	gcm->gsup_client = osmo_gsup_client_create2(gcm, ipa_dev,
						    gsup_server_addr_str,
						    gsup_server_port,
						    &gsup_client_mux_rx, NULL);
	if (!gcm->gsup_client)
		return -ENOMEM;
	gcm->gsup_client->data = gcm;
	return 0;
}

int gsup_client_mux_tx(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg;
	int rc;

	if (!gcm || !gcm->gsup_client) {
		LOGP(DLGSUP, LOGL_ERROR, "GSUP link is down, cannot send GSUP message\n");
		return -ENOTSUP;
	}

	msg = osmo_gsup_client_msgb_alloc();
	rc = osmo_gsup_encode(msg, gsup_msg);
	if (rc < 0) {
		LOGP(DLGSUP, LOGL_ERROR, "Failed to encode GSUP message: '%s'\n", strerror(-rc));
		return rc;
	}

	return osmo_gsup_client_send(gcm->gsup_client, msg);
}

/* Set GSUP source_name to our local IPA name */
void gsup_client_mux_tx_set_source(const struct gsup_client_mux *gcm,
				   struct osmo_gsup_message *gsup_msg)
{
	const char *local_msc_name;

	if (!gcm)
		return;
	if (!gcm->gsup_client)
		return;
	if (!gcm->gsup_client->ipa_dev)
		return;
	local_msc_name = gcm->gsup_client->ipa_dev->serno;
	if (!local_msc_name)
		return;
	gsup_msg->source_name = (const uint8_t *) local_msc_name;
	gsup_msg->source_name_len = strlen(local_msc_name) + 1;
}

/* Transmit GSUP error in response to original message */
void gsup_client_mux_tx_error_reply(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_orig,
				    enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply;

	/* No need to answer if we couldn't parse an ERROR message type, only REQUESTs need an error reply. */
	if (!OSMO_GSUP_IS_MSGT_REQUEST(gsup_orig->message_type))
		return;

	gsup_reply = (struct osmo_gsup_message){
		.cause = cause,
		.message_type = OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type),
		.message_class = gsup_orig->message_class,
		.destination_name = gsup_orig->source_name,
		.destination_name_len = gsup_orig->source_name_len,

		/* RP-Message-Reference is mandatory for SM Service */
		.sm_rp_mr = gsup_orig->sm_rp_mr,
	};

	OSMO_STRLCPY_ARRAY(gsup_reply.imsi, gsup_orig->imsi);
	gsup_client_mux_tx_set_source(gcm, &gsup_reply);

	/* For SS/USSD, it's important to keep both session state and ID IEs */
	if (gsup_orig->session_state != OSMO_GSUP_SESSION_STATE_NONE) {
		gsup_reply.session_state = OSMO_GSUP_SESSION_STATE_END;
		gsup_reply.session_id = gsup_orig->session_id;
	}

	if (osmo_gsup_client_enc_send(gcm->gsup_client, &gsup_reply))
		LOGP(DLGSUP, LOGL_ERROR, "Failed to send Error reply (imsi=%s)\n",
		     osmo_quote_str(gsup_orig->imsi, -1));
}
