/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
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

/**
 * MSC-specific handling of call independent Supplementary
 * Services messages (NC_SS) according to GSM TS 09.11
 * "Signalling interworking for supplementary services".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/osmo_msc.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/transaction.h>

/* FIXME: choose a proper range */
static uint32_t new_callref = 0x20000001;

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn,
			   const struct ss_request *req)
{
	char *own_number = conn->vsub->msisdn;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	DEBUGP(DMM, "%s: MSISDN = %s\n", vlr_subscr_name(conn->vsub),
	       own_number);

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(conn, response_string, req);
}

/* Entry point for call independent MO SS messages */
int gsm0911_rcv_nc_ss(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_trans *trans;
	struct ss_request req;
	uint8_t pdisc, tid;
	uint8_t msg_type;
	int rc;

	pdisc = gsm48_hdr_pdisc(gh);
	msg_type = gsm48_hdr_msg_type(gh);
	tid = gsm48_hdr_trans_id_flip_ti(gh);

	/* Associate logging messages with this subscriber */
	log_set_context(LOG_CTX_VLR_SUBSCR, conn->vsub);

	DEBUGP(DMM, "Received SS/USSD data (trans_id=%x, msg_type=%s)\n",
		tid, gsm48_pdisc_msgtype_name(pdisc, msg_type));

	/* Reuse existing transaction, or create a new one */
	trans = trans_find_by_id(conn, pdisc, tid);
	if (!trans) {
		/**
		 * According to GSM TS 04.80, section 2.4.2 "Register
		 * (mobile station to network direction)", the REGISTER
		 * message is sent by the mobile station to the network
		 * to assign a new transaction identifier for call independent
		 * supplementary service control and to request or acknowledge
		 * a supplementary service.
		 */
		if (msg_type != GSM0480_MTYPE_REGISTER) {
			LOGP(DMM, LOGL_ERROR, "Unexpected message (msg_type=%s), "
				"transaction is not allocated yet\n",
				gsm48_pdisc_msgtype_name(pdisc, msg_type));
			gsm48_tx_simple(conn,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -EINVAL;
		}

		DEBUGP(DMM, " -> (new transaction)\n");
		trans = trans_alloc(conn->network, conn->vsub,
			pdisc, tid, new_callref++);
		if (!trans) {
			DEBUGP(DMM, " -> No memory for trans\n");
			gsm48_tx_simple(conn,
				GSM48_PDISC_NC_SS | (tid << 4),
				GSM0480_MTYPE_RELEASE_COMPLETE);
			return -ENOMEM;
		}

		trans->conn = msc_subscr_conn_get(conn, MSC_CONN_USE_TRANS_NC_SS);
		trans->dlci = OMSC_LINKID_CB(msg);
		cm_service_request_concludes(conn, msg);
	}

	memset(&req, 0, sizeof(req));
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);
	if (!rc) {
		LOGP(DMM, LOGL_ERROR, "SS/USSD message parsing error, "
			"rejecting request...\n");
		gsm0480_send_ussd_reject(conn, &req, GSM_0480_PROBLEM_CODE_TAG_GENERAL,
			GSM_0480_GEN_PROB_CODE_UNRECOGNISED);
		/* The GSM 04.80 API uses inverted codes (0 means error) */
		return -EPROTO;
	}

	/* Interrogation or releaseComplete? */
	if (req.ussd_text[0] == '\0' || req.ussd_text[0] == 0xFF) {
		if (req.ss_code > 0) {
			/* Assume interrogateSS or modification of it and reject */
			return gsm0480_send_ussd_return_error(conn, &req,
				GSM0480_ERR_CODE_ILLEGAL_SS_OPERATION);
		}
		/* Still assuming a Release-Complete and returning */
		return 0;
	}

	msc_subscr_conn_communicating(conn);
	if (!strcmp(USSD_TEXT_OWN_NUMBER, (const char *)req.ussd_text)) {
		DEBUGP(DMM, "USSD: Own number requested\n");
		rc = send_own_number(conn, &req);
	} else {
		DEBUGP(DMM, "Unhandled USSD %s\n", req.ussd_text);
		rc = gsm0480_send_ussd_return_error(conn, &req,
			GSM0480_ERR_CODE_UNEXPECTED_DATA_VALUE);
	}

	/**
	 * TODO: as we only handle *#100# for now, and always
	 * respond with RELEASE COMPLETE, let's manually free
	 * the transaction here, until the external interface
	 * is implemented.
	 */
	trans_free(trans);

	return rc;
}
