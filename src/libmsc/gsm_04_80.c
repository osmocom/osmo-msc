/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009, 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/gsm_04_80.h>
#include <osmocom/msc/msc_ifaces.h>

#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, uint8_t tag)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = tag;
	data[1] = msgb->len - 2;
	return data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, uint8_t tag,
					    uint8_t value)
{
	uint8_t *data = msgb_push(msgb, 3);

	data[0] = tag;
	data[1] = 1;
	data[2] = value;
	return data;
}

static inline unsigned char *msgb_push_NULL(struct msgb *msgb)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = ASN1_NULL_TYPE_TAG;
	data[1] = 0;
	return data;
}


/*! Send a MT RELEASE COMPLETE message with USSD-response,
 *  wrapped into the ReturnResult component (see section 3.6.1).
 *
 * \param[in]  conn            Active subscriber connection
 * \param[in]  transaction_id  Transaction ID with TI flag set
 * \param[in]  invoke_id       InvokeID of the request
 * \param[in]  response_text   The response text
 * \return     result of \ref msc_tx_dtap
 */
int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       uint8_t transaction_id, uint8_t invoke_id,
			       const char *response_text)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USSD RSP");
	struct gsm48_hdr *gh;
	uint8_t *ptr8;
	int response_len;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, 0);
	gsm_7bit_encode_n_ussd(ptr8, msgb_tailroom(msg), response_text, &response_len);
	msgb_put(msg, response_len);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, 0x0F);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the operation code */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE,
			GSM0480_OP_CODE_PROCESS_USS_REQ);

	/* Wrap the operation code and IA5 string as a sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, invoke_id);

	/* Wrap this up as a Return Result component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_RETURN_RESULT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr  = GSM48_PDISC_NC_SS;
	gh->proto_discr |= transaction_id << 4;
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return msc_tx_dtap(conn, msg);
}

/*! Send a MT RELEASE COMPLETE message with ReturnError component
 *  (see section 3.6.1) and given error code (see section 3.6.6).
 *
 * \param[in]  conn            Active subscriber connection
 * \param[in]  transaction_id  Transaction ID with TI flag set
 * \param[in]  invoke_id       InvokeID of the request
 * \param[in]  error_code      Error code (section 4.5)
 * \return     result of \ref msc_tx_dtap
 */
int gsm0480_send_ussd_return_error(struct gsm_subscriber_connection *conn,
	uint8_t transaction_id, uint8_t invoke_id, uint8_t error_code)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USSD ERR");
	struct gsm48_hdr *gh;

	/* First insert the problem code */
	msgb_push_TLV1(msg, GSM_0480_ERROR_CODE_TAG, error_code);

	/* Before it insert the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, invoke_id);

	/* Wrap this up as a Reject component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_RETURN_ERROR);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr  = GSM48_PDISC_NC_SS;
	gh->proto_discr |= transaction_id << 4;
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return msc_tx_dtap(conn, msg);
}

/*! Send a MT RELEASE COMPLETE message with Reject component
 *  (see section 3.6.1) and given error code (see section 3.6.7).
 *
 * \param[in]  conn            Active subscriber connection
 * \param[in]  transaction_id  Transaction ID with TI flag set
 * \param[in]  invoke_id       InvokeID of the request
 * \param[in]  problem_tag     Problem code tag (table 3.13)
 * \param[in]  problem_code    Problem code (tables 3.14-17)
 * \return     result of \ref msc_tx_dtap
 *
 * Note: if InvokeID is not available, e.g. when message parsing
 * failed, any incorrect value can be passed (0x00 > x > 0xff), so
 * the universal NULL-tag (see table 3.6) will be used instead.
 */
int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     uint8_t transaction_id, int invoke_id,
			     uint8_t problem_tag, uint8_t problem_code)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USSD REJ");
	struct gsm48_hdr *gh;

	/* First insert the problem code */
	msgb_push_TLV1(msg, problem_tag, problem_code);

	/**
	 * If the Invoke ID is not available, Universal Null
	 * (table 3.9) with length = 0 shall be used.
	 */
	if (invoke_id < 0 || invoke_id > 255)
		msgb_push_NULL(msg);
	else
		msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, invoke_id);

	/* Wrap this up as a Reject component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_REJECT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr  = GSM48_PDISC_NC_SS;
	gh->proto_discr |= transaction_id << 4;
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return msc_tx_dtap(conn, msg);
}

int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level, const char *text)
{
	struct msgb *msg = gsm0480_create_ussd_notify(level, text);
	if (!msg)
		return -1;
	return msc_tx_dtap(conn, msg);
}

int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm0480_create_ussd_release_complete();
	if (!msg)
		return -1;
	return msc_tx_dtap(conn, msg);
}
