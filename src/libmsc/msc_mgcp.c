/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <arpa/inet.h>

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/msc/msc_mgcp.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/a_iface.h>
#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/iucs.h>
#include <osmocom/msc/vlr.h>

#include "../../bscconfig.h"

#define S(x)	(1 << (x))

#define CONN_ID_RAN 1
#define CONN_ID_CN 2

#define MGCP_MGW_TIMEOUT 4	/* in seconds */
#define MGCP_MGW_TIMEOUT_TIMER_NR 1
#define MGCP_RAN_TIMEOUT 10	/* in seconds */
#define MGCP_RAN_TIMEOUT_TIMER_NR 2
#define MGCP_REL_TIMEOUT 60	/* in seconds */
#define MGCP_REL_TIMEOUT_TIMER_NR 3
#define MGCP_ASS_TIMEOUT 10	/* in seconds */
#define MGCP_ASS_TIMEOUT_TIMER_NR 4

#define MGCP_ENDPOINT_FORMAT "%x@mgw"

/* Some internal cause codes to indicate fault condition inside the FSM */
enum msc_mgcp_cause_code {
	MGCP_ERR_MGW_FAIL,
	MGCP_ERR_MGW_INVAL_RESP,
	MGCP_ERR_MGW_TX_FAIL,
	MGCP_ERR_UNEXP_TEARDOWN,
	MGCP_ERR_UNSUPP_ADDR_FMT,
	MGCP_ERR_RAN_TIMEOUT,
	MGCP_ERR_ASS_TIMEOUT,
	MGCP_ERR_NOMEM,
	MGCP_ERR_ASSGMNT_FAIL
};

/* Human readable respresentation of the faul codes, will be displayed by
 * handle_error() */
static const struct value_string msc_mgcp_cause_codes_names[] = {
	{MGCP_ERR_MGW_FAIL, "operation failed on MGW"},
	{MGCP_ERR_MGW_INVAL_RESP, "invalid / unparseable response from MGW"},
	{MGCP_ERR_MGW_TX_FAIL, "failed to transmit MGCP message to MGW"},
	{MGCP_ERR_UNEXP_TEARDOWN, "unexpected connection teardown"},
	{MGCP_ERR_UNSUPP_ADDR_FMT, "unsupported network address format used (RAN)"},
	{MGCP_ERR_RAN_TIMEOUT, "call could not be completed in time (RAN)"},
	{MGCP_ERR_ASS_TIMEOUT, "assignment could not be completed in time (RAN)"},
	{MGCP_ERR_NOMEM, "out of memory"},
	{MGCP_ERR_ASSGMNT_FAIL, "assignment failure (RAN)"},
	{0, NULL}
};

enum fsm_msc_mgcp_states {
	ST_CRCX_RAN,
	ST_CRCX_CN,
	ST_CRCX_COMPL,
	ST_MDCX_CN,
	ST_MDCX_CN_COMPL,
	ST_MDCX_RAN,
	ST_MDCX_RAN_COMPL,
	ST_CALL,
	ST_HALT,
};

enum msc_mgcp_fsm_evt {
	/* Initial event: start off the state machine */
	EV_INIT,

	/* External event: Notify that the Assignment is complete and we
	 * may now forward IP/Port of the remote call leg to the MGW */
	EV_ASSIGN,

	/* External event: Notify that the Call is complete and that the
	 * two half open connections on the MGW should now be connected */
	EV_CONNECT,

	/* External event: Notify that the call is over and the connections
	 * on the mgw shall be removed */
	EV_TEARDOWN,

	/* Internal event: An error occurred that requires a controlled
	 * teardown of the RTP connections */
	EV_TEARDOWN_ERROR,

	/* Internal event: The mgcp_gw has sent its CRCX response for
	 * the RAN side */
	EV_CRCX_RAN_RESP,

	/* Internal event: The mgcp_gw has sent its CRCX response for
	 * the CN side */
	EV_CRCX_CN_RESP,

	/* Internal event: The mgcp_gw has sent its MDCX response for
	 * the RAN side */
	EV_MDCX_RAN_RESP,

	/* Internal event: The mgcp_gw has sent its MDCX response for
	 * the CN side */
	EV_MDCX_CN_RESP,

	/* Internal event: The mgcp_gw has sent its DLCX response for
	 * the RAN and CN side */
	EV_DLCX_ALL_RESP,
};

/* A general error handler function. On error we still have an interest to
 * remove a half open connection (if possible). This function will execute
 * a controlled jump to the DLCX phase. From there, the FSM will then just
 * continue like the call were ended normally */
static void handle_error(struct mgcp_ctx *mgcp_ctx, enum msc_mgcp_cause_code cause)
{
	struct osmo_fsm_inst *fi;

	OSMO_ASSERT(mgcp_ctx);
	fi = mgcp_ctx->fsm;
	OSMO_ASSERT(fi);

	LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "%s -- graceful shutdown...\n",
		 get_value_string(msc_mgcp_cause_codes_names, cause));

	/* Set the VM into the state where it waits for the call end */
	osmo_fsm_inst_state_chg(fi, ST_CALL, 0, 0);

	/* Simulate the call end by sending a teardown event, so that
	 * the FSM proceeds directly with the DLCX */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_TEARDOWN_ERROR, mgcp_ctx);
}

/* Timer callback to shut down in case of connectivity problems */
static int fsm_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct mgcp_ctx *mgcp_ctx = fi->priv;
	struct mgcp_client *mgcp;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	if (fi->T == MGCP_MGW_TIMEOUT_TIMER_NR) {
		/* We were unable to communicate with the MGW, unfortunately
		 * there is no meaningful action we can take now other than
		 * giving up. */

		/* At least release the occupied endpoint ID */
		mgcp_client_release_endpoint(mgcp_ctx->rtp_endpoint, mgcp);

		/* Cancel the transaction that timed out */
		mgcp_client_cancel(mgcp, mgcp_ctx->mgw_pending_trans);

		/* Initiate self destruction of the FSM */
		osmo_fsm_inst_state_chg(fi, ST_HALT, 0, 0);
		osmo_fsm_inst_dispatch(fi, EV_TEARDOWN_ERROR, mgcp_ctx);
	} else if (fi->T == MGCP_RAN_TIMEOUT_TIMER_NR) {
		/* If the logic that controls the RAN is unable to negotiate a
		 * connection, we presumably still have a working connection to
		 * the MGW, we will try to shut down gracefully. */
		handle_error(mgcp_ctx, MGCP_ERR_RAN_TIMEOUT);
	} else if (fi->T == MGCP_REL_TIMEOUT_TIMER_NR) {
		/* Under normal conditions, the MSC logic should always command
		 * to release the call at some point. However, the release may
		 * be missing due to errors in the MSC logic and we may have
		 * reached ST_HALT because of cascading errors and timeouts. In
		 * this and only in this case we will allow ST_HALT to free all
		 * context information on its own authority. */
		mgcp_ctx->free_ctx = true;

		/* Initiate self destruction of the FSM */
		osmo_fsm_inst_state_chg(fi, ST_HALT, 0, 0);
		osmo_fsm_inst_dispatch(fi, EV_TEARDOWN, mgcp_ctx);
	} else if (fi->T == MGCP_ASS_TIMEOUT_TIMER_NR) {
		/* There may be rare cases in which the MSC is unable to
		 * complete the call assignment */
		handle_error(mgcp_ctx, MGCP_ERR_ASS_TIMEOUT);
	} else {
		/* Ther must not be any unsolicited timers in this FSM. If so,
		 * we have serious problem. */
		OSMO_ASSERT(false);
	}

	return 0;
}

static void mgw_crcx_ran_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_CRCX_RAN: Send CRCX for RAN side to MGW */
static void fsm_crcx_ran_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct mgcp_client *mgcp;
	struct mgcp_msg mgcp_msg;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	mgcp_ctx->rtp_endpoint = mgcp_client_next_endpoint(mgcp);

	LOGPFSML(fi, LOGL_DEBUG,
		 "CRCX/RAN: creating connection for the RAN side on MGW endpoint:0x%x...\n", mgcp_ctx->rtp_endpoint);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_MODE),
		.call_id = mgcp_ctx->rtp_endpoint,
		.conn_mode = MGCP_CONN_LOOPBACK
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, mgcp_ctx->rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	rc = mgcp_client_tx(mgcp, msg, mgw_crcx_ran_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_CRCX_CN, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for RAN associated CRCX */
static void mgw_crcx_ran_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	int rc;
	struct gsm_trans *trans;
	struct gsm_subscriber_connection *conn;

	OSMO_ASSERT(mgcp_ctx);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "CRCX/RAN: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* memorize connection identifier */
	osmo_strlcpy(mgcp_ctx->conn_id_ran, r->head.conn_id, sizeof(mgcp_ctx->conn_id_ran));
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/RAN: MGW responded with CI: %s\n", mgcp_ctx->conn_id_ran);

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "CRCX/RAN: Cannot parse response\n");
		handle_error(mgcp_ctx, MGCP_ERR_MGW_INVAL_RESP);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/BTS: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	conn->rtp.local_port_ran = r->audio_port;
	osmo_strlcpy(conn->rtp.local_addr_ran, r->audio_ip, sizeof(conn->rtp.local_addr_ran));

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_CRCX_RAN_RESP, mgcp_ctx);
}

static void mgw_crcx_cn_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_CRCX_CN: check MGW response and send CRCX for CN side to MGW */
static void fsm_crcx_cn_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct mgcp_client *mgcp;
	struct mgcp_msg mgcp_msg;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	switch (event) {
	case EV_CRCX_RAN_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG,
		 "CRCX/CN creating connection for the CN side on MGW endpoint:0x%x...\n", mgcp_ctx->rtp_endpoint);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_CRCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_MODE),
		.call_id = mgcp_ctx->rtp_endpoint,
		.conn_mode = MGCP_CONN_LOOPBACK
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, mgcp_ctx->rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	rc = mgcp_client_tx(mgcp, msg, mgw_crcx_cn_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_CRCX_COMPL, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for CN associated CRCX */
static void mgw_crcx_cn_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;
	int rc;
	struct gsm_trans *trans;
	struct gsm_subscriber_connection *conn;

	OSMO_ASSERT(mgcp_ctx);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "CRCX/CN: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* memorize connection identifier */
	osmo_strlcpy(mgcp_ctx->conn_id_cn, r->head.conn_id, sizeof(mgcp_ctx->conn_id_cn));
	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/CN: MGW responded with CI: %s\n", mgcp_ctx->conn_id_cn);

	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR, "CRCX/CN: Cannot parse response\n");
		handle_error(mgcp_ctx, MGCP_ERR_MGW_INVAL_RESP);
		return;
	}

	LOGPFSML(mgcp_ctx->fsm, LOGL_DEBUG, "CRCX/CN: MGW responded with address %s:%u\n", r->audio_ip, r->audio_port);

	conn->rtp.local_port_cn = r->audio_port;
	osmo_strlcpy(conn->rtp.local_addr_cn, r->audio_ip, sizeof(conn->rtp.local_addr_cn));

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_CRCX_CN_RESP, mgcp_ctx);
}

/* Callback for ST_CRCX_COMPL: check MGW response, start assignment */
static void fsm_crcx_compl(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct gsm_trans *trans;
	struct gsm_subscriber_connection *conn;

	OSMO_ASSERT(mgcp_ctx);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	switch (event) {
	case EV_CRCX_CN_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	/* Forward assignment request to A/RANAP */
	if (conn->via_ran == RAN_UTRAN_IU) {
#ifdef BUILD_IU
		/* Assign a voice channel via RANAP on 3G */
		if (iu_rab_act_cs(trans))
			goto error;
#else
		LOGPFSML(fi, LOGL_ERROR, "Cannot send Iu RAB Assignment: built without Iu support\n");
		goto error;
#endif
	} else if (conn->via_ran == RAN_GERAN_A) {
		/* Assign a voice channel via A on 2G */
		if (a_iface_tx_assignment(trans))
			goto error;
	} else {
		/* Unset or unimplemented new RAN type */
		LOGPFSML(fi, LOGL_ERROR, "Unknown RAN type: %d\n", conn->via_ran);
		return;
	}

	/* Respond back to MNCC (if requested) */
	if (trans->tch_rtp_create) {
		if (gsm48_tch_rtp_create(trans))
			goto error;
	}

	/* Note: When we reach this point then the situation is basically that
	 * we have two sides connected, both are in loopback. The local ports
	 * of the side pointing towards the BSS should be already communicated
	 * and we are waiting now for the BSS to return with the assignment
	 * complete command. */
	osmo_fsm_inst_state_chg(fi, ST_MDCX_CN, MGCP_RAN_TIMEOUT, MGCP_RAN_TIMEOUT_TIMER_NR);
	return;

error:
	handle_error(mgcp_ctx, MGCP_ERR_ASSGMNT_FAIL);
}

static void mgw_mdcx_cn_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_MDCX_CN: send MDCX for RAN side to MGW */
static void fsm_mdcx_cn_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct mgcp_client *mgcp;
	struct gsm_trans *trans;
	struct gsm_subscriber_connection *conn;
	struct mgcp_msg mgcp_msg;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	switch (event) {
	case EV_CONNECT:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG,
		 "MDCX/CN: completing connection for the CN side on MGW endpoint:0x%x, remote leg expects RTP input on address %s:%u\n",
		 mgcp_ctx->rtp_endpoint, conn->rtp.remote_addr_cn, conn->rtp.remote_port_cn);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_MDCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP |
			     MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id = mgcp_ctx->rtp_endpoint,
		.conn_id = mgcp_ctx->conn_id_cn,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = conn->rtp.remote_addr_cn,
		.audio_port = conn->rtp.remote_port_cn
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, mgcp_ctx->rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	rc = mgcp_client_tx(mgcp, msg, mgw_mdcx_cn_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_MDCX_CN_COMPL, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for CN associated CRCX */
static void mgw_mdcx_cn_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;

	OSMO_ASSERT(mgcp_ctx);

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "MDCX/CN: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_MDCX_CN_RESP, mgcp_ctx);
}

/* Callback for ST_MDCX_CN_COMPL: wait for mgw response, move on with the MDCX
 * for the RAN side if we already have valid IP/Port data for the RAN sided
 * RTP stream. */
static void fsm_mdcx_cn_compl_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct gsm_subscriber_connection *conn;
	struct gsm_trans *trans;

	OSMO_ASSERT(mgcp_ctx);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	switch (event) {
	case EV_MDCX_CN_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	/* Enter MDCX phase, but we must be sure that the Assigmnet on the A or
	 * IuCS interface is complete (IP-Address and Port are valid) */
	osmo_fsm_inst_state_chg(fi, ST_MDCX_RAN, MGCP_ASS_TIMEOUT, MGCP_ASS_TIMEOUT_TIMER_NR);

	/* If we already have a valid remote port and IP-Address from the RAN side
	 * call leg, the assignment has been completed before we got here, so we
	 * may move on immediately */
	if (conn->rtp.remote_port_ran != 0 || strlen(conn->rtp.remote_addr_ran) > 0)
		osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_ASSIGN, mgcp_ctx);
}

static void mgw_mdcx_ran_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_MDCX_RAN: wait for assignment completion, send MDCX for CN side to MGW */
static void fsm_mdcx_ran_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	struct mgcp_client *mgcp;
	struct gsm_trans *trans;
	struct gsm_subscriber_connection *conn;
	struct mgcp_msg mgcp_msg;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);
	trans = mgcp_ctx->trans;
	OSMO_ASSERT(trans);
	conn = trans->conn;
	OSMO_ASSERT(conn);

	switch (event) {
	case EV_ASSIGN:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG,
		 "MDCX/RAN: completing connection for the CN side on MGW endpoint:0x%x, RAN expects RTP input on address %s:%u\n",
		 mgcp_ctx->rtp_endpoint, conn->rtp.remote_addr_ran, conn->rtp.remote_port_ran);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_MDCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID | MGCP_MSG_PRESENCE_CONN_ID |
			     MGCP_MSG_PRESENCE_CONN_MODE | MGCP_MSG_PRESENCE_AUDIO_IP |
			     MGCP_MSG_PRESENCE_AUDIO_PORT),
		.call_id = mgcp_ctx->rtp_endpoint,
		.conn_id = mgcp_ctx->conn_id_ran,
		.conn_mode = MGCP_CONN_RECV_SEND,
		.audio_ip = conn->rtp.remote_addr_ran,
		.audio_port = conn->rtp.remote_port_ran
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, mgcp_ctx->rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	rc = mgcp_client_tx(mgcp, msg, mgw_mdcx_ran_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_MDCX_RAN_COMPL, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for CN associated CRCX */
static void mgw_mdcx_ran_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;

	OSMO_ASSERT(mgcp_ctx);

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "MDCX/RAN: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_MDCX_RAN_RESP, mgcp_ctx);
}

/* Callback for ST_MDCX_RAN_COMPL: check MGW response */
static void fsm_mdcx_ran_compl_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;
	OSMO_ASSERT(mgcp_ctx);

	switch (event) {
	case EV_MDCX_RAN_RESP:
		break;
	default:
		handle_error(mgcp_ctx, MGCP_ERR_UNEXP_TEARDOWN);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "call active, waiting for teardown...\n");
	osmo_fsm_inst_state_chg(fi, ST_CALL, 0, 0);
}

static void mgw_dlcx_all_resp_cb(struct mgcp_response *r, void *priv);

/* Callback for ST_CALL: call is active, send DLCX for both sides on teardown */
static void fsm_call_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{

	struct mgcp_ctx *mgcp_ctx = (struct mgcp_ctx *)data;
	struct mgcp_client *mgcp;
	struct mgcp_msg mgcp_msg;
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(mgcp_ctx);
	mgcp = mgcp_ctx->mgcp;
	OSMO_ASSERT(mgcp);

	LOGPFSML(fi, LOGL_DEBUG,
		 "DLCX: removing connection for the RAN and CN side on MGW endpoint:0x%x...\n", mgcp_ctx->rtp_endpoint);

	/* We now relase the endpoint back to the pool in order to allow
	 * other connections to use this endpoint */
	mgcp_client_release_endpoint(mgcp_ctx->rtp_endpoint, mgcp);

	/* Generate MGCP message string */
	mgcp_msg = (struct mgcp_msg) {
		.verb = MGCP_VERB_DLCX,
		.presence = (MGCP_MSG_PRESENCE_ENDPOINT | MGCP_MSG_PRESENCE_CALL_ID),
		.call_id = mgcp_ctx->rtp_endpoint
	};
	if (snprintf(mgcp_msg.endpoint, MGCP_ENDPOINT_MAXLEN, MGCP_ENDPOINT_FORMAT, mgcp_ctx->rtp_endpoint) >=
	    MGCP_ENDPOINT_MAXLEN) {
		handle_error(mgcp_ctx, MGCP_ERR_NOMEM);
		return;
	}
	msg = mgcp_msg_gen(mgcp, &mgcp_msg);
	OSMO_ASSERT(msg);

	/* Transmit MGCP message to MGW */
	mgcp_ctx->mgw_pending_trans = mgcp_msg_trans_id(msg);
	rc = mgcp_client_tx(mgcp, msg, mgw_dlcx_all_resp_cb, mgcp_ctx);
	if (rc < 0) {
		handle_error(mgcp_ctx, MGCP_ERR_MGW_TX_FAIL);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_HALT, MGCP_MGW_TIMEOUT, MGCP_MGW_TIMEOUT_TIMER_NR);
}

/* Callback for MGCP-Client: handle response for CN associated CRCX */
static void mgw_dlcx_all_resp_cb(struct mgcp_response *r, void *priv)
{
	struct mgcp_ctx *mgcp_ctx = priv;

	OSMO_ASSERT(mgcp_ctx);

	if (r->head.response_code != 200) {
		LOGPFSML(mgcp_ctx->fsm, LOGL_ERROR,
			 "DLCX: response yields error: %d %s\n", r->head.response_code, r->head.comment);
		handle_error(mgcp_ctx, MGCP_ERR_MGW_FAIL);
		return;
	}

	/* Notify the FSM that we got the response. */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_DLCX_ALL_RESP, mgcp_ctx);
}

/* Callback for ST_HALT: Terminate the state machine */
static void fsm_halt_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mgcp_ctx *mgcp_ctx = data;

	OSMO_ASSERT(mgcp_ctx);

	LOGPFSML(fi, LOGL_DEBUG, "state machine halted\n");

	/* NOTE: We must not free the context information now, we have to
	 * wait until msc_mgcp_call_release() is called. Then we are sure
	 * that the logic controlling us is fully aware that the context
	 * information is freed. If we would free early now the controlling
	 * logic might mistakenly think that the context info is still alive,
	 * so lets keep the context info until we are explicitly asked for
	 * throwing it away. */
	if (mgcp_ctx->free_ctx) {
		osmo_fsm_inst_free(mgcp_ctx->fsm);
		talloc_free(mgcp_ctx);
		return;
	}

	osmo_fsm_inst_state_chg(fi, ST_HALT, MGCP_REL_TIMEOUT, MGCP_REL_TIMEOUT_TIMER_NR);
}

static struct osmo_fsm_state fsm_msc_mgcp_states[] = {

	/* Startup state machine, send CRCX for RAN side. */
	[ST_CRCX_RAN] = {
			 .in_event_mask = S(EV_INIT),
			 .out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_CRCX_CN),
			 .name = OSMO_STRINGIFY(ST_CRCX_RAN),
			 .action = fsm_crcx_ran_cb,
			 },
	/* When the response to the RAN CRCX is received, then proceed with
	   sending the CRCX for CN side */
	[ST_CRCX_CN] = {
			.in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_CRCX_RAN_RESP),
			.out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_CRCX_COMPL),
			.name = OSMO_STRINGIFY(ST_CRCX_CN),
			.action = fsm_crcx_cn_cb,
			},
	/* Complete the CRCX phase by starting the assignment. Depending on the
	 * RAT (Radio Access Technology) , this will either trigger an
	 * Assignment Request on the A-Interface or an RAB-Assignment on the
	 * IU-interface */
	[ST_CRCX_COMPL] = {
			   .in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_CRCX_CN_RESP),
			   .out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_MDCX_CN),
			   .name = OSMO_STRINGIFY(ST_CRCX_COMPL),
			   .action = fsm_crcx_compl,
			   },
	/* Wait for MSC to complete the assignment request, when complete, we
	 * will enter the MDCX phase by sending an MDCX for the CN side to the
	 * MGW */
	[ST_MDCX_CN] = {
			.in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_CONNECT),
			.out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_MDCX_CN_COMPL),
			.name = OSMO_STRINGIFY(ST_MDCX_CN),
			.action = fsm_mdcx_cn_cb,
			},
	/* We arrive in this state when the MDCX phase for the CN side as
	 * completed we will check the IP/Port of the RAN connection. If we
	 * this data is valid we may continue with the MDCX phase for the RAN
	 * side. If not we wait until the assinment completes on the A or on
	 * the IuCS interface. The completion of the assigmnet will fill in the
	 * port and IP-Address of the RAN side and way may continue then. */
	[ST_MDCX_CN_COMPL] = {
			      .in_event_mask = S(EV_TEARDOWN) | S(EV_MDCX_CN_RESP),
			      .out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_MDCX_RAN),
			      .name = OSMO_STRINGIFY(ST_MDCX_CN_COMPL),
			      .action = fsm_mdcx_cn_compl_cb,
			      },
	/* When the response for the CN MDCX is received, send the MDCX for the
	 * RAN side to the MGW */
	[ST_MDCX_RAN] = {
			 .in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_ASSIGN),
			 .out_state_mask = S(ST_HALT) | S(ST_CALL) | S(ST_MDCX_RAN_COMPL),
			 .name = OSMO_STRINGIFY(ST_MDCX_RAN),
			 .action = fsm_mdcx_ran_cb,
			 },
	/* The ran side MDCX phase is complete when the response is received
	 * from the MGW. The is then active and we change to ST_CALL and wait
	 * there until the call ends. */
	[ST_MDCX_RAN_COMPL] = {
			       .in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_MDCX_RAN_RESP),
			       .out_state_mask = S(ST_HALT) | S(ST_CALL),
			       .name = OSMO_STRINGIFY(ST_MDCX_RAN_COMPL),
			       .action = fsm_mdcx_ran_compl_cb,
			       },
	/* We are now in the active call phase, wait until the call is done
	 * and send a DLCX then to remove all connections from the MGW */
	[ST_CALL] = {
		     .in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR),
		     .out_state_mask = S(ST_HALT),
		     .name = OSMO_STRINGIFY(ST_CALL),
		     .action = fsm_call_cb,
		     },
	/* When the MGW confirms that the connections are terminated, then halt
	 * the state machine. */
	[ST_HALT] = {
		     .in_event_mask = S(EV_TEARDOWN) | S(EV_TEARDOWN_ERROR) | S(EV_DLCX_ALL_RESP),
		     .out_state_mask = S(ST_HALT),
		     .name = OSMO_STRINGIFY(ST_HALT),
		     .action = fsm_halt_cb,
		     },
};

/* State machine definition */
static struct osmo_fsm fsm_msc_mgcp = {
	.name = "MGW",
	.states = fsm_msc_mgcp_states,
	.num_states = ARRAY_SIZE(fsm_msc_mgcp_states),
	.log_subsys = DMGCP,
	.timer_cb = fsm_timeout_cb,
};

/* Notify that a new call begins. This will create a connection for the
 * RAN and the CN on the MGW.
 * Parameter:
 * trans: transaction context.
 * Returns -EINVAL on error, 0 on success. */
int msc_mgcp_call_assignment(struct gsm_trans *trans)
{
	struct mgcp_ctx *mgcp_ctx;
	char name[32];
	static bool fsm_registered = false;
	struct gsm_subscriber_connection *conn;
	struct mgcp_client *mgcp;

	OSMO_ASSERT(trans);

	if (!trans->conn) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid conn, call assignment failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}

	conn = trans->conn;
	mgcp = conn->network->mgw.client;
	OSMO_ASSERT(mgcp);

	if (conn->rtp.mgcp_ctx) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) double assignment detected, dropping...\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}

#ifdef BUILD_IU
	/* FIXME: HACK. where to scope the RAB Id? At the conn / subscriber / ranap_ue_conn_ctx? */
	static uint8_t next_iu_rab_id = 1;
	if (conn->via_ran == RAN_UTRAN_IU)
		conn->iu.rab_id = next_iu_rab_id++;
#endif

	if (snprintf(name, sizeof(name), "MGW_%i", trans->transaction_id) >= sizeof(name))
		return -EINVAL;

	/* Register the fsm description (if not already done) */
	if (fsm_registered == false) {
		osmo_fsm_register(&fsm_msc_mgcp);
		fsm_registered = true;
	}

	/* Allocate and configure a new fsm instance */
	mgcp_ctx = talloc_zero(NULL, struct mgcp_ctx);
	OSMO_ASSERT(mgcp_ctx);

	mgcp_ctx->fsm = osmo_fsm_inst_alloc(&fsm_msc_mgcp, NULL, NULL, LOGL_DEBUG, name);
	OSMO_ASSERT(mgcp_ctx->fsm);
	mgcp_ctx->fsm->priv = mgcp_ctx;
	mgcp_ctx->mgcp = mgcp;
	mgcp_ctx->trans = trans;

	/* start state machine */
	OSMO_ASSERT(mgcp_ctx->fsm->state == ST_CRCX_RAN);
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_INIT, mgcp_ctx);

	conn->rtp.mgcp_ctx = mgcp_ctx;

	LOGP(DMGCP, LOGL_DEBUG, "(subscriber:%s) call assignment initiated\n",
	     vlr_subscr_name(conn->vsub));

	return 0;
}

/* Inform the FSM that the assignment (RAN connection) is now complete.
 * Parameter:
 * conn: subscriber connection context.
 * port: port number of the remote leg.
 * addr: IP-address of the remote leg.
 * Returns -EINVAL on error, 0 on success. */
int msc_mgcp_ass_complete(struct gsm_subscriber_connection *conn, uint16_t port, char *addr)
{
	struct mgcp_ctx *mgcp_ctx;

	if (port == 0) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid remote call leg port, call completion failed\n",
		     vlr_subscr_name(conn->vsub));
		return -EINVAL;
	}
	if (!addr || strlen(addr) <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) missing remote call leg address, call completion failed\n",
		     vlr_subscr_name(conn->vsub));
		return -EINVAL;
	}
	if (!conn) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid conn, assignment completion failed\n",
		     vlr_subscr_name(conn->vsub));
		return -EINVAL;
	}

	mgcp_ctx = conn->rtp.mgcp_ctx;
	if (!mgcp_ctx) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid mgcp context, assignmnet completion failed.\n",
		     vlr_subscr_name(conn->vsub));
		return -EINVAL;
	}

	/* Memorize port and IP-Address of the remote RAN call leg. We need this
	 * information at latest when we enter the MDCX phase for the RAN side. */
	conn->rtp.remote_port_ran = port;
	osmo_strlcpy(conn->rtp.remote_addr_ran, addr, sizeof(conn->rtp.remote_addr_ran));

	/* Note: We only dispatch the event if we are really waiting for the
	 * assignment, if we are not yet waiting, there is no need to loudly
	 * broadcast an event that the all other states do not understand anyway */
	if (mgcp_ctx->fsm->state == ST_MDCX_RAN)
		osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_ASSIGN, mgcp_ctx);

	return 0;
}

/* Make the connection of a previously assigned call complete
 * Parameter:
 * trans: transaction context.
 * port: port number of the remote leg.
 * addr: IP-address of the remote leg.
 * Returns -EINVAL on error, 0 on success. */
int msc_mgcp_call_complete(struct gsm_trans *trans, uint16_t port, char *addr)
{
	struct mgcp_ctx *mgcp_ctx;
	struct gsm_subscriber_connection *conn;

	OSMO_ASSERT(trans);
	OSMO_ASSERT(addr);

	if (port == 0) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid remote call leg port, call completion failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!addr || strlen(addr) <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) missing remote call leg address, call completion failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!trans->conn) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid conn, call completion failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!trans->conn->rtp.mgcp_ctx) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid mgcp context, call completion failed.\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!trans->conn->rtp.mgcp_ctx->fsm) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) no FSM, call completion failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}

	mgcp_ctx = trans->conn->rtp.mgcp_ctx;

	/* The FSM should already have passed all CRCX phases and be ready to move
	 * on with the MDCX phases. */
	if (mgcp_ctx->fsm->state != ST_MDCX_CN) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid call state, call completion failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}

	conn = trans->conn;
	osmo_strlcpy(conn->rtp.remote_addr_cn, addr, sizeof(conn->rtp.remote_addr_cn));
	conn->rtp.remote_port_cn = port;

	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_CONNECT, mgcp_ctx);

	LOGP(DMGCP, LOGL_DEBUG, "(subscriber:%s) call completion initiated\n",
	     vlr_subscr_name(conn->vsub));

	return 0;
}

/* Release ongoing call.
 * Parameter:
 * trans: connection context.
 * Returns -EINVAL on error, 0 on success. */
int msc_mgcp_call_release(struct gsm_trans *trans)
{
	struct mgcp_ctx *mgcp_ctx;

	if (!trans->conn) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid conn, call release failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!trans->conn->rtp.mgcp_ctx) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) invalid mgcp context, call release failed.\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}
	if (!trans->conn->rtp.mgcp_ctx->fsm) {
		LOGP(DMGCP, LOGL_ERROR, "(subscriber:%s) no FSM, call release failed\n",
		     vlr_subscr_name(trans->vsub));
		return -EINVAL;
	}

	mgcp_ctx = trans->conn->rtp.mgcp_ctx;

	/* Inform the FSM that as soon as it reaches ST_HALT it may free
	 * all context information immediately */
	mgcp_ctx->free_ctx = true;

	/* Initaite teardown, regardless of which state we are currently
	 * in */
	osmo_fsm_inst_dispatch(mgcp_ctx->fsm, EV_TEARDOWN, mgcp_ctx);

	/* Prevent any further operation that is triggered from outside by
	 * overwriting the context pointer with NULL. The FSM will now
	 * take care for a graceful shutdown and when done it will free
	 * all related context information */
	trans->conn->rtp.mgcp_ctx = NULL;

	LOGP(DMGCP, LOGL_DEBUG, "(subscriber:%s) call release initiated\n",
	     vlr_subscr_name(trans->vsub));

	return 0;
}
