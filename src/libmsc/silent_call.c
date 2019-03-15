/* GSM silent call feature */

/*
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/vlr.h>

#include <osmocom/sigtran/sccp_helpers.h>

struct silent_call_data {
	struct gsm0808_channel_type ct;

	char traffic_ip[INET_ADDRSTRLEN];
	uint16_t traffic_port;

	void *data;

	struct osmo_timer_list timer;
	struct ran_conn *conn;
};

static void timer_cb(void *data)
{
	struct silent_call_data *scd = (struct silent_call_data *)data;
	ran_conn_communicating(scd->conn);
	talloc_free(scd);
}

/* paging of the requested subscriber has completed */
static int paging_cb_silent(unsigned int hooknum, unsigned int event,
			    struct msgb *msg, void *_conn, void *_data)
{
	struct silent_call_data *scd = (struct silent_call_data *)_data;
	struct ran_conn *conn = _conn;
	struct scall_signal_data sigdata;
	struct msgb *msg_ass;
	int rc = 0;
	int i;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	DEBUGP(DLSMS, "paging_cb_silent: ");

	sigdata.conn = conn;
	sigdata.data = scd->data;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
#if BEFORE_MSCSPLIT
		/* Re-enable this log output once we can obtain this information via
		 * A-interface, see OS#2391. */
		DEBUGPC(DLSMS, "success, using Timeslot %u on ARFCN %u\n",
			conn->lchan->ts->nr, conn->lchan->ts->trx->arfcn);
#endif
		conn->silent_call = 1;

		/* Increment lchan reference count and mark as active*/
		ran_conn_get(conn, RAN_CONN_USE_SILENT_CALL);

		/* Schedule a timer to mark it as active */
			/* This is a hack we we can't call ran_conn_communicating
			 * from here because we're in the call back context of
			 * a RAN FSM event but before it actually changes its own
			 * state and it's not ready to accept this.
			 * Of all alternatives considered, making the call in an
			 * 'immediate timer' is the least disruptive and least ugly
			 * way to do it I could find.
			 */
		scd->conn = conn;
		osmo_timer_setup(&scd->timer, timer_cb, scd);
		osmo_timer_schedule(&scd->timer, 0, 0);

		/* Manually craft an assignement message with requested mode */
		if (scd->ct.ch_indctr == GSM0808_CHAN_SPEECH) {
			struct gsm0808_speech_codec_list scl;
			union {
				struct sockaddr_storage st;
				struct sockaddr_in in;
			} rtp_addr;

			memset(&rtp_addr, 0, sizeof(rtp_addr));
			rtp_addr.in.sin_family = AF_INET;
			rtp_addr.in.sin_port = osmo_htons(scd->traffic_port);
			rtp_addr.in.sin_addr.s_addr = inet_addr(scd->traffic_ip);

			for (i = 0; i < scd->ct.perm_spch_len; i++)
				gsm0808_speech_codec_from_chan_type(&scl.codec[i], scd->ct.perm_spch[i]);
			scl.len = scd->ct.perm_spch_len;

			msg_ass = gsm0808_create_ass(&scd->ct, NULL, &rtp_addr.st, &scl, NULL);
		} else {
			msg_ass = gsm0808_create_ass(&scd->ct, NULL, NULL, NULL, NULL);
		}

		/* Send assignement message, hoping it will work */
		osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_ass);

		/* Signal completion */
		osmo_signal_dispatch(SS_SCALL, S_SCALL_SUCCESS, &sigdata);
		return 0;

	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_BUSY:
		DEBUGP(DLSMS, "expired\n");
		osmo_signal_dispatch(SS_SCALL, S_SCALL_EXPIRED, &sigdata);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	talloc_free(scd);

	return rc;
}

#if 0
/* receive a layer 3 message from a silent call */
int silent_call_rx(struct ran_conn *conn, struct msgb *msg)
{
	/* FIXME: do something like sending it through a UDP port */
	LOGP(DLSMS, LOGL_NOTICE, "Discarding L3 message from a silent call.\n");
	return 0;
}

struct msg_match {
	uint8_t pdisc;
	uint8_t msg_type;
};

/* list of messages that are handled inside OpenBSC, even in a silent call */
static const struct msg_match silent_call_accept[] = {
	{ GSM48_PDISC_MM, GSM48_MT_MM_LOC_UPD_REQUEST },
	{ GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_REQ },
};

/* decide if we need to reroute a message as part of a silent call */
int silent_call_reroute(struct ran_conn *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	int i;

	/* if we're not part of a silent call, never reroute */
	if (!conn->silent_call)
		return 0;

	/* check if we are a special message that is handled in openbsc */
	for (i = 0; i < ARRAY_SIZE(silent_call_accept); i++) {
		if (silent_call_accept[i].pdisc == pdisc &&
		    silent_call_accept[i].msg_type == msg_type)
			return 0;
	}

	/* otherwise, reroute */
	LOGP(DLSMS, LOGL_INFO, "Rerouting L3 message from a silent call.\n");
	return 1;
}
#endif


/* initiate a silent call with a given subscriber */
int gsm_silent_call_start(struct vlr_subscr *vsub,
	const struct gsm0808_channel_type *ct,
	const char *traffic_dst_ip, uint16_t traffic_dst_port,
	void *data)
{
	struct subscr_request *req;
	struct silent_call_data *scd;

	scd = talloc_zero(vsub, struct silent_call_data);

	memcpy(&scd->ct, ct, sizeof(scd->ct));

	if (traffic_dst_ip) {
		osmo_strlcpy(scd->traffic_ip, traffic_dst_ip, sizeof(scd->traffic_ip));
		scd->traffic_port = traffic_dst_port;
	}

	scd->data = data;

	req = subscr_request_conn(vsub, paging_cb_silent, scd,
				  "establish silent call",
				  SGSAP_SERV_IND_CS_CALL);
	if (!req) {
		talloc_free(scd);
		return -ENODEV;
	}

	return 0;
}

/* end a silent call with a given subscriber */
int gsm_silent_call_stop(struct vlr_subscr *vsub)
{
	struct ran_conn *conn;

	conn = connection_for_subscr(vsub);
	if (!conn) {
		LOGP(DMM, LOGL_ERROR, "%s: Cannot stop silent call, no connection for subscriber\n",
		     vlr_subscr_name(vsub));
		return -ENODEV;
	}

	/* did we actually establish a silent call for this guy? */
	if (!conn->silent_call) {
		LOGP(DMM, LOGL_ERROR, "%s: Cannot stop silent call, subscriber has no active silent call\n",
		     vlr_subscr_name(vsub));
		return -ENOENT;
	}

#if BEFORE_MSCSPLIT
	/* Re-enable this log output once we can obtain this information via
	 * A-interface, see OS#2391. */
	DEBUGPC(DLSMS, "Stopping silent call using Timeslot %u on ARFCN %u\n",
		conn->lchan->ts->nr, conn->lchan->ts->trx->arfcn);
#endif

	conn->silent_call = 0;
	ran_conn_put(conn, RAN_CONN_USE_SILENT_CALL);

	return 0;
}
