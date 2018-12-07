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
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/paging.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/silent_call.h>

#include <osmocom/sigtran/sccp_helpers.h>

/* paging of the requested subscriber has completed */
void paging_cb_silent(struct msc_a *msc_a, struct gsm_trans *trans)
{
	struct scall_signal_data sigdata = {
		.msc_a = msc_a,
		.vty = trans->silent_call.from_vty,
	};
	struct ran_msg assignment;

	if (!msc_a) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Silent call: MS not responding to Paging\n");
		osmo_signal_dispatch(SS_SCALL, S_SCALL_FAILED, &sigdata);
		trans_free(trans);
		return;
	}

	LOG_MSC_A(msc_a, LOGL_INFO, "Silent call: MS responding to Paging\n");

	trans->msc_a = msc_a;
	msc_a_get(msc_a, MSC_A_USE_SILENT_CALL);

	osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_TRANSACTION_ACCEPTED, trans);

	assignment = (struct ran_msg){
		.msg_type = RAN_MSG_ASSIGNMENT_COMMAND,
		.assignment_command = {
			.channel_type = &trans->silent_call.ct,
			.cn_rtp = &trans->silent_call.rtp_cn,
		},
	};
	if (msc_a_ran_down(msc_a, MSC_ROLE_I, &assignment)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Silent call failed\n");
		osmo_signal_dispatch(SS_SCALL, S_SCALL_FAILED, &sigdata);
		trans_free(trans);
	} else {
		osmo_signal_dispatch(SS_SCALL, S_SCALL_SUCCESS, &sigdata);
	}
}

void trans_silent_call_free(struct gsm_trans *trans)
{
	struct scall_signal_data sigdata = {
		.msc_a = trans->msc_a,
		.vty = trans->silent_call.from_vty,
	};
	osmo_signal_dispatch(SS_SCALL, S_SCALL_DETACHED, &sigdata);
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
	struct vty *vty)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	struct gsm_trans *trans = trans_alloc(net, vsub, TRANS_SILENT_CALL, 0, 0);

	trans->silent_call.ct = *ct;
	if (traffic_dst_ip) {
		osmo_sockaddr_str_from_str(&trans->silent_call.rtp_cn, traffic_dst_ip, traffic_dst_port);
	}
	trans->silent_call.from_vty = vty;

	if (!paging_request_start(vsub, PAGING_CAUSE_CALL_BACKGROUND, paging_cb_silent, trans,
				  "establish silent call")) {
		trans_free(trans);
		return -ENODEV;
	}

	return 0;
}

/* end a silent call with a given subscriber */
int gsm_silent_call_stop(struct vlr_subscr *vsub)
{
	struct msc_a *msc_a = msc_a_for_vsub(vsub, true);
	struct gsm_trans *trans;
	if (!msc_a) {
		LOGP(DMM, LOGL_ERROR, "%s: Cannot stop silent call, no connection for subscriber\n",
		     vlr_subscr_name(vsub));
		return -ENODEV;
	}

	/* did we actually establish a silent call for this guy? */
	trans = trans_find_by_type(msc_a, TRANS_SILENT_CALL);
	if (!trans) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Cannot stop silent call, subscriber has no active silent call\n");
		return -ENOENT;
	}

	trans_free(trans);
	return 0;
}
