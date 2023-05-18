/* Handle an MNCC managed call (external MNCC). */
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
#pragma once

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/mncc_call.h>

struct osmo_fsm_inst;
struct rtp_stream;

#define LOG_MNCC_CALL(MNCC, LEVEL, FMT, ARGS...) \
	LOGPFSML((MNCC) ? (MNCC)->fi : NULL, LEVEL, FMT, ##ARGS)

enum mncc_call_fsm_event {
	/* An MNCC message was received from the MNCC socket. The data argument is a const union mncc_msg* pointing at
	 * the message contents. */
	MNCC_CALL_EV_RX_MNCC_MSG,

	/* The user has invoked mncc_call_outgoing_start(); this event exists to ensure that the FSM is in a state that
	 * allows starting a new outgoing call. */
	MNCC_CALL_EV_OUTGOING_START,
	/* The MNCC server has sent an MNCC_ALERT_REQ. */
	MNCC_CALL_EV_OUTGOING_ALERTING,
	/* The MNCC server has confirmed call setup with an MNCC_SETUP_RSP, we have sent an MNCC_SETUP_COMPL_IND. */
	MNCC_CALL_EV_OUTGOING_SETUP_COMPLETE,

	/* The user has invoked mncc_call_incoming_start(); this event exists to ensure that the FSM is in a state that
	 * allows starting a new incoming call. */
	MNCC_CALL_EV_INCOMING_START,
	/* MNCC server sent an MNCC_SETUP_REQ */
	MNCC_CALL_EV_INCOMING_SETUP,
	/* MNCC server confirmed call setup with an MNCC_SETUP_COMPL_REQ */
	MNCC_CALL_EV_INCOMING_SETUP_COMPLETE,

	/* MNCC server requests call release (Rx MNCC_DISC_REQ) */
	MNCC_CALL_EV_CN_RELEASE,
	/* osmo-msc should request call release (Tx MNCC_DISC_IND) */
	MNCC_CALL_EV_MS_RELEASE,
};

/* The typical progression of outgoing and incoming calls via MNCC is shown by doc/sequence_charts/mncc_call_fsm.msc */
enum mncc_call_fsm_state {
	MNCC_CALL_ST_NOT_STARTED = 0,

	MNCC_CALL_ST_OUTGOING_WAIT_PROCEEDING,
	MNCC_CALL_ST_OUTGOING_WAIT_COMPLETE,

	MNCC_CALL_ST_INCOMING_WAIT_COMPLETE,

	MNCC_CALL_ST_TALKING,

	MNCC_CALL_ST_WAIT_RELEASE_ACK,
};

struct mncc_call_incoming_req {
	bool bearer_cap_present;
	struct gsm_mncc_bearer_cap bearer_cap;

	bool cccap_present;
	struct gsm_mncc_cccap cccap;

	struct gsm_mncc setup_req_msg;
};

struct mncc_call;
typedef void (* mncc_call_message_cb_t )(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg, void *data);

struct mncc_call {
	struct llist_head entry;

	struct osmo_fsm_inst *fi;
	struct vlr_subscr *vsub;
	struct gsm_network *net;

	/* Details originally passed to mncc_call_outgoing_start(), if any. */
	struct gsm_mncc outgoing_req;

	uint32_t callref;
	bool remote_msisdn_present;
	struct gsm_mncc_number remote_msisdn;
	bool local_msisdn_present;
	struct gsm_mncc_number local_msisdn;
	struct rtp_stream *rtps;
	bool received_rtp_create;

	mncc_call_message_cb_t message_cb;
	void *forward_cb_data;

	/* Event to dispatch to the FSM inst parent when the call is complete. Omit event dispatch when negative. See
	 * mncc_call_alloc()'s arg of same name. */
	int parent_event_call_setup_complete;
};

void mncc_call_fsm_init(struct gsm_network *net);
struct mncc_call *mncc_call_alloc(struct vlr_subscr *vsub,
				  struct osmo_fsm_inst *parent,
				  int parent_event_call_setup_complete,
				  uint32_t parent_event_call_released,
				  mncc_call_message_cb_t message_cb, void *forward_cb_data);
void mncc_call_reparent(struct mncc_call *mncc_call,
			struct osmo_fsm_inst *new_parent,
			int parent_event_call_setup_complete,
			uint32_t parent_event_call_released,
			mncc_call_message_cb_t message_cb, void *forward_cb_data);

int mncc_call_outgoing_start(struct mncc_call *mncc_call, const struct gsm_mncc *outgoing_req);

int mncc_call_incoming_start(struct mncc_call *mncc_call, const struct mncc_call_incoming_req *incoming_req);
int mncc_call_incoming_tx_setup_cnf(struct mncc_call *mncc_call, const struct gsm_mncc_number *connected_number);

int mncc_call_set_rtp_stream(struct mncc_call *mncc_call, struct rtp_stream *rtps);
void mncc_call_detach_rtp_stream(struct mncc_call *mncc_call);

void mncc_call_rx(struct mncc_call *mncc_call, const union mncc_msg *mncc_msg);
int mncc_call_tx(struct mncc_call *mncc_call, union mncc_msg *mncc_msg);
int mncc_call_tx_msgt(struct mncc_call *mncc_call, uint32_t msg_type);

struct mncc_call *mncc_call_find_by_callref(uint32_t callref);

void mncc_call_release(struct mncc_call *mncc_call);

uint32_t mgcp_codec_to_mncc_payload_msg_type(enum mgcp_codecs codec);
