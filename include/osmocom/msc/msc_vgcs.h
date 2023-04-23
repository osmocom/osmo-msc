/* Handle a call via VGCS/VBCS (Voice Group/Broadcast Call Service). */
/*
 * (C) 2023 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Andreas Eversberg
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

#include <osmocom/msc/transaction.h>

#define GSM44068_ALLOC_SIZE        2048
#define GSM44068_ALLOC_HEADROOM    256

static inline struct msgb *gsm44068_msgb_alloc_name(const char *name)
{
	return msgb_alloc_headroom(GSM44068_ALLOC_SIZE, GSM44068_ALLOC_HEADROOM, name);
}

/* VGCS/VBS "call control" connection to each BSS */
struct vgcs_bss {
	struct llist_head list;		/* List entry */
	struct llist_head cell_list;	/* List of cells */
	struct gsm_trans *trans;	/* Back pointer to transaction */
	struct osmo_fsm_inst *fi;	/* State machine of each BSS */
	struct ran_conn *conn;		/* RAN ("SCCP") connection */
	enum trans_type trans_type;	/* Transaction type */
	uint32_t callref;		/* Callref */
	int pc;				/* Point code for debug purpose */
};

/* VGCS/VBS "resource control" connection to each cell in BSS */
struct vgcs_bss_cell {
	struct llist_head list_bss;	/* List entry in vgcs_bss */
	struct llist_head list_mgw;	/* List entry in MGW endpoint */
	struct vgcs_bss *bss;		/* Back pointer to vgcs_bss */
	struct vgcs_mgw_ep *mgw;	/* Back pointer to vgcs_mgw_ep */
	struct osmo_fsm_inst *fi;	/* State machine of each cell */
	int cell_id;			/* Id of cell (BTS) to use */
	struct ran_conn *conn;		/* RAN ("SCCP") connection */
	enum trans_type trans_type;	/* Transaction type */
	uint32_t callref;		/* Callref */
	int call_id;			/* Id of call (used for MGW connections) */
	int pc;				/* Point code for debug purpose */
	bool assigned;			/* Flags if assignment is complete */
	struct rtp_stream *rtps;	/* MGW connection process */
};

/* VGCS/VBS MGW endpoint for each call */
struct vgcs_mgw_ep {
	struct llist_head cell_list;	/* List of cells with connections */
	struct llist_head list;		/* List entry */
	struct osmo_fsm_inst *fi;	/* State machine of each cell */
	struct osmo_mgcpc_ep *mgw_ep;	/* MGW endpoint */
};

/* Events for the GCC/BCC state machine.
 * There is no primitive definition like MNGCC-* oder MNBCC-* in the standard. */
enum vgcs_gcc_fsm_event {
	/* The network sets up a call. */
	VGCS_GCC_EV_NET_SETUP,
	/* The network requests termination. */
	VGCS_GCC_EV_NET_TERM,
	/* The user sets up a call. */
	VGCS_GCC_EV_USER_SETUP,
	/* The user requests termination. */
	VGCS_GCC_EV_USER_TERM,
	/* BSS completed call establishment (all BSCs) */
	VGCS_GCC_EV_BSS_ESTABLISHED,
	/* Assignment was completed. */
	VGCS_GCC_EV_BSS_ASSIGN_CPL,
	/* Assignment failed. */
	VGCS_GCC_EV_BSS_ASSIGN_FAIL,
	/* BSS released call establishment (all BSCs) */
	VGCS_GCC_EV_BSS_RELEASED,
	/* Inactivity timeout */
	VGCS_GCC_EV_TIMEOUT,
};

/* 3GPP TS 44.068 6.1.2.2 States of GCC/BCC */
enum vgcs_gcc_fsm_state {
	/* No call. Initial state when instance is created. */
	VGCS_GCC_ST_N0_NULL = 0,
	/* An MS wants to establish a call. */
	VGCS_GCC_ST_N1_CALL_INITIATED,
	/* Call established in at least one cell. */
	VGCS_GCC_ST_N2_CALL_ACTIVE,
	/* Channel activation is requested, CONNECT already sent to MS. */
	VGCS_GCC_ST_N3_CALL_EST_PROC,
	/* Call termination is requested, waiting for all cells to confirm. */
	VGCS_GCC_ST_N4_TERMINATION_REQ,
};

const char *vgcs_bcc_gcc_state_name(struct osmo_fsm_inst *fi);

/* Events for the VGCS/VBS "call control" state machine */
enum vgcs_bss_fsm_event {
	/* Start a VGCS/VBS call using VGCS/VBS SETUP message */
	VGCS_BSS_EV_SETUP,
	/* VGCS/VBS SETUP ACK is received */
	VGCS_BSS_EV_SETUP_ACK,
	/* VGCS/VBS SETUP REFUSE is received */
	VGCS_BSS_EV_SETUP_REFUSE,
	/* VGCS/VBS ASSIGNMENT complete or failed */
	VGCS_BSS_EV_ACTIVE_OR_FAIL,
	/* Talker request */
	VGCS_BSS_EV_UL_REQUEST,
	/* Talker established uplink */
	VGCS_BSS_EV_UL_REQUEST_CNF,
	/* Talker send app data */
	VGCS_BSS_EV_UL_APP_DATA,
	/* Talker send signaling data */
	VGCS_BSS_EV_BSS_DTAP,
	/* Talker becomes listener */
	VGCS_BSS_EV_UL_RELEASE,
	/* Release channel towards BSS */
	VGCS_BSS_EV_CLEAR,
	/* Channel closed from BSS */
	VGCS_BSS_EV_CLOSE,
	/* Release is complete */
	VGCS_BSS_EV_RELEASED,
};

/* States of the VGCS/VBS "call control" state machine */
enum vgcs_bss_fsm_state {
	/* No call. Initial state when instance is created. */
	VGCS_BSS_ST_NULL = 0,
	/* VGCS/VBS SETUP is sent towards BSC */
	VGCS_BSS_ST_SETUP,
	/* VGCS/VBS ASSIGNMENT REQUEST is sent towards BSC */
	VGCS_BSS_ST_ASSIGNMENT,
	/* VGCS/VBS is establised */
	VGCS_BSS_ST_ACTIVE,
	/* CLEAR COMMAND was sent */
	VGCS_BSS_ST_RELEASE,
};

/* Events for the VGCS/VBS "resource control" state machine */
enum vgcs_cell_fsm_event {
	/* RTP stream gone */
	VGCS_CELL_EV_RTP_STREAM_GONE,
	/* RTP stream remote addr available */
	VGCS_CELL_EV_RTP_STREAM_ADDR_AVAILABLE,
	/* RTP stream established */
	VGCS_CELL_EV_RTP_STREAM_ESTABLISHED,
	/* Start a VGCS/VBS channel using VGCS/VBS ASSIGNMENT message */
	VGCS_CELL_EV_ASSIGN,
	/* VGCS/VBS ASSIGNMENT RESULT is received */
	VGCS_CELL_EV_ASSIGN_RES,
	/* VGCS/VBS ASSIGNMENT FAILURE is received */
	VGCS_CELL_EV_ASSIGN_FAIL,
	/* Release channel towards BSS */
	VGCS_CELL_EV_CLEAR,
	/* Channel closed from BSS */
	VGCS_CELL_EV_CLOSE,
	/* Release is complete */
	VGCS_CELL_EV_RELEASED,
};

/* States of the VGCS/VBS "resource control" state machine */
enum vgcs_cell_fsm_state {
	/* No call. Initial state when instance is created. */
	VGCS_CELL_ST_NULL = 0,
	/* VGCS/VBS ASSIGNMENT REQUEST is sent towards BSC */
	VGCS_CELL_ST_ASSIGNMENT,
	/* Channel is establised */
	VGCS_CELL_ST_ACTIVE,
	/* CLEAR COMMAND was sent */
	VGCS_CELL_ST_RELEASE,
};

/* Events for the VGCS/VBS MGW endpoint state machine */
enum vgcs_mgw_ep_fsm_event {
	/* MGW endpoint gone */
	VGCS_MGW_EP_EV_FREE,
	/* Destroy MGW endpoint */
	VGCS_MGW_EP_EV_CLEAR,
};

/* States of the VGCS/VBS MGW endpoint state machine */
enum vgcs_mgw_ep_fsm_state {
	VGCS_MGW_EP_ST_NULL = 0,
	/* MGW endpoint allocated */
	VGCS_MGW_EP_ST_ACTIVE,
};

const char *gsm44068_group_id_string(uint32_t callref);

struct gcr;

int gsm44068_rcv_rr(struct msc_a *msc_a, struct msgb *msg);
int gsm44068_rcv_bcc_gcc(struct msc_a *msc_a, struct gsm_trans *trans, struct msgb *msg);
const char *vgcs_vty_initiate(struct gsm_network *gsmnet, struct gcr *gcr);
const char *vgcs_vty_terminate(struct gsm_network *gsmnet, struct gcr *gcr);
void gsm44068_bcc_gcc_trans_free(struct gsm_trans *trans);

void vgcs_vbs_setup_ack(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_vbs_setup_refuse(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_vbs_assign_result(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg);
void vgcs_vbs_assign_fail(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg);
void vgcs_vbs_queuing_ind(struct vgcs_bss_cell *cell);
void vgcs_uplink_request(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_uplink_request_cnf(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_app_data(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_bss_dtap(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_uplink_release_ind(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_vbs_assign_status(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg);
void vgcs_vbs_clear_req_channel(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg);
void vgcs_vbs_clear_cpl_channel(struct vgcs_bss_cell *cell, const struct ran_msg *ran_msg);
void vgcs_vbs_clear_req(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_vbs_clear_cpl(struct vgcs_bss *bss, const struct ran_msg *ran_msg);
void vgcs_vbs_caller_assign_cpl(struct gsm_trans *trans);
void vgcs_vbs_caller_assign_fail(struct gsm_trans *trans);
