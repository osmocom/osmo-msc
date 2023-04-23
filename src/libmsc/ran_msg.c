/* Common bits for RAN message handling */
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

#include <osmocom/core/utils.h>

#include <osmocom/msc/ran_msg.h>

const struct value_string ran_msg_type_names[] = {
	{ RAN_MSG_NONE, "NONE" },
	{ RAN_MSG_COMPL_L3, "COMPL_L3" },
	{ RAN_MSG_DTAP, "DTAP" },
	{ RAN_MSG_CLEAR_COMMAND, "CLEAR_COMMAND" },
	{ RAN_MSG_CLEAR_REQUEST, "CLEAR_REQUEST" },
	{ RAN_MSG_CLEAR_COMPLETE, "CLEAR_COMPLETE" },
	{ RAN_MSG_CLASSMARK_REQUEST, "CLASSMARK_REQUEST" },
	{ RAN_MSG_CLASSMARK_UPDATE, "CLASSMARK_UPDATE" },
	{ RAN_MSG_CIPHER_MODE_COMMAND, "CIPHER_MODE_COMMAND" },
	{ RAN_MSG_CIPHER_MODE_COMPLETE, "CIPHER_MODE_COMPLETE" },
	{ RAN_MSG_CIPHER_MODE_REJECT, "CIPHER_MODE_REJECT" },
	{ RAN_MSG_COMMON_ID, "COMMON_ID" },
	{ RAN_MSG_ASSIGNMENT_COMMAND, "ASSIGNMENT_COMMAND" },
	{ RAN_MSG_ASSIGNMENT_COMPLETE, "ASSIGNMENT_COMPLETE" },
	{ RAN_MSG_ASSIGNMENT_FAILURE, "ASSIGNMENT_FAILURE" },
	{ RAN_MSG_SAPI_N_REJECT, "SAPI_N_REJECT" },
	{ RAN_MSG_LCLS_STATUS, "LCLS_STATUS" },
	{ RAN_MSG_LCLS_BREAK_REQ, "LCLS_BREAK_REQ" },
	{ RAN_MSG_HANDOVER_COMMAND, "HANDOVER_COMMAND" },
	{ RAN_MSG_HANDOVER_SUCCEEDED, "HANDOVER_SUCCEEDED" },
	{ RAN_MSG_HANDOVER_PERFORMED, "HANDOVER_PERFORMED" },
	{ RAN_MSG_HANDOVER_REQUIRED, "HANDOVER_REQUIRED" },
	{ RAN_MSG_HANDOVER_REQUIRED_REJECT, "HANDOVER_REQUIRED_REJECT" },
	{ RAN_MSG_HANDOVER_REQUEST, "HANDOVER_REQUEST" },
	{ RAN_MSG_HANDOVER_REQUEST_ACK, "HANDOVER_REQUEST_ACK" },
	{ RAN_MSG_HANDOVER_DETECT, "HANDOVER_DETECT" },
	{ RAN_MSG_HANDOVER_COMPLETE, "HANDOVER_COMPLETE" },
	{ RAN_MSG_HANDOVER_FAILURE, "HANDOVER_FAILURE" },
	{ RAN_MSG_VGCS_VBS_SETUP, "VGCS_VBS_SETUP" },
	{ RAN_MSG_VGCS_VBS_SETUP_ACK, "VGCS_VBS_SETUP_ACK" },
	{ RAN_MSG_VGCS_VBS_SETUP_REFUSE, "VGCS_VBS_SETUP_REFUSE" },
	{ RAN_MSG_VGCS_VBS_ASSIGN_REQ, "VGCS_VBS_ASSIGN_REQ" },
	{ RAN_MSG_VGCS_VBS_ASSIGN_RES, "VGCS_VBS_ASSIGN_RES" },
	{ RAN_MSG_VGCS_VBS_ASSIGN_FAIL, "VGCS_VBS_ASSIGN_FAIL" },
	{ RAN_MSG_VGCS_VBS_QUEUING_IND, "VGCS_VBS_QUEUING_IND" },
	{ RAN_MSG_UPLINK_REQUEST, "UPLINK_REQUEST" },
	{ RAN_MSG_UPLINK_REQUEST_ACK, "UPLINK_REQUEST_ACK" },
	{ RAN_MSG_UPLINK_REQUEST_CNF, "UPLINK_REQUEST_CNF" },
	{ RAN_MSG_UPLINK_APPLICATION_DATA, "UPLINK_APPLICATION_DATA" },
	{ RAN_MSG_UPLINK_RELEASE_IND, "UPLINK_RELEASE_IND" },
	{ RAN_MSG_UPLINK_REJECT_CMD, "UPLINK_REJECT_CMD" },
	{ RAN_MSG_UPLINK_RELEASE_CMD, "UPLINK_RELEASE_CMD" },
	{ RAN_MSG_UPLINK_SEIZED_CMD, "UPLINK_SEIZED_CMD" },
	{ RAN_MSG_VGCS_ADDITIONAL_INFO, "VGCS_ADDITIONAL_INFO" },
	{ RAN_MSG_VGCS_VBS_AREA_CELL_INFO, "VGCS_VBS_AREA_CELL_INFO" },
	{ RAN_MSG_VGCS_VBS_ASSIGN_STATUS, "VGCS_VBS_ASSIGN_STATUS" },
	{ RAN_MSG_VGCS_SMS, "VGCS_SMS" },
	{}
};

/* extract the N(SD) and return the modulo value for a R99 message */
static uint8_t ran_dec_dtap_undup_determine_nsd_ret_modulo_r99(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		*n_sd = (msg_type >> 6) & 0x3;
		return 4;
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* extract the N(SD) and return the modulo value for a R98 message */
static uint8_t gsm0407_determine_nsd_ret_modulo_r98(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* TS 24.007 11.2.3.2.3 Message Type Octet / Duplicate Detection.
 * (Not static for unit testing). */
int ran_dec_dtap_undup_pdisc_ctr_bin(uint8_t pdisc)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		return 0;
	case GSM48_PDISC_GROUP_CC:
		return 1;
	case GSM48_PDISC_BCAST_CC:
		return 2;
	case GSM48_PDISC_LOC:
		return 3;
	default:
		return -1;
	}
}

/* TS 24.007 11.2.3.2 Message Type Octet / Duplicate Detection */
bool ran_dec_dtap_undup_is_duplicate(struct osmo_fsm_inst *log_fi, uint8_t *n_sd_next, bool is_r99, struct msgb *l3)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t n_sd, modulo;
	int bin;

	gh = msgb_l3(l3);
	pdisc = gsm48_hdr_pdisc(gh);

	if (is_r99) {
		modulo = ran_dec_dtap_undup_determine_nsd_ret_modulo_r99(pdisc, gh->msg_type, &n_sd);
	} else { /* pre R99 */
		modulo = gsm0407_determine_nsd_ret_modulo_r98(pdisc, gh->msg_type, &n_sd);
	}
	if (modulo == 0)
		return false;
	bin = ran_dec_dtap_undup_pdisc_ctr_bin(pdisc);
	if (bin < 0)
		return false;

	OSMO_ASSERT(bin >= 0 && bin < 4);
	if (n_sd != n_sd_next[bin]) {
		/* not what we expected: duplicate */
		LOGPFSML(log_fi, LOGL_NOTICE, "Duplicate DTAP: bin=%d, expected n_sd == %u, got %u\n",
			 bin, n_sd_next[bin], n_sd);
		return true;
	} else {
		/* as expected: no dup; update expected counter for next message */
		n_sd_next[bin] = (n_sd + 1) % modulo;
		return false;
	}
}

/* convenience: RAN decode implementations can call this to dispatch the decode_cb with a decoded ran_msg. */
int ran_decoded(struct ran_dec *ran_dec, struct ran_msg *ran_msg)
{
	if (!ran_dec->decode_cb)
		return -1;
	return ran_dec->decode_cb(ran_dec->caller_fi, ran_dec->caller_data, ran_msg);
}
